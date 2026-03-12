"""
dispatcher.py — L0 email dispatcher.

For every raw email received from ImapClient:
  1. Parse headers (Message-ID, From, To, Subject)
  2. Compute SHA-256
  3. Deduplication check via Redis (TTL = dedup_window_hours)
  4. Save .eml file to storage_path/<sha256>.eml
  5. INSERT into emails table with verdict = PENDING
  6. Enqueue Celery scan_email task
  7. Return the email_id or None if duplicate
"""

import email
import email.policy
import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import asyncpg
import redis.asyncio as aioredis

from core.config.config import Settings

log = logging.getLogger(__name__)

_DEDUP_PREFIX = "dedup:"


def _build_db_url() -> str:
    return (
        f"postgresql://{os.environ.get('POSTGRES_USER', 'maildome')}"
        f":{os.environ.get('POSTGRES_PASSWORD', '')}"
        f"@{os.environ.get('POSTGRES_HOST', 'postgres')}:5432"
        f"/{os.environ.get('POSTGRES_DB', 'maildome')}"
    )


def _build_redis_url() -> str:
    return f"redis://:{os.environ.get('REDIS_PASSWORD', '')}@{os.environ.get('REDIS_HOST', 'redis')}:6379/0"


class Dispatcher:
    """
    Stateful dispatcher that holds persistent connections to Postgres and Redis.
    Call `await dispatcher.start()` before use; `await dispatcher.stop()` on shutdown.
    """

    def __init__(self, settings: Settings) -> None:
        self._cfg = settings.acquisition
        self._dedup_ttl = settings.acquisition.dedup_window_hours * 3600
        self._pool: asyncpg.Pool | None = None
        self._redis: aioredis.Redis | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._pool = await asyncpg.create_pool(dsn=_build_db_url(), min_size=1, max_size=5)
        self._redis = aioredis.from_url(_build_redis_url(), decode_responses=False)
        log.info("Dispatcher started (DB pool + Redis ready)")

    async def stop(self) -> None:
        if self._pool:
            await self._pool.close()
        if self._redis:
            await self._redis.aclose()
        log.info("Dispatcher stopped")

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def dispatch(self, uid: bytes, raw: bytes) -> int | None:
        """
        Process one raw email.

        Returns the database email_id on success, or None if the message
        was skipped (duplicate or parse error).
        """
        sha256 = hashlib.sha256(raw).hexdigest()

        # --- 1. Deduplication ---
        dedup_key = f"{_DEDUP_PREFIX}{sha256}"
        if await self._redis.exists(dedup_key):
            log.debug("Duplicate message (sha256=%s) — skipped", sha256[:16])
            return None

        # --- 2. Parse headers ---
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        message_id = (msg.get("Message-ID") or f"<no-id-{sha256[:16]}>").strip()
        sender = msg.get("From", "").strip()
        # Take only the first recipient for the primary record
        recipient = msg.get("To", "").strip().split(",")[0].strip()
        subject = msg.get("Subject", "").strip() or None

        # --- 3. Save .eml file ---
        storage_path = self._cfg.storage_path
        storage_path.mkdir(parents=True, exist_ok=True)
        eml_path = storage_path / f"{sha256}.eml"
        if not eml_path.exists():
            eml_path.write_bytes(raw)
            log.debug("Saved %s (%d bytes)", eml_path.name, len(raw))

        # --- 4. Insert DB record ---
        email_id = await self._insert_email(
            message_id=message_id,
            sha256=sha256,
            sender=sender,
            recipient=recipient,
            subject=subject,
            storage_path=str(eml_path),
        )
        if email_id is None:
            # message_id collision (already in DB from a previous run)
            log.debug("Message-ID already in DB (%s) — skipped", message_id)
            return None

        # --- 5. Mark dedup key in Redis ---
        await self._redis.setex(dedup_key, self._dedup_ttl, b"1")

        # --- 6. Enqueue Celery task ---
        self._enqueue(email_id)

        log.info(
            "Dispatched email_id=%d sha256=%.16s from=%s subject=%s",
            email_id,
            sha256,
            sender,
            subject or "(none)",
        )
        return email_id

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _insert_email(
        self,
        *,
        message_id: str,
        sha256: str,
        sender: str,
        recipient: str,
        subject: str | None,
        storage_path: str,
    ) -> int | None:
        """
        Insert a new email record.
        Returns the generated id, or None if message_id already exists.
        """
        row = await self._pool.fetchrow(
            """
            INSERT INTO emails
                (message_id, sha256, received_at, sender, recipient, subject,
                 storage_path, verdict, profile)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING', 'standard')
            ON CONFLICT (message_id) DO NOTHING
            RETURNING id
            """,
            message_id,
            sha256,
            datetime.now(timezone.utc),
            sender,
            recipient,
            subject,
            storage_path,
        )
        return row["id"] if row else None

    def _enqueue(self, email_id: int) -> None:
        """Send scan_email task to Celery. Uses a direct Redis LPUSH to avoid
        importing the full Celery app here; the worker picks it up normally."""
        from core.engine.worker import celery_app

        celery_app.send_task("scan_email", args=[email_id])
        log.debug("Enqueued scan_email(email_id=%d)", email_id)
