"""
worker.py — Celery application for MailDome.

The acquisition module enqueues tasks here.
The scan_email task runs the L1 Static Analysis pipeline.

Startup:
    celery -A core.engine.worker worker --loglevel=info
"""

import asyncio
import email
import email.policy
import os
from pathlib import Path

import asyncpg
import redis.asyncio as aioredis
import structlog
from celery import Celery

from core.analysis.l1_static import run_all_checks

log = structlog.get_logger()

_redis_password = os.environ.get("REDIS_PASSWORD", "")
_redis_host = os.environ.get("REDIS_HOST", "redis")
_broker_url = f"redis://:{_redis_password}@{_redis_host}:6379/0"

celery_app = Celery("maildome", broker=_broker_url, backend=_broker_url)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)


def _build_db_url() -> str:
    return (
        f"postgresql://{os.environ.get('POSTGRES_USER', 'maildome')}"
        f":{os.environ.get('POSTGRES_PASSWORD', '')}"
        f"@{os.environ.get('POSTGRES_HOST', 'postgres')}:5432"
        f"/{os.environ.get('POSTGRES_DB', 'maildome')}"
    )


def _build_redis_url() -> str:
    return f"redis://:{os.environ.get('REDIS_PASSWORD', '')}@{os.environ.get('REDIS_HOST', 'redis')}:6379/0"


async def _run_analysis(email_id: int) -> dict:
    """Async core of the scan_email task: load email, run L1 checks, persist results."""
    pool = await asyncpg.create_pool(dsn=_build_db_url(), min_size=1, max_size=1)
    redis = aioredis.from_url(_build_redis_url(), decode_responses=False)

    try:
        row = await pool.fetchrow(
            "SELECT storage_path FROM emails WHERE id = $1", email_id
        )
        if row is None:
            raise ValueError(f"email_id {email_id} not found in DB")

        eml_path = Path(row["storage_path"])
        raw = eml_path.read_bytes()
        msg = email.message_from_bytes(raw, policy=email.policy.default)

        results = await run_all_checks(msg, pool, redis)

        partial_score = min(100, sum(r.score for r in results))

        async with pool.acquire() as conn:
            async with conn.transaction():
                for r in results:
                    await conn.execute(
                        """
                        INSERT INTO check_results (email_id, check_name, passed, score, detail)
                        VALUES ($1, $2, $3, $4, $5)
                        """,
                        email_id,
                        r.name,
                        r.passed,
                        r.score,
                        r.detail,
                    )
                await conn.execute(
                    "UPDATE emails SET score = $1 WHERE id = $2",
                    partial_score,
                    email_id,
                )

        log.info(
            "l1_complete",
            email_id=email_id,
            partial_score=partial_score,
            checks={r.name: r.score for r in results},
        )
        return {"email_id": email_id, "status": "l1_complete", "score": partial_score}

    finally:
        await pool.close()
        await redis.aclose()


@celery_app.task(name="scan_email", bind=True, max_retries=3)
def scan_email(self, email_id: int) -> dict:
    """L1 analysis pipeline entry point. Enqueued by the L0 acquisition module."""
    try:
        return asyncio.run(_run_analysis(email_id))
    except Exception as exc:
        log.error("scan_email_failed", email_id=email_id, error=str(exc))
        raise self.retry(exc=exc, countdown=5 * (2 ** self.request.retries))
