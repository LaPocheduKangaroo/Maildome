"""
api/main.py — MailDome REST API

Endpoints
---------
GET  /                                   health probe (no auth)
GET  /api/v1/status                      component health (no auth)
GET  /api/v1/emails                      list emails, paginated (auth)
GET  /api/v1/emails/{email_id}           email + check results (auth)
GET  /api/v1/emails/by-message-id/{mid} look up by Message-ID (auth)
POST /api/v1/emails/{email_id}/override  override verdict (auth)
GET  /api/v1/audit                       audit log, paginated (auth)

Auth
----
Static bearer token: set API_TOKEN env var.
All protected endpoints return 401 when the token is absent or wrong.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from typing import Optional

import asyncpg
import redis.asyncio as aioredis
import structlog
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from api.schemas import (
    AuditEntry,
    AuditListResponse,
    EmailDetail,
    EmailListResponse,
    EmailSummary,
    VerdictOverrideRequest,
    VerdictOverrideResponse,
    CheckResultOut,
)

log = structlog.get_logger()

_bearer = HTTPBearer()

# ── Helpers ───────────────────────────────────────────────────────────────────


def _db_url() -> str:
    return (
        f"postgresql://{os.environ.get('POSTGRES_USER', 'maildome')}"
        f":{os.environ.get('POSTGRES_PASSWORD', '')}"
        f"@{os.environ.get('POSTGRES_HOST', 'postgres')}:5432"
        f"/{os.environ.get('POSTGRES_DB', 'maildome')}"
    )


def _redis_url() -> str:
    return (
        f"redis://:{os.environ.get('REDIS_PASSWORD', '')}"
        f"@{os.environ.get('REDIS_HOST', 'redis')}:6379"
    )


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Create shared DB pool and Redis client on startup; close on shutdown."""
    application.state.db_pool = await asyncpg.create_pool(dsn=_db_url(), min_size=2, max_size=10)
    application.state.redis = aioredis.from_url(_redis_url(), decode_responses=True)
    log.info("api_startup", db="connected", redis="connected")
    yield
    await application.state.db_pool.close()
    await application.state.redis.aclose()
    log.info("api_shutdown")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="MailDome",
    description="Email security pipeline API",
    version="0.2.0",
    lifespan=lifespan,
)


# ── Dependencies ──────────────────────────────────────────────────────────────


async def get_db(request: Request) -> asyncpg.Pool:
    """Return the shared DB pool from app state."""
    return request.app.state.db_pool


async def require_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> None:
    """Validate the static bearer token. Raises 401 on mismatch."""
    expected = os.environ.get("API_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="API_TOKEN not configured")
    if credentials.credentials != expected:
        raise HTTPException(status_code=401, detail="Invalid token")


# ── Public endpoints ──────────────────────────────────────────────────────────


@app.get("/")
async def root():
    """Liveness probe — no auth required."""
    return {"status": "ok", "service": "MailDome"}


@app.get("/api/v1/status")
async def status(request: Request):
    """Component health check — no auth required."""
    components: dict[str, str] = {"api": "ok"}

    try:
        pool: asyncpg.Pool = request.app.state.db_pool
        await pool.fetchval("SELECT 1")
        components["postgres"] = "ok"
    except Exception as exc:
        components["postgres"] = f"error: {exc}"

    try:
        redis = request.app.state.redis
        await redis.ping()
        components["redis"] = "ok"
    except Exception as exc:
        components["redis"] = f"error: {exc}"

    overall = "ok" if all(v == "ok" for v in components.values()) else "degraded"
    return {"status": overall, "version": "0.2.0", "components": components}


# ── Protected endpoints ───────────────────────────────────────────────────────


@app.get("/api/v1/emails", response_model=EmailListResponse, dependencies=[Depends(require_token)])
async def list_emails(
    verdict: Optional[str] = Query(None, description="Filter by verdict: CLEAN | SUSPICIOUS | DANGEROUS | PENDING | FAILED"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    db: asyncpg.Pool = Depends(get_db),
) -> EmailListResponse:
    """List email scan records, paginated and optionally filtered by verdict."""
    offset = (page - 1) * per_page

    if verdict:
        rows = await db.fetch(
            "SELECT id, message_id, received_at, sender, recipient, subject, "
            "verdict, score, scanned_at, profile FROM emails "
            "WHERE verdict = $1 ORDER BY received_at DESC LIMIT $2 OFFSET $3",
            verdict, per_page, offset,
        )
        total = await db.fetchval("SELECT COUNT(*) FROM emails WHERE verdict = $1", verdict)
    else:
        rows = await db.fetch(
            "SELECT id, message_id, received_at, sender, recipient, subject, "
            "verdict, score, scanned_at, profile FROM emails "
            "ORDER BY received_at DESC LIMIT $1 OFFSET $2",
            per_page, offset,
        )
        total = await db.fetchval("SELECT COUNT(*) FROM emails")

    return EmailListResponse(
        emails=[EmailSummary(**dict(r)) for r in rows],
        total=total or 0,
        page=page,
        per_page=per_page,
    )


@app.get(
    "/api/v1/emails/by-message-id/{message_id:path}",
    response_model=EmailDetail,
    dependencies=[Depends(require_token)],
)
async def get_email_by_message_id(
    message_id: str,
    db: asyncpg.Pool = Depends(get_db),
) -> EmailDetail:
    """Fetch a single email by its RFC 5322 Message-ID (used by the Thunderbird plugin)."""
    row = await db.fetchrow(
        "SELECT id, message_id, sha256, received_at, sender, recipient, subject, "
        "storage_path, verdict, score, scanned_at, profile "
        "FROM emails WHERE message_id = $1",
        message_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Email not found")
    return await _build_email_detail(row, db)


@app.get(
    "/api/v1/emails/{email_id}",
    response_model=EmailDetail,
    dependencies=[Depends(require_token)],
)
async def get_email(
    email_id: int,
    db: asyncpg.Pool = Depends(get_db),
) -> EmailDetail:
    """Fetch a single email record with all L1 check results."""
    row = await db.fetchrow(
        "SELECT id, message_id, sha256, received_at, sender, recipient, subject, "
        "storage_path, verdict, score, scanned_at, profile "
        "FROM emails WHERE id = $1",
        email_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Email not found")
    return await _build_email_detail(row, db)


async def _build_email_detail(row: asyncpg.Record, db: asyncpg.Pool) -> EmailDetail:
    """Fetch check_results for an email and assemble an EmailDetail."""
    check_rows = await db.fetch(
        "SELECT check_name, passed, score, detail FROM check_results WHERE email_id = $1",
        row["id"],
    )
    checks = [CheckResultOut(**dict(cr)) for cr in check_rows]
    return EmailDetail(**dict(row), check_results=checks)


@app.post(
    "/api/v1/emails/{email_id}/override",
    response_model=VerdictOverrideResponse,
    dependencies=[Depends(require_token)],
)
async def override_verdict(
    email_id: int,
    body: VerdictOverrideRequest,
    db: asyncpg.Pool = Depends(get_db),
) -> VerdictOverrideResponse:
    """
    Override the verdict for an email. Reason is mandatory.
    The original and new verdicts are appended to audit_log (append-only).
    """
    row = await db.fetchrow(
        "SELECT id, verdict FROM emails WHERE id = $1", email_id
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Email not found")

    old_verdict = row["verdict"]

    async with db.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "UPDATE emails SET verdict = $1 WHERE id = $2",
                body.verdict,
                email_id,
            )
            await conn.execute(
                """
                INSERT INTO audit_log (event_type, email_id, actor, detail)
                VALUES ('verdict_override', $1, 'api', $2::jsonb)
                """,
                email_id,
                json.dumps({
                    "old_verdict": old_verdict,
                    "new_verdict": body.verdict,
                    "reason": body.reason,
                }),
            )

    log.info(
        "verdict_overridden",
        email_id=email_id,
        old=old_verdict,
        new=body.verdict,
    )
    return VerdictOverrideResponse(
        email_id=email_id,
        old_verdict=old_verdict,
        new_verdict=body.verdict,
        reason=body.reason,
    )


@app.get("/api/v1/audit", response_model=AuditListResponse, dependencies=[Depends(require_token)])
async def list_audit(
    email_id: Optional[int] = Query(None, description="Filter by email_id"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    db: asyncpg.Pool = Depends(get_db),
) -> AuditListResponse:
    """List audit log entries, paginated. Optionally filter by email_id."""
    offset = (page - 1) * per_page

    if email_id is not None:
        rows = await db.fetch(
            "SELECT id, created_at, event_type, email_id, actor, detail "
            "FROM audit_log WHERE email_id = $1 "
            "ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            email_id, per_page, offset,
        )
        total = await db.fetchval(
            "SELECT COUNT(*) FROM audit_log WHERE email_id = $1", email_id
        )
    else:
        rows = await db.fetch(
            "SELECT id, created_at, event_type, email_id, actor, detail "
            "FROM audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            per_page, offset,
        )
        total = await db.fetchval("SELECT COUNT(*) FROM audit_log")

    entries = [
        AuditEntry(
            id=r["id"],
            created_at=r["created_at"],
            event_type=r["event_type"],
            email_id=r["email_id"],
            actor=r["actor"],
            detail=r["detail"],
        )
        for r in rows
    ]
    return AuditListResponse(
        entries=entries,
        total=total or 0,
        page=page,
        per_page=per_page,
    )
