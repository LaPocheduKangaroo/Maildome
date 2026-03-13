"""
tests/test_api.py — Unit tests for Block 6: REST API + auth.

All DB and Redis calls are mocked via FastAPI dependency overrides.
No real connections are made.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import app, get_db

# ── Fixtures ──────────────────────────────────────────────────────────────────

_TOKEN = "test-secret-token"
_AUTH = {"Authorization": f"Bearer {_TOKEN}"}

_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_email_row(**kwargs):
    """Return a dict mimicking an asyncpg Record for the emails table."""
    defaults = {
        "id": 1,
        "message_id": "<msg001@example.com>",
        "sha256": "abc123",
        "received_at": _NOW,
        "sender": "alice@example.com",
        "recipient": "bob@example.com",
        "subject": "Test",
        "storage_path": "/var/lib/mailshield/emails/abc123.eml",
        "verdict": "CLEAN",
        "score": 5,
        "scanned_at": _NOW,
        "profile": "standard",
    }
    defaults.update(kwargs)
    return defaults


def _make_check_row(**kwargs):
    defaults = {
        "check_name": "spf_dkim_dmarc",
        "passed": True,
        "score": 0,
        "detail": "pass",
    }
    defaults.update(kwargs)
    return defaults


def _make_audit_row(**kwargs):
    defaults = {
        "id": 1,
        "created_at": _NOW,
        "event_type": "verdict_override",
        "email_id": 1,
        "actor": "api",
        "detail": {"old_verdict": "CLEAN", "new_verdict": "DANGEROUS", "reason": "re-review"},
    }
    defaults.update(kwargs)
    return defaults


def _mock_pool(**kwargs):
    """Build an AsyncMock that behaves like an asyncpg pool."""
    pool = AsyncMock()
    pool.fetchval = AsyncMock(return_value=kwargs.get("fetchval", 0))
    pool.fetch = AsyncMock(return_value=kwargs.get("fetch", []))
    pool.fetchrow = AsyncMock(return_value=kwargs.get("fetchrow", None))

    # Simulate `async with pool.acquire() as conn`
    conn = AsyncMock()
    conn.execute = AsyncMock()
    conn.transaction = MagicMock()
    conn.transaction.return_value.__aenter__ = AsyncMock(return_value=None)
    conn.transaction.return_value.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock()
    pool.acquire.return_value.__aenter__ = AsyncMock(return_value=conn)
    pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)
    pool._mock_conn = conn
    return pool


@pytest.fixture()
def client():
    """
    TestClient with the lifespan mocked out so no real DB/Redis connections
    are attempted.  Per-test DB calls are injected via get_db overrides.
    """
    mock_pool = AsyncMock()
    mock_pool.close = AsyncMock()
    mock_pool.fetchval = AsyncMock(return_value=1)
    mock_redis = AsyncMock()
    mock_redis.aclose = AsyncMock()
    mock_redis.ping = AsyncMock()

    with (
        patch("api.main.asyncpg.create_pool", new=AsyncMock(return_value=mock_pool)),
        patch("api.main.aioredis.from_url", return_value=mock_redis),
    ):
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c


@pytest.fixture(autouse=True)
def patch_token(monkeypatch):
    monkeypatch.setenv("API_TOKEN", _TOKEN)


# ── Auth tests ────────────────────────────────────────────────────────────────


class TestAuth:
    def test_missing_token_returns_403(self, client):
        """No Authorization header → 403 (HTTPBearer returns 403 when missing)."""
        resp = client.get("/api/v1/emails")
        assert resp.status_code == 403

    def test_wrong_token_returns_401(self, client):
        """Wrong bearer token → 401."""
        pool = _mock_pool(fetchval=0, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/emails", headers={"Authorization": "Bearer wrong-token"})
        app.dependency_overrides.clear()
        assert resp.status_code == 401

    def test_valid_token_allows_access(self, client):
        """Valid token → 200."""
        pool = _mock_pool(fetchval=0, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/emails", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 200

    def test_public_endpoints_need_no_token(self, client):
        """/ and /api/v1/status do not require auth."""
        resp = client.get("/")
        assert resp.status_code == 200

    def test_status_no_token(self, client):
        """/api/v1/status does not require auth."""
        # patch app.state so status endpoint doesn't crash
        app.state.db_pool = _mock_pool(fetchval=1)
        app.state.redis = AsyncMock()
        app.state.redis.ping = AsyncMock()
        resp = client.get("/api/v1/status")
        assert resp.status_code == 200

    def test_api_token_not_configured_returns_503(self, client, monkeypatch):
        """If API_TOKEN env var is unset, a protected endpoint returns 503."""
        monkeypatch.delenv("API_TOKEN", raising=False)
        resp = client.get("/api/v1/emails", headers={"Authorization": "Bearer anything"})
        assert resp.status_code == 503


# ── GET /api/v1/emails ────────────────────────────────────────────────────────


class TestListEmails:
    def test_empty_result(self, client):
        """Empty DB → empty list with total=0."""
        pool = _mock_pool(fetchval=0, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/emails", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["emails"] == []
        assert data["page"] == 1

    def test_returns_email_list(self, client):
        """Single email row is returned correctly."""
        row = _make_email_row()
        pool = _mock_pool(fetchval=1, fetch=[row])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/emails", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        emails = resp.json()["emails"]
        assert len(emails) == 1
        assert emails[0]["message_id"] == "<msg001@example.com>"
        assert emails[0]["verdict"] == "CLEAN"

    def test_filter_by_verdict(self, client):
        """verdict query param is forwarded to the DB query."""
        pool = _mock_pool(fetchval=0, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/emails?verdict=DANGEROUS", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        # DB fetch was called with the verdict filter
        pool.fetch.assert_called_once()
        call_args = pool.fetch.call_args[0]
        assert "DANGEROUS" in call_args

    def test_pagination_params(self, client):
        """page and per_page are respected."""
        pool = _mock_pool(fetchval=0, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/emails?page=2&per_page=10", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["page"] == 2
        assert data["per_page"] == 10

    def test_per_page_max_enforced(self, client):
        """per_page > 100 is rejected with 422."""
        pool = _mock_pool(fetchval=0, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/emails?per_page=200", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 422


# ── GET /api/v1/emails/{email_id} ─────────────────────────────────────────────


class TestGetEmail:
    def test_found(self, client):
        """Known email_id → 200 with check_results."""
        row = _make_email_row()
        check = _make_check_row()
        pool = _mock_pool(fetchrow=row, fetch=[check])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/emails/1", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == 1
        assert len(data["check_results"]) == 1
        assert data["check_results"][0]["check_name"] == "spf_dkim_dmarc"

    def test_not_found(self, client):
        """Unknown email_id → 404."""
        pool = _mock_pool(fetchrow=None, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/emails/9999", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 404

    def test_check_results_embedded(self, client):
        """Multiple check_results are all embedded in the response."""
        row = _make_email_row()
        checks = [
            _make_check_row(check_name="spf_dkim_dmarc", score=0),
            _make_check_row(check_name="ip_reputation", score=30, passed=False),
            _make_check_row(check_name="url_blacklist", score=0),
        ]
        pool = _mock_pool(fetchrow=row, fetch=checks)
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/emails/1", headers=_AUTH)
        app.dependency_overrides.clear()
        assert len(resp.json()["check_results"]) == 3


# ── GET /api/v1/emails/by-message-id/{message_id} ────────────────────────────


class TestGetEmailByMessageId:
    def test_found_by_message_id(self, client):
        """Valid Message-ID → 200 with full EmailDetail."""
        row = _make_email_row(message_id="<test123@example.com>")
        pool = _mock_pool(fetchrow=row, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get(
            "/api/v1/emails/by-message-id/<test123@example.com>", headers=_AUTH
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        assert resp.json()["message_id"] == "<test123@example.com>"

    def test_not_found_by_message_id(self, client):
        """Unknown Message-ID → 404."""
        pool = _mock_pool(fetchrow=None, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get(
            "/api/v1/emails/by-message-id/<noexist@example.com>", headers=_AUTH
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 404

    def test_verdict_field_present(self, client):
        """Verdict is included in the by-message-id response (used by Thunderbird plugin)."""
        row = _make_email_row(verdict="SUSPICIOUS", score=55)
        pool = _mock_pool(fetchrow=row, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get(
            "/api/v1/emails/by-message-id/<any@example.com>", headers=_AUTH
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "SUSPICIOUS"
        assert resp.json()["score"] == 55


# ── POST /api/v1/emails/{email_id}/override ───────────────────────────────────


class TestOverrideVerdict:
    def test_valid_override_updates_verdict(self, client):
        """Valid override changes verdict and returns response."""
        row = _make_email_row(verdict="CLEAN")
        pool = _mock_pool(fetchrow=row)
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.post(
            "/api/v1/emails/1/override",
            headers=_AUTH,
            json={"verdict": "DANGEROUS", "reason": "Manual review confirmed phishing"},
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["old_verdict"] == "CLEAN"
        assert data["new_verdict"] == "DANGEROUS"
        assert data["reason"] == "Manual review confirmed phishing"

    def test_override_writes_to_audit_log(self, client):
        """The DB transaction executes both UPDATE and INSERT."""
        row = _make_email_row(verdict="SUSPICIOUS")
        pool = _mock_pool(fetchrow=row)
        app.dependency_overrides[get_db] = lambda: pool
        client.post(
            "/api/v1/emails/1/override",
            headers=_AUTH,
            json={"verdict": "CLEAN", "reason": "FP confirmed"},
        )
        app.dependency_overrides.clear()
        # Both UPDATE and INSERT should have been called
        assert pool._mock_conn.execute.call_count == 2
        calls = [c[0][0].strip() for c in pool._mock_conn.execute.call_args_list]
        assert any("UPDATE emails" in c for c in calls)
        assert any("INSERT INTO audit_log" in c for c in calls)

    def test_override_empty_reason_rejected(self, client):
        """Empty reason string → 422."""
        pool = _mock_pool(fetchrow=_make_email_row())
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.post(
            "/api/v1/emails/1/override",
            headers=_AUTH,
            json={"verdict": "CLEAN", "reason": "   "},
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 422

    def test_override_invalid_verdict_rejected(self, client):
        """Unknown verdict string → 422."""
        pool = _mock_pool(fetchrow=_make_email_row())
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.post(
            "/api/v1/emails/1/override",
            headers=_AUTH,
            json={"verdict": "MAYBE", "reason": "test"},
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 422

    def test_override_email_not_found(self, client):
        """Override on non-existent email_id → 404."""
        pool = _mock_pool(fetchrow=None)
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.post(
            "/api/v1/emails/9999/override",
            headers=_AUTH,
            json={"verdict": "CLEAN", "reason": "does not exist"},
        )
        app.dependency_overrides.clear()
        assert resp.status_code == 404


# ── GET /api/v1/audit ─────────────────────────────────────────────────────────


class TestAuditLog:
    def test_empty_audit_log(self, client):
        """Empty audit log → empty entries list."""
        pool = _mock_pool(fetchval=0, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/audit", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        assert resp.json()["total"] == 0
        assert resp.json()["entries"] == []

    def test_returns_audit_entries(self, client):
        """Audit rows are returned correctly."""
        row = _make_audit_row()
        pool = _mock_pool(fetchval=1, fetch=[row])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/audit", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert len(entries) == 1
        assert entries[0]["event_type"] == "verdict_override"
        assert entries[0]["actor"] == "api"

    def test_filter_by_email_id(self, client):
        """email_id query param filters results."""
        pool = _mock_pool(fetchval=0, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/audit?email_id=42", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        # Verify the filter value was passed to the DB
        pool.fetch.assert_called_once()
        assert 42 in pool.fetch.call_args[0]

    def test_audit_pagination(self, client):
        """Pagination fields are reflected in the response."""
        pool = _mock_pool(fetchval=0, fetch=[])
        app.dependency_overrides[get_db] = lambda: pool
        resp = client.get("/api/v1/audit?page=3&per_page=20", headers=_AUTH)
        app.dependency_overrides.clear()
        assert resp.status_code == 200
        data = resp.json()
        assert data["page"] == 3
        assert data["per_page"] == 20
