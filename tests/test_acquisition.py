"""
tests/test_acquisition.py — Unit tests for Block 3: L0 IMAP acquisition.

Tests run without a live IMAP server, PostgreSQL, or Redis by mocking
all I/O dependencies.
"""

import asyncio
import email
import email.policy
import hashlib
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RAW_EMAIL = textwrap.dedent("""\
    Message-ID: <test-001@example.com>
    From: alice@example.com
    To: bob@example.com
    Subject: Test email
    MIME-Version: 1.0
    Content-Type: text/plain; charset=utf-8

    Hello, this is a test.
""").encode()

SHA256 = hashlib.sha256(RAW_EMAIL).hexdigest()


def _make_settings(tmp_path: Path):
    """Build a minimal Settings-like object for tests."""
    from core.config.config import (
        AcquisitionConfig,
        ApiConfig,
        BlacklistsConfig,
        LoggingConfig,
        NotificationsConfig,
        ScoringConfig,
        Settings,
    )

    return Settings(
        acquisition=AcquisitionConfig(
            mode="imap",
            imap_host="imap.example.com",
            imap_port=993,
            imap_use_ssl=True,
            imap_user="scanner@example.com",
            imap_password="secret",
            imap_mailbox="INBOX",
            imap_idle=False,
            imap_poll_interval=30,
            dedup_window_hours=24,
            storage_path=tmp_path / "emails",
        ),
        scoring=ScoringConfig(
            threshold_suspicious=40,
            threshold_dangerous=70,
            weight_spf_dkim_dmarc=30,
            weight_ip_reputation=25,
            weight_url_blacklist=25,
            weight_header_anomalies=10,
            weight_typosquatting=10,
        ),
        notifications=NotificationsConfig(
            admin_email="",
            degraded_alert=True,
            dangerous_alert=True,
        ),
        api=ApiConfig(host="127.0.0.1", port=8080, token_expire_minutes=60),
        logging=LoggingConfig(level="debug", path=tmp_path / "mailshield.log"),
        groups={},
        default_profile="standard",
        blacklists=BlacklistsConfig(
            spamhaus=True,
            abusech=True,
            openphish=True,
            phishtank=True,
            custom_ip_list=None,
            custom_url_list=None,
        ),
    )


# ---------------------------------------------------------------------------
# Dispatcher tests
# ---------------------------------------------------------------------------


class TestDispatcher:
    """Tests for core.acquisition.dispatcher.Dispatcher"""

    @pytest.fixture()
    def settings(self, tmp_path):
        return _make_settings(tmp_path)

    @pytest.fixture()
    def dispatcher(self, settings):
        from core.acquisition.dispatcher import Dispatcher

        return Dispatcher(settings)

    @pytest.mark.asyncio
    async def test_new_email_saved_and_dispatched(self, dispatcher, tmp_path):
        """A fresh email is saved to disk and inserted into the DB."""
        mock_pool = AsyncMock()
        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=0)
        mock_redis.setex = AsyncMock()

        # DB returns a new row id
        mock_pool.fetchrow = AsyncMock(return_value={"id": 42})
        dispatcher._pool = mock_pool
        dispatcher._redis = mock_redis

        with patch("core.acquisition.dispatcher.Dispatcher._enqueue") as mock_enqueue:
            email_id = await dispatcher.dispatch(b"1", RAW_EMAIL)

        assert email_id == 42
        mock_enqueue.assert_called_once_with(42)

        # .eml file must exist
        eml_path = dispatcher._cfg.storage_path / f"{SHA256}.eml"
        assert eml_path.exists()
        assert eml_path.read_bytes() == RAW_EMAIL

        # Dedup key must have been set
        mock_redis.setex.assert_called_once()
        args = mock_redis.setex.call_args[0]
        assert args[0] == f"dedup:{SHA256}"
        assert args[1] == 24 * 3600  # TTL

    @pytest.mark.asyncio
    async def test_duplicate_email_skipped(self, dispatcher):
        """An email whose SHA-256 is already in Redis is skipped."""
        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=1)  # already in dedup cache
        dispatcher._redis = mock_redis
        dispatcher._pool = AsyncMock()

        with patch("core.acquisition.dispatcher.Dispatcher._enqueue") as mock_enqueue:
            result = await dispatcher.dispatch(b"2", RAW_EMAIL)

        assert result is None
        mock_enqueue.assert_not_called()

    @pytest.mark.asyncio
    async def test_db_conflict_skipped(self, dispatcher):
        """
        If the DB returns no row (ON CONFLICT DO NOTHING), dispatch returns None
        and the Celery task is not enqueued.
        """
        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=0)
        mock_redis.setex = AsyncMock()
        dispatcher._redis = mock_redis

        mock_pool = AsyncMock()
        mock_pool.fetchrow = AsyncMock(return_value=None)  # conflict
        dispatcher._pool = mock_pool

        with patch("core.acquisition.dispatcher.Dispatcher._enqueue") as mock_enqueue:
            result = await dispatcher.dispatch(b"3", RAW_EMAIL)

        assert result is None
        mock_enqueue.assert_not_called()

    @pytest.mark.asyncio
    async def test_eml_not_overwritten(self, dispatcher, tmp_path):
        """If the .eml already exists on disk it is not overwritten."""
        storage = dispatcher._cfg.storage_path
        storage.mkdir(parents=True, exist_ok=True)
        eml_path = storage / f"{SHA256}.eml"
        eml_path.write_bytes(b"existing content")

        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=0)
        mock_redis.setex = AsyncMock()
        dispatcher._redis = mock_redis
        dispatcher._pool = AsyncMock()
        dispatcher._pool.fetchrow = AsyncMock(return_value={"id": 7})

        with patch("core.acquisition.dispatcher.Dispatcher._enqueue"):
            await dispatcher.dispatch(b"4", RAW_EMAIL)

        # Original content preserved
        assert eml_path.read_bytes() == b"existing content"

    def test_sha256_computed_correctly(self):
        """SHA-256 is computed over the raw bytes."""
        expected = hashlib.sha256(RAW_EMAIL).hexdigest()
        assert expected == SHA256

    def test_parsed_headers(self):
        """Headers are correctly extracted from the raw email."""
        msg = email.message_from_bytes(RAW_EMAIL, policy=email.policy.default)
        assert msg["Message-ID"].strip() == "<test-001@example.com>"
        assert msg["From"].strip() == "alice@example.com"
        assert msg["To"].strip() == "bob@example.com"
        assert msg["Subject"].strip() == "Test email"


# ---------------------------------------------------------------------------
# ImapClient unit tests (no live server)
# ---------------------------------------------------------------------------


class TestImapClientHelpers:
    """Tests that do not require a network connection."""

    def _make_client(self, idle: bool = False):
        from core.acquisition.imap_client import ImapClient
        from core.config.config import AcquisitionConfig

        cfg = AcquisitionConfig(
            mode="imap",
            imap_host="imap.example.com",
            imap_port=993,
            imap_use_ssl=True,
            imap_user="user",
            imap_password="pass",
            imap_mailbox="INBOX",
            imap_idle=idle,
            imap_poll_interval=5,
            dedup_window_hours=24,
            storage_path=Path("/tmp/emails"),
        )
        return ImapClient(cfg)

    @pytest.mark.asyncio
    async def test_search_unseen_empty(self):
        """Empty UNSEEN search returns an empty list."""
        client = self._make_client()
        mock_imap = AsyncMock()
        mock_imap.uid = AsyncMock(return_value=("OK", [b""]))
        client._imap = mock_imap

        result = await client._search_unseen()
        assert result == []

    @pytest.mark.asyncio
    async def test_search_unseen_returns_uids(self):
        """UIDs are correctly parsed from the SEARCH response."""
        client = self._make_client()
        mock_imap = AsyncMock()
        mock_imap.uid = AsyncMock(return_value=("OK", [b"1 2 3"]))
        client._imap = mock_imap

        result = await client._search_unseen()
        assert result == [b"1", b"2", b"3"]

    @pytest.mark.asyncio
    async def test_fetch_raw_returns_bytes(self):
        """_fetch_raw returns the literal bytes from the FETCH response."""
        client = self._make_client()
        mock_imap = AsyncMock()
        mock_imap.uid = AsyncMock(
            return_value=("OK", [b"1 (RFC822 {123}", RAW_EMAIL, b")"])
        )
        client._imap = mock_imap

        result = await client._fetch_raw(b"1")
        assert result == RAW_EMAIL

    @pytest.mark.asyncio
    async def test_fetch_raw_error_returns_none(self):
        """A failed FETCH returns None without raising."""
        client = self._make_client()
        mock_imap = AsyncMock()
        mock_imap.uid = AsyncMock(return_value=("NO", []))
        client._imap = mock_imap

        result = await client._fetch_raw(b"99")
        assert result is None

    @pytest.mark.asyncio
    async def test_server_has_idle_true(self):
        client = self._make_client(idle=True)
        mock_imap = AsyncMock()
        mock_imap.capability = AsyncMock(return_value=("OK", [b"IMAP4rev1 IDLE UIDPLUS"]))
        client._imap = mock_imap

        assert await client._server_has_idle() is True

    @pytest.mark.asyncio
    async def test_server_has_idle_false(self):
        client = self._make_client(idle=True)
        mock_imap = AsyncMock()
        mock_imap.capability = AsyncMock(return_value=("OK", [b"IMAP4rev1 UIDPLUS"]))
        client._imap = mock_imap

        assert await client._server_has_idle() is False
