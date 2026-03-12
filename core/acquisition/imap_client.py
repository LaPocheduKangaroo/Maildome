"""
imap_client.py — Async IMAP client for L0 email acquisition.

Supports:
  - SSL (port 993) or plain/STARTTLS
  - IMAP IDLE push mode (RFC 2177) with automatic re-IDLE every 29 min
  - Polling fallback when IDLE is unavailable or the server drops IDLE
  - Automatic reconnect with exponential back-off on transient errors

Usage:
    client = ImapClient(settings.acquisition)
    async for uid, raw_bytes in client.stream():
        await dispatcher.dispatch(uid, raw_bytes)
"""

import asyncio
import logging
from typing import AsyncIterator

import aioimaplib

from core.config.config import AcquisitionConfig

log = logging.getLogger(__name__)

# RFC 2177 recommends re-issuing IDLE before 30 minutes
_IDLE_REFRESH_SECS = 29 * 60
# Seconds to wait before reconnect on error (doubles each attempt, max 120)
_RECONNECT_BASE = 5
_RECONNECT_MAX = 120


class ImapClient:
    """
    Async IMAP client that yields (uid, raw_bytes) for every UNSEEN message.

    IDLE mode  — server pushes EXISTS notifications; no polling loop needed.
    Poll mode  — checks for UNSEEN messages every `imap_poll_interval` seconds.

    In both modes the client marks each message \\Seen immediately after
    yielding it so that a restart does not re-process already-dispatched mail.
    """

    def __init__(self, cfg: AcquisitionConfig) -> None:
        self._cfg = cfg
        self._imap: aioimaplib.IMAP4_SSL | aioimaplib.IMAP4 | None = None

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    async def _connect(self) -> None:
        cfg = self._cfg
        if cfg.imap_use_ssl:
            self._imap = aioimaplib.IMAP4_SSL(host=cfg.imap_host, port=cfg.imap_port)
        else:
            self._imap = aioimaplib.IMAP4(host=cfg.imap_host, port=cfg.imap_port)

        await self._imap.wait_hello_from_server()
        status, _ = await self._imap.login(cfg.imap_user, cfg.imap_password)
        if status != "OK":
            raise ConnectionError(f"IMAP login failed for {cfg.imap_user}")

        status, _ = await self._imap.select(cfg.imap_mailbox)
        if status != "OK":
            raise ConnectionError(f"IMAP SELECT failed for mailbox {cfg.imap_mailbox}")

        log.info("IMAP connected — %s/%s", cfg.imap_host, cfg.imap_mailbox)

    async def _disconnect(self) -> None:
        if self._imap is not None:
            try:
                await self._imap.logout()
            except Exception:
                pass
            self._imap = None

    async def _server_has_idle(self) -> bool:
        _, caps = await self._imap.capability()
        raw = caps[0] if caps else b""
        return b"IDLE" in raw

    # ------------------------------------------------------------------
    # Message fetching
    # ------------------------------------------------------------------

    async def _search_unseen(self) -> list[bytes]:
        """Return list of UIDs (as bytes) for all UNSEEN messages."""
        status, data = await self._imap.uid("search", "UNSEEN")
        if status != "OK" or not data or not data[0]:
            return []
        raw = data[0].decode()
        return [uid.encode() for uid in raw.split() if uid]

    async def _fetch_raw(self, uid: bytes) -> bytes | None:
        """Fetch RFC822 (full raw email) for a single UID. Returns None on error."""
        status, data = await self._imap.uid("fetch", uid.decode(), "(RFC822)")
        if status != "OK" or len(data) < 2:
            log.warning("Fetch failed for UID %s (status=%s)", uid, status)
            return None
        # aioimaplib response layout: [header_line, literal_bytes, closing_paren, ...]
        raw = data[1]
        if not isinstance(raw, (bytes, bytearray)):
            log.warning("Unexpected fetch payload type %s for UID %s", type(raw), uid)
            return None
        return bytes(raw)

    async def _mark_seen(self, uid: bytes) -> None:
        await self._imap.uid("store", uid.decode(), "+FLAGS", "\\Seen")

    async def _drain_unseen(self) -> AsyncIterator[tuple[bytes, bytes]]:
        """Fetch and yield all currently UNSEEN messages."""
        uids = await self._search_unseen()
        log.debug("Found %d UNSEEN message(s)", len(uids))
        for uid in uids:
            raw = await self._fetch_raw(uid)
            if raw is not None:
                yield uid, raw
                await self._mark_seen(uid)

    # ------------------------------------------------------------------
    # Public streaming interface
    # ------------------------------------------------------------------

    async def stream(self) -> AsyncIterator[tuple[bytes, bytes]]:
        """
        Yields (uid, raw_bytes) continuously until the caller stops.

        Reconnects automatically on any error using exponential back-off.
        """
        backoff = _RECONNECT_BASE

        while True:
            try:
                await self._connect()
                backoff = _RECONNECT_BASE  # reset on successful connect

                use_idle = self._cfg.imap_idle and await self._server_has_idle()

                # Always drain existing UNSEEN messages first
                async for uid, raw in self._drain_unseen():
                    yield uid, raw

                if use_idle:
                    log.info("IMAP IDLE mode active (refresh every %ds)", _IDLE_REFRESH_SECS)
                    await self._run_idle_loop()
                else:
                    log.info(
                        "IMAP poll mode — interval %ds",
                        self._cfg.imap_poll_interval,
                    )
                    await self._run_poll_loop()

            except asyncio.CancelledError:
                await self._disconnect()
                raise

            except Exception as exc:
                log.warning(
                    "IMAP error (%s: %s) — reconnecting in %ds",
                    type(exc).__name__,
                    exc,
                    backoff,
                )
                await self._disconnect()
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _RECONNECT_MAX)

    async def _run_idle_loop(self) -> AsyncIterator[tuple[bytes, bytes]]:
        """
        IDLE loop: enter IDLE, wait for EXISTS push, drain new messages, repeat.
        Re-issues IDLE every 29 minutes to satisfy RFC 2177 keep-alive rules.
        """
        while True:
            await self._imap.idle_start(timeout=_IDLE_REFRESH_SECS)
            try:
                await asyncio.wait_for(
                    self._imap.wait_server_push(),
                    timeout=_IDLE_REFRESH_SECS + 5,
                )
            except asyncio.TimeoutError:
                pass  # 29-minute keep-alive refresh
            finally:
                await self._imap.idle_done()

            async for uid, raw in self._drain_unseen():
                yield uid, raw

    async def _run_poll_loop(self) -> AsyncIterator[tuple[bytes, bytes]]:
        """Poll loop: sleep then search for UNSEEN, yield, repeat."""
        while True:
            await asyncio.sleep(self._cfg.imap_poll_interval)
            async for uid, raw in self._drain_unseen():
                yield uid, raw
