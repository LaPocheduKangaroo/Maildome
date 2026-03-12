"""
runner.py — L0 Acquisition service entry point.

Wires ImapClient → Dispatcher and runs the acquisition loop.

Startup (via docker-compose):
    python -m core.acquisition.runner

The service reconnects automatically on transient failures.
Shutdown is handled cleanly on SIGINT / SIGTERM.
"""

import asyncio
import logging
import signal
import sys

import structlog

from core.acquisition.dispatcher import Dispatcher
from core.acquisition.imap_client import ImapClient
from core.config.config import settings

log = structlog.get_logger(__name__)


def _configure_logging() -> None:
    level = getattr(logging, settings.logging.level.upper(), logging.INFO)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
    )
    logging.basicConfig(stream=sys.stdout, level=level, format="%(message)s")


async def run() -> None:
    _configure_logging()
    log.info("MailDome L0 Acquisition starting", mode=settings.acquisition.mode)

    if settings.acquisition.mode != "imap":
        log.error(
            "Unsupported acquisition mode — only 'imap' is implemented in Block 3",
            mode=settings.acquisition.mode,
        )
        sys.exit(1)

    dispatcher = Dispatcher(settings)
    await dispatcher.start()

    imap = ImapClient(settings.acquisition)

    # Handle SIGINT / SIGTERM gracefully
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _handle_signal() -> None:
        log.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    acquisition_task = asyncio.create_task(_acquisition_loop(imap, dispatcher))
    stop_task = asyncio.create_task(stop_event.wait())

    done, pending = await asyncio.wait(
        {acquisition_task, stop_task}, return_when=asyncio.FIRST_COMPLETED
    )

    for task in pending:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    await dispatcher.stop()
    log.info("MailDome L0 Acquisition stopped")


async def _acquisition_loop(imap: ImapClient, dispatcher: Dispatcher) -> None:
    """Consume the IMAP stream and hand each message to the dispatcher."""
    async for uid, raw in imap.stream():
        try:
            email_id = await dispatcher.dispatch(uid, raw)
            if email_id is not None:
                log.debug("Dispatched", uid=uid.decode(), email_id=email_id)
        except Exception as exc:
            log.error(
                "Dispatch error — message skipped",
                uid=uid.decode(),
                error=str(exc),
            )


if __name__ == "__main__":
    asyncio.run(run())
