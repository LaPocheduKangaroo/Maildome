"""
worker.py — Celery application for MailDome.

The acquisition module enqueues tasks here.
Analysis layers (L1–L5) will be implemented in subsequent blocks.

Startup:
    celery -A core.engine.worker worker --loglevel=info
"""

import logging
import os

from celery import Celery

log = logging.getLogger(__name__)

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
    # Prevent tasks from being lost if the broker restarts
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)


@celery_app.task(name="scan_email", bind=True, max_retries=3)
def scan_email(self, email_id: int) -> dict:
    """
    L1+ analysis pipeline entry point.

    Block 3 (L0) enqueues this task after saving the .eml and DB record.
    Block 4 (Static Analysis) will implement the actual checks.
    """
    log.info(
        "scan_email received email_id=%d — analysis pipeline not yet implemented",
        email_id,
    )
    return {"email_id": email_id, "status": "queued"}
