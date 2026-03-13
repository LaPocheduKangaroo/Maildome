"""
api/schemas.py — Pydantic request/response models for the MailDome API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, field_validator


# ── Outbound models ───────────────────────────────────────────────────────────


class CheckResultOut(BaseModel):
    check_name: str
    passed: bool
    score: int
    detail: Optional[str]


class EmailSummary(BaseModel):
    id: int
    message_id: str
    received_at: datetime
    sender: str
    recipient: str
    subject: Optional[str]
    verdict: Optional[str]
    score: Optional[int]
    scanned_at: Optional[datetime]
    profile: str


class EmailDetail(EmailSummary):
    """Full email record including per-check results."""

    sha256: str
    storage_path: str
    check_results: list[CheckResultOut]


class EmailListResponse(BaseModel):
    emails: list[EmailSummary]
    total: int
    page: int
    per_page: int


class AuditEntry(BaseModel):
    id: int
    created_at: datetime
    event_type: str
    email_id: Optional[int]
    actor: str
    detail: Optional[dict[str, Any]]


class AuditListResponse(BaseModel):
    entries: list[AuditEntry]
    total: int
    page: int
    per_page: int


# ── Inbound models ────────────────────────────────────────────────────────────

_VALID_VERDICTS = {"CLEAN", "SUSPICIOUS", "DANGEROUS"}


class VerdictOverrideRequest(BaseModel):
    """Payload for manually overriding a verdict. Reason is mandatory."""

    verdict: str
    reason: str

    @field_validator("verdict")
    @classmethod
    def verdict_must_be_valid(cls, v: str) -> str:
        if v not in _VALID_VERDICTS:
            raise ValueError(f"verdict must be one of {sorted(_VALID_VERDICTS)}")
        return v

    @field_validator("reason")
    @classmethod
    def reason_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("reason must not be empty")
        return v.strip()


class VerdictOverrideResponse(BaseModel):
    email_id: int
    old_verdict: Optional[str]
    new_verdict: str
    reason: str
