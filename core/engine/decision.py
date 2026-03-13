"""
decision.py — L5 Decision Engine for MailDome.

Computes a normalized weighted aggregate score from L1 check results
and maps it to a verdict: CLEAN | SUSPICIOUS | DANGEROUS.

Thresholds and weights are read from the settings singleton so every
value can be overridden in mailshield.conf — nothing is hardcoded here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import structlog

from core.analysis.l1_static import CheckResult
from core.config.config import Settings, settings as _default_settings

log = structlog.get_logger()

# Ordered list of check names that have configurable weights.
_CHECK_NAMES = (
    "spf_dkim_dmarc",
    "ip_reputation",
    "url_blacklist",
    "header_anomalies",
    "typosquatting",
)

# Maximum raw score each check can contribute (per CLAUDE.md spec).
_CHECK_MAX_RAW: dict[str, int] = {
    "spf_dkim_dmarc": 50,    # 25 (dmarc fail) + 15 (dkim) + 10 (spf)
    "ip_reputation": 30,
    "url_blacklist": 35,
    "header_anomalies": 50,  # 15 + 5 + 10 + 20
    "typosquatting": 40,
}

VERDICT_CLEAN = "CLEAN"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_DANGEROUS = "DANGEROUS"


@dataclass
class DecisionResult:
    """Output of the decision engine."""

    verdict: str          # CLEAN | SUSPICIOUS | DANGEROUS
    score: int            # 0–100 normalized
    detail: str           # human-readable breakdown


def _weight_for(name: str, cfg: Settings) -> int:
    """Return the configured weight for a check by name."""
    sc = cfg.scoring
    return {
        "spf_dkim_dmarc": sc.weight_spf_dkim_dmarc,
        "ip_reputation": sc.weight_ip_reputation,
        "url_blacklist": sc.weight_url_blacklist,
        "header_anomalies": sc.weight_header_anomalies,
        "typosquatting": sc.weight_typosquatting,
    }.get(name, 0)


def decide(
    check_results: Sequence[CheckResult],
    cfg: Settings | None = None,
) -> DecisionResult:
    """
    Compute a normalized 0–100 score and emit a verdict.

    Disabled checks (score == 0 because the check was skipped entirely)
    reduce the maximum denominator proportionally rather than inflating
    the apparent score.  Only checks that are present in check_results
    are considered — missing checks are treated as disabled.
    """
    if cfg is None:
        cfg = _default_settings

    results_by_name: dict[str, CheckResult] = {r.name: r for r in check_results}

    weighted_score = 0.0
    total_weight = 0

    for name in _CHECK_NAMES:
        weight = _weight_for(name, cfg)
        if weight == 0:
            continue

        result = results_by_name.get(name)
        if result is None:
            # Check absent — treat as disabled, exclude from denominator
            continue

        max_raw = _CHECK_MAX_RAW.get(name, 100)
        # Normalize this check's raw score to [0, weight]
        check_max = max_raw if max_raw > 0 else 1
        normalized = (result.score / check_max) * weight
        weighted_score += normalized
        total_weight += weight

    if total_weight == 0:
        normalized_total = 0
    else:
        # Scale to 0–100
        normalized_total = round((weighted_score / total_weight) * 100)

    normalized_total = max(0, min(100, normalized_total))

    sc = cfg.scoring
    if normalized_total >= sc.threshold_dangerous:
        verdict = VERDICT_DANGEROUS
    elif normalized_total >= sc.threshold_suspicious:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_CLEAN

    breakdown = ", ".join(
        f"{r.name}={r.score}" for r in check_results
    )
    detail = f"score={normalized_total} [{breakdown}] verdict={verdict}"

    log.info(
        "decision_complete",
        verdict=verdict,
        score=normalized_total,
        checks={r.name: r.score for r in check_results},
    )

    return DecisionResult(verdict=verdict, score=normalized_total, detail=detail)
