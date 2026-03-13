"""
tests/test_decision.py — Unit tests for Block 5: L5 Decision Engine.

All tests use in-process Settings objects — no network, DB, or Redis.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.analysis.l1_static import CheckResult
from core.engine.decision import (
    VERDICT_CLEAN,
    VERDICT_DANGEROUS,
    VERDICT_SUSPICIOUS,
    DecisionResult,
    decide,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_cfg(
    *,
    threshold_suspicious: int = 40,
    threshold_dangerous: int = 70,
    w_spf: int = 30,
    w_ip: int = 25,
    w_url: int = 25,
    w_hdr: int = 10,
    w_typo: int = 10,
):
    """Build a minimal Settings-like object without touching the file system."""
    from core.config.config import (
        AcquisitionConfig,
        ApiConfig,
        BlacklistsConfig,
        LoggingConfig,
        NotificationsConfig,
        ScoringConfig,
        Settings,
    )
    from pathlib import Path

    return Settings(
        acquisition=AcquisitionConfig(
            mode="imap",
            imap_host="h",
            imap_port=993,
            imap_use_ssl=True,
            imap_user="u",
            imap_password="p",
            imap_mailbox="INBOX",
            imap_idle=False,
            imap_poll_interval=30,
            dedup_window_hours=24,
            storage_path=Path("/tmp"),
        ),
        scoring=ScoringConfig(
            threshold_suspicious=threshold_suspicious,
            threshold_dangerous=threshold_dangerous,
            weight_spf_dkim_dmarc=w_spf,
            weight_ip_reputation=w_ip,
            weight_url_blacklist=w_url,
            weight_header_anomalies=w_hdr,
            weight_typosquatting=w_typo,
        ),
        notifications=NotificationsConfig(
            admin_email="",
            degraded_alert=False,
            dangerous_alert=False,
        ),
        api=ApiConfig(host="127.0.0.1", port=8080, token_expire_minutes=60),
        logging=LoggingConfig(level="info", path=Path("/tmp/test.log")),
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


def _result(name: str, score: int, passed: bool = True, detail: str = "") -> CheckResult:
    return CheckResult(name=name, score=score, detail=detail, passed=passed)


def _clean_results() -> list[CheckResult]:
    return [
        _result("spf_dkim_dmarc", 0, True, "SPF/DKIM/DMARC pass"),
        _result("ip_reputation", 0, True, "clean"),
        _result("url_blacklist", 0, True, "clean"),
        _result("header_anomalies", 0, True, "clean"),
        _result("typosquatting", 0, True, "clean"),
    ]


# ── Verdict thresholds ────────────────────────────────────────────────────────


class TestVerdictThresholds:
    def test_all_clean_returns_clean(self):
        """All checks score 0 → CLEAN."""
        result = decide(_clean_results(), _make_cfg())
        assert result.verdict == VERDICT_CLEAN
        assert result.score == 0

    def test_score_above_dangerous_threshold(self):
        """Score ≥ threshold_dangerous → DANGEROUS."""
        cfg = _make_cfg(threshold_dangerous=70)
        # ip_reputation at max (30/30) + url_blacklist at max (35/35):
        # ip contributes (30/30)*25 = 25 weight-points
        # url contributes (35/35)*25 = 25 weight-points
        # total weight = 100, weighted_score = 50 → normalized = 50/100*100 = 50
        # Need to push higher — use all max scores
        results = [
            _result("spf_dkim_dmarc", 50, False),   # max 50
            _result("ip_reputation", 30, False),     # max 30
            _result("url_blacklist", 35, False),     # max 35
            _result("header_anomalies", 50, False),  # max 50
            _result("typosquatting", 40, False),     # max 40
        ]
        r = decide(results, cfg)
        assert r.verdict == VERDICT_DANGEROUS
        assert r.score >= 70

    def test_score_in_suspicious_band(self):
        """Score between threshold_suspicious and threshold_dangerous → SUSPICIOUS."""
        cfg = _make_cfg(threshold_suspicious=40, threshold_dangerous=70)
        # ip_reputation listed (30/30 = 100% raw) contributes (30/30)*25=25 of 100 total weight
        # normalized = 25/100*100 = 25 → too low; also add url_blacklist at max
        # ip: 25 weight-points, url: 25 weight-points → 50/100 = 50 → SUSPICIOUS
        results = [
            _result("spf_dkim_dmarc", 0, True),
            _result("ip_reputation", 30, False),
            _result("url_blacklist", 35, False),
            _result("header_anomalies", 0, True),
            _result("typosquatting", 0, True),
        ]
        r = decide(results, cfg)
        assert r.verdict == VERDICT_SUSPICIOUS
        assert 40 <= r.score < 70

    def test_score_below_suspicious_is_clean(self):
        """Score just below threshold_suspicious → CLEAN."""
        cfg = _make_cfg(threshold_suspicious=40)
        # Only header_anomalies anomaly (15/50 raw) with weight 10
        # weighted = (15/50)*10 = 3 / 10 total weight → 30 → CLEAN
        results = [
            _result("spf_dkim_dmarc", 0, True),
            _result("ip_reputation", 0, True),
            _result("url_blacklist", 0, True),
            _result("header_anomalies", 15, False),
            _result("typosquatting", 0, True),
        ]
        r = decide(results, cfg)
        assert r.verdict == VERDICT_CLEAN
        assert r.score < 40


# ── Normalization ─────────────────────────────────────────────────────────────


class TestNormalization:
    def test_score_capped_at_100(self):
        """Normalized score is always ≤ 100."""
        results = [
            _result("spf_dkim_dmarc", 50, False),
            _result("ip_reputation", 30, False),
            _result("url_blacklist", 35, False),
            _result("header_anomalies", 50, False),
            _result("typosquatting", 40, False),
        ]
        r = decide(results, _make_cfg())
        assert r.score <= 100

    def test_score_floor_at_zero(self):
        """Normalized score is always ≥ 0."""
        r = decide(_clean_results(), _make_cfg())
        assert r.score >= 0

    def test_disabled_check_reduces_denominator(self):
        """Missing checks reduce max denominator, not inflate score."""
        cfg = _make_cfg()
        # Only provide ip_reputation at full score; others absent
        results_all = [
            _result("spf_dkim_dmarc", 0, True),
            _result("ip_reputation", 30, False),
            _result("url_blacklist", 0, True),
            _result("header_anomalies", 0, True),
            _result("typosquatting", 0, True),
        ]
        results_only_ip = [
            _result("ip_reputation", 30, False),
        ]
        score_all = decide(results_all, cfg).score
        score_only = decide(results_only_ip, cfg).score
        # With only ip_reputation present, denominator = 25 (its weight)
        # score = (30/30)*25 / 25 * 100 = 100
        # With all checks at 0 except ip, score = 25/100*100 = 25
        assert score_only > score_all

    def test_all_weights_zero_returns_zero(self):
        """If all weights are zero the score is 0 and verdict CLEAN."""
        cfg = _make_cfg(w_spf=0, w_ip=0, w_url=0, w_hdr=0, w_typo=0)
        results = [
            _result("spf_dkim_dmarc", 50, False),
            _result("ip_reputation", 30, False),
        ]
        r = decide(results, cfg)
        assert r.score == 0
        assert r.verdict == VERDICT_CLEAN

    def test_partial_max_score_proportional(self):
        """Half-max raw score yields half-max normalized contribution."""
        cfg = _make_cfg(
            w_spf=100, w_ip=0, w_url=0, w_hdr=0, w_typo=0,
            threshold_suspicious=60,
        )
        # spf_dkim_dmarc max raw = 50; pass half = 25
        results = [_result("spf_dkim_dmarc", 25, False)]
        r = decide(results, cfg)
        assert r.score == 50


# ── Configurable thresholds ───────────────────────────────────────────────────


class TestConfigurableThresholds:
    def test_custom_thresholds_respected(self):
        """Custom thresholds in config override defaults."""
        cfg = _make_cfg(threshold_suspicious=10, threshold_dangerous=20)
        results = [
            _result("spf_dkim_dmarc", 25, False),  # will push score above 10
            _result("ip_reputation", 0, True),
            _result("url_blacklist", 0, True),
            _result("header_anomalies", 0, True),
            _result("typosquatting", 0, True),
        ]
        r = decide(results, cfg)
        # spf at 25/50 → (0.5)*30 = 15 of 100 weight → score=15 → SUSPICIOUS (≥10)
        assert r.verdict in (VERDICT_SUSPICIOUS, VERDICT_DANGEROUS)

    def test_threshold_boundary_suspicious(self):
        """Score exactly at threshold_suspicious → SUSPICIOUS, not CLEAN."""
        # Craft score = exactly threshold_suspicious
        cfg = _make_cfg(
            threshold_suspicious=50,
            threshold_dangerous=80,
            w_spf=100, w_ip=0, w_url=0, w_hdr=0, w_typo=0,
        )
        # spf raw=25 out of max=50 → normalized = (25/50)*100 = 50
        results = [_result("spf_dkim_dmarc", 25, False)]
        r = decide(results, cfg)
        assert r.score == 50
        assert r.verdict == VERDICT_SUSPICIOUS

    def test_threshold_boundary_dangerous(self):
        """Score exactly at threshold_dangerous → DANGEROUS, not SUSPICIOUS."""
        cfg = _make_cfg(
            threshold_suspicious=40,
            threshold_dangerous=70,
            w_spf=100, w_ip=0, w_url=0, w_hdr=0, w_typo=0,
        )
        # spf raw=35 out of max=50 → 35/50*100 = 70
        results = [_result("spf_dkim_dmarc", 35, False)]
        r = decide(results, cfg)
        assert r.score == 70
        assert r.verdict == VERDICT_DANGEROUS

    def test_weight_change_changes_score(self):
        """Doubling a check's weight doubles its contribution to the score."""
        base_cfg = _make_cfg(w_ip=25)
        high_cfg = _make_cfg(w_ip=50)
        results = [
            _result("spf_dkim_dmarc", 0, True),
            _result("ip_reputation", 30, False),
            _result("url_blacklist", 0, True),
            _result("header_anomalies", 0, True),
            _result("typosquatting", 0, True),
        ]
        score_base = decide(results, base_cfg).score
        score_high = decide(results, high_cfg).score
        assert score_high > score_base


# ── Output contract ───────────────────────────────────────────────────────────


class TestOutputContract:
    def test_returns_decision_result_type(self):
        """decide() always returns a DecisionResult."""
        r = decide(_clean_results(), _make_cfg())
        assert isinstance(r, DecisionResult)

    def test_verdict_is_one_of_three_values(self):
        """Verdict is always one of the three defined string constants."""
        for results in [
            _clean_results(),
            [_result("ip_reputation", 30, False)],
            [
                _result("spf_dkim_dmarc", 50, False),
                _result("ip_reputation", 30, False),
                _result("url_blacklist", 35, False),
                _result("header_anomalies", 50, False),
                _result("typosquatting", 40, False),
            ],
        ]:
            r = decide(results, _make_cfg())
            assert r.verdict in (VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_DANGEROUS)

    def test_detail_contains_verdict(self):
        """DecisionResult.detail mentions the verdict."""
        r = decide(_clean_results(), _make_cfg())
        assert r.verdict in r.detail

    def test_empty_check_list_returns_clean(self):
        """Empty check list → score 0, verdict CLEAN."""
        r = decide([], _make_cfg())
        assert r.score == 0
        assert r.verdict == VERDICT_CLEAN

    def test_unknown_check_name_ignored(self):
        """Checks with unrecognized names do not crash the engine."""
        results = _clean_results() + [
            _result("future_l2_check", 99, False),
        ]
        r = decide(results, _make_cfg())
        assert isinstance(r, DecisionResult)
