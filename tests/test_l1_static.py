"""
tests/test_l1_static.py — Unit tests for Block 4: L1 Static Analysis.

All external calls (DNS, Redis, DB, HTTP) are mocked.
"""

import email
import email.policy
import textwrap
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.analysis.l1_static import (
    CheckResult,
    check_header_anomalies,
    check_ip_reputation,
    check_spf_dkim_dmarc,
    check_typosquatting,
    check_url_blacklist,
    run_all_checks,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse(raw: str) -> email.message.Message:
    return email.message_from_string(textwrap.dedent(raw), policy=email.policy.default)


def _clean_email() -> email.message.Message:
    return _parse("""\
        Message-ID: <test@example.com>
        From: alice@example.com
        To: bob@example.com
        Subject: Hello
        Date: Thu, 01 Jan 2026 10:00:00 +0000
        X-Mailer: TestMailer/1.0
        Authentication-Results: mx1.example.com; spf=pass; dkim=pass; dmarc=pass

        Clean email body.
    """)


# ── check_spf_dkim_dmarc ──────────────────────────────────────────────────────


class TestSpfDkimDmarc:
    @pytest.mark.asyncio
    async def test_all_pass_score_zero(self):
        """spf=pass dkim=pass dmarc=pass → score 0."""
        msg = _clean_email()
        result = await check_spf_dkim_dmarc(msg)
        assert result.score == 0
        assert result.passed is True
        assert result.name == "spf_dkim_dmarc"

    @pytest.mark.asyncio
    async def test_dmarc_fail_adds_25(self):
        """dmarc=fail → score 25."""
        msg = _parse("""\
            Authentication-Results: mx1.example.com; spf=pass; dkim=pass; dmarc=fail
            From: attacker@evil.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Body.
        """)
        result = await check_spf_dkim_dmarc(msg)
        assert result.score == 25
        assert result.passed is False
        assert "DMARC=fail" in result.detail

    @pytest.mark.asyncio
    async def test_dmarc_fail_dkim_fail_spf_fail_score_50(self):
        """dmarc=fail + dkim=fail + spf=fail → score 25+15+10=50."""
        msg = _parse("""\
            Authentication-Results: mx1.example.com; spf=fail; dkim=fail; dmarc=fail
            From: bad@evil.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Body.
        """)
        result = await check_spf_dkim_dmarc(msg)
        assert result.score == 50
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_no_auth_headers_no_dmarc_policy(self):
        """No Authentication-Results; checkdmarc says no DMARC → score 10."""
        msg = _parse("""\
            From: sender@nodmarc.example
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Body.
        """)
        with patch(
            "core.analysis.l1_static._check_domain_has_dmarc", return_value=False
        ):
            result = await check_spf_dkim_dmarc(msg)
        assert result.score == 10
        assert result.passed is False

    @pytest.mark.asyncio
    async def test_dmarc_missing_from_auth_results(self):
        """Auth header present but DMARC absent → score 10."""
        msg = _parse("""\
            Authentication-Results: mx1.example.com; spf=pass; dkim=pass
            From: sender@example.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Body.
        """)
        result = await check_spf_dkim_dmarc(msg)
        assert result.score == 10
        assert "DMARC not evaluated" in result.detail


# ── check_ip_reputation ───────────────────────────────────────────────────────


class TestIpReputation:
    @pytest.mark.asyncio
    async def test_listed_ip_score_30(self):
        """IP in Spamhaus ZEN → score 30."""
        msg = _parse("""\
            Received: from mail.evil.com ([1.2.3.4]) by mx.example.com
            From: bad@evil.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Body.
        """)
        with patch("core.analysis.l1_static._zen_listed", return_value=True):
            result = await check_ip_reputation(msg)
        assert result.score == 30
        assert result.passed is False
        assert "1.2.3.4" in result.detail

    @pytest.mark.asyncio
    async def test_clean_ip_score_zero(self):
        """IP not in any DNSBL → score 0."""
        msg = _parse("""\
            Received: from mail.legit.com ([8.8.8.8]) by mx.example.com
            From: legit@legit.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Body.
        """)
        with patch("core.analysis.l1_static._zen_listed", return_value=False):
            result = await check_ip_reputation(msg)
        assert result.score == 0
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_no_received_header_score_zero(self):
        """No Received header → score 0 (no IP to check)."""
        msg = _parse("""\
            From: sender@example.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Body.
        """)
        result = await check_ip_reputation(msg)
        assert result.score == 0
        assert "No external sender IP" in result.detail

    @pytest.mark.asyncio
    async def test_private_ip_ignored(self):
        """Private IPs in Received headers are skipped."""
        msg = _parse("""\
            Received: from localhost ([127.0.0.1]) by mx.example.com
            Received: from internal ([192.168.1.1]) by mx.example.com
            From: sender@example.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Body.
        """)
        result = await check_ip_reputation(msg)
        assert result.score == 0
        assert "No external sender IP" in result.detail


# ── check_typosquatting ───────────────────────────────────────────────────────


def _mock_pool(domains: list[str]) -> AsyncMock:
    pool = AsyncMock()
    pool.fetch = AsyncMock(return_value=[{"domain": d} for d in domains])
    return pool


class TestTyposquatting:
    @pytest.mark.asyncio
    async def test_exact_domain_score_zero(self):
        """Exact match in known_domains → score 0."""
        msg = _parse("From: alice@paypal.com\nDate: Thu, 01 Jan 2026 10:00:00 +0000\n\nBody.")
        result = await check_typosquatting(msg, _mock_pool(["paypal.com", "google.com"]))
        assert result.score == 0
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_distance_1_score_40(self):
        """Domain 1 edit from known domain → score 40."""
        msg = _parse("From: user@paypa1.com\nDate: Thu, 01 Jan 2026 10:00:00 +0000\n\nBody.")
        result = await check_typosquatting(msg, _mock_pool(["paypal.com"]))
        assert result.score == 40
        assert result.passed is False
        assert "distance 1" in result.detail

    @pytest.mark.asyncio
    async def test_distance_2_score_20(self):
        """Domain 2 edits from known domain → score 20."""
        msg = _parse("From: user@paypa11.com\nDate: Thu, 01 Jan 2026 10:00:00 +0000\n\nBody.")
        result = await check_typosquatting(msg, _mock_pool(["paypal.com"]))
        assert result.score == 20
        assert result.passed is False
        assert "distance 2" in result.detail

    @pytest.mark.asyncio
    async def test_no_match_score_zero(self):
        """Domain far from all known domains → score 0."""
        msg = _parse("From: user@completely-different.org\nDate: Thu, 01 Jan 2026 10:00:00 +0000\n\nBody.")
        result = await check_typosquatting(msg, _mock_pool(["paypal.com", "google.com"]))
        assert result.score == 0
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_empty_known_domains(self):
        """Empty known_domains table → score 0."""
        msg = _parse("From: user@example.com\nDate: Thu, 01 Jan 2026 10:00:00 +0000\n\nBody.")
        result = await check_typosquatting(msg, _mock_pool([]))
        assert result.score == 0
        assert "empty" in result.detail


# ── check_url_blacklist ───────────────────────────────────────────────────────


def _mock_redis(cached: bytes | None = None) -> AsyncMock:
    r = AsyncMock()
    r.get = AsyncMock(return_value=cached)
    r.setex = AsyncMock()
    return r


class TestUrlBlacklist:
    @pytest.mark.asyncio
    async def test_no_urls_score_zero(self):
        """Email with no URLs → score 0."""
        msg = _parse("""\
            From: sender@example.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Just plain text, no URLs here.
        """)
        result = await check_url_blacklist(msg, _mock_redis())
        assert result.score == 0
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_clean_urls_score_zero(self):
        """URLs not in any blacklist → score 0."""
        msg = _parse("""\
            From: sender@example.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Visit https://safe.example.com for info.
        """)
        cached = b"https://evil-phishing.com\nhttps://malware.example.net"
        redis = _mock_redis(cached=cached)
        result = await check_url_blacklist(msg, redis)
        assert result.score == 0
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_blacklisted_url_score_35(self):
        """URL matching cache entry → score 35."""
        msg = _parse("""\
            From: sender@example.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Click here: https://evil-phishing.com/steal
        """)
        cached = b"https://evil-phishing.com/steal\nhttps://other-bad.com"
        redis = _mock_redis(cached=cached)
        result = await check_url_blacklist(msg, redis)
        assert result.score == 35
        assert result.passed is False
        assert "evil-phishing.com" in result.detail

    @pytest.mark.asyncio
    async def test_feed_fetch_on_cache_miss(self):
        """On cache miss the feed is fetched and result cached."""
        msg = _parse("""\
            From: sender@example.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Visit https://phish-target.com/login
        """)
        redis = _mock_redis(cached=None)

        with patch(
            "core.analysis.l1_static._fetch_url_feed",
            new=AsyncMock(return_value=["https://phish-target.com/login"]),
        ):
            result = await check_url_blacklist(msg, redis)

        assert result.score == 35
        redis.setex.assert_called()

    @pytest.mark.asyncio
    async def test_feed_fetch_failure_scores_zero(self):
        """If feed fetch fails, the check returns score 0 (fail open)."""
        msg = _parse("""\
            From: sender@example.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Visit https://unknown.example.com/page
        """)
        redis = _mock_redis(cached=None)

        with patch(
            "core.analysis.l1_static._fetch_url_feed",
            new=AsyncMock(side_effect=Exception("network error")),
        ):
            result = await check_url_blacklist(msg, redis)

        assert result.score == 0
        assert result.passed is True


# ── check_header_anomalies ────────────────────────────────────────────────────


class TestHeaderAnomalies:
    @pytest.mark.asyncio
    async def test_clean_email_score_zero(self):
        """Well-formed email headers → score 0."""
        msg = _clean_email()
        result = await check_header_anomalies(msg)
        assert result.score == 0
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_reply_to_different_domain_score_15(self):
        """Reply-To domain differs from From domain → +15."""
        msg = _parse("""\
            From: ceo@legit-company.com
            Reply-To: reply@attacker.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000
            X-Mailer: TestMailer

            BEC bait.
        """)
        result = await check_header_anomalies(msg)
        assert result.score >= 15
        assert "Reply-To domain" in result.detail

    @pytest.mark.asyncio
    async def test_missing_date_score_10(self):
        """Missing Date header → +10."""
        msg = _parse("""\
            From: sender@example.com
            X-Mailer: TestMailer

            No date.
        """)
        result = await check_header_anomalies(msg)
        assert result.score >= 10
        assert "Date header missing" in result.detail

    @pytest.mark.asyncio
    async def test_multiple_from_headers_score_20(self):
        """Multiple From headers → +20."""
        # Build message manually to inject duplicate From
        raw = (
            "From: real@example.com\r\n"
            "From: spoof@evil.com\r\n"
            "Date: Thu, 01 Jan 2026 10:00:00 +0000\r\n"
            "X-Mailer: TestMailer\r\n"
            "\r\n"
            "Body."
        )
        msg = email.message_from_string(raw)
        result = await check_header_anomalies(msg)
        assert result.score >= 20
        assert "Multiple From" in result.detail

    @pytest.mark.asyncio
    async def test_missing_xmailer_non_automated_adds_5(self):
        """Missing X-Mailer on a non-automated sender → +5."""
        msg = _parse("""\
            From: user@company.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Body.
        """)
        result = await check_header_anomalies(msg)
        assert result.score >= 5
        assert "X-Mailer" in result.detail

    @pytest.mark.asyncio
    async def test_no_xmailer_penalty_for_noreply(self):
        """Automated senders (noreply) are not penalised for missing X-Mailer."""
        msg = _parse("""\
            From: noreply@service.com
            Date: Thu, 01 Jan 2026 10:00:00 +0000

            Body.
        """)
        result = await check_header_anomalies(msg)
        # Score must not include +5 X-Mailer penalty
        assert "X-Mailer" not in result.detail


# ── run_all_checks ────────────────────────────────────────────────────────────


class TestRunAllChecks:
    @pytest.mark.asyncio
    async def test_returns_five_results(self):
        """run_all_checks always returns exactly 5 CheckResult objects."""
        msg = _clean_email()
        pool = _mock_pool(["example.com"])
        redis = _mock_redis(cached=b"")

        with (
            patch("core.analysis.l1_static._zen_listed", return_value=False),
            patch("core.analysis.l1_static._check_domain_has_dmarc", return_value=True),
        ):
            results = await run_all_checks(msg, pool, redis)

        assert len(results) == 5
        names = {r.name for r in results}
        assert names == {
            "spf_dkim_dmarc",
            "ip_reputation",
            "typosquatting",
            "url_blacklist",
            "header_anomalies",
        }

    @pytest.mark.asyncio
    async def test_check_exception_does_not_abort_pipeline(self):
        """If one check raises, the others still run."""
        msg = _clean_email()
        pool = AsyncMock()
        pool.fetch = AsyncMock(side_effect=RuntimeError("DB down"))
        redis = _mock_redis(cached=b"")

        with (
            patch("core.analysis.l1_static._zen_listed", return_value=False),
            patch("core.analysis.l1_static._check_domain_has_dmarc", return_value=True),
        ):
            results = await run_all_checks(msg, pool, redis)

        assert len(results) == 5
        # typosquatting failed, others succeeded
        failed = [r for r in results if "exception" in r.detail.lower()]
        assert len(failed) == 1
        assert failed[0].name == "typosquatting"
