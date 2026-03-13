"""
l1_static.py — L1 Static Analysis checks for MailDome.

Each check accepts a parsed email.Message and returns a CheckResult.
All checks are independent — one failure does not prevent others from running.

Checks:
  spf_dkim_dmarc   — Authentication-Results header parsing + checkdmarc fallback
  ip_reputation    — Spamhaus ZEN DNSBL lookup
  typosquatting    — Levenshtein distance against known_domains table
  url_blacklist    — OpenPhish + PhishTank feeds (Redis-cached, 1h TTL)
  header_anomalies — Rule-based header inspection
"""

from __future__ import annotations

import asyncio
import email.utils
import ipaddress
import re
from dataclasses import dataclass
from email.message import Message
from html.parser import HTMLParser
from typing import Optional

import asyncpg
import dns.exception
import dns.resolver
import httpx
import Levenshtein
import structlog

from core.config.config import settings

log = structlog.get_logger()


# ── Data model ────────────────────────────────────────────────────────────────


@dataclass
class CheckResult:
    """Result of a single L1 check."""

    name: str
    score: int
    detail: str
    passed: bool


# ── URL helpers ───────────────────────────────────────────────────────────────

_URL_RE = re.compile(r"https?://[^\s<>\"'\\]+", re.IGNORECASE)


class _HtmlUrlExtractor(HTMLParser):
    """Collect href/src URLs from HTML markup."""

    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for attr, value in attrs:
            if attr in ("href", "src") and value and value.startswith("http"):
                self.urls.append(value)


def _extract_urls(msg: Message) -> list[str]:
    """Return all HTTP/HTTPS URLs from plain-text and HTML parts, deduplicated."""
    urls: set[str] = set()
    for part in msg.walk():
        ct = part.get_content_type()
        raw = part.get_payload(decode=True)
        if not raw:
            continue
        charset = part.get_content_charset() or "utf-8"
        text = raw.decode(charset, errors="replace")
        if ct in ("text/plain", "text/html"):
            urls.update(_URL_RE.findall(text))
        if ct == "text/html":
            parser = _HtmlUrlExtractor()
            parser.feed(text)
            urls.update(parser.urls)
    return list(urls)


# ── Sender IP helpers ─────────────────────────────────────────────────────────

_RECV_IP_RE = re.compile(
    r"(?:from\s+\S+\s+\()?\[(\d{1,3}(?:\.\d{1,3}){3})\]",
    re.IGNORECASE,
)


def _extract_sender_ip(msg: Message) -> Optional[str]:
    """Extract the first routable sender IP from Received headers."""
    for header in msg.get_all("Received") or []:
        for m in _RECV_IP_RE.finditer(header):
            try:
                ip = ipaddress.ip_address(m.group(1))
                if not ip.is_private and not ip.is_loopback and not ip.is_link_local:
                    return str(ip)
            except ValueError:
                continue
    return None


# ── Sender domain helper ──────────────────────────────────────────────────────


def _sender_domain(msg: Message) -> Optional[str]:
    """Extract the domain part of the From address."""
    m = re.search(r"@([\w.\-]+)", msg.get("From", ""))
    return m.group(1).lower() if m else None


# ── Check: spf_dkim_dmarc ─────────────────────────────────────────────────────

_AUTH_RE = re.compile(r"(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)


def _check_domain_has_dmarc(domain: str) -> bool:
    """Return True if the domain publishes a valid DMARC record (sync, for executor)."""
    try:
        import checkdmarc

        result = checkdmarc.check_dmarc(domain)
        return bool(result.get("valid", False))
    except Exception:
        return False


async def check_spf_dkim_dmarc(msg: Message) -> CheckResult:
    """Parse Authentication-Results headers for SPF/DKIM/DMARC; use checkdmarc as fallback."""
    auth_headers = msg.get_all("Authentication-Results") or []
    score = 0
    details: list[str] = []

    if auth_headers:
        found: dict[str, str] = {}
        for proto, result in _AUTH_RE.findall(" ".join(auth_headers)):
            found.setdefault(proto.lower(), result.lower())

        dmarc = found.get("dmarc")
        if dmarc is None:
            score += 10
            details.append("DMARC not evaluated in Authentication-Results")
        elif dmarc != "pass":
            score += 25
            details.append(f"DMARC={dmarc}")

        dkim = found.get("dkim")
        if dkim is not None and dkim not in ("pass", "none"):
            score += 15
            details.append(f"DKIM={dkim}")

        spf = found.get("spf")
        if spf is not None and spf not in ("pass", "none"):
            score += 10
            details.append(f"SPF={spf}")
    else:
        # No Authentication-Results — check if domain even publishes a DMARC policy
        domain = _sender_domain(msg)
        if domain:
            loop = asyncio.get_running_loop()
            has_dmarc = await loop.run_in_executor(None, _check_domain_has_dmarc, domain)
            if not has_dmarc:
                score += 10
                details.append(f"No DMARC policy published for {domain}")
            else:
                score += 10
                details.append("Authentication-Results headers missing (DMARC policy exists)")
        else:
            score += 10
            details.append("No Authentication-Results headers")

    detail = "; ".join(details) if details else "SPF/DKIM/DMARC pass"
    return CheckResult(name="spf_dkim_dmarc", score=score, detail=detail, passed=(score == 0))


# ── Check: ip_reputation ──────────────────────────────────────────────────────


def _zen_listed(ip: str) -> bool:
    """Return True if the IPv4 address is listed in Spamhaus ZEN (sync)."""
    reversed_ip = ".".join(reversed(ip.split(".")))
    try:
        dns.resolver.resolve(f"{reversed_ip}.zen.spamhaus.org", "A")
        return True
    except (dns.exception.DNSException, Exception):
        return False


async def check_ip_reputation(msg: Message) -> CheckResult:
    """Check sender IP against Spamhaus ZEN DNSBL."""
    ip = _extract_sender_ip(msg)
    if ip is None:
        return CheckResult(
            name="ip_reputation",
            score=0,
            detail="No external sender IP found in Received headers",
            passed=True,
        )

    loop = asyncio.get_running_loop()
    listed = await loop.run_in_executor(None, _zen_listed, ip)

    if listed:
        return CheckResult(
            name="ip_reputation",
            score=30,
            detail=f"Sender IP {ip} listed in Spamhaus ZEN",
            passed=False,
        )
    return CheckResult(
        name="ip_reputation",
        score=0,
        detail=f"Sender IP {ip} not listed in any DNSBL",
        passed=True,
    )


# ── Check: typosquatting ──────────────────────────────────────────────────────


async def check_typosquatting(msg: Message, db_pool: asyncpg.Pool) -> CheckResult:
    """Compare sender domain against known_domains table using Levenshtein distance."""
    domain = _sender_domain(msg)
    if domain is None:
        return CheckResult(
            name="typosquatting",
            score=0,
            detail="Could not extract sender domain",
            passed=True,
        )

    rows = await db_pool.fetch("SELECT domain FROM known_domains")
    if not rows:
        return CheckResult(
            name="typosquatting",
            score=0,
            detail="known_domains table is empty — skipping",
            passed=True,
        )

    min_dist: Optional[int] = None
    closest: Optional[str] = None

    for row in rows:
        kd = row["domain"]
        if kd == domain:
            return CheckResult(
                name="typosquatting",
                score=0,
                detail=f"{domain} is a known domain",
                passed=True,
            )
        dist = Levenshtein.distance(domain, kd)
        if min_dist is None or dist < min_dist:
            min_dist = dist
            closest = kd

    if min_dist == 1:
        return CheckResult(
            name="typosquatting",
            score=40,
            detail=f"{domain} is distance 1 from known domain {closest}",
            passed=False,
        )
    if min_dist == 2:
        return CheckResult(
            name="typosquatting",
            score=20,
            detail=f"{domain} is distance 2 from known domain {closest}",
            passed=False,
        )
    return CheckResult(
        name="typosquatting",
        score=0,
        detail=f"{domain}: closest known domain {closest!r} (dist={min_dist})",
        passed=True,
    )


# ── Check: url_blacklist ──────────────────────────────────────────────────────

_OPENPHISH_CACHE_KEY = "bl:openphish"
_PHISHTANK_CACHE_KEY = "bl:phishtank"
_FEED_TTL = 3600  # seconds

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.csv"


async def _fetch_url_feed(url: str) -> list[str]:
    """Fetch a URL feed and return non-empty lines."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(url)
        response.raise_for_status()
        return [line.strip() for line in response.text.splitlines() if line.strip()]


async def _get_blacklisted_urls(cache_key: str, feed_url: str, redis_client) -> set[str]:
    """Return the cached blacklist set, fetching from feed_url on cache miss."""
    cached = await redis_client.get(cache_key)
    if cached:
        return set(cached.decode().splitlines())
    try:
        urls = await _fetch_url_feed(feed_url)
        await redis_client.setex(cache_key, _FEED_TTL, "\n".join(urls))
        return set(urls)
    except Exception as exc:
        log.warning("url_feed_fetch_failed", url=feed_url, error=str(exc))
        return set()


async def check_url_blacklist(msg: Message, redis_client) -> CheckResult:
    """Check email URLs against OpenPhish and PhishTank feeds (Redis-cached, 1h TTL)."""
    urls = _extract_urls(msg)
    if not urls:
        return CheckResult(
            name="url_blacklist",
            score=0,
            detail="No URLs found in email body",
            passed=True,
        )

    blacklisted: set[str] = set()
    bl = settings.blacklists
    if bl.openphish:
        blacklisted |= await _get_blacklisted_urls(
            _OPENPHISH_CACHE_KEY, OPENPHISH_FEED_URL, redis_client
        )
    if bl.phishtank:
        blacklisted |= await _get_blacklisted_urls(
            _PHISHTANK_CACHE_KEY, PHISHTANK_FEED_URL, redis_client
        )

    matches = [u for u in urls if u in blacklisted]
    if matches:
        return CheckResult(
            name="url_blacklist",
            score=35,
            detail=f"Blacklisted URL(s): {', '.join(matches[:3])}",
            passed=False,
        )
    return CheckResult(
        name="url_blacklist",
        score=0,
        detail=f"Checked {len(urls)} URL(s), none blacklisted",
        passed=True,
    )


# ── Check: header_anomalies ───────────────────────────────────────────────────

_AUTOMATED_PATTERN = re.compile(
    r"(noreply|no-reply|mailer-daemon|postmaster|bounce|autorespond|listserv)",
    re.IGNORECASE,
)


async def check_header_anomalies(msg: Message) -> CheckResult:
    """Rule-based anomaly checks on standard email headers."""
    score = 0
    details: list[str] = []

    # Reply-To domain differs from From domain
    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    from_m = re.search(r"@([\w.\-]+)", from_addr)
    reply_m = re.search(r"@([\w.\-]+)", reply_to)
    if from_m and reply_m and from_m.group(1).lower() != reply_m.group(1).lower():
        score += 15
        details.append(
            f"Reply-To domain ({reply_m.group(1)}) differs from From domain ({from_m.group(1)})"
        )

    # X-Mailer missing (skip obviously automated senders)
    if msg.get("X-Mailer") is None and not _AUTOMATED_PATTERN.search(from_addr):
        score += 5
        details.append("X-Mailer header missing")

    # Date missing or malformed
    date_val = msg.get("Date")
    if date_val is None:
        score += 10
        details.append("Date header missing")
    else:
        try:
            if email.utils.parsedate_to_datetime(date_val) is None:
                raise ValueError("unparseable")
        except Exception:
            score += 10
            details.append(f"Date header malformed: {date_val!r}")

    # Multiple From headers
    from_count = len(msg.get_all("From") or [])
    if from_count > 1:
        score += 20
        details.append(f"Multiple From headers ({from_count})")

    detail = "; ".join(details) if details else "No header anomalies detected"
    return CheckResult(name="header_anomalies", score=score, detail=detail, passed=(score == 0))


# ── Entry point ───────────────────────────────────────────────────────────────


async def run_all_checks(
    msg: Message,
    db_pool: asyncpg.Pool,
    redis_client,
) -> list[CheckResult]:
    """Run all L1 checks independently. Exceptions are caught per-check."""
    named_checks: list[tuple[str, object]] = [
        ("spf_dkim_dmarc", check_spf_dkim_dmarc(msg)),
        ("ip_reputation", check_ip_reputation(msg)),
        ("typosquatting", check_typosquatting(msg, db_pool)),
        ("url_blacklist", check_url_blacklist(msg, redis_client)),
        ("header_anomalies", check_header_anomalies(msg)),
    ]
    results: list[CheckResult] = []
    for name, coro in named_checks:
        try:
            results.append(await coro)  # type: ignore[arg-type]
        except Exception as exc:
            log.error("l1_check_exception", check=name, error=str(exc))
            results.append(
                CheckResult(
                    name=name,
                    score=0,
                    detail=f"Check raised exception: {exc}",
                    passed=False,
                )
            )
    return results
