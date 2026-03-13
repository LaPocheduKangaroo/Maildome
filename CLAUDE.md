# MailDome — Agent Context

This file is the single source of truth for any AI agent working on this codebase.
Read it entirely before touching any file.

---

## What MailDome is

Open source email security platform for SMEs. Receives async copies of emails,
analyses them through a multi-layer pipeline, returns a verdict via banner in the
user's mail client. The primary mail server delivers normally — MailDome is never
in the mail flow. If MailDome goes down, email is delivered anyway.

GitHub: https://github.com/LaPocheduKangaroo/Maildome
Branch convention: work on `dev`, `main` is for releases only.

---

## Core philosophy — never deviate from these

1. Inform, don't block. Default action is always banner. Blocking and quarantine
   are opt-in, configured by the admin.
2. Maximum configurability. Every threshold, weight, and behaviour has a
   documented default in mailshield.conf and can be overridden. Nothing hardcoded.
3. Start simple, harden later. No gold-plating. Each block delivers something
   testable.
4. SME-first. Target is a sysadmin managing 20–100 users, possibly alone.
   Complexity must be justified.
5. Defense against the 99.9%. Mass automated attacks, not APTs. Targeted
   nation-state attacks are out of scope.

---

## Architecture

MailDome does NOT sit in the mail flow. It receives a copy via:
- IMAP (primary — IDLE push, polling fallback)
- SMTP Journaling (O365, Google Workspace)
- Milter (local Postfix)

### Pipeline levels

| Level | Name | Tier |
|-------|------|------|
| L0 | Acquisition | All |
| L1 | Static Analysis | All |
| L2 | Sender Behaviour | Advanced + Premium |
| L3 | Attachment Triage | Advanced + Premium |
| L4 | VM Sandbox | Premium only |
| L5 | Decision Engine | All |
| L6 | Orchestrator | All |
| L7 | Infrastructure Security | All |
| L8 | Dashboard / API | All |

### Deployment tiers

| | Basic | Advanced | Premium |
|---|---|---|---|
| Pipeline | L0→L1→L5 | L0→L2→L3→L5 | L0→L4→L5 |
| Servers | 1 | 1 | 2 |
| LDAP | ✗ | ✓ | ✓ |
| ClamAV | ✗ | ✓ gVisor | ✓ gVisor |
| BEC detection | ✗ | ✓ | ✓ |
| VM Sandbox | ✗ | ✗ | ✓ dedicated |
| Score display | 3 states | 5 color bands | 0–100 numeric |

### Recipient profiles

| Profile | Levels | L4 trigger | Default |
|---------|--------|------------|---------|
| CRITICAL | L0–L4 always | always | banner + configurable |
| HIGH | L0–L3+L5 | score ≥ 5 | banner |
| STANDARD | L0–L2+L5 | score ≥ 7 | banner |
| LOW | L0–L1+L5 | never | banner |
| RED_TEAM | L0–L4 always | always | block disabled, verbose log |

Policy resolution: exact address → AD group → department → domain → global default.
Multi-recipient: most restrictive profile wins.

---

## Tech stack

- Runtime: Python 3.11
- API: FastAPI + uvicorn
- Task queue: Celery + Redis
- Database: PostgreSQL 15 (asyncpg)
- Cache / queue: Redis 7
- Mail reception: Postfix (Docker), aioimaplib
- Auth: Keycloak JWT (Block 6+)
- Monitoring: Prometheus + Grafana (optional, Advanced+)
- NLP: spaCy (Block 4, L2)
- Antivirus: ClamAV in gVisor (Advanced+)
- Sandbox: CAPE (Premium only)
- Logging: structlog (JSON)
- Tests: pytest + pytest-asyncio

---

## Codebase structure

```
mailshield/
├── api/
│   ├── __init__.py
│   └── main.py              ← FastAPI entry point, health check
├── core/
│   ├── acquisition/
│   │   ├── __init__.py
│   │   ├── imap_client.py   ← IMAP IDLE + polling, reconnect backoff
│   │   ├── dispatcher.py    ← SHA256 dedup, .eml storage, DB insert, Celery enqueue
│   │   └── runner.py        ← asyncio entry point, SIGINT/SIGTERM handling
│   ├── analysis/
│   │   └── __init__.py      ← empty, Block 4 fills this
│   ├── config/
│   │   ├── config.py        ← settings loader, singleton, exits on misconfiguration
│   │   ├── mailshield.conf  ← fully commented defaults
│   │   └── schema.sql       ← tables: emails, check_results, audit_log, known_domains
│   └── engine/
│       ├── __init__.py
│       └── worker.py        ← Celery app, scan_email task stub
├── tests/
│   ├── __init__.py
│   ├── conftest.py          ← sets MAILSHIELD_CONFIG before imports
│   └── test_acquisition.py  ← 12 unit tests, all mocked
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
└── CLAUDE.md                ← this file
```

---

## Key design decisions — do not revisit without reason

**SHA256 deduplication**: computed on raw email bytes, checked in Redis
(key: `dedup:<sha256>`, TTL = dedup_window_hours * 3600). DB has a secondary
guard via ON CONFLICT DO NOTHING on message_id.

**IMAP IDLE**: re-IDLE every 29 minutes to stay within RFC 2177's 30-minute limit.
Exponential backoff on reconnect: 5s → 10s → ... → 120s max.

**ClamAV placement**: L3 only (Advanced+), inside gVisor container. Not in Basic —
running ClamAV directly on the host without gVisor reintroduces parser exploitation
risk. This was a deliberate decision.

**AI text analysis**: removed. Cost/benefit ratio was unfavourable (governance,
external data dependency, latency, cost). NLP phishing pattern detection via spaCy
is sufficient and runs locally.

**CAPE only for L4**: active Cuckoo fork. Guest OS is configurable by admin — no
default imposed. Video conferencing whitelist bypass requires all three: SPF/DKIM/DMARC
pass + known official domain + no executable attachment.

**Decision engine**: weighted aggregate score, normalized when checks are disabled
(disabled checks reduce max proportionally, not the score). Thresholds configurable.
Override requires mandatory reason field, logged to audit_log (append-only,
no delete API).

**BEC detection**: reads executive list from LDAP only. Never manual input.
LDAP proxy is read-only, never touches AD directly.

**Circuit breaker**: auto-restart → degraded banner → admin email notification.
Dead letter produces banner "integrity unknown", email delivered.

---

## Block development status

| Block | Description | Status |
|-------|-------------|--------|
| 1 | Project skeleton, Docker Compose | ✓ done |
| 2 | Config system, DB/Redis connections | ✓ done |
| 3 | L0 Acquisition — IMAP module | ✓ done |
| 4 | L1 Static Analysis | ✓ done |
| 5 | L5 Decision Engine | ✓ done |
| 6 | API complete + auth | ✓ done |
| 7 | Thunderbird plugin | ✓ done |
| 8 | install.sh | ✓ done |

---

## Block 4 — L1 Static Analysis spec

Implement `core/analysis/l1_static.py` with the following checks.
Each check returns a `CheckResult(name, score, detail)`.
All checks must be independent — one failure must not prevent others from running.

### Checks to implement

**spf_dkim_dmarc**
Use `checkdmarc` library. Parse email headers for SPF, DKIM, DMARC results.
- DMARC pass → score 0
- DMARC fail → score 25
- DMARC missing → score 10
- DKIM fail → score +15
- SPF fail → score +10

**ip_reputation**
Extract sender IP from Received headers.
Query Spamhaus ZEN (zen.spamhaus.org) via DNS lookup (dnspython).
- Listed → score 30
- Not listed → score 0
Custom blacklist path configurable in mailshield.conf.

**typosquatting**
Extract sender domain. Compare against known_domains table in PostgreSQL
using Levenshtein distance (python-Levenshtein).
- Distance 1 from a known domain → score 40
- Distance 2 → score 20
- Clean → score 0
known_domains is populated from Tranco top 1M list (update script separate).

**url_blacklist**
Extract all URLs from email body (plain text + HTML).
Query OpenPhish feed and PhishTank feed (cached in Redis, TTL 1 hour).
- Any URL matches → score 35
- Clean → score 0
Custom blacklist path configurable in mailshield.conf.

**header_anomalies**
Rule-based checks on email headers:
- Reply-To domain differs from From domain → score 15
- X-Mailer missing on non-automated sender → score 5
- Date header missing or malformed → score 10
- Multiple From headers → score 20

### Integration

Update `core/engine/worker.py` scan_email task to:
1. Load email from storage_path/<sha256>.eml
2. Run all L1 checks
3. Write results to check_results table
4. Update emails table with partial score

### Tests

Write `tests/test_l1_static.py` with unit tests for each check.
All external calls (DNS, Redis, DB) must be mocked.
Minimum 3 tests per check.

---

## Coding conventions

- Async everywhere (asyncio, asyncpg, redis.asyncio, aioimaplib)
- structlog for all logging — JSON format, no print statements
- Pydantic for data validation at API boundaries
- Type hints on all functions
- Docstrings on public methods only — one line is enough
- No bare except — catch specific exceptions, log and re-raise or handle
- Config always from settings singleton — never os.environ directly in business logic
- Tests: pytest-asyncio, all external services mocked, no real connections in unit tests

---

## Git conventions

- Branch: always work on `dev`
- Commit format: `type: Block N — short description`
  - types: feat, fix, docs, test, refactor
- Commit at end of each block, never mid-block
- Never commit .env — only .env.example

---

## What NOT to do

- Do not add Keycloak auth before Block 6 — simple token auth is enough for now
- Do not implement L2/L3/L4 logic — those are Advanced/Premium tier, out of scope for Basic
- Do not add Elasticsearch — PostgreSQL is the default log store
- Do not add Prometheus/Grafana — optional, Advanced+ only
- Do not hardcode any threshold, IP, domain, or credential
- Do not use synchronous I/O in async context
