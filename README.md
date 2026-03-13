# MailDome

Open source email security platform for SMEs. Aggregates established tools into a multi-layer analysis pipeline. The software is free — the business model is managed hosting and support.

---

## Architecture

```
                         INBOUND EMAIL
                              │
                    ┌─────────▼─────────┐
               L0   │      Postfix       │  receive, save .eml (read-only),
                    │   + Celery/Redis   │  compute SHA256, create job
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
               L1   │   Static Analysis  │  SPF/DKIM/DMARC, IP reputation,
                    │                   │  typosquatting, URL blacklist
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
               L2   │ Sender Behaviour  │  Redis history, NLP phishing patterns,
                    │                   │  BEC detection via LDAP (read-only)
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐
               L3   │  Attachment Triage │  file type detection, ClamAV
                    │     (gVisor)       │  in isolated container
                    └─────────┬─────────┘
                              │
                    ┌─────────▼─────────┐  only if score threshold reached
               L4   │   VM Sandbox      │  CAPE, syscall/registry/network
                    │  (dedicated node) │  monitoring, Suricata, IoC extraction,
                    └─────────┬─────────┘  automatic snapshot rollback
                              │
                    ┌─────────▼─────────┐
               L5   │  Decision Engine  │  weighted aggregate score,
                    │                   │  configurable thresholds and actions
                    └─────────┬─────────┘
                              │
               ┌──────────────┴──────────────┐
               │                             │
     ┌─────────▼─────────┐       ┌───────────▼───────────┐
L6   │  Celery Orchestr.  │  L7   │  Infra Security        │
     │  priority queues,  │       │  VLANs, OPNsense,      │
     │  circuit breaker   │       │  Vault, immutable logs  │
     └─────────┬─────────┘       └───────────────────────┘
               │
     ┌─────────▼─────────┐
L8   │  Dashboard / API   │  FastAPI, Keycloak RBAC, TheHive,
     │                   │  Prometheus, Grafana, Elasticsearch
     └───────────────────┘
```

**Fast path / Deep path** — 95% of emails are classified in under 2 seconds at L1–L2. Only emails that exceed the score threshold progress to L3 and L4. SHA256 deduplication prevents re-analysis of identical emails within the configured window.

---

## Deployment Tiers

| | Basic | Advanced | Premium |
|---|---|---|---|
| Pipeline | L0→L1→L5 | L0→L2→L3→L5 | L0→L4→L5 |
| Architecture | single server | single server | two servers |
| LDAP integration | ✗ | ✓ | ✓ |
| ClamAV | ✗ | ✓ gVisor | ✓ gVisor |
| BEC detection | ✗ | ✓ | ✓ |
| VM Sandbox | ✗ | ✗ | ✓ dedicated node |
| Score display | 3 states | 5 color bands | 0–100 numeric |
| Threat coverage | ~90% | ~95% | ~98% |

---

## Recipient Profiles

| Profile  | Levels active   | L4 trigger | Default action |
|----------|-----------------|------------|----------------|
| CRITICAL | L0–L4 always    | always     | banner + configurable |
| HIGH     | L0–L3 + L5      | score ≥ 5  | banner |
| STANDARD | L0–L2 + L5      | score ≥ 7  | banner |
| LOW      | L0–L1 + L5      | never      | banner |
| RED_TEAM | L0–L4 always    | always     | block disabled, verbose log |

Policy resolution order: exact address → AD group → department → domain → global default. For multi-recipient emails, the most restrictive profile wins.

---

## Philosophy

MailDome does not intercept mail flow. The primary mail server delivers normally. MailDome receives an async copy, analyses it, and returns a verdict via banner. If MailDome is unavailable, email is delivered anyway.

Default action is always banner — never block, never quarantine. Blocking is opt-in. Every parameter has a documented default and can be overridden. Nothing is hardcoded.

---

## Requirements

### Basic — single node (Docker Compose)

| Resource | Minimum |
|----------|---------|
| CPU      | 2 cores |
| RAM      | 4 GB    |
| Disk     | 30 GB SSD |
| OS       | Ubuntu 22.04 LTS |

### Advanced — single node

| Resource | Minimum |
|----------|---------|
| CPU      | 4 cores |
| RAM      | 8 GB    |
| Disk     | 60 GB SSD |
| OS       | Ubuntu 22.04 LTS |

### Premium — two nodes

| Node | CPU | RAM | Notes |
|------|-----|-----|-------|
| Main server | 8 cores | 16 GB | full pipeline |
| VM sandbox | 8 cores | 16 GB | CAPE, isolated VLAN, KVM required |

---

## Quick Start

```bash
curl -sSL https://raw.githubusercontent.com/LaPocheduKangaroo/Maildome/main/install.sh | bash
```

The installer walks through 5 questions, recommends a tier, and deploys the stack.

---

## Development Status

| Block | Description | Status |
|-------|-------------|--------|
| 1 | Project skeleton, Docker Compose | ✓ |
| 2 | Config system, DB/Redis connections | ✓ |
| 3 | L0 Acquisition — IMAP IDLE + polling | ✓ |
| 4 | L1 Static Analysis — SPF/DKIM/DMARC, IP reputation, typosquatting, URL blacklist, header anomalies | ✓ |
| 5 | L5 Decision Engine — weighted score, configurable thresholds, CLEAN/SUSPICIOUS/DANGEROUS | ✓ |
| 6 | REST API — email list/detail, verdict override, audit log, bearer token auth | ✓ |
| 7 | Thunderbird plugin — verdict banner, settings popup | ✓ |
| 8 | install.sh — interactive installer, tier recommendation, secrets generation | ✓ |
| 9 | L2 Sender Behaviour (Advanced tier) | ⬜ |
| 10 | L3 Attachment Triage — ClamAV in gVisor (Advanced tier) | ⬜ |
| 11 | L4 VM Sandbox — CAPE (Premium tier) | ⬜ |
| 12 | Keycloak RBAC + multi-tenant API | ⬜ |

---

## Stack

Postfix · ClamAV · YARA · oletools · CAPE · MISP · TheHive · Suricata · Celery · Redis · PostgreSQL · FastAPI · spaCy · Keycloak · Vault · Prometheus · Grafana · Elasticsearch

---

## License

[MIT](LICENSE)
