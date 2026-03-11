-- MailShield Basic — database schema
-- PostgreSQL 15+
-- Applied automatically on first start via docker-compose

-- Email scan records
CREATE TABLE IF NOT EXISTS emails (
    id              SERIAL PRIMARY KEY,
    message_id      TEXT NOT NULL UNIQUE,   -- from email headers
    sha256          TEXT NOT NULL,          -- for deduplication
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sender          TEXT NOT NULL,
    recipient       TEXT NOT NULL,
    subject         TEXT,
    storage_path    TEXT NOT NULL,          -- path to .eml file

    -- Verdict
    verdict         TEXT,                   -- CLEAN | SUSPICIOUS | DANGEROUS | PENDING | FAILED
    score           INTEGER,                -- 0–100 normalized
    scanned_at      TIMESTAMPTZ,

    -- Profile applied
    profile         TEXT NOT NULL DEFAULT 'standard'
);

-- Individual check results (one row per check per email)
CREATE TABLE IF NOT EXISTS check_results (
    id          SERIAL PRIMARY KEY,
    email_id    INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    check_name  TEXT NOT NULL,              -- spf_dkim_dmarc | ip_reputation | etc.
    passed      BOOLEAN NOT NULL,
    score       INTEGER NOT NULL,           -- raw score from this check
    detail      TEXT                        -- human-readable explanation
);

-- Audit log — append only, never delete
CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type  TEXT NOT NULL,              -- scan_complete | verdict_override | system_degraded | etc.
    email_id    INTEGER REFERENCES emails(id),
    actor       TEXT,                       -- system | username
    detail      JSONB                       -- structured event data
);

-- Typosquatting repository — built from mail history
CREATE TABLE IF NOT EXISTS known_domains (
    id              SERIAL PRIMARY KEY,
    domain          TEXT NOT NULL UNIQUE,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    email_count     INTEGER NOT NULL DEFAULT 1,
    source          TEXT NOT NULL           -- history | tranco | manual
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_emails_message_id  ON emails(message_id);
CREATE INDEX IF NOT EXISTS idx_emails_sha256       ON emails(sha256);
CREATE INDEX IF NOT EXISTS idx_emails_received_at  ON emails(received_at);
CREATE INDEX IF NOT EXISTS idx_emails_verdict      ON emails(verdict);
CREATE INDEX IF NOT EXISTS idx_check_results_email ON check_results(email_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created   ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_known_domains_domain ON known_domains(domain);
