-- 001: initial schema. One prepared shift is a batch; everything else hangs off batch_id.
-- Timestamps are ISO-8601 UTC strings ("...Z" or "+00:00").

CREATE TABLE batches (
    batch_id          TEXT PRIMARY KEY,
    prepared_at       TEXT NOT NULL,
    source_dir        TEXT NOT NULL,
    alert_count       INTEGER NOT NULL,
    incident_count    INTEGER NOT NULL,
    first_alert_at    TEXT NOT NULL,
    last_alert_at     TEXT NOT NULL,
    timezone          TEXT NOT NULL,
    attack_version    TEXT NOT NULL,
    prompt_version    TEXT,
    model             TEXT,
    pipeline_seconds  REAL NOT NULL,
    briefing_seconds  REAL,
    config_json       TEXT NOT NULL
);

CREATE TABLE alerts (
    batch_id     TEXT NOT NULL REFERENCES batches(batch_id),
    alert_id     TEXT NOT NULL,
    incident_id  TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    alert_json   TEXT NOT NULL,
    PRIMARY KEY (batch_id, alert_id)
);
CREATE INDEX alerts_by_incident ON alerts (batch_id, incident_id, timestamp);

CREATE TABLE incidents (
    batch_id       TEXT NOT NULL REFERENCES batches(batch_id),
    incident_id    TEXT NOT NULL,
    rank           INTEGER NOT NULL,
    tier           TEXT NOT NULL CHECK (tier IN ('P1', 'P2', 'P3', 'P4')),
    risk           REAL NOT NULL,
    status         TEXT NOT NULL DEFAULT 'open'
                   CHECK (status IN ('open', 'approved', 'dismissed', 'escalated')),
    asset          TEXT,
    criticality    INTEGER NOT NULL,
    tactics_json   TEXT NOT NULL,
    alert_count    INTEGER NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    incident_json  TEXT NOT NULL,
    detail_json    TEXT NOT NULL,
    PRIMARY KEY (batch_id, incident_id)
);
CREATE INDEX incidents_by_rank ON incidents (batch_id, rank);
CREATE INDEX incidents_by_tier ON incidents (batch_id, tier);
CREATE INDEX incidents_by_status ON incidents (batch_id, status);

CREATE TABLE links (
    id           INTEGER PRIMARY KEY,
    batch_id     TEXT NOT NULL REFERENCES batches(batch_id),
    incident_id  TEXT NOT NULL,
    alert_id     TEXT NOT NULL,
    linked_to    TEXT NOT NULL,
    reason       TEXT NOT NULL,
    entity       TEXT NOT NULL,
    gap_seconds  REAL NOT NULL,
    rule_name    TEXT
);
CREATE INDEX links_by_incident ON links (batch_id, incident_id);

CREATE TABLE hubs (
    batch_id        TEXT NOT NULL REFERENCES batches(batch_id),
    entity          TEXT NOT NULL,
    alerts          INTEGER NOT NULL,
    share           REAL NOT NULL,
    distinct_users  INTEGER NOT NULL,
    fanout          INTEGER NOT NULL,
    reasons_json    TEXT NOT NULL,
    PRIMARY KEY (batch_id, entity)
);

CREATE TABLE briefs (
    batch_id               TEXT NOT NULL REFERENCES batches(batch_id),
    incident_id            TEXT NOT NULL,
    brief_json             TEXT NOT NULL,
    context_json           TEXT NOT NULL,
    generated_by           TEXT NOT NULL,
    validated              INTEGER NOT NULL,
    confidence             TEXT NOT NULL,
    path                   TEXT NOT NULL,
    attempts               INTEGER NOT NULL,
    latency_seconds        REAL NOT NULL,
    prompt_version         TEXT NOT NULL,
    model                  TEXT NOT NULL,
    cache_hit              INTEGER NOT NULL,
    fallback_reason        TEXT,
    model_confidence       TEXT,
    validation_errors_json TEXT NOT NULL,
    PRIMARY KEY (batch_id, incident_id)
);

-- Phase 7 study runs. Decisions made while no session runs have study_session NULL.
CREATE TABLE study_sessions (
    session_id  TEXT PRIMARY KEY,
    analyst     TEXT NOT NULL,
    batch_id    TEXT NOT NULL REFERENCES batches(batch_id),
    started_at  TEXT NOT NULL,
    ended_at    TEXT
);
CREATE UNIQUE INDEX one_running_session_per_analyst
    ON study_sessions (analyst) WHERE ended_at IS NULL;

-- When triage of an incident started. Closed (decision_id set) by the decision it led to.
CREATE TABLE openings (
    id             INTEGER PRIMARY KEY,
    batch_id       TEXT NOT NULL,
    incident_id    TEXT NOT NULL,
    analyst        TEXT NOT NULL,
    study_session  TEXT REFERENCES study_sessions(session_id),
    opened_at      TEXT NOT NULL,
    decision_id    INTEGER REFERENCES decisions(id)
);
CREATE INDEX openings_open ON openings (batch_id, incident_id, analyst) WHERE decision_id IS NULL;

CREATE TABLE decisions (
    id              INTEGER PRIMARY KEY,
    batch_id        TEXT NOT NULL,
    incident_id     TEXT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('approve', 'edit', 'dismiss', 'escalate')),
    analyst         TEXT NOT NULL,
    opened_at       TEXT NOT NULL,
    decided_at      TEXT NOT NULL,
    triage_seconds  REAL NOT NULL CHECK (triage_seconds >= 0),
    edited_brief    TEXT,
    notes           TEXT,
    study_session   TEXT REFERENCES study_sessions(session_id),
    decision_json   TEXT NOT NULL
);
CREATE INDEX decisions_by_incident ON decisions (batch_id, incident_id, decided_at);
CREATE INDEX decisions_by_session ON decisions (study_session);

-- Append-only: rows can be inserted, never changed or removed.
CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY,
    at            TEXT NOT NULL,
    actor         TEXT NOT NULL,
    event         TEXT NOT NULL,
    batch_id      TEXT,
    incident_id   TEXT,
    payload_json  TEXT NOT NULL DEFAULT '{}'
);
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
