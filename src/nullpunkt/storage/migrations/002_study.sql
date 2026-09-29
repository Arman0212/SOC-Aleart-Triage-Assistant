-- 002: the before/after study (Phase 7). A study session has an arm (baseline or tool), a
-- purpose (study, practice or dry-run; only "study" counts in results) and a time box. The
-- participant code is stored as the session's analyst. Baseline participants flag raw alerts.

ALTER TABLE study_sessions ADD COLUMN arm TEXT CHECK (arm IN ('baseline', 'tool'));
ALTER TABLE study_sessions ADD COLUMN purpose TEXT NOT NULL DEFAULT 'study'
    CHECK (purpose IN ('study', 'practice', 'dry-run'));
ALTER TABLE study_sessions ADD COLUMN time_box_seconds INTEGER CHECK (time_box_seconds > 0);
ALTER TABLE study_sessions ADD COLUMN end_reason TEXT;

-- Append-only, like the audit log: a flag records what the participant decided at that moment.
CREATE TABLE flags (
    id          INTEGER PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES study_sessions(session_id),
    batch_id    TEXT NOT NULL,
    alert_id    TEXT NOT NULL,
    note        TEXT,
    flagged_at  TEXT NOT NULL
);
CREATE INDEX flags_by_session ON flags (session_id, flagged_at);
CREATE TRIGGER flags_no_update BEFORE UPDATE ON flags
BEGIN
    SELECT RAISE(ABORT, 'flags are append-only');
END;
CREATE TRIGGER flags_no_delete BEFORE DELETE ON flags
BEGIN
    SELECT RAISE(ABORT, 'flags are append-only');
END;
