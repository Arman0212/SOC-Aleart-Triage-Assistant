-- 001: analyst accounts, in their own database (ACCOUNTS_DB_PATH), so resetting the demo shift
-- never touches them. Passwords and one-time codes are stored only as hashes. Usernames and email
-- addresses are unique without regard to case: the *_key columns hold the lower-cased forms.

CREATE TABLE accounts (
    username        TEXT PRIMARY KEY,
    username_key    TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL,
    email_key       TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    verified_at     TEXT,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT
);

-- One-time codes for confirming an email address and for resetting a password. Issuing a new
-- code for the same purpose retires the older ones (used_at is set).
CREATE TABLE codes (
    id          INTEGER PRIMARY KEY,
    username    TEXT NOT NULL REFERENCES accounts(username) ON DELETE CASCADE,
    purpose     TEXT NOT NULL CHECK (purpose IN ('verify', 'reset')),
    code_hash   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    used_at     TEXT
);
CREATE INDEX codes_by_account ON codes (username, purpose, id);
