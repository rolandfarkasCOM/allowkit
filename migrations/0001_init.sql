-- AllowKit append-only audit log.
-- Every consent grant or withdrawal appends a row. No updates, no deletes.

CREATE TABLE IF NOT EXISTS consent_audit (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_hash  TEXT    NOT NULL,
  app_id        TEXT    NOT NULL,
  action        TEXT    NOT NULL CHECK (action IN ('grant','withdraw')),
  necessary     INTEGER NOT NULL CHECK (necessary IN (0,1)),
  functional    INTEGER NOT NULL CHECK (functional IN (0,1)),
  analytics     INTEGER NOT NULL CHECK (analytics IN (0,1)),
  marketing     INTEGER NOT NULL CHECK (marketing IN (0,1)),
  ip_hash       TEXT,
  user_agent    TEXT,
  created_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_subject
  ON consent_audit (subject_hash, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_app
  ON consent_audit (app_id, created_at DESC);

-- Append-only enforcement at the DB level.
-- Any attempt to UPDATE or DELETE consent_audit aborts the statement.
-- Code paths only INSERT, so this is defense-in-depth: if a future change
-- (or SQL injection) tries to mutate audit history, SQLite refuses.
CREATE TRIGGER IF NOT EXISTS consent_audit_no_update
  BEFORE UPDATE ON consent_audit
BEGIN
  SELECT RAISE(ABORT, 'consent_audit is append-only');
END;

CREATE TRIGGER IF NOT EXISTS consent_audit_no_delete
  BEFORE DELETE ON consent_audit
BEGIN
  SELECT RAISE(ABORT, 'consent_audit is append-only');
END;
