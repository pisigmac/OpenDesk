-- Migration: 0002_auth_hardening
-- Adds email_verification_tokens, password_reset_tokens, audit_log_events tables.

-- Email verification tokens
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_email_verification_tokens_user_id ON email_verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS ix_email_verification_tokens_token_hash ON email_verification_tokens(token_hash);

-- Password reset tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);

-- Audit log events (immutable — no UPDATE or DELETE should be issued on this table)
CREATE TABLE IF NOT EXISTS audit_log_events (
    id TEXT PRIMARY KEY,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT
);
CREATE INDEX IF NOT EXISTS ix_audit_log_events_occurred_at ON audit_log_events(occurred_at);
CREATE INDEX IF NOT EXISTS ix_audit_log_events_actor_id ON audit_log_events(actor_id);
CREATE INDEX IF NOT EXISTS ix_audit_log_events_action ON audit_log_events(action);
CREATE INDEX IF NOT EXISTS ix_audit_log_events_action_occurred ON audit_log_events(action, occurred_at);

-- Add is_active and deleted_at to users.
-- Run via migrations/run_migrations.py for idempotent application; the runner skips
-- duplicate-column / already-exists errors on both PostgreSQL and SQLite.
ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN deleted_at TIMESTAMP WITH TIME ZONE;
