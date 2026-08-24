-- Migration: 0003_email_verification_and_lockout
-- Adds email verification and account lockout columns to users.

ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TIMESTAMP WITH TIME ZONE;
