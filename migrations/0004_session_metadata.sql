-- Session device metadata on refresh tokens.
ALTER TABLE refresh_tokens ADD COLUMN ip_address TEXT;
ALTER TABLE refresh_tokens ADD COLUMN user_agent TEXT;
