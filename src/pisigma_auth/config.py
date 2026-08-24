"""Auth service configuration.

All environment-specific values (URLs, hostnames, ports, credentials) are loaded
from the runtime environment. Defaults in this file are safe, non-environmental
policy values only. See `.env.example` for local development values.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTH_", env_file=".env", extra="ignore")

    # Database — must be provided by the environment.
    database_url: str = ""

    # JWT issuer — must be a stable, deployment-specific URL.
    issuer: str = ""

    # CORS origins — comma-separated; empty means no cross-origin requests are allowed.
    cors_origins: str = ""

    # Token lifetimes (policy defaults, not environment-specific).
    access_token_minutes: int = 60
    refresh_token_days: int = 30

    # Registration policy.
    # Default False so a fresh deployment cannot be claimed by the first stranger
    # to discover it. The first platform admin must register with AUTH_BOOTSTRAP_TOKEN
    # or explicitly enable AUTH_OPEN_REGISTRATION.
    open_registration: bool = False

    # One-time token required to create the first platform admin when
    # open_registration is False. Generate a strong random value for each deployment.
    bootstrap_token: str = ""

    # SPA callback URL — provided by the environment; used for OAuth and email links.
    spa_callback_url: str = ""

    # JWT signing keys — must be provided by the environment. The crypto layer fails
    # closed when keys are missing.
    jwt_private_key: str = ""
    jwt_public_key: str = ""
    jwt_private_key_file: str = ""
    jwt_public_key_file: str = ""
    jwt_kid: str = "pisigma-auth-1"

    # OAuth provider credentials — empty means the provider is disabled.
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = ""
    google_authorize_url: str = "https://accounts.google.com/o/oauth2/v2/auth"
    google_token_url: str = "https://oauth2.googleapis.com/token"
    google_userinfo_url: str = "https://www.googleapis.com/oauth2/v3/userinfo"
    github_client_id: str = ""
    github_client_secret: str = ""
    github_redirect_uri: str = ""
    github_authorize_url: str = "https://github.com/login/oauth/authorize"
    github_token_url: str = "https://github.com/login/oauth/access_token"
    github_userinfo_url: str = "https://api.github.com/user"
    github_emails_url: str = "https://api.github.com/user/emails"

    # Dev server binding — must be provided by the environment.
    host: str = ""
    port: int | None = None

    # Comma-separated product audiences to auto-grant on signup (empty = none).
    # Set per deployment via AUTH_DEFAULT_AUDIENCES — Auth itself is product-agnostic.
    default_audiences: str = ""
    default_role: str = "operator"

    # Mail service integration — empty means email features are disabled.
    mail_base_url: str = ""
    mail_api_key: str = ""

    # Rate limiting (policy defaults).
    rate_limit_login: int = 10
    rate_limit_login_window_seconds: int = 60
    rate_limit_register: int = 10
    rate_limit_register_window_seconds: int = 60
    rate_limit_password_reset: int = 5
    rate_limit_password_reset_window_seconds: int = 60
    rate_limit_verify_email: int = 10
    rate_limit_verify_email_window_seconds: int = 60
    rate_limit_reset_password: int = 5
    rate_limit_reset_password_window_seconds: int = 60
    rate_limit_refresh: int = 20
    rate_limit_refresh_window_seconds: int = 60

    # Trust X-Forwarded-For / Forwarded headers for rate-limit IP extraction.
    # Enable ONLY when Auth is behind a trusted reverse proxy.
    rate_limit_trust_proxy: bool = False
    rate_limit_proxy_header: str = "x-forwarded-for"

    # Introspection endpoint API key (empty = endpoint disabled).
    introspection_api_key: str = ""

    # DB connection pool (ignored for SQLite).
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_timeout: int = 30

    # Password policy.
    password_min_length: int = 8
    password_require_uppercase: bool = False
    password_require_digit: bool = False

    # OAuth state TTL (seconds) — rows older than this are stale and can be purged.
    oauth_state_ttl_seconds: int = 600

    # Account security.
    require_email_verification: bool = True
    account_lockout_max_attempts: int = 5
    account_lockout_duration_seconds: int = 900  # 15 minutes

    @model_validator(mode="after")
    def _require_critical_settings(self) -> "Settings":
        """Fail closed if required runtime values are missing."""
        if not self.database_url:
            raise ValueError("AUTH_DATABASE_URL is required")
        if not self.issuer:
            raise ValueError("AUTH_ISSUER is required")
        return self

    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def default_audience_list(self) -> list[str]:
        return [a.strip() for a in self.default_audiences.split(",") if a.strip()]

    def private_key_pem(self) -> str:
        if self.jwt_private_key.strip():
            return self.jwt_private_key.replace("\\n", "\n")
        if self.jwt_private_key_file:
            return Path(self.jwt_private_key_file).read_text(encoding="utf-8")
        return ""

    def public_key_pem(self) -> str:
        if self.jwt_public_key.strip():
            return self.jwt_public_key.replace("\\n", "\n")
        if self.jwt_public_key_file:
            return Path(self.jwt_public_key_file).read_text(encoding="utf-8")
        return ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
