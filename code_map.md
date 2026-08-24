# Auth — Code Map

Companion to `AGENTS.md`. Use this instead of listing directories. Paths are relative to `Auth/`.

## Directory tree

```
Auth/
├── AGENTS.md                 Agent context (read first)
├── code_map.md               This file
├── gaps_enhancements.md      Current features and remaining gaps
├── README.md                 Operator/developer README
├── IMPLEMENTATION_STATUS.md  2026-08 hardening checklist (partially stale vs current routes)
├── pyproject.toml            Package opendesk-auth 1.0.0; script opendesk-auth
├── Dockerfile                python:3.12-slim, pip -e ".[postgres]", CMD opendesk-auth
├── docker-compose.yml        postgres:16-alpine :5433 + auth :8090
├── client.ts                 TypeScript SDK class OpenDesk Auth
├── .env.example              AUTH_* template
├── .gitignore                .venv, .env, *.db — does NOT ignore *.pem
├── src/opendesk_auth/         Service implementation
├── tests/test_auth.py        56 pytest tests
└── migrations/               0002, 0003 + run_migrations.py (no 0001; base via create_all)
```

Untracked local secrets often present: `private.pem`, `public.pem`, `.env`. Do not commit.

## Source files

### `src/opendesk_auth/__init__.py`

`__version__ = "1.0.0"`. Used by `/health` and FastAPI metadata.

### `src/opendesk_auth/app.py`

- `create_app()` factory; module-level `app = create_app()`.
- Lifespan: `logging.basicConfig` + `init_db()` (`Base.metadata.create_all`).
- `app.state.rate_limiter = RateLimiter(settings)`.
- Middleware order: `RequestContextMiddleware` then `CORSMiddleware`.
- Exception handlers: `HTTPException` → `{error, code: HTTP_<n>, request_id}`; `RequestValidationError` → 422 `{error, code: VALIDATION_ERROR, request_id, detail}`.
- `GET /health` — `check_db_health()` + `get_key_material()`; body `status` is `ok` or `degraded`; **HTTP status is always 200**.
- Routers: `jwks` (no prefix), others under `/v1`.

### `src/opendesk_auth/cli.py`

`opendesk-auth` entry. Requires `AUTH_HOST` and `AUTH_PORT`. `uvicorn.run("opendesk_auth.app:app", ...)`.

### `src/opendesk_auth/config.py`

`Settings(BaseSettings)` with `env_prefix="AUTH_"`, `.env` file, `extra="ignore"`. Cached via `@lru_cache get_settings()`.

| Field | Env | Default | Notes |
|-------|-----|---------|-------|
| `database_url` | `AUTH_DATABASE_URL` | `""` | **Required** |
| `issuer` | `AUTH_ISSUER` | `""` | **Required** |
| `cors_origins` | `AUTH_CORS_ORIGINS` | `""` | CSV |
| `access_token_minutes` | | `60` | Not in `.env.example` |
| `refresh_token_days` | | `30` | Not in `.env.example` |
| `open_registration` | | `false` | |
| `bootstrap_token` | | `""` | First admin when closed |
| `spa_callback_url` | | `""` | OAuth fragment target + mail link base |
| `jwt_private_key` / `jwt_public_key` | | `""` | Inline PEM, `\n` unescaped |
| `jwt_private_key_file` / `jwt_public_key_file` | | `""` | |
| `jwt_kid` | | `opendesk-auth-1` | |
| `google_*` / `github_*` | | `""` | Empty client_id disables provider |
| `host` / `port` | | `""` / `None` | Required to start CLI |
| `default_audiences` / `default_role` | | `""` / `operator` | |
| `mail_base_url` / `mail_api_key` | | `""` | Empty disables mail |
| `rate_limit_*` | | see file | Per-action count + window |
| `rate_limit_trust_proxy` | | `false` | |
| `rate_limit_proxy_header` | | `x-forwarded-for` | |
| `introspection_api_key` | | `""` | Empty → `/introspect` 503 |
| `db_pool_size` / `max_overflow` / `pool_timeout` | | `5` / `10` / `30` | Ignored for SQLite |
| `password_min_length` | | `8` | Not in `.env.example` |
| `password_require_uppercase` / `_digit` | | `false` | |
| `oauth_state_ttl_seconds` | | `600` | |
| `require_email_verification` | | `true` | |
| `account_lockout_max_attempts` | | `5` | `0` disables lockout increment path still checks existing lock |
| `account_lockout_duration_seconds` | | `900` | |

Helpers: `cors_origin_list()`, `default_audience_list()`, `private_key_pem()`, `public_key_pem()`.

### `src/opendesk_auth/db.py`

Lazy global engine + sessionmaker. SQLite: `check_same_thread=False`. Else: pool + `pool_pre_ping`. `init_db()` = `create_all`. `get_db()` yield/close. `check_db_health()` = `SELECT 1`. `reset_engine()` for tests.

### `src/opendesk_auth/models.py`

SQLAlchemy 2 declarative. IDs are UUID strings.

| Class | Table | Purpose |
|-------|-------|---------|
| `User` | `users` | Identity record |
| `Identity` | `identities` | Unique `(provider, provider_subject)` |
| `Org` | `orgs` | Tenant |
| `Membership` | `memberships` | Unique `(org_id, user_id)`; role `owner\|admin\|member` |
| `ProductGrant` | `product_grants` | Unique `(user_id, audience)`; role `admin\|operator\|viewer` |
| `RefreshToken` | `refresh_tokens` | `token_hash` unique; `revoked` flag |
| `EmailVerificationToken` | `email_verification_tokens` | hashed, `used_at` |
| `PasswordResetToken` | `password_reset_tokens` | hashed, `used_at` |
| `AuditLogEvent` | `audit_log_events` | Append-only by convention |
| `OAuthState` | `oauth_states` | CSRF state |

`User.deleted_at` is set on admin suspend; GDPR path **hard-deletes** the row instead.

### `src/opendesk_auth/schemas.py`

Pydantic v2 request/response models. `RegisterRequest.password` and `ResetPasswordRequest.password` have `min_length=8` (duplicates policy default). `RegisterResponse` allows null tokens when `verification_required`. `ErrorDetail` documents the envelope (handlers live in `app.py`). `SessionOut` has no IP/UA/device fields (sessions are refresh-token rows).

### `src/opendesk_auth/crypto.py`

- `hash_password` / `verify_password` — bcrypt.
- `hash_token` — SHA-256 hex (refresh, verify, reset).
- `generate_urlsafe_token` / `new_refresh_token` — `secrets.token_urlsafe`.
- `_ensure_keys` — cached; **raises** if PEMs missing (no ephemeral generation).
- `public_jwk()` — RSA JWK `kty/use/alg/kid/n/e`.
- `issue_access_token` — RS256, `aud = ["opendesk-auth", *audiences]`. No `jti`, `nbf`, `azp`.
- `decode_access_token(token, audience=None)` — verifies `iss`; `verify_aud` only if `audience` passed. `/introspect` calls it **without** audience.

### `src/opendesk_auth/services.py`

Domain functions (not a class). Grouped:

| Function | Role |
|----------|------|
| `user_to_out` / `primary_org` | Serialization; primary org = first owner else first membership |
| `issue_tokens` | Access JWT + persist hashed refresh |
| `ensure_default_grant` / `_apply_default_grants` | Signup audiences |
| `create_user_with_password` | User + password identity + personal org + grants |
| `authenticate_password` | Lockout, bcrypt, verify-email gate, `is_active` |
| `find_or_create_oauth_user` | Link only if existing email is verified; new OAuth users pre-verified |
| `rotate_refresh` / `revoke_refresh` | Rotation rejects inactive users |
| `create_verification_token` / `verify_email_token` | 24h TTL |
| `create_password_reset_token` / `consume_password_reset_token` / `reset_user_password` | 1h TTL; reset does not revoke sessions |
| `emit_audit` | Insert `AuditLogEvent` |
| `export_user_data` / `delete_user_data` | GDPR; delete does not remove owned `Org` rows |
| `validate_password_policy` | Length + optional upper/digit |
| `update_user_profile` | Email change does **not** clear `email_verified_at` |
| `change_password` | Requires current password |
| `set_user_active` | Suspend revokes all refresh tokens, sets `deleted_at` |
| `list_user_sessions` / `revoke_session` | Refresh-token rows as "sessions" |
| `purge_stale_oauth_states` | Best-effort |

### `src/opendesk_auth/middleware.py`

`RequestContextMiddleware`: `x-request-id` (echo or UUID), contextvar `{request_id, ip}`. Security headers on every response: `X-Content-Type-Options`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy`, `HSTS` (always, including HTTP), `CSP: default-src 'none'`. IP is **direct** `request.client.host` (rate limiter has separate proxy logic).

### `src/opendesk_auth/rate_limit.py`

In-process `dict[str, list[datetime]]` + `Lock`. Not shared across workers. `rate_limit_dependency(action)` reads `app.state.rate_limiter`. Proxy IP only if `rate_limit_trust_proxy`.

### `src/opendesk_auth/mail_client.py`

`POST {mail_base_url}/v1/send` with Bearer API key. Link base = `spa_callback_url.rsplit("/", 1)[0]` then `/verify-email?token=` or `/reset-password?token=`. Raises if mail env empty. Register/forgot catch exceptions and continue.

### `src/opendesk_auth/oauth_providers.py`

Hardcoded:

- Google authorize `https://accounts.google.com/o/oauth2/v2/auth`
- Google token `https://oauth2.googleapis.com/token`
- Google userinfo `https://www.googleapis.com/oauth2/v3/userinfo`
- GitHub authorize `https://github.com/login/oauth/authorize`
- GitHub token `https://github.com/login/oauth/access_token`
- GitHub user `https://api.github.com/user` (+ `/user/emails`)

No PKCE, no `nonce`, no OIDC id_token verification (uses userinfo / GitHub API).

### `src/opendesk_auth/routes/__init__.py`

Re-exports six routers.

### `src/opendesk_auth/routes/auth.py`

Prefix `/auth` (mounted at `/v1`). `current_user` decodes JWT with `audience="opendesk-auth"`, loads user, rejects inactive.

Endpoints: register, login, refresh, logout, GET/PATCH me, verify-email, forgot/reset-password, change-password, list/revoke sessions.

Logout always returns ok even if token unknown. Logout audit has `actor_id=None`.

### `src/opendesk_auth/routes/oauth.py`

Prefix `/oauth`. State stored in DB. Tokens returned in **fragment**. Exceptions from provider exchange become generic `400` (no leak). `purge_stale_oauth_states` after store, errors swallowed.

### `src/opendesk_auth/routes/orgs.py`

Prefix `/orgs`. List own orgs; create org (caller becomes owner); add/update member if caller is `owner` or `admin`. **Missing:** list members, remove member, delete/rename org, transfer ownership, invite-by-email.

### `src/opendesk_auth/routes/admin.py`

Prefix `/admin`. `require_platform_admin`. List all users (no pagination/search). PATCH active. POST grants (`admin|operator|viewer`). GET audit (filters action/actor/resource; does **not** return `ip_address` / `user_agent`).

### `src/opendesk_auth/routes/jwks.py`

`GET /.well-known/jwks.json` — `{keys: [one JWK]}`. `POST /introspect` — API key; decode without audience check.

### `src/opendesk_auth/routes/me.py`

Prefix `/me`. Export + delete. Profile/sessions live under `/auth/me*` instead.

## Request flow (login)

```
POST /v1/auth/login
  → rate_limit_dependency("login")
  → authenticate_password
       lockout? → None → 401
       bcrypt fail → increment / maybe lock → None → 401
       unverified or inactive → None / 403
  → emit_audit user.login
  → issue_tokens (JWT + RefreshToken row)
```

## Request flow (product validation)

```
Product service
  GET Auth/.well-known/jwks.json   (cache locally)
  jwt.decode(access_token, key, iss=AUTH_ISSUER, aud=<product>)
  read sub, email, org_id, workspace_id, roles[product]
```

No per-request call to Auth is required. `/introspect` is optional for opaque checks.

## Migrations

| File | What |
|------|------|
| *(none 0001)* | Base tables created by `init_db()` / `create_all` |
| `migrations/0002_auth_hardening.sql` | verify/reset/audit tables; `users.is_active`, `users.deleted_at` |
| `migrations/0003_email_verification_and_lockout.sql` | `email_verified_at`, `failed_login_attempts`, `locked_until` |
| `migrations/run_migrations.py` | `_migrations` ledger; idempotent skip of duplicate-column errors |

`create_all` will **not** add new columns to existing DBs. Always add SQL for column changes.

## Tests (`tests/test_auth.py`)

Fixture: tmp SQLite, generated RSA, `AUTH_OPEN_REGISTRATION=true`, `AUTH_REQUIRE_EMAIL_VERIFICATION=false`, `AUTH_DEFAULT_AUDIENCES=demo-app`.

Covered: register/login/me/jwks, orgs/grants, OAuth unconfigured 501, introspect + API key gate, no product coupling in defaults, models, token helpers, fail-closed keys, schemas, mail payload builders, token lifecycle, rate limiter (allow/block, XFF trust/untrust, login/register/refresh/verify/reset), email send + verify + reset flows, request-id, audit emit + admin query + filters + grant audit, GDPR export/delete, `aud` includes `opendesk-auth`, login blocked until verify, lockout + reset + expiry, closed registration + bootstrap token, register without tokens when verify required, OAuth cannot take over unverified email, refresh blocked when suspended, config required fields, mail failure logged.

Not covered: OAuth happy path, PATCH me, change-password, session list/revoke, SDK, multi-worker rate limit, key rotation, org member edge cases.

## SDK methods vs routes

| SDK | Route | Present |
|-----|-------|---------|
| `checkHealth` | `GET /health` | yes |
| `register` | `POST /v1/auth/register` | yes |
| `login` | `POST /v1/auth/login` | yes |
| `refresh` / `logout` | refresh/logout | yes |
| `me` | `GET /v1/auth/me` | yes |
| `verifyEmail` / `forgotPassword` / `resetPassword` | yes | yes |
| `exportMyData` / `deleteMyAccount` | `/v1/me/*` | yes |
| `listUsers` / `setGrant` / `queryAuditLog` | admin | yes |
| — | `PATCH /v1/auth/me` | **missing** |
| — | `POST /v1/auth/me/change-password` | **missing** |
| — | sessions | **missing** |
| — | orgs | **missing** |
| — | `PATCH /v1/admin/users/{id}/active` | **missing** |

## Docker

`docker-compose.yml` sets DB URL, host/port, CORS, SPA callback, OAuth ids from host env. **Does not set** `AUTH_ISSUER`, JWT keys, bootstrap token, mail, or open-registration. Image install is `.[postgres]` only. Dockerfile does not copy `migrations/`.

## Integration points

| Direction | Target | How |
|-----------|--------|-----|
| Outbound | Mail service | `mail_client.send_mail` → `POST /v1/send` |
| Outbound | Google / GitHub | `httpx` in `oauth_providers.py` |
| Inbound | Product services | JWKS + JWT |
| Inbound | TS apps | `Tools/sdk` → `OpenDesk Auth` |
| Not wired | MFA, SSO, RBAC, AuditLogs | — |

