# Auth — Agent Context

Read this file first. Then read `code_map.md` for file-level navigation and `gaps_enhancements.md` for remaining product gaps. This directory is **only** the OpenDesk Auth service.

## What this directory is

Shared identity microservice for OpenDesk Auth products. Stack: Python 3.10+ / FastAPI / SQLAlchemy 2 / Pydantic v2 / Postgres or SQLite. Typed client: `client.ts` (`OpenDesk Auth`). Tests: 56 in `tests/test_auth.py`.

Health: `http://127.0.0.1:8090/health`. OpenAPI: `http://127.0.0.1:8090/docs`.

## Do / do not

- **Do** change Auth under `src/opendesk_auth/`, `client.ts`, `tests/`, `migrations/`, `.env.example`, `README.md`.
- **Do** keep Auth product-agnostic: no product names in source. Product access is `ProductGrant.audience` plus `AUTH_DEFAULT_AUDIENCES` at deploy time.
- **Do not** generate ephemeral JWT keys. `_ensure_keys` must fail closed.
- **Do not** put tokens in OAuth redirect **query** strings. Fragments only (`oauth.py` `_redirect_with_tokens`).
- **Do not** link OAuth to an existing password account unless `email_verified_at` is set.
- **Do not** issue access/refresh tokens at register when `AUTH_REQUIRE_EMAIL_VERIFICATION=true`.
- **Do not** let suspended users (`is_active=false`) refresh tokens.
- **Do not** commit `.env`, `private.pem`, or `public.pem`.

## How to run

```bash
cd Auth
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # add .[postgres] for Postgres
cp .env.example .env             # AUTH_DATABASE_URL + AUTH_ISSUER required
# RSA keys required for token issuance:
#   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
#   openssl rsa -in private.pem -pubout -out public.pem
opendesk-auth                     # uvicorn, AUTH_HOST + AUTH_PORT required
# health: http://127.0.0.1:8090/health
# openapi: http://127.0.0.1:8090/docs
pytest tests/ -v                 # 56 tests, uses tmp SQLite + generated RSA
PYTHONPATH=src python3 migrations/run_migrations.py
docker compose up -d             # Postgres :5433 + Auth :8090 (compose does not pass JWT keys)
```

Env prefix is `AUTH_`. Settings live in `src/opendesk_auth/config.py` (`pydantic-settings`). Missing `AUTH_DATABASE_URL` or `AUTH_ISSUER` raises at settings load. Missing JWT keys raise at first token/JWKS use.

## Mental model

```
Client / SDK (client.ts OpenDesk Auth)
        │  HTTP JSON
        ▼
FastAPI app (app.py create_app)
  middleware: RequestContextMiddleware (x-request-id + security headers)
              CORSMiddleware (AUTH_CORS_ORIGINS, empty = no CORS)
  /health     DB SELECT 1 + get_key_material(); status "ok"|"degraded" (always HTTP 200)
  routers     /v1/auth  /v1/oauth  /v1/orgs  /v1/admin  /v1/me
              /.well-known/jwks.json   /introspect
        │
        ▼
services.py  (domain)     crypto.py (bcrypt, SHA-256 token hash, RS256 JWT)
        │
        ▼
SQLAlchemy models → SQLite (dev/test) or Postgres (compose / AUTH_DATABASE_URL)
```

Auth is **not** an OIDC Authorization Server. It is a custom JSON API that issues RS256 JWTs. Products validate locally via JWKS (`iss`, `aud`, `exp`). There is no `/.well-known/openid-configuration`, no authorize endpoint, no authorization-code grant, no UserInfo, no PKCE, no client registry.

### JWT access token claims

Issued by `crypto.issue_access_token`:

| Claim | Source |
|-------|--------|
| `sub` | `User.id` (UUID string) |
| `email` | `User.email` |
| `org_id` | Primary membership (first `owner`, else first membership) |
| `workspace_id` | That membership's `workspace_id` (defaults to org id) |
| `aud` | Always `["opendesk-auth", ...product audiences from grants]` |
| `roles` | `{ audience: role }` from `ProductGrant` |
| `iss` | `AUTH_ISSUER` |
| `iat` / `exp` | now / now + `AUTH_ACCESS_TOKEN_MINUTES` (default 60) |
| header `kid` | `AUTH_JWT_KID` (default `opendesk-auth-1`) |

Auth's own routes decode with `audience="opendesk-auth"`. Product services should decode with their own audience.

Refresh tokens are opaque `token_urlsafe(48)`, stored as SHA-256 hex, single-use (revoked on rotate). Not JWTs. Lifetime `AUTH_REFRESH_TOKEN_DAYS` (default 30).

### Identity model

- **User** — email unique, optional password hash (OAuth-only users have `password_hash=None`), `is_platform_admin`, `is_active`, `email_verified_at`, lockout counters, `deleted_at`.
- **Identity** — `provider` ∈ `password|google|github` + `provider_subject`, unique per pair.
- **Org + Membership** — auto-created personal org on signup (`"{email}'s org"`, role `owner`, `workspace_id=org.id`). Roles: `owner|admin|member`.
- **ProductGrant** — unique `(user_id, audience)`, role `admin|operator|viewer`. Becomes JWT `aud` + `roles`.
- **Tokens** — `RefreshToken`, `EmailVerificationToken` (24h), `PasswordResetToken` (1h). Hashed at rest.
- **AuditLogEvent** — append-only by convention (no DB trigger). IP captured; `user_agent` column exists but is not written today.
- **OAuthState** — CSRF state, TTL `AUTH_OAUTH_STATE_TTL_SECONDS` (default 600), opportunistic purge.

First registered user becomes platform admin. When `AUTH_OPEN_REGISTRATION=false` (default), that first user must send `bootstrap_token` matching `AUTH_BOOTSTRAP_TOKEN`. Later signups are rejected unless open registration is enabled.

### Critical flows

**Register** (`POST /v1/auth/register`) — closed-reg gate → password policy → unique email → create user+password identity+personal org+default grants → verification token → Mail (non-fatal on failure) → audit `user.register` → if verification required, `{verification_required: true}` and **no tokens**.

**Login** (`POST /v1/auth/login`) — lockout check → bcrypt → increment/lock on fail → on success clear lockout → require `email_verified_at` if configured → require `is_active` → generic `401 Invalid credentials` for unknown user / bad password / locked / unverified (suspended is `403` after authenticate succeeds). Audit `user.login`.

**OAuth** — store state → redirect to Google/GitHub → exchange code → `find_or_create_oauth_user` (OAuth users marked verified) → tokens in **URL fragment** to `AUTH_SPA_CALLBACK_URL`.

**Refresh** — hash lookup → reject revoked/expired/inactive user → revoke old → issue new pair.

**Forgot/reset** — always `200 {ok:true}` on forgot (no enumeration). Reset consumes one-time token then sets password. Does **not** revoke existing refresh tokens.

**GDPR delete** — audit `user.delete` then hard-delete tokens/identities/memberships/grants/user. Audit rows kept. Orgs the user owned are **not** deleted (orphaned orgs possible).

### Auth surface (complete)

Public (no JWT):

| Method | Path | Notes |
|--------|------|-------|
| GET | `/health` | DB + keys; HTTP 200 even if `degraded` |
| GET | `/.well-known/jwks.json` | Single RSA JWK |
| POST | `/introspect` | Requires `AUTH_INTROSPECTION_API_KEY`; empty key → 503 |
| POST | `/v1/auth/register` | Rate limited |
| POST | `/v1/auth/login` | Rate limited |
| POST | `/v1/auth/refresh` | Rate limited |
| POST | `/v1/auth/logout` | Always `{ok:true}` |
| POST | `/v1/auth/verify-email` | Rate limited |
| POST | `/v1/auth/forgot-password` | Rate limited; enum-safe |
| POST | `/v1/auth/reset-password` | Rate limited |
| GET | `/v1/oauth/{google,github}/start` | 501 if client_id empty |
| GET | `/v1/oauth/{google,github}/callback` | |

Bearer JWT (`aud` must include `opendesk-auth`):

| Method | Path |
|--------|------|
| GET/PATCH | `/v1/auth/me` |
| POST | `/v1/auth/me/change-password` |
| GET | `/v1/auth/me/sessions` |
| DELETE | `/v1/auth/me/sessions/{session_id}` |
| GET/POST | `/v1/orgs` |
| POST | `/v1/orgs/{id}/members` |
| GET | `/v1/me/export` |
| POST | `/v1/me/delete` |

Platform admin (`is_platform_admin`):

| Method | Path |
|--------|------|
| GET | `/v1/admin/users` |
| PATCH | `/v1/admin/users/{id}/active` |
| POST | `/v1/admin/grants` |
| GET | `/v1/admin/audit` |

Rate-limit buckets (in-process memory, per IP): `login`, `register`, `password_reset`, `verify_email`, `reset_password`, `refresh`. Trust `X-Forwarded-For` only when `AUTH_RATE_LIMIT_TRUST_PROXY=true`.

Audit actions emitted: `user.register`, `user.login`, `user.logout` (actor_id often null), `user.verify_email`, `user.forgot_password`, `user.reset_password`, `user.update_profile`, `user.change_password`, `user.revoke_session`, `user.delete`, `admin.set_grant`, `admin.suspend_user`, `admin.activate_user`.

### SDK (`client.ts` → `OpenDesk Auth`)

Re-exported from `Tools/sdk/index.ts`. Covers register/login/refresh/logout/me/verify/forgot/reset/export/delete/listUsers/setGrant/queryAuditLog/checkHealth.

**Not in SDK:** PATCH `/v1/auth/me`, change-password, sessions, orgs, admin suspend/activate, OAuth start URLs.

### Tests

`tests/test_auth.py` — one file, 56 tests. Fixture opens registration, disables email verification (unless the test is about those gates), generates RSA, tmp SQLite. No OAuth success path, no TypeScript SDK tests, no profile/session/change-password tests.

### Sibling services (not wired into Auth)

- `MFA/` — in-memory TOTP stub; Auth does not call it
- `SSO/` — placeholder providers; Auth does its own Google/GitHub OAuth
- `RBAC/` — in-memory roles; Auth uses `is_platform_admin` + product grants
- `Mail/` — used when `AUTH_MAIL_BASE_URL` + `AUTH_MAIL_API_KEY` are set
- `AuditLogs/` — separate service; Auth writes its own `audit_log_events` table

## Config cheat sheet

Required: `AUTH_DATABASE_URL`, `AUTH_ISSUER`, and for `opendesk-auth` CLI also `AUTH_HOST`, `AUTH_PORT`. JWT PEM or `*_FILE`.

Important defaults (in `config.py`, not all listed in `.env.example`):

| Setting | Default | Meaning |
|---------|---------|---------|
| `open_registration` | `false` | Closed signup |
| `require_email_verification` | `true` | No password login / no register tokens until verify |
| `account_lockout_max_attempts` | `5` | Then lock `900`s |
| `password_min_length` | `8` | Uppercase/digit flags default off |
| `access_token_minutes` | `60` | |
| `refresh_token_days` | `30` | |
| `jwt_kid` | `opendesk-auth-1` | Single key, no rotation set |
| `introspection_api_key` | `""` | Empty disables `/introspect` |
| `cors_origins` | `""` | Empty = no browser CORS |
| `default_audiences` | `""` | Auto-grant on signup |

OAuth authorize/token/userinfo **URLs are hardcoded** in `oauth_providers.py` (Google/GitHub). Only client id/secret/redirect are configurable.

## Conventions when changing Auth

1. New mutating routes: rate-limit if public; `emit_audit`; validate with Pydantic; fail closed.
2. Passwords: `validate_password_policy` + bcrypt via `crypto.py`. Never store raw tokens — `hash_token`.
3. New tables: SQLAlchemy model **and** a `migrations/000N_*.sql` so existing DBs upgrade. `init_db()` is `create_all` only (won't add columns).
4. Extend `client.ts` and tests in the same change.
5. Keep error bodies `{error, code, request_id}` (see `app.py` handlers).
6. Do not add product names, localhost, or provider hostnames as new source defaults. Env or `.env.example` only.

## File jump list

| Need | File |
|------|------|
| App factory, health, error envelope | `src/opendesk_auth/app.py` |
| All env settings | `src/opendesk_auth/config.py` |
| Domain logic | `src/opendesk_auth/services.py` |
| JWT / bcrypt / token hash | `src/opendesk_auth/crypto.py` |
| Tables | `src/opendesk_auth/models.py` |
| Request/response types | `src/opendesk_auth/schemas.py` |
| Register/login/me/sessions | `src/opendesk_auth/routes/auth.py` |
| Google/GitHub | `src/opendesk_auth/routes/oauth.py`, `oauth_providers.py` |
| Admin + audit query | `src/opendesk_auth/routes/admin.py` |
| GDPR | `src/opendesk_auth/routes/me.py` |
| JWKS + introspect | `src/opendesk_auth/routes/jwks.py` |
| Orgs | `src/opendesk_auth/routes/orgs.py` |
| SDK | `client.ts` |
| Tests | `tests/test_auth.py` |
| Full file map | `code_map.md` |
| Features and remaining gaps | `gaps_enhancements.md` |
