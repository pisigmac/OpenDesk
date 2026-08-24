# PiSigma Auth

Shared identity microservice for PiSigma products. **Product-agnostic:** no consumer product is hard-coded in Auth. Other services validate JWTs via JWKS and assign product grants via admin API or deployment env.

## Features

- Email/password register & login with **email verification**
- **Password reset** via Mail service
- Google + GitHub OAuth
- RS256 access tokens + refresh tokens (rotation + revocation)
- Public JWKS (`/.well-known/jwks.json`) with deterministic key management
- Orgs / memberships (`org_id` / `workspace_id` claims)
- Product grants (`aud` + `roles.<product>`) — assigned per product, not baked into Auth
- **Rate limiting** on login, register, and password-reset endpoints
- **Immutable audit log** for all auth and admin events
- **User data export and deletion** (GDPR/CCPA)
- **Request-ID middleware** (`x-request-id` on every response)
- **Authenticated token introspection** (`/introspect` requires API key)

## Quick start

```bash
cd Auth
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Edit .env — at minimum set AUTH_JWT_PRIVATE_KEY / AUTH_JWT_PUBLIC_KEY
pisigma-auth
# → http://127.0.0.1:8090
```

Generate an RSA key pair for local dev:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl rsa -in private.pem -pubout -out public.pem
# Then set AUTH_JWT_PRIVATE_KEY_FILE=./private.pem and AUTH_JWT_PUBLIC_KEY_FILE=./public.pem
```

OpenAPI: http://127.0.0.1:8090/docs

## Integrate from another product

1. Send users to Auth login API or OAuth start URLs
2. Receive `access_token` (Bearer JWT)
3. Validate locally with JWKS (`iss`, `aud`, `exp`) — no call to Auth per request
4. Read claims: `sub`, `email`, `org_id`, `workspace_id`, `roles`
5. Ensure users have a **product grant** for your audience (`POST /v1/admin/grants` or `AUTH_DEFAULT_AUDIENCES` in that environment)

```bash
curl http://127.0.0.1:8090/.well-known/jwks.json
```

Example claims (after granting audience `myproduct`):

```json
{
  "sub": "user_uuid",
  "email": "dev@example.com",
  "org_id": "…",
  "workspace_id": "…",
  "aud": ["myproduct"],
  "roles": { "myproduct": "operator" },
  "iss": "https://auth.pisigma.local"
}
```

## JWT key management

**Keys are required.** Auth will refuse to start token issuance without configured keys — it no longer generates ephemeral key pairs. This prevents token invalidation on restart.

Set via env (inline PEM with `\n` escapes) or file paths:

```bash
AUTH_JWT_PRIVATE_KEY_FILE=/run/secrets/auth_private.pem
AUTH_JWT_PUBLIC_KEY_FILE=/run/secrets/auth_public.pem
```

To rotate keys without downtime: add the new public key to JWKS (keep both KIDs active), migrate signing to the new private key, then remove the old KID after existing tokens expire.

## Email verification and password reset

Requires the **Mail service** to be running and configured:

```bash
AUTH_MAIL_BASE_URL=http://127.0.0.1:8787
AUTH_MAIL_API_KEY=your-mail-api-key
```

On register, a verification email is sent automatically. Password-based accounts cannot log in until the email is verified via `POST /v1/auth/verify-email`. OAuth users are treated as already verified by their provider.

Password reset is initiated via `POST /v1/auth/forgot-password` — a reset link is emailed to the user. Mail failures are non-fatal in development (registration still succeeds) but are logged.

## Account lockout

After repeated failed password attempts, an account is temporarily locked to slow brute-force attacks:

```bash
AUTH_ACCOUNT_LOCKOUT_MAX_ATTEMPTS=5
AUTH_ACCOUNT_LOCKOUT_DURATION_SECONDS=900  # 15 minutes
```

A successful login resets the failed-attempt counter. The same generic `401 Invalid credentials` is returned for wrong passwords, locked accounts, and unverified emails to avoid information leakage.

## Rate limiting

Per-IP in-memory rate limits are applied to sensitive endpoints. Configure via env:

```bash
AUTH_RATE_LIMIT_LOGIN=10                    # max requests
AUTH_RATE_LIMIT_LOGIN_WINDOW_SECONDS=60     # per window
AUTH_RATE_LIMIT_REGISTER=10
AUTH_RATE_LIMIT_REGISTER_WINDOW_SECONDS=60
AUTH_RATE_LIMIT_PASSWORD_RESET=5
AUTH_RATE_LIMIT_PASSWORD_RESET_WINDOW_SECONDS=60
AUTH_RATE_LIMIT_REFRESH=20
AUTH_RATE_LIMIT_REFRESH_WINDOW_SECONDS=60
```

When Auth is deployed behind a trusted reverse proxy, enable `AUTH_RATE_LIMIT_TRUST_PROXY=true` so the rate limiter uses the client IP from `X-Forwarded-For` instead of the proxy's IP. Do not enable this if Auth is exposed directly to clients.

Blocked requests receive `429 Too Many Requests`.

## Token introspection

`/introspect` requires a Bearer API key. Set `AUTH_INTROSPECTION_API_KEY` to enable it; leaving it empty disables the endpoint (returns `503`).

```bash
curl -X POST http://127.0.0.1:8090/introspect \
  -H "Authorization: Bearer $AUTH_INTROSPECTION_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"token": "<access_token>"}'
```

## Audit log

All auth and admin events are written to `audit_log_events`. Query via the admin API:

```bash
GET /v1/admin/audit?action=user.login&limit=25
```

Emitted actions: `user.register`, `user.login`, `user.logout`, `user.verify_email`, `user.forgot_password`, `user.reset_password`, `user.delete`, `admin.set_grant`.

## OAuth setup

Create Google / GitHub OAuth apps. Redirect URIs:

- `http://localhost:8090/v1/oauth/google/callback`
- `http://localhost:8090/v1/oauth/github/callback`

```bash
AUTH_GOOGLE_CLIENT_ID=…
AUTH_GOOGLE_CLIENT_SECRET=…
AUTH_GITHUB_CLIENT_ID=…
AUTH_GITHUB_CLIENT_SECRET=…
AUTH_SPA_CALLBACK_URL=http://localhost:5173/auth/callback
```

## Docker

```bash
docker compose up -d
```

Postgres + Auth on port 8090. Mount RSA PEMs as `./private.pem` and `./public.pem` (or set `AUTH_JWT_*_KEY_FILE` on the host). Set `AUTH_ISSUER` and `AUTH_BOOTSTRAP_TOKEN`.

## Admin console

Platform admins can operate users, grants, and the audit log in the browser:

http://127.0.0.1:8090/admin/console

## Protocol shape

Auth is a first-party JSON + RS256 JWT API, **not** an OpenID Connect authorization server. Products validate JWKS locally. Standard OIDC clients (discovery, authorization-code, PKCE) are a non-goal until explicitly scheduled.

Rate limits are per process. Run a single replica or put a shared limiter in front until a Redis/Cache backend is added.

## API map

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/health` | none | Ready check (HTTP 503 when DB or keys fail) |
| GET | `/admin/console` | browser | Platform-admin UI |
| POST | `/v1/auth/register` | none | Email/password signup |
| POST | `/v1/auth/login` | none | Password login |
| POST | `/v1/auth/refresh` | none | Rotate refresh token |
| POST | `/v1/auth/logout` | none | Revoke refresh token |
| GET | `/v1/auth/me` | Bearer JWT | Current user profile |
| PATCH | `/v1/auth/me` | Bearer JWT | Update profile (email change re-verifies) |
| POST | `/v1/auth/me/change-password` | Bearer JWT | Change password; revokes other sessions |
| GET | `/v1/auth/me/sessions` | Bearer JWT | List refresh sessions |
| DELETE | `/v1/auth/me/sessions` | Bearer JWT | Revoke all sessions |
| DELETE | `/v1/auth/me/sessions/{id}` | Bearer JWT | Revoke one session |
| POST | `/v1/auth/verify-email` | none | Verify email with token |
| POST | `/v1/auth/forgot-password` | none | Request password reset email |
| POST | `/v1/auth/reset-password` | none | Reset password with token |
| GET | `/v1/oauth/google/start` | none | Initiate Google OAuth |
| GET | `/v1/oauth/github/start` | none | Initiate GitHub OAuth |
| GET | `/.well-known/jwks.json` | none | Public JWKS |
| POST | `/introspect` | API key | Token introspection |
| GET | `/metrics` | none | In-process auth counters |
| GET/POST | `/v1/orgs` | Bearer JWT | List/create orgs |
| DELETE | `/v1/orgs/{id}` | Bearer JWT | Delete org (owner) |
| GET | `/v1/orgs/{id}/members` | Bearer JWT | List members |
| POST | `/v1/orgs/{id}/members` | Bearer JWT | Add/update member |
| DELETE | `/v1/orgs/{id}/members/{user_id}` | Bearer JWT | Remove member |
| GET | `/v1/me/export` | Bearer JWT | Export own data (GDPR) |
| POST | `/v1/me/delete` | Bearer JWT | Delete own account (GDPR) |
| GET | `/v1/admin/users` | Bearer JWT + admin | List/search users (`q`, `limit`, `offset`) |
| PATCH | `/v1/admin/users/{id}/active` | Bearer JWT + admin | Suspend or activate |
| POST | `/v1/admin/grants` | Bearer JWT + admin | Assign product grant |
| GET | `/v1/admin/audit` | Bearer JWT + admin | Query audit log |

## TypeScript SDK

```typescript
import { PisigmaAuth } from './client'

const auth = new PisigmaAuth({ baseUrl: 'http://127.0.0.1:8090' })

// Auth flows
await auth.register({ email, password })
await auth.login({ email, password })
await auth.refresh(refreshToken)
await auth.logout(refreshToken)
await auth.me(accessToken)

// Email / password management
await auth.verifyEmail({ token })
await auth.forgotPassword({ email })
await auth.resetPassword({ token, password })

// Self-service (GDPR)
await auth.exportMyData(accessToken)
await auth.deleteMyAccount(accessToken)

// Admin
await auth.listUsers(accessToken)
await auth.setGrant(accessToken, { user_id, audience, role })
await auth.queryAuditLog(accessToken, { action: 'user.login', limit: 25 })
```

## Running tests

```bash
pytest tests/ -v
```
