# Auth Service Hardening — Implementation Status

All P0 gaps from `gaps-enhancements.md` have been implemented, tested (56/56 passing), and documented.

## Blocker fixes applied on `auth-hardening-blocker-fixes`

| # | Blocker | Fix |
|---|---------|-----|
| 1 | First user could claim a fresh deployment | `AUTH_OPEN_REGISTRATION` defaults to `false`; first admin must supply `AUTH_BOOTSTRAP_TOKEN` |
| 2 | Tokens issued before email verification | Registration returns `verification_required: true` with no tokens when `AUTH_REQUIRE_EMAIL_VERIFICATION=true` |
| 3 | Verify-email / reset-password not rate-limited | Added `verify_email` and `reset_password` rate-limit buckets and dependencies |
| 4 | OAuth could take over unverified password account | OAuth linking by email now requires the existing account's email to be verified |
| 5 | Suspended users could refresh tokens | `rotate_refresh` now rejects rotation when `user.is_active` is false |

## Tasks

| # | Task | Status | Files Changed |
|---|------|--------|---------------|
| 1 | Email Verification Token model | ✅ Done | `models.py` |
| 2 | Password Reset Token model | ✅ Done | `models.py` |
| 3 | Audit Log Event model | ✅ Done | `models.py` |
| 4 | Secure token helpers + fail-closed RSA keys | ✅ Done | `crypto.py` |
| 5 | Schemas for new flows | ✅ Done | `schemas.py` |
| 6 | Mail service client | ✅ Done | `mail_client.py` (new), `config.py` |
| 7 | Verification + reset token services + audit helper | ✅ Done | `services.py` |
| 8 | In-memory rate limiter | ✅ Done | `rate_limit.py` (new), `config.py` |
| 9 | Email verification endpoints | ✅ Done | `routes/auth.py` |
| 10 | Password reset endpoints | ✅ Done | `routes/auth.py` |
| 11 | Rate limiting on login / register / forgot-password | ✅ Done | `routes/auth.py`, `app.py` |
| 12 | JWT `aud` claim verification support | ✅ Done | `crypto.py` |
| 13 | Request-ID middleware | ✅ Done | `middleware.py` (new), `app.py` |
| 14 | Audit event emission in auth + admin routes | ✅ Done | `routes/auth.py`, `routes/admin.py` |
| 15 | Admin audit log query endpoint | ✅ Done | `routes/admin.py` |
| 16 | User data export endpoint (`/v1/me/export`) | ✅ Done | `routes/me.py` (new), `services.py` |
| 17 | User account deletion endpoint (`/v1/me/delete`) | ✅ Done | `routes/me.py`, `services.py` |
| 18 | Authenticated token introspection | ✅ Done | `routes/jwks.py`, `config.py` |
| 19 | Database migration SQL | ✅ Done | `migrations/0002_auth_hardening.sql` (new) |
| 20 | TypeScript SDK expansion | ✅ Done | `client.ts` |
| 21 | README + `.env.example` updates | ✅ Done | `README.md`, `.env.example` |

## P0 Gap Coverage

| Gap from audit | Addressed by |
|----------------|-------------|
| No email verification | Tasks 1, 7, 9 |
| No password reset | Tasks 2, 7, 10 |
| JWT `aud` not verified | Task 12 |
| No rate limiting / brute-force protection | Tasks 8, 11 |
| No immutable audit log | Tasks 3, 7, 13, 14, 15 |
| No GDPR export / deletion | Tasks 16, 17 |
| Ephemeral RSA key fallback | Task 4 |
| Token introspection unauthenticated | Task 18 |

## New Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/auth/verify-email` | Consume email verification token |
| POST | `/v1/auth/forgot-password` | Request password reset (email-enumeration safe) |
| POST | `/v1/auth/reset-password` | Reset password with token |
| GET | `/v1/me/export` | GDPR data export |
| POST | `/v1/me/delete` | GDPR account deletion |
| GET | `/v1/admin/audit` | Query immutable audit log |

## Test Coverage

56 tests — all passing. Coverage spans:
- All new model types
- Token lifecycle (create → consume → expiry / replay rejection)
- Rate limiter allow/block behaviour
- Email send interception via monkeypatch
- Email verification and password reset full flows
- Audit event emission on login and register
- Admin audit query (admin-only gate enforced)
- GDPR export and deletion
- Request-ID header round-trip
- JWT audience verification
- Introspect auth key gating

## Deferred (P1/P2 — out of scope for this branch)

- MFA / TOTP
- SAML / OIDC / enterprise SSO
- Machine-to-machine / service-account tokens
- Session / device management
- Admin role hierarchy
- Alembic migrations
- Multi-language SDKs
- Hosted login UI
- ✅ OAuth token handoff now uses URL fragments
