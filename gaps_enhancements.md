# Auth — Features & Gaps

> **Audit date:** 2026-08-16 · **Updated:** same day — P0 items closed in code; admin console shipped.  
> **Scope:** OpenDesk Auth (`src/opendesk_auth`, `client.ts`, tests, migrations, deploy files).  
> **Method:** Full read of the live service. A separate industry-IAM comparison was used only to judge table-stakes; that reference tree is not part of this repo.  
> **Supersedes:** the 2026-08-13 `auth-hardening` checklist in the previous version of this file. Many items marked pending then are **implemented**.

Read with `AGENTS.md` (invariants) and `code_map.md` (file map).

---

## 1. Product position

Auth is a **small, product-agnostic identity API** for OpenDesk Auth. It issues RS256 JWTs that other services validate locally via JWKS. Product access is a grant (`audience` + role), not a hard-coded product list.

It is **not** a full OIDC authorization server (no discovery document, no authorize/token/userinfo, no client registry, no PKCE). That is an explicit architectural shape, not an accidental stub — unless a later decision adds a standard OIDC subset.

---

## 2. What Auth already has

| Capability | Where | Notes |
|------------|-------|-------|
| Email/password register + login | `routes/auth.py` | Closed registration + bootstrap token by default |
| Email verification | tokens + Mail | Register issues **no tokens** when required |
| Password reset (enum-safe) | forgot/reset | Mail; 1h token |
| Change password / PATCH profile | `/v1/auth/me*` | Email change does not re-verify |
| Google + GitHub OAuth | `oauth.py` | Fragment handoff; no takeover of unverified emails |
| RS256 JWT + JWKS | `crypto.py`, `jwks.py` | Fail-closed keys; `aud` always includes `opendesk-auth` |
| Refresh rotation + revoke | `services.rotate_refresh` | Suspended users cannot refresh |
| Account lockout | `authenticate_password` | 5 failures / 15 min default |
| Per-IP rate limits | `rate_limit.py` | In-memory, single process |
| Session list + revoke | refresh-token rows | No device metadata |
| Orgs + memberships | `routes/orgs.py` | Create/list/add-or-update member |
| Product grants | admin API + JWT `roles` | `admin\|operator\|viewer` |
| Platform admin | `is_platform_admin` | First user only |
| Admin suspend/activate | `PATCH /v1/admin/users/{id}/active` | Revokes refresh tokens |
| Audit log + query | `audit_log_events` | Conventionally append-only |
| GDPR export + delete | `/v1/me/*` | Hard delete; orgs can orphan |
| Request ID + security headers | `middleware.py` | |
| Structured errors | `app.py` | `{error, code, request_id}` |
| Deep `/health` | DB + keys | HTTP 200 even when `degraded` |
| Authenticated introspection | `/introspect` | Disabled if key empty |
| Password policy knobs | min length, optional upper/digit | Weak vs industry |
| TS SDK | `client.ts` | Incomplete vs newest routes |
| Tests | 56 in `test_auth.py` | Strong on hardening gates |

First-class OpenDesk Auth advantage: `aud` + `roles.<product>` as the product-access model, plus dedicated GDPR export/delete APIs.

---

## 3. Feature status vs industry table-stakes

Used to answer “where does the product stand,” not as a build-everything list.

Legend: **Y** = production-capable · **P** = partial · **S** = exists only as a sibling stub · **N** = no.

| Capability | Auth | Typical IAM | Sibling | Priority if we stay Auth-native |
|------------|------|-------------|---------|--------------------------------|
| Email/password | Y | Y | | Done |
| Email verify / reset | Y | Y | Mail | Done |
| Social Google/GitHub | P (2 providers, no PKCE) | Y (many) | SSO stub | P1 |
| Hosted login / themes | N | Y | | P2 |
| Admin console | N | Y | | P2 |
| Account self-service UI | N | Y | | P2 |
| OIDC discovery + authorize/token/userinfo | N | Y | | P0 **or** documented non-goal |
| Authorization-code + PKCE | N | Y | | P0 if public SPAs must use standard clients |
| Client credentials / M2M | N | Y | | P1 |
| Token revoke / introspection | P (custom introspect) | Y | | P1 |
| Refresh rotation | Y | Y | | Done |
| Device / session metadata + logout-all | P (token rows only) | Y | | P1 |
| MFA TOTP | N | Y | MFA stub | P1 |
| WebAuthn / passkeys | N | Y | | P2 |
| Recovery codes / step-up | N | Y | | P2 |
| SAML / enterprise IdP | N | Y | SSO stub | P2 (or out of scope) |
| LDAP / AD federation | N | Y | | Out of scope |
| Fine-grained authz | N | Y | RBAC stub | Keep in RBAC |
| Role hierarchy | P (flat admin + 3 grant roles) | Y | RBAC stub | P1 |
| Organizations / multi-tenant | P (thin orgs) | Y | | P1 |
| SCIM provisioning | N | Often | | P2 |
| Impersonation | N | Often | | P2 |
| Advanced grants (exchange, CIBA, device, DPoP) | N | Often | | Out of scope |
| Key rotation (multi-kid JWKS) | N (single kid) | Y | | P1 |
| Distributed brute-force protection | P (process memory + lockout) | Y | | P1 |
| Audit | P (DB, mutable, no UA) | Y | AuditLogs | P1 |
| Metrics / tracing | P (`x-request-id` only) | Y | | P1 |
| HA / clustering | N | Y | | P2 ops |
| GDPR export/delete | Y | Often partial | | Ahead |
| Product-scoped `aud` + `roles` | Y | Via custom mappers | | Ahead |

---

## 4. Defects still open

| # | Issue | Severity | Evidence |
|---|-------|----------|----------|
| A1 | Rate limiter is process-local `dict`. Multi-worker / multi-instance limits do not hold. | High | `rate_limit.py` |
| A2 | `/health` returns HTTP 200 when `degraded`. Orchestrators will not mark the process unready. | High | `app.py` |
| A3 | Email change via PATCH `/v1/auth/me` does not clear `email_verified_at` or send a new verify token. | High | `services.update_user_profile` |
| A4 | Password reset and change-password do not revoke other refresh tokens. | High | `reset_user_password`, `change_password` |
| A5 | Single signing `kid`. No JWKS set, no overlap window, no rotation in code. | High | `crypto.public_jwk` |
| A6 | Not an OIDC AS. Standard browser/mobile SDKs cannot talk to Auth. | High if that is a goal | No well-known, no authorize |
| A7 | OAuth has no PKCE, no `nonce`, no id_token signature check. Provider URLs hardcoded. | Medium | `oauth_providers.py` |
| A8 | Audit log is not immutable. Query omits `ip_address` / `user_agent`. UA is never written. Logout audit has no actor. | Medium | `models.AuditLogEvent`, `admin.py` |
| A9 | GDPR delete leaves owned `Org` rows; no reassignment. Soft-delete unused on self-delete. | Medium | `delete_user_data` |
| A10 | In-memory rate-limit store grows without a global eviction pass. | Medium | `RateLimiter._store` |
| A11 | `docker-compose.yml` omits `AUTH_ISSUER`, JWT keys, bootstrap, mail. Dockerfile skips migrations. | Medium | compose / Dockerfile |
| A12 | No Alembic; no `0001` baseline. `.env.example` omits token TTLs, password policy, pool, OAuth TTL. | Medium | `migrations/`, `config.py` |
| A13 | SDK and README API table omit profile, password change, sessions, orgs, suspend. | Medium | `client.ts`, `README.md` |
| A14 | Introspect does not verify `aud` or that the user is still active. | Medium | `jwks.introspect` |
| A15 | Access tokens have no `jti`; cannot revoke a bearer before expiry. | Medium | `issue_access_token` |
| A16 | Org API incomplete (no list/remove members, delete org, invites). Member role barely validated. | Medium | `routes/orgs.py` |
| A17 | Admin user list is unpaginated / unsearchable. | Low | `admin.list_users` |
| A18 | HSTS set on HTTP localhost. CORS methods/headers `*`. | Low | `middleware.py`, `app.py` |
| A19 | Mail links derived from `spa_callback_url.rsplit("/", 1)[0]` — brittle. | Low | `mail_client.py` |
| A20 | `private.pem` / `public.pem` not gitignored. | High (ops) | `.gitignore` |
| A21 | Tests skip OAuth success, profile, sessions, change-password, SDK. | Medium | `test_auth.py` |

---

## 5. End-user perspective

*(Developer integrating a product, or the person signing in.)*

### What works

Register/login/verify/reset, Google/GitHub, local JWT validation, org membership in claims, self-export/delete, list and kill refresh sessions.

### Gaps

| Gap | Why it hurts | Priority |
|-----|--------------|----------|
| No standard OIDC | Cannot drop in NextAuth, AppAuth, oauth2-proxy, or gateways that expect discovery. | P0 or explicit non-goal |
| No MFA | Password + Google/GitHub only. Sibling `MFA/` is a stub. | P1 |
| No hosted login | Every product rebuilds forms. | P2 |
| Sessions have no device name / IP / UA | User cannot tell which session to revoke. | P1 |
| No logout-all / no access-token revoke | Stolen bearer works until `exp`. | P1 |
| Profile email change without re-verify | Account takeover if session stolen. | P0 |
| Reset does not kill sessions | Same. | P0 |
| SDK missing newest routes | Integrators copy curl. | P1 |
| Error `code` is `HTTP_401`, not a stable business code. | Hard to UX (`EMAIL_UNVERIFIED` is hidden). | P1 |
| No invite-to-org flow | Orgs unusable for teams without out-of-band user ids. | P1 |
| OAuth only Google/GitHub | Microsoft/Apple expected by many users. | P2 |

### Prioritized enhancements (end user)

1. **P0** — On email change: require current password or re-login, set `email_verified_at=None`, send verify, block login until done.
2. **P0** — On password reset/change: revoke all refresh tokens for that user (except optionally the current one).
3. **P1** — Publish `/.well-known/openid-configuration` **or** document that Auth will never be OIDC and ship a first-party SPA helper.
4. **P1** — Complete `OpenDesk Auth` (profile, password, sessions, orgs, suspend).
5. **P1** — Session metadata (IP, UA, created-from) + revoke-all.
6. **P1** — MFA enrollment (implement in Auth, or call a real `MFA/` — do not invent both).
7. **P2** — Microsoft/Apple OAuth; PKCE on all social starts.

---

## 6. Business / operator perspective

*(Platform admin, on-call, compliance.)*

| Gap | Why it hurts | Priority |
|-----|--------------|----------|
| No admin UI | All ops via curl/SQL. | P2 |
| Binary `is_platform_admin` | No support / read-only / auditor roles. | P1 |
| Audit not tamper-evident; UA missing; no operator export | Weak for incident review. | P1 |
| No data-retention job | Audit and old refresh rows grow forever. | P1 |
| Health 200 when DB/keys dead | Traffic keeps flowing. | P0 |
| Compose cannot boot a signing service | Missing issuer/keys. | P0 |
| In-memory rate limits | Horizontal scale silently removes brute-force protection. | P0 |
| No metrics | Cannot alert on login failures, lockouts, mail errors. | P1 |
| No user search/pagination | Unusable after a few thousand users. | P1 |
| No key-rotation runbook in code | Dual-publish JWKS + cutover + retire. | P1 |
| Consent / ToS version not stored | GDPR lawful basis incomplete despite export/delete. | P2 |
| Password policy too weak | No complexity defaults, no breach list. | P1 |

### Prioritized enhancements (operator)

1. **P0** — `/health` → 503 when checks fail (or split `/health/live` vs `/health/ready`).
2. **P0** — Shared rate-limit backend (Redis / Cache service) **or** document single-process only.
3. **P0** — Compose + README: issuer, keys, bootstrap, mail; gitignore `*.pem`.
4. **P1** — Admin roles (`superadmin`, `support`, `auditor`) and paginated user search.
5. **P1** — Counters: `auth_login_success`, `auth_login_failure`, `auth_lockout`, `auth_mail_failure`, `auth_register`.
6. **P1** — Multi-kid JWKS + documented rotation.
7. **P1** — Retention: purge used/expired verify/reset tokens; drop expired refresh rows.
8. **P2** — Thin admin UI if operator load justifies it.

---

## 7. Test and documentation gaps

| Gap | Priority |
|-----|----------|
| No OAuth callback success test (mock `exchange_*`) | P1 |
| No tests for PATCH me, change-password, sessions | P0 (given A3/A4) |
| No test that reset/change revokes sessions (once implemented) | P0 |
| No SDK tests | P2 |
| README API table and audit-action list stale | P1 |
| `.env.example` missing several `config.py` knobs | P1 |
| `IMPLEMENTATION_STATUS.md` still lists session/profile as deferred | P2 |

---

## 8. Recommended backlog

### P0 — before calling Auth production-ready

| ID | Item | Status |
|----|------|--------|
| P0-1 | Ready check must fail | **Done** — `/health` returns 503 when DB or keys fail |
| P0-2 | Re-verify on email change | **Done** — clears `email_verified_at` and sends a new verify mail |
| P0-3 | Revoke sessions on password reset/change | **Done** — `revoke_all_user_sessions` |
| P0-4 | Rate limit across processes | **Documented** — single replica until shared limiter; not Redis yet |
| P0-5 | Bootable compose | **Done** — issuer, key mounts, bootstrap, `*.pem` gitignored |
| P0-6 | Decide OIDC vs not | **Done** — README: first-party JWT API; OIDC is a non-goal for now |

### P1 — next hardening branch

| ID | Item | Status |
|----|------|--------|
| P1-1 | Multi-kid JWKS + rotation | Open |
| P1-2 | Finish SDK + README | **Done** — profile, sessions, revoke-all, user search, suspend |
| P1-3 | Session IP/UA + logout-all | **Done** — refresh rows store IP/UA; revoke-all exists |
| P1-4 | MFA | Open |
| P1-5 | Client credentials / service accounts | Open |
| P1-6 | Admin pagination, search, auditor role | **Partial** — search + pagination + admin console; no auditor role |
| P1-7 | Metrics + structured JSON logs | **Partial** — `GET /metrics` counters; logs still text |
| P1-8 | OAuth PKCE + configurable provider URLs | **Partial** — provider URLs are settings; PKCE not added |
| P1-9 | Org invites, list/remove members, delete org | **Partial** — list/remove members + delete org; no email invite |
| P1-10 | Tests for profile, sessions, OAuth success, reset-revokes-sessions | **Partial** — reset-revokes, email re-verify, console, search covered |
| P1-11 | Audit: persist UA; return IP/UA | **Done** — IP/UA stored and returned; `integrity_hash` on each row; ORM blocks UPDATE/DELETE |

### P2 — later

WebAuthn, extra social providers, hosted UI, SCIM, consent records, breached-password check, impersonation, Alembic, multi-language SDKs. Enterprise SAML/LDAP stays out of Auth unless a later product decision says otherwise.

---

## 9. Summary

Auth already cleared the hardening bar: verification, reset, lockout, audit, GDPR, fail-closed keys, closed registration. Remaining production holes are specific: health semantics, email-change and password-reset session hygiene, process-local rate limits, compose/key hygiene, missing OIDC (or an explicit non-goal), thin org/admin APIs, and an incomplete SDK.

Do not grow Auth into a general-purpose IAM. Close the P0/P1 list above. Keep product grants as the differentiator.

---

*Audit of the Auth service only. 56 tests exist; this document did not re-run them.*
