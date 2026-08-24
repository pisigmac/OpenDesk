# OpenDesk Auth Public UI — Design Specification

**Date**: 2026-08-25  
**Scope**: Public authentication UI screens (`static/auth.html`) for OpenDesk Auth  
**Status**: Approved  

---

## 1. Overview

OpenDesk Auth requires a production-ready, highly polished public authentication UI for multi-product SaaS deployments. This document details the visual design, user flows, architecture, and API integration for `static/auth.html`, which will host Login, Register, Forgot Password, Reset Password, Email Verification, and OAuth callback screens.

---

## 2. Design System & Aesthetics

### Visual Identity
- **Personality**: Minimal, developer-focused, premium monochrome (Linear/Vercel aesthetic).
- **Layout Structure**: 
  - Desktop: 50/50 Split layout (Left: Brand & Atmosphere, Right: Interactive Form Panel).
  - Mobile/Tablet: Single column layout; brand header stacked above the form panel.

### Design Tokens
- **Background (Base)**: `#0a0a0d`
- **Panel / Card Background**: `#111114`
- **Input Background**: `#18181b`
- **Border Tone**: `rgba(255, 255, 255, 0.08)`
- **Border Focus**: `rgba(255, 255, 255, 0.25)`
- **Primary Text**: `#f4f4f5`
- **Muted Text**: `#71717a`
- **Subtle / Dim Text**: `#3f3f46`
- **Primary Button**: Background `#ffffff`, Text `#000000`, Hover `#e4e4e7`
- **Error / Alert**: Background `rgba(239, 68, 68, 0.1)`, Text `#f87171`, Border `rgba(239, 68, 68, 0.2)`
- **Success Alert**: Background `rgba(34, 197, 94, 0.1)`, Text `#4ade80`, Border `rgba(34, 197, 94, 0.2)`
- **Font Stack**: System UI (`-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`) with monospace for code/tokens (`ui-monospace, SFMono-Regular, Consolas, monospace`).

---

## 3. Architecture & Routing

### Single-File Application (`static/auth.html`)
To maintain consistency with `static/index.html` and `static/admin.html`, the entire UI will be implemented in a zero-dependency HTML file containing CSS and vanilla JS.

### Client-Side Hash Routing
The application will use window hash routes to render the relevant screen state dynamically without page reloads:

| Hash | View | Purpose |
|---|---|---|
| `#login` (default) | Login View | Email/password login & OAuth start triggers |
| `#register` | Register View | Account creation with password validation & bootstrap handling |
| `#forgot-password` | Forgot Password View | Password reset request form |
| `#reset-password` | Reset Password View | Password confirmation form (requires `?token=`) |
| `#verify-email` | Verify Email View | Email verification status view (reads `?token=`) |
| `#callback` | OAuth Callback View | Handles fragment/query tokens post-OAuth redirect |

---

## 4. Screen Specifications & Flows

### 4.1 Left Brand Panel (Desktop)
- Logo icon: Clean SVG keymark/lock badge.
- Brand Title: `OPENDESK AUTH`
- Subtitle: `Secure identity infrastructure`
- Footer badge: `OpenDesk Identity v1.0`

### 4.2 Login View (`#login`)
- **Inputs**: Email (`type="email"`), Password (`type="password"` with show/hide toggle).
- **Options**: "Remember Me" checkbox, "Forgot Password?" link leading to `#forgot-password`.
- **OAuth Buttons**: Google and GitHub buttons invoking `/v1/oauth/{provider}/start`.
- **API Call**: `POST /v1/auth/login`
- **Response Handling**:
  - `200 OK`: Save tokens to localStorage/sessionStorage based on "Remember Me", redirect to query param `redirect_url` or default landing.
  - `401 Unauthorized`: Render generic error toast ("Invalid credentials").
  - `429 Rate Limited`: Display lockout timer / countdown.

### 4.3 Register View (`#register`)
- **Inputs**: Email, Password, Confirm Password.
- **Bootstrap Mode**: If registration is closed (`AUTH_OPEN_REGISTRATION=false`), reveal Bootstrap Token field.
- **Validation**: Live strength indicator checking password length (>=8 chars).
- **API Call**: `POST /v1/auth/register`
- **Response Handling**:
  - `200 OK` (with `verification_required: true`): Switch view to verification prompt notice.
  - `200 OK` (with tokens): Store tokens and redirect.

### 4.4 Forgot & Reset Password Views
- **Forgot (`#forgot-password`)**: Email field. Submits `POST /v1/auth/forgot-password`. Always shows success message to prevent user enumeration.
- **Reset (`#reset-password`)**: Token parsed from URL (`?token=...`), New Password, Confirm Password. Submits `POST /v1/auth/reset-password`.

### 4.5 Verify Email & OAuth Callbacks
- **Verify (`#verify-email`)**: Auto-submits `POST /v1/auth/verify-email` using `token` parameter. Displays success or failure alert.
- **OAuth Callback (`#callback`)**: Reads URL hash fragment (e.g. `#access_token=...&refresh_token=...`), validates token storage, and completes redirect.

---

## 5. Security & Invariant Adherence

Per `AGENTS.md` system rules:
1. **URL Fragment Security**: OAuth state callback processes tokens passed via URL fragment (`#access_token=...`), never query strings.
2. **Error Envelope Standard**: Parses all server API errors using standard format `{error: string, code: string, request_id: string}`.
3. **No Hardcoded Product Names**: UI remains product-agnostic for OpenDesk Auth.

---

## 6. Implementation Plan & Verification

1. **Create `static/auth.html`**: Complete split-screen HTML layout with CSS design tokens and responsive queries.
2. **Implement Client Script**: Hash router, API fetch wrapper, toast notification manager, input validation.
3. **Update Server Serving**: Ensure FastAPI serves `static/auth.html` or exposes `/auth` route cleanly.
4. **Verification**: Run local Auth server, test all forms via browser/curl, run `pytest tests/ -v` to ensure zero backend regression.
