"""Domain helpers for users, tokens, orgs."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from opendesk_auth.config import Settings, get_settings
from opendesk_auth.crypto import (
    generate_urlsafe_token,
    hash_password,
    hash_token,
    issue_access_token,
    new_refresh_token,
    verify_password,
)
from opendesk_auth.models import (
    AuditLogEvent,
    EmailVerificationToken,
    Identity,
    Membership,
    Org,
    PasswordResetToken,
    ProductGrant,
    RefreshToken,
    User,
)
from opendesk_auth.schemas import GrantOut, OrgOut, TokenResponse, UserOut


def user_to_out(user: User) -> UserOut:
    orgs = [
        OrgOut(
            id=m.org.id,
            name=m.org.name,
            role=m.role,
            workspace_id=m.workspace_id,
        )
        for m in user.memberships
    ]
    grants = [GrantOut(audience=g.audience, role=g.role) for g in user.grants]
    return UserOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        is_platform_admin=user.is_platform_admin,
        is_active=user.is_active,
        orgs=orgs,
        grants=grants,
    )


def primary_org(user: User) -> Membership | None:
    if not user.memberships:
        return None
    owners = [m for m in user.memberships if m.role == "owner"]
    return owners[0] if owners else user.memberships[0]


def issue_tokens(db: Session, user: User, settings: Settings | None = None) -> TokenResponse:
    settings = settings or get_settings()
    membership = primary_org(user)
    roles = {g.audience: g.role for g in user.grants}
    audiences = list(roles.keys())
    access = issue_access_token(
        sub=user.id,
        email=user.email,
        org_id=membership.org_id if membership else None,
        workspace_id=membership.workspace_id if membership else None,
        audiences=audiences,
        roles=roles,
        settings=settings,
    )
    from opendesk_auth.middleware import get_request_context

    ctx = get_request_context()
    refresh = new_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_token(refresh),
            expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_days),
            ip_address=ctx.get("ip"),
            user_agent=ctx.get("user_agent"),
        )
    )
    db.commit()
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.access_token_minutes * 60,
    )


def ensure_default_grant(
    db: Session,
    user: User,
    audience: str,
    role: str = "operator",
) -> None:
    existing = next((g for g in user.grants if g.audience == audience), None)
    if existing:
        return
    grant = ProductGrant(user_id=user.id, audience=audience, role=role)
    db.add(grant)
    db.commit()
    db.refresh(user)


def _apply_default_grants(db: Session, user: User, *, role: str) -> None:
    settings = get_settings()
    for audience in settings.default_audience_list():
        db.add(ProductGrant(user_id=user.id, audience=audience, role=role))


def create_user_with_password(
    db: Session,
    *,
    email: str,
    password: str,
    display_name: str | None = None,
    is_platform_admin: bool = False,
    default_role: str | None = None,
) -> User:
    settings = get_settings()
    role = default_role or ("admin" if is_platform_admin else settings.default_role)
    user = User(
        email=email.lower().strip(),
        password_hash=hash_password(password),
        display_name=display_name,
        is_platform_admin=is_platform_admin,
    )
    db.add(user)
    db.flush()
    db.add(Identity(user_id=user.id, provider="password", provider_subject=user.email))
    org = Org(name=f"{user.email}'s org")
    db.add(org)
    db.flush()
    db.add(Membership(org_id=org.id, user_id=user.id, role="owner", workspace_id=org.id))
    _apply_default_grants(db, user, role=role)
    db.commit()
    db.refresh(user)
    return user


def authenticate_password(db: Session, email: str, password: str) -> User | None:
    settings = get_settings()
    user = db.query(User).filter(User.email == email.lower().strip()).one_or_none()
    if not user or not user.password_hash:
        return None

    now = datetime.now(timezone.utc)

    # Check account lockout before processing the password.
    if user.locked_until:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > now:
            return None

    if not verify_password(password, user.password_hash):
        # Record failed attempt and lock account if threshold reached.
        if settings.account_lockout_max_attempts > 0:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.account_lockout_max_attempts:
                user.locked_until = now + timedelta(
                    seconds=settings.account_lockout_duration_seconds
                )
            db.commit()
        return None

    # Password is correct: clear any prior lockout state.
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
    db.refresh(user)

    # Email verification is required for password-based accounts.
    if settings.require_email_verification and not user.email_verified_at:
        return None

    if not user.is_active:
        return None
    return user


def find_or_create_oauth_user(
    db: Session,
    *,
    provider: str,
    provider_subject: str,
    email: str,
    display_name: str | None,
) -> User:
    identity = (
        db.query(Identity)
        .filter(Identity.provider == provider, Identity.provider_subject == provider_subject)
        .one_or_none()
    )
    if identity:
        return identity.user

    email_l = email.lower().strip()
    existing = db.query(User).filter(User.email == email_l).one_or_none()

    # Security: only link OAuth to an existing password account when that account's
    # email address has already been verified. An unverified password account cannot
    # be taken over via OAuth; the caller must verify the email first.
    if existing is not None:
        if existing.email_verified_at is None:
            raise ValueError("Email exists but is not verified. Verify the email before linking OAuth.")
        existing.identities.append(
            Identity(provider=provider, provider_subject=provider_subject)
        )
        db.commit()
        db.refresh(existing)
        return existing

    settings = get_settings()
    # OAuth providers are treated as already verified (they own the email).
    user = User(
        email=email_l,
        display_name=display_name,
        password_hash=None,
        email_verified_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.flush()
    org = Org(name=f"{email_l}'s org")
    db.add(org)
    db.flush()
    db.add(Membership(org_id=org.id, user_id=user.id, role="owner", workspace_id=org.id))
    _apply_default_grants(db, user, role=settings.default_role)
    db.add(Identity(user_id=user.id, provider=provider, provider_subject=provider_subject))
    db.commit()
    db.refresh(user)
    return user


def rotate_refresh(db: Session, refresh_token: str, settings: Settings | None = None) -> TokenResponse | None:
    settings = settings or get_settings()
    row = db.query(RefreshToken).filter(RefreshToken.token_hash == hash_token(refresh_token)).one_or_none()
    if not row or row.revoked:
        return None
    if row.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return None
    user = db.query(User).filter(User.id == row.user_id).one()
    # Fail closed: suspended/deactivated accounts cannot extend their session.
    if not user.is_active:
        return None
    row.revoked = True
    db.commit()
    return issue_tokens(db, user, settings)


def revoke_refresh(db: Session, refresh_token: str) -> bool:
    row = db.query(RefreshToken).filter(RefreshToken.token_hash == hash_token(refresh_token)).one_or_none()
    if not row:
        return False
    row.revoked = True
    db.commit()
    return True


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------

def create_verification_token(db: Session, user: User) -> str:
    raw = generate_urlsafe_token()
    token = EmailVerificationToken(
        user_id=user.id,
        token_hash=hash_token(raw),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db.add(token)
    db.commit()
    return raw


def verify_email_token(db: Session, raw_token: str) -> User | None:
    token_hash = hash_token(raw_token)
    now = datetime.now(timezone.utc)
    row = (
        db.query(EmailVerificationToken)
        .filter(
            EmailVerificationToken.token_hash == token_hash,
            EmailVerificationToken.used_at.is_(None),
            EmailVerificationToken.expires_at > now,
        )
        .first()
    )
    if not row:
        return None
    row.used_at = now
    user = db.query(User).filter(User.id == row.user_id).one()
    user.email_verified_at = now
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

def create_password_reset_token(db: Session, user: User) -> str:
    raw = generate_urlsafe_token()
    token = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_token(raw),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(token)
    db.commit()
    return raw


def consume_password_reset_token(db: Session, raw_token: str) -> User | None:
    token_hash = hash_token(raw_token)
    now = datetime.now(timezone.utc)
    row = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .first()
    )
    if not row:
        return None
    row.used_at = now
    db.commit()
    user = db.query(User).filter(User.id == row.user_id).one()
    return user


def reset_user_password(db: Session, user: User, password: str) -> None:
    user.password_hash = hash_password(password)
    revoke_all_user_sessions(db, user, commit=False)
    db.commit()


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def _audit_integrity_hash(*, action: str, actor_type: str, actor_id: str | None, resource_type: str, resource_id: str | None, details: str | None) -> str:
    import hashlib

    payload = "|".join(
        [
            action,
            actor_type,
            actor_id or "",
            resource_type,
            resource_id or "",
            details or "",
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def emit_audit(
    db: Session,
    *,
    action: str,
    actor_type: str = "system",
    actor_id: str | None = None,
    resource_type: str,
    resource_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict | None = None,
) -> None:
    event = AuditLogEvent(
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details=json.dumps(details) if details else None,
    )
    event.integrity_hash = _audit_integrity_hash(
        action=event.action,
        actor_type=event.actor_type,
        actor_id=event.actor_id,
        resource_type=event.resource_type,
        resource_id=event.resource_id,
        details=event.details,
    )
    db.add(event)
    db.commit()


# ---------------------------------------------------------------------------
# User data export / deletion (GDPR)
# ---------------------------------------------------------------------------

def export_user_data(db: Session, user: User) -> dict:
    audit_events = (
        db.query(AuditLogEvent)
        .filter(AuditLogEvent.actor_id == user.id)
        .order_by(AuditLogEvent.occurred_at.desc())
        .limit(200)
        .all()
    )
    return {
        "user": user_to_out(user),
        "identities": [
            {
                "provider": i.provider,
                "provider_subject": i.provider_subject,
                "created_at": i.created_at.isoformat(),
            }
            for i in user.identities
        ],
        "memberships": [
            {
                "org_id": m.org_id,
                "role": m.role,
                "workspace_id": m.workspace_id,
                "created_at": m.created_at.isoformat(),
            }
            for m in user.memberships
        ],
        "grants": [
            {"audience": g.audience, "role": g.role, "created_at": g.created_at.isoformat()}
            for g in user.grants
        ],
        "refresh_tokens": [
            {
                "id": t.id,
                "expires_at": t.expires_at.isoformat(),
                "revoked": t.revoked,
                "created_at": t.created_at.isoformat(),
            }
            for t in user.refresh_tokens
        ],
        "audit_events": [
            {
                "id": e.id,
                "action": e.action,
                "occurred_at": e.occurred_at.isoformat(),
                "details": e.details,
            }
            for e in audit_events
        ],
    }


def delete_user_data(db: Session, user: User) -> None:
    for token in list(user.refresh_tokens):
        db.delete(token)
    for token in list(user.verification_tokens):
        db.delete(token)
    for token in list(user.reset_tokens):
        db.delete(token)
    for identity in list(user.identities):
        db.delete(identity)
    for membership in list(user.memberships):
        db.delete(membership)
    for grant in list(user.grants):
        db.delete(grant)
    db.delete(user)
    db.commit()

# ---------------------------------------------------------------------------
# Password policy validation
# ---------------------------------------------------------------------------

def validate_password_policy(password: str) -> list[str]:
    """Return a list of policy violation messages. Empty = valid."""
    settings = get_settings()
    errors: list[str] = []
    if len(password) < settings.password_min_length:
        errors.append(f"Password must be at least {settings.password_min_length} characters.")
    if settings.password_require_uppercase and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter.")
    if settings.password_require_digit and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit.")
    return errors


# ---------------------------------------------------------------------------
# Profile management
# ---------------------------------------------------------------------------

def update_user_profile(
    db: Session,
    user: User,
    *,
    display_name: str | None = None,
    email: str | None = None,
) -> User:
    if display_name is not None:
        user.display_name = display_name
    if email is not None:
        email_l = email.lower().strip()
        existing = db.query(User).filter(User.email == email_l, User.id != user.id).one_or_none()
        if existing:
            raise ValueError("Email already in use")
        if email_l != user.email:
            user.email = email_l
            user.email_verified_at = None
    db.commit()
    db.refresh(user)
    return user


def change_password(db: Session, user: User, current_password: str, new_password: str) -> None:
    if not user.password_hash or not verify_password(current_password, user.password_hash):
        raise ValueError("Current password is incorrect")
    errors = validate_password_policy(new_password)
    if errors:
        raise ValueError("; ".join(errors))
    user.password_hash = hash_password(new_password)
    revoke_all_user_sessions(db, user, commit=False)
    db.commit()


# ---------------------------------------------------------------------------
# Admin user lifecycle (suspend / activate)
# ---------------------------------------------------------------------------

def set_user_active(db: Session, user: User, *, is_active: bool) -> User:
    user.is_active = is_active
    if not is_active:
        user.deleted_at = datetime.now(timezone.utc)
        # Revoke all active refresh tokens
        for token in user.refresh_tokens:
            token.revoked = True
    else:
        user.deleted_at = None
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Session listing
# ---------------------------------------------------------------------------

def list_user_sessions(db: Session, user: User) -> list[dict]:
    now = datetime.now(timezone.utc)
    return [
        {
            "id": t.id,
            "created_at": t.created_at.isoformat(),
            "expires_at": t.expires_at.isoformat(),
            "revoked": t.revoked,
            "expired": t.expires_at.replace(tzinfo=timezone.utc) < now,
            "ip_address": t.ip_address,
            "user_agent": t.user_agent,
        }
        for t in sorted(user.refresh_tokens, key=lambda t: t.created_at, reverse=True)
    ]


def revoke_all_user_sessions(db: Session, user: User, *, commit: bool = True) -> int:
    rows = (
        db.query(RefreshToken)
        .filter(RefreshToken.user_id == user.id, RefreshToken.revoked.is_(False))
        .all()
    )
    for token in rows:
        token.revoked = True
    if commit:
        db.commit()
    return len(rows)


def revoke_session(db: Session, user: User, session_id: str) -> bool:
    token = db.query(RefreshToken).filter(
        RefreshToken.id == session_id,
        RefreshToken.user_id == user.id,
    ).one_or_none()
    if not token:
        return False
    token.revoked = True
    db.commit()
    return True


# ---------------------------------------------------------------------------
# OAuth state cleanup
# ---------------------------------------------------------------------------

def purge_stale_oauth_states(db: Session) -> int:
    from opendesk_auth.models import OAuthState
    settings = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.oauth_state_ttl_seconds)
    stale = db.query(OAuthState).filter(OAuthState.created_at < cutoff).all()
    count = len(stale)
    for row in stale:
        db.delete(row)
    if count:
        db.commit()
    return count
