"""Auth routes: register, login, refresh, logout, me, verify-email, forgot/reset password."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from pisigma_auth.config import get_settings
from pisigma_auth.crypto import decode_access_token
from pisigma_auth.db import get_db
from pisigma_auth.mail_client import build_password_reset_email, build_verification_email, send_mail
from pisigma_auth.metrics import inc
from pisigma_auth.middleware import get_request_context
from pisigma_auth.models import User
from pisigma_auth.rate_limit import rate_limit_dependency
from pisigma_auth.schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    ResetPasswordRequest,
    SessionOut,
    TokenResponse,
    UpdateProfileRequest,
    UserOut,
    VerifyEmailRequest,
)
from pisigma_auth.services import (
    authenticate_password,
    change_password,
    consume_password_reset_token,
    create_password_reset_token,
    create_user_with_password,
    create_verification_token,
    emit_audit,
    issue_tokens,
    list_user_sessions,
    reset_user_password,
    revoke_all_user_sessions,
    revoke_refresh,
    revoke_session,
    rotate_refresh,
    update_user_profile,
    user_to_out,
    validate_password_policy,
    verify_email_token,
)

logger = logging.getLogger("pisigma_auth.auth")
router = APIRouter(prefix="/auth", tags=["auth"])
bearer = HTTPBearer(auto_error=False)


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        claims = decode_access_token(creds.credentials, audience="pisigma-auth")
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    user = db.query(User).filter(User.id == claims["sub"]).one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account suspended")
    return user


def _emit(db: Session, action: str, actor_id: str | None, resource_type: str = "user", resource_id: str | None = None, details: dict | None = None) -> None:
    ctx = get_request_context()
    emit_audit(
        db,
        action=action,
        actor_type="user" if actor_id else "system",
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ctx.get("ip"),
        user_agent=ctx.get("user_agent"),
        details=details,
    )


@router.post(
    "/register",
    response_model=RegisterResponse,
    dependencies=[Depends(rate_limit_dependency("register"))],
)
def register(body: RegisterRequest, db: Session = Depends(get_db)) -> RegisterResponse:
    settings = get_settings()
    is_first = db.query(User).count() == 0

    # Bootstrap gate: the very first admin must either supply the bootstrap token
    # or register while open_registration is explicitly enabled.
    if is_first and not settings.open_registration:
        if not settings.bootstrap_token or body.bootstrap_token != settings.bootstrap_token:
            raise HTTPException(status_code=403, detail="Registration is closed")
    elif not settings.open_registration:
        raise HTTPException(status_code=403, detail="Registration is closed")

    errors = validate_password_policy(body.password)
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    existing = db.query(User).filter(User.email == body.email.lower().strip()).one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user = create_user_with_password(
        db,
        email=body.email,
        password=body.password,
        display_name=body.display_name,
        is_platform_admin=is_first,
        default_role="admin" if is_first else "operator",
    )
    token = create_verification_token(db, user)
    try:
        send_mail(build_verification_email(user.email, token))
    except Exception as exc:
        # Don't fail registration if mail is misconfigured in dev, but log loudly.
        logger.warning("register_mail_failed user_id=%s email=%s error=%s", user.id, user.email, exc)
    inc("auth_register")
    logger.info("register_ok user_id=%s email=%s", user.id, user.email)
    _emit(db, "user.register", user.id, resource_id=user.id)

    # When email verification is required, do not issue product-scoped tokens until
    # the user proves ownership of their email address.
    if settings.require_email_verification:
        return RegisterResponse(verification_required=True)

    tokens = issue_tokens(db, user)
    return RegisterResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        token_type=tokens.token_type,
        expires_in=tokens.expires_in,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_dependency("login"))],
)
def login(body: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = authenticate_password(db, body.email, body.password)
    if not user:
        inc("auth_login_failure")
        logger.warning("login_failed email=%s", body.email)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        logger.warning("login_suspended email=%s", body.email)
        raise HTTPException(status_code=403, detail="Account suspended")
    inc("auth_login_success")
    logger.info("login_ok user_id=%s", user.id)
    _emit(db, "user.login", user.id, resource_id=user.id)
    return issue_tokens(db, user)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_dependency("refresh"))],
)
def refresh(body: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    tokens = rotate_refresh(db, body.refresh_token)
    if not tokens:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    return tokens


@router.post("/logout")
def logout(body: LogoutRequest, db: Session = Depends(get_db)) -> dict:
    revoke_refresh(db, body.refresh_token)
    _emit(db, "user.logout", None, resource_type="session")
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)) -> UserOut:
    return user_to_out(user)


@router.post(
    "/verify-email",
    dependencies=[Depends(rate_limit_dependency("verify_email"))],
)
def verify_email(body: VerifyEmailRequest, db: Session = Depends(get_db)) -> dict:
    user = verify_email_token(db, body.token)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    _emit(db, "user.verify_email", user.id, resource_id=user.id)
    return {"ok": True, "email": user.email}


@router.post(
    "/forgot-password",
    dependencies=[Depends(rate_limit_dependency("password_reset"))],
)
def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_db)) -> dict:
    user = db.query(User).filter(User.email == body.email.lower().strip()).one_or_none()
    if user:
        token = create_password_reset_token(db, user)
        try:
            send_mail(build_password_reset_email(user.email, token))
        except Exception as exc:
            logger.warning("forgot_password_mail_failed user_id=%s email=%s error=%s", user.id, user.email, exc)
        _emit(db, "user.forgot_password", user.id, resource_id=user.id)
    # Always return 202 to avoid email enumeration
    return {"ok": True}


@router.post(
    "/reset-password",
    dependencies=[Depends(rate_limit_dependency("reset_password"))],
)
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)) -> dict:
    user = consume_password_reset_token(db, body.token)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    errors = validate_password_policy(body.password)
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    reset_user_password(db, user, body.password)
    _emit(db, "user.reset_password", user.id, resource_id=user.id)
    return {"ok": True}


@router.patch("/me", response_model=UserOut)
def update_profile(
    body: UpdateProfileRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> UserOut:
    previous_email = user.email
    try:
        updated = update_user_profile(db, user, display_name=body.display_name, email=body.email)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if body.email is not None and updated.email != previous_email:
        token = create_verification_token(db, updated)
        try:
            send_mail(build_verification_email(updated.email, token))
        except Exception as exc:
            logger.warning("email_change_mail_failed user_id=%s email=%s error=%s", updated.id, updated.email, exc)
    _emit(db, "user.update_profile", updated.id, resource_id=updated.id)
    return user_to_out(updated)


@router.post("/me/change-password")
def change_my_password(
    body: ChangePasswordRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    try:
        change_password(db, user, body.current_password, body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    _emit(db, "user.change_password", user.id, resource_id=user.id)
    return {"ok": True}


@router.get("/me/sessions", response_model=list[SessionOut])
def my_sessions(user: User = Depends(current_user), db: Session = Depends(get_db)) -> list[SessionOut]:
    return [SessionOut(**s) for s in list_user_sessions(db, user)]


@router.delete("/me/sessions")
def revoke_all_my_sessions(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    revoked = revoke_all_user_sessions(db, user)
    _emit(db, "user.revoke_all_sessions", user.id, resource_type="session")
    return {"ok": True, "revoked": revoked}


@router.delete("/me/sessions/{session_id}")
def revoke_my_session(
    session_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    if not revoke_session(db, user, session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    _emit(db, "user.revoke_session", user.id, resource_id=session_id)
    return {"ok": True}
