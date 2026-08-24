"""OAuth start/callback routes."""

from __future__ import annotations

import logging
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from opendesk_auth.config import get_settings
from opendesk_auth.db import get_db
from opendesk_auth.models import OAuthState
from opendesk_auth.oauth_providers import (
    exchange_github_code,
    exchange_google_code,
    github_authorize_url,
    google_authorize_url,
)
from opendesk_auth.services import find_or_create_oauth_user, issue_tokens, purge_stale_oauth_states

logger = logging.getLogger("opendesk_auth.oauth")
router = APIRouter(prefix="/oauth", tags=["oauth"])


def _store_state(db: Session, provider: str) -> str:
    settings = get_settings()
    state = secrets.token_urlsafe(24)
    db.add(OAuthState(state=state, provider=provider, redirect_uri=settings.spa_callback_url))
    db.commit()
    # Opportunistically purge stale states (non-blocking, best-effort)
    try:
        purge_stale_oauth_states(db)
    except Exception:
        pass
    return state


def _consume_state(db: Session, state: str, provider: str) -> OAuthState:
    row = (
        db.query(OAuthState)
        .filter(OAuthState.state == state, OAuthState.provider == provider)
        .one_or_none()
    )
    if not row:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")
    db.delete(row)
    db.commit()
    return row


def _redirect_with_tokens(spa_url: str, access: str, refresh: str, expires_in: int) -> RedirectResponse:
    """Redirect to SPA with tokens in the URL fragment (not query params) to avoid
    exposure in server logs, browser history, and Referer headers."""
    fragment = urlencode(
        {
            "access_token": access,
            "refresh_token": refresh,
            "expires_in": str(expires_in),
            "token_type": "bearer",
        }
    )
    return RedirectResponse(f"{spa_url}#{fragment}")


@router.get("/google/start")
def google_start(db: Session = Depends(get_db)) -> RedirectResponse:
    settings = get_settings()
    if not settings.google_client_id:
        raise HTTPException(status_code=501, detail="Google OAuth not configured")
    state = _store_state(db, "google")
    return RedirectResponse(google_authorize_url(settings, state))


@router.get("/google/callback")
def google_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    settings = get_settings()
    oauth_state = _consume_state(db, state, "google")
    try:
        profile = exchange_google_code(settings, code)
    except Exception:
        logger.warning("google_oauth_exchange_failed")
        raise HTTPException(status_code=400, detail="Google OAuth failed")
    user = find_or_create_oauth_user(
        db,
        provider="google",
        provider_subject=profile.subject,
        email=profile.email,
        display_name=profile.display_name,
    )
    tokens = issue_tokens(db, user)
    return _redirect_with_tokens(
        oauth_state.redirect_uri, tokens.access_token, tokens.refresh_token, tokens.expires_in
    )


@router.get("/github/start")
def github_start(db: Session = Depends(get_db)) -> RedirectResponse:
    settings = get_settings()
    if not settings.github_client_id:
        raise HTTPException(status_code=501, detail="GitHub OAuth not configured")
    state = _store_state(db, "github")
    return RedirectResponse(github_authorize_url(settings, state))


@router.get("/github/callback")
def github_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    settings = get_settings()
    oauth_state = _consume_state(db, state, "github")
    try:
        profile = exchange_github_code(settings, code)
    except Exception:
        logger.warning("github_oauth_exchange_failed")
        raise HTTPException(status_code=400, detail="GitHub OAuth failed")
    user = find_or_create_oauth_user(
        db,
        provider="github",
        provider_subject=profile.subject,
        email=profile.email,
        display_name=profile.display_name,
    )
    tokens = issue_tokens(db, user)
    return _redirect_with_tokens(
        oauth_state.redirect_uri, tokens.access_token, tokens.refresh_token, tokens.expires_in
    )
