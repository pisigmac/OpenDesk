"""OAuth provider helpers (Google, GitHub)."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from pisigma_auth.config import Settings


@dataclass
class OAuthProfile:
    provider: str
    subject: str
    email: str
    display_name: str | None


def google_authorize_url(settings: Settings, state: str) -> str:
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    return f"{settings.google_authorize_url}?{urlencode(params)}"


def github_authorize_url(settings: Settings, state: str) -> str:
    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": settings.github_redirect_uri,
        "scope": "read:user user:email",
        "state": state,
    }
    return f"{settings.github_authorize_url}?{urlencode(params)}"


def exchange_google_code(settings: Settings, code: str) -> OAuthProfile:
    with httpx.Client(timeout=30.0) as client:
        token_res = client.post(
            settings.google_token_url,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": settings.google_redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        token_res.raise_for_status()
        access = token_res.json()["access_token"]
        info = client.get(
            settings.google_userinfo_url,
            headers={"Authorization": f"Bearer {access}"},
        )
        info.raise_for_status()
        data = info.json()
    email = data.get("email")
    if not email:
        raise ValueError("Google account has no email")
    return OAuthProfile(
        provider="google",
        subject=str(data["sub"]),
        email=email,
        display_name=data.get("name"),
    )


def exchange_github_code(settings: Settings, code: str) -> OAuthProfile:
    with httpx.Client(timeout=30.0) as client:
        token_res = client.post(
            settings.github_token_url,
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": settings.github_redirect_uri,
            },
        )
        token_res.raise_for_status()
        access = token_res.json()["access_token"]
        user_res = client.get(
            settings.github_userinfo_url,
            headers={"Authorization": f"Bearer {access}", "Accept": "application/json"},
        )
        user_res.raise_for_status()
        user = user_res.json()
        email = user.get("email")
        if not email:
            emails_res = client.get(
                settings.github_emails_url,
                headers={"Authorization": f"Bearer {access}", "Accept": "application/json"},
            )
            emails_res.raise_for_status()
            emails = emails_res.json()
            primary = next((e for e in emails if e.get("primary") and e.get("verified")), None)
            email = (primary or emails[0])["email"] if emails else None
        if not email:
            raise ValueError("GitHub account has no email")
    return OAuthProfile(
        provider="github",
        subject=str(user["id"]),
        email=email,
        display_name=user.get("name") or user.get("login"),
    )
