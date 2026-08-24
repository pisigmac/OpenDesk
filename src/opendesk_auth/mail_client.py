"""Thin client for Mail service."""

from __future__ import annotations

from typing import Any

import httpx

from opendesk_auth.config import get_settings


def build_verification_email(to: str, token: str) -> dict[str, Any]:
    settings = get_settings()
    base_url = settings.spa_callback_url.rsplit("/", 1)[0]  # strip path component
    link = f"{base_url}/verify-email?token={token}"
    return {
        "to": to,
        "subject": "Verify your OpenDesk Auth account",
        "text": f"Please verify your email by visiting: {link}",
        "html": f'<p>Please <a href="{link}">verify your email</a>.</p>',
        "tags": ["auth", "verify-email"],
    }


def build_password_reset_email(to: str, token: str) -> dict[str, Any]:
    settings = get_settings()
    base_url = settings.spa_callback_url.rsplit("/", 1)[0]
    link = f"{base_url}/reset-password?token={token}"
    return {
        "to": to,
        "subject": "Reset your OpenDesk Auth password",
        "text": f"Reset your password by visiting: {link}",
        "html": f'<p><a href="{link}">Reset your password</a>.</p>',
        "tags": ["auth", "reset-password"],
    }


def send_mail(payload: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    base_url = settings.mail_base_url
    api_key = settings.mail_api_key
    if not base_url or not api_key:
        raise RuntimeError(
            "Mail service is not configured (AUTH_MAIL_BASE_URL / AUTH_MAIL_API_KEY)"
        )
    with httpx.Client(timeout=10.0) as client:
        res = client.post(
            f"{base_url}/v1/send",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
        )
        res.raise_for_status()
        return res.json()
