"""Authenticated user self-service endpoints: export, delete, profile, sessions."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from opendesk_auth.db import get_db
from opendesk_auth.middleware import get_request_context
from opendesk_auth.models import User
from opendesk_auth.routes.auth import current_user
from opendesk_auth.services import delete_user_data, emit_audit, export_user_data

router = APIRouter(prefix="/me", tags=["me"])


@router.get("/export")
def export_my_data(user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    return export_user_data(db, user)


@router.post("/delete")
def delete_my_account(user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    ctx = get_request_context()
    user_id = user.id
    emit_audit(
        db,
        action="user.delete",
        actor_type="user",
        actor_id=user_id,
        resource_type="user",
        resource_id=user_id,
        ip_address=ctx.get("ip"),
        user_agent=ctx.get("user_agent"),
    )
    delete_user_data(db, user)
    return {"ok": True}
