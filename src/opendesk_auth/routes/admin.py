"""Admin user and product-grant management."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from opendesk_auth.db import get_db
from opendesk_auth.middleware import get_request_context
from opendesk_auth.models import AuditLogEvent, ProductGrant, User
from opendesk_auth.routes.auth import current_user
from opendesk_auth.schemas import GrantRequest, SetUserActiveRequest, UserOut
from opendesk_auth.services import emit_audit, set_user_active, user_to_out

logger = logging.getLogger("opendesk_auth.admin")
router = APIRouter(prefix="/admin", tags=["admin"])


def require_platform_admin(user: User = Depends(current_user)) -> User:
    if not user.is_platform_admin:
        raise HTTPException(status_code=403, detail="Platform admin required")
    return user


@router.get("/users")
def list_users(
    q: str | None = Query(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(require_platform_admin),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(User)
    if q:
        term = f"%{q.strip()}%"
        query = query.filter(or_(User.email.ilike(term), User.display_name.ilike(term)))
    total = query.count()
    users = query.order_by(User.created_at).offset(offset).limit(limit).all()
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "users": [user_to_out(u) for u in users],
    }


@router.patch("/users/{user_id}/active")
def set_user_active_status(
    user_id: str,
    body: SetUserActiveRequest,
    admin: User = Depends(require_platform_admin),
    db: Session = Depends(get_db),
) -> dict:
    target = db.query(User).filter(User.id == user_id).one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    set_user_active(db, target, is_active=body.is_active)
    action = "admin.activate_user" if body.is_active else "admin.suspend_user"
    ctx = get_request_context()
    emit_audit(
        db,
        action=action,
        actor_type="admin",
        actor_id=admin.id,
        resource_type="user",
        resource_id=user_id,
        ip_address=ctx.get("ip"),
        user_agent=ctx.get("user_agent"),
    )
    logger.info("%s admin=%s target=%s", action, admin.id, user_id)
    return {"ok": True, "user_id": user_id, "is_active": body.is_active}


@router.post("/grants")
def set_grant(
    body: GrantRequest,
    admin: User = Depends(require_platform_admin),
    db: Session = Depends(get_db),
) -> dict:
    user = db.query(User).filter(User.id == body.user_id).one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if body.role not in {"admin", "operator", "viewer"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    grant = (
        db.query(ProductGrant)
        .filter(ProductGrant.user_id == body.user_id, ProductGrant.audience == body.audience)
        .one_or_none()
    )
    if grant:
        grant.role = body.role
    else:
        db.add(ProductGrant(user_id=body.user_id, audience=body.audience, role=body.role))
    db.commit()
    ctx = get_request_context()
    emit_audit(
        db,
        action="admin.set_grant",
        actor_type="admin",
        actor_id=admin.id,
        resource_type="product_grant",
        resource_id=body.user_id,
        ip_address=ctx.get("ip"),
        user_agent=ctx.get("user_agent"),
        details={"audience": body.audience, "role": body.role},
    )
    logger.info("admin.set_grant admin=%s user=%s audience=%s role=%s", admin.id, body.user_id, body.audience, body.role)
    return {"ok": True, "user_id": body.user_id, "audience": body.audience, "role": body.role}


@router.get("/audit")
def query_audit_log(
    action: str | None = None,
    actor_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    limit: int = 25,
    offset: int = 0,
    _: User = Depends(require_platform_admin),
    db: Session = Depends(get_db),
) -> dict:
    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    query = db.query(AuditLogEvent)
    if action:
        query = query.filter(AuditLogEvent.action == action)
    if actor_id:
        query = query.filter(AuditLogEvent.actor_id == actor_id)
    if resource_type:
        query = query.filter(AuditLogEvent.resource_type == resource_type)
    if resource_id:
        query = query.filter(AuditLogEvent.resource_id == resource_id)

    total = query.count()
    events = (
        query.order_by(AuditLogEvent.occurred_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "events": [
            {
                "id": e.id,
                "occurred_at": e.occurred_at.isoformat(),
                "actor_type": e.actor_type,
                "actor_id": e.actor_id,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "ip_address": e.ip_address,
                "user_agent": e.user_agent,
                "integrity_hash": e.integrity_hash,
                "details": e.details,
            }
            for e in events
        ],
    }
