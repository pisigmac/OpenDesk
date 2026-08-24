"""Pydantic request/response schemas."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    display_name: str | None = None
    # Required to create the first platform admin when open_registration is False.
    bootstrap_token: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RegisterResponse(BaseModel):
    """Registration response.

    When email verification is required, no tokens are returned and
    verification_required is True. Otherwise the caller receives a full token set.
    """

    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str | None = None
    expires_in: int | None = None
    verification_required: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class GrantOut(BaseModel):
    audience: str
    role: str


class OrgOut(BaseModel):
    id: str
    name: str
    role: str
    workspace_id: str | None = None


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str | None
    is_platform_admin: bool
    is_active: bool = True
    orgs: list[OrgOut] = Field(default_factory=list)
    grants: list[GrantOut] = Field(default_factory=list)


class CreateOrgRequest(BaseModel):
    name: str = Field(min_length=1)


class AddMemberRequest(BaseModel):
    user_id: str
    role: str = "member"
    workspace_id: str | None = None


class GrantRequest(BaseModel):
    user_id: str
    audience: str
    role: str


class IntrospectRequest(BaseModel):
    token: str


class IntrospectResponse(BaseModel):
    active: bool
    claims: dict | None = None


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=1)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=1)
    password: str = Field(min_length=8)


class UserExportResponse(BaseModel):
    user: UserOut
    identities: list[dict]
    memberships: list[dict]
    grants: list[dict]
    refresh_tokens: list[dict]
    audit_events: list[dict]


class AuditLogQueryParams(BaseModel):
    action: str | None = None
    actor_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


# Profile and password management
class UpdateProfileRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=255)
    email: EmailStr | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


# Structured error envelope
class ErrorDetail(BaseModel):
    error: str
    code: str
    request_id: str | None = None


# Admin user management
class SetUserActiveRequest(BaseModel):
    is_active: bool


# Session listing
class SessionOut(BaseModel):
    id: str
    created_at: str
    expires_at: str
    revoked: bool
    ip_address: str | None = None
    user_agent: str | None = None
