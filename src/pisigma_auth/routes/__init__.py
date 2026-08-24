"""Route package."""

from pisigma_auth.routes.admin import router as admin_router
from pisigma_auth.routes.auth import router as auth_router
from pisigma_auth.routes.jwks import router as jwks_router
from pisigma_auth.routes.me import router as me_router
from pisigma_auth.routes.oauth import router as oauth_router
from pisigma_auth.routes.orgs import router as orgs_router

__all__ = ["auth_router", "oauth_router", "orgs_router", "admin_router", "jwks_router", "me_router"]
