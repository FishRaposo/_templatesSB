"""
API Router - Main router assembly
"""

from fastapi import APIRouter

from app.api.v1 import auth, users, organizations, billing, webhooks

# ============================================================================
# API v1 Router
# ============================================================================

v1_router = APIRouter(prefix="/v1")

# Auth routes
v1_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])

# User routes
v1_router.include_router(users.router, prefix="/users", tags=["Users"])

# Organization routes
v1_router.include_router(organizations.router, prefix="/organizations", tags=["Organizations"])

# Billing routes
v1_router.include_router(billing.router, prefix="/billing", tags=["Billing"])

# Webhook routes
v1_router.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])


# ============================================================================
# Main API Router
# ============================================================================

api_router = APIRouter()
api_router.include_router(v1_router)
