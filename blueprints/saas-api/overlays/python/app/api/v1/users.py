"""
Users API Routes
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query

from app.dependencies import get_db, get_current_user, get_current_org, require_role
from app.models import User, Organization, UserRole
from app.schemas.user import (
    UserResponse,
    UserUpdate,
    UserListResponse,
    UserProfileResponse,
)
from app.services.user_service import UserService


router = APIRouter()


# ============================================================================
# Current User
# ============================================================================

@router.get("/me", response_model=UserProfileResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    """Get current user's profile."""
    return current_user


@router.patch("/me", response_model=UserResponse)
async def update_current_user(
    data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Update current user's profile."""
    user_service = UserService(db)
    
    # Check username uniqueness if changing
    if data.username and data.username != current_user.username:
        existing = await user_service.get_by_username(data.username)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken",
            )
    
    updated_user = await user_service.update(current_user.id, data)
    return updated_user


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_current_user(
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Delete current user's account."""
    user_service = UserService(db)
    await user_service.delete(current_user.id)
    return None


# ============================================================================
# User Management (Admin)
# ============================================================================

@router.get("/", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    is_active: Optional[bool] = None,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """List all users (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    
    user_service = UserService(db)
    users, total = await user_service.list(
        page=page,
        page_size=page_size,
        search=search,
        is_active=is_active,
    )
    
    return UserListResponse(
        items=users,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Get a specific user."""
    user_service = UserService(db)
    user = await user_service.get(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # Non-admins can only view themselves
    if not current_user.is_superuser and user.id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    
    return user


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Update a user (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    
    user_service = UserService(db)
    user = await user_service.get(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    updated_user = await user_service.update(user_id, data)
    return updated_user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Delete a user (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account via this endpoint",
        )
    
    user_service = UserService(db)
    await user_service.delete(user_id)
    return None


# ============================================================================
# User Status
# ============================================================================

@router.post("/{user_id}/activate", response_model=UserResponse)
async def activate_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Activate a user account (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    
    user_service = UserService(db)
    user = await user_service.activate(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    return user


@router.post("/{user_id}/deactivate", response_model=UserResponse)
async def deactivate_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Deactivate a user account (admin only)."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account",
        )
    
    user_service = UserService(db)
    user = await user_service.deactivate(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    return user
