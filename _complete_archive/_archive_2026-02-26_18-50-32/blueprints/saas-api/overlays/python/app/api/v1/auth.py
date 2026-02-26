"""
Authentication API Routes
"""

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm

from app.core.security import (
    create_access_token,
    create_refresh_token,
    verify_password,
    get_password_hash,
    decode_token,
)
from app.dependencies import get_db, get_current_user
from app.models import User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    PasswordResetRequest,
    PasswordResetConfirm,
)
from app.services.auth_service import AuthService
from app.services.email_service import EmailService
from app.config import settings


router = APIRouter()


# ============================================================================
# Registration
# ============================================================================

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(
    data: RegisterRequest,
    background_tasks: BackgroundTasks,
    db = Depends(get_db),
):
    """Register a new user account."""
    auth_service = AuthService(db)
    
    # Check if user exists
    if await auth_service.get_user_by_email(data.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    if await auth_service.get_user_by_username(data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    # Create user
    user = await auth_service.create_user(
        email=data.email,
        username=data.username,
        password=data.password,
        full_name=data.full_name,
    )
    
    # Send verification email
    background_tasks.add_task(
        EmailService.send_verification_email,
        user.email,
        user.id,
    )
    
    # Generate tokens
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    
    return RegisterResponse(
        user=user,
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


# ============================================================================
# Login
# ============================================================================

@router.post("/login", response_model=LoginResponse)
async def login(
    data: LoginRequest,
    db = Depends(get_db),
):
    """Authenticate and get access tokens."""
    auth_service = AuthService(db)
    
    # Authenticate user
    user = await auth_service.authenticate(data.email, data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )
    
    # Update last login
    await auth_service.update_last_login(user.id)
    
    # Generate tokens
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.security.access_token_expire_minutes * 60,
    )


@router.post("/login/oauth2", response_model=LoginResponse)
async def oauth2_login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db = Depends(get_db),
):
    """OAuth2 compatible login endpoint."""
    auth_service = AuthService(db)
    
    user = await auth_service.authenticate(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.security.access_token_expire_minutes * 60,
    )


# ============================================================================
# Token Refresh
# ============================================================================

@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_token(
    data: RefreshTokenRequest,
    db = Depends(get_db),
):
    """Refresh access token using refresh token."""
    try:
        payload = decode_token(data.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
        
        # Verify user still exists and is active
        auth_service = AuthService(db)
        user = await auth_service.get_user_by_id(int(user_id))
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )
        
        # Generate new access token
        access_token = create_access_token(user.id)
        
        return RefreshTokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.security.access_token_expire_minutes * 60,
        )
    
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )


# ============================================================================
# Logout
# ============================================================================

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Logout and invalidate current session."""
    auth_service = AuthService(db)
    await auth_service.invalidate_session(current_user.id)
    return None


@router.post("/logout/all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Logout from all devices."""
    auth_service = AuthService(db)
    await auth_service.invalidate_all_sessions(current_user.id)
    return None


# ============================================================================
# Email Verification
# ============================================================================

@router.post("/verify-email")
async def verify_email(
    token: str,
    db = Depends(get_db),
):
    """Verify user email address."""
    auth_service = AuthService(db)
    
    try:
        user = await auth_service.verify_email_token(token)
        return {"message": "Email verified successfully"}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )


@router.post("/resend-verification")
async def resend_verification(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
):
    """Resend email verification."""
    if current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified",
        )
    
    background_tasks.add_task(
        EmailService.send_verification_email,
        current_user.email,
        current_user.id,
    )
    
    return {"message": "Verification email sent"}


# ============================================================================
# Password Reset
# ============================================================================

@router.post("/forgot-password")
async def forgot_password(
    data: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    db = Depends(get_db),
):
    """Request password reset email."""
    auth_service = AuthService(db)
    user = await auth_service.get_user_by_email(data.email)
    
    # Always return success to prevent email enumeration
    if user:
        background_tasks.add_task(
            EmailService.send_password_reset_email,
            user.email,
            user.id,
        )
    
    return {"message": "If the email exists, a reset link has been sent"}


@router.post("/reset-password")
async def reset_password(
    data: PasswordResetConfirm,
    db = Depends(get_db),
):
    """Reset password with token."""
    auth_service = AuthService(db)
    
    try:
        await auth_service.reset_password(data.token, data.new_password)
        return {"message": "Password reset successfully"}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )


# ============================================================================
# Change Password
# ============================================================================

@router.post("/change-password")
async def change_password(
    current_password: str,
    new_password: str,
    current_user: User = Depends(get_current_user),
    db = Depends(get_db),
):
    """Change password for authenticated user."""
    if not verify_password(current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    
    auth_service = AuthService(db)
    await auth_service.update_password(current_user.id, new_password)
    
    return {"message": "Password changed successfully"}
