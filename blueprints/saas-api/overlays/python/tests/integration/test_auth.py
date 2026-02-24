"""
Authentication API Tests
"""

import pytest
from httpx import AsyncClient

from app.models import User


class TestRegister:
    """Test user registration."""
    
    async def test_register_success(self, client: AsyncClient):
        """Test successful registration."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "username": "newuser",
                "password": "SecurePass123!",
                "full_name": "New User",
            },
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["user"]["email"] == "newuser@example.com"
        assert data["user"]["username"] == "newuser"
        assert "access_token" in data
        assert "refresh_token" in data
        assert "password" not in data["user"]
    
    async def test_register_duplicate_email(
        self,
        client: AsyncClient,
        test_user: User,
    ):
        """Test registration with existing email."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": test_user.email,
                "username": "differentuser",
                "password": "SecurePass123!",
            },
        )
        
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"].lower()
    
    async def test_register_duplicate_username(
        self,
        client: AsyncClient,
        test_user: User,
    ):
        """Test registration with existing username."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "different@example.com",
                "username": test_user.username,
                "password": "SecurePass123!",
            },
        )
        
        assert response.status_code == 400
        assert "username" in response.json()["detail"].lower()
    
    async def test_register_weak_password(self, client: AsyncClient):
        """Test registration with weak password."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "username": "newuser",
                "password": "weak",
            },
        )
        
        assert response.status_code == 422
    
    async def test_register_invalid_email(self, client: AsyncClient):
        """Test registration with invalid email."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "not-an-email",
                "username": "newuser",
                "password": "SecurePass123!",
            },
        )
        
        assert response.status_code == 422


class TestLogin:
    """Test user login."""
    
    async def test_login_success(
        self,
        client: AsyncClient,
        test_user: User,
        test_password: str,
    ):
        """Test successful login."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": test_password,
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
    
    async def test_login_wrong_password(
        self,
        client: AsyncClient,
        test_user: User,
    ):
        """Test login with wrong password."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "wrongpassword",
            },
        )
        
        assert response.status_code == 401
        assert "incorrect" in response.json()["detail"].lower()
    
    async def test_login_nonexistent_user(self, client: AsyncClient):
        """Test login with non-existent email."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "nonexistent@example.com",
                "password": "anypassword",
            },
        )
        
        assert response.status_code == 401
    
    async def test_login_inactive_user(
        self,
        client: AsyncClient,
        inactive_user: User,
        test_password: str,
    ):
        """Test login with inactive account."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": inactive_user.email,
                "password": test_password,
            },
        )
        
        assert response.status_code == 403
        assert "disabled" in response.json()["detail"].lower()


class TestTokenRefresh:
    """Test token refresh."""
    
    async def test_refresh_token_success(
        self,
        client: AsyncClient,
        test_user: User,
        test_password: str,
    ):
        """Test successful token refresh."""
        # First login to get refresh token
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": test_password,
            },
        )
        refresh_token = login_response.json()["refresh_token"]
        
        # Use refresh token
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    async def test_refresh_with_invalid_token(self, client: AsyncClient):
        """Test refresh with invalid token."""
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid-token"},
        )
        
        assert response.status_code == 401


class TestLogout:
    """Test logout."""
    
    async def test_logout_success(
        self,
        client: AsyncClient,
        auth_headers: dict,
    ):
        """Test successful logout."""
        response = await client.post(
            "/api/v1/auth/logout",
            headers=auth_headers,
        )
        
        assert response.status_code == 204
    
    async def test_logout_without_auth(self, client: AsyncClient):
        """Test logout without authentication."""
        response = await client.post("/api/v1/auth/logout")
        
        assert response.status_code == 401


class TestPasswordReset:
    """Test password reset flow."""
    
    async def test_forgot_password(
        self,
        client: AsyncClient,
        test_user: User,
        mock_email_service,
    ):
        """Test forgot password request."""
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": test_user.email},
        )
        
        assert response.status_code == 200
        # Should not reveal if email exists
        assert "if the email exists" in response.json()["message"].lower()
    
    async def test_forgot_password_nonexistent(
        self,
        client: AsyncClient,
        mock_email_service,
    ):
        """Test forgot password with non-existent email."""
        response = await client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nonexistent@example.com"},
        )
        
        # Should return same response to prevent email enumeration
        assert response.status_code == 200


class TestChangePassword:
    """Test password change."""
    
    async def test_change_password_success(
        self,
        client: AsyncClient,
        auth_headers: dict,
        test_password: str,
    ):
        """Test successful password change."""
        response = await client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers,
            params={
                "current_password": test_password,
                "new_password": "NewSecurePass123!",
            },
        )
        
        assert response.status_code == 200
    
    async def test_change_password_wrong_current(
        self,
        client: AsyncClient,
        auth_headers: dict,
    ):
        """Test password change with wrong current password."""
        response = await client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers,
            params={
                "current_password": "wrongpassword",
                "new_password": "NewSecurePass123!",
            },
        )
        
        assert response.status_code == 400
