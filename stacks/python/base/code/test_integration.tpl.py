"""
File: test_integration.tpl.py
Purpose: Integration test patterns and examples
Generated for: {{PROJECT_NAME}}
"""

import pytest
from httpx import AsyncClient


# ============================================================================
# API Integration Tests
# ============================================================================

class TestAuthenticationFlow:
    """Integration tests for authentication flow."""
    
    @pytest.mark.asyncio
    async def test_register_login_flow(self, client: AsyncClient):
        """Test complete registration and login flow."""
        # Register
        register_data = {
            "email": "newuser@test.com",
            "username": "newuser",
            "password": "SecurePassword123!",
            "full_name": "New User",
        }
        response = await client.post("/api/v1/auth/register", json=register_data)
        assert response.status_code == 201
        data = response.json()
        assert "access_token" in data
        user_id = data["user"]["id"]
        
        # Login with credentials
        login_data = {
            "email": register_data["email"],
            "password": register_data["password"],
        }
        response = await client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        token = data["access_token"]
        
        # Access protected resource
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.get("/api/v1/users/me", headers=headers)
        assert response.status_code == 200
        assert response.json()["id"] == user_id
    
    @pytest.mark.asyncio
    async def test_password_reset_flow(self, client: AsyncClient, test_user, mock_email_service):
        """Test password reset flow."""
        # Request password reset
        response = await client.post(
            "/api/v1/auth/password-reset/request",
            json={"email": test_user.email}
        )
        assert response.status_code == 200
        
        # Verify email was sent (check mock)
        mock_email_service.send_template.assert_called_once()
        
        # Get reset token from mock call
        call_args = mock_email_service.send_template.call_args
        reset_token = call_args.kwargs.get("data", {}).get("reset_token")
        
        # Reset password
        new_password = "NewSecurePassword456!"
        response = await client.post(
            "/api/v1/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": new_password}
        )
        assert response.status_code == 200
        
        # Login with new password
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": test_user.email, "password": new_password}
        )
        assert response.status_code == 200


class TestCRUDOperations:
    """Integration tests for CRUD operations."""
    
    @pytest.mark.asyncio
    async def test_create_read_update_delete_post(
        self, authenticated_client: AsyncClient, test_user
    ):
        """Test complete CRUD flow for posts."""
        # Create
        post_data = {
            "title": "Test Post",
            "content": "This is the content of the test post.",
            "status": "draft",
        }
        response = await authenticated_client.post("/api/v1/posts", json=post_data)
        assert response.status_code == 201
        post = response.json()
        post_id = post["id"]
        assert post["title"] == post_data["title"]
        assert post["author_id"] == test_user.id
        
        # Read
        response = await authenticated_client.get(f"/api/v1/posts/{post_id}")
        assert response.status_code == 200
        assert response.json()["id"] == post_id
        
        # Update
        update_data = {"title": "Updated Title", "status": "published"}
        response = await authenticated_client.patch(
            f"/api/v1/posts/{post_id}", json=update_data
        )
        assert response.status_code == 200
        assert response.json()["title"] == "Updated Title"
        assert response.json()["status"] == "published"
        
        # List
        response = await authenticated_client.get("/api/v1/posts")
        assert response.status_code == 200
        posts = response.json()["data"]
        assert any(p["id"] == post_id for p in posts)
        
        # Delete
        response = await authenticated_client.delete(f"/api/v1/posts/{post_id}")
        assert response.status_code == 204
        
        # Verify deleted
        response = await authenticated_client.get(f"/api/v1/posts/{post_id}")
        assert response.status_code == 404
    
    @pytest.mark.asyncio
    async def test_pagination(self, authenticated_client: AsyncClient, post_factory, test_user):
        """Test pagination of list endpoints."""
        # Create multiple posts
        for _ in range(25):
            await post_factory.create(author=test_user)
        
        # First page
        response = await authenticated_client.get("/api/v1/posts?page=1&per_page=10")
        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]) == 10
        assert data["pagination"]["page"] == 1
        assert data["pagination"]["total"] >= 25
        
        # Second page
        response = await authenticated_client.get("/api/v1/posts?page=2&per_page=10")
        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]) == 10
        assert data["pagination"]["page"] == 2


class TestConcurrency:
    """Integration tests for concurrent operations."""
    
    @pytest.mark.asyncio
    async def test_concurrent_updates(self, authenticated_client: AsyncClient, post_factory, test_user):
        """Test handling of concurrent updates."""
        import asyncio
        
        post = await post_factory.create(author=test_user, view_count=0)
        
        # Simulate concurrent view increments
        async def increment_view():
            await authenticated_client.post(f"/api/v1/posts/{post.id}/view")
        
        tasks = [increment_view() for _ in range(10)]
        await asyncio.gather(*tasks)
        
        # Verify final count
        response = await authenticated_client.get(f"/api/v1/posts/{post.id}")
        assert response.json()["view_count"] == 10
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, client: AsyncClient):
        """Test rate limiting."""
        import asyncio
        
        async def make_request():
            return await client.get("/api/v1/health")
        
        # Make many requests quickly
        tasks = [make_request() for _ in range(100)]
        responses = await asyncio.gather(*tasks)
        
        # Some should be rate limited
        status_codes = [r.status_code for r in responses]
        assert 429 in status_codes, "Rate limiting should be triggered"


class TestWebhooks:
    """Integration tests for webhook handling."""
    
    @pytest.mark.asyncio
    async def test_stripe_webhook(self, client: AsyncClient, mock_payment_service):
        """Test Stripe webhook handling."""
        # Simulate Stripe webhook payload
        payload = {
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_123",
                    "customer": "cus_456",
                    "status": "active",
                }
            }
        }
        
        # Send webhook with signature
        signature = "test_signature"  # In real test, compute proper signature
        headers = {"Stripe-Signature": signature}
        
        response = await client.post(
            "/api/v1/webhooks/stripe",
            json=payload,
            headers=headers
        )
        assert response.status_code == 200


class TestFileUpload:
    """Integration tests for file uploads."""
    
    @pytest.mark.asyncio
    async def test_upload_and_download(self, authenticated_client: AsyncClient):
        """Test file upload and download."""
        # Upload
        files = {"file": ("test.txt", b"Hello, World!", "text/plain")}
        response = await authenticated_client.post("/api/v1/files/upload", files=files)
        assert response.status_code == 201
        file_id = response.json()["id"]
        
        # Download
        response = await authenticated_client.get(f"/api/v1/files/{file_id}/download")
        assert response.status_code == 200
        assert response.content == b"Hello, World!"
    
    @pytest.mark.asyncio
    async def test_upload_size_limit(self, authenticated_client: AsyncClient):
        """Test file size limit enforcement."""
        # Create large file (assuming 10MB limit)
        large_content = b"x" * (11 * 1024 * 1024)  # 11 MB
        files = {"file": ("large.bin", large_content, "application/octet-stream")}
        
        response = await authenticated_client.post("/api/v1/files/upload", files=files)
        assert response.status_code == 413  # Payload Too Large


# ============================================================================
# Database Integration Tests
# ============================================================================

class TestDatabaseIntegrity:
    """Tests for database integrity and constraints."""
    
    @pytest.mark.asyncio
    async def test_unique_email_constraint(self, db_session, user_factory):
        """Test unique email constraint."""
        user1 = await user_factory.create(email="duplicate@test.com")
        
        with pytest.raises(Exception) as exc_info:
            await user_factory.create(email="duplicate@test.com")
        
        assert "unique" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_cascade_delete(self, db_session, user_factory, post_factory):
        """Test cascade delete behavior."""
        from sqlalchemy import select
        
        user = await user_factory.create()
        post1 = await post_factory.create(author=user)
        post2 = await post_factory.create(author=user)
        
        # Delete user
        await db_session.delete(user)
        await db_session.flush()
        
        # Posts should be deleted
        from models import Post
        result = await db_session.execute(
            select(Post).filter_by(author_id=user.id)
        )
        posts = result.scalars().all()
        assert len(posts) == 0
    
    @pytest.mark.asyncio
    async def test_soft_delete(self, db_session, post_factory, test_user):
        """Test soft delete functionality."""
        from sqlalchemy import select
        
        post = await post_factory.create(author=test_user)
        post_id = post.id
        
        # Soft delete
        post.soft_delete()
        await db_session.flush()
        
        # Should not appear in normal queries
        from models import Post
        result = await db_session.execute(
            select(Post).filter_by(id=post_id, is_deleted=False)
        )
        assert result.scalar_one_or_none() is None
        
        # Should appear when including deleted
        result = await db_session.execute(
            select(Post).filter_by(id=post_id)
        )
        deleted_post = result.scalar_one()
        assert deleted_post.is_deleted is True
