# Universal Template System - Python Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: python
# Category: testing

#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# FILE: integration-tests.tpl.py
# PURPOSE: Integration testing patterns for Python projects
# USAGE: Test interactions between multiple components and services
# DEPENDENCIES: pytest, pytest-asyncio, httpx, testcontainers
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
Python Integration Tests Template
Purpose: Integration testing patterns for Python projects
Usage: Test interactions between multiple components and services
"""

import pytest
import asyncio
import httpx
from unittest.mock import patch, AsyncMock
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Import your application modules here
# from your_app.main import app
# from your_app.database import get_db, Base
# from your_app.services.auth_service import AuthService
# from your_app.services.user_service import UserService
# from your_app.repositories.user_repository import UserRepository

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="function")
async def postgres_container():
    """Start PostgreSQL container for integration tests."""
    with PostgresContainer("postgres:13") as postgres:
        yield postgres

@pytest.fixture(scope="function")
async def redis_container():
    """Start Redis container for integration tests."""
    with RedisContainer("redis:6") as redis:
        yield redis

@pytest.fixture(scope="function")
async def test_db(postgres_container):
    """Create test database session."""
    engine = create_engine(postgres_container.get_connection_url())
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture(scope="function")
async def test_client(test_db):
    """Create test client with database dependency override."""
    def override_get_db():
        try:
            yield test_db
        finally:
            test_db.close()
    
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()

class TestUserAuthenticationIntegration:
    """Integration tests for user authentication workflow."""
    
    async def test_complete_user_registration_flow(self, test_client: TestClient):
        """Test complete user registration from API to database."""
        # Arrange
        user_data = {
            "email": "test@example.com",
            "password": "password123",
            "name": "Test User"
        }
        
        # Act - Register user
        response = test_client.post("/api/auth/register", json=user_data)
        
        # Assert - Registration successful
        assert response.status_code == 201
        assert response.json()["email"] == user_data["email"]
        assert "id" in response.json()
        
        # Act - Login with registered user
        login_data = {
            "email": user_data["email"],
            "password": user_data["password"]
        }
        login_response = test_client.post("/api/auth/login", json=login_data)
        
        # Assert - Login successful
        assert login_response.status_code == 200
        assert "access_token" in login_response.json()
        assert login_response.json()["token_type"] == "bearer"
        
        # Act - Access protected endpoint
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        profile_response = test_client.get("/api/users/profile", headers=headers)
        
        # Assert - Protected endpoint accessible
        assert profile_response.status_code == 200
        assert profile_response.json()["email"] == user_data["email"]

    async def test_user_session_management(self, test_client: TestClient):
        """Test user session creation and management."""
        # Arrange
        user_data = {
            "email": "session@example.com",
            "password": "password123",
            "name": "Session User"
        }
        
        # Register user
        test_client.post("/api/auth/register", json=user_data)
        
        # Act - Login and create session
        login_response = test_client.post("/api/auth/login", json={
            "email": user_data["email"],
            "password": user_data["password"]
        })
        
        # Assert - Session created
        assert login_response.status_code == 200
        token = login_response.json()["access_token"]
        
        # Act - Verify session in database
        headers = {"Authorization": f"Bearer {token}"}
        session_response = test_client.get("/api/auth/sessions", headers=headers)
        
        # Assert - Session exists
        assert session_response.status_code == 200
        sessions = session_response.json()
        assert len(sessions) > 0
        assert sessions[0]["user_id"] is not None

    async def test_password_reset_flow(self, test_client: TestClient):
        """Test complete password reset workflow."""
        # Arrange
        user_data = {
            "email": "reset@example.com",
            "password": "oldpassword",
            "name": "Reset User"
        }
        
        # Register user
        test_client.post("/api/auth/register", json=user_data)
        
        # Act - Request password reset
        reset_request = test_client.post("/api/auth/reset-password", json={
            "email": user_data["email"]
        })
        
        # Assert - Reset token generated
        assert reset_request.status_code == 200
        reset_token = reset_request.json()["reset_token"]
        
        # Act - Reset password
        reset_confirm = test_client.post("/api/auth/reset-password/confirm", json={
            "token": reset_token,
            "new_password": "newpassword123"
        })
        
        # Assert - Password reset successful
        assert reset_confirm.status_code == 200
        
        # Act - Login with new password
        login_response = test_client.post("/api/auth/login", json={
            "email": user_data["email"],
            "password": "newpassword123"
        })
        
        # Assert - Login successful with new password
        assert login_response.status_code == 200

class TestDatabaseIntegration:
    """Integration tests for database operations."""
    
    async def test_user_crud_operations(self, test_db):
        """Test CRUD operations with real database."""
        # Arrange
        user_repo = UserRepository(test_db)
        user_data = {
            "email": "crud@example.com",
            "password": "password123",
            "name": "CRUD User"
        }
        
        # Act - Create user
        created_user = await user_repo.create(user_data)
        
        # Assert - User created
        assert created_user.id is not None
        assert created_user.email == user_data["email"]
        
        # Act - Read user
        retrieved_user = await user_repo.get_by_id(created_user.id)
        
        # Assert - User retrieved
        assert retrieved_user is not None
        assert retrieved_user.email == user_data["email"]
        
        # Act - Update user
        update_data = {"name": "Updated User"}
        updated_user = await user_repo.update(created_user.id, update_data)
        
        # Assert - User updated
        assert updated_user.name == update_data["name"]
        
        # Act - Delete user
        deleted = await user_repo.delete(created_user.id)
        
        # Assert - User deleted
        assert deleted is True
        
        # Verify deletion
        deleted_user = await user_repo.get_by_id(created_user.id)
        assert deleted_user is None

    async def test_database_transactions(self, test_db):
        """Test database transaction handling."""
        # Arrange
        user_repo = UserRepository(test_db)
        
        # Act - Test successful transaction
        async with test_db.begin():
            user1 = await user_repo.create({
                "email": "trans1@example.com",
                "password": "password123",
                "name": "Transaction User 1"
            })
            user2 = await user_repo.create({
                "email": "trans2@example.com",
                "password": "password123",
                "name": "Transaction User 2"
            })
        
        # Assert - Both users created
        assert user1.id is not None
        assert user2.id is not None
        
        # Act - Test failed transaction
        try:
            async with test_db.begin():
                user3 = await user_repo.create({
                    "email": "trans3@example.com",
                    "password": "password123",
                    "name": "Transaction User 3"
                })
                # Force an error
                raise ValueError("Transaction failed")
        except ValueError:
            pass
        
        # Assert - User3 not created due to transaction rollback
        user3_retrieved = await user_repo.get_by_email("trans3@example.com")
        assert user3_retrieved is None

class TestAPIIntegration:
    """Integration tests for API endpoints."""
    
    async def test_cors_headers(self, test_client: TestClient):
        """Test CORS headers are properly set."""
        # Act
        response = test_client.options("/api/users/profile")
        
        # Assert
        assert "access-control-allow-origin" in response.headers
        assert "access-control-allow-methods" in response.headers

    async def test_rate_limiting(self, test_client: TestClient):
        """Test API rate limiting functionality."""
        # Act - Make multiple requests quickly
        responses = []
        for _ in range(10):
            response = test_client.post("/api/auth/login", json={
                "email": "test@example.com",
                "password": "wrongpassword"
            })
            responses.append(response)
        
        # Assert - Should be rate limited after certain attempts
        rate_limited_responses = [r for r in responses if r.status_code == 429]
        assert len(rate_limited_responses) > 0

    async def test_api_versioning(self, test_client: TestClient):
        """Test API versioning works correctly."""
        # Act - Test different API versions
        v1_response = test_client.get("/api/v1/users/profile")
        v2_response = test_client.get("/api/v2/users/profile")
        
        # Assert - Different versions should respond appropriately
        assert v1_response.status_code in [200, 401]  # May require auth
        assert v2_response.status_code in [200, 401]  # May require auth

class TestExternalServiceIntegration:
    """Integration tests for external service integrations."""
    
    @patch('httpx.AsyncClient.get')
    async def test_third_party_api_integration(self, mock_get):
        """Test integration with third-party APIs."""
        # Arrange
        mock_response = httpx.Response(
            status_code=200,
            json={"data": "external_data", "status": "success"}
        )
        mock_get.return_value = mock_response
        
        # Act
        external_service = ExternalService()
        result = await external_service.fetch_data()
        
        # Assert
        assert result["status"] == "success"
        assert result["data"] == "external_data"
        mock_get.assert_called_once()

    async def test_email_service_integration(self):
        """Test email service integration."""
        # Arrange
        email_service = EmailService()
        
        # Act - Send test email
        result = await email_service.send_email(
            to="test@example.com",
            subject="Test Email",
            body="This is a test email"
        )
        
        # Assert
        assert result["status"] == "sent"
        assert "message_id" in result

class TestCacheIntegration:
    """Integration tests for caching functionality."""
    
    async def test_redis_caching(self, redis_container):
        """Test Redis caching integration."""
        # Arrange
        cache_service = RedisCacheService(redis_container.get_connection_url())
        
        # Act - Cache data
        await cache_service.set("test_key", {"data": "test_value"}, ttl=60)
        
        # Retrieve cached data
        cached_data = await cache_service.get("test_key")
        
        # Assert
        assert cached_data is not None
        assert cached_data["data"] == "test_value"
        
        # Act - Delete cached data
        await cache_service.delete("test_key")
        deleted_data = await cache_service.get("test_key")
        
        # Assert
        assert deleted_data is None

    async def test_cache_invalidation(self, redis_container):
        """Test cache invalidation strategies."""
        # Arrange
        cache_service = RedisCacheService(redis_container.get_connection_url())
        
        # Cache multiple related keys
        await cache_service.set("user:1:profile", {"name": "User 1"})
        await cache_service.set("user:1:settings", {"theme": "dark"})
        await cache_service.set("user:1:posts", [{"id": 1, "title": "Post 1"}])
        
        # Act - Invalidate all user-related cache
        await cache_service.invalidate_pattern("user:1:*")
        
        # Assert - All user-related cache cleared
        profile = await cache_service.get("user:1:profile")
        settings = await cache_service.get("user:1:settings")
        posts = await cache_service.get("user:1:posts")
        
        assert profile is None
        assert settings is None
        assert posts is None

class TestBackgroundTaskIntegration:
    """Integration tests for background task processing."""
    
    async def test_async_task_processing(self):
        """Test async background task processing."""
        # Arrange
        task_queue = TaskQueue()
        
        # Act - Enqueue tasks
        task1_id = await task_queue.enqueue("process_data", {"data": "test1"})
        task2_id = await task_queue.enqueue("process_data", {"data": "test2"})
        
        # Process tasks
        results = await task_queue.process_batch(max_tasks=2)
        
        # Assert
        assert len(results) == 2
        assert all(result["status"] == "completed" for result in results)

    async def test_task_failure_handling(self):
        """Test background task failure handling."""
        # Arrange
        task_queue = TaskQueue()
        
        # Act - Enqueue failing task
        task_id = await task_queue.enqueue("failing_task", {"should_fail": True})
        
        # Process task
        result = await task_queue.process_task(task_id)
        
        # Assert
        assert result["status"] == "failed"
        assert "error" in result

class TestFileStorageIntegration:
    """Integration tests for file storage operations."""
    
    async def test_file_upload_workflow(self):
        """Test complete file upload workflow."""
        # Arrange
        storage_service = S3StorageService()
        file_content = b"test file content"
        
        # Act - Upload file
        upload_result = await storage_service.upload(
            file_content=file_content,
            filename="test.txt",
            content_type="text/plain"
        )
        
        # Assert
        assert "url" in upload_result
        assert upload_result["size"] == len(file_content)
        
        # Act - Download file
        downloaded_content = await storage_service.download(upload_result["key"])
        
        # Assert
        assert downloaded_content == file_content
        
        # Act - Delete file
        delete_result = await storage_service.delete(upload_result["key"])
        
        # Assert
        assert delete_result is True

# Example service classes for testing
class ExternalService:
    async def fetch_data(self):
        async with httpx.AsyncClient() as client:
            response = await client.get("https://api.example.com/data")
            return response.json()

class EmailService:
    async def send_email(self, to: str, subject: str, body: str):
        # Mock email service implementation
        return {
            "status": "sent",
            "message_id": "msg_12345",
            "to": to,
            "subject": subject
        }

class RedisCacheService:
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
    
    async def set(self, key: str, value: dict, ttl: int = 3600):
        # Mock Redis implementation
        pass
    
    async def get(self, key: str):
        # Mock Redis implementation
        return None
    
    async def delete(self, key: str):
        # Mock Redis implementation
        pass
    
    async def invalidate_pattern(self, pattern: str):
        # Mock Redis implementation
        pass

class TaskQueue:
    async def enqueue(self, task_name: str, task_data: dict):
        # Mock task queue implementation
        return f"task_{task_name}_{hash(str(task_data))}"
    
    async def process_batch(self, max_tasks: int = 10):
        # Mock batch processing
        return [{"status": "completed", "task_id": f"task_{i}"} for i in range(max_tasks)]
    
    async def process_task(self, task_id: str):
        # Mock single task processing
        return {"status": "completed", "task_id": task_id}

class S3StorageService:
    async def upload(self, file_content: bytes, filename: str, content_type: str):
        # Mock S3 upload
        return {
            "key": f"uploads/{filename}",
            "url": f"https://bucket.s3.amazonaws.com/uploads/{filename}",
            "size": len(file_content)
        }
    
    async def download(self, key: str):
        # Mock S3 download
        return b"downloaded content"
    
    async def delete(self, key: str):
        # Mock S3 delete
        return True

if __name__ == "__main__":
    pytest.main([
        __file__, 
        "-v", 
        "--cov=your_app", 
        "--cov-report=html",
        "--cov-report=term-missing"
    ])
