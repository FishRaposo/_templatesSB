"""
File: test_fixtures.tpl.py
Purpose: Comprehensive pytest fixtures for testing
Generated for: {{PROJECT_NAME}}
"""

import asyncio
import os
from datetime import datetime, timedelta
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from faker import Faker
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

# Initialize Faker
fake = Faker()


# ============================================================================
# Database Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def test_engine():
    """Create a test database engine."""
    DATABASE_URL = os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql+asyncpg://test:test@localhost:5432/test_db"
    )
    engine = create_async_engine(
        DATABASE_URL,
        echo=False,
        pool_pre_ping=True,
    )
    yield engine
    await engine.dispose()


@pytest.fixture(scope="session")
async def setup_database(test_engine):
    """Create all tables before tests."""
    from models import Base  # Import your models
    
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield
    
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session(test_engine, setup_database) -> AsyncGenerator[AsyncSession, None]:
    """Create a new database session for each test."""
    async_session = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    
    async with async_session() as session:
        async with session.begin():
            yield session
            await session.rollback()


# ============================================================================
# Redis Fixtures
# ============================================================================

@pytest.fixture
async def redis_client():
    """Create a Redis client for testing."""
    import redis.asyncio as redis
    
    client = redis.from_url(
        os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/1")
    )
    yield client
    await client.flushdb()
    await client.close()


@pytest.fixture
def mock_redis():
    """Mock Redis client for unit tests."""
    mock = AsyncMock()
    mock.get = AsyncMock(return_value=None)
    mock.set = AsyncMock(return_value=True)
    mock.delete = AsyncMock(return_value=1)
    mock.expire = AsyncMock(return_value=True)
    mock.incr = AsyncMock(return_value=1)
    mock.hget = AsyncMock(return_value=None)
    mock.hset = AsyncMock(return_value=1)
    mock.hgetall = AsyncMock(return_value={})
    return mock


# ============================================================================
# HTTP Client Fixtures
# ============================================================================

@pytest.fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """Create an async HTTP client for API testing."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def authenticated_client(client, test_user, auth_token) -> AsyncClient:
    """Client with authentication headers."""
    client.headers["Authorization"] = f"Bearer {auth_token}"
    return client


@pytest.fixture
def mock_http_client():
    """Mock HTTP client for external API calls."""
    mock = AsyncMock()
    mock.get = AsyncMock()
    mock.post = AsyncMock()
    mock.put = AsyncMock()
    mock.delete = AsyncMock()
    return mock


# ============================================================================
# User Fixtures
# ============================================================================

@pytest.fixture
def user_data() -> dict:
    """Generate random user data."""
    return {
        "email": fake.email(),
        "username": fake.user_name(),
        "password": fake.password(length=12),
        "full_name": fake.name(),
    }


@pytest.fixture
async def test_user(db_session, user_data) -> "User":
    """Create a test user in database."""
    from models import User
    from services import hash_password
    
    user = User(
        email=user_data["email"],
        username=user_data["username"],
        password_hash=hash_password(user_data["password"]),
        full_name=user_data["full_name"],
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def admin_user(db_session) -> "User":
    """Create an admin user."""
    from models import User
    from services import hash_password
    
    user = User(
        email="admin@test.com",
        username="admin",
        password_hash=hash_password("adminpassword"),
        full_name="Admin User",
        is_active=True,
        is_verified=True,
        is_superuser=True,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)
    return user


@pytest.fixture
def auth_token(test_user) -> str:
    """Generate an authentication token."""
    from services import create_access_token
    return create_access_token({"sub": str(test_user.id)})


# ============================================================================
# Mock Service Fixtures
# ============================================================================

@pytest.fixture
def mock_email_service():
    """Mock email service."""
    mock = AsyncMock()
    mock.send_email = AsyncMock(return_value={"status": "sent"})
    mock.send_template = AsyncMock(return_value={"status": "sent"})
    return mock


@pytest.fixture
def mock_payment_service():
    """Mock payment/Stripe service."""
    mock = AsyncMock()
    mock.create_customer = AsyncMock(return_value={"id": "cus_test123"})
    mock.create_subscription = AsyncMock(return_value={"id": "sub_test123"})
    mock.create_payment_intent = AsyncMock(return_value={"client_secret": "secret_test"})
    mock.cancel_subscription = AsyncMock(return_value={"status": "canceled"})
    return mock


@pytest.fixture
def mock_storage_service():
    """Mock file storage service."""
    mock = AsyncMock()
    mock.upload = AsyncMock(return_value={"url": "https://storage.test/file.pdf"})
    mock.download = AsyncMock(return_value=b"file content")
    mock.delete = AsyncMock(return_value=True)
    mock.get_signed_url = AsyncMock(return_value="https://storage.test/signed/file.pdf")
    return mock


@pytest.fixture
def mock_queue():
    """Mock job queue."""
    mock = MagicMock()
    mock.enqueue = MagicMock(return_value="job-123")
    mock.get_job = MagicMock(return_value={"status": "completed"})
    return mock


# ============================================================================
# Time Fixtures
# ============================================================================

@pytest.fixture
def frozen_time():
    """Freeze time for deterministic tests."""
    from freezegun import freeze_time
    
    with freeze_time("2024-01-15 12:00:00") as frozen:
        yield frozen


@pytest.fixture
def future_time():
    """Get a future timestamp."""
    return datetime.utcnow() + timedelta(days=30)


@pytest.fixture
def past_time():
    """Get a past timestamp."""
    return datetime.utcnow() - timedelta(days=30)


# ============================================================================
# Factory Fixtures
# ============================================================================

class UserFactory:
    """Factory for creating test users."""
    
    def __init__(self, session):
        self.session = session
    
    async def create(self, **overrides) -> "User":
        from models import User
        from services import hash_password
        
        defaults = {
            "email": fake.email(),
            "username": fake.user_name(),
            "password_hash": hash_password("password123"),
            "full_name": fake.name(),
            "is_active": True,
            "is_verified": True,
        }
        defaults.update(overrides)
        
        user = User(**defaults)
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        return user
    
    async def create_batch(self, count: int, **overrides) -> list:
        return [await self.create(**overrides) for _ in range(count)]


class PostFactory:
    """Factory for creating test posts."""
    
    def __init__(self, session):
        self.session = session
    
    async def create(self, author, **overrides) -> "Post":
        from models import Post
        
        defaults = {
            "author_id": author.id,
            "title": fake.sentence(),
            "slug": fake.slug(),
            "content": fake.text(max_nb_chars=1000),
            "excerpt": fake.text(max_nb_chars=200),
            "status": "published",
        }
        defaults.update(overrides)
        
        post = Post(**defaults)
        self.session.add(post)
        await self.session.flush()
        await self.session.refresh(post)
        return post


@pytest.fixture
def user_factory(db_session):
    return UserFactory(db_session)


@pytest.fixture
def post_factory(db_session):
    return PostFactory(db_session)


# ============================================================================
# Environment Fixtures
# ============================================================================

@pytest.fixture
def env_vars():
    """Set environment variables for tests."""
    original = os.environ.copy()
    os.environ.update({
        "ENV": "test",
        "DEBUG": "true",
        "SECRET_KEY": "test-secret-key",
    })
    yield os.environ
    os.environ.clear()
    os.environ.update(original)


@pytest.fixture
def mock_settings():
    """Mock application settings."""
    return MagicMock(
        debug=True,
        secret_key="test-secret",
        database_url="postgresql://test:test@localhost/test",
        redis_url="redis://localhost:6379/1",
        jwt_expiration=3600,
    )
