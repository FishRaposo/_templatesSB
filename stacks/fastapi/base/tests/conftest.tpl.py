"""
File: conftest.tpl.py
Purpose: Pytest fixtures for FastAPI testing
Generated for: {{PROJECT_NAME}}
Tier: base
Stack: fastapi
Category: testing
"""

import pytest
import asyncio
from typing import AsyncGenerator, Generator
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

# Import app and dependencies
from app.main import app
from app.dependencies import get_db, Base
from app.models import User
from app.auth import get_password_hash

# Test database URL (use in-memory SQLite or separate test database)
TEST_DATABASE_URL = "postgresql+asyncpg://test:test@localhost:5432/test_{{PROJECT_NAME}}"


# ============================================================================
# Async Event Loop Fixture
# ============================================================================

@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """
    Create an event loop for the test session.
    """
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# Database Fixtures
# ============================================================================

@pytest.fixture(scope="session")
async def test_engine():
    """
    Create test database engine.
    """
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=NullPool,
    )
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Drop all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    await engine.dispose()


@pytest.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """
    Create a database session for a test.
    """
    async_session = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    
    async with async_session() as session:
        # Start a transaction
        async with session.begin():
            yield session
            # Rollback after test
            await session.rollback()


# ============================================================================
# FastAPI Test Client Fixtures
# ============================================================================

@pytest.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """
    Create an async test client for FastAPI app.
    """
    # Override database dependency
    async def override_get_db():
        yield db_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    
    app.dependency_overrides.clear()


@pytest.fixture
async def authenticated_client(
    client: AsyncClient,
    test_user: User,
    db_session: AsyncSession
) -> AsyncClient:
    """
    Create an authenticated test client.
    """
    from app.auth import create_access_token
    
    # Create access token for test user
    token = create_access_token({"sub": str(test_user.id)})
    
    # Set authorization header
    client.headers["Authorization"] = f"Bearer {token}"
    
    return client


# ============================================================================
# User Fixtures
# ============================================================================

@pytest.fixture
async def test_user(db_session: AsyncSession) -> User:
    """
    Create a test user in the database.
    """
    user = User(
        email="test@example.com",
        username="testuser",
        full_name="Test User",
        hashed_password=get_password_hash("testpassword123"),
        is_active=True,
        is_admin=False,
    )
    
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    return user


@pytest.fixture
async def admin_user(db_session: AsyncSession) -> User:
    """
    Create an admin test user.
    """
    user = User(
        email="admin@example.com",
        username="adminuser",
        full_name="Admin User",
        hashed_password=get_password_hash("adminpassword123"),
        is_active=True,
        is_admin=True,
    )
    
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    return user


@pytest.fixture
async def multiple_users(db_session: AsyncSession) -> list[User]:
    """
    Create multiple test users.
    """
    users = []
    for i in range(5):
        user = User(
            email=f"user{i}@example.com",
            username=f"user{i}",
            full_name=f"User {i}",
            hashed_password=get_password_hash(f"password{i}"),
            is_active=True,
            is_admin=False,
        )
        db_session.add(user)
        users.append(user)
    
    await db_session.commit()
    
    for user in users:
        await db_session.refresh(user)
    
    return users


# ============================================================================
# Item Fixtures (Example Resource)
# ============================================================================

@pytest.fixture
async def test_item(db_session: AsyncSession, test_user: User):
    """
    Create a test item.
    """
    from app.models import Item
    
    item = Item(
        name="Test Item",
        description="A test item for testing",
        price=99.99,
        tax=10.0,
        owner_id=test_user.id,
        is_available=True,
    )
    
    db_session.add(item)
    await db_session.commit()
    await db_session.refresh(item)
    
    return item


@pytest.fixture
async def multiple_items(db_session: AsyncSession, test_user: User):
    """
    Create multiple test items.
    """
    from app.models import Item
    
    items = []
    for i in range(10):
        item = Item(
            name=f"Item {i}",
            description=f"Description for item {i}",
            price=10.0 * (i + 1),
            tax=1.0,
            owner_id=test_user.id,
            is_available=True,
        )
        db_session.add(item)
        items.append(item)
    
    await db_session.commit()
    
    for item in items:
        await db_session.refresh(item)
    
    return items


# ============================================================================
# Mock Data Factories
# ============================================================================

class UserFactory:
    """Factory for creating test users."""
    
    @staticmethod
    def create_user_data(
        email: str = "test@example.com",
        username: str = "testuser",
        password: str = "testpassword123",
        **kwargs
    ) -> dict:
        """Create user data dictionary."""
        return {
            "email": email,
            "username": username,
            "password": password,
            "full_name": kwargs.get("full_name", "Test User"),
            **kwargs
        }


class ItemFactory:
    """Factory for creating test items."""
    
    @staticmethod
    def create_item_data(
        name: str = "Test Item",
        price: float = 99.99,
        **kwargs
    ) -> dict:
        """Create item data dictionary."""
        return {
            "name": name,
            "description": kwargs.get("description", "Test description"),
            "price": price,
            "tax": kwargs.get("tax", 10.0),
            **kwargs
        }
