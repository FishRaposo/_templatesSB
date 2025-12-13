"""
Test Configuration and Fixtures
"""

import asyncio
from typing import AsyncGenerator, Generator
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.config import settings
from app.db.base import Base
from app.db.session import get_async_session
from app.core.security import create_access_token, get_password_hash
from app.models import User, Organization, OrganizationMember, Subscription, UserRole


# ============================================================================
# Test Database Setup
# ============================================================================

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ============================================================================
# Pytest Configuration
# ============================================================================

@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create database session for tests."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with TestingSessionLocal() as session:
        yield session
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create test client with database override."""
    
    async def override_get_session():
        yield db_session
    
    app.dependency_overrides[get_async_session] = override_get_session
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    
    app.dependency_overrides.clear()


# ============================================================================
# User Fixtures
# ============================================================================

@pytest_asyncio.fixture
async def test_password() -> str:
    """Common test password."""
    return "TestPassword123!"


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession, test_password: str) -> User:
    """Create a test user."""
    user = User(
        email="test@example.com",
        username="testuser",
        password_hash=get_password_hash(test_password),
        full_name="Test User",
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def test_admin(db_session: AsyncSession, test_password: str) -> User:
    """Create a test admin user."""
    user = User(
        email="admin@example.com",
        username="adminuser",
        password_hash=get_password_hash(test_password),
        full_name="Admin User",
        is_active=True,
        is_verified=True,
        is_superuser=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def inactive_user(db_session: AsyncSession, test_password: str) -> User:
    """Create an inactive test user."""
    user = User(
        email="inactive@example.com",
        username="inactiveuser",
        password_hash=get_password_hash(test_password),
        full_name="Inactive User",
        is_active=False,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def unverified_user(db_session: AsyncSession, test_password: str) -> User:
    """Create an unverified test user."""
    user = User(
        email="unverified@example.com",
        username="unverifieduser",
        password_hash=get_password_hash(test_password),
        full_name="Unverified User",
        is_active=True,
        is_verified=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


# ============================================================================
# Auth Fixtures
# ============================================================================

@pytest_asyncio.fixture
async def user_token(test_user: User) -> str:
    """Get access token for test user."""
    return create_access_token(test_user.id)


@pytest_asyncio.fixture
async def admin_token(test_admin: User) -> str:
    """Get access token for admin user."""
    return create_access_token(test_admin.id)


@pytest_asyncio.fixture
async def auth_headers(user_token: str) -> dict:
    """Get authorization headers for test user."""
    return {"Authorization": f"Bearer {user_token}"}


@pytest_asyncio.fixture
async def admin_headers(admin_token: str) -> dict:
    """Get authorization headers for admin user."""
    return {"Authorization": f"Bearer {admin_token}"}


# ============================================================================
# Organization Fixtures
# ============================================================================

@pytest_asyncio.fixture
async def test_org(
    db_session: AsyncSession,
    test_user: User,
) -> Organization:
    """Create a test organization with owner."""
    org = Organization(
        name="Test Organization",
        slug="test-org",
        description="A test organization",
    )
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    
    # Add owner membership
    membership = OrganizationMember(
        organization_id=org.id,
        user_id=test_user.id,
        role=UserRole.OWNER,
    )
    db_session.add(membership)
    await db_session.commit()
    
    return org


@pytest_asyncio.fixture
async def org_with_subscription(
    db_session: AsyncSession,
    test_org: Organization,
) -> Organization:
    """Create organization with active subscription."""
    subscription = Subscription(
        organization_id=test_org.id,
        stripe_subscription_id="sub_test123",
        stripe_price_id="price_test123",
        status="active",
        tier="pro",
        current_period_start=datetime.utcnow(),
        current_period_end=datetime.utcnow() + timedelta(days=30),
        seats_limit=25,
        storage_limit_mb=10000,
        api_calls_limit=100000,
    )
    db_session.add(subscription)
    await db_session.commit()
    await db_session.refresh(test_org)
    return test_org


# ============================================================================
# Factory Fixtures
# ============================================================================

@pytest_asyncio.fixture
def create_user(db_session: AsyncSession, test_password: str):
    """Factory to create users."""
    
    async def _create_user(
        email: str = None,
        username: str = None,
        is_active: bool = True,
        is_verified: bool = True,
        is_superuser: bool = False,
    ) -> User:
        import uuid
        unique_id = uuid.uuid4().hex[:8]
        
        user = User(
            email=email or f"user_{unique_id}@example.com",
            username=username or f"user_{unique_id}",
            password_hash=get_password_hash(test_password),
            full_name=f"User {unique_id}",
            is_active=is_active,
            is_verified=is_verified,
            is_superuser=is_superuser,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user
    
    return _create_user


@pytest_asyncio.fixture
def create_org(db_session: AsyncSession):
    """Factory to create organizations."""
    
    async def _create_org(
        name: str = None,
        slug: str = None,
        owner: User = None,
    ) -> Organization:
        import uuid
        unique_id = uuid.uuid4().hex[:8]
        
        org = Organization(
            name=name or f"Org {unique_id}",
            slug=slug or f"org-{unique_id}",
        )
        db_session.add(org)
        await db_session.commit()
        await db_session.refresh(org)
        
        if owner:
            membership = OrganizationMember(
                organization_id=org.id,
                user_id=owner.id,
                role=UserRole.OWNER,
            )
            db_session.add(membership)
            await db_session.commit()
        
        return org
    
    return _create_org


# ============================================================================
# Utility Fixtures
# ============================================================================

@pytest.fixture
def mock_stripe(mocker):
    """Mock Stripe API calls."""
    mock = mocker.patch("stripe.Subscription")
    mock.create.return_value = mocker.MagicMock(id="sub_mock123", status="active")
    mock.retrieve.return_value = mocker.MagicMock(id="sub_mock123", status="active")
    return mock


@pytest.fixture
def mock_email_service(mocker):
    """Mock email service."""
    return mocker.patch("app.services.email_service.EmailService")


# ============================================================================
# Cleanup
# ============================================================================

@pytest_asyncio.fixture(autouse=True)
async def cleanup_after_test(db_session: AsyncSession):
    """Clean up after each test."""
    yield
    # Rollback any uncommitted changes
    await db_session.rollback()
