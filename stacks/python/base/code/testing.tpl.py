"""
File: testing.tpl.py
Purpose: Testing utilities and fixtures for pytest
Generated for: {{PROJECT_NAME}}
"""

import asyncio
from typing import AsyncGenerator, Generator, Any
from contextlib import asynccontextmanager
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool


# Test database URL (in-memory SQLite for tests)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def test_engine():
    """Create test database engine"""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    yield engine
    await engine.dispose()


@pytest.fixture(scope="function")
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Get a database session for each test"""
    # Import your Base model here
    # from models import Base
    # async with test_engine.begin() as conn:
    #     await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with session_maker() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """Get async HTTP client for testing FastAPI app"""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest.fixture
def auth_headers():
    """Get authentication headers for protected endpoints"""
    def _headers(token: str = "test-token") -> dict:
        return {"Authorization": f"Bearer {token}"}
    return _headers


# Test utilities
class TestDataFactory:
    """Factory for creating test data"""

    @staticmethod
    def user_data(
        email: str = "test@example.com",
        username: str = "testuser",
        password: str = "Password123!",
        **kwargs,
    ) -> dict:
        return {
            "email": email,
            "username": username,
            "password": password,
            **kwargs,
        }

    @staticmethod
    def post_data(
        title: str = "Test Post",
        content: str = "Test content",
        **kwargs,
    ) -> dict:
        return {
            "title": title,
            "content": content,
            **kwargs,
        }


# Async context managers for test setup/teardown
@asynccontextmanager
async def create_test_user(db_session: AsyncSession, **kwargs):
    """Create a test user and clean up after"""
    # from models import User
    # user = User(**TestDataFactory.user_data(**kwargs))
    # db_session.add(user)
    # await db_session.commit()
    # await db_session.refresh(user)
    # try:
    #     yield user
    # finally:
    #     await db_session.delete(user)
    #     await db_session.commit()
    yield None  # Placeholder


# Assertion helpers
def assert_response_ok(response, expected_status: int = 200):
    """Assert response is successful"""
    assert response.status_code == expected_status, (
        f"Expected {expected_status}, got {response.status_code}: {response.text}"
    )


def assert_response_error(response, expected_status: int, error_code: str = None):
    """Assert response is an error with expected status"""
    assert response.status_code == expected_status
    if error_code:
        data = response.json()
        assert data.get("error", {}).get("code") == error_code


def assert_contains_keys(data: dict, keys: list):
    """Assert dict contains all expected keys"""
    for key in keys:
        assert key in data, f"Missing key: {key}"


# Mock utilities
class MockResponse:
    """Mock HTTP response for testing"""

    def __init__(
        self,
        json_data: Any = None,
        status_code: int = 200,
        text: str = "",
    ):
        self._json_data = json_data
        self.status_code = status_code
        self.text = text or str(json_data)

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


# Usage in tests:
# @pytest.mark.asyncio
# async def test_create_user(client: AsyncClient, db_session: AsyncSession):
#     response = await client.post("/users", json=TestDataFactory.user_data())
#     assert_response_ok(response, 201)
#     assert_contains_keys(response.json(), ["id", "email", "username"])
