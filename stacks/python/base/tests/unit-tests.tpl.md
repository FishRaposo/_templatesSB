# Python Unit Testing Template
# Comprehensive unit testing patterns for Python projects using pytest

"""
Python Unit Test Patterns
Adapted from Go test patterns to Python/pytest
"""

import pytest
import unittest
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any, Optional
import json

# ====================
# BASIC UNIT TEST PATTERNS
# ====================

class TestSimpleFunctions:
    """Basic unit test patterns for Python functions"""
    
    @pytest.fixture
    def sample_data(self):
        return {"name": "John Doe", "email": "john@example.com"}
    
    def test_square_positive(self):
        """Test square function with positive numbers"""
        result = square(5)
        assert result == 25
    
    def test_square_zero(self):
        """Test square function with zero"""
        result = square(0)
        assert result == 0
    
    def test_square_negative(self):
        """Test square function with negative numbers"""
        result = square(-3)
        assert result == 9
    
    def test_square_large_number(self):
        """Test square function with large numbers"""
        result = square(100)
        assert result == 10000
    
    def test_calculate_discount_table_driven(self):
        """Table-driven tests for calculate_discount"""
        test_cases = [
            ("regular", 100.0, 0.0),
            ("premium", 50.0, 2.5),
            ("premium", 200.0, 20.0),
            ("vip", 100.0, 15.0),
        ]
        
        for customer_type, amount, expected in test_cases:
            discount = calculate_discount(customer_type, amount)
            assert abs(discount - expected) < 0.01
    
    def test_user_creation_with_setup_teardown(self, db_connection):
        """Test with setup and teardown using fixtures"""
        user = User(
            name="John Doe",
            email="john@example.com",
            password_hash="hashed_password"
        )
        
        created_user = db_connection.create_user(user)
        assert created_user.id is not None
        assert created_user.email == "john@example.com"
        
        # Verify retrieval
        found_user = db_connection.get_user(created_user.id)
        assert found_user.name == user.name

# ====================
# MOCK TESTING PATTERNS
# ====================

class TestWithMocking:
    """Demonstrate mocking patterns with unittest.mock"""
    
    @pytest.fixture
    def mock_repository(self):
        """Create a mock repository"""
        mock = Mock()
        mock.get_user = Mock()
        mock.save_user = Mock()
        return mock
    
    def test_service_with_mock_repository(self, mock_repository):
        """Test service layer with mocked repository"""
        # Setup expectations
        expected_user = User(
            id=1,
            name="John Doe",
            email="john@example.com"
        )
        mock_repository.get_user.return_value = expected_user
        mock_repository.save_user.return_value = None
        
        # Create service with mock
        service = UserService(mock_repository)
        
        # Execute
        user = service.get_user(1)
        
        # Assert
        assert user == expected_user
        mock_repository.get_user.assert_called_once_with(1)
        mock_repository.save_user.assert_not_called()
    
    def test_api_call_with_mock_requests(self):
        """Test API calls with mocked requests library"""
        with patch('requests.get') as mock_get:
            # Setup mock response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "id": 1,
                "name": "John Doe"
            }
            mock_get.return_value = mock_response
            
            # Execute
            result = fetch_user(1)
            
            # Assert
            assert result["name"] == "John Doe"
            mock_get.assert_called_once_with("https://api.example.com/users/1")
    
    def test_database_with_mock_session(self):
        """Test database operations with mocked SQLAlchemy session"""
        with patch('sqlalchemy.orm.Session') as mock_session:
            mock_session.add = Mock()
            mock_session.commit = Mock()
            mock_session.query = Mock()
            
            # Setup query mock
            mock_query = Mock()
            mock_query.filter_by = Mock(return_value=mock_query)
            mock_query.first = Mock(return_value=User(id=1, name="John"))
            mock_session.query.return_value = mock_query
            
            # Test
            user = get_user_by_id(mock_session, 1)
            assert user.id == 1
            mock_session.query.assert_called_once()

# ====================
# PARAMETERIZED AND TABLE-DRIVEN TESTS
# ====================

class TestParameterized:
    """Parameterized test patterns"""
    
    @pytest.mark.parametrize("customer_type,amount,expected", [
        ("regular", 100.0, 0.0),
        ("premium", 50.0, 2.5),
        ("premium", 200.0, 20.0),
        ("vip", 100.0, 15.0),
        ("vip", 1000.0, 150.0),
    ])
    def test_calculate_discount_parameterized(self, customer_type, amount, expected):
        """Parameterized discount calculation tests"""
        discount = calculate_discount(customer_type, amount)
        assert abs(discount - expected) < 0.01
    
    @pytest.mark.parametrize("input_value,expected_error", [
        ("invalid_customer", ValueError),
        (-100.0, ValueError),
        (None, TypeError),
    ])
    def test_calculate_discount_error_cases(self, input_value, expected_error):
        """Test error cases"""
        with pytest.raises(expected_error):
            calculate_discount("regular", input_value if input_value is not None else None)

# ====================
# FIXTURE PATTERNS
# ====================

@pytest.fixture
def test_database():
    """Create test database fixture"""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    engine = create_engine("sqlite:///:memory:")
    SessionLocal = sessionmaker(bind=engine)
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    session = SessionLocal()
    yield session
    session.close()

@pytest.fixture
def sample_user():
    """Create sample user fixture"""
    return User(
        id=1,
        name="John Doe",
        email="john@example.com",
        password_hash="hashed_password"
    )

@pytest.fixture
def authenticated_client():
    """Create authenticated test client"""
    from fastapi.testclient import TestClient
    from main import app
    
    client = TestClient(app)
    # Login and get token
    response = client.post("/auth/login", json={
        "email": "test@example.com",
        "password": "password123"
    })
    token = response.json()["access_token"]
    
    # Set authorization header
    client.headers = {"Authorization": f"Bearer {token}"}
    
    return client

class TestWithFixtures:
    """Demonstrate fixture usage patterns"""
    
    def test_user_creation_with_fixture(self, test_database, sample_user):
        """Test user creation using fixtures"""
        test_database.add(sample_user)
        test_database.commit()
        
        retrieved = test_database.query(User).filter_by(id=1).first()
        assert retrieved.name == "John Doe"
        assert retrieved.email == "john@example.com"
    
    def test_protected_endpoint_with_auth_client(self, authenticated_client):
        """Test protected endpoint with authenticated client"""
        response = authenticated_client.get("/users/profile")
        assert response.status_code == 200
        assert "email" in response.json()

# ====================
# ASYNC TESTING PATTERNS
# ====================

@pytest.mark.asyncio
class TestAsyncFunctions:
    """Async function testing patterns"""
    
    async def test_async_api_call(self):
        """Test async API calls"""
        result = await async_fetch_user(1)
        assert result["id"] == 1
        assert "name" in result
    
    async def test_async_database_query(self, async_db_connection):
        """Test async database operations"""
        users = await async_db_connection.execute(
            select(User).where(User.name == "John Doe")
        )
        assert len(users) > 0
    
    async def test_async_with_mock(self):
        """Test async functions with mocks"""
        with patch('httpx.AsyncClient.get') as mock_get:
            mock_response = Mock()
            mock_response.json = Mock(return_value={"id": 1, "name": "John"})
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = await async_api_call("https://api.example.com/users/1")
            assert result["name"] == "John"

# ====================
# DATABASE TESTING PATTERNS
# ====================

class TestDatabaseOperations:
    """Database operation test patterns"""
    
    def test_user_repository_create(self, test_database):
        """Test user creation in database"""
        user_repo = UserRepository(test_database)
        user = User(
            name="Jane Doe",
            email="jane@example.com",
            password_hash="hashed_password"
        )
        
        created_user = user_repo.create(user)
        assert created_user.id is not None
        assert created_user.created_at is not None
    
    def test_user_repository_find_by_email(self, test_database, sample_user):
        """Test finding user by email"""
        test_database.add(sample_user)
        test_database.commit()
        
        user_repo = UserRepository(test_database)
        found = user_repo.find_by_email("john@example.com")
        
        assert found is not None
        assert found.name == "John Doe"
    
    def test_user_not_found(self, test_database):
        """Test user not found scenario"""
        user_repo = UserRepository(test_database)
        found = user_repo.find_by_email("nonexistent@example.com")
        
        assert found is None
    
    def test_database_transaction_rollback(self, test_database):
        """Test transaction rollback on error"""
        user_repo = UserRepository(test_database)
        
        initial_count = test_database.query(User).count()
        
        try:
            with test_database.begin_nested():
                user = User(
                    name="Test User",
                    email="invalid_email",  # This might trigger a validation error
                    password_hash="hash"
                )
                test_database.add(user)
                # Force an error
                raise ValueError("Simulated error")
        except ValueError:
            pass
        
        # Verify no users were added
        final_count = test_database.query(User).count()
        assert final_count == initial_count

# ====================
# ERROR HANDLING TESTS
# ====================

class TestErrorHandling:
    """Error handling and exception test patterns"""
    
    def test_custom_exception_raised(self):
        """Test custom exception raising"""
        with pytest.raises(UserNotFoundError) as exc_info:
            get_user_by_id(999)
        
        assert "User 999 not found" in str(exc_info.value)
    
    def test_http_error_handling(self):
        """Test HTTP error handling"""
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.HTTPError("404 Not Found")
            
            with pytest.raises(HTTPException) as exc_info:
                fetch_external_resource("https://api.example.com/resource")
            
            assert exc_info.value.status_code == 404
    
    def test_validation_errors(self):
        """Test input validation errors"""
        with pytest.raises(ValidationError) as exc_info:
            validate_user_data({
                "email": "invalid-email",
                "age": -5
            })
        
        errors = exc_info.value.errors()
        assert len(errors) >= 2  # Should have multiple validation errors

# ====================
# API ENDPOINT TESTING
# ====================

class TestAPIEndpoints:
    """API endpoint testing patterns with FastAPI TestClient"""
    
    def test_create_user_endpoint(self, test_client):
        """Test user creation endpoint"""
        new_user = {
            "name": "Alice Smith",
            "email": "alice@example.com",
            "password": "SecurePass123!"
        }
        
        response = test_client.post("/api/v1/users", json=new_user)
        assert response.status_code == 201
        
        data = response.json()
        assert "id" in data
        assert data["email"] == "alice@example.com"
        assert "password" not in data  # Ensure password is not returned
    
    def test_get_user_endpoint(self, test_client, sample_user):
        """Test get user endpoint"""
        response = test_client.get(f"/api/v1/users/{sample_user.id}")
        assert response.status_code == 200
        
        data = response.json()
        assert data["id"] == sample_user.id
        assert data["name"] == sample_user.name
    
    def test_update_user_endpoint(self, test_client, sample_user):
        """Test user update endpoint"""
        updates = {"name": "Updated Name"}
        
        response = test_client.put(
            f"/api/v1/users/{sample_user.id}",
            json=updates
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["name"] == "Updated Name"
    
    def test_delete_user_endpoint(self, test_client, sample_user):
        """Test user deletion endpoint"""
        response = test_client.delete(f"/api/v1/users/{sample_user.id}")
        assert response.status_code == 204
        
        # Verify user is deleted
        get_response = test_client.get(f"/api/v1/users/{sample_user.id}")
        assert get_response.status_code == 404
    
    def test_pagination(self, test_client):
        """Test pagination of list endpoints"""
        response = test_client.get("/api/v1/users?page=1&limit=10")
        assert response.status_code == 200
        
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert data["page"] == 1
        assert len(data["items"]) <= 10

# ====================
# PYTEST CUSTOM MARKS
# ====================

# slow marks (configure in pytest.ini)
# Run with: pytest -m "not slow" to skip slow tests

@pytest.mark.slow
def test_expensive_computation():
    """Slow test that should be skipped in fast runs"""
    result = expensive_computation(n=1000000)
    assert result > 0

@pytest.mark.integration
def test_database_connection_real():
    """Integration test requiring real database"""
    conn = connect_to_real_database()
    assert conn.is_connected()
    conn.close()

@pytest.mark.parametrize("execution_number", range(5))
def test_multiple_times(execution_number):
    """Run same test multiple times for reliability"""
    result = flaky_operation()
    assert result is not None

# ====================
# TEST UTILITIES
# ====================

def assert_valid_user(user_dict: dict):
    """Custom assertion for user objects"""
    assert "id" in user_dict
    assert "email" in user_dict
    assert "name" in user_dict
    assert "password" not in user_dict  # Should never return password
    assert user_dict["email"].contains("@")

def create_test_user(overrides: dict = None) -> dict:
    """Factory function for test user creation"""
    user = {
        "name": "Test User",
        "email": "test@example.com",
        "password": "TestPass123!"
    }
    if overrides:
        user.update(overrides)
    return user

# ====================
# CODE COVERAGE
# ====================

'''
Run tests with coverage:
pytest --cov=app --cov-report=html --cov-report=term-missing

View coverage report:
open htmlcov/index.html

Coverage configuration in .coveragerc:
[run]
source = app
omit = 
    */tests/*
    */test_*
    */__pycache__/*

[report]
precision = 2
show_missing = True
skip_covered = False
exclude_lines =
    pragma: no cover
    def __repr__
    raise AssertionError
    raise NotImplementedError
    if __name__ == .__main__.:
    if TYPE_CHECKING:
'''

# ====================
# PERFORMANCE BENCHMARKS
# ====================

import time

def test_performance():
    """Simple performance test"""
    start_time = time.time()
    
    # Code to test
    result = expensive_operation()
    
    end_time = time.time()
    duration = end_time - start_time
    
    assert duration < 1.0  # Should complete in less than 1 second
    assert result is not None
"""

# ====================
# RUN TESTS
# ====================

'''
# Run all tests
pytest

# Run specific test file
pytest tests/unit/test_simple_functions.py

# Run specific test class
pytest tests/unit/test_simple_functions.py::TestSimpleFunctions

# Run specific test method
pytest tests/unit/test_simple_functions.py::TestSimpleFunctions::test_square_positive

# Run with verbose output
pytest -v

# Run in parallel (requires pytest-xdist)
pytest -n auto

# Run and generate coverage
pytest --cov=app

# Run only fast tests
pytest -m "not slow"

# Run only integration tests
pytest -m integration

# Watch mode (requires pytest-watch)
pytest-watch

# Debug a test
pytest --pdb

# Generate JUnit XML for CI
pytest --junitxml=reports/junit.xml

# Generate HTML report
pytest --html=reports/report.html

# Run with profiling (requires pytest-profiling)
pytest --profile
'''
