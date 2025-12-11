#!/usr/bin/env python3
"""
File: testing-helpers.tpl.py
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
"""

# -----------------------------------------------------------------------------
# FILE: testing-helpers.tpl.py
# PURPOSE: Testing utilities and helpers for Python projects
# USAGE: Common testing patterns, fixtures, and utilities for comprehensive testing
# DEPENDENCIES: pytest, pytest-asyncio, pytest-mock, faker, factory_boy, httpx
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
Python Testing Helpers Template
Purpose: Testing utilities and helpers for Python projects
Usage: Common testing patterns, fixtures, and utilities for comprehensive testing
"""

import asyncio
import json
import os
import tempfile
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch
import uuid
import hashlib
import secrets
import random

import pytest
import httpx
from faker import Faker
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from pydantic import BaseModel
import redis
import boto3
from moto import mock_s3, mock_dynamodb2
import mongomock
import psycopg2
from elasticsearch import Elasticsearch
from opensearchpy import OpenSearch

fake = Faker()

# =============================================================================
# DATABASE FIXTURES AND HELPERS
# =============================================================================

@pytest.fixture
def test_db_engine():
    """Create a test database engine"""
    engine = create_engine("sqlite:///:memory:")
    yield engine
    engine.dispose()

@pytest.fixture
def test_db_session(test_db_engine):
    """Create a test database session"""
    Session = sessionmaker(bind=test_db_engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture
def test_redis():
    """Create a test Redis client"""
    import fakeredis
    redis_client = fakeredis.FakeRedis(decode_responses=True)
    yield redis_client
    redis_client.flushall()

@pytest.fixture
def test_mongodb():
    """Create a test MongoDB client"""
    client = mongomock.MongoClient()
    db = client.test_db
    yield db
    client.drop_database('test_db')

@pytest.fixture
def test_elasticsearch():
    """Create a test Elasticsearch client"""
    from unittest.mock import MagicMock
    es_client = MagicMock()
    es_client.index.return_value = {"_id": "test_id", "result": "created"}
    es_client.search.return_value = {"hits": {"hits": []}}
    es_client.get.return_value = {"_source": {}}
    yield es_client

# =============================================================================
# API TESTING HELPERS
# =============================================================================

@pytest.fixture
def test_client(app):
    """Create a test client for FastAPI applications"""
    return TestClient(app)

@pytest.fixture
async def async_test_client(app):
    """Create an async test client for FastAPI applications"""
    async with httpx.AsyncClient(app=app, base_url="http://test") as client:
        yield client

@pytest.fixture
def mock_external_api():
    """Mock external API calls"""
    with patch('httpx.AsyncClient.get') as mock_get:
        mock_get.return_value = httpx.Response(
            status_code=200,
            json={"data": "mocked_response"}
        )
        yield mock_get

class APITestHelper:
    """Helper class for API testing"""
    
    def __init__(self, client: Union[TestClient, httpx.AsyncClient]):
        self.client = client
    
    def create_auth_headers(self, token: str = None) -> Dict[str, str]:
        """Create authentication headers"""
        if token is None:
            token = self.generate_test_token()
        return {"Authorization": f"Bearer {token}"}
    
    def generate_test_token(self, user_id: str = None, expires_in: int = 3600) -> str:
        """Generate a test JWT token"""
        import jwt
        payload = {
            "sub": user_id or str(uuid.uuid4()),
            "exp": int(time.time()) + expires_in,
            "iat": int(time.time()),
            "type": "access"
        }
        return jwt.encode(payload, "test_secret", algorithm="HS256")
    
    def assert_response_structure(self, response: Any, expected_fields: List[str]):
        """Assert response contains expected fields"""
        response_data = response.json() if hasattr(response, 'json') else response
        for field in expected_fields:
            assert field in response_data, f"Missing field: {field}"
    
    def assert_error_response(self, response: Any, expected_status: int, expected_error: str = None):
        """Assert error response structure"""
        assert response.status_code == expected_status
        response_data = response.json() if hasattr(response, 'json') else response
        assert "error" in response_data or "detail" in response_data
        if expected_error:
            error_msg = response_data.get("error") or response_data.get("detail")
            assert expected_error in error_msg

# =============================================================================
# ASYNC TESTING HELPERS
# =============================================================================

@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def async_context():
    """Create an async context for testing"""
    async with asynccontextmanager(lambda: (yield None))():
        yield

class AsyncTestHelper:
    """Helper class for async testing"""
    
    @staticmethod
    async def run_with_timeout(coro, timeout: float = 5.0):
        """Run coroutine with timeout"""
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            pytest.fail(f"Test timed out after {timeout} seconds")
    
    @staticmethod
    async def gather_with_exceptions(*coros):
        """Gather coroutines and return results with exceptions"""
        results = await asyncio.gather(*coros, return_exceptions=True)
        return results
    
    @staticmethod
    def create_async_mock(return_value=None, side_effect=None):
        """Create an async mock"""
        mock = AsyncMock()
        if return_value is not None:
            mock.return_value = return_value
        if side_effect is not None:
            mock.side_effect = side_effect
        return mock

# =============================================================================
# FILE SYSTEM TESTING HELPERS
# =============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)

@pytest.fixture
def temp_file(temp_dir):
    """Create a temporary file for testing"""
    def _create_temp_file(content: str = "", filename: str = None) -> Path:
        if filename is None:
            filename = f"test_file_{uuid.uuid4().hex[:8]}.txt"
        file_path = temp_dir / filename
        file_path.write_text(content)
        return file_path
    return _create_temp_file

class FileSystemHelper:
    """Helper class for file system testing"""
    
    @staticmethod
    @contextmanager
    def temp_file_context(content: str = "", suffix: str = ".txt") -> Generator[Path, None, None]:
        """Create a temporary file within a context manager"""
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(content)
            temp_path = Path(f.name)
        try:
            yield temp_path
        finally:
            temp_path.unlink(missing_ok=True)
    
    @staticmethod
    def create_mock_file_structure(base_dir: Path, structure: Dict[str, Any]):
        """Create a mock file structure from a dictionary"""
        for name, content in structure.items():
            path = base_dir / name
            if isinstance(content, dict):
                path.mkdir(parents=True, exist_ok=True)
                FileSystemHelper.create_mock_file_structure(path, content)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(content, bytes):
                    path.write_bytes(content)
                else:
                    path.write_text(str(content))
    
    @staticmethod
    def assert_file_exists(file_path: Path, should_exist: bool = True):
        """Assert file exists or doesn't exist"""
        if should_exist:
            assert file_path.exists(), f"File should exist: {file_path}"
        else:
            assert not file_path.exists(), f"File should not exist: {file_path}"
    
    @staticmethod
    def assert_file_content(file_path: Path, expected_content: str):
        """Assert file content matches expected content"""
        actual_content = file_path.read_text()
        assert actual_content == expected_content, f"File content mismatch in {file_path}"

# =============================================================================
# MOCKING HELPERS
# =============================================================================

class MockHelper:
    """Helper class for creating and managing mocks"""
    
    @staticmethod
    def create_mock_response(status_code: int = 200, json_data: Dict = None, text: str = None):
        """Create a mock HTTP response"""
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = json_data or {}
        mock_response.text = text or ""
        mock_response.content = (text or "").encode()
        return mock_response
    
    @staticmethod
    def create_mock_database_session():
        """Create a mock database session"""
        session = MagicMock()
        session.add = MagicMock()
        session.commit = MagicMock()
        session.rollback = MagicMock()
        session.query = MagicMock()
        session.delete = MagicMock()
        session.close = MagicMock()
        return session
    
    @staticmethod
    def create_mock_s3_client():
        """Create a mock S3 client"""
        client = MagicMock()
        client.upload_fileobj = MagicMock()
        client.download_fileobj = MagicMock()
        client.delete_object = MagicMock()
        client.head_object = MagicMock()
        client.list_objects_v2 = MagicMock()
        client.get_object = MagicMock()
        return client
    
    @staticmethod
    def patch_environment_variables(env_vars: Dict[str, str]):
        """Patch environment variables"""
        return patch.dict(os.environ, env_vars)
    
    @staticmethod
    def create_mock_cache():
        """Create a mock cache client"""
        cache = MagicMock()
        cache.get = MagicMock()
        cache.set = MagicMock()
        cache.delete = MagicMock()
        cache.exists = MagicMock()
        cache.expire = MagicMock()
        return cache

# =============================================================================
# PERFORMANCE TESTING HELPERS
# =============================================================================

class PerformanceHelper:
    """Helper class for performance testing"""
    
    @staticmethod
    def measure_execution_time(func, *args, **kwargs):
        """Measure execution time of a function"""
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        return result, execution_time
    
    @staticmethod
    def measure_memory_usage(func, *args, **kwargs):
        """Measure memory usage of a function"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        mem_before = process.memory_info().rss
        
        result = func(*args, **kwargs)
        
        mem_after = process.memory_info().rss
        memory_used = mem_after - mem_before
        
        return result, memory_used
    
    @staticmethod
    def benchmark_function(func, iterations: int = 1000, *args, **kwargs):
        """Benchmark a function over multiple iterations"""
        times = []
        for _ in range(iterations):
            _, execution_time = PerformanceHelper.measure_execution_time(func, *args, **kwargs)
            times.append(execution_time)
        
        return {
            "min_time": min(times),
            "max_time": max(times),
            "avg_time": sum(times) / len(times),
            "total_time": sum(times),
            "iterations": iterations
        }

# =============================================================================
# SECURITY TESTING HELPERS
# =============================================================================

class SecurityHelper:
    """Helper class for security testing"""
    
    @staticmethod
    def generate_test_payload(size: int = 1024) -> str:
        """Generate test payload of specified size"""
        return 'A' * size
    
    @staticmethod
    def generate_sql_injection_payloads() -> List[str]:
        """Generate common SQL injection payloads"""
        return [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin' /*",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR '1'='1--",
            "') OR ('1'='1--"
        ]
    
    @staticmethod
    def generate_xss_payloads() -> List[str]:
        """Generate common XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//"
        ]
    
    @staticmethod
    def generate_path_traversal_payloads() -> List[str]:
        """Generate common path traversal payloads"""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
    
    @staticmethod
    def assert_no_vulnerabilities(response: Any, payload: str, vulnerability_type: str):
        """Assert that response doesn't contain vulnerability indicators"""
        response_text = response.text if hasattr(response, 'text') else str(response)
        
        if vulnerability_type == "xss":
            assert "<script>" not in response_text.lower()
            assert "javascript:" not in response_text.lower()
        elif vulnerability_type == "sql_injection":
            assert "sql syntax" not in response_text.lower()
            assert "mysql_fetch" not in response_text.lower()
        elif vulnerability_type == "path_traversal":
            assert "root:" not in response_text.lower()
            assert "[boot loader]" not in response_text.lower()

# =============================================================================
# DATA VALIDATION HELPERS
# =============================================================================

class ValidationHelper:
    """Helper class for data validation testing"""
    
    @staticmethod
    def assert_valid_email(email: str):
        """Assert email is valid"""
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        assert re.match(email_pattern, email), f"Invalid email format: {email}"
    
    @staticmethod
    def assert_valid_phone(phone: str, pattern: str = None):
        """Assert phone number is valid"""
        import re
        if pattern is None:
            pattern = r'^\+?1?-?\.?\s?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$'
        assert re.match(pattern, phone), f"Invalid phone format: {phone}"
    
    @staticmethod
    def assert_valid_uuid(uuid_string: str):
        """Assert UUID is valid"""
        import uuid as uuid_lib
        try:
            uuid_lib.UUID(uuid_string)
        except ValueError:
            pytest.fail(f"Invalid UUID format: {uuid_string}")
    
    @staticmethod
    def assert_valid_json(json_string: str):
        """Assert string is valid JSON"""
        try:
            json.loads(json_string)
        except json.JSONDecodeError:
            pytest.fail(f"Invalid JSON format: {json_string}")
    
    @staticmethod
    def assert_password_strength(password: str, min_length: int = 8):
        """Assert password meets strength requirements"""
        assert len(password) >= min_length, f"Password too short: {len(password)} < {min_length}"
        assert any(c.isupper() for c in password), "Password missing uppercase letter"
        assert any(c.islower() for c in password), "Password missing lowercase letter"
        assert any(c.isdigit() for c in password), "Password missing digit"
        assert any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password), "Password missing special character"

# =============================================================================
# INTEGRATION TESTING HELPERS
# =============================================================================

class IntegrationHelper:
    """Helper class for integration testing"""
    
    @staticmethod
    @contextmanager
    def docker_compose_context(compose_file: str, services: List[str]):
        """Context manager for Docker Compose integration testing"""
        import docker
        client = docker.from_env()
        
        try:
            # Start services
            for service in services:
                client.containers.run(service, detach=True)
            
            # Wait for services to be ready
            time.sleep(10)
            yield
            
        finally:
            # Clean up containers
            for service in services:
                containers = client.containers.list(filters={"name": service})
                for container in containers:
                    container.stop()
                    container.remove()
    
    @staticmethod
    def wait_for_service(url: str, timeout: int = 30, interval: int = 2):
        """Wait for a service to be available"""
        import requests
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    return True
            except requests.RequestException:
                pass
            time.sleep(interval)
        
        raise TimeoutError(f"Service not available at {url} after {timeout} seconds")
    
    @staticmethod
    def create_test_database_config(db_type: str = "postgresql") -> Dict[str, str]:
        """Create test database configuration"""
        configs = {
            "postgresql": {
                "host": "localhost",
                "port": "5432",
                "database": "test_db",
                "username": "test_user",
                "password": "test_password"
            },
            "mysql": {
                "host": "localhost",
                "port": "3306",
                "database": "test_db",
                "username": "test_user",
                "password": "test_password"
            },
            "mongodb": {
                "host": "localhost",
                "port": "27017",
                "database": "test_db"
            }
        }
        return configs.get(db_type, configs["postgresql"])

# =============================================================================
# CUSTOM PYTEST MARKERS
# =============================================================================

def pytest_configure(config):
    """Configure custom pytest markers"""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as a performance test"
    )
    config.addinivalue_line(
        "markers", "security: mark test as a security test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "external_api: mark test that calls external APIs"
    )
    config.addinivalue_line(
        "markers", "database: mark test that requires database"
    )
    config.addinivalue_line(
        "markers", "redis: mark test that requires Redis"
    )
    config.addinivalue_line(
        "markers", "s3: mark test that requires S3"
    )

# =============================================================================
# TEST DATA GENERATORS
# =============================================================================

class TestDataGenerator:
    """Helper class for generating test data"""
    
    @staticmethod
    def generate_user_data(overrides: Dict = None) -> Dict:
        """Generate user test data"""
        data = {
            "email": fake.email(),
            "first_name": fake.first_name(),
            "last_name": fake.last_name(),
            "username": fake.user_name(),
            "password": fake.password(length=12),
            "phone": fake.phone_number(),
            "date_of_birth": fake.date_of_birth().isoformat(),
            "address": {
                "street": fake.street_address(),
                "city": fake.city(),
                "state": fake.state(),
                "zip_code": fake.zipcode(),
                "country": fake.country()
            },
            "preferences": {
                "theme": random.choice(["light", "dark"]),
                "language": random.choice(["en", "es", "fr"]),
                "notifications": fake.boolean()
            }
        }
        if overrides:
            data.update(overrides)
        return data
    
    @staticmethod
    def generate_product_data(overrides: Dict = None) -> Dict:
        """Generate product test data"""
        data = {
            "name": fake.catch_phrase(),
            "description": fake.paragraph(nb_sentences=5),
            "price": round(random.uniform(10.0, 1000.0), 2),
            "category": random.choice(["electronics", "clothing", "books", "home"]),
            "sku": f"SKU-{fake.uuid4().hex[:8].upper()}",
            "stock_quantity": random.randint(0, 1000),
            "is_active": fake.boolean(chance_of_getting_true=85),
            "tags": random.choices(["popular", "new", "sale", "featured"], k=random.randint(1, 3)),
            "attributes": {
                "color": fake.color_name(),
                "size": random.choice(["S", "M", "L", "XL"]),
                "material": random.choice(["cotton", "polyester", "wool"])
            }
        }
        if overrides:
            data.update(overrides)
        return data
    
    @staticmethod
    def generate_order_data(user_id: str = None, overrides: Dict = None) -> Dict:
        """Generate order test data"""
        data = {
            "user_id": user_id or str(uuid.uuid4()),
            "status": random.choice(["pending", "confirmed", "shipped", "delivered"]),
            "total_amount": round(random.uniform(50.0, 500.0), 2),
            "currency": random.choice(["USD", "EUR", "GBP"]),
            "items": [
                {
                    "product_id": str(uuid.uuid4()),
                    "quantity": random.randint(1, 5),
                    "unit_price": round(random.uniform(10.0, 100.0), 2)
                }
                for _ in range(random.randint(1, 5))
            ],
            "payment_method": random.choice(["credit_card", "paypal", "bank_transfer"]),
            "shipping_address": {
                "street": fake.street_address(),
                "city": fake.city(),
                "state": fake.state(),
                "zip_code": fake.zipcode(),
                "country": fake.country()
            }
        }
        if overrides:
            data.update(overrides)
        return data

# =============================================================================
# ASSERTION HELPERS
# =============================================================================

class AssertionHelper:
    """Helper class for custom assertions"""
    
    @staticmethod
    def assert_datetime_close(actual: datetime, expected: datetime, tolerance_seconds: int = 5):
        """Assert two datetimes are close within tolerance"""
        diff = abs((actual - expected).total_seconds())
        assert diff <= tolerance_seconds, f"Datetimes differ by {diff} seconds"
    
    @staticmethod
    def assert_lists_equal_unordered(list1: List, list2: List):
        """Assert two lists are equal regardless of order"""
        assert len(list1) == len(list2), f"Lists have different lengths: {len(list1)} vs {len(list2)}"
        assert sorted(list1) == sorted(list2), f"Lists contain different elements"
    
    @staticmethod
    def assert_dicts_subset(subset: Dict, superset: Dict):
        """Assert one dictionary is a subset of another"""
        for key, value in subset.items():
            assert key in superset, f"Key '{key}' not found in superset"
            assert superset[key] == value, f"Value mismatch for key '{key}': {subset[key]} != {superset[key]}"
    
    @staticmethod
    def assert_response_contains_keys(response: Dict, required_keys: List[str]):
        """Assert response contains all required keys"""
        missing_keys = [key for key in required_keys if key not in response]
        assert not missing_keys, f"Response missing required keys: {missing_keys}"
    
    @staticmethod
    def assert_valid_pagination(response: Dict, page: int = 1, page_size: int = 10):
        """Assert response has valid pagination structure"""
        required_keys = ["data", "pagination"]
        AssertionHelper.assert_response_contains_keys(response, required_keys)
        
        pagination = response["pagination"]
        assert "page" in pagination
        assert "page_size" in pagination
        assert "total" in pagination
        assert "total_pages" in pagination
        
        assert pagination["page"] == page
        assert pagination["page_size"] == page_size
        assert isinstance(pagination["total"], int)
        assert isinstance(pagination["total_pages"], int)

# Export all helper classes for easy import
__all__ = [
    "APITestHelper",
    "AsyncTestHelper",
    "FileSystemHelper",
    "MockHelper",
    "PerformanceHelper",
    "SecurityHelper",
    "ValidationHelper",
    "IntegrationHelper",
    "TestDataGenerator",
    "AssertionHelper"
]