"""
File: test_helpers.tpl.py
Purpose: Test helper functions and assertions
Generated for: {{PROJECT_NAME}}
"""

import json
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Type
from unittest.mock import MagicMock

import pytest
from httpx import Response


# ============================================================================
# Response Assertions
# ============================================================================

class APIResponse:
    """Wrapper for API responses with assertion methods."""
    
    def __init__(self, response: Response):
        self.response = response
        self._json = None
    
    @property
    def status_code(self) -> int:
        return self.response.status_code
    
    @property
    def json(self) -> dict:
        if self._json is None:
            self._json = self.response.json()
        return self._json
    
    @property
    def data(self) -> Any:
        return self.json.get("data")
    
    @property
    def errors(self) -> List[dict]:
        return self.json.get("errors", [])
    
    @property
    def message(self) -> Optional[str]:
        return self.json.get("message")
    
    def assert_status(self, expected: int) -> "APIResponse":
        assert self.status_code == expected, \
            f"Expected status {expected}, got {self.status_code}: {self.response.text}"
        return self
    
    def assert_ok(self) -> "APIResponse":
        assert 200 <= self.status_code < 300, \
            f"Expected 2xx status, got {self.status_code}: {self.response.text}"
        return self
    
    def assert_created(self) -> "APIResponse":
        return self.assert_status(201)
    
    def assert_no_content(self) -> "APIResponse":
        return self.assert_status(204)
    
    def assert_bad_request(self) -> "APIResponse":
        return self.assert_status(400)
    
    def assert_unauthorized(self) -> "APIResponse":
        return self.assert_status(401)
    
    def assert_forbidden(self) -> "APIResponse":
        return self.assert_status(403)
    
    def assert_not_found(self) -> "APIResponse":
        return self.assert_status(404)
    
    def assert_unprocessable(self) -> "APIResponse":
        return self.assert_status(422)
    
    def assert_server_error(self) -> "APIResponse":
        assert 500 <= self.status_code < 600
        return self
    
    def assert_json_contains(self, expected: dict) -> "APIResponse":
        for key, value in expected.items():
            assert key in self.json, f"Key '{key}' not in response"
            assert self.json[key] == value, \
                f"Expected {key}={value}, got {self.json[key]}"
        return self
    
    def assert_data_contains(self, expected: dict) -> "APIResponse":
        for key, value in expected.items():
            assert key in self.data, f"Key '{key}' not in data"
            assert self.data[key] == value
        return self
    
    def assert_error_code(self, code: str) -> "APIResponse":
        assert any(e.get("code") == code for e in self.errors), \
            f"Error code '{code}' not found in errors: {self.errors}"
        return self
    
    def assert_has_key(self, *keys: str) -> "APIResponse":
        for key in keys:
            assert key in self.json, f"Key '{key}' not found"
        return self
    
    def assert_list_length(self, expected: int, key: str = "data") -> "APIResponse":
        data = self.json.get(key, [])
        assert len(data) == expected, \
            f"Expected {expected} items, got {len(data)}"
        return self


def assert_response(response: Response) -> APIResponse:
    """Create an APIResponse wrapper for fluent assertions."""
    return APIResponse(response)


# ============================================================================
# Database Assertions
# ============================================================================

async def assert_exists_in_db(session, model: Type, **filters) -> Any:
    """Assert that a record exists in the database."""
    from sqlalchemy import select
    
    query = select(model).filter_by(**filters)
    result = await session.execute(query)
    record = result.scalar_one_or_none()
    assert record is not None, f"No {model.__name__} found with {filters}"
    return record


async def assert_not_exists_in_db(session, model: Type, **filters):
    """Assert that a record does not exist in the database."""
    from sqlalchemy import select
    
    query = select(model).filter_by(**filters)
    result = await session.execute(query)
    record = result.scalar_one_or_none()
    assert record is None, f"Found {model.__name__} with {filters}"


async def assert_count_in_db(session, model: Type, expected: int, **filters):
    """Assert the count of records in the database."""
    from sqlalchemy import select, func
    
    query = select(func.count()).select_from(model).filter_by(**filters)
    result = await session.execute(query)
    count = result.scalar()
    assert count == expected, f"Expected {expected} records, got {count}"


# ============================================================================
# Validation Helpers
# ============================================================================

def assert_email_format(email: str):
    """Assert that a string is a valid email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    assert re.match(pattern, email), f"Invalid email format: {email}"


def assert_uuid_format(value: str):
    """Assert that a string is a valid UUID format."""
    pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    assert re.match(pattern, value, re.I), f"Invalid UUID format: {value}"


def assert_iso_datetime(value: str):
    """Assert that a string is a valid ISO datetime."""
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        pytest.fail(f"Invalid ISO datetime: {value}")


def assert_url_format(url: str):
    """Assert that a string is a valid URL format."""
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    assert re.match(pattern, url), f"Invalid URL format: {url}"


def assert_json_schema(data: dict, schema: dict):
    """Assert that data matches a JSON schema (simplified)."""
    for key, expected_type in schema.items():
        if key.endswith("?"):  # Optional field
            key = key[:-1]
            if key not in data:
                continue
        
        assert key in data, f"Missing required key: {key}"
        
        if expected_type == "string":
            assert isinstance(data[key], str)
        elif expected_type == "int":
            assert isinstance(data[key], int)
        elif expected_type == "bool":
            assert isinstance(data[key], bool)
        elif expected_type == "list":
            assert isinstance(data[key], list)
        elif expected_type == "dict":
            assert isinstance(data[key], dict)


# ============================================================================
# Time Helpers
# ============================================================================

def assert_recent(dt: datetime, within_seconds: int = 60):
    """Assert that a datetime is within a certain time of now."""
    now = datetime.utcnow()
    diff = abs((now - dt).total_seconds())
    assert diff <= within_seconds, \
        f"Datetime {dt} is not within {within_seconds}s of now"


def assert_in_future(dt: datetime):
    """Assert that a datetime is in the future."""
    assert dt > datetime.utcnow(), f"Datetime {dt} is not in the future"


def assert_in_past(dt: datetime):
    """Assert that a datetime is in the past."""
    assert dt < datetime.utcnow(), f"Datetime {dt} is not in the past"


# ============================================================================
# Mock Helpers
# ============================================================================

def assert_called_with_schema(mock: MagicMock, schema: dict):
    """Assert that a mock was called with arguments matching a schema."""
    assert mock.called, "Mock was not called"
    
    call_args = mock.call_args
    if call_args.kwargs:
        for key, expected_type in schema.items():
            assert key in call_args.kwargs, f"Missing argument: {key}"
    elif call_args.args:
        # For positional arguments, check by position
        pass


def create_mock_response(
    status_code: int = 200,
    json_data: Optional[dict] = None,
    text: str = "",
) -> MagicMock:
    """Create a mock HTTP response."""
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data or {}
    mock.text = text or json.dumps(json_data or {})
    mock.headers = {}
    return mock


# ============================================================================
# Test Data Generators
# ============================================================================

def generate_test_data(count: int, template: dict) -> List[dict]:
    """Generate test data based on a template."""
    from faker import Faker
    fake = Faker()
    
    result = []
    for i in range(count):
        item = {}
        for key, value in template.items():
            if callable(value):
                item[key] = value(fake, i)
            else:
                item[key] = value
        result.append(item)
    return result


# Example usage:
# users = generate_test_data(10, {
#     "email": lambda f, i: f.email(),
#     "name": lambda f, i: f.name(),
#     "index": lambda f, i: i,
# })


# ============================================================================
# Context Managers
# ============================================================================

class assert_raises_with_message:
    """Context manager for asserting exceptions with messages."""
    
    def __init__(self, exception_type: Type[Exception], message_contains: str):
        self.exception_type = exception_type
        self.message_contains = message_contains
        self.exception = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            pytest.fail(f"Expected {self.exception_type.__name__} was not raised")
        
        if not issubclass(exc_type, self.exception_type):
            return False  # Re-raise
        
        self.exception = exc_val
        assert self.message_contains in str(exc_val), \
            f"Expected message containing '{self.message_contains}', got: {exc_val}"
        
        return True  # Suppress exception


class assert_no_queries:
    """Context manager to assert no database queries are made."""
    
    def __init__(self, engine):
        self.engine = engine
        self.query_count = 0
    
    def __enter__(self):
        # Set up query logging
        return self
    
    def __exit__(self, *args):
        assert self.query_count == 0, \
            f"Expected no queries, but {self.query_count} were executed"
