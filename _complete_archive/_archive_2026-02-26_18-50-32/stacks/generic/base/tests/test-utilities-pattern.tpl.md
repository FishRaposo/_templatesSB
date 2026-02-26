<!--
File: test-utilities-pattern.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# ----------------------------------------------------------------------------- 
# FILE: test-utilities-pattern.tpl.md
# PURPOSE: Generic test utilities design pattern
# USAGE: Adapt this pattern for your specific technology stack
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Test Utilities Pattern

## Overview
Test utilities provide common helper functions, fixtures, and tools that make testing more efficient and maintainable. This pattern includes test data factories, assertion helpers, mock utilities, and test environment management across different technology stacks.

## Core Design Pattern

### 1. Test Utility Categories

#### Data Utilities
- **Test Factories**: Generate consistent test data
- **Data Builders**: Build complex objects step by step
- **Fixtures**: Pre-configured test data sets
- **Data Generators**: Create random but valid data

#### Assertion Utilities
- **Custom Assertions**: Domain-specific assertions
- **Comparison Helpers**: Deep comparison utilities
- **Validation Helpers**: Test data validation
- **Response Assertions**: HTTP/API response validation

#### Mock Utilities
- **Mock Builders**: Create configured mocks
- **Response Simulators**: Simulate external service responses
- **State Managers**: Manage mock state and expectations
- **Verification Helpers**: Verify mock interactions

#### Environment Utilities
- **Test Containers**: Manage test environment containers
- **Database Helpers**: Database setup and cleanup
- **File System Helpers**: Temporary file management
- **Network Helpers**: Network testing utilities

### 2. Pseudocode Implementation

```pseudocode
// Test Data Factory
class TestDataFactory:
    function __init__():
        self.sequences = {}
        self.random = RandomGenerator()
    
    function create_user(overrides=None):
        sequence = self.get_sequence("user")
        base_data = {
            "id": generate_uuid(),
            "username": f"user_{sequence}",
            "email": f"user_{sequence}@example.com",
            "password": "Password123!",
            "first_name": self.random.first_name(),
            "last_name": self.random.last_name(),
            "roles": ["user"],
            "is_active": True,
            "created_at": current_time(),
            "updated_at": current_time()
        }
        
        return merge(base_data, overrides or {})
    
    function create_product(overrides=None):
        sequence = self.get_sequence("product")
        base_data = {
            "id": generate_uuid(),
            "name": f"Product {sequence}",
            "description": f"Description for product {sequence}",
            "price": round(self.random.float(10.0, 1000.0), 2),
            "category": self.random.choice(["electronics", "clothing", "books", "home"]),
            "sku": f"SKU-{sequence:06d}",
            "in_stock": self.random.boolean(),
            "quantity": self.random.int(0, 100),
            "created_at": current_time()
        }
        
        return merge(base_data, overrides or {})
    
    function create_order(overrides=None):
        sequence = self.get_sequence("order")
        base_data = {
            "id": generate_uuid(),
            "user_id": generate_uuid(),
            "order_number": f"ORD-{sequence:08d}",
            "status": self.random.choice(["pending", "processing", "shipped", "delivered", "cancelled"]),
            "items": [],
            "subtotal": 0.0,
            "tax": 0.0,
            "total": 0.0,
            "created_at": current_time()
        }
        
        return merge(base_data, overrides or {})
    
    function create_batch(factory_method, count, overrides=None):
        return [factory_method(overrides) for _ in range(count)]
    
    function create_users(count, overrides=None):
        return self.create_batch(self.create_user, count, overrides)
    
    function create_products(count, overrides=None):
        return self.create_batch(self.create_product, count, overrides)
    
    function get_sequence(name):
        if name not in self.sequences:
            self.sequences[name] = 0
        self.sequences[name] += 1
        return self.sequences[name]

// Data Builder Pattern
class DataBuilder:
    function __init__(factory_method):
        self.factory_method = factory_method
        self.data = {}
        self.overrides = {}
    
    function with_field(field, value):
        self.overrides[field] = value
        return self
    
    function with_fields(fields_dict):
        self.overrides.update(fields_dict)
        return self
    
    function with_id(id):
        return self.with_field("id", id)
    
    function with_username(username):
        return self.with_field("username", username)
    
    function with_email(email):
        return self.with_field("email", email)
    
    function with_password(password):
        return self.with_field("password", password)
    
    function with_roles(roles):
        return self.with_field("roles", roles)
    
    function active():
        return self.with_field("is_active", True)
    
    function inactive():
        return self.with_field("is_active", False)
    
    function created_at(timestamp):
        return self.with_field("created_at", timestamp)
    
    function build():
        base_data = self.factory_method()
        return merge(base_data, self.overrides)

// Usage Example
function builder_example():
    # Using builder pattern
    user = (DataBuilder(TestDataFactory().create_user)
        .with_username("custom_user")
        .with_email("custom@example.com")
        .with_roles(["admin", "user"])
        .active()
        .created_at(parse_timestamp("2023-01-01T00:00:00Z"))
        .build())

// Assertion Helpers
class AssertionHelper:
    function assert_equal(actual, expected, message=None):
        if actual != expected:
            error_msg = message or f"Expected {expected}, got {actual}"
            raise AssertionError(error_msg)
    
    function assert_not_equal(actual, expected, message=None):
        if actual == expected:
            error_msg = message or f"Expected not {expected}, got {actual}"
            raise AssertionError(error_msg)
    
    function assert_contains(collection, item, message=None):
        if item not in collection:
            error_msg = message or f"Expected {item} to be in {collection}"
            raise AssertionError(error_msg)
    
    function assert_not_contains(collection, item, message=None):
        if item in collection:
            error_msg = message or f"Expected {item} not to be in {collection}"
            raise AssertionError(error_msg)
    
    function assert_is_none(value, message=None):
        if value is not None:
            error_msg = message or f"Expected None, got {value}"
            raise AssertionError(error_msg)
    
    function assert_is_not_none(value, message=None):
        if value is None:
            error_msg = message or "Expected not None, got None"
            raise AssertionError(error_msg)
    
    function assert_true(value, message=None):
        if not value:
            error_msg = message or f"Expected True, got {value}"
            raise AssertionError(error_msg)
    
    function assert_false(value, message=None):
        if value:
            error_msg = message or f"Expected False, got {value}"
            raise AssertionError(error_msg)
    
    function assert_greater_than(actual, expected, message=None):
        if actual <= expected:
            error_msg = message or f"Expected {actual} > {expected}"
            raise AssertionError(error_msg)
    
    function assert_less_than(actual, expected, message=None):
        if actual >= expected:
            error_msg = message or f"Expected {actual} < {expected}"
            raise AssertionError(error_msg)
    
    function assert_in_range(value, min_val, max_val, message=None):
        if value < min_val or value > max_val:
            error_msg = message or f"Expected {value} to be in range [{min_val}, {max_val}]"
            raise AssertionError(error_msg)
    
    function assert_matches_pattern(value, pattern, message=None):
        if not regex_match(pattern, value):
            error_msg = message or f"Expected {value} to match pattern {pattern}"
            raise AssertionError(error_msg)
    
    function assert_valid_email(email, message=None):
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        self.assert_matches_pattern(email, email_pattern, message or f"Invalid email: {email}")
    
    function assert_valid_uuid(uuid_string, message=None):
        uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        self.assert_matches_pattern(uuid_string, uuid_pattern, message or f"Invalid UUID: {uuid_string}")
    
    function assert_http_response(response, expected_status=200, expected_fields=None):
        self.assert_equal(response.status_code, expected_status, f"Expected status {expected_status}, got {response.status_code}")
        
        if expected_fields:
            response_data = response.json()
            for field in expected_fields:
                self.assert_contains(response_data, field, f"Response missing field: {field}")

// Mock Utilities
class MockBuilder:
    function __init__(service_name):
        self.service_name = service_name
        self.expectations = []
        self.default_responses = {}
    
    function expect_method(method_name):
        expectation = MethodExpectation(method_name)
        self.expectations.append(expectation)
        return expectation
    
    function default_response(method_name, response):
        self.default_responses[method_name] = response
        return self
    
    function build():
        return ConfiguredMock(self.service_name, self.expectations, self.default_responses)

class MethodExpectation:
    function __init__(method_name):
        self.method_name = method_name
        self.args = None
        self.kwargs = None
        self.response = None
        self.exception = None
        self.call_count = 1
        self.times_called = 0
    
    function with_args(*args):
        self.args = args
        return self
    
    function with_kwargs(**kwargs):
        self.kwargs = kwargs
        return self
    
    function return_value(response):
        self.response = response
        return self
    
    function raise_exception(exception):
        self.exception = exception
        return self
    
    function times(count):
        self.call_count = count
        return self
    
    function once():
        return self.times(1)
    
    function never():
        return self.times(0)

// File System Utilities
class FileSystemTestHelper:
    function __init__():
        self.temp_dirs = []
        self.temp_files = []
    
    function create_temp_directory():
        temp_dir = create_temp_directory()
        self.temp_dirs.append(temp_dir)
        return temp_dir
    
    function create_temp_file(content="", suffix=".tmp"):
        temp_file = create_temp_file(suffix=suffix)
        temp_file.write(content)
        temp_file.close()
        self.temp_files.append(temp_file.name)
        return temp_file.name
    
    function create_temp_json_file(data, suffix=".json"):
        json_content = json.dumps(data, indent=2)
        return self.create_temp_file(json_content, suffix)
    
    function create_temp_csv_file(data, headers=None, suffix=".csv"):
        # data should be list of lists or list of dicts
        csv_content = self._format_csv(data, headers)
        return self.create_temp_file(csv_content, suffix)
    
    function read_file(file_path):
        with open(file_path, 'r') as f:
            return f.read()
    
    function write_file(file_path, content):
        with open(file_path, 'w') as f:
            f.write(content)
    
    function file_exists(file_path):
        return file_path_exists(file_path)
    
    function directory_exists(dir_path):
        return directory_path_exists(dir_path)
    
    function cleanup():
        # Clean up all temporary files and directories
        for temp_file in self.temp_files:
            if file_path_exists(temp_file):
                remove_file(temp_file)
        
        for temp_dir in self.temp_dirs:
            if directory_path_exists(temp_dir):
                remove_directory(temp_dir)
        
        self.temp_files.clear()
        self.temp_dirs.clear()

// Database Test Helper
class DatabaseTestHelper:
    function __init__(database_connection):
        self.db = database_connection
        self.transactions = []
    
    function begin_transaction():
        transaction = self.db.begin_transaction()
        self.transactions.append(transaction)
        return transaction
    
    function rollback_transaction(transaction):
        transaction.rollback()
        self.transactions.remove(transaction)
    
    function commit_transaction(transaction):
        transaction.commit()
        self.transactions.remove(transaction)
    
    function cleanup_all_transactions():
        for transaction in self.transactions:
            transaction.rollback()
        self.transactions.clear()
    
    function truncate_table(table_name):
        self.db.execute(f"TRUNCATE TABLE {table_name}")
    
    function truncate_all_tables():
        tables = self.db.get_table_names()
        for table in tables:
            if not table.startswith("pg_"):  # Skip system tables for PostgreSQL
                self.truncate_table(table)
    
    function insert_record(table_name, data):
        return self.db.insert(table_name, data)
    
    function insert_records(table_name, records):
        return self.db.insert_many(table_name, records)
    
    function count_records(table_name, where_clause=None):
        return self.db.count(table_name, where_clause)
    
    function find_record(table_name, where_clause):
        return self.db.find_one(table_name, where_clause)
    
    function find_records(table_name, where_clause=None, limit=None):
        return self.db.find_many(table_name, where_clause, limit)

// HTTP Test Helper
class HTTPTestHelper:
    function __init__(base_url="http://localhost:8080"):
        self.base_url = base_url
        self.session = create_http_session()
    
    function get(endpoint, params=None, headers=None):
        url = f"{self.base_url}{endpoint}"
        return self.session.get(url, params=params, headers=headers)
    
    function post(endpoint, data=None, json=None, headers=None):
        url = f"{self.base_url}{endpoint}"
        return self.session.post(url, data=data, json=json, headers=headers)
    
    function put(endpoint, data=None, json=None, headers=None):
        url = f"{self.base_url}{endpoint}"
        return self.session.put(url, data=data, json=json, headers=headers)
    
    function delete(endpoint, headers=None):
        url = f"{self.base_url}{endpoint}"
        return self.session.delete(url, headers=headers)
    
    function assert_response(response, expected_status=200, expected_content_type=None):
        assert response.status_code == expected_status, f"Expected status {expected_status}, got {response.status_code}"
        
        if expected_content_type:
            content_type = response.headers.get("content-type", "")
            assert expected_content_type in content_type, f"Expected content-type {expected_content_type}, got {content_type}"
    
    function assert_json_response(response, expected_status=200, expected_fields=None):
        self.assert_response(response, expected_status, "application/json")
        
        response_data = response.json()
        
        if expected_fields:
            for field in expected_fields:
                assert field in response_data, f"Response missing field: {field}"
        
        return response_data
    
    function assert_error_response(response, expected_status=400, expected_error_message=None):
        self.assert_json_response(response, expected_status, ["error"])
        
        response_data = response.json()
        
        if expected_error_message:
            assert expected_error_message in response_data["error"], f"Expected error message '{expected_error_message}' in '{response_data['error']}'"

// Time Test Helper
class TimeTestHelper:
    function __init__():
        self.freeze_time = None
    
    function freeze_time(timestamp):
        self.freeze_time = timestamp
        set_system_time(timestamp)
    
    function unfreeze_time():
        self.freeze_time = None
        restore_system_time()
    
    function travel_to_time(timestamp):
        set_system_time(timestamp)
    
    function travel_forward(duration):
        new_time = current_time() + duration
        set_system_time(new_time)
    
    function travel_backward(duration):
        new_time = current_time() - duration
        set_system_time(new_time)
    
    function create_timestamp(year, month, day, hour=0, minute=0, second=0):
        return create_timestamp(year, month, day, hour, minute, second)
    
    function create_date(year, month, day):
        return create_date(year, month, day)
    
    function assert_timestamp_near(actual, expected, tolerance_seconds=1):
        diff = abs(actual - expected)
        assert diff <= tolerance_seconds, f"Timestamp {actual} not within {tolerance_seconds} seconds of {expected}"

// Random Data Generator
class RandomGenerator:
    function __init__(seed=None):
        self.random = create_random_generator(seed)
        self.first_names = ["John", "Jane", "Michael", "Sarah", "David", "Emily", "Robert", "Lisa"]
        self.last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"]
        self.companies = ["Acme Corp", "Tech Solutions", "Global Industries", "Innovation Labs", "Digital Systems"]
        self.cities = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia"]
        self.states = ["CA", "NY", "TX", "FL", "IL", "PA"]
    
    function string(length=10, charset="abcdefghijklmnopqrstuvwxyz"):
        return ''.join(self.random.choice(charset) for _ in range(length))
    
    function int(min_val=0, max_val=100):
        return self.random.randint(min_val, max_val)
    
    function float(min_val=0.0, max_val=100.0):
        return self.random.uniform(min_val, max_val)
    
    function boolean():
        return self.random.choice([True, False])
    
    function choice(choices):
        return self.random.choice(choices)
    
    function choices(choices, count):
        return [self.choice(choices) for _ in range(count)]
    
    function email():
        username = self.string(8, "abcdefghijklmnopqrstuvwxyz")
        domain = self.string(6, "abcdefghijklmnopqrstuvwxyz")
        return f"{username}@{domain}.com"
    
    function phone():
        area = self.random.randint(200, 999)
        prefix = self.random.randint(200, 999)
        line = self.random.randint(1000, 9999)
        return f"({area}) {prefix}-{line}"
    
    function uuid():
        return generate_uuid()
    
    function first_name():
        return self.choice(self.first_names)
    
    function last_name():
        return self.choice(self.last_names)
    
    function full_name():
        return f"{self.first_name()} {self.last_name()}"
    
    function company():
        return self.choice(self.companies)
    
    function address():
        number = self.int(1, 9999)
        street = self.choice(["Main", "Oak", "Pine", "Maple", "Cedar"])
        return f"{number} {street} St"
    
    function city():
        return self.choice(self.cities)
    
    function state():
        return self.choice(self.states)
    
    function zip_code():
        return self.string(5, "0123456789")
    
    function date(start_year=2020, end_year=2023):
        year = self.int(start_year, end_year)
        month = self.int(1, 12)
        day = self.int(1, 28)  # Use 28 to avoid month-specific issues
        return create_date(year, month, day)
    
    function datetime(start_year=2020, end_year=2023):
        date_obj = self.date(start_year, end_year)
        hour = self.int(0, 23)
        minute = self.int(0, 59)
        second = self.int(0, 59)
        return create_datetime(date_obj.year, date_obj.month, date_obj.day, hour, minute, second)
```

## Technology-Specific Implementations

### Python

```python
# tests/utils/test_data_factory.py
import uuid
import random
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

class TestDataFactory:
    def __init__(self, seed: Optional[int] = None):
        if seed:
            random.seed(seed)
        self.sequences = {}
        self.random = RandomGenerator(seed)
    
    def create_user(self, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        sequence = self._get_sequence("user")
        base_data = {
            "id": str(uuid.uuid4()),
            "username": f"user_{sequence}",
            "email": f"user_{sequence}@example.com",
            "password": "Password123!",
            "first_name": self.random.first_name(),
            "last_name": self.random.last_name(),
            "roles": ["user"],
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        return {**base_data, **(overrides or {})}
    
    def create_product(self, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        sequence = self._get_sequence("product")
        base_data = {
            "id": str(uuid.uuid4()),
            "name": f"Product {sequence}",
            "description": f"Description for product {sequence}",
            "price": round(self.random.float(10.0, 1000.0), 2),
            "category": self.random.choice(["electronics", "clothing", "books", "home"]),
            "sku": f"SKU-{sequence:06d}",
            "in_stock": self.random.boolean(),
            "quantity": self.random.int(0, 100),
            "created_at": datetime.utcnow()
        }
        
        return {**base_data, **(overrides or {})}
    
    def create_batch(self, factory_method, count: int, overrides: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return [factory_method(overrides) for _ in range(count)]

class DataBuilder:
    def __init__(self, factory_method):
        self.factory_method = factory_method
        self.overrides = {}
    
    def with_field(self, field: str, value: Any):
        self.overrides[field] = value
        return self
    
    def with_fields(self, fields_dict: Dict[str, Any]):
        self.overrides.update(fields_dict)
        return self
    
    def with_id(self, user_id: str):
        return self.with_field("id", user_id)
    
    def with_username(self, username: str):
        return self.with_field("username", username)
    
    def with_email(self, email: str):
        return self.with_field("email", email)
    
    def with_roles(self, roles: List[str]):
        return self.with_field("roles", roles)
    
    def active(self):
        return self.with_field("is_active", True)
    
    def build(self):
        base_data = self.factory_method()
        return {**base_data, **self.overrides}

# tests/utils/assertions.py
import re
from typing import Any, Dict, List

class AssertionHelper:
    @staticmethod
    def assert_equal(actual: Any, expected: Any, message: Optional[str] = None):
        assert actual == expected, message or f"Expected {expected}, got {actual}"
    
    @staticmethod
    def assert_contains(collection: List[Any], item: Any, message: Optional[str] = None):
        assert item in collection, message or f"Expected {item} to be in {collection}"
    
    @staticmethod
    def assert_valid_email(email: str, message: Optional[str] = None):
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        assert re.match(email_pattern, email), message or f"Invalid email: {email}"
    
    @staticmethod
    def assert_valid_uuid(uuid_string: str, message: Optional[str] = None):
        uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        assert re.match(uuid_pattern, uuid_string), message or f"Invalid UUID: {uuid_string}"
    
    @staticmethod
    def assert_http_response(response, expected_status: int = 200, expected_fields: Optional[List[str]] = None):
        assert response.status_code == expected_status, f"Expected status {expected_status}, got {response.status_code}"
        
        if expected_fields:
            response_data = response.json()
            for field in expected_fields:
                assert field in response_data, f"Response missing field: {field}"

# tests/utils/file_helper.py
import tempfile
import json
import csv
import os
from typing import Any, Dict, List, Union

class FileSystemTestHelper:
    def __init__(self):
        self.temp_dirs = []
        self.temp_files = []
    
    def create_temp_directory(self) -> str:
        temp_dir = tempfile.mkdtemp()
        self.temp_dirs.append(temp_dir)
        return temp_dir
    
    def create_temp_file(self, content: str = "", suffix: str = ".tmp") -> str:
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(content)
            temp_file = f.name
        
        self.temp_files.append(temp_file)
        return temp_file
    
    def create_temp_json_file(self, data: Dict[str, Any], suffix: str = ".json") -> str:
        json_content = json.dumps(data, indent=2)
        return self.create_temp_file(json_content, suffix)
    
    def cleanup(self):
        for temp_file in self.temp_files:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
        
        for temp_dir in self.temp_dirs:
            if os.path.exists(temp_dir):
                import shutil
                shutil.rmtree(temp_dir)
        
        self.temp_files.clear()
        self.temp_dirs.clear()

# tests/utils/http_helper.py
import requests
from typing import Dict, Any, Optional, List

class HTTPTestHelper:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def get(self, endpoint: str, params: Optional[Dict] = None, headers: Optional[Dict] = None):
        url = f"{self.base_url}{endpoint}"
        return self.session.get(url, params=params, headers=headers)
    
    def post(self, endpoint: str, data: Optional[Dict] = None, json: Optional[Dict] = None, headers: Optional[Dict] = None):
        url = f"{self.base_url}{endpoint}"
        return self.session.post(url, data=data, json=json, headers=headers)
    
    def assert_response(self, response, expected_status: int = 200, expected_content_type: Optional[str] = None):
        assert response.status_code == expected_status, f"Expected status {expected_status}, got {response.status_code}"
        
        if expected_content_type:
            content_type = response.headers.get("content-type", "")
            assert expected_content_type in content_type, f"Expected content-type {expected_content_type}, got {content_type}"
    
    def assert_json_response(self, response, expected_status: int = 200, expected_fields: Optional[List[str]] = None):
        self.assert_response(response, expected_status, "application/json")
        
        response_data = response.json()
        
        if expected_fields:
            for field in expected_fields:
                assert field in response_data, f"Response missing field: {field}"
        
        return response_data

# tests/conftest.py
import pytest
from tests.utils.test_data_factory import TestDataFactory, DataBuilder
from tests.utils.assertions import AssertionHelper
from tests.utils.file_helper import FileSystemTestHelper
from tests.utils.http_helper import HTTPTestHelper

@pytest.fixture
def test_data_factory():
    return TestDataFactory()

@pytest.fixture
def assertion_helper():
    return AssertionHelper()

@pytest.fixture
def file_helper():
    helper = FileSystemTestHelper()
    yield helper
    helper.cleanup()

@pytest.fixture
def http_helper():
    return HTTPTestHelper()

@pytest.fixture
def user_builder():
    return DataBuilder(TestDataFactory().create_user)
```

### Node.js (Jest)

```javascript
// tests/utils/TestDataFactory.js
class TestDataFactory {
  constructor(seed = null) {
    this.sequences = {};
    this.random = new RandomGenerator(seed);
  }
  
  createUser(overrides = {}) {
    const sequence = this._getSequence('user');
    const baseData = {
      id: this._generateUUID(),
      username: `user_${sequence}`,
      email: `user_${sequence}@example.com`,
      password: 'Password123!',
      firstName: this.random.firstName(),
      lastName: this.random.lastName(),
      roles: ['user'],
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    return { ...baseData, ...overrides };
  }
  
  createProduct(overrides = {}) {
    const sequence = this._getSequence('product');
    const baseData = {
      id: this._generateUUID(),
      name: `Product ${sequence}`,
      description: `Description for product ${sequence}`,
      price: Math.round(this.random.float(10.0, 1000.0) * 100) / 100,
      category: this.random.choice(['electronics', 'clothing', 'books', 'home']),
      sku: `SKU-${sequence.toString().padStart(6, '0')}`,
      inStock: this.random.boolean(),
      quantity: this.random.int(0, 100),
      createdAt: new Date()
    };
    
    return { ...baseData, ...overrides };
  }
  
  createBatch(factoryMethod, count, overrides = {}) {
    return Array.from({ length: count }, () => factoryMethod(overrides));
  }
  
  _getSequence(name) {
    if (!this.sequences[name]) {
      this.sequences[name] = 0;
    }
    this.sequences[name]++;
    return this.sequences[name];
  }
  
  _generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}

class DataBuilder {
  constructor(factoryMethod) {
    this.factoryMethod = factoryMethod;
    this.overrides = {};
  }
  
  withField(field, value) {
    this.overrides[field] = value;
    return this;
  }
  
  withFields(fieldsObj) {
    this.overrides = { ...this.overrides, ...fieldsObj };
    return this;
  }
  
  withId(id) {
    return this.withField('id', id);
  }
  
  withUsername(username) {
    return this.withField('username', username);
  }
  
  withEmail(email) {
    return this.withField('email', email);
  }
  
  withRoles(roles) {
    return this.withField('roles', roles);
  }
  
  active() {
    return this.withField('isActive', true);
  }
  
  build() {
    const baseData = this.factoryMethod();
    return { ...baseData, ...this.overrides };
  }
}

// tests/utils/AssertionHelper.js
class AssertionHelper {
  static assertEqual(actual, expected, message = null) {
    expect(actual).toEqual(expected);
  }
  
  static assertContains(collection, item, message = null) {
    expect(collection).toContain(item);
  }
  
  static assertValidEmail(email, message = null) {
    const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    expect(email).toMatch(emailPattern);
  }
  
  static assertValidUUID(uuidString, message = null) {
    const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    expect(uuidString).toMatch(uuidPattern);
  }
  
  static assertHttpResponse(response, expectedStatus = 200, expectedFields = null) {
    expect(response.status).toBe(expectedStatus);
    
    if (expectedFields) {
      expectedFields.forEach(field => {
        expect(response.data).toHaveProperty(field);
      });
    }
  }
}

// tests/utils/FileSystemTestHelper.js
const fs = require('fs');
const path = require('path');
const os = require('os');

class FileSystemTestHelper {
  constructor() {
    this.tempDirs = [];
    this.tempFiles = [];
  }
  
  createTempDirectory() {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'test-'));
    this.tempDirs.push(tempDir);
    return tempDir;
  }
  
  createTempFile(content = '', suffix = '.tmp') {
    const tempFile = fs.mkdtempSync(path.join(os.tmpdir(), 'test-')) + suffix;
    fs.writeFileSync(tempFile, content);
    this.tempFiles.push(tempFile);
    return tempFile;
  }
  
  createTempJSONFile(data, suffix = '.json') {
    const jsonContent = JSON.stringify(data, null, 2);
    return this.createTempFile(jsonContent, suffix);
  }
  
  cleanup() {
    this.tempFiles.forEach(file => {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    });
    
    this.tempDirs.forEach(dir => {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
    
    this.tempFiles = [];
    this.tempDirs = [];
  }
}

// tests/setup.js
const { TestDataFactory, DataBuilder } = require('./utils/TestDataFactory');
const { AssertionHelper } = require('./utils/AssertionHelper');
const { FileSystemTestHelper } = require('./utils/FileSystemTestHelper');

// Global test utilities
global.testDataFactory = new TestDataFactory();
global.assertionHelper = AssertionHelper;
global.fileHelper = new FileSystemTestHelper();

// Global builder functions
global.createUserBuilder = () => new DataBuilder(global.testDataFactory.createUser.bind(global.testDataFactory));

// Cleanup after all tests
afterAll(() => {
  global.fileHelper.cleanup();
});

// tests/example.test.js
describe('Test Utilities Example', () => {
  let fileHelper;
  
  beforeEach(() => {
    fileHelper = new FileSystemTestHelper();
  });
  
  afterEach(() => {
    fileHelper.cleanup();
  });
  
  test('should create test user with builder', () => {
    const user = createUserBuilder()
      .withUsername('custom_user')
      .withEmail('custom@example.com')
      .withRoles(['admin'])
      .active()
      .build();
    
    expect(user.username).toBe('custom_user');
    expect(user.email).toBe('custom@example.com');
    expect(user.roles).toContain('admin');
    expect(user.isActive).toBe(true);
  });
  
  test('should create temp file with JSON content', () => {
    const testData = { name: 'Test', value: 123 };
    const tempFile = fileHelper.createTempJSONFile(testData);
    
    expect(fs.existsSync(tempFile)).toBe(true);
    
    const content = fs.readFileSync(tempFile, 'utf8');
    const parsedData = JSON.parse(content);
    
    expect(parsedData.name).toBe('Test');
    expect(parsedData.value).toBe(123);
  });
});
```

### Go

```go
// tests/utils/test_data_factory.go
package utils

import (
    "fmt"
    "math/rand"
    "time"
    "github.com/google/uuid"
)

type TestDataFactory struct {
    sequences map[string]int
    random    *RandomGenerator
}

func NewTestDataFactory(seed int64) *TestDataFactory {
    if seed == 0 {
        seed = time.Now().UnixNano()
    }
    
    return &TestDataFactory{
        sequences: make(map[string]int),
        random:    NewRandomGenerator(seed),
    }
}

func (f *TestDataFactory) CreateUser(overrides map[string]interface{}) map[string]interface{} {
    sequence := f.getSequence("user")
    baseData := map[string]interface{}{
        "id":        uuid.New().String(),
        "username":  fmt.Sprintf("user_%d", sequence),
        "email":     fmt.Sprintf("user_%d@example.com", sequence),
        "password":  "Password123!",
        "firstName": f.random.FirstName(),
        "lastName":  f.random.LastName(),
        "roles":     []string{"user"},
        "isActive":  true,
        "createdAt": time.Now(),
        "updatedAt": time.Now(),
    }
    
    return mergeMaps(baseData, overrides)
}

func (f *TestDataFactory) CreateProduct(overrides map[string]interface{}) map[string]interface{} {
    sequence := f.getSequence("product")
    baseData := map[string]interface{}{
        "id":          uuid.New().String(),
        "name":        fmt.Sprintf("Product %d", sequence),
        "description": fmt.Sprintf("Description for product %d", sequence),
        "price":       f.random.Float(10.0, 1000.0),
        "category":    f.random.Choice([]string{"electronics", "clothing", "books", "home"}),
        "sku":         fmt.Sprintf("SKU-%06d", sequence),
        "inStock":     f.random.Boolean(),
        "quantity":    f.random.Int(0, 100),
        "createdAt":   time.Now(),
    }
    
    return mergeMaps(baseData, overrides)
}

func (f *TestDataFactory) CreateBatch(createFunc func(map[string]interface{}) map[string]interface{}, count int, overrides map[string]interface{}) []map[string]interface{} {
    results := make([]map[string]interface{}, count)
    for i := 0; i < count; i++ {
        results[i] = createFunc(overrides)
    }
    return results
}

func (f *TestDataFactory) getSequence(name string) int {
    if f.sequences[name] == 0 {
        f.sequences[name] = 0
    }
    f.sequences[name]++
    return f.sequences[name]
}

// tests/utils/data_builder.go
type DataBuilder struct {
    factoryMethod func(map[string]interface{}) map[string]interface{}
    overrides     map[string]interface{}
}

func NewDataBuilder(factoryMethod func(map[string]interface{}) map[string]interface{}) *DataBuilder {
    return &DataBuilder{
        factoryMethod: factoryMethod,
        overrides:     make(map[string]interface{}),
    }
}

func (b *DataBuilder) WithField(field string, value interface{}) *DataBuilder {
    b.overrides[field] = value
    return b
}

func (b *DataBuilder) WithFields(fields map[string]interface{}) *DataBuilder {
    for k, v := range fields {
        b.overrides[k] = v
    }
    return b
}

func (b *DataBuilder) WithID(id string) *DataBuilder {
    return b.WithField("id", id)
}

func (b *DataBuilder) WithUsername(username string) *DataBuilder {
    return b.WithField("username", username)
}

func (b *DataBuilder) WithEmail(email string) *DataBuilder {
    return b.WithField("email", email)
}

func (b *DataBuilder) WithRoles(roles []string) *DataBuilder {
    return b.WithField("roles", roles)
}

func (b *DataBuilder) Active() *DataBuilder {
    return b.WithField("isActive", true)
}

func (b *DataBuilder) Build() map[string]interface{} {
    baseData := b.factoryMethod(nil)
    return mergeMaps(baseData, b.overrides)
}

// tests/utils/assertion_helper.go
package utils

import (
    "regexp"
    "testing"
)

type AssertionHelper struct {
    t *testing.T
}

func NewAssertionHelper(t *testing.T) *AssertionHelper {
    return &AssertionHelper{t: t}
}

func (a *AssertionHelper) Equal(actual, expected interface{}, message ...string) {
    if len(message) > 0 {
        a.t.Helper()
        a.t.Fatalf(message[0])
    }
    if actual != expected {
        a.t.Helper()
        a.t.Fatalf("Expected %v, got %v", expected, actual)
    }
}

func (a *AssertionHelper) Contains(collection interface{}, item interface{}, message ...string) {
    // Implementation depends on collection type
    // This is a simplified version
    a.t.Helper()
    // Add actual implementation based on your needs
}

func (a *AssertionHelper) ValidEmail(email string, message ...string) {
    emailPattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
    matched, err := regexp.MatchString(emailPattern, email)
    if err != nil {
        a.t.Helper()
        a.t.Fatalf("Error validating email: %v", err)
    }
    
    if !matched {
        if len(message) > 0 {
            a.t.Helper()
            a.t.Fatalf(message[0])
        }
        a.t.Helper()
        a.t.Fatalf("Invalid email: %s", email)
    }
}

func (a *AssertionHelper) ValidUUID(uuidString string, message ...string) {
    uuidPattern := `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
    matched, err := regexp.MatchString(uuidPattern, uuidString)
    if err != nil {
        a.t.Helper()
        a.t.Fatalf("Error validating UUID: %v", err)
    }
    
    if !matched {
        if len(message) > 0 {
            a.t.Helper()
            a.t.Fatalf(message[0])
        }
        a.t.Helper()
        a.t.Fatalf("Invalid UUID: %s", uuidString)
    }
}

// tests/utils/file_system_helper.go
package utils

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
)

type FileSystemTestHelper struct {
    tempDirs  []string
    tempFiles []string
}

func NewFileSystemTestHelper() *FileSystemTestHelper {
    return &FileSystemTestHelper{
        tempDirs:  make([]string, 0),
        tempFiles: make([]string, 0),
    }
}

func (h *FileSystemTestHelper) CreateTempDirectory() (string, error) {
    tempDir, err := ioutil.TempDir("", "test-")
    if err != nil {
        return "", err
    }
    
    h.tempDirs = append(h.tempDirs, tempDir)
    return tempDir, nil
}

func (h *FileSystemTestHelper) CreateTempFile(content string, suffix string) (string, error) {
    tempFile, err := ioutil.TempFile("", "test-*"+suffix)
    if err != nil {
        return "", err
    }
    
    defer tempFile.Close()
    
    if _, err := tempFile.WriteString(content); err != nil {
        return "", err
    }
    
    h.tempFiles = append(h.tempFiles, tempFile.Name())
    return tempFile.Name(), nil
}

func (h *FileSystemTestHelper) CreateTempJSONFile(data interface{}, suffix string) (string, error) {
    jsonContent, err := json.MarshalIndent(data, "", "  ")
    if err != nil {
        return "", err
    }
    
    return h.CreateTempFile(string(jsonContent), suffix)
}

func (h *FileSystemTestHelper) Cleanup() {
    // Clean up temp files
    for _, tempFile := range h.tempFiles {
        if _, err := os.Stat(tempFile); err == nil {
            os.Remove(tempFile)
        }
    }
    
    // Clean up temp directories
    for _, tempDir := range h.tempDirs {
        if _, err := os.Stat(tempDir); err == nil {
            os.RemoveAll(tempDir)
        }
    }
    
    h.tempFiles = h.tempFiles[:0]
    h.tempDirs = h.tempDirs[:0]
}

// tests/utils/random_generator.go
package utils

import (
    "math/rand"
    "time"
)

type RandomGenerator struct {
    rng *rand.Rand
}

func NewRandomGenerator(seed int64) *RandomGenerator {
    if seed == 0 {
        seed = time.Now().UnixNano()
    }
    
    source := rand.NewSource(seed)
    return &RandomGenerator{
        rng: rand.New(source),
    }
}

func (r *RandomGenerator) String(length int, charset string) string {
    if charset == "" {
        charset = "abcdefghijklmnopqrstuvwxyz"
    }
    
    result := make([]byte, length)
    for i := range result {
        result[i] = charset[r.rng.Intn(len(charset))]
    }
    
    return string(result)
}

func (r *RandomGenerator) Int(min, max int) int {
    return r.rng.Intn(max-min+1) + min
}

func (r *RandomGenerator) Float(min, max float64) float64 {
    return r.rng.Float64()*(max-min) + min
}

func (r *RandomGenerator) Boolean() bool {
    return r.rng.Intn(2) == 1
}

func (r *RandomGenerator) Choice(choices []string) string {
    return choices[r.rng.Intn(len(choices))]
}

func (r *RandomGenerator) FirstName() string {
    names := []string{"John", "Jane", "Michael", "Sarah", "David", "Emily"}
    return r.Choice(names)
}

func (r *RandomGenerator) LastName() string {
    names := []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia"}
    return r.Choice(names)
}

// Helper functions
func mergeMaps(base, overrides map[string]interface{}) map[string]interface{} {
    result := make(map[string]interface{})
    
    for k, v := range base {
        result[k] = v
    }
    
    for k, v := range overrides {
        result[k] = v
    }
    
    return result
}
```

## Best Practices

### 1. Test Data Management
- Use factories for consistent test data
- Implement builder pattern for complex objects
- Generate realistic but simple test data
- Clean up test data automatically

### 2. Assertion Design
- Create domain-specific assertions
- Provide clear error messages
- Support both positive and negative assertions
- Make assertions composable and reusable

### 3. Mock Management
- Create configurable mock builders
- Support both static and dynamic responses
- Provide verification helpers
- Ensure proper cleanup

### 4. File System Testing
- Use temporary files and directories
- Clean up resources automatically
- Support different file formats
- Handle platform differences

## Adaptation Checklist

- [ ] Implement test data factory for your domain
- [ ] Create assertion helpers for common checks
- [ ] Set up file system test utilities
- [ ] Add HTTP testing helpers
- [ ] Create database test utilities
- [ ] Implement random data generators
- [ ] Set up proper cleanup mechanisms
- [ ] Add time manipulation utilities

## Common Pitfalls

1. **Hardcoded test data** - Use factories and generators
2. **Missing cleanup** - Always clean up temporary resources
3. **Brittle assertions** - Use flexible comparison methods
4. **Shared state** - Keep tests independent
5. **Complex setup** - Keep test utilities simple and focused

---

*Generic Test Utilities Pattern - Adapt to your technology stack*
