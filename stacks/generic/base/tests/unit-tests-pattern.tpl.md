<!--
File: unit-tests-pattern.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# ----------------------------------------------------------------------------- 
# FILE: unit-tests-pattern.tpl.md
# PURPOSE: Generic unit testing design pattern
# USAGE: Adapt this pattern for your specific technology stack
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Unit Testing Pattern

## Overview
Unit testing is essential for verifying individual components and functions work correctly in isolation. This pattern provides a comprehensive approach to unit testing with proper test organization, mocking, and assertion strategies across different technology stacks.

## Core Design Pattern

### 1. Unit Testing Architecture

#### Test Structure
- **Arrange**: Set up test data and dependencies
- **Act**: Execute the function/method being tested
- **Assert**: Verify the results match expectations
- **Cleanup**: Remove test artifacts and reset state

#### Test Categories
- **Happy Path Tests**: Expected behavior with valid inputs
- **Edge Case Tests**: Boundary conditions and special values
- **Error Case Tests**: Invalid inputs and exception handling
- **Integration Lite Tests**: Minimal dependency interactions

#### Core Components
- **Test Runner**: Execute tests and collect results
- **Assertion Library**: Verify expected vs actual results
- **Mocking Framework**: Create test doubles for dependencies
- **Test Data Factory**: Generate consistent test data
- **Test Utilities**: Helper functions for common test operations
- **Coverage Reporter**: Track code coverage metrics

### 2. Pseudocode Implementation

```pseudocode
// Base Test Class
class BaseTest:
    function setup():
        # Run before each test
        self.test_data = TestDataFactory()
        self.mocks = MockRegistry()
        self.logger = TestLogger()
    
    function teardown():
        # Run after each test
        self.mocks.reset_all()
        self.test_data.cleanup()
    
    function setup_class():
        # Run once before all tests in class
        pass
    
    function teardown_class():
        # Run once after all tests in class
        pass

// Test Data Factory
class TestDataFactory:
    function create_user(overrides=None):
        default_data = {
            "id": generate_uuid(),
            "username": "testuser_" + random_string(8),
            "email": "test_" + random_string(8) + "@example.com",
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User",
            "roles": ["user"],
            "created_at": current_time(),
            "is_active": true
        }
        
        return merge(default_data, overrides or {})
    
    function create_product(overrides=None):
        default_data = {
            "id": generate_uuid(),
            "name": "Test Product",
            "description": "A test product",
            "price": 99.99,
            "category": "electronics",
            "in_stock": true,
            "created_at": current_time()
        }
        
        return merge(default_data, overrides or {})
    
    function create_order(overrides=None):
        default_data = {
            "id": generate_uuid(),
            "user_id": generate_uuid(),
            "items": [],
            "total": 0.0,
            "status": "pending",
            "created_at": current_time()
        }
        
        return merge(default_data, overrides or {})

// Mock Registry
class MockRegistry:
    function __init__():
        self.mocks = {}
    
    function create_mock(service_name):
        mock = Mock(service_name)
        self.mocks[service_name] = mock
        return mock
    
    function get_mock(service_name):
        return self.mocks.get(service_name)
    
    function reset_all():
        for mock in self.mocks.values():
            mock.reset()
    
    function verify_all():
        for mock in self.mocks.values():
            mock.verify()

// Assertion Helpers
class AssertHelper:
    function assert_equal(actual, expected, message=None):
        if actual != expected:
            raise AssertionError(message or f"Expected {expected}, got {actual}")
    
    function assert_not_equal(actual, expected, message=None):
        if actual == expected:
            raise AssertionError(message or f"Expected not {expected}, got {actual}")
    
    function assert_true(value, message=None):
        if not value:
            raise AssertionError(message or f"Expected true, got {value}")
    
    function assert_false(value, message=None):
        if value:
            raise AssertionError(message or f"Expected false, got {value}")
    
    function assert_none(value, message=None):
        if value is not None:
            raise AssertionError(message or f"Expected None, got {value}")
    
    function assert_not_none(value, message=None):
        if value is None:
            raise AssertionError(message or f"Expected not None, got {value}")
    
    function assert_contains(collection, item, message=None):
        if item not in collection:
            raise AssertionError(message or f"Expected {item} in {collection}")
    
    function assert_not_contains(collection, item, message=None):
        if item in collection:
            raise AssertionError(message or f"Expected {item} not in {collection}")
    
    function assert_raises(exception_class, function, *args, **kwargs):
        try:
            function(*args, **kwargs)
            raise AssertionError(f"Expected {exception_class.__name__} to be raised")
        except exception_class:
            pass  # Expected exception
        except Exception as e:
            raise AssertionError(f"Expected {exception_class.__name__}, got {type(e).__name__}")

// Test Utilities
class TestUtils:
    function create_temp_file(content=""):
        temp_file = create_temp_file()
        temp_file.write(content)
        temp_file.close()
        return temp_file.path
    
    function create_temp_directory():
        return create_temp_directory()
    
    function capture_stdout(function, *args, **kwargs):
        # Capture standard output from function call
        with capture_output() as captured:
            function(*args, **kwargs)
        return captured.output
    
    function measure_time(function, *args, **kwargs):
        start_time = current_time_milliseconds()
        result = function(*args, **kwargs)
        end_time = current_time_milliseconds()
        return result, end_time - start_time
    
    function generate_test_data(count, factory_method, **overrides):
        return [factory_method(**overrides) for _ in range(count)]

// Example Test Class
class UserServiceTest(BaseTest):
    function setup():
        super().setup()
        self.mock_db = self.mocks.create_mock("database")
        self.mock_email = self.mocks.create_mock("email_service")
        self.user_service = UserService(self.mock_db, self.mock_email)
    
    function test_create_user_success():
        # Arrange
        user_data = self.test_data.create_user()
        expected_user = merge(user_data, {"id": generate_uuid()})
        
        self.mock_db.save.expect_call(user_data).return_value(expected_user)
        self.mock_email.send_welcome_email.expect_call(user_data.email).return_value(True)
        
        # Act
        result = self.user_service.create_user(user_data)
        
        # Assert
        self.assert_equal(result.username, user_data.username)
        self.assert_equal(result.email, user_data.email)
        self.assert_not_none(result.id)
        self.assert_true(result.is_active)
        
        # Verify mocks
        self.mocks.verify_all()
    
    function test_create_user_duplicate_email():
        # Arrange
        user_data = self.test_data.create_user()
        self.mock_db.save.expect_call(user_data).raise_error(DuplicateError("Email already exists"))
        
        # Act & Assert
        self.assert_raises(DuplicateError, self.user_service.create_user, user_data)
        
        # Verify email was not sent
        self.mock_email.send_welcome_email.expect_never_called()
    
    function test_create_user_invalid_email():
        # Arrange
        invalid_data = self.test_data.create_user({"email": "invalid-email"})
        
        # Act & Assert
        self.assert_raises(ValidationError, self.user_service.create_user, invalid_data)
        
        # Verify database was not called
        self.mock_db.save.expect_never_called()
    
    function test_get_user_by_id_found():
        # Arrange
        user_id = generate_uuid()
        expected_user = self.test_data.create_user({"id": user_id})
        self.mock_db.find_by_id.expect_call(user_id).return_value(expected_user)
        
        # Act
        result = self.user_service.get_user_by_id(user_id)
        
        # Assert
        self.assert_equal(result.id, user_id)
        self.assert_equal(result.username, expected_user.username)
    
    function test_get_user_by_id_not_found():
        # Arrange
        user_id = generate_uuid()
        self.mock_db.find_by_id.expect_call(user_id).return_value(None)
        
        # Act
        result = self.user_service.get_user_by_id(user_id)
        
        # Assert
        self.assert_none(result)
    
    function test_update_user_success():
        # Arrange
        user_id = generate_uuid()
        existing_user = self.test_data.create_user({"id": user_id})
        update_data = {"first_name": "Updated", "last_name": "Name"}
        expected_user = merge(existing_user, update_data)
        
        self.mock_db.find_by_id.expect_call(user_id).return_value(existing_user)
        self.mock_db.update.expect_call(user_id, update_data).return_value(expected_user)
        
        # Act
        result = self.user_service.update_user(user_id, update_data)
        
        # Assert
        self.assert_equal(result.first_name, "Updated")
        self.assert_equal(result.last_name, "Name")
        self.assert_equal(result.id, user_id)
    
    function test_delete_user_success():
        # Arrange
        user_id = generate_uuid()
        self.mock_db.delete.expect_call(user_id).return_value(True)
        
        # Act
        result = self.user_service.delete_user(user_id)
        
        # Assert
        self.assert_true(result)

// Test Configuration
class TestConfig:
    function __init__():
        self.test_database_url = "sqlite:///:memory:"
        self.test_redis_url = "redis://localhost:6379/1"
        self.log_level = "DEBUG"
        self.timeout = 30
        self.retry_attempts = 3
    
    function get_test_config():
        return {
            "database": {"url": self.test_database_url},
            "redis": {"url": self.test_redis_url},
            "logging": {"level": self.log_level},
            "timeouts": {"default": self.timeout},
            "retries": {"attempts": self.retry_attempts}
        }

// Test Runner
class TestRunner:
    function __init__(config=None):
        self.config = config or TestConfig()
        self.discoverer = TestDiscoverer()
        self.reporter = TestReporter()
        self.coverage = CoverageReporter()
    
    function run_tests(test_path="tests/"):
        # Discover tests
        test_suites = self.discoverer.discover(test_path)
        
        # Start coverage
        self.coverage.start()
        
        # Run tests
        results = []
        for suite in test_suites:
            result = self.run_suite(suite)
            results.append(result)
        
        # Generate coverage report
        coverage_report = self.coverage.generate_report()
        
        # Generate final report
        final_report = self.reporter.generate_report(results, coverage_report)
        
        return final_report
    
    function run_suite(test_suite):
        suite_results = []
        
        for test_class in test_suite.classes:
            class_result = self.run_test_class(test_class)
            suite_results.append(class_result)
        
        return TestSuiteResult(test_suite.name, suite_results)
    
    function run_test_class(test_class):
        test_instance = test_class()
        
        # Run setup_class
        test_instance.setup_class()
        
        class_results = []
        test_methods = [method for method in dir(test_instance) if method.startswith("test_")]
        
        for test_method in test_methods:
            try:
                # Run setup
                test_instance.setup()
                
                # Run test
                getattr(test_instance, test_method)()
                
                # Record success
                class_results.append(TestResult(test_method, "PASSED"))
                
            except Exception as e:
                # Record failure
                class_results.append(TestResult(test_method, "FAILED", str(e)))
            
            finally:
                # Run teardown
                try:
                    test_instance.teardown()
                except Exception as teardown_error:
                    print(f"Teardown error in {test_method}: {teardown_error}")
        
        # Run teardown_class
        test_instance.teardown_class()
        
        return TestClassResult(test_class.__name__, class_results)
```

## Technology-Specific Implementations

### Python (pytest)

```python
# tests/conftest.py
import pytest
from typing import Dict, Any
from unittest.mock import Mock, MagicMock
import tempfile
import os

@pytest.fixture
def test_data_factory():
    """Factory for creating test data"""
    class TestDataFactory:
        @staticmethod
        def create_user(overrides: Dict[str, Any] = None) -> Dict[str, Any]:
            default_data = {
                "id": "test-user-123",
                "username": "testuser",
                "email": "test@example.com",
                "password": "TestPassword123!",
                "first_name": "Test",
                "last_name": "User",
                "roles": ["user"],
                "is_active": True
            }
            return {**default_data, **(overrides or {})}
        
        @staticmethod
        def create_product(overrides: Dict[str, Any] = None) -> Dict[str, Any]:
            default_data = {
                "id": "test-product-123",
                "name": "Test Product",
                "price": 99.99,
                "category": "electronics"
            }
            return {**default_data, **(overrides or {})}
    
    return TestDataFactory()

@pytest.fixture
def mock_database():
    """Mock database fixture"""
    return Mock()

@pytest.fixture
def mock_email_service():
    """Mock email service fixture"""
    return Mock()

@pytest.fixture
def temp_file():
    """Temporary file fixture"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("test content")
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)

# tests/test_user_service.py
import pytest
from unittest.mock import patch, Mock
from user_service import UserService, DuplicateError, ValidationError

class TestUserService:
    @pytest.fixture
    def user_service(self, mock_database, mock_email_service):
        return UserService(mock_database, mock_email_service)
    
    def test_create_user_success(self, user_service, test_data_factory, mock_database, mock_email_service):
        # Arrange
        user_data = test_data_factory.create_user()
        expected_user = {**user_data, "id": "generated-id-123"}
        
        mock_database.save.return_value = expected_user
        mock_email_service.send_welcome_email.return_value = True
        
        # Act
        result = user_service.create_user(user_data)
        
        # Assert
        assert result["username"] == user_data["username"]
        assert result["email"] == user_data["email"]
        assert result["id"] == "generated-id-123"
        assert result["is_active"] is True
        
        # Verify mocks
        mock_database.save.assert_called_once_with(user_data)
        mock_email_service.send_welcome_email.assert_called_once_with(user_data["email"])
    
    def test_create_user_duplicate_email(self, user_service, test_data_factory, mock_database, mock_email_service):
        # Arrange
        user_data = test_data_factory.create_user()
        mock_database.save.side_effect = DuplicateError("Email already exists")
        
        # Act & Assert
        with pytest.raises(DuplicateError):
            user_service.create_user(user_data)
        
        # Verify email was not sent
        mock_email_service.send_welcome_email.assert_not_called()
    
    def test_create_user_invalid_email(self, user_service, test_data_factory, mock_database):
        # Arrange
        invalid_data = test_data_factory.create_user({"email": "invalid-email"})
        
        # Act & Assert
        with pytest.raises(ValidationError):
            user_service.create_user(invalid_data)
        
        # Verify database was not called
        mock_database.save.assert_not_called()
    
    @pytest.mark.parametrize("user_id,should_find", [
        ("valid-user-123", True),
        ("invalid-user-456", False)
    ])
    def test_get_user_by_id(self, user_service, mock_database, user_id, should_find):
        # Arrange
        if should_find:
            expected_user = {"id": user_id, "username": "testuser"}
            mock_database.find_by_id.return_value = expected_user
        else:
            mock_database.find_by_id.return_value = None
        
        # Act
        result = user_service.get_user_by_id(user_id)
        
        # Assert
        if should_find:
            assert result is not None
            assert result["id"] == user_id
        else:
            assert result is None
        
        mock_database.find_by_id.assert_called_once_with(user_id)

# tests/test_utils.py
import pytest
from utils import validate_email, hash_password

class TestUtils:
    @pytest.mark.parametrize("email,expected", [
        ("test@example.com", True),
        ("invalid-email", False),
        ("", False),
        ("test@domain", False)
    ])
    def test_validate_email(self, email, expected):
        assert validate_email(email) == expected
    
    def test_hash_password(self):
        password = "testpassword123"
        hashed = hash_password(password)
        
        assert hashed != password
        assert len(hashed) > 50  # bcrypt hashes are long
        assert hashed.startswith("$2b$")  # bcrypt prefix
```

### Node.js (Jest)

```javascript
// tests/setup.js
const { MockFactory } = require('./utils/mock-factory');

// Global test setup
beforeEach(() => {
  // Reset all mocks before each test
  jest.clearAllMocks();
});

// Global test data factory
global.testDataFactory = {
  createUser: (overrides = {}) => ({
    id: 'test-user-123',
    username: 'testuser',
    email: 'test@example.com',
    password: 'TestPassword123!',
    firstName: 'Test',
    lastName: 'User',
    roles: ['user'],
    isActive: true,
    createdAt: new Date(),
    ...overrides
  }),
  
  createProduct: (overrides = {}) => ({
    id: 'test-product-123',
    name: 'Test Product',
    price: 99.99,
    category: 'electronics',
    inStock: true,
    createdAt: new Date(),
    ...overrides
  })
};

// Mock utilities
global.createMockService = () => ({
  save: jest.fn(),
  findById: jest.fn(),
  update: jest.fn(),
  delete: jest.fn()
});

// tests/userService.test.js
const UserService = require('../src/services/UserService');
const { DuplicateError, ValidationError } = require('../src/utils/errors');

describe('UserService', () => {
  let userService;
  let mockDatabase;
  let mockEmailService;
  
  beforeEach(() => {
    mockDatabase = createMockService();
    mockEmailService = {
      sendWelcomeEmail: jest.fn()
    };
    
    userService = new UserService(mockDatabase, mockEmailService);
  });
  
  describe('createUser', () => {
    test('should create user successfully', async () => {
      // Arrange
      const userData = testDataFactory.createUser();
      const expectedUser = { ...userData, id: 'generated-id-123' };
      
      mockDatabase.save.mockResolvedValue(expectedUser);
      mockEmailService.sendWelcomeEmail.mockResolvedValue(true);
      
      // Act
      const result = await userService.createUser(userData);
      
      // Assert
      expect(result.username).toBe(userData.username);
      expect(result.email).toBe(userData.email);
      expect(result.id).toBe('generated-id-123');
      expect(result.isActive).toBe(true);
      
      // Verify mocks
      expect(mockDatabase.save).toHaveBeenCalledWith(userData);
      expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(userData.email);
    });
    
    test('should throw DuplicateError for duplicate email', async () => {
      // Arrange
      const userData = testDataFactory.createUser();
      mockDatabase.save.mockRejectedValue(new DuplicateError('Email already exists'));
      
      // Act & Assert
      await expect(userService.createUser(userData))
        .rejects.toThrow(DuplicateError);
      
      // Verify email was not sent
      expect(mockEmailService.sendWelcomeEmail).not.toHaveBeenCalled();
    });
    
    test('should throw ValidationError for invalid email', async () => {
      // Arrange
      const invalidData = testDataFactory.createUser({ email: 'invalid-email' });
      
      // Act & Assert
      await expect(userService.createUser(invalidData))
        .rejects.toThrow(ValidationError);
      
      // Verify database was not called
      expect(mockDatabase.save).not.toHaveBeenCalled();
    });
  });
  
  describe('getUserById', () => {
    test('should return user when found', async () => {
      // Arrange
      const userId = 'test-user-123';
      const expectedUser = testDataFactory.createUser({ id: userId });
      mockDatabase.findById.mockResolvedValue(expectedUser);
      
      // Act
      const result = await userService.getUserById(userId);
      
      // Assert
      expect(result).not.toBeNull();
      expect(result.id).toBe(userId);
      expect(result.username).toBe(expectedUser.username);
      
      expect(mockDatabase.findById).toHaveBeenCalledWith(userId);
    });
    
    test('should return null when user not found', async () => {
      // Arrange
      const userId = 'nonexistent-user';
      mockDatabase.findById.mockResolvedValue(null);
      
      // Act
      const result = await userService.getUserById(userId);
      
      // Assert
      expect(result).toBeNull();
      expect(mockDatabase.findById).toHaveBeenCalledWith(userId);
    });
  });
  
  describe.each([
    ['valid-user-123', true],
    ['invalid-user-456', false]
  ])('getUserById with param %s', (userId, shouldFind) => {
    test(`should ${shouldFind ? 'return user' : 'return null'}`, async () => {
      // Arrange
      if (shouldFind) {
        const expectedUser = testDataFactory.createUser({ id: userId });
        mockDatabase.findById.mockResolvedValue(expectedUser);
      } else {
        mockDatabase.findById.mockResolvedValue(null);
      }
      
      // Act
      const result = await userService.getUserById(userId);
      
      // Assert
      if (shouldFind) {
        expect(result).not.toBeNull();
        expect(result.id).toBe(userId);
      } else {
        expect(result).toBeNull();
      }
    });
  });
});

// tests/utils.test.js
const { validateEmail, hashPassword } = require('../src/utils/validation');

describe('Validation Utils', () => {
  describe('validateEmail', () => {
    test.each([
      ['test@example.com', true],
      ['user.name@domain.co.uk', true],
      ['invalid-email', false],
      ['', false],
      ['test@domain', false],
      ['@domain.com', false]
    ])('should validate email %s as %s', (email, expected) => {
      expect(validateEmail(email)).toBe(expected);
    });
  });
  
  describe('hashPassword', () => {
    test('should hash password correctly', () => {
      const password = 'testpassword123';
      const hashed = hashPassword(password);
      
      expect(hashed).not.toBe(password);
      expect(hashed.length).toBeGreaterThan(50);
      expect(hashed).toMatch(/^\$2[aby]\$\d+\$/); // bcrypt pattern
    });
    
    test('should generate different hashes for same password', () => {
      const password = 'testpassword123';
      const hash1 = hashPassword(password);
      const hash2 = hashPassword(password);
      
      expect(hash1).not.toBe(hash2);
    });
  });
});
```

### Go

```go
// tests/utils_test.go
package tests

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/stretchr/testify/require"
    "uuid"
    "time"
)

// TestDataFactory provides test data creation utilities
type TestDataFactory struct{}

func (f *TestDataFactory) CreateUser(overrides map[string]interface{}) map[string]interface{} {
    defaultData := map[string]interface{}{
        "id":        uuid.New().String(),
        "username":  "testuser",
        "email":     "test@example.com",
        "password":  "TestPassword123!",
        "firstName": "Test",
        "lastName":  "User",
        "roles":     []string{"user"},
        "isActive":  true,
        "createdAt": time.Now(),
    }
    
    return mergeMaps(defaultData, overrides)
}

func (f *TestDataFactory) CreateProduct(overrides map[string]interface{}) map[string]interface{} {
    defaultData := map[string]interface{}{
        "id":        uuid.New().String(),
        "name":      "Test Product",
        "price":     99.99,
        "category":  "electronics",
        "inStock":   true,
        "createdAt": time.Now(),
    }
    
    return mergeMaps(defaultData, overrides)
}

// MockDatabase is a mock for database operations
type MockDatabase struct {
    mock.Mock
}

func (m *MockDatabase) Save(user map[string]interface{}) (map[string]interface{}, error) {
    args := m.Called(user)
    return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockDatabase) FindByID(id string) (map[string]interface{}, error) {
    args := m.Called(id)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockDatabase) Update(id string, updates map[string]interface{}) (map[string]interface{}, error) {
    args := m.Called(id, updates)
    return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockDatabase) Delete(id string) error {
    args := m.Called(id)
    return args.Error(0)
}

// MockEmailService is a mock for email operations
type MockEmailService struct {
    mock.Mock
}

func (m *MockEmailService) SendWelcomeEmail(email string) error {
    args := m.Called(email)
    return args.Error(0)
}

// TestUserService tests the UserService
func TestUserService_CreateUser_Success(t *testing.T) {
    // Arrange
    factory := &TestDataFactory{}
    userData := factory.CreateUser(nil)
    
    mockDB := new(MockDatabase)
    mockEmail := new(MockEmailService)
    
    expectedUser := factory.CreateUser(map[string]interface{}{
        "id": "generated-id-123",
    })
    
    mockDB.On("Save", userData).Return(expectedUser, nil)
    mockEmail.On("SendWelcomeEmail", userData["email"]).Return(nil)
    
    userService := NewUserService(mockDB, mockEmail)
    
    // Act
    result, err := userService.CreateUser(userData)
    
    // Assert
    require.NoError(t, err)
    assert.Equal(t, expectedUser["username"], result["username"])
    assert.Equal(t, expectedUser["email"], result["email"])
    assert.Equal(t, expectedUser["id"], result["id"])
    assert.True(t, result["isActive"].(bool))
    
    // Verify mocks
    mockDB.AssertExpectations(t)
    mockEmail.AssertExpectations(t)
}

func TestUserService_CreateUser_DuplicateEmail(t *testing.T) {
    // Arrange
    factory := &TestDataFactory{}
    userData := factory.CreateUser(nil)
    
    mockDB := new(MockDatabase)
    mockEmail := new(MockEmailService)
    
    mockDB.On("Save", userData).Return(nil, DuplicateError{})
    
    userService := NewUserService(mockDB, mockEmail)
    
    // Act
    result, err := userService.CreateUser(userData)
    
    // Assert
    assert.Error(t, err)
    assert.Nil(t, result)
    assert.IsType(t, DuplicateError{}, err)
    
    // Verify email was not sent
    mockEmail.AssertNotCalled(t, "SendWelcomeEmail")
}

func TestUserService_CreateUser_InvalidEmail(t *testing.T) {
    // Arrange
    factory := &TestDataFactory{}
    invalidData := factory.CreateUser(map[string]interface{}{
        "email": "invalid-email",
    })
    
    mockDB := new(MockDatabase)
    mockEmail := new(MockEmailService)
    
    userService := NewUserService(mockDB, mockEmail)
    
    // Act
    result, err := userService.CreateUser(invalidData)
    
    // Assert
    assert.Error(t, err)
    assert.Nil(t, result)
    assert.IsType(t, ValidationError{}, err)
    
    // Verify database was not called
    mockDB.AssertNotCalled(t, "Save")
}

func TestUserService_GetUserByID_Found(t *testing.T) {
    // Arrange
    userID := "test-user-123"
    factory := &TestDataFactory{}
    expectedUser := factory.CreateUser(map[string]interface{}{
        "id": userID,
    })
    
    mockDB := new(MockDatabase)
    mockEmail := new(MockEmailService)
    
    mockDB.On("FindByID", userID).Return(expectedUser, nil)
    
    userService := NewUserService(mockDB, mockEmail)
    
    // Act
    result, err := userService.GetUserByID(userID)
    
    // Assert
    require.NoError(t, err)
    assert.Equal(t, userID, result["id"])
    assert.Equal(t, expectedUser["username"], result["username"])
    
    mockDB.AssertExpectations(t)
}

func TestUserService_GetUserByID_NotFound(t *testing.T) {
    // Arrange
    userID := "nonexistent-user"
    
    mockDB := new(MockDatabase)
    mockEmail := new(MockEmailService)
    
    mockDB.On("FindByID", userID).Return(nil, nil)
    
    userService := NewUserService(mockDB, mockEmail)
    
    // Act
    result, err := userService.GetUserByID(userID)
    
    // Assert
    require.NoError(t, err)
    assert.Nil(t, result)
    
    mockDB.AssertExpectations(t)
}

// Table-driven tests
func TestUserService_GetUserByID_TableDriven(t *testing.T) {
    factory := &TestDataFactory{}
    
    tests := []struct {
        name          string
        userID        string
        setupMock     func(*MockDatabase)
        expectedResult map[string]interface{}
        expectError   bool
    }{
        {
            name:   "user found",
            userID: "valid-user-123",
            setupMock: func(m *MockDatabase) {
                user := factory.CreateUser(map[string]interface{}{
                    "id": "valid-user-123",
                })
                m.On("FindByID", "valid-user-123").Return(user, nil)
            },
            expectedResult: factory.CreateUser(map[string]interface{}{
                "id": "valid-user-123",
            }),
            expectError: false,
        },
        {
            name:   "user not found",
            userID: "invalid-user-456",
            setupMock: func(m *MockDatabase) {
                m.On("FindByID", "invalid-user-456").Return(nil, nil)
            },
            expectedResult: nil,
            expectError:   false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Arrange
            mockDB := new(MockDatabase)
            mockEmail := new(MockEmailService)
            
            tt.setupMock(mockDB)
            
            userService := NewUserService(mockDB, mockEmail)
            
            // Act
            result, err := userService.GetUserByID(tt.userID)
            
            // Assert
            if tt.expectError {
                assert.Error(t, err)
            } else {
                require.NoError(t, err)
                if tt.expectedResult == nil {
                    assert.Nil(t, result)
                } else {
                    assert.Equal(t, tt.expectedResult["id"], result["id"])
                }
            }
            
            mockDB.AssertExpectations(t)
        })
    }
}

// Helper functions
func mergeMaps(default, overrides map[string]interface{}) map[string]interface{} {
    result := make(map[string]interface{})
    for k, v := range default {
        result[k] = v
    }
    for k, v := range overrides {
        result[k] = v
    }
    return result
}
```

## Best Practices

### 1. Test Organization
- Group related tests in test classes/suites
- Use descriptive test names that explain what is being tested
- Follow Arrange-Act-Assert pattern consistently
- Keep tests small and focused on single behaviors

### 2. Test Data Management
- Use factory methods for creating test data
- Avoid hardcoding test values in multiple places
- Use realistic but simple test data
- Clean up test data after each test

### 3. Mocking and Stubbing
- Mock external dependencies, not internal logic
- Verify mock interactions but don't over-specify
- Use real objects when possible, mocks when necessary
- Reset mocks between tests to avoid interference

### 4. Assertion Strategies
- Use specific assertions that check exact values
- Test both positive and negative cases
- Include edge cases and boundary conditions
- Assert on behavior, not implementation details

## Adaptation Checklist

- [ ] Choose testing framework for your technology stack
- [ ] Set up test data factory for consistent test data
- [ ] Create base test class with common utilities
- [ ] Implement mocking framework integration
- [ ] Add assertion helpers for common checks
- [ ] Set up test configuration and environment
- [ ] Configure test coverage reporting
- [ ] Create test utilities for file/database operations

## Common Pitfalls

1. **Testing implementation details** - Focus on behavior, not internal structure
2. **Over-mocking** - Only mock external dependencies
3. **Test dependency** - Tests should run independently in any order
4. **Missing edge cases** - Test boundaries and error conditions
5. **Slow tests** - Keep unit tests fast and focused

---

*Generic Unit Testing Pattern - Adapt to your technology stack*
