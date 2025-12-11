<!--
File: core-next-testing-examples.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Core Tier Testing Examples
# Purpose: Concrete examples of Core-level testing patterns
# Tier: Core (Production Ready)
# Coverage Target: 85%

## Overview

Core tier builds on MVP by adding comprehensive testing patterns for production environments. Includes integration tests, feature tests, mocking, and more sophisticated validation while maintaining focus on reliability and maintainability.

## Go Core Testing Examples

### Integration Test Structure
```go
// test/integration/user_integration_test.go
//go:build integration
// +build integration

package integration

import (
    "testing"
    "net/http/httptest"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/suite"
    "github.com/yourapp/internal/database"
    "github.com/yourapp/internal/server"
)

type UserIntegrationSuite struct {
    suite.Suite
    db     *database.DB
    server *httptest.Server
    client *http.Client
}

func (s *UserIntegrationSuite) SetupSuite() {
    // Setup test database
    s.db = database.NewTestDB()
    require.NoError(s.T(), s.db.Migrate())
    
    // Setup test server
    s.server = httptest.NewServer(server.NewRouter(s.db))
    s.client = s.server.Client()
}

func (s *UserIntegrationSuite) TearDownSuite() {
    s.server.Close()
    s.db.Close()
}

func (s *UserIntegrationSuite) SetupTest() {
    // Clean database before each test
    s.db.TruncateAll()
}

func (s *UserIntegrationSuite) TestUserCreationFlow() {
    // Test complete user creation flow through API
    payload := map[string]interface{}{
        "name":  "John Doe",
        "email": "john@example.com",
    }
    
    resp, err := s.client.Post(
        s.server.URL+"/api/users",
        "application/json",
        bytes.NewBuffer(json.Marshal(payload)),
    )
    require.NoError(s.T(), err)
    defer resp.Body.Close()
    
    assert.Equal(s.T(), http.StatusCreated, resp.StatusCode)
    
    var user map[string]interface{}
    err = json.NewDecoder(resp.Body).Decode(&user)
    require.NoError(s.T(), err)
    
    assert.NotEmpty(s.T(), user["id"])
    assert.Equal(s.T(), payload["name"], user["name"])
    assert.Equal(s.T(), payload["email"], user["email"])
}

func TestUserIntegrationSuite(t *testing.T) {
    suite.Run(t, new(UserIntegrationSuite))
}
```

### Mock-based Unit Test
```go
// test/user_service_test.go
package user

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/stretchr/testify/require"
)

// Mock repository
type MockUserRepository struct {
    mock.Mock
}

func (m *MockUserRepository) Create(user *User) error {
    args := m.Called(user)
    return args.Error(0)
}

func (m *MockUserRepository) GetByID(id string) (*User, error) {
    args := m.Called(id)
    return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(email string) (*User, error) {
    args := m.Called(email)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*User), args.Error(1)
}

func TestUserService_CreateUser_EmailAlreadyExists(t *testing.T) {
    // Arrange
    mockRepo := new(MockUserRepository)
    userService := NewUserService(mockRepo)
    
    existingUser := &User{
        ID:    "123",
        Name:  "Existing User",
        Email: "existing@example.com",
    }
    
    mockRepo.On("GetByEmail", "existing@example.com").Return(existingUser, nil)
    
    input := CreateUserInput{
        Name:  "New User",
        Email: "existing@example.com",
    }
    
    // Act
    user, err := userService.CreateUser(input)
    
    // Assert
    assert.Error(t, err)
    assert.Nil(t, user)
    assert.Contains(t, err.Error(), "email already exists")
    mockRepo.AssertExpectations(t)
}

func TestUserService_CreateUser_Success(t *testing.T) {
    // Arrange
    mockRepo := new(MockUserRepository)
    userService := NewUserService(mockRepo)
    
    input := CreateUserInput{
        Name:  "John Doe",
        Email: "john@example.com",
    }
    
    mockRepo.On("GetByEmail", input.Email).Return(nil, assert.AnError)
    mockRepo.On("Create", mock.AnythingOfType("*user.User")).Return(nil)
    
    // Act
    user, err := userService.CreateUser(input)
    
    // Assert
    require.NoError(t, err)
    assert.NotEmpty(t, user.ID)
    assert.Equal(t, input.Name, user.Name)
    assert.Equal(t, input.Email, user.Email)
    mockRepo.AssertExpectations(t)
}
```

### Feature Test (End-to-End Workflow)
```go
// test/feature/user_registration_feature_test.go
package feature

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/yourapp/test/integration"
)

func TestUserRegistrationFeature(t *testing.T) {
    // Setup integration test environment
    suite := &integration.UserIntegrationSuite{}
    suite.SetupSuite()
    defer suite.TearDownSuite()
    suite.SetupTest()
    
    // Test complete user registration workflow
    t.Run("successful registration", func(t *testing.T) {
        // Step 1: Register user via API
        registerPayload := map[string]interface{}{
            "name":  "Jane Doe",
            "email": "jane@example.com",
            "password": "securePassword123",
        }
        
        resp, err := suite.client.Post(
            suite.server.URL+"/api/auth/register",
            "application/json",
            bytes.NewBuffer(json.Marshal(registerPayload)),
        )
        require.NoError(t, err)
        defer resp.Body.Close()
        
        assert.Equal(t, http.StatusCreated, resp.StatusCode)
        
        // Step 2: Verify user exists in database
        user, err := suite.db.GetUserByEmail("jane@example.com")
        require.NoError(t, err)
        assert.Equal(t, registerPayload["name"], user.Name)
        assert.Equal(t, registerPayload["email"], user.Email)
        
        // Step 3: Login with registered user
        loginPayload := map[string]interface{}{
            "email":    "jane@example.com",
            "password": "securePassword123",
        }
        
        resp, err = suite.client.Post(
            suite.server.URL+"/api/auth/login",
            "application/json",
            bytes.NewBuffer(json.Marshal(loginPayload)),
        )
        require.NoError(t, err)
        defer resp.Body.Close()
        
        assert.Equal(t, http.StatusOK, resp.StatusCode)
        
        var loginResponse map[string]interface{}
        err = json.NewDecoder(resp.Body).Decode(&loginResponse)
        require.NoError(t, err)
        
        assert.NotEmpty(t, loginResponse["token"])
        
        // Step 4: Access protected endpoint with token
        req, _ := http.NewRequest("GET", suite.server.URL+"/api/users/profile", nil)
        req.Header.Set("Authorization", "Bearer "+loginResponse["token"].(string))
        
        resp, err = suite.client.Do(req)
        require.NoError(t, err)
        defer resp.Body.Close()
        
        assert.Equal(t, http.StatusOK, resp.StatusCode)
    })
}
```

## Python Core Testing Examples

### Integration Test with pytest
```python
# tests/integration/test_user_integration.py
import pytest
from fastapi.testclient import TestClient
from yourapp.main import app
from yourapp.database import get_test_db

@pytest.fixture(scope="module")
def test_client():
    """Setup test client with test database"""
    with TestClient(app) as client:
        with get_test_db() as db:
            yield client, db

@pytest.mark.integration
class TestUserIntegration:
    def test_user_creation_flow(self, test_client):
        """Test complete user creation flow through API"""
        client, db = test_client
        
        # Create user via API
        payload = {
            "name": "John Doe",
            "email": "john@example.com",
            "password": "securePassword123"
        }
        
        response = client.post("/api/users", json=payload)
        assert response.status_code == 201
        
        user_data = response.json()
        assert user_data["id"] is not None
        assert user_data["name"] == payload["name"]
        assert user_data["email"] == payload["email"]
        
        # Verify user exists in database
        db_user = db.get_user_by_email(payload["email"])
        assert db_user is not None
        assert db_user.name == payload["name"]
    
    def test_user_validation_flow(self, test_client):
        """Test user validation workflow"""
        client, db = test_client
        
        # Test duplicate email
        payload = {
            "name": "Jane Doe",
            "email": "jane@example.com",
            "password": "securePassword123"
        }
        
        # First user creation should succeed
        response = client.post("/api/users", json=payload)
        assert response.status_code == 201
        
        # Second user with same email should fail
        payload["name"] = "Another User"
        response = client.post("/api/users", json=payload)
        assert response.status_code == 400
        assert "email already exists" in response.json()["detail"]
```

### Mock-based Unit Test
```python
# tests/test_user_service.py
import pytest
from unittest.mock import Mock, patch
from yourapp.user_service import UserService
from yourapp.models import User

class TestUserService:
    def test_create_user_email_already_exists(self):
        """Test user creation with existing email"""
        # Arrange
        mock_repo = Mock()
        user_service = UserService(mock_repo)
        
        existing_user = User(
            id="123",
            name="Existing User",
            email="existing@example.com"
        )
        
        mock_repo.get_by_email.return_value = existing_user
        
        input_data = {
            "name": "New User",
            "email": "existing@example.com"
        }
        
        # Act & Assert
        with pytest.raises(ValueError, match="email already exists"):
            user_service.create_user(input_data)
        
        mock_repo.get_by_email.assert_called_once_with("existing@example.com")
    
    def test_create_user_success(self):
        """Test successful user creation"""
        # Arrange
        mock_repo = Mock()
        user_service = UserService(mock_repo)
        
        input_data = {
            "name": "John Doe",
            "email": "john@example.com"
        }
        
        mock_repo.get_by_email.return_value = None
        mock_repo.create.return_value = User(
            id="new-id",
            name=input_data["name"],
            email=input_data["email"]
        )
        
        # Act
        user = user_service.create_user(input_data)
        
        # Assert
        assert user.id == "new-id"
        assert user.name == input_data["name"]
        assert user.email == input_data["email"]
        
        mock_repo.get_by_email.assert_called_once_with(input_data["email"])
        mock_repo.create.assert_called_once()
```

### Feature Test (End-to-End Workflow)
```python
# tests/feature/test_user_registration_feature.py
import pytest
from fastapi.testclient import TestClient
from yourapp.main import app

@pytest.mark.feature
class TestUserRegistrationFeature:
    def test_complete_registration_workflow(self):
        """Test complete user registration workflow"""
        with TestClient(app) as client:
            # Step 1: Register user
            register_payload = {
                "name": "Jane Doe",
                "email": "jane@example.com",
                "password": "securePassword123"
            }
            
            response = client.post("/api/auth/register", json=register_payload)
            assert response.status_code == 201
            
            # Step 2: Login with registered user
            login_payload = {
                "email": "jane@example.com",
                "password": "securePassword123"
            }
            
            response = client.post("/api/auth/login", json=login_payload)
            assert response.status_code == 200
            
            login_data = response.json()
            assert "access_token" in login_data
            
            # Step 3: Access protected endpoint
            headers = {"Authorization": f"Bearer {login_data['access_token']}"}
            response = client.get("/api/users/profile", headers=headers)
            assert response.status_code == 200
            
            profile_data = response.json()
            assert profile_data["email"] == login_payload["email"]
            assert profile_data["name"] == register_payload["name"]
```

## JavaScript Core Testing Examples

### Integration Test with Jest and Supertest
```javascript
// tests/integration/user.integration.test.js
const request = require('supertest');
const app = require('../../src/app');
const { TestDatabase } = require('../../src/test/database');

describe('User Integration Tests', () => {
    let testDb;
    
    beforeAll(async () => {
        testDb = new TestDatabase();
        await testDb.setup();
        await testDb.migrate();
    });
    
    afterAll(async () => {
        await testDb.cleanup();
    });
    
    beforeEach(async () => {
        await testDb.truncateAll();
    });
    
    describe('User Creation Flow', () => {
        test('should create user successfully via API', async () => {
            const payload = {
                name: 'John Doe',
                email: 'john@example.com',
                password: 'securePassword123'
            };
            
            const response = await request(app)
                .post('/api/users')
                .send(payload)
                .expect(201);
            
            expect(response.body.id).toBeDefined();
            expect(response.body.name).toBe(payload.name);
            expect(response.body.email).toBe(payload.email);
            expect(response.body.password).toBeUndefined(); // Password should not be returned
            
            // Verify user exists in database
            const user = await testDb.getUserByEmail(payload.email);
            expect(user).toBeTruthy();
            expect(user.name).toBe(payload.name);
        });
        
        test('should reject duplicate email', async () => {
            const payload = {
                name: 'Jane Doe',
                email: 'jane@example.com',
                password: 'securePassword123'
            };
            
            // First user creation should succeed
            await request(app)
                .post('/api/users')
                .send(payload)
                .expect(201);
            
            // Second user with same email should fail
            payload.name = 'Another User';
            const response = await request(app)
                .post('/api/users')
                .send(payload)
                .expect(400);
            
            expect(response.body.message).toContain('email already exists');
        });
    });
});
```

### Mock-based Unit Test
```javascript
// tests/user.service.test.js
const { UserService } = require('../src/user.service');
const { UserMockRepository } = require('./mocks/user.repository.mock');

describe('UserService', () => {
    let userService;
    let mockRepository;
    
    beforeEach(() => {
        mockRepository = new UserMockRepository();
        userService = new UserService(mockRepository);
    });
    
    describe('createUser', () => {
        test('should throw error for existing email', async () => {
            // Arrange
            const existingUser = {
                id: '123',
                name: 'Existing User',
                email: 'existing@example.com'
            };
            
            mockRepository.getByEmail.mockResolvedValue(existingUser);
            
            const input = {
                name: 'New User',
                email: 'existing@example.com'
            };
            
            // Act & Assert
            await expect(userService.createUser(input))
                .rejects.toThrow('email already exists');
            
            expect(mockRepository.getByEmail).toHaveBeenCalledWith(input.email);
        });
        
        test('should create user successfully', async () => {
            // Arrange
            const input = {
                name: 'John Doe',
                email: 'john@example.com'
            };
            
            const createdUser = {
                id: 'new-id',
                name: input.name,
                email: input.email
            };
            
            mockRepository.getByEmail.mockResolvedValue(null);
            mockRepository.create.mockResolvedValue(createdUser);
            
            // Act
            const user = await userService.createUser(input);
            
            // Assert
            expect(user.id).toBe(createdUser.id);
            expect(user.name).toBe(input.name);
            expect(user.email).toBe(input.email);
            
            expect(mockRepository.getByEmail).toHaveBeenCalledWith(input.email);
            expect(mockRepository.create).toHaveBeenCalled();
        });
    });
});
```

### Feature Test (End-to-End Workflow)
```javascript
// tests/feature/user.registration.feature.test.js
const request = require('supertest');
const app = require('../../src/app');

describe('User Registration Feature', () => {
    test('should complete full registration workflow', async () => {
        // Step 1: Register user
        const registerPayload = {
            name: 'Jane Doe',
            email: 'jane@example.com',
            password: 'securePassword123'
        };
        
        const registerResponse = await request(app)
            .post('/api/auth/register')
            .send(registerPayload)
            .expect(201);
        
        expect(registerResponse.body.id).toBeDefined();
        
        // Step 2: Login with registered user
        const loginPayload = {
            email: 'jane@example.com',
            password: 'securePassword123'
        };
        
        const loginResponse = await request(app)
            .post('/api/auth/login')
            .send(loginPayload)
            .expect(200);
        
        expect(loginResponse.body.token).toBeDefined();
        
        // Step 3: Access protected endpoint
        const profileResponse = await request(app)
            .get('/api/users/profile')
            .set('Authorization', `Bearer ${loginResponse.body.token}`)
            .expect(200);
        
        expect(profileResponse.body.email).toBe(loginPayload.email);
        expect(profileResponse.body.name).toBe(registerPayload.name);
    });
});
```

## Dart/Flutter Core Testing Examples

### Integration Test with test package
```dart
// test/integration/user_integration_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:your_app/main.dart';
import 'package:your_app/database.dart';
import 'package:your_app/user_service.dart';

void main() {
    group('User Integration Tests', () {
        late Database testDb;
        late UserService userService;
        
        setUpAll(() async {
            testDb = Database.test();
            await testDb.open();
            await testDb.migrate();
            userService = UserService(testDb);
        });
        
        tearDownAll(() async {
            await testDb.close();
        });
        
        setUp(() async {
            await testDb.truncateAll();
        });
        
        test('should create user successfully', () async {
            // Arrange
            final input = CreateUserInput(
                name: 'John Doe',
                email: 'john@example.com',
            );
            
            // Act
            final user = await userService.createUser(input);
            
            // Assert
            expect(user.id, isNotEmpty);
            expect(user.name, equals(input.name));
            expect(user.email, equals(input.email));
            
            // Verify user exists in database
            final dbUser = await testDb.getUserByEmail(input.email);
            expect(dbUser, isNotNull);
            expect(dbUser!.name, equals(input.name));
        });
        
        test('should reject duplicate email', () async {
            // Arrange
            final input = CreateUserInput(
                name: 'Jane Doe',
                email: 'jane@example.com',
            );
            
            // First user creation should succeed
            await userService.createUser(input);
            
            // Act & Assert
            expect(
                () => userService.createUser(input),
                throwsA(contains('email already exists')),
            );
        });
    });
}
```

### Mock-based Unit Test
```dart
// test/user_service_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:your_app/user_service.dart';
import 'package:your_app/user_repository.dart';

import 'user_service_test.mocks.dart';

@GenerateMocks([UserRepository])
void main() {
    group('UserService', () {
        late UserService userService;
        late MockUserRepository mockRepository;
        
        setUp(() {
            mockRepository = MockUserRepository();
            userService = UserService(mockRepository);
        });
        
        test('should throw error for existing email', () async {
            // Arrange
            final existingUser = User(
                id: '123',
                name: 'Existing User',
                email: 'existing@example.com',
            );
            
            when(mockRepository.getByEmail('existing@example.com'))
                .thenAnswer((_) async => existingUser);
            
            final input = CreateUserInput(
                name: 'New User',
                email: 'existing@example.com',
            );
            
            // Act & Assert
            expect(
                () => userService.createUser(input),
                throwsA(contains('email already exists')),
            );
            
            verify(mockRepository.getByEmail(input.email)).called(1);
        });
        
        test('should create user successfully', () async {
            // Arrange
            final input = CreateUserInput(
                name: 'John Doe',
                email: 'john@example.com',
            );
            
            final createdUser = User(
                id: 'new-id',
                name: input.name,
                email: input.email,
            );
            
            when(mockRepository.getByEmail(input.email))
                .thenAnswer((_) async => null);
            when(mockRepository.create(any))
                .thenAnswer((_) async => createdUser);
            
            // Act
            final user = await userService.createUser(input);
            
            // Assert
            expect(user.id, equals(createdUser.id));
            expect(user.name, equals(input.name));
            expect(user.email, equals(input.email));
            
            verify(mockRepository.getByEmail(input.email)).called(1);
            verify(mockRepository.create(any)).called(1);
        });
    });
}
```

### Feature Test (End-to-End Workflow)
```dart
// test/feature/user_registration_feature_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:your_app/app.dart';
import 'package:your_app/auth_service.dart';
import 'package:your_app/user_service.dart';

void main() {
    group('User Registration Feature', () {
        late App app;
        late AuthService authService;
        late UserService userService;
        
        setUpAll(() async {
            app = App.test();
            await app.setup();
            authService = app.authService;
            userService = app.userService;
        });
        
        tearDownAll(() async {
            await app.cleanup();
        });
        
        setUp(() async {
            await app.resetDatabase();
        });
        
        test('should complete full registration workflow', () async {
            // Step 1: Register user
            final registerInput = RegisterInput(
                name: 'Jane Doe',
                email: 'jane@example.com',
                password: 'securePassword123',
            );
            
            final registerResult = await authService.register(registerInput);
            expect(registerResult.success, isTrue);
            expect(registerResult.user?.email, equals(registerInput.email));
            
            // Step 2: Login with registered user
            final loginInput = LoginInput(
                email: 'jane@example.com',
                password: 'securePassword123',
            );
            
            final loginResult = await authService.login(loginInput);
            expect(loginResult.success, isTrue);
            expect(loginResult.token, isNotEmpty);
            
            // Step 3: Access protected endpoint
            final profileResult = await userService.getProfile(loginResult.token);
            expect(profileResult.success, isTrue);
            expect(profileResult.user?.email, equals(loginInput.email));
            expect(profileResult.user?.name, equals(registerInput.name));
        });
    });
}
```

## Core Testing Best Practices

### ✅ DO include:
- **Integration tests** - Database and API integration testing
- **Feature tests** - End-to-end workflow validation
- **Mocking** - Isolate unit tests with proper mocks
- **Test suites** - Organize related tests with setup/teardown
- **Database transactions** - Rollback changes between tests
- **API testing** - Test HTTP endpoints and responses
- **Error scenarios** - Network failures, database errors, validation failures

### ❌ DO NOT include:
- **Enterprise security patterns** - Save for Full tier
- **Compliance testing** - Save for Full tier
- **Penetration testing** - Save for Full tier
- **Heavy observability** - Keep monitoring simple

### 🎯 Coverage Strategy:
- **85% coverage target** - Comprehensive but practical
- **Focus on business logic** - Critical path coverage
- **Include integration points** - Database, external APIs
- **Test error handling** - Failure scenarios and edge cases

## Running Core Tests

### Go
```bash
# Run unit tests
go test ./...

# Run integration tests
go test -tags=integration ./...

# Run with coverage
go test -cover ./...

# Run specific test suite
go test -v ./test/integration/...
```

### Python
```bash
# Run unit tests
pytest

# Run integration tests
pytest -m integration

# Run feature tests
pytest -m feature

# Run with coverage
pytest --cov --cov-report=term-missing
```

### JavaScript
```bash
# Run unit tests
npm test

# Run integration tests
npm test -- --testPathPattern=integration

# Run feature tests
npm test -- --testPathPattern=feature

# Run with coverage
npm test -- --coverage
```

### Dart/Flutter
```bash
# Run unit tests
flutter test

# Run integration tests
flutter test --integration

# Run specific test file
flutter test test/integration/user_integration_test.dart
```

---

**Core Tier Testing Philosophy**: Production-ready testing with comprehensive coverage, integration validation, and feature workflow testing. Focus on reliability and maintainability without enterprise complexity.
