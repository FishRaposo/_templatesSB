# Universal Template System - Generic Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: generic
# Category: testing

# ----------------------------------------------------------------------------- 
# FILE: integration-tests-pattern.tpl.md
# PURPOSE: Generic integration testing design pattern
# USAGE: Adapt this pattern for your specific technology stack
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Integration Testing Pattern

## Overview
Integration testing verifies that multiple components work together correctly. This pattern provides a comprehensive approach to testing component interactions, database operations, external API calls, and end-to-end workflows across different technology stacks.

## Core Design Pattern

### 1. Integration Testing Architecture

#### Test Categories
- **Database Integration**: Test data persistence and retrieval
- **API Integration**: Test external service communication
- **Component Integration**: Test internal component interactions
- **Workflow Integration**: Test complete business processes
- **Message Queue Integration**: Test async message processing

#### Test Environment
- **Test Database**: Isolated database instance for testing
- **Mock Services**: Controlled external service responses
- **Test Containers**: Docker containers for dependencies
- **Environment Configuration**: Test-specific settings
- **Data Cleanup**: Automatic test data cleanup

#### Core Components
- **Test Database Manager**: Handle database setup and cleanup
- **Service Container**: Manage test service instances
- **Mock Server**: Simulate external APIs
- **Test Data Seeder**: Populate test data
- **Assertion Helpers**: Verify integration behavior
- **Environment Manager**: Control test environment

### 2. Pseudocode Implementation

```pseudocode
// Base Integration Test Class
class BaseIntegrationTest:
    function setup():
        # Run before each integration test
        self.setup_test_database()
        self.setup_mock_services()
        self.setup_test_environment()
        self.seed_test_data()
    
    function teardown():
        # Run after each integration test
        self.cleanup_test_data()
        self.reset_mock_services()
        self.cleanup_test_database()
    
    function setup_class():
        # Run once before all integration tests
        self.start_test_containers()
        self.migrate_test_database()
        self.setup_global_mocks()
    
    function teardown_class():
        # Run once after all integration tests
        self.stop_test_containers()
        self.cleanup_global_resources()

// Test Database Manager
class TestDatabaseManager:
    function __init__(database_config):
        self.config = database_config
        self.connection = None
        self.transaction = None
    
    function setup_database():
        # Create test database connection
        self.connection = create_connection(self.config.test_url)
        
        # Start transaction for isolation
        self.transaction = self.connection.begin_transaction()
        
        # Run migrations
        self.run_migrations()
        
        return self.connection
    
    function cleanup_database():
        # Rollback transaction to ensure clean state
        if self.transaction:
            self.transaction.rollback()
        
        # Close connection
        if self.connection:
            self.connection.close()
    
    function seed_data(data_sets):
        # Insert test data for testing
        for data_set in data_sets:
            self.insert_data(data_set)
    
    function cleanup_data():
        # Clean up all test data
        self.truncate_all_tables()
    
    function run_migrations():
        # Run database migrations
        migration_runner = MigrationRunner(self.connection)
        migration_runner.run_pending_migrations()

// Mock Server
class MockServer:
    function __init__(port=8080):
        self.port = port
        self.endpoints = {}
        self.server = None
        self.request_log = []
    
    function start():
        # Start mock HTTP server
        self.server = create_http_server(self.port, self.handle_request)
        self.server.start()
    
    function stop():
        # Stop mock server
        if self.server:
            self.server.stop()
    
    function add_endpoint(method, path, response, status_code=200):
        # Register mock endpoint
        key = f"{method}:{path}"
        self.endpoints[key] = {
            "response": response,
            "status_code": status_code,
            "call_count": 0
        }
    
    function add_endpoint_with_callback(method, path, callback):
        # Register endpoint with dynamic response
        key = f"{method}:{path}"
        self.endpoints[key] = {
            "callback": callback,
            "call_count": 0
        }
    
    function handle_request(request):
        # Log request for verification
        self.request_log.append({
            "method": request.method,
            "path": request.path,
            "headers": request.headers,
            "body": request.body,
            "timestamp": current_time()
        })
        
        # Find matching endpoint
        key = f"{request.method}:{request.path}"
        endpoint = self.endpoints.get(key)
        
        if endpoint:
            endpoint["call_count"] += 1
            
            if "callback" in endpoint:
                # Call registered callback for dynamic responses
                return endpoint["callback"] (request)
            else:
                return create_response(endpoint["response"], endpoint["status_code"])
        else:
            return create_response({"error": "Not found"}, 404)
    
    function get_request_count(method, path):
        # Get call count for specific endpoint
        key = f"{method}:{path}"
        endpoint = self.endpoints.get(key)
        return endpoint["call_count"] if endpoint else 0
    
    function was_called(method, path):
        # Check if endpoint was called
        return self.get_request_count(method, path) > 0
    
    function get_last_request(method, path):
        # Get the last request to specific endpoint
        for request in reversed(self.request_log):
            if request["method"] == method and request["path"] == path:
                return request
        return None

// Test Data Seeder
class TestDataSeeder:
    function __init__(database_manager):
        self.db = database_manager
        self.factories = {}
    
    function register_factory(name, factory):
        # Register a data factory
        self.factories[name] = factory
    
    function seed(data_type, count=1, overrides=None):
        # Seed test data
        factory = self.factories.get(data_type)
        if not factory:
            raise ValueError(f"Unknown data type: {data_type}")
        
        data = []
        for i in range(count):
            item = factory.create(overrides)
            self.db.insert(data_type, item)
            data.append(item)
        
        return data
    
    function seed_users(count=5, overrides=None):
        return self.seed("user", count, overrides)
    
    def seed_products(count=10, overrides=None):
        return self.seed("product", count, overrides)
    
    def seed_orders(count=3, overrides=None):
        return self.seed("order", count, overrides)

// Environment Manager
class TestEnvironmentManager:
    function __init__():
        self.environment_vars = {}
        self.services = {}
        self.containers = {}
    
    function setup_environment():
        # Set up test environment variables
        self.set_environment_variables()
        
        # Start required services
        self.start_services()
        
        # Wait for services to be ready
        self.wait_for_services_ready()
    
    function cleanup_environment():
        # Stop services
        self.stop_services()
        
        # Clean up containers
        self.cleanup_containers()
        
        # Restore environment variables
        self.restore_environment_variables()
    
    function set_environment_variables():
        # Store original values
        self.environment_vars = {
            "DATABASE_URL": get_environment("DATABASE_URL"),
            "REDIS_URL": get_environment("REDIS_URL"),
            "EXTERNAL_API_URL": get_environment("EXTERNAL_API_URL")
        }
        
        # Set test values
        set_environment("DATABASE_URL", "sqlite:///:memory:")
        set_environment("REDIS_URL", "redis://localhost:6379/1")
        set_environment("EXTERNAL_API_URL", "http://localhost:8080")
    
    function start_services():
        # Start Redis
        self.services["redis"] = start_redis_container()
        
        # Start database
        self.services["database"] = start_postgres_container()
        
        # Start mock external API
        self.services["mock_api"] = MockServer(8080)
        self.services["mock_api"].start()
    
    function wait_for_services_ready():
        # Wait for all services to be ready
        for service_name, service in self.services.items():
            self.wait_for_service_ready(service_name, service)
    
    function wait_for_service_ready(service_name, service, timeout=30):
        # Wait for specific service to be ready
        start_time = current_time()
        
        while current_time() - start_time < timeout:
            if service.is_ready():
                return True
            sleep(1)
        
        raise TimeoutError(f"Service {service_name} not ready within {timeout} seconds")

// Integration Test Examples
class UserServiceIntegrationTest(BaseIntegrationTest):
    function setup():
        super().setup()
        self.user_service = UserService(
            database=self.test_db,
            email_service=self.mock_email_service
        )
    
    function test_create_user_with_database():
        # Arrange
        user_data = {
            "username": "integration_user",
            "email": "integration@example.com",
            "password": "IntegrationPass123!"
        }
        
        # Act
        created_user = self.user_service.create_user(user_data)
        
        # Assert - Verify user was saved to database
        saved_user = self.test_db.find_user_by_email(user_data["email"])
        assert saved_user is not None
        assert saved_user["username"] == user_data["username"]
        assert saved_user["email"] == user_data["email"]
        
        # Verify password was hashed
        assert saved_user["password"] != user_data["password"]
        assert saved_user["password"].startswith("$2b$")  # bcrypt prefix
    
    function test_user_authentication_flow():
        # Arrange
        user_data = self.data_seeder.seed_users(1)[0]
        login_data = {
            "email": user_data["email"],
            "password": "original_password"
        }
        
        # Act
        auth_result = self.user_service.authenticate(login_data)
        
        # Assert
        assert auth_result["success"] is True
        assert "token" in auth_result
        assert auth_result["user"]["id"] == user_data["id"]
        
        # Verify token is valid JWT
        token_data = self.user_service.validate_token(auth_result["token"])
        assert token_data["user_id"] == user_data["id"]
    
    function test_user_registration_with_email_service():
        # Arrange
        user_data = {
            "username": "new_user",
            "email": "newuser@example.com",
            "password": "NewUserPass123!"
        }
        
        # Act
        created_user = self.user_service.register_user(user_data)
        
        # Assert
        assert created_user["id"] is not None
        assert created_user["email"] == user_data["email"]
        
        # Verify welcome email was sent
        assert self.mock_email_service.was_called("send_welcome_email", user_data["email"])
        
        # Get the email request details
        email_request = self.mock_email_service.get_last_request("send_welcome_email", user_data["email"])
        assert email_request["to"] == user_data["email"]
        assert "Welcome" in email_request["subject"]

class APIIntegrationTest(BaseIntegrationTest):
    function setup():
        super().setup()
        self.api_client = APIClient(base_url="http://localhost:3000")
        self.mock_external_api = self.services["mock_api"]
        
        # Set up mock external API endpoints
        self.mock_external_api.add_endpoint("GET", "/api/users", [
            {"id": 1, "name": "External User 1"},
            {"id": 2, "name": "External User 2"}
        ])
    
    function test_api_integration_with_external_service():
        # Arrange
        self.mock_external_api.add_endpoint("POST", "/api/webhook", {
            "status": "success",
            "webhook_id": "webhook_123"
        })
        
        webhook_data = {
            "event": "user_created",
            "user_id": "local_user_456"
        }
        
        # Act
        response = self.api_client.post("/webhooks/send", webhook_data)
        
        # Assert
        assert response["status_code"] == 200
        assert response["data"]["status"] == "success"
        
        # Verify external API was called
        assert self.mock_external_api.was_called("POST", "/api/webhook")
        
        # Get the request sent to external API
        external_request = self.mock_external_api.get_last_request("POST", "/api/webhook")
        assert external_request["body"]["event"] == "user_created"
        assert external_request["body"]["user_id"] == "local_user_456"
    
    function test_data_sync_between_services():
        # Arrange
        local_users = self.data_seeder.seed_users(3)
        
        # Act
        sync_result = self.api_client.post("/sync/users", {
            "source": "local",
            "target": "external"
        })
        
        # Assert
        assert sync_result["status_code"] == 200
        assert sync_result["data"]["synced_count"] == 3
        
        # Verify data was sent to external service
        external_requests = self.mock_external_api.get_all_requests("POST", "/api/users")
        assert len(external_requests) == 1
        
        sent_users = external_requests[0]["body"]["users"]
        assert len(sent_users) == 3
        assert all(user["id"] in [u["id"] for u in local_users] for user in sent_users)

class DatabaseIntegrationTest(BaseIntegrationTest):
    function test_transaction_rollback_on_error():
        # Arrange
        user_data = {"username": "test_user", "email": "test@example.com"}
        
        # Act - Simulate operation that fails and should rollback
        try:
            self.test_db.execute_transaction([
                lambda: self.test_db.insert_user(user_data),
                lambda: self.test_db.insert_user({"username": "", "email": "invalid"}),  # This will fail
                lambda: self.test_db.insert_user({"username": "another_user", "email": "another@example.com"})
            ])
        except DatabaseError:
            pass  # Expected to fail
        
        # Assert - Verify transaction was rolled back
        users = self.test_db.get_all_users()
        assert len(users) == 0  # No users should be saved due to rollback
    
    def test_database_constraints():
        # Arrange
        user_data = {"username": "unique_user", "email": "unique@example.com"}
        
        # Act - Insert first user
        self.test_db.insert_user(user_data)
        
        # Try to insert duplicate user
        try:
            self.test_db.insert_user(user_data)
            assert False, "Should have raised constraint violation"
        except ConstraintViolationError:
            pass  # Expected
        
        # Assert - Verify only one user exists
        users = self.test_db.get_all_users()
        assert len(users) == 1
        assert users[0]["username"] == "unique_user"

// Test Configuration
class IntegrationTestConfig:
    function __init__():
        self.database_config = {
            "test_url": "postgresql://test:test@localhost:5432/test_db",
            "pool_size": 5,
            "timeout": 30
        }
        
        self.redis_config = {
            "url": "redis://localhost:6379/1",
            "max_connections": 10
        }
        
        self.external_api_config = {
            "base_url": "http://localhost:8080",
            "timeout": 10,
            "retry_attempts": 3
        }
        
        self.test_containers = {
            "postgres": {
                "image": "postgres:13",
                "port": 5432,
                "environment": {
                    "POSTGRES_DB": "test_db",
                    "POSTGRES_USER": "test",
                    "POSTGRES_PASSWORD": "test"
                }
            },
            "redis": {
                "image": "redis:6",
                "port": 6379
            }
        }
```

## Technology-Specific Implementations

### Python (pytest + testcontainers)

```python
# tests/conftest.py
import pytest
import os
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer
from unittest.mock import Mock
from app import create_app
from app.database import get_db
from app.services.user_service import UserService

@pytest.fixture(scope="session")
def postgres_container():
    """Start PostgreSQL container for testing"""
    with PostgresContainer("postgres:13") as postgres:
        yield postgres

@pytest.fixture(scope="session")
def redis_container():
    """Start Redis container for testing"""
    with RedisContainer("redis:6") as redis:
        yield redis

@pytest.fixture(scope="session")
def test_database(postgres_container):
    """Create test database session"""
    connection_url = postgres_container.get_connection_url()
    
    # Override database URL for tests
    os.environ["DATABASE_URL"] = connection_url
    
    # Create tables
    from app.database import create_tables
    create_tables(connection_url)
    
    yield connection_url
    
    # Cleanup
    os.environ.pop("DATABASE_URL", None)

@pytest.fixture
def test_app(test_database):
    """Create test application instance"""
    app = create_app(testing=True)
    
    with app.app_context():
        yield app

@pytest.fixture
def test_client(test_app):
    """Create test client"""
    return test_app.test_client()

@pytest.fixture
def test_db_session(test_app):
    """Create database session for testing"""
    from app.database import get_db_session
    
    session = get_db_session()
    try:
        yield session
    finally:
        session.rollback()
        session.close()

@pytest.fixture
def mock_email_service():
    """Mock email service for testing"""
    return Mock()

@pytest.fixture
def user_service(test_db_session, mock_email_service):
    """Create user service with test dependencies"""
    return UserService(test_db_session, mock_email_service)

@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "TestPassword123!",
        "first_name": "Test",
        "last_name": "User"
    }

# tests/integration/test_user_service_integration.py
import pytest
from app.services.user_service import UserService
from app.models.user import User

class TestUserServiceIntegration:
    def test_create_user_persists_to_database(self, user_service, sample_user_data, test_db_session):
        # Arrange
        user_data = sample_user_data.copy()
        
        # Act
        created_user = user_service.create_user(user_data)
        
        # Assert - Verify user was saved to database
        saved_user = test_db_session.query(User).filter_by(email=user_data["email"]).first()
        assert saved_user is not None
        assert saved_user.username == user_data["username"]
        assert saved_user.email == user_data["email"]
        
        # Verify password was hashed
        assert saved_user.password_hash != user_data["password"]
        assert saved_user.password_hash.startswith("$2b$")
    
    def test_user_authentication_flow(self, user_service, sample_user_data, test_db_session):
        # Arrange
        # Create user directly in database
        user = User(
            username=sample_user_data["username"],
            email=sample_user_data["email"],
            password_hash=user_service.hash_password(sample_user_data["password"])
        )
        test_db_session.add(user)
        test_db_session.commit()
        
        login_data = {
            "email": sample_user_data["email"],
            "password": sample_user_data["password"]
        }
        
        # Act
        auth_result = user_service.authenticate(login_data)
        
        # Assert
        assert auth_result["success"] is True
        assert "token" in auth_result
        assert auth_result["user"]["id"] == user.id
        
        # Verify token is valid
        token_data = user_service.validate_token(auth_result["token"])
        assert token_data["user_id"] == user.id
    
    def test_user_registration_sends_welcome_email(self, user_service, sample_user_data, mock_email_service):
        # Act
        created_user = user_service.register_user(sample_user_data)
        
        # Assert
        assert created_user["id"] is not None
        assert created_user["email"] == sample_user_data["email"]
        
        # Verify welcome email was sent
        mock_email_service.send_welcome_email.assert_called_once_with(sample_user_data["email"])

# tests/integration/test_api_integration.py
import pytest
import requests
from unittest.mock import patch

class TestAPIIntegration:
    def test_user_creation_api_flow(self, test_client, sample_user_data):
        # Act
        response = test_client.post('/api/users', json=sample_user_data)
        
        # Assert
        assert response.status_code == 201
        
        response_data = response.get_json()
        assert response_data["username"] == sample_user_data["username"]
        assert response_data["email"] == sample_user_data["email"]
        assert "id" in response_data
        assert "password_hash" not in response_data  # Should not expose password
    
    @patch('app.services.external_api.ExternalAPIService.get_users')
    def test_external_api_integration(self, mock_get_users, test_client):
        # Arrange
        mock_external_users = [
            {"id": 1, "name": "External User 1"},
            {"id": 2, "name": "External User 2"}
        ]
        mock_get_users.return_value = mock_external_users
        
        # Act
        response = test_client.get('/api/users/external')
        
        # Assert
        assert response.status_code == 200
        
        response_data = response.get_json()
        assert len(response_data) == 2
        assert response_data[0]["name"] == "External User 1"
        
        # Verify external API was called
        mock_get_users.assert_called_once()
    
    def test_data_sync_workflow(self, test_client, test_db_session):
        # Arrange - Create local users
        local_users = [
            {"username": "user1", "email": "user1@example.com"},
            {"username": "user2", "email": "user2@example.com"}
        ]
        
        for user_data in local_users:
            test_client.post('/api/users', json=user_data)
        
        # Act
        response = test_client.post('/api/sync/users', json={
            "source": "local",
            "target": "external"
        })
        
        # Assert
        assert response.status_code == 200
        
        response_data = response.get_json()
        assert response_data["synced_count"] == 2
        assert response_data["status"] == "success"
```

### Node.js (Jest + Supertest)

```javascript
// tests/setup/integration-setup.js
const { PostgresContainer } = require('testcontainers');
const Redis = require('ioredis');
const app = require('../../src/app');

let postgresContainer;
let redisClient;

beforeAll(async () => {
  // Start PostgreSQL container
  postgresContainer = await new PostgresContainer()
    .withDatabase('test_db')
    .withUsername('test')
    .withPassword('test')
    .start();
  
  // Set environment variables
  process.env.DATABASE_URL = postgresContainer.getConnectionUri();
  process.env.REDIS_URL = 'redis://localhost:6379/1';
  
  // Start Redis
  redisClient = new Redis(process.env.REDIS_URL);
  
  // Run database migrations
  await runMigrations();
}, 30000);

afterAll(async () => {
  // Cleanup
  if (postgresContainer) {
    await postgresContainer.stop();
  }
  
  if (redisClient) {
    await redisClient.quit();
  }
});

beforeEach(async () => {
  // Clean up database before each test
  await cleanupDatabase();
  
  // Clean up Redis
  await redisClient.flushdb();
});

// tests/integration/userService.integration.test.js
const request = require('supertest');
const UserService = require('../../src/services/UserService');
const db = require('../../src/database/connection');

describe('UserService Integration Tests', () => {
  let userService;
  let mockEmailService;
  
  beforeEach(() => {
    mockEmailService = {
      sendWelcomeEmail: jest.fn().mockResolvedValue(true)
    };
    
    userService = new UserService(db, mockEmailService);
  });
  
  describe('createUser', () => {
    test('should persist user to database', async () => {
      // Arrange
      const userData = {
        username: 'integration_user',
        email: 'integration@example.com',
        password: 'IntegrationPass123!',
        firstName: 'Integration',
        lastName: 'User'
      };
      
      // Act
      const createdUser = await userService.createUser(userData);
      
      // Assert - Verify user was saved to database
      const savedUser = await db.query(
        'SELECT * FROM users WHERE email = $1',
        [userData.email]
      );
      
      expect(savedUser.rows).toHaveLength(1);
      expect(savedUser.rows[0].username).toBe(userData.username);
      expect(savedUser.rows[0].email).toBe(userData.email);
      
      // Verify password was hashed
      expect(savedUser.rows[0].password_hash).not.toBe(userData.password);
      expect(savedUser.rows[0].password_hash).toMatch(/^\$2b\$/);
    });
    
    test('should send welcome email', async () => {
      // Arrange
      const userData = {
        username: 'new_user',
        email: 'newuser@example.com',
        password: 'NewUserPass123!'
      };
      
      // Act
      await userService.registerUser(userData);
      
      // Assert
      expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(
        userData.email
      );
    });
  });
  
  describe('authenticate', () => {
    test('should authenticate user with valid credentials', async () => {
      // Arrange
      const userData = {
        username: 'auth_user',
        email: 'auth@example.com',
        password: 'AuthPass123!'
      };
      
      const createdUser = await userService.createUser(userData);
      
      const loginData = {
        email: userData.email,
        password: userData.password
      };
      
      // Act
      const authResult = await userService.authenticate(loginData);
      
      // Assert
      expect(authResult.success).toBe(true);
      expect(authResult.token).toBeDefined();
      expect(authResult.user.id).toBe(createdUser.id);
      
      // Verify token is valid
      const tokenData = userService.validateToken(authResult.token);
      expect(tokenData.userId).toBe(createdUser.id);
    });
  });
});

// tests/integration/api.integration.test.js
const request = require('supertest');
const app = require('../../src/app');

describe('API Integration Tests', () => {
  describe('User API', () => {
    test('POST /api/users should create user', async () => {
      // Arrange
      const userData = {
        username: 'api_user',
        email: 'apiuser@example.com',
        password: 'ApiPass123!',
        firstName: 'API',
        lastName: 'User'
      };
      
      // Act
      const response = await request(app)
        .post('/api/users')
        .send(userData)
        .expect(201);
      
      // Assert
      expect(response.body.username).toBe(userData.username);
      expect(response.body.email).toBe(userData.email);
      expect(response.body.id).toBeDefined();
      expect(response.body.password_hash).toBeUndefined(); // Should not expose password
    });
    
    test('GET /api/users should return all users', async () => {
      // Arrange - Create test users
      const users = [
        { username: 'user1', email: 'user1@example.com', password: 'Pass123!' },
        { username: 'user2', email: 'user2@example.com', password: 'Pass123!' }
      ];
      
      for (const userData of users) {
        await request(app)
          .post('/api/users')
          .send(userData);
      }
      
      // Act
      const response = await request(app)
        .get('/api/users')
        .expect(200);
      
      // Assert
      expect(response.body).toHaveLength(2);
      expect(response.body[0].username).toBe('user1');
      expect(response.body[1].username).toBe('user2');
    });
  });
  
  describe('External API Integration', () => {
    test('should integrate with external user service', async () => {
      // Mock external API
      const mockExternalUsers = [
        { id: 1, name: 'External User 1', email: 'external1@example.com' },
        { id: 2, name: 'External User 2', email: 'external2@example.com' }
      ];
      
      // Mock the external service
      jest.doMock('../../src/services/externalService', () => ({
        getExternalUsers: jest.fn().mockResolvedValue(mockExternalUsers)
      }));
      
      // Act
      const response = await request(app)
        .get('/api/users/external')
        .expect(200);
      
      // Assert
      expect(response.body).toHaveLength(2);
      expect(response.body[0].name).toBe('External User 1');
    });
  });
});
```

### Go

```go
// tests/integration/user_service_integration_test.go
package integration

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/suite"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "testcontainers-go"
    "testcontainers-go/wait"
    
    "github.com/yourproject/internal/database"
    "github.com/yourproject/internal/services"
    "github.com/yourproject/internal/models"
)

type UserServiceIntegrationSuite struct {
    suite.Suite
    db         *gorm.DB
    container  testcontainers.Container
    userService *services.UserService
    mockEmail   *MockEmailService
}

func (suite *UserServiceIntegrationSuite) SetupSuite() {
    // Start PostgreSQL container
    ctx := context.Background()
    req := testcontainers.ContainerRequest{
        Image:        "postgres:13",
        ExposedPorts: []string{"5432/tcp"},
        Env: map[string]string{
            "POSTGRES_DB":       "testdb",
            "POSTGRES_USER":     "test",
            "POSTGRES_PASSWORD": "test",
        },
        WaitingFor: wait.ForLog("database system is ready to accept connections"),
    }
    
    container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
        ContainerRequest: req,
        Started:          true,
    })
    require.NoError(suite.T(), err)
    
    suite.container = container
    
    // Get database connection string
    host, err := container.Host(ctx)
    require.NoError(suite.T(), err)
    
    port, err := container.MappedPort(ctx, "5432")
    require.NoError(suite.T(), err)
    
    dsn := fmt.Sprintf("host=%s port=%d user=test password=test dbname=testdb sslmode=disable", host, port.Int())
    
    // Connect to database
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    require.NoError(suite.T(), err)
    
    // Run migrations
    err = db.AutoMigrate(&models.User{})
    require.NoError(suite.T(), err)
    
    suite.db = db
}

func (suite *UserServiceIntegrationSuite) TearDownSuite() {
    if suite.container != nil {
        ctx := context.Background()
        suite.container.Terminate(ctx)
    }
}

func (suite *UserServiceIntegrationSuite) SetupTest() {
    // Clean up database before each test
    suite.db.Exec("DELETE FROM users")
    
    // Create fresh service instance
    suite.mockEmail = new(MockEmailService)
    suite.userService = services.NewUserService(suite.db, suite.mockEmail)
}

func (suite *UserServiceIntegrationSuite) TestCreateUser_PersistsToDatabase() {
    // Arrange
    userData := &models.User{
        Username:  "integration_user",
        Email:     "integration@example.com",
        Password:  "IntegrationPass123!",
        FirstName: "Integration",
        LastName:  "User",
    }
    
    // Act
    createdUser, err := suite.userService.CreateUser(userData)
    require.NoError(suite.T(), err)
    
    // Assert - Verify user was saved to database
    var savedUser models.User
    err = suite.db.Where("email = ?", userData.Email).First(&savedUser).Error
    require.NoError(suite.T(), err)
    
    assert.Equal(suite.T(), userData.Username, savedUser.Username)
    assert.Equal(suite.T(), userData.Email, savedUser.Email)
    assert.NotEmpty(suite.T(), savedUser.ID)
    
    // Verify password was hashed
    assert.NotEqual(suite.T(), userData.Password, savedUser.PasswordHash)
    assert.True(suite.T(), len(savedUser.PasswordHash) > 50)
}

func (suite *UserServiceIntegrationSuite) TestUserAuthentication_Flow() {
    // Arrange
    userData := &models.User{
        Username: "auth_user",
        Email:    "auth@example.com",
        Password: "AuthPass123!",
    }
    
    createdUser, err := suite.userService.CreateUser(userData)
    require.NoError(suite.T(), err)
    
    loginData := &services.LoginRequest{
        Email:    userData.Email,
        Password: userData.Password,
    }
    
    // Act
    authResult, err := suite.userService.Authenticate(loginData)
    require.NoError(suite.T(), err)
    
    // Assert
    assert.True(suite.T(), authResult.Success)
    assert.NotEmpty(suite.T(), authResult.Token)
    assert.Equal(suite.T(), createdUser.ID, authResult.User.ID)
    
    // Verify token is valid
    tokenData, err := suite.userService.ValidateToken(authResult.Token)
    require.NoError(suite.T(), err)
    assert.Equal(suite.T(), createdUser.ID, tokenData.UserID)
}

func (suite *UserServiceIntegrationSuite) TestUserRegistration_SendsWelcomeEmail() {
    // Arrange
    userData := &models.User{
        Username: "new_user",
        Email:    "newuser@example.com",
        Password: "NewUserPass123!",
    }
    
    // Setup mock expectation
    suite.mockEmail.On("SendWelcomeEmail", userData.Email).Return(nil)
    
    // Act
    createdUser, err := suite.userService.RegisterUser(userData)
    require.NoError(suite.T(), err)
    
    // Assert
    assert.NotEmpty(suite.T(), createdUser.ID)
    assert.Equal(suite.T(), userData.Email, createdUser.Email)
    
    // Verify welcome email was sent
    suite.mockEmail.AssertCalled(suite.T(), "SendWelcomeEmail", userData.Email)
}

func TestUserServiceIntegrationSuite(t *testing.T) {
    suite.Run(t, new(UserServiceIntegrationSuite))
}

// tests/integration/api_integration_test.go
type APIIntegrationSuite struct {
    suite.Suite
    server    *httptest.Server
    db        *gorm.DB
    container testcontainers.Container
}

func (suite *APIIntegrationSuite) SetupSuite() {
    // Setup database (same as above)
    // ... database setup code ...
    
    // Setup test server
    router := setupRouter(suite.db)
    suite.server = httptest.NewServer(router)
}

func (suite *APIIntegrationSuite) TearDownSuite() {
    if suite.server != nil {
        suite.server.Close()
    }
    if suite.container != nil {
        ctx := context.Background()
        suite.container.Terminate(ctx)
    }
}

func (suite *APIIntegrationSuite) TestCreateUserAPI() {
    // Arrange
    userData := map[string]interface{}{
        "username":  "api_user",
        "email":     "apiuser@example.com",
        "password":  "ApiPass123!",
        "firstName": "API",
        "lastName":  "User",
    }
    
    jsonData, _ := json.Marshal(userData)
    
    // Act
    resp, err := http.Post(suite.server.URL+"/api/users", "application/json", bytes.NewBuffer(jsonData))
    require.NoError(suite.T(), err)
    defer resp.Body.Close()
    
    // Assert
    assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)
    
    var response map[string]interface{}
    err = json.NewDecoder(resp.Body).Decode(&response)
    require.NoError(suite.T(), err)
    
    assert.Equal(suite.T(), userData["username"], response["username"])
    assert.Equal(suite.T(), userData["email"], response["email"])
    assert.NotEmpty(suite.T(), response["id"])
    assert.NotContains(suite.T(), response, "password_hash") // Should not expose password
}

func (suite *APIIntegrationSuite) TestGetUsersAPI() {
    // Arrange - Create test users
    users := []map[string]interface{}{
        {"username": "user1", "email": "user1@example.com", "password": "Pass123!"},
        {"username": "user2", "email": "user2@example.com", "password": "Pass123!"},
    }
    
    for _, userData := range users {
        jsonData, _ := json.Marshal(userData)
        http.Post(suite.server.URL+"/api/users", "application/json", bytes.NewBuffer(jsonData))
    }
    
    // Act
    resp, err := http.Get(suite.server.URL + "/api/users")
    require.NoError(suite.T(), err)
    defer resp.Body.Close()
    
    // Assert
    assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
    
    var response []map[string]interface{}
    err = json.NewDecoder(resp.Body).Decode(&response)
    require.NoError(suite.T(), err)
    
    assert.Len(suite.T(), response, 2)
    assert.Equal(suite.T(), "user1", response[0]["username"])
    assert.Equal(suite.T(), "user2", response[1]["username"])
}

func TestAPIIntegrationSuite(t *testing.T) {
    suite.Run(t, new(APIIntegrationSuite))
}
```

## Best Practices

### 1. Test Environment
- Use isolated test databases and services
- Clean up test data after each test
- Use test containers for consistent environments
- Mock external services to control responses

### 2. Data Management
- Seed consistent test data
- Use transactions for test isolation
- Clean up resources properly
- Avoid test dependencies on shared state

### 3. Test Design
- Test realistic scenarios and workflows
- Verify both success and failure cases
- Test error handling and recovery
- Include performance considerations

### 4. Maintenance
- Keep integration tests fast and reliable
- Use descriptive test names and documentation
- Regularly update test data and scenarios
- Monitor test execution and flakiness

## Adaptation Checklist

- [ ] Set up test containers for dependencies
- [ ] Configure test database with migrations
- [ ] Create test data factories and seeders
- [ ] Implement mock server for external APIs
- [ ] Set up test environment management
- [ ] Create integration test utilities
- [ ] Configure test cleanup and isolation
- [ ] Add test coverage reporting

## Common Pitfalls

1. **Shared test state** - Tests should be independent
2. **Slow tests** - Use efficient setup and cleanup
3. **External dependencies** - Mock external services
4. **Data cleanup failures** - Ensure proper cleanup
5. **Flaky tests** - Make tests deterministic and reliable

---

*Generic Integration Testing Pattern - Adapt to your technology stack*
