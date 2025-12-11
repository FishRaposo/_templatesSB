# Cross-Stack Integration Testing Template

## Overview

This template provides comprehensive cross-stack integration testing patterns for the Universal Template System. It covers scenarios where multiple technology stacks need to work together seamlessly.

## Supported Stack Combinations

### Backend + Frontend Integration
- **Python (FastAPI) + React**: REST API integration
- **Node.js (Express) + React**: Real-time WebSocket integration
- **Go + Flutter**: gRPC/REST API integration
- **Python + Next.js**: SSR API integration

### Microservices Integration
- **Python + Go**: Service-to-service communication
- **Node.js + Python**: Event-driven architecture
- **Go + Node.js**: Database replication scenarios

### Full-Stack Integration
- **Python Backend + React Frontend + PostgreSQL**
- **Node.js Backend + React Frontend + MongoDB**
- **Go Backend + Flutter Frontend + PostgreSQL**

## Test Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Test Runner   │    │  Docker Compose │    │  Test Database  │
│                 │    │                 │    │                 │
│ - pytest       │    │ - Backend A     │    │ - PostgreSQL    │
│ - Jest         │    │ - Backend B     │    │ - MongoDB       │
│ - Flutter Test │    │ - Frontend      │    │ - Redis         │
│ - Go Test      │    │ - Message Queue  │    │ - Elasticsearch │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Test Reports  │
                    │                 │
                    │ - Coverage      │
                    │ - Performance  │
                    │ - Security     │
                    └─────────────────┘
```

## Python + React Integration Tests

### Test Setup

```python
# tests/integration/test_python_react_integration.py
import pytest
import asyncio
from fastapi.testclient import TestClient
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from app.main import app
from tests.integration.react_app import start_react_app

@pytest.fixture(scope="session")
def test_environment():
    """Setup test environment with both backend and frontend"""
    # Start FastAPI backend
    backend_client = TestClient(app)
    
    # Start React frontend
    frontend_url = start_react_app()
    
    # Setup Selenium WebDriver
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=chrome_options)
    
    yield {
        "backend": backend_client,
        "frontend_url": frontend_url,
        "driver": driver
    }
    
    driver.quit()

@pytest.fixture
def authenticated_user(test_environment):
    """Create authenticated user for testing"""
    user_data = {
        "email": "test@example.com",
        "password": "testpassword123"
    }
    
    # Create user via backend API
    response = test_environment["backend"].post("/api/auth/register", json=user_data)
    assert response.status_code == 201
    
    # Login and get token
    login_response = test_environment["backend"].post("/api/auth/login", json=user_data)
    token = login_response.json()["access_token"]
    
    return {
        "user": user_data,
        "token": token
    }
```

### Integration Test Examples

```python
class TestPythonReactIntegration:
    """Test Python backend with React frontend integration"""
    
    def test_user_registration_flow(self, test_environment):
        """Test complete user registration flow"""
        driver = test_environment["driver"]
        frontend_url = test_environment["frontend_url"]
        
        # Navigate to registration page
        driver.get(f"{frontend_url}/register")
        
        # Fill registration form
        driver.find_element("name", "email").send_keys("test@example.com")
        driver.find_element("name", "password").send_keys("testpassword123")
        driver.find_element("name", "confirmPassword").send_keys("testpassword123")
        
        # Submit form
        driver.find_element("css", "button[type='submit']").click()
        
        # Verify success message
        success_message = driver.find_element("css", ".success-message")
        assert "Registration successful" in success_message.text
        
        # Verify user exists in backend
        backend = test_environment["backend"]
        response = backend.get("/api/users/email/test@example.com")
        assert response.status_code == 200
        assert response.json()["email"] == "test@example.com"
    
    def test_api_data_display(self, test_environment, authenticated_user):
        """Test that React frontend correctly displays data from Python backend"""
        driver = test_environment["driver"]
        backend = test_environment["backend"]
        frontend_url = test_environment["frontend_url"]
        
        # Create test data via backend
        product_data = {
            "name": "Test Product",
            "price": 29.99,
            "description": "A test product for integration testing"
        }
        
        headers = {"Authorization": f"Bearer {authenticated_user['token']}"}
        create_response = backend.post("/api/products", json=product_data, headers=headers)
        assert create_response.status_code == 201
        
        product_id = create_response.json()["id"]
        
        # Navigate to product page in React frontend
        driver.get(f"{frontend_url}/products/{product_id}")
        
        # Wait for page to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".product-detail"))
        )
        
        # Verify product data is displayed
        product_name = driver.find_element("css", ".product-name").text
        product_price = driver.find_element("css", ".product-price").text
        product_description = driver.find_element("css", ".product-description").text
        
        assert product_name == product_data["name"]
        assert product_price == f"${product_data['price']}"
        assert product_description == product_data["description"]
    
    def test_real_time_updates(self, test_environment, authenticated_user):
        """Test real-time updates between backend and frontend"""
        driver = test_environment["driver"]
        backend = test_environment["backend"]
        frontend_url = test_environment["frontend_url"]
        
        # Navigate to dashboard
        driver.get(f"{frontend_url}/dashboard")
        
        # Get initial notification count
        initial_count = len(driver.find_elements("css", ".notification"))
        
        # Create notification via backend API
        headers = {"Authorization": f"Bearer {authenticated_user['token']}"}
        notification_data = {
            "message": "Test notification",
            "type": "info"
        }
        
        backend.post("/api/notifications", json=notification_data, headers=headers)
        
        # Wait for WebSocket update
        WebDriverWait(driver, 10).until(
            lambda d: len(d.find_elements("css", ".notification")) > initial_count
        )
        
        # Verify new notification appears
        notifications = driver.find_elements("css", ".notification")
        assert len(notifications) == initial_count + 1
        
        new_notification = notifications[-1]
        assert notification_data["message"] in new_notification.text
```

## Node.js + React Integration Tests

### WebSocket Integration

```javascript
// tests/integration/websocket_integration.test.js
const WebSocket = require('ws');
const request = require('supertest');
const app = require('../../app');
const puppeteer = require('puppeteer');

describe('Node.js + React WebSocket Integration', () => {
  let server;
  let browser;
  let page;
  let wsConnection;

  beforeAll(async () => {
    // Start Node.js server
    server = app.listen(3001);
    
    // Start browser
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox']
    });
    page = await browser.newPage();
  });

  afterAll(async () => {
    if (wsConnection) {
      wsConnection.close();
    }
    if (browser) {
      await browser.close();
    }
    if (server) {
      server.close();
    }
  });

  test('should establish WebSocket connection', async () => {
    // Navigate to React app
    await page.goto('http://localhost:3000');
    
    // Wait for WebSocket connection
    await page.waitForFunction(() => window.socketConnected);
    
    // Verify connection status
    const isConnected = await page.evaluate(() => window.socketConnected);
    expect(isConnected).toBe(true);
  });

  test('should receive real-time updates', async () => {
    // Connect WebSocket client
    wsConnection = new WebSocket('ws://localhost:3001');
    
    await new Promise((resolve) => {
      wsConnection.on('open', resolve);
    });
    
    // Navigate to page with real-time updates
    await page.goto('http://localhost:3000/live-updates');
    
    // Send message via WebSocket
    const testMessage = {
      type: 'update',
      data: { message: 'Test update', timestamp: Date.now() }
    };
    
    wsConnection.send(JSON.stringify(testMessage));
    
    // Wait for UI update
    await page.waitForFunction((expectedMessage) => {
      return window.lastMessage && 
             window.lastMessage.message === expectedMessage.message;
    }, {}, testMessage);
    
    // Verify update displayed
    const displayedMessage = await page.evaluate(() => {
      const element = document.querySelector('.live-update');
      return element ? element.textContent : null;
    });
    
    expect(displayedMessage).toContain(testMessage.data.message);
  });

  test('should handle connection errors gracefully', async () => {
    // Navigate to page
    await page.goto('http://localhost:3000/connection-status');
    
    // Simulate connection loss
    await page.evaluate(() => {
      window.simulateConnectionLoss();
    });
    
    // Wait for error handling
    await page.waitForSelector('.connection-error');
    
    // Verify error message
    const errorMessage = await page.evaluate(() => {
      const element = document.querySelector('.connection-error');
      return element ? element.textContent : null;
    });
    
    expect(errorMessage).toContain('Connection lost');
    
    // Verify retry mechanism
    await page.waitForFunction(() => window.reconnectAttempted);
    
    const reconnectStatus = await page.evaluate(() => {
      const element = document.querySelector('.reconnect-status');
      return element ? element.textContent : null;
    });
    
    expect(reconnectStatus).toContain('Reconnecting');
  });
});
```

## Go + Flutter Integration Tests

### gRPC Integration

```go
// tests/integration/grpc_integration_test.go
package integration

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
    "google.golang.org/grpc"
    "google.golang.org/grpc/test/bufconn"
    
    pb "github.com/yourproject/proto"
    flutter "github.com/yourproject/flutter/testing"
)

type GrpcIntegrationSuite struct {
    suite.Suite
    listener *bufconn.Listener
    client   pb.UserServiceClient
    flutterApp *flutter.TestApp
}

func (suite *GrpcIntegrationSuite) SetupSuite() {
    // Setup gRPC server
    suite.listener = bufconn.Listen(1024 * 1024)
    server := grpc.NewServer()
    pb.RegisterUserServiceServer(server, &userService{})
    
    go func() {
        if err := server.Serve(suite.listener); err != nil {
            suite.T().Fatalf("Failed to serve: %v", err)
        }
    }()
    
    // Setup gRPC client
    ctx := context.Background()
    conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
        return suite.listener.Dial()
    }), grpc.WithInsecure())
    
    if err != nil {
        suite.T().Fatalf("Failed to dial: %v", err)
    }
    
    suite.client = pb.NewUserServiceClient(conn)
    
    // Setup Flutter app
    suite.flutterApp = flutter.NewTestApp()
    go suite.flutterApp.Run()
}

func (suite *GrpcIntegrationSuite) TearDownSuite() {
    if suite.flutterApp != nil {
        suite.flutterApp.Stop()
    }
}

func (suite *GrpcIntegrationSuite) TestUserCreationFlow() {
    // Test user creation via gRPC from Flutter
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    // Simulate Flutter user creation
    userReq := &pb.CreateUserRequest{
        Email:    "test@example.com",
        Name:     "Test User",
        Password:  "testpassword123",
    }
    
    // Call gRPC service from Flutter test
    resp, err := suite.flutterApp.CreateUser(userReq)
    assert.NoError(suite.T(), err)
    assert.NotNil(suite.T(), resp)
    assert.Equal(suite.T(), userReq.Email, resp.User.Email)
    assert.Equal(suite.T(), userReq.Name, resp.User.Name)
    
    // Verify user exists via direct gRPC call
    getReq := &pb.GetUserRequest{
        UserId: resp.User.Id,
    }
    
    user, err := suite.client.GetUser(ctx, getReq)
    assert.NoError(suite.T(), err)
    assert.NotNil(suite.T(), user)
    assert.Equal(suite.T(), resp.User.Id, user.Id)
}

func (suite *GrpcIntegrationSuite) TestRealTimeUpdates() {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    // Test real-time updates via gRPC streaming
    streamReq := &pb.StreamUpdatesRequest{
        UserId: "test-user-id",
    }
    
    stream, err := suite.client.StreamUpdates(ctx, streamReq)
    assert.NoError(suite.T(), err)
    
    // Send update from Flutter
    updateData := &pb.UpdateData{
        Message: "Test update",
        Timestamp: time.Now().Unix(),
    }
    
    err = suite.flutterApp.SendUpdate(updateData)
    assert.NoError(suite.T(), err)
    
    // Receive update via stream
    update, err := stream.Recv()
    assert.NoError(suite.T(), err)
    assert.Equal(suite.T(), updateData.Message, update.Message)
}

func TestGrpcIntegrationSuite(t *testing.T) {
    suite.Run(t, new(GrpcIntegrationSuite))
}
```

## Microservices Integration Tests

### Event-Driven Architecture

```python
# tests/integration/microservices_event_driven.py
import pytest
import asyncio
import json
from unittest.mock import AsyncMock
from app.services.order_service import OrderService
from app.services.notification_service import NotificationService
from app.services.inventory_service import InventoryService
from tests.integration.message_broker import TestMessageBroker

@pytest.fixture
async def message_broker():
    """Setup test message broker"""
    broker = TestMessageBroker()
    await broker.start()
    yield broker
    await broker.stop()

@pytest.fixture
async def services(message_broker):
    """Setup microservices with test message broker"""
    order_service = OrderService(message_broker)
    notification_service = NotificationService(message_broker)
    inventory_service = InventoryService(message_broker)
    
    await asyncio.gather(
        order_service.start(),
        notification_service.start(),
        inventory_service.start()
    )
    
    yield {
        "order": order_service,
        "notification": notification_service,
        "inventory": inventory_service
    }

class TestMicroservicesIntegration:
    """Test microservices integration with event-driven architecture"""
    
    async def test_order_processing_flow(self, services, message_broker):
        """Test complete order processing across microservices"""
        # Create order
        order_data = {
            "user_id": "user123",
            "items": [
                {"product_id": "prod1", "quantity": 2},
                {"product_id": "prod2", "quantity": 1}
            ],
            "total": 99.99
        }
        
        # Submit order to order service
        order = await services["order"].create_order(order_data)
        assert order["status"] == "pending"
        
        # Wait for inventory check event
        inventory_event = await message_broker.wait_for_event(
            "inventory.checked",
            timeout=5.0
        )
        assert inventory_event["order_id"] == order["id"]
        assert inventory_event["available"] is True
        
        # Wait for payment processing event
        payment_event = await message_broker.wait_for_event(
            "payment.processed",
            timeout=5.0
        )
        assert payment_event["order_id"] == order["id"]
        assert payment_event["status"] == "completed"
        
        # Wait for notification event
        notification_event = await message_broker.wait_for_event(
            "notification.sent",
            timeout=5.0
        )
        assert notification_event["user_id"] == order_data["user_id"]
        assert "order confirmed" in notification_event["message"].lower()
        
        # Verify final order status
        final_order = await services["order"].get_order(order["id"])
        assert final_order["status"] == "confirmed"
    
    async def test_inventory_reservation_compensation(self, services, message_broker):
        """Test compensation transaction when inventory is insufficient"""
        # Create order with insufficient inventory
        order_data = {
            "user_id": "user123",
            "items": [
                {"product_id": "out_of_stock", "quantity": 10}
            ]
        }
        
        # Submit order
        order = await services["order"].create_order(order_data)
        
        # Wait for inventory check event
        inventory_event = await message_broker.wait_for_event(
            "inventory.checked",
            timeout=5.0
        )
        assert inventory_event["available"] is False
        
        # Wait for compensation event
        compensation_event = await message_broker.wait_for_event(
            "order.cancelled",
            timeout=5.0
        )
        assert compensation_event["order_id"] == order["id"]
        assert compensation_event["reason"] == "insufficient_inventory"
        
        # Verify notification sent
        notification_event = await message_broker.wait_for_event(
            "notification.sent",
            timeout=5.0
        )
        assert "insufficient inventory" in notification_event["message"].lower()
```

## Database Integration Tests

### Multi-Database Scenarios

```python
# tests/integration/multi_database_integration.py
import pytest
import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.postgres import PostgreSQLModel
from app.models.mongodb import MongoDBModel
from app.services.data_sync import DataSyncService

@pytest.fixture
def postgres_db():
    """Setup PostgreSQL test database"""
    engine = create_engine("postgresql://test:test@localhost/test_db")
    Session = sessionmaker(bind=engine)
    session = Session()
    
    yield session
    session.close()
    engine.dispose()

@pytest.fixture
def mongodb_db():
    """Setup MongoDB test database"""
    from pymongo import MongoClient
    client = MongoClient("mongodb://localhost:27017")
    db = client.test_db
    
    yield db
    client.drop_database("test_db")

class TestMultiDatabaseIntegration:
    """Test integration across multiple databases"""
    
    async def test_data_sync_between_databases(self, postgres_db, mongodb_db):
        """Test data synchronization between PostgreSQL and MongoDB"""
        # Create record in PostgreSQL
        postgres_record = PostgreSQLModel(
            name="Test Record",
            value=42,
            metadata={"source": "postgres"}
        )
        postgres_db.add(postgres_record)
        postgres_db.commit()
        
        # Run data sync service
        sync_service = DataSyncService()
        await sync_service.sync_postgres_to_mongodb()
        
        # Verify record exists in MongoDB
        mongo_record = mongodb_db.test_collection.find_one({
            "name": "Test Record"
        })
        
        assert mongo_record is not None
        assert mongo_record["value"] == 42
        assert mongo_record["metadata"]["source"] == "postgres"
    
    async def test_transaction_rollback_across_databases(self, postgres_db, mongodb_db):
        """Test transaction rollback across multiple databases"""
        # Start distributed transaction
        sync_service = DataSyncService()
        
        try:
            # Create records in both databases
            postgres_record = PostgreSQLModel(
                name="Transaction Test",
                value=100
            )
            postgres_db.add(postgres_record)
            
            mongodb_record = {
                "name": "Transaction Test",
                "value": 100,
                "source": "transaction_test"
            }
            mongodb_db.test_collection.insert_one(mongodb_record)
            
            # Simulate error condition
            await sync_service.process_complex_business_logic()
            
            # This should trigger rollback
            assert False, "Should have raised an exception"
            
        except BusinessLogicError:
            # Verify rollback in PostgreSQL
            postgres_record = postgres_db.query(PostgreSQLModel).filter_by(
                name="Transaction Test"
            ).first()
            assert postgres_record is None
            
            # Verify rollback in MongoDB
            mongo_record = mongodb_db.test_collection.find_one({
                "name": "Transaction Test"
            })
            assert mongo_record is None
```

## Performance Integration Tests

### Load Testing Across Stacks

```python
# tests/integration/cross_stack_load_test.py
import pytest
import asyncio
import aiohttp
from locust import HttpUser, task, between
from tests.integration.load_test_environment import LoadTestEnvironment

class CrossStackLoadTest(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        """Initialize user session"""
        self.client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "testpassword"
        })
    
    @task(3)
    def view_products(self):
        """Browse products - hits backend and frontend"""
        self.client.get("/api/products")
        self.client.get("/products")
    
    @task(2)
    def search_products(self):
        """Search products - tests search functionality"""
        self.client.get("/api/products/search?q=test")
        self.client.get("/search?q=test")
    
    @task(1)
    def create_order(self):
        """Create order - tests complete workflow"""
        # Add item to cart
        self.client.post("/api/cart/items", json={
            "product_id": "test_product",
            "quantity": 1
        })
        
        # Checkout
        self.client.post("/api/orders", json={
            "items": [{"product_id": "test_product", "quantity": 1}],
            "payment_method": "credit_card"
        })

@pytest.mark.performance
class TestCrossStackPerformance:
    """Test performance across all stacks"""
    
    async def test_load_balancing(self):
        """Test load balancing across multiple backend instances"""
        env = LoadTestEnvironment()
        await env.start_multiple_instances(count=3)
        
        try:
            # Simulate load
            tasks = []
            for i in range(100):
                task = self.simulate_user_request(env)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            
            # Verify load distribution
            instance_stats = env.get_instance_stats()
            for stats in instance_stats:
                assert abs(stats.request_count - 33) < 10  # ~33 requests per instance
            
        finally:
            await env.stop_all_instances()
    
    async def simulate_user_request(self, env):
        """Simulate a single user request"""
        async with aiohttp.ClientSession() as session:
            # Try different instances
            instance_url = env.get_random_instance_url()
            
            async with session.get(f"{instance_url}/api/health") as response:
                return response.status == 200
```

## Security Integration Tests

### Cross-Stack Security Validation

```python
# tests/integration/cross_stack_security.py
import pytest
import requests
from tests.integration.security_test_helper import SecurityTestHelper

class TestCrossStackSecurity:
    """Test security across all stacks"""
    
    def test_authentication_flow_security(self, test_environment):
        """Test security of authentication flow"""
        helper = SecurityTestHelper()
        
        # Test SQL injection in login
        sql_payloads = helper.generate_sql_injection_payloads()
        for payload in sql_payloads:
            response = test_environment["backend"].post("/api/auth/login", json={
                "email": payload,
                "password": "testpassword"
            })
            
            # Should not authenticate with SQL injection
            assert response.status_code in [400, 401]
        
        # Test XSS in registration
        xss_payloads = helper.generate_xss_payloads()
        for payload in xss_payloads:
            response = test_environment["backend"].post("/api/auth/register", json={
                "email": "test@example.com",
                "password": "testpassword",
                "name": payload
            })
            
            # Should either reject or sanitize
            if response.status_code == 201:
                # If accepted, verify sanitization
                user_response = test_environment["backend"].get(
                    f"/api/users/email/test@example.com"
                )
                user_data = user_response.json()
                assert payload not in user_data["name"]
    
    def test_cors_configuration(self, test_environment):
        """Test CORS configuration across all services"""
        frontend_url = test_environment["frontend_url"]
        backend_url = test_environment["backend"].base_url
        
        # Test preflight requests
        response = requests.options(
            f"{backend_url}/api/users",
            headers={
                "Origin": frontend_url,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Content-Type"
            }
        )
        
        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == frontend_url
        assert "GET" in response.headers["Access-Control-Allow-Methods"]
        assert "Content-Type" in response.headers["Access-Control-Allow-Headers"]
    
    def test_rate_limiting_across_services(self, test_environment):
        """Test rate limiting is consistent across services"""
        backend = test_environment["backend"]
        
        # Test API rate limiting
        responses = []
        for i in range(100):
            response = backend.get("/api/products")
            responses.append(response.status_code)
        
        # Should have rate limiting responses
        rate_limited_count = sum(1 for status in responses if status == 429)
        assert rate_limited_count > 0
        
        # Test frontend rate limiting
        driver = test_environment["driver"]
        driver.get(f"{test_environment['frontend_url']}/products")
        
        # Rapidly click search button
        search_button = driver.find_element("css", ".search-button")
        for i in range(50):
            search_button.click()
        
        # Should show rate limiting message
        rate_limit_message = driver.find_elements("css", ".rate-limit-message")
        assert len(rate_limit_message) > 0
```

## Test Data Management

### Cross-Stack Test Data Factory

```python
# tests/integration/cross_stack_data_factory.py
import pytest
from tests.integration.data_factory import CrossStackDataFactory

@pytest.fixture
def data_factory():
    """Create cross-stack data factory"""
    return CrossStackDataFactory()

class TestCrossStackDataFactory:
    """Test data factory for cross-stack scenarios"""
    
    def test_consistent_user_data(self, data_factory):
        """Test user data consistency across stacks"""
        # Generate user data for different stacks
        python_user = data_factory.create_python_user()
        nodejs_user = data_factory.create_nodejs_user()
        go_user = data_factory.create_go_user()
        
        # Verify consistent structure
        required_fields = ["email", "name", "password", "created_at"]
        
        for user in [python_user, nodejs_user, go_user]:
            for field in required_fields:
                assert field in user, f"Missing field {field} in user data"
        
        # Verify data type consistency
        assert isinstance(python_user["email"], str)
        assert isinstance(nodejs_user["email"], str)
        assert isinstance(go_user["email"], str)
    
    def test_related_data_generation(self, data_factory):
        """Test generation of related data across stacks"""
        # Create order with related user and products
        order_data = data_factory.create_complete_order()
        
        # Verify relationships
        assert "user" in order_data
        assert "items" in order_data
        assert "payments" in order_data
        
        # Verify data consistency
        user_id = order_data["user"]["id"]
        for item in order_data["items"]:
            assert "product" in item
            assert "order_id" in item
            assert item["order_id"] == order_data["id"]
        
        for payment in order_data["payments"]:
            assert "order_id" in payment
            assert payment["order_id"] == order_data["id"]
```

## CI/CD Integration

### Cross-Stack Pipeline

```yaml
# .github/workflows/cross-stack-integration.yml
name: Cross-Stack Integration Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  setup-environment:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Docker Compose
      run: |
        docker-compose -f docker-compose.test.yml up -d
        sleep 30  # Wait for services to be ready
    
    - name: Run health checks
      run: |
        curl -f http://localhost:3001/health || exit 1
        curl -f http://localhost:3002/health || exit 1
        curl -f http://localhost:3000 || exit 1

  python-react-integration:
    needs: setup-environment
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        npm ci
    
    - name: Run integration tests
      run: |
        pytest tests/integration/test_python_react_integration.py -v
        npm run test:integration

  microservices-integration:
    needs: setup-environment
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.19'
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
    
    - name: Run microservices tests
      run: |
        go test ./tests/integration/... -v
        npm run test:microservices

  cross-stack-performance:
    needs: setup-environment
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Run performance tests
      run: |
        pytest tests/integration/cross_stack_load_test.py -v
    
    - name: Upload performance reports
      uses: actions/upload-artifact@v3
      with:
        name: performance-reports
        path: reports/performance/

  cleanup:
    needs: [python-react-integration, microservices-integration, cross-stack-performance]
    runs-on: ubuntu-latest
    if: always()
    steps:
    - name: Cleanup test environment
      run: |
        docker-compose -f docker-compose.test.yml down -v
```

## Conclusion

This cross-stack integration testing template provides comprehensive patterns for testing interactions between different technology stacks. By following these patterns, development teams can ensure that their microservices, frontend-backend integrations, and multi-stack applications work seamlessly together.

Key benefits:
1. **Comprehensive Coverage**: Tests all interaction points between stacks
2. **Realistic Scenarios**: Simulates real-world usage patterns
3. **Automated Testing**: Integrates with CI/CD pipelines
4. **Performance Validation**: Ensures performance across stack boundaries
5. **Security Verification**: Tests security across all components

Remember to adapt these templates to your specific stack combinations and business requirements.