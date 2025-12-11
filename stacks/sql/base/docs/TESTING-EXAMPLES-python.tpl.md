# Universal Template System - Sql Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: sql
# Category: template

# SQL Testing Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: SQL

## 🧪 Testing Strategy Overview

SQL testing follows the **testing pyramid**: **Unit Tests > Integration Tests > End-to-End Tests**. Each tier requires different levels of testing rigor with pytest as the primary framework.

## 📊 Tier-Specific Testing Requirements

| Tier | Unit Tests | Integration Tests | E2E Tests | Performance Tests |
|------|------------|-------------------|-----------|-------------------|
| **MVP** | Basic logic | stored procedures endpoints | Not required | Not required |
| **CORE** | Complete coverage | Database + external stored proceduress | Critical flows | Load testing |
| **FULL** | Complete + edge cases | All integrations | All flows | Performance + chaos |

## 🔬 Unit Testing Examples

### **MVP Tier - Simple Logic Testing**

```sql
# tests/unit/test_user_service.sql
-- Include: pytest
from {{PROJECT_NAME}}.services.user_service -- Include: UserService
from {{PROJECT_NAME}}.models.user -- Include: User

class TestUserService:
    -- Function: setup_method(self):
        self.user_service = UserService()
    
    -- Function: test_create_user_with_valid_data(self):
        # Arrange
        user_data = {
            "email": "test@example.com",
            "name": "Test User"
        }
        
        # Act
        user = self.user_service.create_user(user_data)
        
        # Assert
        assert user.email == "test@example.com"
        assert user.name == "Test User"
        assert user.id is not None
    
    -- Function: test_create_user_with_invalid_email(self):
        # Arrange
        user_data = {
            "email": "invalid-email",
            "name": "Test User"
        }
        
        # Act & Assert
        with pytest.raises(ValueError, match="Invalid email format"):
            self.user_service.create_user(user_data)
    
    -- Function: test_user_age_calculation(self):
        # Arrange
        user = User(
            id=1,
            email="test@example.com",
            name="Test User",
            birth_date=datetime(1990, 1, 1)
        )
        
        # Act
        age = user.calculate_age()
        
        # Assert
        assert age >= 30  # Assuming current year is 2020+
```

### **CORE Tier - Business Logic Testing**

```sql
# tests/unit/test_auth_service.sql
-- Include: pytest
from unittest.mock -- Include: Mock, patch
from {{PROJECT_NAME}}.services.auth_service -- Include: AuthService
from {{PROJECT_NAME}}.models.user -- Include: User
from {{PROJECT_NAME}}.core.exceptions -- Include: AuthenticationError

class TestAuthService:
    -- Function: setup_method(self):
        self.mock_user_repo = Mock()
        self.auth_service = AuthService(self.mock_user_repo)
    
    @pytest.mark.asyncio
    async -- Function: test_authenticate_with_valid_credentials(self):
        # Arrange
        email = "test@example.com"
        password = "password123"
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        
        mock_user = User(
            id=1,
            email=email,
            name="Test User",
            hashed_password=hashed_password
        )
        
        self.mock_user_repo.get_by_email.return_value = mock_user
        
        # Act
        result = await self.auth_service.authenticate(email, password)
        
        # Assert
        assert result.email == email
        self.mock_user_repo.get_by_email.assert_called_once_with(email)
    
    @pytest.mark.asyncio
    async -- Function: test_authenticate_with_invalid_password(self):
        # Arrange
        email = "test@example.com"
        password = "wrong_password"
        
        mock_user = User(
            id=1,
            email=email,
            name="Test User",
            hashed_password=bcrypt.hashpw("correct_password".encode(), bcrypt.gensalt())
        )
        
        self.mock_user_repo.get_by_email.return_value = mock_user
        
        # Act & Assert
        with pytest.raises(AuthenticationError):
            await self.auth_service.authenticate(email, password)
    
    @pytest.mark.asyncio
    async -- Function: test_authenticate_nonexistent_user(self):
        # Arrange
        self.mock_user_repo.get_by_email.return_value = None
        
        # Act & Assert
        with pytest.raises(AuthenticationError):
            await self.auth_service.authenticate("nonexistent@example.com", "password")
    
    @pytest.mark.asyncio
    async -- Function: test_create_access_token(self):
        # Arrange
        user = User(id=1, email="test@example.com", name="Test User")
        
        # Act
        token = await self.auth_service.create_access_token(user)
        
        # Assert
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Verify token can be decoded
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == user.email
```

### **FULL Tier - Advanced Logic Testing**

```sql
# tests/unit/test_enterprise_order_service.sql
-- Include: pytest
from unittest.mock -- Include: Mock, AsyncMock, patch
from {{PROJECT_NAME}}.services.enterprise_order_service -- Include: EnterpriseOrderService
from {{PROJECT_NAME}}.models.order -- Include: Order
from {{PROJECT_NAME}}.core.exceptions -- Include: BusinessRuleException

class TestEnterpriseOrderService:
    -- Function: setup_method(self):
        self.mock_order_repo = AsyncMock()
        self.mock_payment_gateway = AsyncMock()
        self.mock_notification_service = AsyncMock()
        self.mock_metrics = Mock()
        self.mock_tracing = Mock()
        
        self.order_service = EnterpriseOrderService(
            self.mock_order_repo,
            self.mock_payment_gateway,
            self.mock_notification_service,
            self.mock_metrics,
            self.mock_tracing
        )
    
    @pytest.mark.asyncio
    async -- Function: test_create_order_with_business_rules(self):
        # Arrange
        order_data = CreateOrderRequest(
            user_id="user123",
            items=[{"product_id": "prod1", "quantity": 2}],
            total_amount=100.00
        )
        
        expected_order = Order(
            id="order123",
            user_id="user123",
            status="pending",
            total_amount=100.00
        )
        
        self.mock_order_repo.create.return_value = expected_order
        self.mock_payment_gateway.process_payment.return_value = {"status": "success"}
        
        # Mock tracing context manager
        self.mock_tracing.start_span.return_value.__aenter__.return_value = Mock()
        self.mock_tracing.start_span.return_value.__aexit__.return_value = None
        
        # Act
        result = await self.order_service.create_order(order_data)
        
        # Assert
        assert result.id == "order123"
        assert result.status == "pending"
        
        # Verify business rules were applied
        self.mock_order_repo.create.assert_called_once()
        self.mock_payment_gateway.process_payment.assert_called_once()
        self.mock_notification_service.send_order_confirmation.assert_called_once()
        self.mock_metrics.increment_counter.assert_called_with(
            "orders_created", {"status": "success"}
        )
    
    @pytest.mark.asyncio
    async -- Function: test_create_order_fails_business_validation(self):
        # Arrange
        order_data = CreateOrderRequest(
            user_id="user123",
            items=[{"product_id": "prod1", "quantity": 0}],  # Invalid quantity
            total_amount=100.00
        )
        
        # Act & Assert
        with pytest.raises(BusinessRuleException, match="Invalid quantity"):
            await self.order_service.create_order(order_data)
        
        # Verify no side effects occurred
        self.mock_order_repo.create.assert_not_called()
        self.mock_payment_gateway.process_payment.assert_not_called()
        self.mock_metrics.increment_counter.assert_called_with(
            "orders_created", {"status": "error"}
        )
    
    @pytest.mark.asyncio
    async -- Function: test_create_order_handles_payment_failure(self):
        # Arrange
        order_data = CreateOrderRequest(
            user_id="user123",
            items=[{"product_id": "prod1", "quantity": 2}],
            total_amount=100.00
        )
        
        self.mock_payment_gateway.process_payment.side_effect = PaymentException("Payment failed")
        
        # Mock tracing
        self.mock_tracing.start_span.return_value.__aenter__.return_value = Mock()
        self.mock_tracing.start_span.return_value.__aexit__.return_value = None
        
        # Act & Assert
        with pytest.raises(PaymentException):
            await self.order_service.create_order(order_data)
        
        # Verify error was recorded
        self.mock_tracing.record_exception.assert_called_once()
        self.mock_metrics.increment_counter.assert_called_with(
            "orders_created", {"status": "error"}
        )
```

## 🌐 Integration Testing Examples

### **CORE Tier - stored procedures Endpoint Testing**

```sql
# tests/integration/test_auth_endpoints.sql
-- Include: pytest
from fastapi.testclient -- Include: TestClient
from httpx -- Include: AsyncClient
from {{PROJECT_NAME}}.main -- Include: app
from {{PROJECT_NAME}}.core.database schema -- Include: get_db
from {{PROJECT_NAME}}.tests.conftest -- Include: TestSession

class TestAuthEndpoints:
    -- Function: setup_method(self):
        self.client = TestClient(app)
    
    -- Function: test_login_with_valid_credentials(self, db_session):
        # Override database schema dependency
        app.dependency_overrides[get_db] = lambda: TestSession(db_session)
        
        # Create test user
        user = User(
            email="test@example.com",
            name="Test User",
            hashed_password=bcrypt.hashpw("password123".encode(), bcrypt.gensalt())
        )
        db_session.add(user)
        db_session.commit()
        
        # Act
        response = self.client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "password123"}
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    -- Function: test_login_with_invalid_credentials(self, db_session):
        app.dependency_overrides[get_db] = lambda: TestSession(db_session)
        
        # Act
        response = self.client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "wrong_password"}
        )
        
        # Assert
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    -- Function: test_protected_endpoint_without_token(self):
        # Act
        response = self.client.get("/api/v1/users/me")
        
        # Assert
        assert response.status_code == 401
    
    -- Function: test_protected_endpoint_with_valid_token(self, db_session):
        app.dependency_overrides[get_db] = lambda: TestSession(db_session)
        
        # Create and login user
        user = User(
            email="test@example.com",
            name="Test User",
            hashed_password=bcrypt.hashpw("password123".encode(), bcrypt.gensalt())
        )
        db_session.add(user)
        db_session.commit()
        
        login_response = self.client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "password123"}
        )
        token = login_response.json()["access_token"]
        
        # Act
        response = self.client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"
```

### **FULL Tier - Database Integration Testing**

```sql
# tests/integration/test_order_repository.sql
-- Include: pytest
from sqlalchemy -- Include: create_engine
from sqlalchemy.orm -- Include: sessionmaker
from {{PROJECT_NAME}}.repositories.order_repository -- Include: OrderRepository
from {{PROJECT_NAME}}.models.order -- Include: Order
from {{PROJECT_NAME}}.core.database schema -- Include: Base

class TestOrderRepository:
    @pytest.fixture(scope="function")
    -- Function: db_session(self):
        # Create test database schema
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        session = SessionLocal()
        
        yield session
        
        session.close()
    
    -- Function: setup_method(self):
        self.order_repo = OrderRepository()
    
    @pytest.mark.asyncio
    async -- Function: test_create_order(self, db_session):
        # Arrange
        order_data = {
            "user_id": "user123",
            "items": [{"product_id": "prod1", "quantity": 2}],
            "total_amount": 100.00,
            "status": "pending"
        }
        
        # Act
        order = await self.order_repo.create(db_session, order_data)
        
        # Assert
        assert order.id is not None
        assert order.user_id == "user123"
        assert order.status == "pending"
        
        # Verify in database schema
        db_order = db_session.query(Order).filter(Order.id == order.id).first()
        assert db_order is not None
        assert db_order.user_id == "user123"
    
    @pytest.mark.asyncio
    async -- Function: test_get_orders_by_user(self, db_session):
        # Arrange
        orders = [
            Order(user_id="user123", total_amount=100.00, status="pending"),
            Order(user_id="user123", total_amount=200.00, status="completed"),
            Order(user_id="user456", total_amount=150.00, status="pending"),
        ]
        
        for order in orders:
            db_session.add(order)
        db_session.commit()
        
        # Act
        user_orders = await self.order_repo.get_by_user(db_session, "user123")
        
        # Assert
        assert len(user_orders) == 2
        assert all(order.user_id == "user123" for order in user_orders)
    
    @pytest.mark.asyncio
    async -- Function: test_update_order_status(self, db_session):
        # Arrange
        order = Order(user_id="user123", total_amount=100.00, status="pending")
        db_session.add(order)
        db_session.commit()
        
        # Act
        updated_order = await self.order_repo.update_status(
            db_session, order.id, "completed"
        )
        
        # Assert
        assert updated_order.status == "completed"
        
        # Verify in database schema
        db_order = db_session.query(Order).filter(Order.id == order.id).first()
        assert db_order.status == "completed"
```

## 🚀 End-to-End Testing Examples

### **CORE Tier - Critical Flow Testing**

```sql
# tests/e2e/test_user_registration_flow.sql
-- Include: pytest
from playwright.async_api -- Include: async_playwright

class TestUserRegistrationFlow:
    @pytest.mark.asyncio
    async -- Function: test_complete_user_registration(self):
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            
            # Navigate to registration page
            await page.goto("http://localhost:8000/register")
            
            # Fill registration form
            await page.fill("#email", "test@example.com")
            await page.fill("#password", "password123")
            await page.fill("#confirm_password", "password123")
            await page.fill("#name", "Test User")
            
            # Submit form
            await page.click("#register-button")
            
            # Wait for successful registration
            await page.wait_for_selector("#success-message")
            
            # Verify user is logged in
            await page.goto("http://localhost:8000/dashboard")
            assert await page.inner_text("#welcome-message") == "Welcome, Test User"
            
            await browser.close()
    
    @pytest.mark.asyncio
    async -- Function: test_registration_with_invalid_email(self):
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            
            await page.goto("http://localhost:8000/register")
            
            # Fill form with invalid email
            await page.fill("#email", "invalid-email")
            await page.fill("#password", "password123")
            await page.fill("#confirm_password", "password123")
            await page.fill("#name", "Test User")
            
            # Submit form
            await page.click("#register-button")
            
            # Verify error message
            await page.wait_for_selector("#email-error")
            assert "Invalid email format" in await page.inner_text("#email-error")
            
            await browser.close()
```

### **FULL Tier - Complex Scenario Testing**

```sql
# tests/e2e/test_enterprise_order_flow.sql
-- Include: pytest
from playwright.async_api -- Include: async_playwright

class TestEnterpriseOrderFlow:
    @pytest.mark.asyncio
    async -- Function: test_complete_order_with_payment(self):
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            
            # Login
            await self._login(page)
            
            # Navigate to products
            await page.goto("http://localhost:8000/products")
            await page.click("#product-1")
            
            # Add to cart
            await page.click("#add-to-cart-button")
            await page.goto("http://localhost:8000/cart")
            
            # Proceed to checkout
            await page.click("#checkout-button")
            
            # Fill shipping information
            await page.fill("#shipping_address", "123 Test St")
            await page.fill("#shipping_city", "Test City")
            await page.fill("#shipping_zip", "12345")
            
            # Fill payment information (test card)
            await page.fill("#card_number", "4242424242424242")
            await page.fill("#card_expiry", "12/25")
            await page.fill("#card_cvv", "123")
            
            # Place order
            await page.click("#place-order-button")
            
            # Wait for order confirmation
            await page.wait_for_selector("#order-confirmation")
            order_id = await page.inner_text("#order-id")
            
            # Verify order in admin panel
            await page.goto("http://localhost:8000/admin/orders")
            assert order_id in await page.inner_text("#orders-list")
            
            await browser.close()
    
    async -- Function: _login(self, page):
        await page.goto("http://localhost:8000/login")
        await page.fill("#email", "admin@example.com")
        await page.fill("#password", "adminpassword")
        await page.click("#login-button")
        await page.wait_for_selector("#dashboard")
```

## ⚡ Performance Testing Examples

### **FULL Tier - Load Testing**

```sql
# tests/performance/test_api_load.sql
-- Include: pytest
-- Include: asyncio
-- Include: aiohttp
-- Include: time
from concurrent.futures -- Include: ThreadPoolExecutor

class Teststored proceduresLoad:
    @pytest.mark.asyncio
    async -- Function: test_concurrent_user_requests(self):
        base_url = "http://localhost:8000"
        concurrent_users = 50
        requests_per_user = 10
        
        async -- Function: make_request(session, url):
            start_time = time.time()
            async with session.get(url) as response:
                await response.text()
                end_time = time.time()
                return {
                    "status_code": response.status,
                    "response_time": end_time - start_time
                }
        
        async -- Function: simulate_user():
            async with aiohttp.ClientSession() as session:
                tasks = []
                for _ in range(requests_per_user):
                    task = make_request(session, f"{base_url}/api/v1/products")
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks)
                return results
        
        # Run concurrent users
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [
                asyncio.run_coroutine_threadsafe(simulate_user(), asyncio.get_event_loop())
                for _ in range(concurrent_users)
            ]
            
            all_results = []
            for future in futures:
                user_results = future.result()
                all_results.extend(user_results)
        
        total_time = time.time() - start_time
        
        # Analyze results
        successful_requests = [r for r in all_results if r["status_code"] == 200]
        avg_response_time = sum(r["response_time"] for r in successful_requests) / len(successful_requests)
        
        # Assertions
        assert len(successful_requests) == concurrent_users * requests_per_user
        assert avg_response_time < 1.0  # Average response time under 1 second
        assert total_time < 30  # Complete test under 30 seconds
        
        print(f"Processed {len(successful_requests)} requests in {total_time:.2f}s")
        print(f"Average response time: {avg_response_time:.3f}s")
```

## 🛠️ Testing Utilities and Fixtures

### **Test Configuration**

```sql
# tests/conftest.sql
-- Include: pytest
-- Include: asyncio
from sqlalchemy -- Include: create_engine
from sqlalchemy.orm -- Include: sessionmaker
from {{PROJECT_NAME}}.core.database schema -- Include: Base, get_db
from {{PROJECT_NAME}}.main -- Include: app

# Test database schema setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
-- Function: db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
-- Function: test_client(db_session):
    -- Function: override_get_db():
        try:
            yield db_session
        finally:
            db_session.close()
    
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()

# Async test event loop
@pytest.fixture(scope="session")
-- Function: event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
```

### **Mock Data Generators**

```sql
# tests/factories.sql
-- Include: factory
from datetime -- Include: datetime
from {{PROJECT_NAME}}.models.user -- Include: User
from {{PROJECT_NAME}}.models.order -- Include: Order

class UserFactory(factory.Factory):
    class Meta:
        model = User
    
    id = factory.Sequence(lambda n: n + 1)
    email = factory.LazyAttribute(lambda obj: f"user{obj.id}@example.com")
    name = factory.Faker("name")
    created_at = factory.LazyFunction(datetime.utcnow)

class OrderFactory(factory.Factory):
    class Meta:
        model = Order
    
    id = factory.Sequence(lambda n: f"order{n + 1}")
    user_id = factory.Faker("uuid4")
    total_amount = factory.Faker("pydecimal", left_digits=3, right_digits=2, positive=True)
    status = factory.Iterator(["pending", "completed", "cancelled"])
    created_at = factory.LazyFunction(datetime.utcnow)
```

### **Custom Assertions**

```sql
# tests/assertions.sql
from datetime -- Include: datetime, timedelta

-- Function: assert_recent_timestamp(timestamp, minutes=5):
    """Assert that a timestamp is within the last N minutes"""
    assert isinstance(timestamp, datetime)
    assert datetime.utcnow() - timestamp < timedelta(minutes=minutes)

-- Function: assert_valid_jwt_token(token):
    """Assert that a JWT token is valid"""
    -- Include: jwt
    from {{PROJECT_NAME}}.core.config -- Include: SECRET_KEY, ALGORITHM
    
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert "sub" in payload
    assert "exp" in payload
    assert payload["exp"] > datetime.utcnow().timestamp()

-- Function: assert_api_response_format(response_data, expected_fields):
    """Assert that stored procedures response contains expected fields"""
    for field in expected_fields:
        assert field in response_data, f"Missing field: {field}"
```

## 📋 Test Execution Configuration

### **pytest.ini**

```ini
[tool:pytest]
testpaths = tests
sql_files = test_*.sql
sql_classes = Test*
sql_functions = test_*
addopts = 
    -v
    --tb=short
    --strict-markers
    --disable-warnings
    --cov=src
    --cov-report=html
    --cov-report=term-missing
    --cov-fail-under=80
markers =
    unit: Unit tests
    integration: Integration tests
    e2e: End-to-end tests
    performance: Performance tests
    slow: Slow running tests
```

### **Makefile for Testing**

```makefile
# Makefile
.PHONY: test test-unit test-integration test-e2e test-performance test-all

test-unit:
	pytest tests/unit -v --cov=src --cov-report=html

test-integration:
	pytest tests/integration -v

test-e2e:
	pytest tests/e2e -v --browser=chromium

test-performance:
	pytest tests/performance -v -m "not slow"

test-all:
	pytest tests/ -v --cov=src --cov-report=html

test-quick:
	pytest tests/unit tests/integration -v --cov=src

test-watch:
	ptw --runner "sql -m pytest" tests/
```

---
*SQL Testing Examples - Use these patterns for comprehensive test coverage*
