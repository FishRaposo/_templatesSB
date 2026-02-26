---
name: integration-testing
description: Use this skill when testing how components work together, including API testing, database integration, service communication, and end-to-end workflows. This includes setting up test environments, using test containers, testing API contracts, and verifying data flow between components.
---

# Integration Testing

I'll help you test how components work together — APIs, databases, services, and full workflows. We'll set up proper test environments and verify real interactions.

## Core Approach

### What to Test

- API contracts and endpoints
- Database operations and migrations
- Service-to-service communication
- Message queue interactions
- End-to-end workflows
- External system integration

### Test Environment Strategy

| Strategy | Speed | Realism | Use Case |
|----------|-------|---------|----------|
| **Test Containers** | Medium | High | Database, message queues |
| **Local Services** | Medium | High | Microservices, APIs |
| **Dedicated Test Env** | Slow | Full | Staging, pre-prod validation |
| **Mock Server** | Fast | Low | External APIs, flaky services |

## Step-by-Step Instructions

### 1. API Integration Testing

**JavaScript (supertest)**
```javascript
const request = require('supertest');
const app = require('../app');

describe('API Integration', () => {
  test('GET /users returns user list', async () => {
    const response = await request(app)
      .get('/users')
      .expect('Content-Type', /json/)
      .expect(200);
    
    expect(response.body).toBeInstanceOf(Array);
    expect(response.body[0]).toHaveProperty('id');
    expect(response.body[0]).toHaveProperty('name');
  });
  
  test('POST /users creates user', async () => {
    const newUser = { name: 'John', email: 'john@example.com' };
    
    const response = await request(app)
      .post('/users')
      .send(newUser)
      .expect(201);
    
    expect(response.body).toMatchObject(newUser);
    expect(response.body).toHaveProperty('id');
  });
  
  test('GET /users/:id returns 404 for non-existent', async () => {
    await request(app)
      .get('/users/999999')
      .expect(404);
  });
});
```

**Python (pytest + requests/httpx)**
```python
import pytest
import requests

class TestUserAPI:
    BASE_URL = "http://localhost:8000"
    
    def test_get_users_returns_list(self):
        response = requests.get(f"{self.BASE_URL}/users")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        
        data = response.json()
        assert isinstance(data, list)
        assert "id" in data[0]
        assert "name" in data[0]
    
    def test_create_user(self):
        new_user = {"name": "John", "email": "john@example.com"}
        
        response = requests.post(
            f"{self.BASE_URL}/users",
            json=new_user
        )
        
        assert response.status_code == 201
        assert response.json()["name"] == "John"
        assert "id" in response.json()
    
    def test_get_nonexistent_user_returns_404(self):
        response = requests.get(f"{self.BASE_URL}/users/999999")
        assert response.status_code == 404
```

**Go**
```go
func TestUserAPI(t *testing.T) {
    // Setup test server
    router := setupRouter()
    ts := httptest.NewServer(router)
    defer ts.Close()
    
    t.Run("GET /users returns list", func(t *testing.T) {
        resp, err := http.Get(ts.URL + "/users")
        if err != nil {
            t.Fatal(err)
        }
        defer resp.Body.Close()
        
        if resp.StatusCode != 200 {
            t.Errorf("status = %d; want 200", resp.StatusCode)
        }
        
        var users []User
        json.NewDecoder(resp.Body).Decode(&users)
        
        if len(users) == 0 {
            t.Error("expected users list")
        }
    })
    
    t.Run("POST /users creates user", func(t *testing.T) {
        newUser := map[string]string{
            "name": "John",
            "email": "john@example.com",
        }
        body, _ := json.Marshal(newUser)
        
        resp, err := http.Post(
            ts.URL+"/users",
            "application/json",
            bytes.NewBuffer(body),
        )
        if err != nil {
            t.Fatal(err)
        }
        defer resp.Body.Close()
        
        if resp.StatusCode != 201 {
            t.Errorf("status = %d; want 201", resp.StatusCode)
        }
    })
}
```

### 2. Database Integration Testing

**JavaScript (Testcontainers)**
```javascript
const { GenericContainer } = require('testcontainers');

describe('Database Integration', () => {
  let container;
  let db;
  
  beforeAll(async () => {
    container = await new GenericContainer('postgres:15')
      .withExposedPorts(5432)
      .withEnvironment({
        POSTGRES_USER: 'test',
        POSTGRES_PASSWORD: 'test',
        POSTGRES_DB: 'testdb',
      })
      .start();
    
    const port = container.getMappedPort(5432);
    db = new Database({
      host: 'localhost',
      port,
      user: 'test',
      password: 'test',
      database: 'testdb',
    });
    await db.migrate();
  }, 30000);
  
  afterAll(async () => {
    await db.close();
    await container.stop();
  });
  
  beforeEach(async () => {
    await db.truncate('users');
  });
  
  test('saves and retrieves user', async () => {
    const userRepo = new UserRepository(db);
    
    const id = await userRepo.create({
      name: 'John',
      email: 'john@example.com',
    });
    
    const user = await userRepo.findById(id);
    expect(user.name).toBe('John');
    expect(user.email).toBe('john@example.com');
  });
});
```

**Python (pytest-postgresql)**
```python
import pytest
from sqlalchemy import create_engine
from myapp.models import Base, User
from myapp.repository import UserRepository

@pytest.fixture(scope="session")
def database():
    """Create test database"""
    from testing.postgresql import Postgresql
    with Postgresql() as postgresql:
        engine = create_engine(postgresql.url())
        Base.metadata.create_all(engine)
        yield engine

@pytest.fixture
def db_session(database):
    """Create fresh session for each test"""
    connection = database.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

class TestUserRepository:
    def test_saves_and_retrieves_user(self, db_session):
        repo = UserRepository(db_session)
        
        user_id = repo.create(
            name="John",
            email="john@example.com"
        )
        
        user = repo.find_by_id(user_id)
        assert user.name == "John"
        assert user.email == "john@example.com"
    
    def test_find_by_email(self, db_session):
        repo = UserRepository(db_session)
        repo.create(name="John", email="john@example.com")
        
        user = repo.find_by_email("john@example.com")
        assert user is not None
        assert user.name == "John"
```

### 3. Service Integration Testing

**JavaScript**
```javascript
describe('OrderService Integration', () => {
  let orderService;
  let paymentService;
  let inventoryService;
  
  beforeAll(async () => {
    // Start dependent services or use test containers
    paymentService = await startPaymentService();
    inventoryService = await startInventoryService();
    
    orderService = new OrderService({
      payment: paymentService.url,
      inventory: inventoryService.url,
    });
  });
  
  test('processes complete order workflow', async () => {
    const order = {
      items: [{ id: 'item1', quantity: 2 }],
      payment: { method: 'card', token: 'tok_visa' },
      customer: { email: 'customer@example.com' },
    };
    
    const result = await orderService.process(order);
    
    expect(result.status).toBe('completed');
    expect(result.paymentId).toBeDefined();
    
    // Verify inventory was updated
    const inventory = await inventoryService.getStock('item1');
    expect(inventory.reserved).toBe(2);
  });
});
```

## Multi-Language Examples

### End-to-End Workflow Test

**Python (API + Database)**
```python
class TestOrderWorkflow:
    """Test complete order placement workflow"""
    
    def test_customer_can_place_order(self, client, db):
        # Arrange: Create customer and products
        customer = create_customer(db, name="John")
        product = create_product(db, name="Widget", price=29.99, stock=10)
        
        # Act: Place order via API
        response = client.post("/orders", json={
            "customer_id": customer.id,
            "items": [{"product_id": product.id, "quantity": 2}]
        })
        
        # Assert: Order created
        assert response.status_code == 201
        order_id = response.json()["id"]
        
        # Assert: Database state updated
        order = db.query(Order).get(order_id)
        assert order.total == 59.98
        assert order.status == "confirmed"
        
        # Assert: Inventory reduced
        product = db.query(Product).get(product.id)
        assert product.stock == 8
        
        # Assert: Payment processed (via mock or test payment service)
        assert order.payment_status == "paid"
```

**JavaScript (Full Stack)**
```javascript
describe('Order Workflow', () => {
  test('complete purchase flow', async () => {
    // Setup: Create test data
    const customer = await createCustomer({ name: 'John' });
    const product = await createProduct({ 
      name: 'Widget', 
      price: 29.99,
      stock: 10 
    });
    
    // Execute: Add to cart and checkout
    await page.goto('/shop');
    await page.click(`[data-product="${product.id}"]`);
    await page.click('#checkout');
    await page.fill('#email', customer.email);
    await page.fill('#card', '4242424242424242');
    await page.click('#submit-order');
    
    // Verify: Success page
    await expect(page).toHaveText('Order confirmed');
    
    // Verify: Database updated
    const order = await db.query(
      'SELECT * FROM orders WHERE customer_id = $1',
      [customer.id]
    );
    expect(order.total).toBe(29.99);
    expect(order.status).toBe('confirmed');
  });
});
```

## Best Practices

### Test Data Management

```javascript
// factories.js - Create test data
const factory = {
  async createUser(overrides = {}) {
    return db.insert('users', {
      name: 'Test User',
      email: `test${Date.now()}@example.com`,
      ...overrides,
    });
  },
  
  async createProduct(overrides = {}) {
    return db.insert('products', {
      name: 'Test Product',
      price: 19.99,
      stock: 100,
      ...overrides,
    });
  },
};
```

### Cleanup Strategy

```python
@pytest.fixture(autouse=True)
def cleanup(db):
    yield
    # Cleanup after each test
    db.execute("TRUNCATE orders, order_items CASCADE")
```

### Health Checks

```javascript
beforeAll(async () => {
  // Wait for services to be ready
  await waitFor(async () => {
    const response = await fetch(`${apiUrl}/health`);
    return response.status === 200;
  }, { timeout: 30000 });
});
```

## Common Pitfalls

❌ **Testing with production data**
- Always use isolated test databases
- Never run integration tests against production

❌ **Not cleaning up**
- Leftover data causes flaky tests
- Use transactions or cleanup fixtures

❌ **External dependencies without fallbacks**
```javascript
// Bad: tests fail when external service is down
const result = await realPaymentAPI.charge(...);

// Good: use test doubles for external services
const result = await processPayment(useTestDouble ? mockAPI : realAPI);
```

## Validation Checklist

- [ ] Tests use isolated test environments
- [ ] Test data is created and cleaned up properly
- [ ] External services are handled (mocked or test instances)
- [ ] Tests verify real interactions, not mocks
- [ ] Tests are deterministic (no race conditions)
- [ ] Services are healthy before tests run
- [ ] Database migrations run before tests

## Related Skills

- **unit-testing** — Use for isolated component testing
- **test-doubles** — Mock external dependencies
- **test-data-management** — Create test data for integration tests
