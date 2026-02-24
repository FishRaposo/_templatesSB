---
name: test-data-management
description: Use this skill when creating and managing test data for unit and integration tests. This includes building data factories, managing fixtures, generating realistic test data, handling database state between tests, and ensuring test isolation through proper data setup and teardown.
---

# Test Data Management

I'll help you create and manage test data effectively — using factories, fixtures, and seed data to ensure tests are isolated, realistic, and maintainable.

## Core Approach

### Strategies by Test Type

| Type | Strategy | Data Source |
|------|----------|-------------|
| **Unit** | Generated/fake data | Factories, Faker |
| **Integration** | Test database | Migrations + seeders |
| **E2E** | Realistic scenarios | Production-like data |
| **Performance** | Production volume | Data generators |

### Principles

- **Isolation**: Each test creates its own data
- **Realism**: Data looks like production
- **Speed**: Data creation is fast
- **Maintainability**: Easy to update

## Step-by-Step Instructions

### 1. Create Data Factories

**JavaScript (faker.js)**
```javascript
// factories/user.js
const { faker } = require('@faker-js/faker');

class UserFactory {
  static create(overrides = {}) {
    return {
      id: faker.string.uuid(),
      name: faker.person.fullName(),
      email: faker.internet.email(),
      createdAt: faker.date.past(),
      ...overrides,
    };
  }
  
  static createMany(count, overrides = {}) {
    return Array.from({ length: count }, () => this.create(overrides));
  }
}

// Usage
test('creates user', () => {
  const user = UserFactory.create({ name: 'John' });
  expect(user.name).toBe('John');
  expect(user.email).toContain('@');
});
```

**Python (factory_boy)**
```python
import factory
from factory import Faker
from myapp.models import User, Order

class UserFactory(factory.Factory):
    class Meta:
        model = User
    
    name = Faker('name')
    email = Faker('email')
    created_at = Faker('date_time')

class OrderFactory(factory.Factory):
    class Meta:
        model = Order
    
    user = factory.SubFactory(UserFactory)
    total = factory.LazyAttribute(lambda o: sum(item.price for item in o.items))
    status = 'pending'

# Usage
def test_order_creation():
    user = UserFactory(name="Test User")
    order = OrderFactory(user=user, status="confirmed")
    
    assert order.user.name == "Test User"
    assert order.status == "confirmed"
```

**Go**
```go
package testutil

import (
    "github.com/brianvoe/gofakeit/v6"
    "myapp/models"
)

func NewUser(overrides map[string]interface{}) models.User {
    user := models.User{
        ID:        gofakeit.UUID(),
        Name:      gofakeit.Name(),
        Email:     gofakeit.Email(),
        CreatedAt: gofakeit.Date(),
    }
    
    for k, v := range overrides {
        switch k {
        case "Name":
            user.Name = v.(string)
        case "Email":
            user.Email = v.(string)
        }
    }
    
    return user
}

func NewUsers(n int) []models.User {
    users := make([]models.User, n)
    for i := range users {
        users[i] = NewUser(nil)
    }
    return users
}
```

### 2. Manage Database State

**JavaScript (Setup/Teardown)**
```javascript
// Test with database isolation
describe('OrderService', () => {
  let db;
  
  beforeAll(async () => {
    db = await setupTestDatabase();
  });
  
  afterAll(async () => {
    await db.close();
  });
  
  beforeEach(async () => {
    await db.truncate('orders', 'users');
  });
  
  test('creates order', async () => {
    const user = await db.insert('users', UserFactory.create());
    const order = await createOrder(user.id, { total: 100 });
    
    expect(order.userId).toBe(user.id);
    expect(order.total).toBe(100);
  });
});
```

**Python (pytest fixtures)**
```python
import pytest
from myapp.database import db_session

@pytest.fixture(scope="function")
def database():
    """Fresh database for each test"""
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture
def user(database):
    """Create a test user"""
    user = UserFactory()
    database.add(user)
    database.commit()
    return user

def test_user_orders(database, user):
    order = OrderFactory(user=user)
    database.add(order)
    database.commit()
    
    assert user.orders[0].id == order.id
```

**Go (test transactions)**
```go
func TestOrderCreation(t *testing.T) {
    db := setupTestDB(t)
    defer db.Rollback()
    
    user := testutil.NewUser(nil)
    db.Create(&user)
    
    order := models.Order{UserID: user.ID, Total: 100}
    db.Create(&order)
    
    var found models.Order
    db.First(&found, order.ID)
    
    if found.Total != 100 {
        t.Errorf("expected total 100, got %d", found.Total)
    }
}
```

### 3. Use Fixtures for Common Data

**JavaScript**
```javascript
// fixtures/orders.js
module.exports = {
  standardOrder: {
    id: 'order-123',
    items: [
      { sku: 'SKU-001', quantity: 2, price: 29.99 },
      { sku: 'SKU-002', quantity: 1, price: 15.00 },
    ],
    total: 74.98,
    status: 'confirmed',
  },
  
  cancelledOrder: {
    id: 'order-456',
    items: [{ sku: 'SKU-003', quantity: 1, price: 50.00 }],
    total: 50.00,
    status: 'cancelled',
    cancelledAt: '2024-01-15T10:00:00Z',
  },
};

// test
test('calculates refund for cancelled order', () => {
  const refund = calculateRefund(fixtures.cancelledOrder);
  expect(refund).toBe(50.00);
});
```

**Python**
```python
# conftest.py
import pytest

@pytest.fixture
def standard_order():
    return {
        "id": "order-123",
        "items": [
            {"sku": "SKU-001", "quantity": 2, "price": 29.99},
        ],
        "total": 59.98,
        "status": "confirmed",
    }

@pytest.fixture
def cancelled_order():
    return {
        "id": "order-456",
        "items": [{"sku": "SKU-003", "quantity": 1, "price": 50.00}],
        "total": 50.00,
        "status": "cancelled",
    }

def test_refund_calculation(cancelled_order):
    refund = calculate_refund(cancelled_order)
    assert refund == 50.00
```

### 4. Generate Realistic Data at Scale

**JavaScript**
```javascript
// Generate 10,000 users for performance testing
const generateUsers = (count) => {
  return Array.from({ length: count }, (_, i) => ({
    id: `user-${i}`,
    name: faker.person.fullName(),
    email: faker.internet.email(),
    registrationDate: faker.date.past({ years: 2 }),
    purchaseCount: faker.number.int({ min: 0, max: 50 }),
    totalSpent: faker.number.float({ min: 0, max: 5000, fractionDigits: 2 }),
  }));
};

// Insert in batches for performance
const batchInsert = async (table, data, batchSize = 1000) => {
  for (let i = 0; i < data.length; i += batchSize) {
    const batch = data.slice(i, i + batchSize);
    await db.insert(table, batch);
  }
};
```

**Python**
```python
def generate_realistic_orders(num_orders=1000):
    """Generate orders with realistic distributions"""
    orders = []
    
    for i in range(num_orders):
        # 70% of orders are standard, 20% large, 10% small
        order_type = random.choices(
            ['standard', 'large', 'small'],
            weights=[0.7, 0.2, 0.1]
        )[0]
        
        if order_type == 'standard':
            item_count = random.randint(1, 5)
        elif order_type == 'large':
            item_count = random.randint(10, 50)
        else:
            item_count = 1
        
        orders.append({
            'id': f'order-{i}',
            'item_count': item_count,
            'total': round(random.uniform(10, 500), 2),
            'status': random.choices(
                ['confirmed', 'shipped', 'delivered'],
                weights=[0.6, 0.3, 0.1]
            )[0],
        })
    
    return orders
```

## Multi-Language Examples

### Complex Object Graphs

**JavaScript**
```javascript
// Build complete order with nested objects
const buildOrder = (overrides = {}) => {
  const user = UserFactory.create(overrides.user);
  const items = (overrides.items || ItemFactory.createMany(3))
    .map(item => ({
      ...item,
      product: ProductFactory.create(),
    }));
  
  return {
    id: faker.string.uuid(),
    user,
    items,
    shippingAddress: AddressFactory.create(),
    billingAddress: overrides.billingAddress || AddressFactory.create(),
    payment: PaymentFactory.create(),
    createdAt: new Date(),
    ...overrides,
  };
};
```

**Python (factory_boy with relations)**
```python
class ProductFactory(factory.Factory):
    class Meta:
        model = Product
    
    name = factory.Sequence(lambda n: f"Product {n}")
    price = factory.Faker('pydecimal', left_digits=3, right_digits=2, positive=True)
    category = factory.SubFactory(CategoryFactory)

class OrderItemFactory(factory.Factory):
    class Meta:
        model = OrderItem
    
    order = factory.SubFactory(OrderFactory)
    product = factory.SubFactory(ProductFactory)
    quantity = factory.Faker('random_int', min=1, max=10)
    price_at_purchase = factory.SelfAttribute('.product.price')

# Create order with 3 items
order = OrderFactory()
OrderItemFactory.create_batch(3, order=order)
```

## Best Practices

### Factory Guidelines

✅ **Use sequences for unique fields**
```javascript
// Good: unique values
email: factory.sequence(n => `user${n}@example.com`)

// Bad: potential collisions
email: 'test@example.com'
```

✅ **Make overrides easy**
```python
# Good: simple override
user = UserFactory(name="Specific Name")

# Good: override nested
order = OrderFactory(user__name="Specific Name")
```

✅ **Keep factories in sync with models**
```python
# When model changes, update factory
class UserFactory:
    # All required fields have defaults
    required_field = 'default'
```

### Database Isolation

```python
# Fast: Rollback transaction
@pytest.fixture
def db():
    transaction = connection.begin()
    yield session
    transaction.rollback()

# Slower: Truncate tables
@pytest.fixture
def db():
    yield session
    truncate_all_tables()

# Slowest: Recreate database
@pytest.fixture(scope="function")
def db():
    create_fresh_database()
    yield session
    drop_database()
```

### Test Data Cleanup

**Automatic cleanup with context managers:**
```python
@pytest.fixture
def temp_user():
    user = create_user()
    yield user
    # Cleanup runs after test
    delete_user(user.id)
```

## Common Pitfalls

❌ **Shared mutable state**
```javascript
// Bad: data modified by one test affects others
const sharedData = { count: 0 };

test('increments', () => {
  sharedData.count++;
  expect(sharedData.count).toBe(1);
});
```

❌ **Hard-coded IDs causing collisions**
```javascript
// Bad: duplicate IDs
test('test 1', () => {
  db.insert({ id: 1, name: 'A' });
});

test('test 2', () => {
  db.insert({ id: 1, name: 'B' });  // Collision!
});
```

❌ **Unrealistic data**
```python
# Bad: doesn't reflect production
user = User(name="Test", email="test@test.com")

# Good: realistic variety
user = UserFactory()  # John Smith, john.smith@example.com
```

## Validation Checklist

- [ ] Each test creates/isolates its own data
- [ ] Factories generate realistic data
- [ ] Database state is cleaned between tests
- [ ] Test data creation is fast (< 100ms)
- [ ] Complex object graphs can be built easily
- [ ] Fixtures exist for commonly used data
- [ ] Tests don't depend on data order
- [ ] Data schema changes are easy to propagate

## Related Skills

- **unit-testing** — Use factories for test data
- **integration-testing** — Manage database state
- **test-automation** — Seed data in CI
