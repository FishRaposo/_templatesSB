# Test Data Management Examples

## Data Factory (JavaScript)

```javascript
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

class OrderFactory {
  static create(overrides = {}) {
    return {
      id: faker.string.uuid(),
      user: overrides.user || UserFactory.create(),
      total: faker.number.float({ min: 10, max: 500, precision: 0.01 }),
      status: faker.helpers.arrayElement(['pending', 'confirmed', 'shipped']),
      items: overrides.items || [],
      ...overrides,
    };
  }
}

// Usage
const user = UserFactory.create({ name: 'John' });
const users = UserFactory.createMany(10);
const order = OrderFactory.create({ user, items: [/* ... */] });
```

## Python (factory_boy)

```python
import factory
from factory import Faker

class UserFactory(factory.Factory):
    class Meta:
        model = User
    
    name = Faker('name')
    email = Faker('email')
    created_at = Faker('date_time')

class ProductFactory(factory.Factory):
    class Meta:
        model = Product
    
    name = Faker('product_name')
    price = factory.Faker('pydecimal', left_digits=3, right_digits=2)
    stock = factory.Faker('random_int', min=10, max=100)

class OrderFactory(factory.Factory):
    class Meta:
        model = Order
    
    user = factory.SubFactory(UserFactory)
    total = 0
    status = 'pending'

# Usage
user = UserFactory(name="Test User")
product = ProductFactory(stock=50)
order = OrderFactory(user=user)
```

## Database Isolation (Python)

```python
import pytest

@pytest.fixture
def database():
    """Fresh database transaction for each test"""
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture
def user(database):
    """Create test user"""
    user = UserFactory()
    database.add(user)
    database.commit()
    return user
```

## Fixtures (JavaScript)

```javascript
// fixtures/orders.js
module.exports = {
  standardOrder: {
    id: 'order-123',
    items: [
      { sku: 'SKU-001', quantity: 2, price: 29.99 },
    ],
    total: 59.98,
    status: 'confirmed',
  },
  
  cancelledOrder: {
    id: 'order-456',
    items: [{ sku: 'SKU-003', quantity: 1, price: 50.00 }],
    total: 50.00,
    status: 'cancelled',
  },
};
```

## Best Practices

- Use factories for realistic test data
- Isolate database state between tests
- Generate unique values to avoid collisions
- Clean up resources in teardown
