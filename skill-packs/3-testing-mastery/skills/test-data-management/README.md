# Test Data Management

Create and manage test data using factories, fixtures, and seed data.

## Quick Start

```javascript
// Factory
class UserFactory {
  static create(overrides = {}) {
    return {
      id: faker.string.uuid(),
      name: faker.person.fullName(),
      email: faker.internet.email(),
      ...overrides,
    };
  }
}

// Usage
const user = UserFactory.create({ name: 'John' });
```

## Strategies

| Type | Strategy |
|------|----------|
| Unit | Generated/fake data |
| Integration | Test database |
| E2E | Realistic scenarios |

## Database Isolation

```python
@pytest.fixture
def database():
    transaction = connection.begin()
    yield session
    transaction.rollback()  # Clean up
```

## Python (factory_boy)

```python
class UserFactory(factory.Factory):
    class Meta:
        model = User
    
    name = factory.Faker('name')
    email = factory.Faker('email')

# Usage
user = UserFactory(name="Test")
```

## Key Principles

- **Isolation**: Each test creates its own data
- **Realism**: Data looks like production
- **Speed**: Data creation is fast
- **Maintainability**: Easy to update

## Examples

See `examples/basic-examples.md` for full test data management examples.

## Related Skills

- `unit-testing` — Use factories for test data
- `integration-testing` — Manage database state
