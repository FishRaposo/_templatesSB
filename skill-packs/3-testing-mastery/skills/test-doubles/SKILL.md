---
name: test-doubles
description: Use this skill when creating mocks, stubs, fakes, and spies to isolate code under test from its dependencies. This includes replacing external services, databases, APIs, and complex objects with controllable test doubles that simulate real behavior for testing purposes.
---

# Test Doubles

I'll help you isolate code under test by replacing dependencies with test doubles — mocks, stubs, fakes, and spies. This enables fast, deterministic unit tests.

## Core Approach

### Types of Test Doubles

| Type | Purpose | Use When |
|------|---------|----------|
| **Stub** | Provides canned answers | Need predefined responses |
| **Mock** | Verifies interactions | Need to verify calls were made |
| **Fake** | Working implementation (simplified) | Need functional but lightweight version |
| **Spy** | Records interactions for later verification | Need to capture and inspect calls |

### When to Use Test Doubles

- External services (APIs, databases, message queues)
- Slow or non-deterministic dependencies
- Components not yet implemented
- Complex setup requirements

## Step-by-Step Instructions

### 1. Identify Dependencies to Replace

```javascript
// Code under test has dependencies:
class OrderService {
  constructor(paymentGateway, inventoryService, emailService) {
    this.payment = paymentGateway;
    this.inventory = inventoryService;
    this.email = emailService;
  }
  
  async processOrder(order) {
    const payment = await this.payment.charge(order.total);
    await this.inventory.reserve(order.items);
    await this.email.sendConfirmation(order.customer);
    return payment.id;
  }
}
```

### 2. Create Test Doubles

**JavaScript (Jest)**
```javascript
// Stubs - return canned responses
const paymentStub = {
  charge: jest.fn().mockResolvedValue({ id: 'pay_123', status: 'success' })
};

const inventoryStub = {
  reserve: jest.fn().mockResolvedValue(true)
};

// Mock with verification
const emailMock = {
  sendConfirmation: jest.fn().mockResolvedValue(true)
};

// Spy on existing object
const logger = { log: jest.fn() };
```

**Python (pytest + unittest.mock)**
```python
from unittest.mock import Mock, MagicMock, patch

# Stub
payment_stub = Mock()
payment_stub.charge.return_value = {"id": "pay_123", "status": "success"}

# Mock with side effects
inventory_mock = Mock()
inventory_mock.reserve.return_value = True

# Spy
logger = Mock()
logger.log = Mock()

# Patch decorator
@patch('module.ExternalAPI')
def test_process(mock_api):
    mock_api.call.return_value = {"status": "ok"}
    # test code
```

**Go (gomock or manual interfaces)**
```go
// Define interface for dependency
type PaymentGateway interface {
    Charge(amount float64) (*Payment, error)
}

// Manual mock
type MockPaymentGateway struct {
    chargeFunc func(float64) (*Payment, error)
    calls      []float64  // spy
}

func (m *MockPaymentGateway) Charge(amount float64) (*Payment, error) {
    m.calls = append(m.calls, amount)
    return m.chargeFunc(amount)
}

// Usage in test
mockPayment := &MockPaymentGateway{
    chargeFunc: func(a float64) (*Payment, error) {
        return &Payment{ID: "pay_123", Status: "success"}, nil
    },
}
```

### 3. Inject Doubles and Test

**JavaScript**
```javascript
describe('OrderService', () => {
  test('processes order and sends email', async () => {
    // Arrange
    const payment = { charge: jest.fn().mockResolvedValue({ id: 'pay_123' }) };
    const inventory = { reserve: jest.fn().mockResolvedValue(true) };
    const email = { sendConfirmation: jest.fn().mockResolvedValue(true) };
    const service = new OrderService(payment, inventory, email);
    
    const order = { total: 100, items: ['item1'], customer: 'john@example.com' };
    
    // Act
    const result = await service.processOrder(order);
    
    // Assert - behavior verification
    expect(payment.charge).toHaveBeenCalledWith(100);
    expect(inventory.reserve).toHaveBeenCalledWith(['item1']);
    expect(email.sendConfirmation).toHaveBeenCalledWith('john@example.com');
    expect(result).toBe('pay_123');
  });
  
  test('fails when payment fails', async () => {
    const payment = { 
      charge: jest.fn().mockRejectedValue(new Error('Card declined')) 
    };
    // ... setup other stubs
    
    await expect(service.processOrder(order))
      .rejects.toThrow('Card declined');
    
    // Verify inventory was NOT called
    expect(inventory.reserve).not.toHaveBeenCalled();
  });
});
```

**Python**
```python
from unittest.mock import Mock, call

class TestOrderService:
    def test_processes_order_and_sends_email(self):
        payment = Mock()
        payment.charge.return_value = {"id": "pay_123"}
        
        inventory = Mock()
        inventory.reserve.return_value = True
        
        email = Mock()
        email.send_confirmation.return_value = True
        
        service = OrderService(payment, inventory, email)
        order = {"total": 100, "items": ["item1"], "customer": "john@example.com"}
        
        result = service.process_order(order)
        
        # Verify interactions
        payment.charge.assert_called_once_with(100)
        inventory.reserve.assert_called_once_with(["item1"])
        email.send_confirmation.assert_called_once_with("john@example.com")
        assert result == "pay_123"
    
    def test_fails_when_payment_fails(self):
        payment = Mock()
        payment.charge.side_effect = Exception("Card declined")
        # ... setup
        
        with pytest.raises(Exception, match="Card declined"):
            service.process_order(order)
        
        # Verify inventory was NOT called
        inventory.reserve.assert_not_called()
```

## Multi-Language Examples

### Mocking HTTP Requests

**JavaScript (Jest)**
```javascript
// Mock fetch globally
global.fetch = jest.fn();

describe('API Client', () => {
  test('fetches user data', async () => {
    fetch.mockResolvedValueOnce({
      ok: true,
      json: jest.fn().mockResolvedValue({ id: 1, name: 'John' })
    });
    
    const user = await apiClient.getUser(1);
    
    expect(fetch).toHaveBeenCalledWith('/api/users/1');
    expect(user).toEqual({ id: 1, name: 'John' });
  });
  
  test('throws on error response', async () => {
    fetch.mockResolvedValueOnce({ ok: false, status: 404 });
    
    await expect(apiClient.getUser(999))
      .rejects.toThrow('User not found');
  });
});
```

**Python (responses library)**
```python
import responses

@responses.activate
def test_fetches_user_data():
    responses.add(
        responses.GET,
        'https://api.example.com/users/1',
        json={'id': 1, 'name': 'John'},
        status=200
    )
    
    client = APIClient()
    user = client.get_user(1)
    
    assert user == {'id': 1, 'name': 'John'}
    assert len(responses.calls) == 1
```

**Python (unittest.mock)**
```python
from unittest.mock import patch, Mock

@patch('requests.get')
def test_fetches_user_data(mock_get):
    mock_get.return_value = Mock(
        ok=True,
        json=lambda: {'id': 1, 'name': 'John'}
    )
    
    client = APIClient()
    user = client.get_user(1)
    
    mock_get.assert_called_with('https://api.example.com/users/1')
    assert user['name'] == 'John'
```

### Fake Database

**JavaScript**
```javascript
// Fake: In-memory database
class FakeDatabase {
  constructor() {
    this.users = new Map();
    this.id = 1;
  }
  
  async save(user) {
    const id = this.id++;
    this.users.set(id, { ...user, id });
    return id;
  }
  
  async findById(id) {
    return this.users.get(id);
  }
  
  async findByEmail(email) {
    return Array.from(this.users.values()).find(u => u.email === email);
  }
}

// Test using fake
describe('UserRepository', () => {
  test('saves and retrieves user', async () => {
    const db = new FakeDatabase();
    const repo = new UserRepository(db);
    
    const id = await repo.save({ name: 'John', email: 'john@example.com' });
    const user = await repo.findById(id);
    
    expect(user.name).toBe('John');
  });
});
```

**Python**
```python
class FakeDatabase:
    def __init__(self):
        self.users = {}
        self.id_counter = 1
    
    def save(self, user):
        user_id = self.id_counter
        self.id_counter += 1
        self.users[user_id] = {**user, "id": user_id}
        return user_id
    
    def find_by_id(self, user_id):
        return self.users.get(user_id)

class TestUserRepository:
    def test_saves_and_retrieves_user(self):
        db = FakeDatabase()
        repo = UserRepository(db)
        
        user_id = repo.save({"name": "John", "email": "john@example.com"})
        user = repo.find_by_id(user_id)
        
        assert user["name"] == "John"
```

## Best Practices

### Stub vs Mock

**Use Stubs** when you only need canned responses:
```javascript
const stub = { getUser: () => ({ id: 1, name: 'John' }) };
```

**Use Mocks** when you need to verify interactions:
```javascript
const mock = { save: jest.fn().mockResolvedValue(true) };
// ... later
expect(mock.save).toHaveBeenCalledWith(expectedData);
```

### Avoid Over-Mocking

❌ **Bad: mocking internal implementation details**
```javascript
const service = {
  _internalHelper: jest.fn()  // Don't mock private methods
};
```

✅ **Good: mocking external boundaries**
```javascript
const service = new Service(mockDatabase, mockApi);  // Mock at boundaries
```

### Matchers for Flexible Assertions

**JavaScript**
```javascript
expect(mock).toHaveBeenCalledWith(expect.any(String));
expect(mock).toHaveBeenCalledWith(expect.objectContaining({ id: 1 }));
```

**Python**
```python
from unittest.mock import ANY, call
mock.method.assert_called_with(ANY, name='John')
```

## Common Pitfalls

❌ **Mocking what you don't own**
- Don't mock third-party libraries directly
- Wrap them in your own abstraction, then mock the wrapper

❌ **Over-specified tests**
```javascript
// Bad: tests will break on minor changes
expect(mock).toHaveBeenCalledWith(exactObject);

// Good: flexible matching
expect(mock).toHaveBeenCalledWith(expect.objectContaining({ id: 1 }));
```

❌ **Not verifying important interactions**
```javascript
// Bad: no verification
await service.process();
// Did it actually save?

// Good: verify critical side effects
await service.process();
expect(repository.save).toHaveBeenCalled();
```

## Validation Checklist

- [ ] Only mock at system boundaries (external services, I/O)
- [ ] Don't mock internal implementation details
- [ ] Verify critical interactions when using mocks
- [ ] Use stubs for simple canned responses
- [ ] Keep test doubles simple — they should be obviously correct
- [ ] Use fakes for complex stateful dependencies
- [ ] Test doubles are tested if complex

## Related Skills

- **unit-testing** — Use test doubles to isolate units
- **integration-testing** — Don't use doubles; test real interactions
- **test-driven-development** — TDD often requires test doubles
