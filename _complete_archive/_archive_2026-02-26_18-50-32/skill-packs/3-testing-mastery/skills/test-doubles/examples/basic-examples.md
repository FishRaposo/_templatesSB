# Test Doubles Examples

## Mocking a Payment Gateway

### JavaScript (Jest)

```javascript
// PaymentService depends on PaymentGateway
class PaymentService {
  constructor(gateway) {
    this.gateway = gateway;
  }
  
  async processPayment(amount, cardToken) {
    const result = await this.gateway.charge({
      amount,
      token: cardToken,
      currency: 'USD'
    });
    
    return {
      success: result.status === 'success',
      transactionId: result.id,
      amount: result.amount
    };
  }
}

// Test with mock
describe('PaymentService', () => {
  test('processes successful payment', async () => {
    // Create mock
    const mockGateway = {
      charge: jest.fn().mockResolvedValue({
        id: 'txn_123',
        status: 'success',
        amount: 100
      })
    };
    
    const service = new PaymentService(mockGateway);
    const result = await service.processPayment(100, 'tok_visa');
    
    // Verify result
    expect(result.success).toBe(true);
    expect(result.transactionId).toBe('txn_123');
    
    // Verify mock was called correctly
    expect(mockGateway.charge).toHaveBeenCalledWith({
      amount: 100,
      token: 'tok_visa',
      currency: 'USD'
    });
  });
  
  test('handles payment failure', async () => {
    const mockGateway = {
      charge: jest.fn().mockRejectedValue(
        new Error('Card declined')
      )
    };
    
    const service = new PaymentService(mockGateway);
    
    await expect(service.processPayment(100, 'tok_visa'))
      .rejects.toThrow('Card declined');
  });
});
```

### Python (unittest.mock)

```python
from unittest.mock import Mock, MagicMock
import pytest

class PaymentService:
    def __init__(self, gateway):
        self.gateway = gateway
    
    def process_payment(self, amount, card_token):
        result = self.gateway.charge(
            amount=amount,
            token=card_token,
            currency='USD'
        )
        return {
            'success': result['status'] == 'success',
            'transaction_id': result['id'],
            'amount': result['amount']
        }

def test_processes_successful_payment():
    # Create mock
    mock_gateway = Mock()
    mock_gateway.charge.return_value = {
        'id': 'txn_123',
        'status': 'success',
        'amount': 100
    }
    
    service = PaymentService(mock_gateway)
    result = service.process_payment(100, 'tok_visa')
    
    # Verify result
    assert result['success'] is True
    assert result['transaction_id'] == 'txn_123'
    
    # Verify mock called correctly
    mock_gateway.charge.assert_called_with(
        amount=100,
        token='tok_visa',
        currency='USD'
    )

def test_handles_payment_failure():
    mock_gateway = Mock()
    mock_gateway.charge.side_effect = Exception('Card declined')
    
    service = PaymentService(mock_gateway)
    
    with pytest.raises(Exception, match='Card declined'):
        service.process_payment(100, 'tok_visa')
```

## Fake Database

### JavaScript

```javascript
// Fake implementation
class FakeDatabase {
  constructor() {
    this.users = new Map();
    this.nextId = 1;
  }
  
  async insert(table, data) {
    const id = this.nextId++;
    const record = { ...data, id };
    this.users.set(id, record);
    return id;
  }
  
  async findById(table, id) {
    return this.users.get(id);
  }
  
  async clear() {
    this.users.clear();
    this.nextId = 1;
  }
}

// Test with fake
describe('UserRepository', () => {
  let db;
  let repo;
  
  beforeEach(() => {
    db = new FakeDatabase();
    repo = new UserRepository(db);
  });
  
  test('saves and retrieves user', async () => {
    const user = {
      name: 'John',
      email: 'john@example.com'
    };
    
    const id = await repo.save(user);
    const found = await repo.findById(id);
    
    expect(found.name).toBe('John');
    expect(found.email).toBe('john@example.com');
  });
});
```

## Spy on Function Calls

### JavaScript

```javascript
test('logs user action', () => {
  const logger = { log: jest.fn() };
  const service = new UserService(logger);
  
  service.login('john@example.com');
  
  // Spy verifies call
  expect(logger.log).toHaveBeenCalledWith(
    'User logged in: john@example.com'
  );
  expect(logger.log).toHaveBeenCalledTimes(1);
});
```

### Python

```python
def test_logs_user_action():
    logger = Mock()
    service = UserService(logger)
    
    service.login('john@example.com')
    
    # Spy verifies call
    logger.log.assert_called_with('User logged in: john@example.com')
    assert logger.log.call_count == 1
```

## Stub HTTP Requests

### JavaScript (axios mock)

```javascript
import axios from 'axios';
jest.mock('axios');

test('fetches user data', async () => {
  // Stub HTTP response
  axios.get.mockResolvedValue({
    data: { id: 1, name: 'John' }
  });
  
  const api = new UserAPI();
  const user = await api.getUser(1);
  
  expect(user.name).toBe('John');
  expect(axios.get).toHaveBeenCalledWith('/api/users/1');
});
```

### Python (responses)

```python
import responses

@responses.activate
def test_fetches_user_data():
    # Stub HTTP
    responses.add(
        responses.GET,
        'https://api.example.com/users/1',
        json={'id': 1, 'name': 'John'},
        status=200
    )
    
    api = UserAPI()
    user = api.get_user(1)
    
    assert user['name'] == 'John'
```

## Best Practices

- **Mock at boundaries** — external services, APIs, I/O
- **Don't mock internals** — test real code paths
- **Verify critical calls** — ensure important methods were called
- **Keep stubs simple** — obvious, no complex logic
