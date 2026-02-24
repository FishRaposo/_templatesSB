# Test Doubles

Use mocks, stubs, fakes, and spies to isolate code from dependencies.

## Types of Test Doubles

| Type | Purpose | Use When |
|------|---------|----------|
| **Stub** | Provides canned answers | Need predefined responses |
| **Mock** | Verifies interactions | Need to verify calls were made |
| **Fake** | Working implementation (simplified) | Need functional but lightweight version |
| **Spy** | Records interactions | Need to capture and inspect calls |

## Quick Example

```javascript
// Create mock
const paymentMock = {
  charge: jest.fn().mockResolvedValue({ id: 'pay_123' })
};

// Inject and test
const service = new OrderService(paymentMock, ...);
const result = await service.processOrder(order);

// Verify interaction
expect(paymentMock.charge).toHaveBeenCalledWith(order.total);
```

## When to Use

- External services (APIs, databases)
- Slow or non-deterministic dependencies
- Components not yet implemented
- Complex setup requirements

## Key Rules

- Mock at **boundaries**, not internals
- Don't mock what you don't own
- Verify critical interactions
- Keep doubles simple

## Python Example

```python
from unittest.mock import Mock, patch

# Create mock
payment = Mock()
payment.charge.return_value = {"id": "pay_123"}

# Patch decorator
@patch('module.ExternalAPI')
def test_process(mock_api):
    mock_api.call.return_value = {"status": "ok"}
    # test code
```

## Go Example

```go
type MockPayment struct {
    chargeFunc func(float64) (*Payment, error)
}

func (m *MockPayment) Charge(amount float64) (*Payment, error) {
    return m.chargeFunc(amount)
}
```

## Examples

See `examples/basic-examples.md` for full test double examples.

## Related Skills

- `unit-testing` — Use doubles to isolate units
- `integration-testing` — Don't use doubles; test real interactions
