# Skill Integrations

Examples showing how testing skills work together in realistic scenarios.

## Integration 1: TDD + Unit Testing + Test Doubles

### Scenario: Implementing a Payment Service

**Skills**: test-driven-development, unit-testing, test-doubles

**Approach**:
1. **TDD**: Write failing test for payment processing
2. **Unit Testing**: Test business logic in isolation
3. **Test Doubles**: Mock external payment gateway

```javascript
// RED: Write failing test
describe('PaymentService', () => {
  test('processes payment successfully', async () => {
    // Arrange
    const mockGateway = {
      charge: jest.fn().mockResolvedValue({ id: 'pay_123', status: 'success' })
    };
    const service = new PaymentService(mockGateway);
    
    // Act
    const result = await service.process({
      amount: 100,
      currency: 'USD',
      cardToken: 'tok_visa'
    });
    
    // Assert
    expect(result.success).toBe(true);
    expect(result.paymentId).toBe('pay_123');
    expect(mockGateway.charge).toHaveBeenCalledWith({
      amount: 100,
      currency: 'USD',
      cardToken: 'tok_visa'
    });
  });
  
  test('handles payment failure', async () => {
    const mockGateway = {
      charge: jest.fn().mockRejectedValue(new Error('Card declined'))
    };
    const service = new PaymentService(mockGateway);
    
    await expect(service.process({ amount: 100 }))
      .rejects.toThrow('Card declined');
  });
});

// GREEN: Minimal implementation
class PaymentService {
  constructor(gateway) {
    this.gateway = gateway;
  }
  
  async process(payment) {
    try {
      const result = await this.gateway.charge(payment);
      return {
        success: true,
        paymentId: result.id
      };
    } catch (error) {
      throw new Error(error.message);
    }
  }
}

// REFACTOR: Add validation, logging, etc.
```

**Key Points**:
- TDD drives the API design
- Unit tests verify logic in isolation
- Test doubles enable testing without real payment API
- Fast feedback loop (< 100ms per test)

---

## Integration 2: Integration Testing + Test Data Management

### Scenario: Testing Order API End-to-End

**Skills**: integration-testing, test-data-management

**Approach**:
1. **Test Data Management**: Create realistic orders, users, products
2. **Integration Testing**: Test complete order flow through API

```python
# factories.py
class UserFactory(factory.Factory):
    class Meta:
        model = User
    name = factory.Faker('name')
    email = factory.Faker('email')

class ProductFactory(factory.Factory):
    class Meta:
        model = Product
    name = factory.Faker('product_name')
    price = factory.Faker('pydecimal', left_digits=3, right_digits=2)
    stock = factory.Faker('random_int', min=10, max=100)

class OrderFactory(factory.Factory):
    class Meta:
        model = Order
    user = factory.SubFactory(UserFactory)
    status = 'pending'
    
    @factory.post_generation
    def items(self, create, extracted, **kwargs):
        if not create:
            return
        
        if extracted:
            for item in extracted:
                OrderItemFactory(order=self, product=item)
        else:
            OrderItemFactory.create_batch(2, order=self)

# test_integration.py
@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def sample_order():
    user = UserFactory()
    products = ProductFactory.create_batch(2, stock=10)
    return OrderFactory(user=user, items=products)

class TestOrderAPI:
    def test_create_order(self, api_client):
        user = UserFactory()
        products = ProductFactory.create_batch(2)
        
        response = api_client.post('/orders', {
            'user_id': user.id,
            'items': [
                {'product_id': p.id, 'quantity': 2}
                for p in products
            ]
        })
        
        assert response.status_code == 201
        assert response.json()['status'] == 'confirmed'
        
        # Verify side effects
        for product in products:
            product.refresh_from_db()
            assert product.stock == 8  # Reduced by 2
    
    def test_get_order(self, api_client, sample_order):
        response = api_client.get(f'/orders/{sample_order.id}')
        
        assert response.status_code == 200
        assert response.json()['user']['id'] == sample_order.user.id
        assert len(response.json()['items']) == 2
```

**Key Points**:
- Factories create realistic, isolated test data
- Integration tests verify complete workflow
- Database state verified after API calls
- Test containers provide clean database per test

---

## Integration 3: BDD + Integration Testing

### Scenario: User Registration Flow

**Skills**: behavior-driven-development, integration-testing

**Approach**:
1. **BDD**: Define behavior with Gherkin scenarios
2. **Integration Testing**: Implement step definitions against real API

```gherkin
# features/registration.feature
Feature: User Registration
  As a new user
  I want to register an account
  So that I can access the application

  Scenario: Successful registration
    Given the API is running
    When I send a POST request to "/register" with:
      """
      {
        "name": "John Doe",
        "email": "john@example.com",
        "password": "Secure123!"
      }
      """
    Then the response status should be 201
    And the response should contain a user ID
    And a welcome email should be queued

  Scenario: Duplicate email
    Given a user with email "john@example.com" exists
    When I send a POST request to "/register" with:
      """
      {
        "name": "John Doe",
        "email": "john@example.com",
        "password": "Secure123!"
      }
      """
    Then the response status should be 409
    And the response should contain "Email already exists"
```

```python
# steps/registration_steps.py
@given('the API is running')
def step_api_running(context):
    context.base_url = 'http://localhost:8000'
    response = requests.get(f'{context.base_url}/health')
    assert response.status_code == 200

@when('I send a POST request to "{endpoint}" with')
def step_post_request(context, endpoint):
    data = json.loads(context.text)
    context.response = requests.post(
        f'{context.base_url}{endpoint}',
        json=data
    )

@then('the response status should be {status:d}')
def step_status_code(context, status):
    assert context.response.status_code == status

@then('the response should contain a user ID')
def step_user_id(context):
    response_data = context.response.json()
    assert 'id' in response_data
    assert isinstance(response_data['id'], str)

@then('a welcome email should be queued')
def step_email_queued(context):
    # Check email queue or mock
    email_queue = get_email_queue()
    assert len(email_queue) == 1
    assert email_queue[0]['template'] == 'welcome'
```

**Key Points**:
- BDD scenarios serve as living documentation
- Integration tests verify real API behavior
- Scenarios readable by non-technical stakeholders
- Executable specifications

---

## Integration 4: Performance Testing + Test Automation

### Scenario: Load Testing in CI/CD

**Skills**: performance-testing, test-automation

**Approach**:
1. **Performance Testing**: Define load test scenarios with k6
2. **Test Automation**: Run in CI nightly, fail on SLA breach

```javascript
// tests/performance/load-test.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '2m', target: 100 },   // Ramp up
    { duration: '5m', target: 100 },   // Steady
    { duration: '2m', target: 0 },     // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<200'],  // SLA: p95 < 200ms
    http_req_failed: ['rate<0.1'],      // SLA: < 0.1% errors
  },
};

export default function() {
  const response = http.get('https://api.example.com/products');
  
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 200ms': (r) => r.timings.duration < 200,
  });
  
  sleep(1);
}
```

```yaml
# .github/workflows/performance.yml
name: Performance Tests

on:
  schedule:
    - cron: '0 2 * * *'  # Nightly at 2 AM
  workflow_dispatch:

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup k6
        uses: grafana/setup-k6-action@v1
      
      - name: Run load tests
        run: k6 run tests/performance/load-test.js
        env:
          API_URL: ${{ secrets.STAGING_API_URL }}
      
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: k6-results
          path: results/
```

**Key Points**:
- Performance tests run automatically on schedule
- SLA thresholds fail the build
- Results archived for trend analysis
- Staging environment mirrors production

---

## Integration 5: Test Strategy + Unit Testing + Mutation Testing

### Scenario: Risk-Based Testing Approach

**Skills**: test-strategy, unit-testing, mutation-testing

**Approach**:
1. **Test Strategy**: Identify high-risk components
2. **Unit Testing**: Focus effort on critical code
3. **Mutation Testing**: Verify test quality

```
Risk Assessment:
├── Payment Processing (High Risk)
│   ├── Unit Tests: 95% coverage
│   ├── Mutation Score: 90%+
│   └── Integration: Full flow tested
├── User Preferences (Medium Risk)
│   ├── Unit Tests: 80% coverage
│   └── Mutation Score: 75%
└── Analytics Logging (Low Risk)
    ├── Unit Tests: 60% coverage
    └── Spot testing only
```

```javascript
// Payment service (high-risk, heavily tested)
describe('PaymentService', () => {
  describe('calculateTotal', () => {
    test.each([
      [100, 0, 100],      // No discount
      [100, 10, 90],     // 10% off
      [100, 100, 0],     // Free
      [100, 50, 50],     // Half off
    ])('price %d, discount %d%% = %d', (price, discount, expected) => {
      expect(calculateTotal(price, discount)).toBe(expected);
    });
    
    test('handles floating point', () => {
      expect(calculateTotal(10.99, 10)).toBeCloseTo(9.89, 2);
    });
    
    test('throws on negative price', () => {
      expect(() => calculateTotal(-10, 0)).toThrow();
    });
    
    test('throws on discount > 100', () => {
      expect(() => calculateTotal(100, 101)).toThrow();
    });
  });
});

// Mutation testing verifies test quality
// stryker.config.json
{
  "mutate": ["src/payment/**/*.js"],  // Focus on critical code
  "thresholds": {
    "high": 90,
    "low": 80,
    "break": 75
  }
}
```

**Key Points**:
- Testing effort proportional to risk
- Mutation testing ensures test quality, not just coverage
- Critical code has stricter quality gates
- CI fails if mutation score drops below threshold

---

## Cross-Pack Integration

### With Programming Core (Pack 1)

| Combination | Use Case |
|-------------|----------|
| test-driven-development + algorithms | TDD complex algorithmic solutions |
| unit-testing + data-structures | Verify data structure operations |
| debugging-tests + problem-solving | Debug failing tests systematically |

### With Code Quality (Pack 2)

| Combination | Use Case |
|-------------|----------|
| test-driven-development + clean-code | Tests guide clean implementation |
| mutation-testing + code-quality-review | Verify tests catch bad code |
| unit-testing + code-refactoring | Refactor with confidence |

## Best Practices for Skill Combinations

1. **Start with strategy**, then tactics
2. **Layer tests**: Unit → Integration → E2E
3. **Use right tool for right layer**
4. **Verify test quality**, not just existence
5. **Automate everything** in CI/CD
