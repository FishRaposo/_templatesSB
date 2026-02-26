---
name: unit-testing
description: Use this skill when creating effective unit tests for components in isolation. This includes testing functions, classes, and modules; using assertions effectively; organizing tests with setup and teardown; achieving high code coverage meaningfully; and writing tests that serve as documentation. Works with any testing framework.
---

# Unit Testing

I'll help you write effective unit tests that verify individual components in isolation. Tests will be fast, deterministic, and serve as living documentation.

## Core Approach

### What to Test

Test **behavior**, not implementation:
- Input → Output transformations
- State changes
- Error conditions
- Edge cases (null, empty, boundaries)

### Structure: Arrange-Act-Assert

```
Arrange: Set up the test data and conditions
Act:     Execute the code being tested
Assert:  Verify the expected outcome
```

## Step-by-Step Instructions

### 1. Identify Test Cases

For each function/method, identify:
- Happy path (normal input)
- Edge cases (empty, null, zero, max values)
- Error cases (invalid input, exceptions)
- Boundary conditions

### 2. Write the Test

**JavaScript (Jest)**
```javascript
describe('calculateDiscount', () => {
  test('applies 10% discount to orders over $100', () => {
    // Arrange
    const order = { total: 200 };
    
    // Act
    const result = calculateDiscount(order, 0.10);
    
    // Assert
    expect(result).toBe(20);
  });
  
  test('returns 0 for orders under $100', () => {
    const order = { total: 50 };
    expect(calculateDiscount(order, 0.10)).toBe(0);
  });
  
  test('throws for negative total', () => {
    const order = { total: -10 };
    expect(() => calculateDiscount(order, 0.10))
      .toThrow('Order total must be positive');
  });
});
```

**Python (pytest)**
```python
def test_applies_discount_to_orders_over_100():
    order = {"total": 200}
    result = calculate_discount(order, 0.10)
    assert result == 20

def test_returns_zero_for_orders_under_100():
    order = {"total": 50}
    assert calculate_discount(order, 0.10) == 0

def test_throws_for_negative_total():
    order = {"total": -10}
    with pytest.raises(ValueError, match="Order total must be positive"):
        calculate_discount(order, 0.10)
```

**Go**
```go
func TestCalculateDiscount(t *testing.T) {
    tests := []struct {
        name     string
        total    float64
        rate     float64
        want     float64
        wantErr  bool
    }{
        {"applies discount over 100", 200, 0.10, 20, false},
        {"returns 0 under 100", 50, 0.10, 0, false},
        {"errors on negative", -10, 0.10, 0, true},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            order := Order{Total: tt.total}
            got, err := CalculateDiscount(order, tt.rate)
            if (err != nil) != tt.wantErr {
                t.Errorf("CalculateDiscount() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("CalculateDiscount() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### 3. Use Setup/Teardown for Common Code

**JavaScript**
```javascript
let calculator;

beforeEach(() => {
  calculator = new Calculator();
});

afterEach(() => {
  calculator.dispose();
});
```

**Python**
```python
@pytest.fixture
def calculator():
    calc = Calculator()
    yield calc
    calc.dispose()

def test_add(calculator):
    assert calculator.add(2, 3) == 5
```

**Go**
```go
func setupCalculator(t *testing.T) *Calculator {
    t.Helper()
    return NewCalculator()
}
```

### 4. Assert Effectively

**Prefer specific assertions:**
```javascript
// Good: specific
expect(result).toBe(expected);
expect(array).toHaveLength(3);
expect(object).toHaveProperty('name', 'John');

// Avoid: too vague
expect(result).toBeTruthy();
expect(array).toBeDefined();
```

**Test one concept per test:**
```javascript
// Good: single concept
test('sorts numbers in ascending order', () => {
  expect(sort([3, 1, 2])).toEqual([1, 2, 3]);
});

// Bad: multiple concepts
test('sort works', () => {
  expect(sort([3, 1, 2])).toEqual([1, 2, 3]);
  expect(sort([])).toEqual([]);
  expect(sort([1])).toEqual([1]);
});
```

## Multi-Language Examples

### Testing a Class

**JavaScript**
```javascript
class BankAccount {
  constructor() {
    this.balance = 0;
  }
  
  deposit(amount) {
    if (amount <= 0) throw new Error('Amount must be positive');
    this.balance += amount;
  }
  
  withdraw(amount) {
    if (amount <= 0) throw new Error('Amount must be positive');
    if (amount > this.balance) throw new Error('Insufficient funds');
    this.balance -= amount;
  }
}

describe('BankAccount', () => {
  let account;
  
  beforeEach(() => {
    account = new BankAccount();
  });
  
  describe('deposit', () => {
    test('increases balance', () => {
      account.deposit(100);
      expect(account.balance).toBe(100);
    });
    
    test('throws for non-positive amount', () => {
      expect(() => account.deposit(-10)).toThrow('Amount must be positive');
    });
  });
  
  describe('withdraw', () => {
    test('decreases balance', () => {
      account.deposit(100);
      account.withdraw(30);
      expect(account.balance).toBe(70);
    });
    
    test('throws for insufficient funds', () => {
      account.deposit(50);
      expect(() => account.withdraw(100)).toThrow('Insufficient funds');
    });
  });
});
```

**Python**
```python
class BankAccount:
    def __init__(self):
        self.balance = 0
    
    def deposit(self, amount):
        if amount <= 0:
            raise ValueError("Amount must be positive")
        self.balance += amount
    
    def withdraw(self, amount):
        if amount <= 0:
            raise ValueError("Amount must be positive")
        if amount > self.balance:
            raise ValueError("Insufficient funds")
        self.balance -= amount

class TestBankAccount:
    @pytest.fixture
    def account(self):
        return BankAccount()
    
    def test_deposit_increases_balance(self, account):
        account.deposit(100)
        assert account.balance == 100
    
    def test_deposit_throws_for_non_positive(self, account):
        with pytest.raises(ValueError, match="Amount must be positive"):
            account.deposit(-10)
    
    def test_withdraw_decreases_balance(self, account):
        account.deposit(100)
        account.withdraw(30)
        assert account.balance == 70
```

**Go**
```go
type BankAccount struct {
    balance int
}

func (a *BankAccount) Deposit(amount int) error {
    if amount <= 0 {
        return errors.New("amount must be positive")
    }
    a.balance += amount
    return nil
}

func (a *BankAccount) Withdraw(amount int) error {
    if amount <= 0 {
        return errors.New("amount must be positive")
    }
    if amount > a.balance {
        return errors.New("insufficient funds")
    }
    a.balance -= amount
    return nil
}

func TestBankAccount(t *testing.T) {
    t.Run("deposit", func(t *testing.T) {
        t.Run("increases balance", func(t *testing.T) {
            a := &BankAccount{}
            a.Deposit(100)
            if a.balance != 100 {
                t.Errorf("balance = %d, want 100", a.balance)
            }
        })
        
        t.Run("returns error for non-positive", func(t *testing.T) {
            a := &BankAccount{}
            err := a.Deposit(-10)
            if err == nil {
                t.Error("expected error for negative deposit")
            }
        })
    })
}
```

## Best Practices

### Naming
- Test names should describe behavior: `test_deposit_increases_balance`
- Group related tests in describe blocks
- Use given/when/then style for complex scenarios

### Isolation
- Each test should be independent
- No shared state between tests
- Clean up resources in teardown

### Speed
- Unit tests should run in milliseconds
- Avoid database, network, file system calls
- Use test doubles for dependencies

### Coverage
- Aim for meaningful coverage, not 100%
- Test critical paths thoroughly
- Don't test trivial getters/setters

## Common Patterns

### Parameterized Tests

**JavaScript**
```javascript
test.each([
  [2, 3, 5],
  [0, 0, 0],
  [-1, 1, 0],
])('adds %i + %i = %i', (a, b, expected) => {
  expect(add(a, b)).toBe(expected);
});
```

**Python**
```python
@pytest.mark.parametrize("a,b,expected", [
    (2, 3, 5),
    (0, 0, 0),
    (-1, 1, 0),
])
def test_add(a, b, expected):
    assert add(a, b) == expected
```

**Go**
```go
func TestAdd(t *testing.T) {
    tests := []struct{ a, b, want int }{
        {2, 3, 5},
        {0, 0, 0},
        {-1, 1, 0},
    }
    for _, tt := range tests {
        t.Run(fmt.Sprintf("%d+%d", tt.a, tt.b), func(t *testing.T) {
            got := Add(tt.a, tt.b)
            if got != tt.want {
                t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
            }
        })
    }
}
```

## Validation Checklist

- [ ] Tests run in isolation (no shared state)
- [ ] Tests run fast (< 100ms each)
- [ ] Each test has a clear purpose
- [ ] Assertions are specific and meaningful
- [ ] Error cases are tested
- [ ] Edge cases are covered
- [ ] Test names describe behavior
- [ ] Tests serve as documentation

## Related Skills

- **test-driven-development** — TDD produces unit tests
- **test-doubles** — Mock dependencies for isolation
- **integration-testing** — Test component interactions
- **test-strategy** — Decide what to unit test
