---
name: test-driven-development
description: Use this skill when implementing features using Test-Driven Development (TDD). Write tests before implementation, follow the Red-Green-Refactor cycle, and let tests drive design decisions. This includes writing failing tests first, making them pass with minimal code, then refactoring while keeping tests green.
---

# Test-Driven Development

I'll help you implement features using TDD — writing tests first, then minimal code to make them pass, then refactoring. We'll follow the Red-Green-Refactor cycle rigorously.

## Core Approach

### The TDD Cycle

```
1. RED  → Write a failing test (compile errors count as failing)
2. GREEN → Write minimal code to make the test pass
3. REFACTOR → Clean up while keeping tests green
   ↓
   Repeat
```

### Rules

1. **Write no production code except to pass a failing test**
2. **Write only enough of a test to demonstrate a failure** (or compilation error)
3. **Write only enough production code to pass the test**

## Step-by-Step Instructions

### 1. Start with the Test (RED)

Write a test that describes the behavior you want:

**JavaScript (Jest)**
```javascript
// test/calculator.test.js
describe('Calculator', () => {
  test('adds two numbers', () => {
    const calc = new Calculator();
    expect(calc.add(2, 3)).toBe(5);
  });
});
```

**Python (pytest)**
```python
# test_calculator.py
def test_adds_two_numbers():
    calc = Calculator()
    assert calc.add(2, 3) == 5
```

**Go**
```go
// calculator_test.go
func TestCalculator_Add(t *testing.T) {
    calc := NewCalculator()
    got := calc.Add(2, 3)
    want := 5
    if got != want {
        t.Errorf("Add(2, 3) = %d; want %d", got, want)
    }
}
```

**Run the test — it should fail (RED)**

### 2. Make It Pass (GREEN)

Write the minimal code to pass the test:

**JavaScript**
```javascript
// src/calculator.js
class Calculator {
  add(a, b) {
    return a + b;  // Minimal code to pass
  }
}
module.exports = Calculator;
```

**Python**
```python
# calculator.py
class Calculator:
    def add(self, a, b):
        return a + b  # Minimal code to pass
```

**Go**
```go
// calculator.go
func (c *Calculator) Add(a, b int) int {
    return a + b  // Minimal code to pass
}
```

**Run the test — it should pass (GREEN)**

### 3. Refactor

Clean up the code while keeping tests green:
- Remove duplication
- Improve names
- Extract methods
- Simplify logic

**Never change behavior during refactoring.**

### 4. Repeat

Write the next failing test for new behavior:

```javascript
// Next test (RED)
test('subtracts two numbers', () => {
  const calc = new Calculator();
  expect(calc.subtract(5, 3)).toBe(2);
});
```

## Multi-Language Examples

### Example: FizzBuzz (Kata)

**JavaScript**
```javascript
// Test first
const fizzBuzz = require('./fizzbuzz');

describe('fizzBuzz', () => {
  test('returns number as string for non-multiples', () => {
    expect(fizzBuzz(1)).toBe('1');
  });
  
  test('returns Fizz for multiples of 3', () => {
    expect(fizzBuzz(3)).toBe('Fizz');
  });
  
  test('returns Buzz for multiples of 5', () => {
    expect(fizzBuzz(5)).toBe('Buzz');
  });
  
  test('returns FizzBuzz for multiples of 15', () => {
    expect(fizzBuzz(15)).toBe('FizzBuzz');
  });
});

// Implementation evolves
function fizzBuzz(n) {
  if (n % 15 === 0) return 'FizzBuzz';
  if (n % 3 === 0) return 'Fizz';
  if (n % 5 === 0) return 'Buzz';
  return String(n);
}
```

**Python**
```python
# Test first
def test_returns_number_as_string():
    assert fizzbuzz(1) == "1"

def test_returns_fizz_for_multiples_of_3():
    assert fizzbuzz(3) == "Fizz"

def test_returns_buzz_for_multiples_of_5():
    assert fizzbuzz(5) == "Buzz"

def test_returns_fizzbuzz_for_multiples_of_15():
    assert fizzbuzz(15) == "FizzBuzz"

# Implementation evolves
def fizzbuzz(n):
    if n % 15 == 0:
        return "FizzBuzz"
    if n % 3 == 0:
        return "Fizz"
    if n % 5 == 0:
        return "Buzz"
    return str(n)
```

**Go**
```go
// Test first
func TestFizzBuzz(t *testing.T) {
    tests := []struct {
        n    int
        want string
    }{
        {1, "1"},
        {3, "Fizz"},
        {5, "Buzz"},
        {15, "FizzBuzz"},
    }
    
    for _, tt := range tests {
        got := FizzBuzz(tt.n)
        if got != tt.want {
            t.Errorf("FizzBuzz(%d) = %q; want %q", tt.n, got, tt.want)
        }
    }
}

// Implementation evolves
func FizzBuzz(n int) string {
    if n%15 == 0 {
        return "FizzBuzz"
    }
    if n%3 == 0 {
        return "Fizz"
    }
    if n%5 == 0 {
        return "Buzz"
    }
    return strconv.Itoa(n)
}
```

## Best Practices

### Test Granularity
- One concept per test
- Test behavior, not implementation
- Tests should serve as documentation

### Refactoring Indicators
- Duplicated code
- Long methods/functions
- Unclear names
- Comments explaining code

### When NOT to Use TDD
- Exploratory coding (spikes)
- Learning new APIs/frameworks
- Trivial CRUD with no logic
- UIs requiring visual feedback

## Common Pitfalls

❌ **Testing implementation details**
```javascript
// Bad: tests internal state
expect(calc.internalCache).toHaveLength(1);

// Good: tests behavior
expect(calc.add(2, 3)).toBe(5);
```

❌ **Large steps**
```javascript
// Bad: too many tests at once
test('handles all operations', () => {
  // tests add, subtract, multiply, divide
});

// Good: one small step at a time
test('adds two numbers', () => { ... });
test('subtracts two numbers', () => { ... });
```

❌ **Skipping the refactor step**
- Don't accumulate technical debt
- Refactor every few cycles

## Validation Checklist

- [ ] Tests written before implementation
- [ ] Tests fail for the right reason (not compilation errors)
- [ ] Minimal code to make tests pass
- [ ] Refactoring keeps all tests green
- [ ] Tests describe behavior, not implementation
- [ ] Each test covers one concept

## Related Skills

- **unit-testing** — TDD produces unit tests
- **test-doubles** — Mock dependencies in TDD
- **test-strategy** — When and where to apply TDD
