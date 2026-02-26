# Basic TDD Examples

## Example 1: String Calculator Kata

### JavaScript

```javascript
// Step 1: First test (RED)
describe('StringCalculator', () => {
  test('returns 0 for empty string', () => {
    const calc = new StringCalculator();
    expect(calc.add('')).toBe(0);
  });
});

// Step 2: Minimal implementation (GREEN)
class StringCalculator {
  add(str) {
    return 0;
  }
}

// Step 3: Next test (RED)
test('returns number for single number', () => {
  expect(calc.add('1')).toBe(1);
});

// Step 4: Update implementation (GREEN)
add(str) {
  if (str === '') return 0;
  return parseInt(str);
}

// Step 5: Next test (RED)
test('returns sum for two numbers', () => {
  expect(calc.add('1,2')).toBe(3);
});

// Step 6: Update implementation (GREEN)
add(str) {
  if (str === '') return 0;
  const numbers = str.split(',').map(n => parseInt(n));
  return numbers.reduce((sum, n) => sum + n, 0);
}
```

### Python

```python
# Step 1: First test (RED)
def test_empty_string_returns_zero():
    calc = StringCalculator()
    assert calc.add('') == 0

# Step 2: Minimal implementation (GREEN)
class StringCalculator:
    def add(self, s):
        return 0

# Step 3-6: Progressive enhancement through TDD
class StringCalculator:
    def add(self, s):
        if not s:
            return 0
        numbers = [int(n) for n in s.split(',')]
        return sum(numbers)
```

### Go

```go
// Step 1: First test (RED)
func TestStringCalculator_Empty(t *testing.T) {
    calc := NewStringCalculator()
    got := calc.Add("")
    want := 0
    if got != want {
        t.Errorf("Add(\"\") = %d; want %d", got, want)
    }
}

// Step 2: Minimal implementation (GREEN)
func (c *StringCalculator) Add(s string) int {
    return 0
}

// Step 6: Final implementation
func (c *StringCalculator) Add(s string) int {
    if s == "" {
        return 0
    }
    parts := strings.Split(s, ",")
    sum := 0
    for _, p := range parts {
        n, _ := strconv.Atoi(p)
        sum += n
    }
    return sum
}
```

## Example 2: Password Validator

### JavaScript

```javascript
// Test progression through TDD
describe('PasswordValidator', () => {
  // RED → GREEN → Refactor cycle
  test('accepts valid password', () => {
    expect(validate('Strong1!')).toBe(true);
  });
  
  test('rejects too short', () => {
    expect(validate('Short1!')).toBe(false);
  });
  
  test('rejects without uppercase', () => {
    expect(validate('weak1!weak')).toBe(false);
  });
  
  test('rejects without number', () => {
    expect(validate('Weak!weak')).toBe(false);
  });
  
  test('rejects without special char', () => {
    expect(validate('Weak1weak')).toBe(false);
  });
});

// Implementation evolves through cycles
function validate(password) {
  if (password.length < 8) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  if (!/[^a-zA-Z0-9]/.test(password)) return false;
  return true;
}
```

## Example 3: Stack Implementation

### Python

```python
# Test first for Stack
class TestStack:
    def test_new_stack_is_empty(self):
        stack = Stack()
        assert stack.is_empty()
    
    def test_push_adds_element(self):
        stack = Stack()
        stack.push(1)
        assert not stack.is_empty()
    
    def test_pop_removes_element(self):
        stack = Stack()
        stack.push(1)
        assert stack.pop() == 1
        assert stack.is_empty()
    
    def test_lifo_order(self):
        stack = Stack()
        stack.push(1)
        stack.push(2)
        assert stack.pop() == 2
        assert stack.pop() == 1

# Implementation through TDD
class Stack:
    def __init__(self):
        self._items = []
    
    def push(self, item):
        self._items.append(item)
    
    def pop(self):
        return self._items.pop()
    
    def is_empty(self):
        return len(self._items) == 0
```

## Refactoring Examples

### Before (working but messy)
```javascript
function calculate(price, quantity, tax, discount) {
  const p = price * quantity;
  const t = p * tax;
  const d = (p + t) * discount;
  return p + t - d;
}
```

### After (clean, tested)
```javascript
// Tests pass through refactoring
describe('calculate', () => {
  test('calculates total with tax and discount', () => {
    expect(calculate(100, 2, 0.1, 0.2)).toBe(176);
  });
});

// Extracted methods, clear names
class OrderCalculator {
  subtotal(price, quantity) {
    return price * quantity;
  }
  
  taxAmount(subtotal, rate) {
    return subtotal * rate;
  }
  
  discountAmount(amount, rate) {
    return amount * rate;
  }
  
  total(price, quantity, taxRate, discountRate) {
    const sub = this.subtotal(price, quantity);
    const tax = this.taxAmount(sub, taxRate);
    const beforeDiscount = sub + tax;
    const discount = this.discountAmount(beforeDiscount, discountRate);
    return beforeDiscount - discount;
  }
}
```

## Common TDD Patterns

### Triangulation
When unsure of implementation, add more tests:
```javascript
test('adds 1 + 1', () => { expect(add(1, 1)).toBe(2); });
test('adds 2 + 2', () => { expect(add(2, 2)).toBe(4); }); // Triangulate
test('adds 1 + 2', () => { expect(add(1, 2)).toBe(3); }); // Forces general solution
```

### Fake It Till You Make It
Return constant first, then generalize:
```javascript
// First
add(a, b) { return 2; }

// Then after more tests
add(a, b) { return a + b; }
```

### Obvious Implementation
When the solution is clear, implement directly:
```javascript
test('returns length of string', () => {
  expect(length('hello')).toBe(5);
});

// Obvious: just use .length
length(s) { return s.length; }
```
