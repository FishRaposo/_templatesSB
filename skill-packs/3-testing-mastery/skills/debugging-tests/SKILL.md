---
name: debugging-tests
description: Use this skill when debugging failing tests. This includes understanding test failure messages, identifying root causes, distinguishing between test bugs and code bugs, using debugging tools effectively, and fixing flaky tests. Focus on systematic debugging approaches that identify whether the test, code, or environment is at fault.
---

# Debugging Tests

I'll help you debug failing tests systematically — distinguishing between test bugs, code bugs, and environment issues. We'll get to the root cause quickly.

## Core Approach

### The Debugging Decision Tree

```
Test Failed
├── Test Error (test code problem)
│   ├── Syntax/compile error
│   ├── Wrong assertion
│   ├── Bad test data
│   └── Incorrect setup
├── Assertion Failure (code behavior problem)
│   ├── Expected vs actual mismatch
│   ├── Exception thrown
│   └── Timeout/deadlock
└── Environment Problem
    ├── Flaky test (timing, randomness)
    ├── External dependency down
    └── Test pollution (shared state)
```

### First Steps

1. **Read the error message carefully**
2. **Identify what type of failure** (assertion, error, timeout)
3. **Reproduce consistently**
4. **Isolate the problem**

## Step-by-Step Instructions

### 1. Understand the Failure Type

**Assertion Failure** (most common):
```
Expected: 42
Received: 40

Difference:
- Expected
+ Received

- 42
+ 40
```
→ Code behavior doesn't match expectations

**Test Error**:
```
TypeError: Cannot read property 'name' of undefined
    at test/user.test.js:15:20
```
→ Test code has a bug

**Timeout**:
```
Timeout - Async callback was not invoked within 5000ms
```
→ Async operation didn't complete (infinite loop, missing await)

### 2. Read the Stack Trace

**JavaScript**
```javascript
// Stack trace shows:
// 1. The assertion that failed
// 2. The test file and line number
// 3. The call stack

test('user has name', () => {
  const user = getUser();  // Line 10
  expect(user.name).toBe('John');  // Line 11 - FAILS
});
```

**Python**
```python
# pytest shows:
# 1. Failing assertion
# 2. Local variables at failure point
# 3. Full traceback

def test_user_has_name():
    user = get_user()  # Line 10
    assert user.name == "John"  # Line 11 - FAILS
```

**Go**
```go
// Test output shows:
// 1. Got vs Want
// 2. File:line of failure
// 3. Optional: log output

func TestUserHasName(t *testing.T) {
    user := getUser()  // Line 10
    if user.Name != "John" {  // Line 11 - FAILS
        t.Errorf("Name = %q, want %q", user.Name, "John")
    }
}
```

### 3. Inspect Actual Values

**Add debugging output:**

```javascript
// JavaScript
test('calculates total', () => {
  const items = [{ price: 10 }, { price: 20 }];
  const result = calculateTotal(items);
  
  console.log('Result:', result);  // Debug output
  console.log('Items:', items);
  
  expect(result).toBe(30);
});
```

```python
# Python
def test_calculates_total():
    items = [{"price": 10}, {"price": 20}]
    result = calculate_total(items)
    
    print(f"Result: {result}")  # Debug output
    print(f"Items: {items}")
    
    assert result == 30
```

**Use debugger:**
```javascript
// JavaScript
test('calculates total', () => {
  const items = [{ price: 10 }, { price: 20 }];
  const result = calculateTotal(items);
  
  debugger;  // Breakpoint - inspect variables
  
  expect(result).toBe(30);
});
```

```python
# Python
import pdb

def test_calculates_total():
    items = [{"price": 10}, {"price": 20}]
    result = calculate_total(items)
    
    pdb.set_trace()  # Breakpoint
    
    assert result == 30
```

### 4. Common Failure Patterns & Fixes

**Expected vs Actual Reversed**
```javascript
// Wrong
expect(expected).toBe(actual);

// Right
expect(actual).toBe(expected);
```

**Floating Point Precision**
```javascript
// Wrong
expect(calculateTotal([0.1, 0.2])).toBe(0.3);

// Right
expect(calculateTotal([0.1, 0.2])).toBeCloseTo(0.3, 10);
```

**Async Not Awaited**
```javascript
// Wrong - test completes before async
test('fetches user', () => {
  const user = fetchUser();  // Returns Promise, not user
  expect(user.name).toBe('John');
});

// Right
test('fetches user', async () => {
  const user = await fetchUser();
  expect(user.name).toBe('John');
});
```

**Mutation of Shared State**
```javascript
// Wrong - test order dependent
const list = [];

test('adds item', () => {
  list.push('item');
  expect(list).toHaveLength(1);
});

test('adds another', () => {
  list.push('item2');  // list now has 2 items!
  expect(list).toHaveLength(1);  // FAILS
});

// Right - isolate state
test('adds item', () => {
  const list = [];  // Fresh instance
  list.push('item');
  expect(list).toHaveLength(1);
});
```

## Multi-Language Examples

### Systematic Debugging

**JavaScript**
```javascript
describe('OrderService', () => {
  test('calculates total with discount', async () => {
    // Given - setup
    const order = {
      items: [
        { price: 100, quantity: 2 },
        { price: 50, quantity: 1 },
      ],
      discountCode: 'SAVE10',
    };
    
    // When - action
    const result = await orderService.calculateTotal(order);
    
    // Debug: log intermediate values
    console.log('Subtotal:', result.subtotal);
    console.log('Discount:', result.discount);
    console.log('Total:', result.total);
    
    // Then - assertion
    expect(result.subtotal).toBe(250);
    expect(result.discount).toBe(25);  // 10% of 250
    expect(result.total).toBe(225);
  });
});
```

**Python**
```python
def test_calculates_total_with_discount():
    # Given
    order = {
        "items": [
            {"price": 100, "quantity": 2},
            {"price": 50, "quantity": 1},
        ],
        "discount_code": "SAVE10",
    }
    
    # When
    result = order_service.calculate_total(order)
    
    # Debug: inspect values
    print(f"Subtotal: {result.subtotal}")
    print(f"Discount: {result.discount}")
    print(f"Total: {result.total}")
    
    # Then
    assert result.subtotal == 250
    assert result.discount == 25
    assert result.total == 225
```

### Debugging Flaky Tests

**Identify flakiness source:**
```javascript
// Test fails intermittently

test('timeout occurs after delay', async () => {
  const start = Date.now();
  
  await waitForTimeout(100);
  
  const elapsed = Date.now() - start;
  expect(elapsed).toBeGreaterThanOrEqual(100);  // Sometimes fails!
});

// Fix: account for timing variance
test('timeout occurs after delay', async () => {
  const start = Date.now();
  
  await waitForTimeout(100);
  
  const elapsed = Date.now() - start;
  expect(elapsed).toBeGreaterThanOrEqual(90);  // Tolerance
});
```

**Remove randomness:**
```javascript
// Flaky: uses random data
const user = createUser({ age: Math.random() * 100 });

// Stable: deterministic data
const user = createUser({ age: 25 });
```

**Fix race conditions:**
```javascript
// Flaky: race condition
test('updates cache', async () => {
  await updateCache('key', 'value');
  const value = await getCache('key');
  expect(value).toBe('value');  // May not be set yet
});

// Stable: wait for condition
test('updates cache', async () => {
  await updateCache('key', 'value');
  await waitFor(async () => {
    const value = await getCache('key');
    return value === 'value';
  }, { timeout: 1000 });
});
```

## Best Practices

### Test Debugging Checklist

1. **Read the error** — What exactly failed?
2. **Check recent changes** — What code changed?
3. **Reproduce locally** — Can you make it fail consistently?
4. **Isolate the test** — Does it fail alone?
5. **Inspect values** — What are the actual values?
6. **Check setup** — Is test data correct?
7. **Verify environment** — Are dependencies running?

### Make Tests Debuggable

```javascript
// Good: descriptive assertion messages
test('calculates total', () => {
  const result = calculateTotal(items);
  expect(result).toBe(
    expected,
    `Expected ${expected} but got ${result} for items: ${JSON.stringify(items)}`
  );
});
```

### Fix Root Causes

Don't just make the test pass — understand why it failed:

```
Test fails: expected 42, got 40
├── Test is wrong? → Fix test expectation
├── Code is wrong? → Fix implementation  
├── Data is wrong? → Fix test data
└── Race condition? → Synchronize properly
```

## Common Pitfalls

❌ **Ignoring flakiness**
- "It passes on rerun" → Will bite you in CI
- Track flaky tests, fix root causes

❌ **Changing test to match buggy code**
```javascript
// Wrong: code returns 40, change test to expect 40
test('calculates', () => {
  expect(calculate()).toBe(40);  // Code bug!
});

// Right: fix the code
test('calculates', () => {
  expect(calculate()).toBe(42);  // Correct expectation
});
```

❌ **Debugging without understanding**
- Don't add random delays hoping it fixes timing issues
- Don't disable tests without investigation

## Validation Checklist

- [ ] Error message is read and understood
- [ ] Failure is reproducible consistently
- [ ] Root cause is identified (not just symptom fixed)
- [ ] Fix addresses the actual problem
- [ ] Test passes reliably after fix
- [ ] Related tests still pass
- [ ] Flaky tests are tracked and fixed, not ignored

## Related Skills

- **unit-testing** — Write debuggable tests
- **test-strategy** — Plan for debugging
- **clean-code** — Code that's easy to test and debug
