# Debugging Tests Examples

## Common Test Failures & Fixes

### Async Not Awaited

```javascript
// WRONG - returns Promise, not user
test('fetches user', async () => {
  const user = fetchUser(1);  // Returns Promise
  expect(user.name).toBe('John');  // FAILS: user is Promise
});

// RIGHT - await the Promise
test('fetches user', async () => {
  const user = await fetchUser(1);
  expect(user.name).toBe('John');
});
```

### Shared Mutable State

```javascript
// WRONG - shared state between tests
const list = [];

test('adds item', () => {
  list.push('item');
  expect(list).toHaveLength(1);
});

test('adds another', () => {
  list.push('item2');  // list now has 2 items!
  expect(list).toHaveLength(1);  // FAILS
});

// RIGHT - isolated state
test('adds item', () => {
  const list = [];  // Fresh instance
  list.push('item');
  expect(list).toHaveLength(1);
});
```

### Floating Point Precision

```javascript
// WRONG
expect(0.1 + 0.2).toBe(0.3);  // FAILS: 0.30000000000000004

// RIGHT
expect(0.1 + 0.2).toBeCloseTo(0.3, 5);
```

### Wrong Expected/Actual Order

```javascript
// WRONG
expect(expected).toBe(actual);

// RIGHT  
expect(actual).toBe(expected);
```

## Debugging Techniques

### Add Console Logs

```javascript
test('calculates total', () => {
  const items = [{ price: 10 }, { price: 20 }];
  const result = calculateTotal(items);
  
  console.log('Items:', items);
  console.log('Result:', result);
  
  expect(result).toBe(30);
});
```

### Use Debugger

```javascript
test('calculates total', () => {
  const result = calculateTotal(items);
  debugger;  // Breakpoint - inspect in DevTools
  expect(result).toBe(30);
});
```

### Python: pdb

```python
def test_calculates_total():
    result = calculate_total(items)
    import pdb; pdb.set_trace()  # Breakpoint
    assert result == 30
```

## Flaky Test Fixes

### Timing Issue

```javascript
// FLAKY
test('shows message', async () => {
  await clickButton();
  expect(screen.getByText('Success')).toBeVisible();  // May not appear yet
});

// STABLE - wait for condition
test('shows message', async () => {
  await clickButton();
  await waitFor(() => {
    expect(screen.getByText('Success')).toBeVisible();
  });
});
```

### Random Data Collision

```javascript
// FLAKY - might generate same email
test('creates user', () => {
  const email = `user${Math.random()}@test.com`;
  createUser(email);
});

// STABLE - use sequence
let counter = 0;
test('creates user', () => {
  const email = `user${counter++}@test.com`;
  createUser(email);
});
```

## Debugging Checklist

1. Read error message carefully
2. Check recent code changes
3. Reproduce locally
4. Inspect actual values
5. Verify test isolation
6. Fix root cause, not symptom
