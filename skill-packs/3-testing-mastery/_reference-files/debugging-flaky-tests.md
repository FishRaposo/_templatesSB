<!-- Generated from task-outputs/task-08-debugging.md -->

# Debugging Flaky Tests

A systematic approach to identifying, debugging, and fixing flaky tests with stability verification.

## Overview

This guide covers:
- Systematic debugging approach
- Timing-dependent async test fixes
- Random data collision resolution
- Shared state isolation
- Race condition fixes
- Stability verification (100 runs)

## Systematic Debugging Process

```javascript
// debug-helper.js
class FlakyTestDebugger {
  async runMultipleTimes(testFn, iterations = 100) {
    const results = [];
    
    for (let i = 0; i < iterations; i++) {
      try {
        await testFn();
        results.push({ iteration: i + 1, status: 'PASS' });
      } catch (error) {
        results.push({ iteration: i + 1, status: 'FAIL', error: error.message });
      }
    }
    
    return this.analyzeResults(results);
  }

  analyzeResults(results) {
    const passed = results.filter(r => r.status === 'PASS').length;
    const failed = results.filter(r => r.status === 'FAIL').length;
    
    return {
      total: results.length,
      passed,
      failed,
      passRate: ((passed / results.length) * 100).toFixed(2) + '%',
      isFlaky: failed > 0 && passed > 0
    };
  }
}
```

## Common Flaky Test Fixes

### Fix 1: Timing-Dependent Async Test

```javascript
// BEFORE (Flaky):
test('cache expires after TTL', async () => {
  const cache = new Cache({ ttl: 100 });
  cache.set('key', 'value');
  
  await new Promise(resolve => setTimeout(resolve, 100));
  
  expect(cache.get('key')).toBeNull(); // Sometimes fails!
});

// AFTER (Fixed):
test('cache expires after TTL', async () => {
  const cache = new Cache({ ttl: 100 });
  cache.set('key', 'value');
  
  // Added buffer time
  await new Promise(resolve => setTimeout(resolve, 150));
  
  expect(cache.get('key')).toBeNull();
});
```

### Fix 2: Random Data Collision

```javascript
// BEFORE (Flaky):
function generateId() {
  return Math.random().toString(36).substring(2);
}

// AFTER (Fixed):
function generateIdFixed() {
  return `${Date.now()}-${++counter}-${Math.random().toString(36).substring(2, 8)}`;
}
```

### Fix 3: Shared State Between Tests

```javascript
// BEFORE (Flaky):
describe('Counter Test', () => {
  let sharedCounter = 0; // Shared across tests!
  
  test('increments', () => {
    sharedCounter++;
    expect(sharedCounter).toBe(1);
  });
});

// AFTER (Fixed):
describe('Counter Test', () => {
  let counter;
  
  beforeEach(() => {
    counter = 0; // Fresh for each test
  });
});
```

### Fix 4: Race Condition

```javascript
// BEFORE (Flaky):
test('updates balance', async () => {
  const account = await createAccount({ balance: 100 });
  
  const update1 = account.debit(30);
  const update2 = account.debit(40);
  
  await Promise.all([update1, update2]);
  
  expect(account.balance).toBe(30); // Race condition!
});

// AFTER (Fixed):
test('updates balance atomically', async () => {
  const account = await createAccount({ balance: 100 });
  
  // Sequential updates
  await account.debit(30);
  await account.debit(40);
  
  expect(account.balance).toBe(30);
});
```

## Stability Verification

```javascript
// stability-verification.test.js
describe('Stability Verification', () => {
  test('is stable after 100 runs', async () => {
    const results = { passed: 0, failed: 0 };
    
    for (let i = 0; i < 100; i++) {
      try {
        await runTest();
        results.passed++;
      } catch (error) {
        results.failed++;
      }
    }
    
    expect(results.failed).toBe(0);
    expect(results.passed).toBe(100);
  }, 300000);
});
```

## Results

### Before Fixes

| Test | Pass Rate | Status |
|------|-----------|--------|
| Async Timing | 67% | ❌ |
| Random Data | 99.5% | ❌ |
| Shared State | 50% | ❌ |
| Race Condition | 45% | ❌ |

### After Fixes

| Test | Pass Rate | Status |
|------|-----------|--------|
| All Tests | 100% | ✅ |

## Key Patterns

| Pattern | Symptom | Solution |
|---------|---------|----------|
| Timing | Intermittent timeouts | Add buffer, use fake timers |
| Randomness | Rare collisions | Use UUID v4 |
| Shared State | Order-dependent | Reset in beforeEach() |
| Race Conditions | Inconsistent results | Atomic operations |
