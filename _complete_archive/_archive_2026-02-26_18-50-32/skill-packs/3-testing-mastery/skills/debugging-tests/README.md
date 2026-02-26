# Debugging Tests

Debug failing tests systematically — distinguish between test bugs, code bugs, and environment issues.

## Quick Start

```
Test Failed?
├── Read error message carefully
├── Identify failure type
├── Reproduce consistently
└── Fix root cause
```

## Failure Types

| Type | Pattern | Fix |
|------|---------|-----|
| **Assertion** | Expected ≠ Actual | Check code or expectation |
| **Error** | Exception in test | Fix test code |
| **Timeout** | Async didn't complete | Add await, fix promise |

## Common Fixes

**Async not awaited:**
```javascript
// Wrong
const user = fetchUser();  // Returns Promise
expect(user.name).toBe('John');

// Right
const user = await fetchUser();
expect(user.name).toBe('John');
```

**Shared state:**
```javascript
// Wrong
const list = [];
test('adds', () => { list.push('a'); expect(list).toHaveLength(1); });
test('adds', () => { list.push('b'); expect(list).toHaveLength(1); }); // FAILS

// Right
const list = [];  // Fresh in each test
```

**Floating point:**
```javascript
// Wrong
expect(0.1 + 0.2).toBe(0.3);  // FAILS

// Right
expect(0.1 + 0.2).toBeCloseTo(0.3);
```

## Debugging Checklist

1. Read the error message
2. Check recent changes
3. Reproduce locally
4. Inspect actual values
5. Verify environment
6. Fix root cause

## Examples

See `examples/basic-examples.md` for full debugging examples.

## Related Skills

- `unit-testing` — Write debuggable tests
- `test-strategy` — Plan for debugging
- `clean-code` — Easy to test and debug
