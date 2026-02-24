# Test-Driven Development

Use this skill to implement features using the TDD cycle: Red-Green-Refactor.

## Quick Start

```javascript
// 1. Write a failing test (RED)
test('adds two numbers', () => {
  expect(calculator.add(2, 3)).toBe(5);
});

// 2. Run test — it fails
// 3. Write minimal code to pass (GREEN)
add(a, b) { return a + b; }

// 4. Run test — it passes
// 5. Refactor while green
// 6. Repeat
```

## The TDD Cycle

1. **RED** — Write a test that fails
2. **GREEN** — Write minimal code to pass
3. **REFACTOR** — Clean up, keeping tests green

## When to Use

- Implementing new features
- Fixing bugs (write test that reproduces bug first)
- Refactoring with confidence
- Designing clean APIs

## Key Rules

- Write no production code except to pass a failing test
- Write only enough test to demonstrate failure
- Write only enough code to pass the test
- Refactor every few cycles

## Examples

See `examples/basic-examples.md` for full TDD walkthroughs in JavaScript, Python, and Go.

## Common Mistakes

- Testing implementation details instead of behavior
- Taking steps that are too large
- Skipping the refactor step
- Not running tests frequently enough

## Related Skills

- `unit-testing` — TDD produces unit tests
- `test-doubles` — Mock dependencies
- `debugging-tests` — Fix failing tests
