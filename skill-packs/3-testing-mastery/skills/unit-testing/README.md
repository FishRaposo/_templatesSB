# Unit Testing

Write effective unit tests for functions, classes, and modules in isolation.

## Quick Start

```javascript
// Arrange
const input = { total: 200 };

// Act
const result = calculateDiscount(input, 0.10);

// Assert
expect(result).toBe(20);
```

## Structure: Arrange-Act-Assert

1. **Arrange** — Set up data and conditions
2. **Act** — Execute the code being tested
3. **Assert** — Verify the expected outcome

## What to Test

- Input → Output transformations
- State changes
- Error conditions
- Edge cases (null, empty, boundaries)

## Key Principles

- Test behavior, not implementation
- One concept per test
- Fast (< 100ms each)
- Isolated (no shared state)
- Deterministic (same result every time)

## Setup/Teardown

```javascript
beforeEach(() => {
  // Setup before each test
});

afterEach(() => {
  // Cleanup after each test
});
```

## Parameterized Tests

```javascript
test.each([
  [2, 3, 5],
  [0, 0, 0],
  [-1, 1, 0],
])('adds %i + %i = %i', (a, b, expected) => {
  expect(add(a, b)).toBe(expected);
});
```

## Examples

See `examples/basic-examples.md` for full unit testing examples in JavaScript, Python, and Go.

## Related Skills

- `test-driven-development` — TDD produces unit tests
- `test-doubles` — Mock dependencies
- `integration-testing` — Test component interactions
