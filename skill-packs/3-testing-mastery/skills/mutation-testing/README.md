# Mutation Testing

Verify test quality by introducing code changes (mutants) and checking if tests catch them.

## Quick Start

```bash
# JavaScript (Stryker)
npm install --save-dev @stryker-mutator/core
npx stryker run

# Python (mutmut)
pip install mutmut
mutmut run
mutmut results
```

## How It Works

1. **Generate mutants** — Small code changes (`+` → `-`)
2. **Run tests** — Execute against mutants
3. **Check survival** — Mutant survives = test gap
4. **Kill survivors** — Add tests to catch them

## Metrics

| Metric | Meaning | Goal |
|--------|---------|------|
| **Killed** | Test failed ✓ | 70-90% |
| **Survived** | Test passed ✗ | < 30% |
| **Timeout** | Infinite loop | Fix code |

## Example

**Code:**
```javascript
function add(a, b) {
  return a + b;
}
```

**Mutant:**
```javascript
function add(a, b) {
  return a - b;  // + changed to -
}
```

**If tests pass:** Mutant survived → Add better tests

## Fix Survivors

**Before:**
```javascript
test('add exists', () => {
  expect(add).toBeDefined();  // Passes with bug!
});
```

**After:**
```javascript
test('adds two numbers', () => {
  expect(add(2, 3)).toBe(5);  // Fails if + becomes -
});
```

## Target Scores

| Code Type | Target |
|-----------|--------|
| Critical | 90%+ |
| Standard | 70-80% |
| UI/Boilerplate | 50-60% |

## Examples

See `examples/basic-examples.md` for full mutation testing examples.

## Related Skills

- `unit-testing` — What mutation testing validates
- `test-strategy` — When to use mutation testing
- `test-coverage` — Code coverage vs mutation coverage
