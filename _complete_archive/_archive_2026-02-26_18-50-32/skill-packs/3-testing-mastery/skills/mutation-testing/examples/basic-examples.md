# Mutation Testing Examples

## Running Stryker (JavaScript)

```bash
# Install
npm install --save-dev @stryker-mutator/core

# Run
npx stryker run

# Output:
All tests passed
Ran 45 tests across 12 mutants (10 survived, 2 killed)

#12. [Survived] ArithmeticOperator
src/calculator.js:5:12
-   return a + b;
+   return a - b;
```

## Running mutmut (Python)

```bash
# Install
pip install mutmut

# Run
mutmut run

# Show results
mutmut results
mutmut apply 123  # Apply mutant to see change
```

## Interpreting Results

```
Mutation Score: 73%
- Killed: 33 ✓
- Survived: 12 ✗

Surviving mutants indicate test gaps.
```

## Improving Tests to Kill Mutants

**Before (mutant survives):**
```javascript
test('add exists', () => {
  expect(calculator.add).toBeDefined();  // Passes even with bug!
});
```

**After (mutant killed):**
```javascript
test('adds two numbers', () => {
  expect(calculator.add(2, 3)).toBe(5);  // Fails if + becomes -
});

test('handles negative numbers', () => {
  expect(calculator.add(-2, 3)).toBe(1);
});
```

## Configuration

```javascript
// stryker.config.json
{
  "testRunner": "jest",
  "mutate": ["src/**/*.js"],
  "thresholds": {
    "high": 90,
    "low": 80,
    "break": 75
  }
}
```

## Target Scores

| Code Type | Target |
|-----------|--------|
| Critical | 90%+ |
| Standard | 70-80% |
| UI/Boilerplate | 50-60% |

## Best Practices

- Review each surviving mutant
- Aim for 80%+ on critical code
- Don't chase 100% (diminishing returns)
- Run in CI on key files
