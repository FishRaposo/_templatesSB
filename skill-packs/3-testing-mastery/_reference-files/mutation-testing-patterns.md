<!-- Generated from task-outputs/task-09-mutation.md -->

# Mutation Testing with Stryker

A guide to mutation testing for verifying test quality, identifying test gaps, and improving mutation scores.

## Overview

This guide covers:
- Stryker configuration for JavaScript/TypeScript
- Running mutation tests
- Analyzing surviving mutants
- Improving tests to kill survivors
- Documenting equivalent mutants
- Achieving 80%+ mutation scores

## Stryker Configuration

```json
// stryker.config.json
{
  "$schema": "https://stryker-mutator.io/schema/stryker-config.json",
  "testRunner": "jest",
  "coverageAnalysis": "perTest",
  "reporters": ["progress", "clear-text", "html", "json"],
  "htmlReporter": {
    "fileName": "reports/mutation/index.html"
  },
  "mutate": [
    "src/**/*.js",
    "!src/**/__tests__/**",
    "!src/**/*.test.js"
  ],
  "mutator": {
    "excludedMutations": ["StringLiteral", "ArrayDeclaration"]
  },
  "thresholds": {
    "high": 90,
    "low": 80,
    "break": 70
  }
}
```

## Running Mutation Tests

```bash
# Install Stryker
npm install --save-dev @stryker-mutator/core @stryker-mutator/jest-runner

# Run mutation tests
npx stryker run

# Run with specific config
npx stryker run --configFile stryker.config.json
```

## Sample Output

```
Mutation testing  [====================] 100%

Ran 45 tests across 32 mutants (4 survived, 28 killed, 0 timeout)

Mutation score: 87.5%

Survived mutants:
#1. [Survived] ArithmeticOperator - EQUIVALENT
  src/discount.js:16:28
  -     const discount = price * (discountPercent / 100);
  +     const discount = price * (discountPercent * 100);

#2. [Survived] ConditionalBoundary
  src/discount.js:8:23
  -     if (discountPercent <= 0) {
  +     if (discountPercent < 0) {
```

## Analyzing Survivors

```javascript
// mutant-analysis.js
function analyzeSurvivors(report) {
  const survivors = report.files
    .flatMap(file => 
      file.mutants
        .filter(m => m.status === 'Survived')
        .map(m => ({
          file: file.source,
          line: m.location.start.line,
          mutator: m.mutatorName,
          gap: identifyGap(m.mutatorName)
        }))
    );

  return {
    totalSurvivors: survivors.length,
    testGaps: survivors.map(s => s.gap)
  };
}

function identifyGap(mutatorName) {
  const gaps = {
    'ArithmeticOperator': 'Missing test for operation result',
    'ConditionalBoundary': 'Missing test for boundary value',
    'EqualityOperator': 'Missing test for condition variation'
  };
  return gaps[mutatorName] || 'Review test coverage';
}
```

## Improving Tests

```javascript
// BEFORE (mutant survives):
test('applies discount', () => {
  expect(applyDiscount(100, 10)).toBe(90);
});

// AFTER (mutant killed):
test('applies discount', () => {
  expect(applyDiscount(100, 10)).toBe(90);
  expect(applyDiscount(200, 25)).toBe(150); // Kill + → -
});

test('handles boundary values', () => {
  expect(applyDiscount(100, 0)).toBe(100);
  expect(applyDiscount(100, 0.01)).toBeCloseTo(99.99); // Kill >= → >
  expect(applyDiscount(100, 100)).toBe(0);
});
```

## Progression

| Phase | Score | Killed | Survived |
|-------|-------|--------|----------|
| Initial | 43.75% | 14 | 18 |
| After Improvements | 87.5% | 28 | 4 |
| Effective | 100% | 28 | 0 |

## Best Practices

1. **Boundary testing kills most mutants** — Test at exact thresholds
2. **Multiple assertions help** — Catch arithmetic operator changes
3. **Negative cases matter** — Validate error paths
4. **80% is a good target** — 100% often impractical
