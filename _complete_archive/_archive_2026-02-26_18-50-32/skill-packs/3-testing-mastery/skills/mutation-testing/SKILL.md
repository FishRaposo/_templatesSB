---
name: mutation-testing
description: Use this skill when verifying test quality through mutation testing. This includes running mutation testing tools to introduce small code changes (mutants), verifying that tests catch these mutations, and identifying gaps in test coverage where mutants survive. Focus on improving test suite quality and effectiveness.
---

# Mutation Testing

I'll help you verify test quality using mutation testing — introducing small code changes to check if your tests catch them. This identifies gaps where your tests might pass even when code is broken.

## Core Approach

### What is Mutation Testing?

1. **Generate mutants** — Make small changes to source code
2. **Run tests** — Execute test suite against mutants
3. **Check survival** — Mutant survives if tests pass
4. **Kill survivors** — Add tests to catch surviving mutants

### Types of Mutations

| Type | Example | Description |
|------|---------|-------------|
| **Arithmetic** | `+` → `-` | Change operators |
| **Conditional** | `>` → `>=` | Boundary changes |
| **Negation** | `true` → `false` | Boolean flip |
| **Return** | `return x` → `return null` | Value changes |
| **Void** | Remove method call | Side effect removal |

### Metrics

- **Mutation Score** — % of mutants killed (higher is better)
- **Killed** — Test failed (good)
- **Survived** — Test passed (bad — gap in tests)
- **Timeout** — Infinite loop mutant
- **No Coverage** — Code not tested at all

## Step-by-Step Instructions

### 1. Run Mutation Testing

**JavaScript (Stryker)**
```bash
# Install
npm install --save-dev @stryker-mutator/core

# Configure (stryker.config.json)
{
  "testRunner": "jest",
  "coverageAnalysis": "perTest",
  "mutate": ["src/**/*.js"],
  "jest": {
    "projectType": "custom"
  }
}

# Run
npx stryker run
```

**Output:**
```
Mutation testing  [=====================================] 100% (elapsed: ~2m)

All tests passed
  
Ran 45 tests across 12 mutants (12 survived, 0 killed, 0 timeout)

#12. [Survived] ArithmeticOperator
src/calculator.js:5:12
-   return a + b;
+   return a - b;

Ran all tests for this mutant.

Ran 0.00 tests per mutant on average.
```

**Python (mutmut)**
```bash
# Install
pip install mutmut

# Run
mutmut run

# Show results
mutmut results
mutmut apply 123  # Apply mutant 123 to see what changed
```

**Output:**
```
- Progress: 45/45 (100%)
- Killed: 33 (73%)
- Survived: 12 (27%)
- Timeout: 0

Survived 🙁 (12)

---- src/calculator.py (12) ----

1, 12: 5s  ⌀ calculator.py
      return a + b
->    return a - b
```

**Java (PIT)**
```xml
<!-- pom.xml -->
<plugin>
  <groupId>org.pitest</groupId>
  <artifactId>pitest-maven</artifactId>
  <version>1.9.0</version>
</plugin>
```

```bash
mvn org.pitest:pitest-maven:mutationCoverage
```

### 2. Analyze Surviving Mutants

```
Survived mutant: return a + b → return a - b
Location: calculator.js:5:12

Investigation:
├── Tests exist for addition? YES
├── Tests check the result? NO — only check that function runs
└── Gap: No assertion on return value

Fix: Add assertion
```

### 3. Improve Tests to Kill Mutants

**Before (mutant survives):**
```javascript
// calculator.test.js
test('add exists', () => {
  expect(calculator.add).toBeDefined();  // Passes even with bug!
});
```

**After (mutant killed):**
```javascript
// calculator.test.js
test('adds two numbers', () => {
  expect(calculator.add(2, 3)).toBe(5);  // Fails if + becomes -
});

test('handles negative numbers', () => {
  expect(calculator.add(-2, 3)).toBe(1);
  expect(calculator.add(-2, -3)).toBe(-5);
});
```

### 4. Handle Equivalent Mutants

Some mutants are semantically identical:

```javascript
// Original
return a + b;

// Mutant (equivalent)
return b + a;  // Same for addition

// Mutant (not equivalent)
return a - b;  // Different behavior
```

**Ignore equivalent mutants** — they don't represent real gaps.

## Multi-Language Examples

### Complete Workflow

**JavaScript Project**
```javascript
// src/discount.js
function applyDiscount(price, discountPercent) {
  if (discountPercent <= 0) return price;
  if (discountPercent >= 100) return 0;
  
  const discount = price * (discountPercent / 100);
  return price - discount;
}

// test/discount.test.js (initial)
describe('applyDiscount', () => {
  test('applies discount', () => {
    expect(applyDiscount(100, 10)).toBe(90);
  });
  
  test('handles zero discount', () => {
    expect(applyDiscount(100, 0)).toBe(100);
  });
});
```

**Run mutation testing:**
```bash
npx stryker run
# Mutation score: 40% (survived mutants on boundary conditions)
```

**Analyze survivors:**
```
Survived:
1. discountPercent > 0 → discountPercent >= 0
   (No test for 0.01% discount)
   
2. discountPercent >= 100 → discountPercent > 100
   (No test for exactly 100%)
   
3. return price - discount → return price + discount
   (Only tested 10%, mutation adds instead)
```

**Improve tests:**
```javascript
describe('applyDiscount', () => {
  test('applies discount', () => {
    expect(applyDiscount(100, 10)).toBe(90);
    expect(applyDiscount(200, 25)).toBe(150);  // Kill + mutant
  });
  
  test('handles zero discount', () => {
    expect(applyDiscount(100, 0)).toBe(100);
    expect(applyDiscount(100, 0.01)).toBeCloseTo(99.99);  // Kill >= mutant
  });
  
  test('handles 100% discount', () => {
    expect(applyDiscount(100, 100)).toBe(0);  // Kill > mutant
  });
  
  test('caps at 100%', () => {
    expect(applyDiscount(100, 150)).toBe(0);
  });
});
```

**Re-run mutation testing:**
```bash
npx stryker run
# Mutation score: 100% 🎉
```

### Selective Mutation Testing

**JavaScript (Stryker)**
```json
{
  "mutate": [
    "src/**/*.js",
    "!src/**/__tests__/**",
    "!src/**/*.test.js",
    "!src/generated/**"
  ],
  "mutator": {
    "excludedMutations": [
      "StringLiteral",  // "hello" → ""
      "ArrayDeclaration"  // [1, 2] → []
    ]
  }
}
```

**Python (mutmut)**
```bash
# Run only on specific module
mutmut run --paths-to-mutate=src/core

# Exclude files
mutmut run --ignore-files="src/generated/*"
```

## Best Practices

### Mutation Score Goals

| Context | Target Score | Notes |
|---------|---------------|-------|
| Critical code | 90%+ | Payment, auth, core business logic |
| Standard code | 70-80% | Most application code |
| UI/boilerplate | 50-60% | Less critical, harder to test |
| Generated code | Ignore | Don't mutate generated code |

### Focus Areas

Prioritize killing mutants in:
1. Business logic
2. Edge case handling
3. Error paths
4. Boundary conditions

### CI Integration

```yaml
# .github/workflows/mutation.yml
name: Mutation Testing

on:
  push:
    branches: [main]
  pull_request:
    paths: ['src/**/*.js']

jobs:
  mutation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      
      - name: Run mutation tests
        run: npx stryker run
        
      - name: Check mutation score
        run: |
          SCORE=$(cat reports/mutation/mutation.json | jq '.mutationScore')
          if [ $SCORE -lt 80 ]; then
            echo "Mutation score $SCORE is below 80%"
            exit 1
          fi
```

## Common Pitfalls

❌ **Aiming for 100% mutation score**
- Diminishing returns after 80-90%
- Equivalent mutants waste time
- Focus on meaningful tests

❌ **Ignoring survived mutants**
```bash
# Bad: just looking at score
mutmut run  # Score: 75%
# "Good enough" — missed real gaps!

# Good: review each survivor
mutmut results  # Analyze each one
```

❌ **Running on all code always**
```bash
# Slow for large codebases
mutmut run  # Takes 2 hours

# Better: incremental on changed files
mutmut run --paths-to-mutate=$(git diff --name-only)
```

## Validation Checklist

- [ ] Mutation testing tool is configured
- [ ] Score goal is set appropriately (not 100%)
- [ ] Surviving mutants are reviewed, not ignored
- [ ] Equivalent mutants are identified
- [ ] Critical code has high mutation score (>90%)
- [ ] CI runs mutation tests on relevant changes
- [ ] Test improvements target surviving mutants

## Related Skills

- **unit-testing** — What mutation testing validates
- **test-strategy** — When to use mutation testing
- **test-coverage** — Code coverage vs mutation coverage
