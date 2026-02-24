---
name: test-strategy
description: Use this skill when designing a comprehensive testing approach for a project or feature. This includes deciding what to test, choosing test types, defining coverage goals, planning test environments, and creating a testing pyramid that balances confidence with cost. Focus on practical, risk-based testing strategies.
---

# Test Strategy

I'll help you design a practical testing approach that balances confidence with cost. We'll decide what to test, how to test it, and what "enough" testing looks like.

## Core Approach

### The Testing Pyramid

```
    /\
   /  \        E2E Tests (Few, expensive)
  /----\
 /      \      Integration Tests (Some, medium cost)
/--------\
/          \    Unit Tests (Many, cheap)
/------------\
```

| Level | Quantity | Speed | Cost | Purpose |
|-------|----------|-------|------|---------|
| **Unit** | 70% | <10ms | Low | Business logic |
| **Integration** | 20% | <1s | Medium | Component interaction |
| **E2E** | 10% | Seconds | High | Critical flows |

## Step-by-Step Instructions

### 1. Assess Risk

**Risk Matrix:**

| Component | Business Impact | Technical Complexity | Test Priority |
|-----------|-----------------|---------------------|---------------|
| Payment processing | High | Medium | **Critical** |
| User authentication | High | Low | **High** |
| Admin dashboard | Low | Medium | **Medium** |
| Analytics logging | Low | Low | **Low** |

### 2. Define What to Test

**Always Test:**
- Business-critical paths
- Security-sensitive code
- Data mutations
- External API contracts
- Error handling

**Sometimes Test:**
- Simple getters/setters
- Trivial configuration
- Generated code
- UI styling

**Example Test Plan:**
```
Feature: Shopping Cart Checkout
├── Unit Tests (12 tests)
│   ├── Price calculation (edge cases: 0, negative, large)
│   ├── Discount logic (percentage, fixed, stacked)
│   ├── Tax calculation (by region)
│   └── Validation (required fields)
├── Integration Tests (4 tests)
│   ├── Cart + Inventory (stock check)
│   ├── Cart + Pricing (full calculation)
│   ├── Cart + Payment (payment flow)
│   └── Cart + Email (confirmation)
└── E2E Tests (2 tests)
    ├── Happy path: full checkout
    └── Error path: payment failure
```

### 3. Choose Test Types

**Decision Tree:**

```
What are you testing?
├── Business logic / algorithms
│   └── → Unit tests with edge cases
├── Component interactions
│   └── → Integration tests with real dependencies
├── User workflows
│   └── → E2E tests for critical paths only
├── Performance requirements
│   └── → Load/performance tests
└── Visual consistency
    └── → Visual regression tests (if critical)
```

### 4. Set Coverage Goals

**Meaningful Coverage:**
```
Unit Tests:        80% line coverage (focus on logic)
Integration:       Key user flows covered
E2E:              Critical paths only (not everything)
```

**Quality over quantity:**
```javascript
// Bad: tests trivial code to hit 100%
test('getName returns name', () => {
  const user = new User('John');
  expect(user.getName()).toBe('John');  // Testing getter?
});

// Good: tests meaningful behavior
test('cannot withdraw more than balance', () => {
  const account = new Account(100);
  expect(() => account.withdraw(200)).toThrow('Insufficient funds');
});
```

### 5. Plan Test Environments

| Environment | Purpose | Data |
|-------------|---------|------|
| **Local** | Development | Generated/fake |
| **CI** | Pre-merge validation | Test containers |
| **Staging** | Release candidate | Production-like |
| **Production** | Smoke tests | Real (read-only) |

### 6. Define Test Data Strategy

```
Unit Tests:       Factory-generated data
Integration:      Test database with migrations
E2E:             Seeded realistic scenarios
Performance:     Production-like volume
```

## Multi-Language Examples

### Project Test Strategy Document

```markdown
# Test Strategy: E-Commerce Platform

## Scope

### In Scope
- Order processing pipeline
- Payment integration
- Inventory management
- User authentication

### Out of Scope
- Marketing website (static)
- Third-party analytics
- Email template rendering

## Testing Pyramid

### Unit Tests (Target: 80% coverage)
**Focus:** Business logic, calculations, validations

**Components to test:**
- [ ] Cart price calculations
- [ ] Discount engine
- [ ] Tax calculator
- [ ] Order validation rules

**Not testing:**
- Simple getters/setters
- Configuration loading
- Framework code

### Integration Tests (Target: Key flows)
**Focus:** Component interactions, API contracts

**Test scenarios:**
1. Cart → Inventory (stock validation)
2. Order → Payment (charge flow)
3. Order → Email (confirmation)
4. Auth → User service (permissions)

### E2E Tests (Target: 5 critical flows)
**Focus:** Complete user journeys

**Critical paths:**
1. Browse → Add to cart → Checkout → Payment
2. User registration → Login → Profile update
3. Admin: Add product → View in catalog
4. Order cancellation → Refund flow
5. Search → Filter → Add to cart

## Environments

### CI Pipeline
- Unit tests: Every commit (< 2 min)
- Integration: Every PR (< 5 min)
- E2E: Before merge (< 10 min)

### Nightly
- Full E2E suite
- Performance baseline
- Security scans

## Success Metrics

- Unit test coverage: ≥ 80%
- Integration test pass rate: 100%
- E2E test pass rate: ≥ 95%
- Mean time to detect: < 5 min in CI
- Flaky test rate: < 1%
```

### Test Selection by Change

```javascript
// smart-test-runner.js
const testStrategy = {
  // Map file patterns to test suites
  patterns: {
    'src/utils/*.js': ['unit/utils'],
    'src/services/*.js': ['unit/services', 'integration/services'],
    'src/api/*.js': ['integration/api', 'e2e/critical'],
    'src/ui/*.js': ['unit/components', 'e2e/visual'],
  },
  
  selectTests(changedFiles) {
    const tests = new Set();
    
    changedFiles.forEach(file => {
      for (const [pattern, suites] of Object.entries(this.patterns)) {
        if (minimatch(file, pattern)) {
          suites.forEach(s => tests.add(s));
        }
      }
    });
    
    return Array.from(tests);
  }
};
```

## Best Practices

### Risk-Based Testing

Spend testing effort where risk is highest:

```
High Business Impact + High Complexity → Extensive testing
High Business Impact + Low Complexity → Focus on edge cases
Low Business Impact + High Complexity → Unit tests + monitoring
Low Business Impact + Low Complexity → Minimal/spot testing
```

### The Pareto Principle

80% of value from 20% of tests:
- Identify critical 20% of code
- Test that thoroughly
- Use integration/E2E for the rest

### Test Maintenance

**Tests are code too:**
- Delete obsolete tests
- Refactor confusing tests
- Keep test code clean
- Review test changes in PRs

## Common Anti-Patterns

❌ **Testing everything**
- 100% coverage obsession
- Testing getters/setters
- Testing framework code

❌ **Wrong test type**
- Unit tests that hit database
- E2E tests for business logic
- Integration tests that mock everything

❌ **Neglecting maintenance**
- No test deletion policy
- Ignoring flaky tests
- Outdated E2E tests

## Validation Checklist

- [ ] Testing pyramid is balanced
- [ ] Critical paths have coverage
- [ ] Test environments are defined
- [ ] Coverage goals are realistic
- [ ] Test data strategy is documented
- [ ] CI pipeline runs appropriate tests
- [ ] Flaky tests are tracked and fixed
- [ ] Strategy is reviewed quarterly

## Related Skills

- **unit-testing** — Execute unit test strategy
- **integration-testing** — Execute integration test strategy
- **test-automation** — Automate the test pipeline
