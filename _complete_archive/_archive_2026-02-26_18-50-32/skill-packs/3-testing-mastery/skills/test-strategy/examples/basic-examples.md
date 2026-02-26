# Test Strategy Examples

## Testing Pyramid Example

```
    /\
   /  \        E2E Tests (10%)
  /----\       Critical user journeys
 /      \
/--------\
/          \    Integration Tests (20%)
/------------\  Component interactions
/--------------\
/                \  Unit Tests (70%)
/------------------\ Business logic
```

## Risk-Based Testing Plan

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

## Testing Pyramid

### Unit Tests (Target: 80% coverage)
**Focus:** Business logic, calculations, validations

**Components to test:**
- [ ] Cart price calculations
- [ ] Discount engine
- [ ] Tax calculator
- [ ] Order validation rules

### Integration Tests (Target: Key flows)
**Focus:** Component interactions, API contracts

**Test scenarios:**
1. Cart → Inventory (stock validation)
2. Order → Payment (charge flow)
3. Order → Email (confirmation)

### E2E Tests (Target: 5 critical flows)
**Focus:** Complete user journeys

**Critical paths:**
1. Browse → Add to cart → Checkout → Payment
2. User registration → Login → Profile update
3. Order cancellation → Refund flow

## Environments

### CI Pipeline
- Unit tests: Every commit (< 2 min)
- Integration: Every PR (< 5 min)
- E2E: Before merge (< 10 min)

## Success Metrics

- Unit test coverage: ≥ 80%
- Integration test pass rate: 100%
- E2E test pass rate: ≥ 95%
```

## Decision Tree

```
What to test?
├── Business logic / algorithms
│   └── → Unit tests with edge cases
├── Component interactions
│   └── → Integration tests with real dependencies
├── User workflows
│   └── → E2E tests for critical paths only
└── Performance requirements
    └── → Load/performance tests
```

## Coverage Goals by Risk

| Component | Risk | Unit | Integration | E2E |
|-----------|------|------|-------------|-----|
| Payment | High | 95% | Full | Critical path |
| Cart | Medium | 80% | Key flows | Spot check |
| Analytics | Low | 60% | None | None |

## Best Practices

- Test effort proportional to risk
- 70/20/10 unit/integration/e2e split
- Automate everything in CI
- Quality over quantity
