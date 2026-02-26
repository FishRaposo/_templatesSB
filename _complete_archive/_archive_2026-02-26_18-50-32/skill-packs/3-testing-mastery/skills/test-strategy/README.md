# Test Strategy

Design a practical testing approach that balances confidence with cost.

## Quick Start

```
Testing Pyramid:
- Unit Tests (70%) — Fast, cheap, many
- Integration (20%) — Medium cost, some
- E2E (10%) — Slow, expensive, few
```

## The Testing Pyramid

```
    /\
   /  \        E2E Tests
  /----\       (Critical paths)
 /      \
/--------\
/          \    Unit Tests
/------------\  (Business logic)
```

## Risk-Based Testing

| Component | Impact | Complexity | Priority |
|-----------|--------|------------|----------|
| Payment | High | Medium | **Critical** |
| Auth | High | Low | **High** |
| Dashboard | Low | Medium | **Medium** |

## What to Test

**Always:**
- Business-critical paths
- Security-sensitive code
- Data mutations
- Error handling

**Sometimes:**
- Simple getters/setters
- Generated code
- UI styling

## Example Test Plan

```
Feature: Checkout
├── Unit (12 tests)
│   ├── Price calculation
│   ├── Discount logic
│   └── Validation
├── Integration (4 tests)
│   ├── Cart + Inventory
│   └── Cart + Payment
└── E2E (2 tests)
    ├── Happy path
    └── Error path
```

## Key Principles

- Quality over quantity
- Risk-based prioritization
- Test maintenance matters
- Right test for right layer

## Examples

See `examples/basic-examples.md` for full test strategy examples.

## Related Skills

- `unit-testing` — Execute unit test strategy
- `integration-testing` — Execute integration strategy
- `test-automation` — Automate the pipeline
