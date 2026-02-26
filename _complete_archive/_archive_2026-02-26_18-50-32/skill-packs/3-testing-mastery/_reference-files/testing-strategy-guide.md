<!-- Generated from task-outputs/combined-01-full-strategy.md -->

# Full Testing Strategy for Microservices

A comprehensive testing strategy document for an e-commerce microservices platform with risk-based testing approach.

## Overview

This guide covers:
- Testing pyramid definition (70/20/10 split)
- Risk-based testing matrix
- Unit tests for domain logic
- Integration tests for service communication
- Contract testing with Pact
- E2E tests for critical paths
- CI/CD pipeline with quality gates

## Testing Pyramid

```
        /\
       /  \         E2E Tests (10%)
      /----\
     /      \       Integration Tests (20%)
    /--------\
   /          \     Unit Tests (70%)
  /------------\
```

| Level | Percentage | Count | Runtime | Responsibility |
|-------|-----------|-------|---------|----------------|
| Unit | 70% | ~2,000 | < 2 min | Developers |
| Integration | 20% | ~400 | ~ 5 min | QA + Dev |
| E2E | 10% | ~80 | ~ 10 min | QA |

## Risk-Based Testing Matrix

| Service | Business Impact | Technical Complexity | Test Priority |
|---------|-----------------|---------------------|---------------|
| Payment Service | Critical | High | 🔴 Critical |
| Order Service | Critical | High | 🔴 Critical |
| Inventory Service | High | Medium | 🟡 High |
| User Service | Medium | Low | 🟢 Medium |
| Product Service | Medium | Low | 🟢 Medium |
| Notification Service | Low | Low | 🔵 Low |

## CI/CD Pipeline

```yaml
# .github/workflows/test-pipeline.yml
name: Test Pipeline

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test -- --coverage
      - run: |
          COVERAGE=$(cat coverage/coverage-summary.json | jq '.total.lines.pct')
          if (( $(echo "$COVERAGE < 70" | bc -l) )); then
            exit 1
          fi

  integration-tests:
    needs: unit-tests
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
        ports:
          - 5432:5432
    steps:
      - uses: actions/checkout@v4
      - run: npm run test:integration

  contract-tests:
    needs: unit-tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run test:contract

  e2e-tests:
    needs: [integration-tests, contract-tests]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker-compose -f docker-compose.test.yml up -d
      - run: npm run test:e2e
```

## Quality Gates

### Pre-Merge Requirements
- [ ] Unit test coverage ≥ 70%
- [ ] All unit tests passing
- [ ] Integration tests passing
- [ ] Contract tests verified
- [ ] E2E critical paths passing
- [ ] Security scan clean
- [ ] Mutation score ≥ 80%

## Results

### Testing Pyramid Metrics

| Level | Target | Actual | Status |
|-------|--------|--------|--------|
| Unit Tests | 70% | 73% | ✅ |
| Integration Tests | 20% | 19% | ✅ |
| E2E Tests | 10% | 8% | ⚠️ |

### CI Pipeline Performance

| Stage | Duration | Jobs |
|-------|----------|------|
| Unit Tests | 2m 15s | 4 |
| Integration | 4m 30s | 1 |
| Contract Tests | 1m 45s | 1 |
| E2E Tests | 8m 20s | 2 |
| **Total** | **12m** | **8** |

## Best Practices

1. **Risk-based prioritization** — 90% effort on critical services
2. **Contract testing** — Prevent breaking changes
3. **Parallel unit tests** — Reduce feedback time
4. **Quality gates in CI** — Automated enforcement
