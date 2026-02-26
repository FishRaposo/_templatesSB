# Reference Files Index

This directory contains worked reference implementations demonstrating testing skills in practice.

## Testing Patterns

| File | Skills | Topics |
|------|--------|--------|
| [unit-testing-patterns.md](./unit-testing-patterns.md) | unit-testing, test-doubles | OrderService with mocks, 90%+ coverage, JS/Python/Go |
| [api-integration-patterns.md](./api-integration-patterns.md) | integration-testing | PostgreSQL testcontainers, data factories, error cases |
| [ci-automation-patterns.md](./ci-automation-patterns.md) | test-automation | GitHub Actions CI/CD, parallel execution, coverage gates |
| [tdd-patterns.md](./tdd-patterns.md) | test-driven-development | String Calculator TDD walkthrough, Red-Green-Refactor |
| [performance-testing-patterns.md](./performance-testing-patterns.md) | performance-testing | k6 load testing, SLAs, bottleneck analysis |
| [bdd-patterns.md](./bdd-patterns.md) | behavior-driven-development | Gherkin scenarios, Cucumber.js, living documentation |
| [test-data-factories.md](./test-data-factories.md) | test-data-management | Factory patterns, faker.js, 10k record seeding |
| [debugging-flaky-tests.md](./debugging-flaky-tests.md) | debugging-tests | Flaky test fixes, timing issues, race conditions |
| [mutation-testing-patterns.md](./mutation-testing-patterns.md) | mutation-testing | Stryker setup, test gaps, 80%+ mutation score |
| [visual-testing-patterns.md](./visual-testing-patterns.md) | visual-testing | Playwright visual regression, responsive testing |
| [testing-strategy-guide.md](./testing-strategy-guide.md) | test-strategy | Microservices testing pyramid, risk-based testing |
| [testing-legacy-code.md](./testing-legacy-code.md) | legacy-code-migration | Characterization testing, refactoring for testability |

## Skill Integrations

See `skill-integrations.md` for examples showing how skills work together:
- TDD + Unit Testing + Test Doubles
- Integration Testing + Test Data Management
- BDD + Integration Testing
- Performance Testing + Test Automation

## Quick Lookup by Scenario

| Scenario | Reference Files |
|----------|-----------------|
| **Setting up testing framework** | unit-testing, test-strategy |
| **Writing first test** | test-driven-development, unit-testing |
| **Testing with database** | integration-testing, test-data-management |
| **Testing APIs** | integration-testing, test-doubles |
| **CI/CD setup** | test-automation, test-strategy |
| **Testing legacy code** | unit-testing, test-doubles, debugging-tests |
| **Visual regression** | visual-testing |
| **Performance validation** | performance-testing |
| **Test quality** | mutation-testing, test-strategy |

## By Language

### JavaScript/TypeScript
- Jest configuration and patterns
- Playwright visual testing
- React Testing Library patterns
- Supertest API testing

### Python
- pytest fixtures and markers
- factory_boy patterns
- responses HTTP mocking
- locust performance testing

### Go
- testing package patterns
- testify assertions
- testcontainers integration
- gomock usage

## Reference File Format

Each reference file follows this structure:

```markdown
# Title

## Problem Statement
Clear description of what problem this solves.

## Solution Overview
High-level approach.

## Implementation
Complete, runnable code examples.

## Best Practices
What to do and what to avoid.

## Related Skills
Links to skills used in this example.
```

## Generation Status

Reference files are generated from verification tasks (see `TASKS.md`).

| Status | Count |
|--------|-------|
| Planned | 12 |
| In Progress | 0 |
| Completed | 12 |

**All reference files generated:**
- ✅ unit-testing-patterns.md
- ✅ api-integration-patterns.md
- ✅ ci-automation-patterns.md
- ✅ tdd-patterns.md
- ✅ performance-testing-patterns.md
- ✅ bdd-patterns.md
- ✅ test-data-factories.md
- ✅ debugging-flaky-tests.md
- ✅ mutation-testing-patterns.md
- ✅ visual-testing-patterns.md
- ✅ testing-strategy-guide.md
- ✅ testing-legacy-code.md

Last Updated: 2026-02-17
