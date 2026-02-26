# Testing Mastery

**Pack ID**: 3-testing-mastery  
**Category**: Programming Fundamentals  
**Skills Count**: 12  

## Overview

This pack provides comprehensive testing strategies and implementation patterns that apply across all languages and frameworks. All skills include examples in **JavaScript**, **Python**, and **Go**, showing how testing concepts manifest differently across language ecosystems. Skills progress from individual unit tests to complete testing strategies, covering both manual testing techniques and automated testing pipelines.

## Skills Included

1. **test-driven-development** - Write tests before code to drive design
2. **unit-testing** - Create effective unit tests for components
3. **integration-testing** - Test component interactions and integration
4. **test-automation** - Build automated testing pipelines
5. **test-doubles** - Create mocks, stubs, and fakes for testing
6. **behavior-driven-development** - Define behavior through examples
7. **performance-testing** - Test system performance under load
8. **test-strategy** - Design comprehensive testing strategies
9. **test-data-management** - Manage test data effectively
10. **debugging-tests** - Debug failing tests efficiently
11. **mutation-testing** - Use mutation testing for test quality
12. **visual-testing** - Implement visual regression testing

## When to Use This Pack

Invoke skills from this pack when you need to:
- Write tests before or alongside implementation (TDD)
- Test individual functions, classes, or modules in isolation
- Test how components work together
- Set up CI/CD pipelines with automated testing
- Mock dependencies for isolated testing
- Define and verify system behavior
- Verify system performance under load
- Design a comprehensive testing approach for a project
- Create and manage test data effectively
- Understand why tests fail and fix them
- Verify test quality and coverage
- Ensure UI consistency across changes

## Skill Relationships & Workflows

### Progression:
- **test-strategy** → All other skills (strategy informs tactics)
- **unit-testing** → **integration-testing** → **test-automation**
- **test-driven-development** → **unit-testing** (TDD produces unit tests)
- **test-doubles** → **unit-testing** (mocking enables isolated unit tests)

### By Task:

| Task | Primary Skills | Supporting Skills |
|------|----------------|-------------------|
| **Implement new feature with TDD** | test-driven-development, unit-testing | test-doubles |
| **Verify component works with dependencies** | integration-testing, test-doubles | unit-testing |
| **Set up CI/CD with tests** | test-automation, unit-testing | integration-testing |
| **Define what system should do** | behavior-driven-development, test-strategy | integration-testing |
| **Ensure tests are meaningful** | mutation-testing, debugging-tests | test-strategy |
| **Test UI consistency** | visual-testing | test-automation |
| **Verify system handles load** | performance-testing | test-strategy, test-data-management |

### Cross-Pack References:
- → **1-programming-core**: algorithms, problem-solving (test complex logic)
- → **2-code-quality**: clean-code, code-refactoring (tests guide refactoring)
- → **4-performance-optimization**: performance-analysis (analyze test results)
- → **9-backend-services**: backend-development (test backend services)

## Pack Structure

```
3-testing-mastery/
├── PACK.md                  ← You are here
├── QUICK_REFERENCE.md       ← Decision tree and scenario lookup
├── skills/                  ← 12 skill directories
│   └── <skill>/
│       ├── SKILL.md         ← Skill definition, instructions, multi-language examples
│       ├── config.json      ← Cross-platform config and trigger keywords
│       ├── README.md        ← Quick start guide
│       └── examples/        ← Skill-specific examples
├── reference-files/         ← Worked reference implementations
│   ├── INDEX.md             ← Full index of all reference files
│   ├── TASKS.md             ← Verification tasks
│   ├── skill-integrations.md ← Cross-skill integration examples
│   └── *.md                 ← Standalone reference guides
```

## Reference Files

The `reference-files/` directory contains standalone implementation guides demonstrating each skill in practice. Use these as context when working on real testing problems.

### Testing Patterns & Strategies

| Reference File | Skills Covered | Topics |
|----------------|----------------|--------|
| [unit-testing-patterns.md](./reference-files/unit-testing-patterns.md) | unit-testing, test-doubles | OrderService with mocks, 90%+ coverage |
| [api-integration-patterns.md](./reference-files/api-integration-patterns.md) | integration-testing | PostgreSQL testcontainers, data factories |
| [ci-automation-patterns.md](./reference-files/ci-automation-patterns.md) | test-automation | GitHub Actions CI/CD, parallel execution |
| [tdd-patterns.md](./reference-files/tdd-patterns.md) | test-driven-development | String Calculator TDD walkthrough |
| [performance-testing-patterns.md](./reference-files/performance-testing-patterns.md) | performance-testing | k6 load testing, SLAs, bottlenecks |
| [bdd-patterns.md](./reference-files/bdd-patterns.md) | behavior-driven-development | Gherkin scenarios, Cucumber.js |
| [test-data-factories.md](./reference-files/test-data-factories.md) | test-data-management | Factory patterns, 10k record seeding |
| [debugging-flaky-tests.md](./reference-files/debugging-flaky-tests.md) | debugging-tests | Flaky test fixes, 100-run verification |
| [mutation-testing-patterns.md](./reference-files/mutation-testing-patterns.md) | mutation-testing | Stryker setup, 80%+ mutation score |
| [visual-testing-patterns.md](./reference-files/visual-testing-patterns.md) | visual-testing | Playwright visual regression |
| [testing-strategy-guide.md](./reference-files/testing-strategy-guide.md) | test-strategy | Microservices pyramid, risk-based testing |
| [testing-legacy-code.md](./reference-files/testing-legacy-code.md) | legacy-code-migration | Characterization tests, refactoring |

### Key Principles

- **Test behavior, not implementation** — tests should verify what code does, not how it does it
- **Fast feedback** — unit tests should run in milliseconds; slow tests lose value
- **Deterministic results** — tests should produce the same result every time
- **Readable failures** — when tests fail, the error message should explain why
- **Test pyramid** — many unit tests, fewer integration tests, minimal end-to-end tests

### Language Coverage

All testing examples include implementations in:
- **JavaScript/TypeScript** (Jest, Mocha, Vitest)
- **Python** (pytest, unittest)
- **Go** (testing package, testify)
