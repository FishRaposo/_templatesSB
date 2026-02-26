# Testing Mastery — Quick Reference

> Decision tree and scenario lookup for testing skills

## Decision Tree: Which Testing Skill?

```
What do you need to do?
├── Write code + test simultaneously
│   └── → test-driven-development (TDD cycle)
├── Test a single function/class in isolation
│   └── → unit-testing
├── Test components working together
│   └── → integration-testing
├── Mock/stub dependencies
│   └── → test-doubles
├── Define system behavior with examples
│   └── → behavior-driven-development
├── Set up CI/CD with automated tests
│   └── → test-automation
├── Test under load/stress
│   └── → performance-testing
├── Design overall testing approach
│   └── → test-strategy
├── Create or manage test data
│   └── → test-data-management
├── Understand why tests fail
│   └── → debugging-tests
├── Verify test quality/coverage
│   └── → mutation-testing
├── Check UI hasn't changed unexpectedly
│   └── → visual-testing
```

## By Scenario

### Starting a New Project

| Need | Skill | Quick Action |
|------|-------|--------------|
| Decide testing approach | test-strategy | Define test pyramid, coverage goals, CI integration |
| Write first test | test-driven-development | Red-Green-Refactor cycle |
| Set up test runner | test-automation | Configure Jest/pytest/go test |

### Working on Existing Code

| Need | Skill | Quick Action |
|------|-------|--------------|
| Add tests for untested code | unit-testing | Identify public interfaces, write characterization tests |
| Test refactored code | debugging-tests | Run tests, analyze failures, fix issues |
| Test with database/API | integration-testing | Use test containers, spin up services |
| Mock external calls | test-doubles | Create stubs for HTTP/database |
| Add tests for untested legacy code | unit-testing | Characterization testing, refactoring legacy code |

### Testing Specific Aspects

| Aspect | Skill | Quick Action |
|--------|-------|--------------|
| Function correctness | unit-testing | Assert inputs produce expected outputs |
| Component interaction | integration-testing | Test API contracts, data flow |
| System behavior | behavior-driven-development | Given-When-Then scenarios |
| Load handling | performance-testing | Load tests, stress tests, benchmarks |
| UI consistency | visual-testing | Screenshot comparison, pixel diff |
| Test quality | mutation-testing | Run mutation testing, kill mutants |

### CI/CD & Automation

| Need | Skill | Quick Action |
|------|-------|--------------|
| Run tests automatically | test-automation | GitHub Actions, GitLab CI, etc. |
| Fast test feedback | unit-testing | Keep tests fast, parallelize |
| Test database migrations | integration-testing | Test containers, migration tests |
| Manage test environments | test-data-management | Fixtures, factories, seed data |

## Skill Relationships

### Dependencies (use in order)
1. **test-strategy** → informs all other skills
2. **test-driven-development** → produces → **unit-testing**
3. **test-doubles** → enables → **unit-testing** (isolation)
4. **unit-testing** → builds up to → **integration-testing**
5. **integration-testing** → automates via → **test-automation**

### Alternative Approaches

| Goal | Approach A | Approach B |
|------|-----------|-----------|
| Verify correctness | unit-testing | test-driven-development |
| Test interactions | integration-testing | behavior-driven-development |
| Ensure quality | mutation-testing | code-coverage + review |

## Cross-Pack Skill Combinations

### With Programming Core (Pack 1)

| Combination | Use Case |
|-------------|----------|
| test-driven-development + algorithms | Test complex algorithmic solutions |
| unit-testing + data-structures | Verify data structure operations |
| debugging-tests + problem-solving | Debug failing tests systematically |

### With Code Quality (Pack 2)

| Combination | Use Case |
|-------------|----------|
| test-driven-development + clean-code | Tests guide clean implementation |
| mutation-testing + code-quality-review | Verify tests catch bad code |
| unit-testing + code-refactoring | Refactor with confidence |

## Quick Lookup: Test Types

| Type | Scope | Speed | When to Use |
|------|-------|-------|-------------|
| Unit | Single function/class | < 10ms | Business logic, algorithms |
| Integration | Multiple components | < 1s | API contracts, database |
| End-to-end | Full system flow | Seconds | Critical user journeys |
| Performance | System under load | Minutes | Capacity planning |
| Visual | UI appearance | Seconds | UI consistency |

## Reference Files

The `reference-files/` directory contains standalone implementation guides demonstrating each skill in practice. See the [INDEX](./reference-files/INDEX.md) for the complete list.

### Quick Access by Task

| Task | Reference File |
|------|----------------|
| Unit testing with mocks | [unit-testing-patterns.md](./reference-files/unit-testing-patterns.md) |
| API integration testing | [api-integration-patterns.md](./reference-files/api-integration-patterns.md) |
| CI/CD setup | [ci-automation-patterns.md](./reference-files/ci-automation-patterns.md) |
| TDD walkthrough | [tdd-patterns.md](./reference-files/tdd-patterns.md) |
| Load testing | [performance-testing-patterns.md](./reference-files/performance-testing-patterns.md) |
| BDD scenarios | [bdd-patterns.md](./reference-files/bdd-patterns.md) |
| Test data factories | [test-data-factories.md](./reference-files/test-data-factories.md) |
| Fix flaky tests | [debugging-flaky-tests.md](./reference-files/debugging-flaky-tests.md) |
| Mutation testing | [mutation-testing-patterns.md](./reference-files/mutation-testing-patterns.md) |
| Visual regression | [visual-testing-patterns.md](./reference-files/visual-testing-patterns.md) |
| Full testing strategy | [testing-strategy-guide.md](./reference-files/testing-strategy-guide.md) |
| Testing legacy code | [testing-legacy-code.md](./reference-files/testing-legacy-code.md) |

## Gotchas & Tips

- **Don't test implementation details** — tests should pass even if implementation changes
- **Fast tests are valuable tests** — slow tests get skipped or ignored
- **One assertion per test** — or at least one logical concept per test
- **Descriptive test names** — the name should explain what's being tested
- **Arrange-Act-Assert** — structure tests clearly (Given-When-Then for BDD)
