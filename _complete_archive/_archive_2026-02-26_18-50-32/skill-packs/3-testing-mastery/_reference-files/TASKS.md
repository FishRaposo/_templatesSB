# Verification Tasks

These tasks generate reference files by exercising skills in realistic scenarios. Run each task as a fresh agent conversation, save output to `task-outputs/`, then convert to standalone reference files.

## Task 1: Unit Testing with Mocking

**Skills**: unit-testing, test-doubles

**Task**:
Write comprehensive unit tests for an OrderService class with the following requirements:
- OrderService depends on PaymentGateway, InventoryService, and EmailService
- Implement calculateTotal() with discounts and tax
- Implement processOrder() workflow
- Use test doubles for all dependencies
- Achieve 90%+ coverage
- Include edge cases: empty cart, invalid discount codes, out-of-stock items

**Output**: `task-outputs/task-01-unit-testing.md`

---

## Task 2: API Integration Testing

**Skills**: integration-testing, test-data-management

**Task**:
Set up integration tests for a REST API with:
- PostgreSQL database using testcontainers
- API endpoints: POST /users, GET /users/:id, POST /orders
- Test complete user registration → login → create order flow
- Use data factories for test data
- Include database cleanup between tests
- Test error cases: 400, 404, 409 responses

**Output**: `task-outputs/task-02-api-integration.md`

---

## Task 3: CI/CD Test Automation

**Skills**: test-automation, test-strategy

**Task**:
Configure a complete CI/CD pipeline for a Node.js/Express project:
- GitHub Actions workflow
- Run unit tests with Jest
- Run integration tests with test database
- Generate coverage reports
- Parallel test execution
- Cache dependencies
- Fail fast on first failure
- Upload artifacts

**Output**: `task-outputs/task-03-ci-automation.md`

---

## Task 4: TDD String Calculator

**Skills**: test-driven-development

**Task**:
Implement a String Calculator following strict TDD:
1. Start with empty string returns 0
2. Single number returns itself
3. Two numbers comma-delimited returns sum
4. Handle newlines as delimiters
5. Support custom delimiters
6. Ignore numbers > 1000
7. Throw exception for negative numbers

Show complete Red-Green-Refactor cycle for each feature.

**Output**: `task-outputs/task-04-tdd-calculator.md`

---

## Task 5: Load Testing Setup

**Skills**: performance-testing

**Task**:
Set up performance testing for an e-commerce API:
- Use k6 for load testing
- Define performance SLAs (p95 < 200ms, throughput > 1000 RPS)
- Create load test scenarios: ramp up, steady state, stress
- Test product search, add to cart, checkout endpoints
- Generate HTML report
- Analyze results and identify bottlenecks

**Output**: `task-outputs/task-05-performance.md`

---

## Task 6: BDD Checkout Flow

**Skills**: behavior-driven-development

**Task**:
Write BDD specifications for an e-commerce checkout:
- Feature: Shopping Cart Checkout
- Scenarios: successful purchase, empty cart, invalid payment, out of stock
- Write Gherkin Given-When-Then specifications
- Implement step definitions
- Test through API layer
- Generate living documentation

**Output**: `task-outputs/task-06-bdd-checkout.md`

---

## Task 7: Test Data Factories

**Skills**: test-data-management

**Task**:
Build comprehensive test data factories:
- UserFactory with realistic data (faker)
- ProductFactory with variants
- OrderFactory with associations
- AddressFactory
- PaymentMethodFactory
- Show complex object graph creation
- Demonstrate database seeding at scale (10k records)

**Output**: `task-outputs/task-07-factories.md`

---

## Task 8: Debugging Flaky Tests

**Skills**: debugging-tests

**Task**:
Debug and fix a suite of flaky tests:
- Test 1: Timing-dependent async test
- Test 2: Random data collision
- Test 3: Shared state between tests
- Test 4: Race condition in database
- Show systematic debugging approach
- Apply fixes and verify stability (100 runs)

**Output**: `task-outputs/task-08-debugging.md`

---

## Task 9: Mutation Testing Analysis

**Skills**: mutation-testing

**Task**:
Run mutation testing on a codebase:
- Set up Stryker (JS) or mutmut (Python)
- Analyze survived mutants
- Identify test gaps
- Improve tests to kill survivors
- Document equivalent mutants
- Achieve 80%+ mutation score

**Output**: `task-outputs/task-09-mutation.md`

---

## Task 10: Visual Regression Setup

**Skills**: visual-testing

**Task**:
Set up visual regression testing:
- Configure Playwright screenshot testing
- Test responsive layouts (mobile, tablet, desktop)
- Handle dynamic content (timestamps, charts)
- Cross-browser testing (Chrome, Firefox, Safari)
- CI integration with baseline approval
- Component-level testing with Storybook

**Output**: `task-outputs/task-10-visual.md`

---

## Combined Tasks

### Combined Task 1: Full Testing Strategy

**Skills**: test-strategy, unit-testing, integration-testing, test-automation

**Task**:
Design and implement a complete testing strategy for a microservices project:
- Define testing pyramid (70/20/10 split)
- Risk-based testing approach
- Unit tests for domain logic
- Integration tests for service communication
- Contract testing with Pact
- E2E tests for critical paths
- CI/CD pipeline with all test stages
- Coverage and quality gates

**Output**: `task-outputs/combined-01-full-strategy.md`

### Combined Task 2: Testing Legacy Code

**Skills**: unit-testing, test-doubles, debugging-tests, refactoring

**Task**:
Add tests to untested legacy code:
- Characterization testing to understand behavior
- Refactor for testability (dependency injection)
- Use test doubles for external dependencies
- Incremental test addition
- Maintain existing behavior
- Identify and fix bugs revealed by testing

**Output**: `task-outputs/combined-02-legacy.md`

---

## Task Output Format

Each task output should include:

```markdown
# Task N: Title

## Task Description
[Repeat task description]

## Solution

### Step 1: ...
[Code and explanation]

### Step 2: ...
[Code and explanation]

## Results
- What was achieved
- Metrics (coverage, mutation score, performance numbers)
- Any issues encountered

## Key Learnings
- What worked well
- What to avoid
- Best practices demonstrated
```

## Generation Schedule

| Task | Priority | Skills | Status |
|------|----------|--------|--------|
| 1 | High | unit-testing, test-doubles | Pending |
| 2 | High | integration-testing | Pending |
| 3 | High | test-automation | Pending |
| 4 | Medium | test-driven-development | Pending |
| 5 | Medium | performance-testing | Pending |
| 6 | Medium | behavior-driven-development | Pending |
| 7 | Medium | test-data-management | Pending |
| 8 | Low | debugging-tests | Pending |
| 9 | Low | mutation-testing | Pending |
| 10 | Low | visual-testing | Pending |
| Combined 1 | High | Multiple | Pending |
| Combined 2 | Medium | Multiple | Pending |

## Conversion Process

After running a task:
1. Save raw output to `task-outputs/task-NN-name.md`
2. Convert to standalone reference file in `reference-files/`
3. Remove task language, rename descriptively
4. Add header: `<!-- Generated from task-outputs/task-NN-name.md -->`
5. Update `INDEX.md` with reference file details
