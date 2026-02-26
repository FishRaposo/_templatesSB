---
name: test-automation
description: Use this skill when building automated testing pipelines for CI/CD. This includes configuring test runners, setting up pre-commit hooks, integrating tests with build systems, running tests in parallel, and generating test reports. Focus on making tests run automatically on every change.
---

# Test Automation

I'll help you build automated testing pipelines that run tests on every code change. We'll set up CI/CD integration, parallel execution, and reporting.

## Core Approach

### Automation Levels

| Level | When | Speed | Coverage |
|-------|------|-------|----------|
| **Pre-commit** | Before commit | Fast | Lint + unit |
| **Pre-push** | Before push | Medium | Unit + integration |
| **CI/CD** | On PR/merge | Full | All tests |
| **Nightly** | Scheduled | Slow | E2E + performance |

### Goals

- Tests run without human intervention
- Fast feedback (< 5 minutes for unit tests)
- Clear failure reporting
- Deterministic results

## Step-by-Step Instructions

### 1. Set Up Test Runner Configuration

**JavaScript (Jest)**
```javascript
// jest.config.js
module.exports = {
  // Test discovery
  testMatch: ['**/*.test.js'],
  
  // Parallel execution
  maxWorkers: '50%',
  
  // Coverage
  collectCoverage: true,
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
    },
  },
  
  // Reporting
  reporters: [
    'default',
    ['jest-junit', { outputDirectory: './reports' }],
  ],
  
  // Fail fast in CI
  bail: process.env.CI ? 1 : 0,
};
```

**Python (pytest)**
```ini
# pytest.ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*

addopts = 
    -v
    --tb=short
    --cov=src
    --cov-report=term-missing
    --cov-report=html:reports/coverage
    --junitxml=reports/junit.xml
```

**Go**
```bash
# Makefile
test:
	go test -v -race -coverprofile=coverage.out ./...

test-ci:
	go test -v -race -coverprofile=coverage.out -json ./... > test.json
```

### 2. Configure GitHub Actions

**`.github/workflows/test.yml`**
```yaml
name: Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        node-version: [18, 20]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run linter
        run: npm run lint
      
      - name: Run unit tests
        run: npm test -- --coverage
      
      - name: Run integration tests
        run: npm run test:integration
        env:
          DATABASE_URL: postgresql://test:test@localhost/test
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info
      
      - name: Upload test results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: test-results-${{ matrix.node-version }}
          path: reports/
```

### 3. Pre-commit Hooks

**`.pre-commit-config.yaml`** (Python)
```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
  
  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
  
  - repo: local
    hooks:
      - id: pytest
        name: pytest
        entry: pytest tests/unit -v
        language: system
        types: [python]
        pass_filenames: false
        always_run: true
```

**Husky + lint-staged** (JavaScript)
```javascript
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged"
    }
  },
  "lint-staged": {
    "*.{js,ts}": ["eslint --fix", "jest --findRelatedTests --bail"],
    "*.py": ["black", "pytest --co -q"]
  }
}
```

### 4. Parallel Execution

**JavaScript**
```javascript
// jest.config.js
module.exports = {
  // Use 50% of available CPUs
  maxWorkers: '50%',
  
  // Or specific number
  maxWorkers: 4,
  
  // Shard tests across multiple CI jobs
  testSharding: {
    shardIndex: process.env.SHARD_INDEX,
    shardCount: process.env.SHARD_COUNT,
  },
};
```

**Python**
```bash
# Run tests in parallel with pytest-xdist
pytest -n auto  # auto-detect CPU count
pytest -n 4     # use 4 workers
```

**Go**
```bash
# Go tests are parallel by default
# Control with -p flag
go test -p 4 ./...  # 4 parallel packages
```

### 5. Test Reporting

**JUnit XML Format** (standard for CI)
```javascript
// jest.config.js
reporters: [
  'default',
  ['jest-junit', {
    outputDirectory: './reports',
    outputName: 'junit.xml',
    classNameTemplate: '{classname}',
    titleTemplate: '{title}',
  }],
];
```

**HTML Reports**
```javascript
// jest-html-reporter
reporters: [
  ['jest-html-reporter', {
    pageTitle: 'Test Report',
    outputPath: './reports/test-report.html',
    includeFailureMsg: true,
    includeConsoleLog: true,
  }],
];
```

**Coverage Reports**
```yaml
# GitHub Actions - post coverage comment
- name: Coverage Report
  uses: ArtiomTr/jest-coverage-report-action@v2
  if: github.event_name == 'pull_request'
  with:
    threshold: 80
    skip-step: install
```

### 6. Selective Testing

**Run tests related to changed files**
```bash
# Jest
jest --changedSince=main

# Run only tests affected by changes
jest --findRelatedTests src/utils.js
```

**Python**
```bash
# pytest-testmon - only run tests affected by changes
pytest --testmon

# pytest-smartcov - coverage-aware selection
pytest --smartcov
```

### 7. CI Optimization

**Test Splitting**
```yaml
# Split tests across multiple jobs
strategy:
  matrix:
    shard: [1, 2, 3, 4]

steps:
  - run: npm test -- --shard=${{ matrix.shard }}/4
```

**Docker Layer Caching**
```yaml
- name: Build test image
  uses: docker/build-push-action@v5
  with:
    context: .
    target: test
    cache-from: type=gha
    cache-to: type=gha,mode=max
```

**Dependency Caching**
```yaml
- name: Cache dependencies
  uses: actions/cache@v3
  with:
    path: |
      ~/.npm
      node_modules
    key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
```

## Multi-Language Examples

### Complete CI Setup

**JavaScript Project**
```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
      - run: npm ci
      - run: npm run lint
      - run: npm run typecheck

  test-unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
      - run: npm ci
      - run: npm test -- --coverage
      - uses: codecov/codecov-action@v3

  test-integration:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm ci
      - run: npm run test:integration
        env:
          DATABASE_URL: postgresql://postgres:test@localhost/postgres
```

**Python Project**
```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.10', '3.11', '3.12']
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      
      - name: Cache pip
        uses: actions/cache@v3
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements.txt') }}
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-test.txt
      
      - name: Lint
        run: |
          flake8 src tests
          black --check src tests
      
      - name: Unit tests
        run: pytest tests/unit -v --cov=src --cov-report=xml
      
      - name: Integration tests
        run: pytest tests/integration -v
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Best Practices

### Fast Feedback
- Run fastest tests first (unit → integration → e2e)
- Fail fast (stop on first failure in CI)
- Parallelize test execution
- Cache dependencies and build artifacts

### Reliability
- Tests must be deterministic
- No dependencies on external services in unit tests
- Use test databases/containers for integration tests
- Retry flaky tests with exponential backoff

### Reporting
- JUnit XML for CI integration
- HTML reports for human review
- Coverage reports with diffs
- Slack/email notifications for failures

## Common Pitfalls

❌ **Running all tests sequentially**
```yaml
# Slow
- run: npm test  # 30 minutes

# Fast
- run: npm test -- --maxWorkers=4  # 8 minutes
```

❌ **Not caching dependencies**
```yaml
# Slow: installs every time
- run: npm ci

# Fast: uses cache
- uses: actions/cache@v3
- run: npm ci
```

❌ **Flaky tests in CI**
- Caused by: timing issues, external dependencies, race conditions
- Fix: use test doubles, add retries, stabilize tests

## Validation Checklist

- [ ] Tests run automatically on every PR
- [ ] CI fails on test failure
- [ ] Coverage reports are generated
- [ ] Parallel execution is configured
- [ ] Dependencies are cached
- [ ] Test results are archived
- [ ] Notifications are set up
- [ ] Pre-commit hooks run fast tests

## Related Skills

- **unit-testing** — What to automate
- **integration-testing** — CI pipeline tests
- **ci-cd-pipelines** — Full deployment automation
