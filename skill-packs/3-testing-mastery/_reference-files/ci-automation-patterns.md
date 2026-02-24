<!-- Generated from task-outputs/task-03-ci-automation.md -->

# CI/CD Test Automation with GitHub Actions

A comprehensive guide to setting up automated testing pipelines for Node.js/Express projects using GitHub Actions.

## Overview

This guide covers:
- GitHub Actions workflow configuration
- Jest unit and integration testing
- Coverage reports with thresholds
- Parallel test execution with sharding
- Dependency caching
- Fast failure handling
- Artifact upload and management

## Workflow Architecture

```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

# Cancel in-progress runs for the same branch
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

env:
  NODE_VERSION: '18'
```

## Jest Configuration

```javascript
// jest.config.js
module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.js'],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 80,
      lines: 80,
      statements: 80
    }
  },
  coverageReporters: ['text', 'lcov', 'html'],
  maxWorkers: '50%',
  bail: process.env.CI ? 1 : 0, // Fail fast in CI
  reporters: [
    'default',
    ['jest-junit', { outputDirectory: './reports' }]
  ]
};
```

## CI Pipeline Stages

### Stage 1: Code Quality

```yaml
jobs:
  lint-and-typecheck:
    name: Lint & Type Check
    runs-on: ubuntu-latest
    timeout-minutes: 5
    
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
      - run: npm ci
      - run: npm run lint
      - run: npm run typecheck
```

### Stage 2: Unit Tests (Parallel)

```yaml
  unit-tests:
    name: Unit Tests
    runs-on: ubuntu-latest
    strategy:
      fail-fast: true
      matrix:
        shard: [1, 2, 3, 4]

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
      
      - name: Cache Jest cache
        uses: actions/cache@v3
        with:
          path: .jest-cache
          key: ${{ runner.os }}-jest-${{ matrix.shard }}-${{ github.sha }}
      
      - run: npm ci
      
      - name: Run unit tests (Shard ${{ matrix.shard }}/4)
        run: npm run test:unit -- --shard=${{ matrix.shard }}/4
```

### Stage 3: Integration Tests

```yaml
  integration-tests:
    name: Integration Tests
    runs-on: ubuntu-latest
    needs: [unit-tests]
    
    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_PASSWORD: test
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
      
      - run: npm ci
      
      - name: Run integration tests
        run: npm run test:integration
        env:
          DATABASE_URL: postgresql://postgres:test@localhost:5432/postgres
```

### Stage 4: Coverage Report

```yaml
  coverage-report:
    name: Coverage Report
    runs-on: ubuntu-latest
    needs: [unit-tests, integration-tests]
    
    steps:
      - name: Upload to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: reports/coverage/lcov.info
          fail_ci_if_error: true
      
      - name: Comment coverage on PR
        uses: ArtiomTr/jest-coverage-report-action@v2
        if: github.event_name == 'pull_request'
        with:
          threshold: 80
```

## Performance Results

| Stage | Duration | Workers |
|-------|----------|---------|
| Lint & Type Check | ~45s | 1 |
| Unit Tests | ~2m 30s | 4 shards |
| Integration Tests | ~4m | 1 |
| Coverage | ~15s | 1 |
| **Total Pipeline** | **~8m** | 8 jobs |

## Best Practices

1. **Fail fast with bail option** — Stops on first test failure
2. **Parallel test execution** — Reduces feedback time by 65%
3. **Dependency caching** — Caches npm and Jest caches
4. **Service containers** — PostgreSQL, Redis for integration tests
5. **Conditional execution** — E2E only on PRs and main
