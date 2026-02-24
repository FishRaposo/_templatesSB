# Test Automation

Build automated testing pipelines that run on every code change.

## Quick Start

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
      - run: npm ci
      - run: npm test -- --coverage
```

## Automation Levels

| Level | When | Scope |
|-------|------|-------|
| Pre-commit | Before commit | Lint + fast unit tests |
| CI | On PR/push | Full test suite |
| Nightly | Scheduled | E2E + performance |

## Key Principles

- Tests run without human intervention
- Fast feedback (< 5 min for unit tests)
- Clear failure reporting
- Deterministic results

## Parallel Execution

```javascript
// jest.config.js
module.exports = {
  maxWorkers: '50%',
};
```

```bash
# Python
pytest -n auto
```

## Caching

```yaml
- uses: actions/cache@v3
  with:
    path: ~/.npm
    key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
```

## Examples

See `examples/basic-examples.md` for full CI/CD test automation examples.

## Related Skills

- `unit-testing` — What to automate
- `integration-testing` — CI integration tests
- `ci-cd-pipelines` — Full deployment pipeline
