# Test Automation Examples

## GitHub Actions CI Setup

### Node.js Project

```yaml
# .github/workflows/test.yml
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
      
      - name: Run tests
        run: npm test -- --coverage
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info
```

### Python Project

```yaml
# .github/workflows/test.yml
name: Tests

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
      
      - name: Run tests
        run: pytest tests/ -v --cov=src --cov-report=xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Pre-commit Hooks

### JavaScript (Husky + lint-staged)

```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged"
    }
  },
  "lint-staged": {
    "*.{js,ts}": [
      "eslint --fix",
      "jest --findRelatedTests --bail"
    ]
  }
}
```

### Python (pre-commit)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
  
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
```

## Jest Configuration

```javascript
// jest.config.js
module.exports = {
  // Test discovery
  testMatch: ['**/*.test.js'],
  
  // Coverage
  collectCoverage: true,
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
    },
  },
  
  // Parallel execution
  maxWorkers: '50%',
  
  // Reporters
  reporters: [
    'default',
    ['jest-junit', { outputDirectory: './reports' }],
  ],
  
  // Fail fast in CI
  bail: process.env.CI ? 1 : 0,
};
```

## pytest Configuration

```ini
# pytest.ini
[pytest]
testpaths = tests
python_files = test_*.py
addopts = 
    -v
    --tb=short
    --cov=src
    --cov-report=term-missing
    --cov-report=html:reports/coverage
    --junitxml=reports/junit.xml
```

## Parallel Execution

### Jest

```javascript
// Run tests in parallel
jest --maxWorkers=4

// Run tests related to changed files
jest --changedSince=main
```

### pytest

```bash
# Run in parallel with pytest-xdist
pytest -n auto  # Auto-detect CPU count
pytest -n 4     # Use 4 workers
```

## Test Reporting

### JUnit XML (CI integration)

```javascript
// jest.config.js
reporters: [
  'default',
  ['jest-junit', {
    outputDirectory: './reports',
    outputName: 'junit.xml',
  }],
];
```

### HTML Reports

```javascript
// jest-html-reporter
reporters: [
  ['jest-html-reporter', {
    outputPath: './reports/test-report.html',
    includeFailureMsg: true,
  }],
];
```

## Best Practices

- **Fast feedback**: Run fastest tests first
- **Parallelize**: Use multiple workers
- **Cache dependencies**: Speed up CI
- **Fail fast**: Stop on first failure in CI
- **Archive results**: Store test reports
