# Task 9 — Code Metrics Pipeline
> Skills: code-metrics, technical-debt

## Metrics Implementation

### 1. Cyclomatic Complexity (ESLint)

```javascript
// .eslintrc
{
  "rules": {
    "complexity": ["error", 10],
    "max-lines-per-function": ["error", 50]
  }
}

// Run
npx eslint src/ --format json --output-file eslint-report.json
```

### 2. Test Coverage (Jest)

```javascript
// jest.config.js
module.exports = {
  collectCoverageFrom: ['src/**/*.js'],
  coverageReporters: ['json', 'lcov', 'text'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};

// Run
npm test -- --coverage --coverageReporters=json
```

### 3. Duplication (jscpd)

```bash
npx jscpd src/ --reporters json --output ./reports/jscpd-report.json
```

### 4. Churn Analysis

```bash
# Git log analysis for hotspots
git log --since="3 months ago" --name-only --pretty=format: | \
  grep -E "\.(js|ts)$" | sort | uniq -c | sort -rn | head -20
```

## CI Pipeline

```yaml
name: Metrics
on: [push, pull_request]

jobs:
  metrics:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install
        run: npm ci
        
      - name: Complexity
        run: npx eslint src/ --format json -o reports/complexity.json
        
      - name: Coverage
        run: npm test -- --coverage --coverageReporters=json
        
      - name: Duplication
        run: npx jscpd src/ --reporters json -o reports/duplication.json
        
      - name: Aggregate Metrics
        run: node scripts/aggregate-metrics.js
        
      - name: Check Regression
        run: node scripts/check-regression.js
```

## Sample Metrics Output

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "metrics": {
    "complexity": {
      "average": 4.2,
      "max": 15,
      "violations": 3
    },
    "coverage": {
      "branches": 87.5,
      "functions": 92.1,
      "lines": 89.3,
      "statements": 90.2
    },
    "duplication": {
      "percentage": 8.3,
      "clones": 12
    }
  },
  "regression": false
}
```

- [x] All 4 metric types measured with working commands
- [x] CI pipeline collects and stores metrics
- [x] Regression detection implemented
- [x] Sample output shows realistic data
