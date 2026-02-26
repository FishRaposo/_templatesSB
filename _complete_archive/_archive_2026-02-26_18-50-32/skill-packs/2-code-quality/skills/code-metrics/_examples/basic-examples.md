# Code Metrics — Basic Examples

## Measure Cyclomatic Complexity

```bash
# JavaScript: ESLint complexity report
npx eslint . --rule '{"complexity": ["warn", {"max": 10}]}' --format json | \
  jq '[.[] | select(.messages | length > 0) | {file: .filePath, issues: [.messages[] | .message]}]'

# Python: radon
pip install radon
radon cc src/ -a -nc     # Average complexity per function
radon mi src/ -s         # Maintainability index

# Go: gocyclo
go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
gocyclo -top 10 ./       # Top 10 most complex functions
```

## Measure Test Coverage

```bash
# JavaScript
npx jest --coverage --coverageReporters=text-summary
# Output: Statements: 82%, Branches: 75%, Functions: 88%, Lines: 83%

# Python
pytest --cov=src --cov-report=term-missing
# Shows which lines are NOT covered

# Go
go test -cover ./...
go tool cover -func=coverage.out | tail -1  # Total percentage
```

## Measure Duplication

```bash
# JavaScript/TypeScript
npx jscpd src/ --threshold 5 --reporters consoleFull
# Output: Found 23 clones, 4.7% duplication

# Python
pylint --disable=all --enable=duplicate-code src/
```

## Hotspot Analysis (Churn × Complexity)

```bash
# Find most-changed files in last 6 months
git log --since="6 months ago" --name-only --format="" -- "src/**/*.ts" | \
  sort | uniq -c | sort -rn | head -10

# Output:
#   47 src/services/UserService.ts      ← high churn = refactoring target
#   38 src/controllers/OrderController.ts
#   31 src/utils/validation.ts
```

## Track Trends in CI

```javascript
// Save metrics per build
const metrics = {
  date: new Date().toISOString(),
  commit: process.env.GITHUB_SHA?.slice(0, 7),
  coverage: 82.5,
  complexity: { max: 23, avg: 6.2 },
  duplication: 4.7,
  todoCount: 42,
};

// Alert on regression
if (metrics.coverage < previousMetrics.coverage - 1) {
  console.error(`⚠️ Coverage dropped: ${previousMetrics.coverage}% → ${metrics.coverage}%`);
  process.exit(1);
}
```

## When to Use
- "What's the complexity of this module?"
- "Show me our test coverage"
- "Find the most complex functions"
- "Which files change the most?"
