---
name: code-metrics
description: Use this skill when measuring code quality objectively. This includes cyclomatic complexity, test coverage, code duplication percentage, coupling metrics, churn analysis, and setting up dashboards to track quality over time.
---

# Code Metrics

I'll help you measure code quality with objective, quantifiable metrics. When you invoke this skill, I can guide you through collecting complexity, coverage, coupling, and churn data to make quality decisions based on evidence.

# Core Approach

My approach focuses on:
1. Measuring what matters — complexity, coverage, duplication, churn
2. Setting actionable thresholds, not arbitrary targets
3. Tracking trends over time, not just snapshots
4. Using metrics to guide decisions, not as goals in themselves

# Step-by-Step Instructions

## 1. Measure Complexity

Cyclomatic complexity counts the number of independent paths through code:

```bash
# JavaScript/TypeScript: eslint complexity rule
npx eslint . --rule '{"complexity": ["error", {"max": 15}]}' --format json | \
  jq '[.[] | .messages[] | {file: .filePath, line: .line, complexity: .message}]'

# Python: radon
pip install radon
radon cc src/ -a -nc          # Show average and per-function
radon mi src/ -s              # Maintainability index

# Go: gocyclo
go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
gocyclo -top 20 ./           # Top 20 most complex functions

# Multi-language: SonarQube (Docker)
docker run -d --name sonarqube -p 9000:9000 sonarqube:community
```

**Thresholds:**
| Complexity | Risk Level | Action |
|------------|-----------|--------|
| 1-10 | Low | Good — no action needed |
| 11-20 | Medium | Consider simplifying |
| 21-50 | High | Must refactor |
| 50+ | Critical | Refactor immediately |

## 2. Measure Test Coverage

```bash
# JavaScript: Jest with coverage
npx jest --coverage --coverageReporters=json-summary
# Read summary
cat coverage/coverage-summary.json | jq '.total'

# Python: pytest-cov
pytest --cov=src --cov-report=term-missing --cov-report=json
cat coverage.json | python -c "import json,sys; d=json.load(sys.stdin); print(f'Coverage: {d[\"totals\"][\"percent_covered\"]:.1f}%')"

# Go: built-in
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -1    # Total coverage
go tool cover -html=coverage.out              # Visual report
```

**Thresholds:**
| Metric | Target | Rationale |
|--------|--------|-----------|
| Line coverage | ≥80% | Diminishing returns above 90% |
| Branch coverage | ≥75% | Catches missed conditional paths |
| Critical path coverage | 100% | Auth, payments, data mutations |

## 3. Measure Duplication

```bash
# JavaScript: jscpd
npx jscpd src/ --reporters consoleFull --format "typescript"
# Output: duplication percentage and exact clone locations

# Python: pylint
pylint --disable=all --enable=duplicate-code src/ --min-similarity-lines=5

# Multi-language: PMD CPD
pmd cpd --minimum-tokens 50 --dir src/ --language javascript --format csv
```

**Target**: ≤5% duplication. Above 10% indicates systematic DRY violations.

## 4. Measure Churn and Hotspots

Files that change frequently AND have high complexity are the biggest risks:

```bash
# Most-changed files in the last 6 months
git log --since="6 months ago" --name-only --format="" -- src/ | \
  sort | uniq -c | sort -rn | head -20

# Combine churn with complexity (hotspot analysis)
# High churn + high complexity = highest priority for refactoring
for file in $(git log --since="6 months ago" --name-only --format="" -- "src/**/*.ts" | sort -u); do
  churn=$(git log --since="6 months ago" --oneline -- "$file" | wc -l)
  complexity=$(npx eslint "$file" --rule '{"complexity":["warn",1]}' --format json 2>/dev/null | jq '[.[].messages | length] | add // 0')
  echo "$churn $complexity $file"
done | sort -rn | head -20
```

## 5. Track Trends Over Time

Store metrics per commit/sprint and track direction:

```javascript
// metrics-collector.js — run in CI after each merge to main
import { writeFileSync, existsSync, readFileSync } from 'fs';

const metrics = {
  date: new Date().toISOString(),
  commit: process.env.GITHUB_SHA?.slice(0, 7),
  coverage: parseCoverage(),
  complexity: parseComplexity(),
  duplication: parseDuplication(),
  todoCount: parseTodoCount(),
};

const history = existsSync('metrics.json')
  ? JSON.parse(readFileSync('metrics.json', 'utf8'))
  : [];
history.push(metrics);
writeFileSync('metrics.json', JSON.stringify(history, null, 2));

// Alert if metrics regress
const prev = history[history.length - 2];
if (prev && metrics.coverage < prev.coverage - 1) {
  console.error(`⚠️ Coverage dropped: ${prev.coverage}% → ${metrics.coverage}%`);
  process.exit(1);
}
```

# Best Practices

- Measure trends, not absolutes — a codebase improving from 60% to 75% coverage is healthier than one stuck at 95%
- Don't game metrics — 100% coverage with bad tests is worse than 80% with good tests
- Use metrics to find hotspots, not to judge developers
- Set thresholds as guardrails (prevent regression), not as goals
- Combine multiple metrics — no single metric tells the full story
- Automate collection in CI so metrics are always current

# Validation Checklist

When setting up code metrics, verify:
- [ ] Complexity analysis runs in CI and blocks on critical thresholds
- [ ] Test coverage is measured and has a minimum threshold
- [ ] Duplication detection runs and reports percentage
- [ ] Churn analysis identifies frequently-changed files
- [ ] Metrics are tracked over time (not just snapshots)
- [ ] Thresholds prevent regression (coverage can't drop, complexity can't increase)

# Troubleshooting

## Issue: Coverage Is High But Bugs Still Slip Through

**Symptoms**: 90%+ coverage but production bugs in tested code

**Solution**:
- Check branch coverage, not just line coverage
- Review test quality — are assertions meaningful or just `expect(true)`?
- Add mutation testing (`stryker-mutator`) to verify test effectiveness
- Focus coverage on critical paths (auth, payments, data mutations)

## Issue: Complexity Metrics Don't Match Perceived Difficulty

**Symptoms**: Low complexity score but code is still hard to understand

**Solution**:
- Cyclomatic complexity doesn't capture cognitive complexity — use SonarQube's cognitive complexity
- Check coupling metrics (afferent/efferent coupling) in addition to complexity
- Consider nesting depth as a separate metric
- Factor in naming quality and code organization (manual review)

# Supporting Files

- See `./_examples/basic-examples.md` for complexity, coverage, duplication, and hotspot analysis examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **technical-debt** - Use metrics to quantify and prioritize debt
- **code-quality-review** - Use metrics to inform code reviews
- **code-standards** - Enforce metric thresholds via linter rules
- **simplify-complexity** - Reduce complexity flagged by metrics
- → **12-devops-automation**: ci-cd-pipelines (for automating metric collection)

Remember: Metrics are a flashlight, not a scorecard — use them to find problems, not to judge people!
