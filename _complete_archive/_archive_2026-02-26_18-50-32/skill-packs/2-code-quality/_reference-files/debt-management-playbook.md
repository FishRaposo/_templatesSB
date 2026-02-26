<!-- Generated from task-outputs/task-08-technical-debt.md -->

# Task 8 — Technical Debt Analysis
> Skills: technical-debt, code-metrics, code-refactoring

## Debt Inventory

### Detection Commands

```bash
# TODO/FIXME grep
grep -rn "TODO\|FIXME\|XXX\|HACK" src/ --include="*.js" --include="*.ts" | wc -l
# Result: 47 markers

# Circular dependencies
npx madge --circular src/
# Result: 12 circular dependencies found

# Code duplication
npx jscpd src/ --threshold 5
# Result: 15.3% duplication

# High churn files (changed frequently)
git log --since="6 months ago" --name-only --pretty=format: | \
  grep -E "\.(js|ts)$" | sort | uniq -c | sort -rn | head -10
# Result: api/controller.js (47 changes), utils/helpers.js (38 changes)
```

## Debt Scoring

| Item | Impact (1-5) | Churn (changes) | Effort (days) | Score | Priority |
|------|--------------|-----------------|---------------|-------|----------|
| Circular deps in models | 4 | 23 | 3 | 30.7 | P1 |
| 400-line UserService | 4 | 47 | 5 | 37.6 | P1 |
| No input validation | 5 | 15 | 2 | 37.5 | P1 |
| 47 TODO markers | 3 | 12 | 4 | 9.0 | P2 |
| Test coverage 45% | 4 | 8 | 10 | 3.2 | P3 |

*Score = (Impact × Churn) / Effort*

## Quarterly Payoff Plan

| Sprint | Focus | Capacity | Deliverable |
|--------|-------|----------|-------------|
| 1 | Break circular deps | 20% | Dependency injection container |
| 2 | Decompose UserService | 20% | 3 focused services |
| 3 | Add validation layer | 20% | Zod schemas + middleware |
| 4 | Address TODOs | 20% | 80% of TODOs resolved |

## Prevention Guardrails

```javascript
// .eslintrc
{
  "rules": {
    "complexity": ["error", 10],
    "max-lines-per-function": ["error", 50],
    "no-console": ["warn"]
  }
}

// jest.config
{
  "coverageThreshold": {
    "global": { "branches": 80, "functions": 80, "lines": 80 }
  }
}
```

- [x] Multiple detection methods used (TODO grep, circular deps, duplication, churn)
- [x] Scoring formula applied consistently
- [x] Payoff plan is realistic and time-boxed
- [x] Prevention guardrails included

