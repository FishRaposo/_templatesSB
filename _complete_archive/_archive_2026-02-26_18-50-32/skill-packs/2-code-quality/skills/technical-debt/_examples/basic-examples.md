# Technical Debt — Basic Examples

## Inventory Debt with Tooling

```bash
# Count TODO/FIXME markers
grep -rn "TODO\|FIXME\|HACK\|XXX" src/ --include="*.ts" | wc -l

# Find large files (god class signal)
find src/ -name "*.ts" | xargs wc -l | sort -rn | head -10

# Find circular dependencies
npx madge --circular src/

# Find high-churn files
git log --since="6 months ago" --name-only --format="" -- src/ | \
  sort | uniq -c | sort -rn | head -10

# Find files with most bug-fix commits
git log --since="6 months ago" --grep="fix\|bug" --name-only --format="" | \
  sort | uniq -c | sort -rn | head -10
```

## Prioritize by Impact

**Python:**
```python
debt_items = [
    {"name": "God class: UserService",      "impact": 9, "effort": 5, "churn": 30},
    {"name": "Duplicated validation",        "impact": 6, "effort": 2, "churn": 22},
    {"name": "No integration tests",         "impact": 8, "effort": 3, "churn": 10},
    {"name": "Outdated React 17",            "impact": 4, "effort": 7, "churn": 5},
]

# Score = (impact × churn) / effort
for item in sorted(debt_items, key=lambda d: (d["impact"] * d["churn"]) / d["effort"], reverse=True):
    score = (item["impact"] * item["churn"]) / item["effort"]
    print(f"  [{score:5.1f}] {item['name']}")
# Output:
#   [ 54.0] God class: UserService
#   [ 66.0] Duplicated validation
#   [ 26.7] No integration tests
#   [  2.9] Outdated React 17
```

## Prevent New Debt

```javascript
// eslint.config.js — complexity guardrails
export default [{
  rules: {
    'complexity': ['error', { max: 15 }],
    'max-lines-per-function': ['warn', { max: 50 }],
    'max-depth': ['error', { max: 4 }],
  },
}];
```

```yaml
# CI coverage gate — prevent coverage from dropping
# jest.config.js
coverageThreshold:
  global:
    branches: 80
    functions: 80
    lines: 80
```

## When to Use
- "How much technical debt do we have?"
- "Prioritize our tech debt backlog"
- "Create a debt reduction plan for this quarter"
- "Set up guardrails to prevent new debt"
