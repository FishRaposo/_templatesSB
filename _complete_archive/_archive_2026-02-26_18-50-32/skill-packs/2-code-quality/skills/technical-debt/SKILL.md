---
name: technical-debt
description: Use this skill when identifying, prioritizing, and reducing technical debt in a codebase. This includes debt inventory, impact assessment, payoff planning, and tracking debt reduction over time.
---

# Technical Debt

I'll help you identify, prioritize, and systematically reduce technical debt. When you invoke this skill, I can guide you through inventorying debt, scoring by impact, creating payoff plans, and tracking progress.

# Core Approach

My approach focuses on:
1. Making debt visible through inventory and measurement
2. Prioritizing by business impact, not just technical severity
3. Paying down debt incrementally alongside feature work
4. Preventing new debt with quality gates

# Step-by-Step Instructions

## 1. Inventory Current Debt

Find debt systematically with tooling and code analysis:

```bash
# Find TODO/FIXME/HACK markers
grep -rn "TODO\|FIXME\|HACK\|XXX\|WORKAROUND" src/ --include="*.ts" | wc -l

# Find long files (complexity signal)
find src/ -name "*.ts" | xargs wc -l | sort -rn | head -20

# Find circular dependencies
npx madge --circular src/

# Find code duplication
npx jscpd src/ --threshold 5

# Find high-churn files (changed most in last 6 months)
git log --since="6 months ago" --name-only --format="" -- src/ | \
  sort | uniq -c | sort -rn | head -20

# Find files with most bug-fix commits
git log --since="6 months ago" --grep="fix\|bug" --name-only --format="" -- src/ | \
  sort | uniq -c | sort -rn | head -20
```

## 2. Classify and Score Debt

Categorize each debt item by type and score by impact:

**Python:**
```python
from dataclasses import dataclass
from enum import Enum

class DebtType(Enum):
    DESIGN = "design"           # Architecture issues, wrong abstractions
    CODE = "code"               # Messy code, duplication, long functions
    TEST = "test"               # Missing tests, flaky tests
    DEPENDENCY = "dependency"   # Outdated deps, security vulnerabilities
    DOCUMENTATION = "docs"      # Missing or stale documentation
    INFRASTRUCTURE = "infra"    # Manual deploys, missing monitoring

@dataclass
class DebtItem:
    name: str
    debt_type: DebtType
    impact: int          # 1-10: how much it slows the team
    effort: int          # 1-10: how hard to fix
    churn: int           # how often the affected code changes
    description: str

    @property
    def priority_score(self) -> float:
        """Higher = fix first. Prioritize high-impact, high-churn, low-effort."""
        return (self.impact * self.churn) / max(self.effort, 1)

# Example inventory
debt_inventory = [
    DebtItem("UserService god class", DebtType.DESIGN, impact=9, effort=5, churn=30,
             description="800-line class handling auth, profile, notifications"),
    DebtItem("No integration tests for payments", DebtType.TEST, impact=8, effort=3, churn=10,
             description="Payment bugs found in production, not caught by unit tests"),
    DebtItem("Duplicated validation in 5 controllers", DebtType.CODE, impact=6, effort=2, churn=22,
             description="Same validation logic copy-pasted, bugs fixed in one but not others"),
    DebtItem("React 17 → 18 migration", DebtType.DEPENDENCY, impact=4, effort=7, churn=5,
             description="Missing concurrent features, security patches"),
]

# Sort by priority
for item in sorted(debt_inventory, key=lambda d: d.priority_score, reverse=True):
    print(f"  [{item.priority_score:5.1f}] [{item.debt_type.value:12s}] {item.name}")
```

## 3. Create a Payoff Plan

Allocate a sustainable percentage of sprint capacity to debt:

```markdown
## Debt Payoff Plan — Q1 2026

**Budget**: 20% of sprint capacity (2 days per 2-week sprint)

### Sprint 1-2: Duplicated validation (Score: 66.0)
- Extract shared validation utilities
- Update all 5 controllers
- Add integration tests for validation
- **Effort**: 2 days | **Impact**: Prevents recurring validation bugs

### Sprint 3-4: Payment integration tests (Score: 26.7)
- Write integration tests for payment flows
- Add test environment for payment provider
- **Effort**: 3 days | **Impact**: Catches payment bugs before production

### Sprint 5-8: UserService decomposition (Score: 54.0)
- Extract AuthService from UserService
- Extract NotificationService from UserService
- Add tests for each new service
- **Effort**: 5 days | **Impact**: Reduces merge conflicts, enables team scaling
```

## 4. Prevent New Debt

Set up guardrails to slow the accumulation of new debt:

```yaml
# Complexity limits in ESLint
rules:
  complexity: ["error", { max: 15 }]
  max-lines-per-function: ["warn", { max: 50 }]
  max-depth: ["error", { max: 4 }]

# Coverage gates in CI — prevent coverage from dropping
# jest.config.js
coverageThreshold:
  global:
    branches: 80
    functions: 80
    lines: 80
```

# Best Practices

- Make debt visible — track it in your issue tracker alongside features
- Allocate a fixed percentage (15-20%) of capacity to debt, not "when we have time"
- Fix debt in the area you're already working in (opportunistic cleanup)
- Prioritize by (impact × churn) / effort — don't just fix the easiest items
- Celebrate debt reduction — share metrics and wins with the team
- Never rewrite from scratch — use strangler fig or incremental improvements

# Validation Checklist

When managing technical debt, verify:
- [ ] Debt inventory exists and is up to date
- [ ] Each item has impact, effort, and churn scores
- [ ] Payoff plan allocates regular sprint capacity
- [ ] Quality gates prevent new debt accumulation
- [ ] Debt metrics are tracked over time (trending down?)
- [ ] High-churn, high-impact items are prioritized first

# Troubleshooting

## Issue: "We Don't Have Time for Debt"

**Symptoms**: Debt keeps growing, velocity keeps dropping

**Solution**:
- Show the correlation: track time spent on bugs and workarounds
- Start small: 10% of sprint capacity, measure the improvement
- Piggyback: reduce debt in areas you're already modifying for features
- Quantify: "This god class caused 12 bugs last quarter, costing 15 dev-days"

## Issue: Debt Keeps Coming Back

**Symptoms**: Fixed debt areas degrade again within months

**Solution**:
- Add automated guards (linter rules, coverage thresholds) after fixing
- Do a retrospective on why the debt appeared in the first place
- Consider architectural changes, not just code-level fixes

# Supporting Files

- See `./_examples/basic-examples.md` for debt inventory commands, priority scoring, and guardrail examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **code-metrics** - Quantify debt with cyclomatic complexity, coverage, duplication
- **code-refactoring** - Execute the debt payoff through safe refactoring
- **legacy-code-migration** - For large-scale debt that requires migration
- **code-quality-review** - Catch new debt during code review
- → **32-project-management**: sprint-planning (for allocating debt budget)

Remember: Technical debt is like financial debt — a little is fine, but compound interest will kill you!
