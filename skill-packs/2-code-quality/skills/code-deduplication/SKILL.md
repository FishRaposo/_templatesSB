---
name: code-deduplication
description: Use this skill when eliminating duplicate or near-duplicate code across a codebase. This includes finding repeated patterns, extracting shared utilities, applying DRY principles, and consolidating logic without over-abstracting.
---

# Code Deduplication

I'll help you eliminate duplicate code through extraction, abstraction, and shared utilities. When you invoke this skill, I can find repeated patterns and consolidate them while avoiding premature or harmful abstraction.

# Core Approach

My approach focuses on:
1. Detecting exact and near-duplicate code
2. Choosing the right deduplication strategy (extract, parameterize, or template)
3. Creating shared abstractions that are genuinely reusable
4. Knowing when duplication is acceptable (the Rule of Three)

# Step-by-Step Instructions

## 1. Detect Duplication

Find duplicated code with tooling:

```bash
# JavaScript/TypeScript: jscpd (copy-paste detector)
npx jscpd src/ --min-lines 5 --threshold 5 --reporters consoleFull

# Python: pylint duplicate checker
pylint --disable=all --enable=duplicate-code src/

# Language-agnostic: PMD CPD
pmd cpd --minimum-tokens 50 --dir src/ --language python

# Git-based: find files that always change together (duplication signal)
git log --format=format: --name-only --since='3 months ago' | \
  sort | uniq -c | sort -rn | head -30
```

## 2. Classify the Duplication

Not all duplication should be removed. Classify first:

| Type | Example | Action |
|------|---------|--------|
| **Exact clones** | Copy-pasted functions | Always extract |
| **Near clones** | Same logic, different names/types | Extract with parameters |
| **Structural** | Same pattern, different domains | Consider template/generics |
| **Coincidental** | Same code, different purpose | Leave it — it's not real duplication |

## 3. Extract and Consolidate

### Extract Shared Function

**JavaScript:**
```javascript
// ❌ Duplicated in user-service.js and admin-service.js
function formatUserName(user) {
  return `${user.firstName} ${user.lastName}`.trim();
}

// ✅ Extracted to shared/formatters.js
export function formatFullName(entity) {
  return `${entity.firstName} ${entity.lastName}`.trim();
}
```

### Parameterize Near-Duplicates

**Python:**
```python
# ❌ Two functions that differ only by threshold
def get_premium_customers(customers):
    return [c for c in customers if c.total_spend > 10000]

def get_vip_customers(customers):
    return [c for c in customers if c.total_spend > 50000]

# ✅ Parameterized
def get_customers_by_spend(customers, min_spend):
    return [c for c in customers if c.total_spend > min_spend]
```

### Use Generics / Templates for Structural Duplication

**Go:**
```go
// ❌ Separate functions for each entity type
func findUserByID(users []User, id string) *User { /* ... */ }
func findOrderByID(orders []Order, id string) *Order { /* ... */ }

// ✅ Generic function (Go 1.18+)
func findByID[T any](items []T, id string, getID func(T) string) *T {
    for i := range items {
        if getID(items[i]) == id {
            return &items[i]
        }
    }
    return nil
}
```

## 4. Know When NOT to Deduplicate

The **Rule of Three**: Don't abstract until you see the pattern three times.

- Two occurrences might be coincidental
- Premature abstraction creates wrong abstractions that are harder to change
- Duplication across bounded contexts (microservices) is often intentional
- Test code duplication is usually acceptable for readability

# Best Practices

- Use the Rule of Three before extracting
- Prefer composition over inheritance for sharing behavior
- Keep shared utilities small and focused (one function per concern)
- Don't create "utils" dumping grounds — organize by domain
- When extracting, ensure the abstraction makes sense on its own
- Test the shared code independently from its consumers

# Validation Checklist

When deduplicating, verify:
- [ ] Duplicate code detected with tooling (not just gut feeling)
- [ ] Duplication is real (same purpose, not just same syntax)
- [ ] Extracted code has a clear, descriptive name
- [ ] All call sites updated and tested
- [ ] Shared code lives in an appropriate location (not a junk drawer)
- [ ] No premature abstractions (Rule of Three respected)

# Troubleshooting

## Issue: Extracted Abstraction Keeps Growing Parameters

**Symptoms**: Shared function now has 8 parameters and boolean flags

**Solution**:
- The duplication was structural, not identical — consider splitting back
- Use strategy pattern or configuration objects instead
- Ask: "Are these really the same operation, or just similar?"

## Issue: Changing Shared Code Breaks Multiple Consumers

**Symptoms**: Fixing one consumer's edge case breaks another

**Solution**:
- The abstraction was premature — consumers have diverged
- Consider duplicating back with separate implementations
- Or add extension points (hooks, callbacks) for consumer-specific behavior

# Supporting Files

- See `./_examples/basic-examples.md` for extraction, parameterization, and generic deduplication examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **clean-code** - Identify duplication through code review
- **code-refactoring** - Extract Method is the primary deduplication tool
- **code-standards** - Enforce DRY with automated detection in CI
- **code-metrics** - Measure duplication percentage as a quality metric
- → **1-programming-core**: abstraction (for designing good shared abstractions)

Remember: Duplication is far cheaper than the wrong abstraction!
