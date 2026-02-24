---
name: simplify-complexity
description: Use this skill when reducing unnecessary complexity in code. This includes flattening nested conditionals, decomposing large functions, replacing clever code with clear code, and eliminating accidental complexity while preserving essential complexity.
---

# Simplify Complexity

I'll help you reduce unnecessary complexity through extraction, flattening, and decomposition. When you invoke this skill, I can guide you through turning convoluted code into clear, straightforward implementations.

# Core Approach

My approach focuses on:
1. Distinguishing essential complexity (inherent to the problem) from accidental complexity (introduced by the solution)
2. Flattening deep nesting with guard clauses and early returns
3. Decomposing large units into focused, composable pieces
4. Replacing clever solutions with clear ones

# Step-by-Step Instructions

## 1. Flatten Deep Nesting

Replace nested if/else with guard clauses and early returns:

**JavaScript:**
```javascript
// ❌ Deep nesting — 4 levels
function processOrder(order) {
  if (order) {
    if (order.items.length > 0) {
      if (order.status === 'pending') {
        if (order.total > 0) {
          // actual logic buried 4 levels deep
          return submitOrder(order);
        } else {
          throw new Error('Invalid total');
        }
      } else {
        throw new Error('Not pending');
      }
    } else {
      throw new Error('No items');
    }
  } else {
    throw new Error('No order');
  }
}

// ✅ Guard clauses — flat, readable
function processOrder(order) {
  if (!order) throw new Error('No order');
  if (order.items.length === 0) throw new Error('No items');
  if (order.status !== 'pending') throw new Error('Not pending');
  if (order.total <= 0) throw new Error('Invalid total');

  return submitOrder(order);
}
```

**Python:**
```python
# ❌ Nested conditionals
def get_discount(user, order):
    if user.is_member:
        if order.total > 100:
            if user.membership_years > 5:
                return 0.20
            else:
                return 0.10
        else:
            return 0.05
    else:
        return 0

# ✅ Early returns, clear logic
def get_discount(user, order):
    if not user.is_member:
        return 0
    if order.total <= 100:
        return 0.05
    if user.membership_years > 5:
        return 0.20
    return 0.10
```

## 2. Replace Complex Conditionals with Lookup Tables

**Go:**
```go
// ❌ Long switch/if chain
func getStatusMessage(status string) string {
    if status == "pending" {
        return "Your order is being processed"
    } else if status == "shipped" {
        return "Your order is on the way"
    } else if status == "delivered" {
        return "Your order has been delivered"
    } else if status == "cancelled" {
        return "Your order was cancelled"
    } else if status == "refunded" {
        return "Your refund has been processed"
    }
    return "Unknown status"
}

// ✅ Lookup table
var statusMessages = map[string]string{
    "pending":   "Your order is being processed",
    "shipped":   "Your order is on the way",
    "delivered": "Your order has been delivered",
    "cancelled": "Your order was cancelled",
    "refunded":  "Your refund has been processed",
}

func getStatusMessage(status string) string {
    if msg, ok := statusMessages[status]; ok {
        return msg
    }
    return "Unknown status"
}
```

## 3. Decompose Complex Functions

Break large functions into a high-level orchestrator + focused helpers:

```javascript
// ❌ One function doing everything
async function syncUserData(userId) {
  // 80 lines of fetching, transforming, validating, saving, notifying
}

// ✅ Orchestrator + focused helpers
async function syncUserData(userId) {
  const externalData = await fetchExternalProfile(userId);
  const normalized = normalizeProfileData(externalData);
  validateProfileFields(normalized);
  const changes = detectChanges(userId, normalized);
  if (changes.length === 0) return { status: 'no-changes' };
  await saveProfileUpdates(userId, changes);
  await notifyProfileChanged(userId, changes);
  return { status: 'synced', changes: changes.length };
}
```

## 4. Replace Clever Code with Clear Code

```python
# ❌ Clever one-liner (hard to debug, hard to modify)
result = [x for g in [list(group) for _, group in groupby(sorted(data, key=lambda d: d['type']), key=lambda d: d['type'])] for x in g if x['active']]

# ✅ Clear, step-by-step
sorted_data = sorted(data, key=lambda d: d["type"])
grouped = groupby(sorted_data, key=lambda d: d["type"])

result = []
for _, group in grouped:
    for item in group:
        if item["active"]:
            result.append(item)
```

## 5. Simplify State Management

```javascript
// ❌ Complex boolean state tracking
let isLoading = false;
let hasError = false;
let hasData = false;
let isRetrying = false;
// 16 possible combinations, most invalid

// ✅ State machine — only valid states
const state = { status: 'idle' }; // 'idle' | 'loading' | 'success' | 'error' | 'retrying'

function transition(event) {
  const transitions = {
    idle:     { FETCH: 'loading' },
    loading:  { SUCCESS: 'success', FAILURE: 'error' },
    error:    { RETRY: 'retrying', RESET: 'idle' },
    retrying: { SUCCESS: 'success', FAILURE: 'error' },
    success:  { REFRESH: 'loading', RESET: 'idle' },
  };
  const next = transitions[state.status]?.[event];
  if (next) state.status = next;
}
```

# Best Practices

- Favor clarity over brevity — 5 clear lines beat 1 clever line
- Use guard clauses to flatten nesting (≤3 levels deep)
- Replace conditionals with lookup tables/maps when >3 branches
- Decompose: orchestrator calls focused helpers, each ≤20 lines
- Use state machines instead of boolean flags for multi-state logic
- Ask: "Could a junior dev understand this in 30 seconds?"

# Validation Checklist

When simplifying complexity, verify:
- [ ] No function exceeds 3 levels of nesting
- [ ] No function exceeds 50 lines
- [ ] Complex conditionals replaced with lookup tables or polymorphism
- [ ] Clever one-liners replaced with clear multi-line equivalents
- [ ] Boolean flag combinations replaced with state machines
- [ ] Each function does one thing at one level of abstraction

# Troubleshooting

## Issue: "It's Complex Because the Problem Is Complex"

**Symptoms**: Pushback that complexity can't be reduced

**Solution**:
- Separate essential complexity (domain rules) from accidental complexity (implementation choices)
- Essential: "Pricing depends on membership tier, order size, and promotions" — this IS complex
- Accidental: "Pricing logic is in a 200-line nested if/else" — this can be simplified
- Strategy pattern, lookup tables, and composition can express complex rules clearly

## Issue: Simplification Breaks Edge Cases

**Symptoms**: Refactored code misses previously handled edge cases

**Solution**:
- Write characterization tests before simplifying
- Simplify one conditional branch at a time
- Keep the original as a comment temporarily for verification
- Test each edge case explicitly after simplification

# Supporting Files

- See `./_examples/basic-examples.md` for guard clauses, lookup tables, decomposition, and state machine examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **clean-code** - Simplification is a key clean code practice
- **code-refactoring** - Extract Method and guard clauses are refactoring patterns
- **code-metrics** - Cyclomatic complexity quantifies what needs simplification
- → **1-programming-core**: control-flow (for clean control flow patterns)

Remember: Simple is not easy — it takes effort to make complex things clear!
