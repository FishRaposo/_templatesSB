# Simplify Complexity — Basic Examples

## Guard Clauses: Flatten Nesting

**JavaScript:**
```javascript
// ❌ Deeply nested
function getDiscount(user, cart) {
  if (user) {
    if (user.isMember) {
      if (cart.total > 100) {
        if (user.years > 5) {
          return 0.20;
        } else {
          return 0.10;
        }
      } else {
        return 0.05;
      }
    }
  }
  return 0;
}

// ✅ Guard clauses — flat and readable
function getDiscount(user, cart) {
  if (!user || !user.isMember) return 0;
  if (cart.total <= 100) return 0.05;
  if (user.years > 5) return 0.20;
  return 0.10;
}
```

## Lookup Tables: Replace Conditionals

**Python:**
```python
# ❌ Long if/elif chain
def get_status_label(status):
    if status == "pending":
        return "Awaiting processing"
    elif status == "shipped":
        return "On the way"
    elif status == "delivered":
        return "Delivered"
    elif status == "cancelled":
        return "Cancelled"
    elif status == "refunded":
        return "Refunded"
    return "Unknown"

# ✅ Lookup table
STATUS_LABELS = {
    "pending": "Awaiting processing",
    "shipped": "On the way",
    "delivered": "Delivered",
    "cancelled": "Cancelled",
    "refunded": "Refunded",
}

def get_status_label(status):
    return STATUS_LABELS.get(status, "Unknown")
```

## Decompose: Orchestrator + Helpers

**Go:**
```go
// ❌ One function doing everything (80 lines)
func processOrder(order Order) error {
    // validate... fetch prices... calculate tax... check inventory...
    // charge payment... update stock... send email... log analytics...
}

// ✅ Orchestrator + focused helpers
func processOrder(order Order) error {
    if err := validateOrder(order); err != nil {
        return fmt.Errorf("validation: %w", err)
    }
    total, err := calculateTotal(order)
    if err != nil {
        return fmt.Errorf("pricing: %w", err)
    }
    if err := chargePayment(order.CustomerID, total); err != nil {
        return fmt.Errorf("payment: %w", err)
    }
    if err := fulfillOrder(order); err != nil {
        return fmt.Errorf("fulfillment: %w", err)
    }
    notifyCustomer(order) // fire-and-forget
    return nil
}
```

## State Machine: Replace Boolean Flags

**JavaScript:**
```javascript
// ❌ Boolean flags — 8 possible states, most invalid
let isLoading = false;
let hasError = false;
let hasData = false;

// ✅ State machine — only valid states
const state = { status: 'idle' }; // 'idle' | 'loading' | 'success' | 'error'

const transitions = {
  idle:    { FETCH: 'loading' },
  loading: { SUCCESS: 'success', FAILURE: 'error' },
  error:   { RETRY: 'loading', RESET: 'idle' },
  success: { REFRESH: 'loading' },
};

function dispatch(event) {
  const next = transitions[state.status]?.[event];
  if (next) state.status = next;
}
```

## When to Use
- "This function is too complex"
- "Flatten this deeply nested code"
- "Replace this switch with something simpler"
- "Too many boolean flags tracking state"
