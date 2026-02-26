---
name: legacy-code-migration
description: Use this skill when migrating or modernizing legacy code. This includes strangler fig pattern, characterization testing, incremental rewrites, API wrapping, database migration, and safely transitioning from old systems to new ones without downtime.
---

# Legacy Code Migration

I'll help you migrate legacy code safely with strangler fig, characterization tests, and incremental rewrites. When you invoke this skill, I can guide you through modernizing old systems without big-bang rewrites or production downtime.

# Core Approach

My approach focuses on:
1. Understanding the legacy system before changing it (characterization tests)
2. Migrating incrementally with the strangler fig pattern
3. Running old and new systems in parallel with feature flags
4. Verifying behavioral equivalence at every step

# Step-by-Step Instructions

## 1. Understand Before You Change

Before touching legacy code, capture its current behavior:

```python
# Characterization test: capture WHAT the code does (not what it SHOULD do)
import pytest

class TestLegacyOrderProcessor:
    """Characterization tests — document current behavior, warts and all."""

    def test_empty_order_returns_zero(self):
        result = legacy_calculate_total([])
        assert result == 0  # captured from running the legacy code

    def test_negative_prices_are_included(self):
        # Bug? Feature? Doesn't matter — this is what it does today
        result = legacy_calculate_total([{"price": -10, "qty": 1}])
        assert result == -10

    def test_discount_rounds_down(self):
        # Legacy uses int() truncation, not round()
        result = legacy_calculate_total([{"price": 33, "qty": 3}], discount=0.10)
        assert result == 89  # not 89.1, because int(89.1) == 89
```

```bash
# Generate a test coverage map of the legacy code
pytest --cov=legacy/ --cov-report=html
# Open htmlcov/index.html to see what's covered
```

## 2. Apply the Strangler Fig Pattern

Wrap the legacy system behind a new interface, then migrate one piece at a time:

**JavaScript:**
```javascript
// Phase 1: Define the new interface
class OrderService {
  async calculateTotal(orderId) { /* new interface */ }
  async placeOrder(order) { /* new interface */ }
  async cancelOrder(orderId) { /* new interface */ }
}

// Phase 2: Legacy adapter implements the interface
class LegacyOrderAdapter extends OrderService {
  constructor(legacySystem) {
    super();
    this.legacy = legacySystem;
  }

  async calculateTotal(orderId) {
    // Translate new interface → legacy calls
    const legacyOrder = await this.legacy.getOrder(orderId);
    return this.legacy.calcTotal(legacyOrder.items, legacyOrder.discount_code);
  }
}

// Phase 3: New implementation (one method at a time)
class ModernOrderService extends OrderService {
  async calculateTotal(orderId) {
    const order = await this.orderRepo.findById(orderId);
    return order.items.reduce((sum, item) =>
      sum + item.price * item.quantity, 0) * (1 - order.discountRate);
  }

  // Still delegates to legacy for methods not yet migrated
  async placeOrder(order) {
    return this.legacyAdapter.placeOrder(order);
  }
}

// Phase 4: Feature flag controls traffic
function createOrderService(config) {
  const legacy = new LegacyOrderAdapter(oldSystem);
  const modern = new ModernOrderService(db);

  return new Proxy(modern, {
    get(target, prop) {
      if (config.migratedMethods.includes(prop)) {
        return target[prop].bind(target);
      }
      return legacy[prop].bind(legacy);
    }
  });
}
```

## 3. Run in Parallel and Compare

Verify the new system matches the old one before cutting over:

```python
import logging

logger = logging.getLogger("migration")

async def calculate_total_with_comparison(order_id):
    """Run both systems, compare results, return legacy result until validated."""
    legacy_result = await legacy_service.calculate_total(order_id)
    modern_result = await modern_service.calculate_total(order_id)

    if legacy_result != modern_result:
        logger.warning(
            "migration.mismatch",
            order_id=order_id,
            legacy=legacy_result,
            modern=modern_result,
            diff=abs(legacy_result - modern_result),
        )
        # Return legacy result until mismatches are resolved
        return legacy_result

    logger.info("migration.match", order_id=order_id)
    return modern_result
```

## 4. Migrate Data Incrementally

```bash
# Database migration: add new columns alongside old ones
-- Step 1: Add new columns (backward compatible)
ALTER TABLE orders ADD COLUMN total_v2 DECIMAL(10,2);
ALTER TABLE orders ADD COLUMN status_v2 VARCHAR(50);

-- Step 2: Dual-write (write to both old and new columns)
-- Step 3: Backfill historical data
UPDATE orders SET total_v2 = calculate_new_total(items, discount)
  WHERE total_v2 IS NULL;

-- Step 4: Verify data matches
SELECT COUNT(*) FROM orders WHERE ABS(total - total_v2) > 0.01;

-- Step 5: Switch reads to new columns
-- Step 6: Drop old columns (after verification period)
```

## 5. Cut Over Safely

```yaml
# Feature flag progression
migration_flags:
  order_calculation:
    phase: "shadow"        # shadow → canary → rollout → complete
    shadow_percentage: 100  # Compare 100% but serve legacy
    canary_percentage: 0    # Serve new to X% of traffic
    rollout_percentage: 0   # Serve new to X% of traffic

# Progression:
# Week 1: shadow=100% — compare all, serve legacy
# Week 2: canary=5% — serve new to 5%, monitor errors
# Week 3: rollout=50% — serve new to 50%
# Week 4: rollout=100% — full cutover
# Week 6: complete — remove legacy code
```

# Best Practices

- Never do a big-bang rewrite — migrate incrementally with strangler fig
- Write characterization tests BEFORE changing anything
- Run old and new in parallel with shadow traffic before cutting over
- Use feature flags to control the migration, not deploys
- Migrate the most-changed code first (highest churn = highest ROI)
- Keep the legacy system running until the new system is proven
- Document known legacy behaviors (bugs that are "features")

# Validation Checklist

When migrating legacy code, verify:
- [ ] Characterization tests capture current behavior (including quirks)
- [ ] New interface defined before implementation begins
- [ ] Legacy adapter wraps old system behind new interface
- [ ] Shadow mode compares old and new results for 100% of traffic
- [ ] Mismatches are logged and investigated before cutover
- [ ] Feature flags control traffic routing (not code deploys)
- [ ] Rollback plan exists and is tested
- [ ] Old code is removed after successful migration (no dead code)

# Troubleshooting

## Issue: Legacy Code Has No Tests

**Symptoms**: No test coverage, afraid to change anything

**Solution**:
- Write characterization tests by running the legacy code and recording outputs
- Use approval testing (snapshot the output, approve it as the baseline)
- Focus tests on the area you're about to migrate, not the entire system
- Consider using a test harness that captures HTTP requests/responses

## Issue: Legacy and Modern Results Don't Match

**Symptoms**: Shadow mode shows mismatches for edge cases

**Solution**:
- Categorize mismatches: bug fixes (intentional) vs regressions (unintentional)
- Document intentional behavior changes with business stakeholder approval
- For unintentional differences, fix the modern implementation
- Don't proceed to canary until mismatch rate is <0.1%

# Supporting Files

- See `./_examples/basic-examples.md` for characterization tests, strangler fig, shadow mode, and migration examples
- See `./README.md` for quick start and invocation examples

## Related Skills

- **technical-debt** - Prioritize which legacy code to migrate first
- **code-refactoring** - Safely restructure code during migration
- **code-deduplication** - Consolidate duplicated logic during migration
- **error-handling** - Implement proper error handling in the new system
- → **3-testing-mastery**: integration-testing (for verifying migration correctness)
- → **35-feature-management**: feature-flags (for controlling migration rollout)

Remember: The strangler fig grows around the old tree — it doesn't chop it down!
