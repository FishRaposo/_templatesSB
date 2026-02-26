# Legacy Code Migration — Basic Examples

## Characterization Tests

**Python:**
```python
# Capture current behavior BEFORE changing anything
class TestLegacyCalculator:
    """Document what the code does today — warts and all."""

    def test_empty_list_returns_zero(self):
        assert legacy_calculate([]) == 0

    def test_negative_values_included(self):
        # Bug or feature? Doesn't matter — capture the behavior
        assert legacy_calculate([{"price": -10, "qty": 1}]) == -10

    def test_discount_truncates(self):
        # Legacy uses int() not round()
        assert legacy_calculate([{"price": 33, "qty": 3}], discount=0.10) == 89
```

## Strangler Fig Pattern

**JavaScript:**
```javascript
// Step 1: Define new interface
class OrderService {
  async getTotal(orderId) {}
  async placeOrder(order) {}
}

// Step 2: Legacy adapter
class LegacyOrderAdapter extends OrderService {
  constructor(legacy) { super(); this.legacy = legacy; }

  async getTotal(orderId) {
    const old = await this.legacy.getOrder(orderId);
    return this.legacy.calcTotal(old.items, old.discount);
  }
}

// Step 3: New implementation (migrate one method at a time)
class ModernOrderService extends OrderService {
  async getTotal(orderId) {
    const order = await this.repo.findById(orderId);
    return order.items.reduce((s, i) => s + i.price * i.qty, 0);
  }

  // Not yet migrated — delegate to legacy
  async placeOrder(order) {
    return this.legacyAdapter.placeOrder(order);
  }
}

// Step 4: Feature flag switches traffic
function createOrderService(config) {
  if (config.useModernOrders) return new ModernOrderService(db);
  return new LegacyOrderAdapter(oldSystem);
}
```

## Shadow Mode: Compare Results

**Python:**
```python
async def get_total_with_comparison(order_id):
    """Run both, compare, return legacy until validated."""
    legacy = await legacy_service.get_total(order_id)
    modern = await modern_service.get_total(order_id)

    if legacy != modern:
        logger.warning("migration.mismatch",
                       order_id=order_id, legacy=legacy, modern=modern)
        return legacy  # Safe: serve legacy until mismatches resolved

    return modern
```

## Incremental Database Migration

```sql
-- Step 1: Add new column (backward compatible)
ALTER TABLE orders ADD COLUMN total_v2 DECIMAL(10,2);

-- Step 2: Backfill
UPDATE orders SET total_v2 = recalculate_total(items);

-- Step 3: Verify
SELECT COUNT(*) FROM orders WHERE ABS(total - total_v2) > 0.01;

-- Step 4: Switch reads, then drop old column later
```

## When to Use
- "How do I start migrating this legacy module?"
- "Write characterization tests for this untested code"
- "Apply strangler fig pattern to this service"
- "Set up shadow mode to compare old and new"
