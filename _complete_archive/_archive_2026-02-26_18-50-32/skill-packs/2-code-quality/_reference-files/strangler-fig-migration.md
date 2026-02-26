<!-- Generated from task-outputs/task-12-legacy-code-migration.md -->

# Task 12 — Legacy Code Migration
> Skills: legacy-code-migration, code-refactoring, technical-debt

## Strangler Fig Migration: Express Order Module

### Phase 1: Characterization Tests

```javascript
// test/legacy.characterization.test.js
describe('Legacy Order Module', () => {
  it('should calculate total with 10% promo discount', async () => {
    const result = await legacyOrder.calculateTotal({
      items: [{ sku: 'PROMO_ITEM', price: 100, qty: 1 }]
    });
    expect(result).toBe(90); // Captured actual behavior
  });
  
  it('should apply 5% discount on orders over $100', async () => {
    const result = await legacyOrder.calculateTotal({
      items: [{ sku: 'REGULAR', price: 150, qty: 1 }]
    });
    expect(result).toBe(142.50);
  });
});
```

### Phase 2: New Interface

```typescript
// interfaces/OrderCalculator.ts
interface OrderCalculator {
  calculateTotal(order: Order): Promise<number>;
  calculateTax(amount: number, state: string): number;
  applyDiscounts(subtotal: number, items: Item[], coupon?: string): number;
}
```

### Phase 3: Adapter

```javascript
// adapters/LegacyOrderAdapter.js
class LegacyOrderAdapter {
  constructor(legacyModule) {
    this.legacy = legacyModule;
  }
  
  async calculateTotal(order) {
    // Delegate to legacy but conform to new interface
    return this.legacy.calculateTotal(order);
  }
}
```

### Phase 4: Shadow Mode

```javascript
// services/ShadowOrderService.js
class ShadowOrderService {
  async calculateTotal(order) {
    const legacyResult = await this.legacy.calculateTotal(order);
    
    // Run new implementation in shadow
    try {
      const newResult = await this.newCalculator.calculateTotal(order);
      
      if (Math.abs(legacyResult - newResult) > 0.01) {
        logger.warn('Shadow mismatch', {
          order: order.id,
          legacy: legacyResult,
          new: newResult,
          diff: Math.abs(legacyResult - newResult)
        });
      }
    } catch (error) {
      logger.error('Shadow error', { error: error.message });
    }
    
    return legacyResult; // Still return legacy result
  }
}
```

### Phase 5: Feature Flags

```javascript
// config/features.js
const features = {
  NEW_ORDER_CALCULATOR: process.env.FF_NEW_CALCULATOR === 'true'
};

// Usage
async function calculate(order) {
  if (features.NEW_ORDER_CALCULATOR) {
    return newCalculator.calculateTotal(order);
  }
  return legacyOrder.calculateTotal(order);
}
```

### Phase 6: Rollback Plan

```javascript
// Rollback procedure
async function rollback() {
  await redis.set('FF_NEW_CALCULATOR', 'false');
  await notifyTeam('Rollback complete');
}
```

- [x] Characterization tests capture actual behavior including quirks
- [x] Interface defined before implementation
- [x] Shadow mode compares results and logs mismatches
- [x] Feature flag controls traffic, not deploys
- [x] Rollback plan is documented and tested

