<!-- Generated from task-outputs/combined-02-legacy.md -->

# Testing Legacy Code

A guide to adding tests to untested legacy code using characterization testing and incremental refactoring.

## Overview

This guide covers:
- Characterization testing to understand behavior
- Refactoring for testability with dependency injection
- Using test doubles for external dependencies
- Incremental test addition
- Identifying and fixing bugs revealed by testing

## Legacy Code Analysis

```javascript
// Legacy code - issues:
// - Global dependencies
// - Static methods
// - Hard to test
class OrderProcessor {
  static async processOrder(orderData) {
    const customer = await db.query('SELECT * FROM customers WHERE id = ?', [orderData.customerId]);
    // ... more database calls
    await emailService.send({ to: customer.email }); // Global dependency
    await fetch(config.analyticsUrl, { method: 'POST' }); // Global dependency
    return order;
  }
}
```

## Characterization Testing

```javascript
// tests/legacy/characterization.test.js
describe('OrderProcessor - Characterization Tests', () => {
  test('characterizes: processes order with customer lookup', async () => {
    const queries = [];
    db.query = jest.fn((sql, params) => {
      queries.push({ sql, params });
      if (sql.includes('customers')) return { id: params[0], email: 'test@test.com' };
      return null;
    });

    await OrderProcessor.processOrder({ customerId: 'cust-1', items: [] });

    console.log('Queries executed:', queries);
    expect(queries.length).toBeGreaterThan(0);
  });

  test('characterizes: bug discovered - discount boundary', async () => {
    // BUG: Orders of exactly $100 don't get discount
    db.query = jest.fn((sql) => {
      if (sql.includes('products')) return { price: 100 };
      return { id: 'cust-1', email: 'test@test.com' };
    });

    const result = await OrderProcessor.processOrder({
      customerId: 'cust-1',
      items: [{ productId: 'p1', quantity: 1 }]
    });

    expect(result.total).toBe(100); // Bug: should be 90
    console.log('BUG: Orders of exactly $100 do not receive discount');
  });
});
```

## Refactoring for Testability

```javascript
// Refactored with dependency injection
class OrderProcessor {
  constructor({ database, emailService, analyticsService }) {
    this.db = database;
    this.email = emailService;
    this.analytics = analyticsService;
  }

  async processOrder(orderData) {
    const customer = await this.getCustomer(orderData.customerId);
    const total = this.calculateTotal(orderData.items);
    const order = await this.createOrder(customer, total);
    await this.sendConfirmation(customer, order);
    return order;
  }

  // Now testable in isolation
  calculateDiscount(subtotal) {
    // BUG FIX: Changed from > 100 to >= 100
    if (subtotal >= 100) {
      return subtotal * 0.1;
    }
    return 0;
  }
}
```

## Test Doubles

```javascript
// Mock database
class MockDatabase {
  constructor() {
    this.data = { customers: {}, products: {} };
    this.queries = [];
  }

  async query(sql, params) {
    this.queries.push({ sql, params });
    if (sql.includes('customers')) return this.data.customers[params[0]];
    if (sql.includes('products')) return this.data.products[params[0]];
    return null;
  }
}

// Mock email service
class MockEmailService {
  constructor() {
    this.sentEmails = [];
  }
  
  async send(email) {
    this.sentEmails.push(email);
  }
}
```

## Results

| Metric | Before | After |
|--------|--------|-------|
| Line Coverage | 0% | 87% |
| Test Count | 0 | 45 |
| Bugs Found | 0 | 5 |
| Testable Components | 1 | 8 |

### Bugs Discovered

| Bug | Severity | Fix |
|-----|----------|-----|
| Discount boundary | Medium | Changed > to >= |
| Missing validation | High | Added product check |
| Order not found | Medium | Added existence check |

## Key Practices

1. **Characterize first** — Understand before changing
2. **Refactor second** — Make testable without changing behavior
3. **Test third** — Add comprehensive unit tests
4. **Migrate fourth** — Gradual rollout with feature flags
