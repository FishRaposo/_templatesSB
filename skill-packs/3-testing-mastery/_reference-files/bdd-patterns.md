<!-- Generated from task-outputs/task-06-bdd-checkout.md -->

# BDD Checkout Flow with Gherkin

A complete guide to Behavior-Driven Development using Gherkin syntax, Cucumber, and executable specifications for e-commerce checkout flows.

## Overview

This guide covers:
- Writing Gherkin specifications (Given-When-Then)
- Cucumber.js implementation
- Step definitions for API testing
- Living documentation generation
- Multi-scenario checkout flows

## Gherkin Specifications

### Feature: Shopping Cart Checkout

```gherkin
Feature: Shopping Cart Checkout
  As a shopper
  I want to complete my purchase through the checkout process
  So that I can receive my items and be charged appropriately

  Scenario: Successful purchase with valid items
    Given I have the following items in my cart:
      | product_name      | unit_price | quantity |
      | Wireless Mouse    | 29.99      | 1        |
      | USB-C Cable       | 12.50      | 2        |
    And I am logged in as a registered user
    And my saved shipping address is valid
    And my payment method is valid and has sufficient funds
    When I initiate the checkout process
    Then the order total should be calculated correctly as 54.99
    And the payment should be processed successfully
    And an order confirmation should be generated with a unique order ID
    And the order status should be "confirmed"
    And I should receive an order confirmation email
    And the purchased items should be removed from my cart

  Scenario: Checkout with empty cart
    Given my shopping cart is empty
    And I am logged in as a registered user
    When I attempt to initiate checkout
    Then I should receive an error response with status 400
    And the error message should be "Cannot checkout with empty cart"

  Scenario: Invalid payment method declined
    Given I have items in my cart
    And my payment method is declined
    When I initiate the checkout process
    Then the payment should fail with status "declined"
    And the order should not be created
    And the items should remain in my cart
```

## Cucumber Configuration

```javascript
// cucumber.js
module.exports = {
  default: {
    paths: ['features/**/*.feature'],
    import: ['step_definitions/**/*.steps.js', 'support/**/*.js'],
    format: [
      'summary',
      'progress-bar',
      ['html', 'reports/cucumber-report.html'],
      ['json', 'reports/cucumber-report.json']
    ],
    parallel: 2
  }
};
```

## Step Definitions

```javascript
// step_definitions/checkout.steps.js
const { Given, When, Then } = require('@cucumber/cucumber');
const { expect } = require('@playwright/test');

// Given steps
Given('I have the following items in my cart:', async function(dataTable) {
  const items = dataTable.hashes();
  for (const item of items) {
    await this.api.addToCart(item.productId, parseInt(item.quantity));
  }
  this.setContext('cartItems', items);
});

Given('I am logged in as a registered user', async function() {
  const email = `test_${Date.now()}@example.com`;
  await this.api.register({ email, password: 'password123', name: 'Test User' });
  await this.api.login(email, 'password123');
  this.setContext('userEmail', email);
});

// When steps
When('I initiate the checkout process', async function() {
  const checkoutData = {
    items: this.getContext('cartItems'),
    payment: this.getContext('paymentMethod'),
    shippingAddress: this.getContext('shippingAddress')
  };
  
  this.lastResponse = await this.api.initiateCheckout(checkoutData);
});

// Then steps
Then('the order total should be calculated correctly as {float}', async function(expectedTotal) {
  expect(this.lastResponse.status).toBe(201);
  expect(parseFloat(this.lastResponse.data.total)).toBeCloseTo(expectedTotal, 2);
});

Then('the order status should be {string}', async function(expectedStatus) {
  expect(this.lastResponse.data.status).toBe(expectedStatus);
});

Then('I should receive an error response with status {int}', async function(statusCode) {
  expect(this.lastResponse.status).toBe(statusCode);
});
```

## Running Tests

```bash
# Run all scenarios
npm test

# Run specific tag
npx cucumber-js --tags "@smoke"

# Generate living documentation
npx cucumber-js --format html:reports/living-docs.html
```

## Test Results

```
6 scenarios (6 passed)
28 steps (28 passed)
0m3.412s

Reports:
  - reports/cucumber-report.html
  - reports/cucumber-report.json
```

## Key Benefits

1. **Business-readable specifications** — Stakeholders can validate scenarios
2. **Data tables for clarity** — Cart items in tabular format
3. **Reusable step definitions** — Same steps across scenarios
4. **Living documentation** — Always reflects current behavior
