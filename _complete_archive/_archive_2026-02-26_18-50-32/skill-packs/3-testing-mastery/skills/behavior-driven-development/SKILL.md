---
name: behavior-driven-development
description: Use this skill when defining and verifying system behavior through concrete examples and scenarios. This includes writing Gherkin-style Given-When-Then specifications, implementing step definitions, creating executable specifications that serve as documentation, and bridging the gap between business requirements and technical implementation.
---

# Behavior-Driven Development

I'll help you define system behavior through concrete examples that serve as both documentation and executable tests. We'll bridge business requirements with technical implementation.

## Core Approach

### The BDD Cycle

```
1. DISCOVER  → Collaborate to identify behavior
2. FORMALIZE → Write Given-When-Then scenarios
3. AUTOMATE  → Implement executable specifications
4. VALIDATE  → Run scenarios to verify behavior
```

### Given-When-Then Format

```gherkin
Given [context/setup]
When [action/event]
Then [expected outcome]
```

## Step-by-Step Instructions

### 1. Identify Behaviors

Start with user stories or requirements:

```
As a [role]
I want [feature]
So that [benefit]
```

**Example:**
```
As a customer
I want to withdraw cash from an ATM
So that I can access my money
```

### 2. Write Scenarios

Break down into concrete examples:

```gherkin
Feature: ATM Cash Withdrawal
  As a customer
  I want to withdraw cash from an ATM
  So that I can access my money

  Scenario: Successful withdrawal with sufficient funds
    Given my account balance is $100
    And the ATM has sufficient cash
    When I request $50
    Then the ATM should dispense $50
    And my account balance should be $50
    And I should receive a receipt

  Scenario: Insufficient funds
    Given my account balance is $30
    When I request $50
    Then the ATM should display "Insufficient funds"
    And no cash should be dispensed
    And my account balance should remain $30

  Scenario: ATM has insufficient cash
    Given my account balance is $100
    And the ATM has $20 remaining
    When I request $50
    Then the ATM should display "Unable to process"
    And suggest alternative amounts
```

### 3. Implement Step Definitions

**JavaScript (Cucumber.js)**
```javascript
const { Given, When, Then } = require('@cucumber/cucumber');
const assert = require('assert');

// Setup
Given('my account balance is ${int}', function(balance) {
  this.account = new Account(balance);
});

Given('the ATM has {word} cash', function(amount) {
  this.atm = new ATM(amount === 'sufficient' ? 1000 : 20);
});

// Action
When('I request ${int}', function(amount) {
  this.result = this.atm.withdraw(this.account, amount);
});

// Assertions
Then('the ATM should dispense ${int}', function(amount) {
  assert.strictEqual(this.result.dispensed, amount);
});

Then('my account balance should be ${int}', function(expected) {
  assert.strictEqual(this.account.balance, expected);
});

Then('the ATM should display {string}', function(message) {
  assert.strictEqual(this.result.message, message);
});

Then('no cash should be dispensed', function() {
  assert.strictEqual(this.result.dispensed, 0);
});
```

**Python (Behave)**
```python
from behave import given, when, then

@given('my account balance is {amount:d}')
def step_account_balance(context, amount):
    context.account = Account(balance=amount)

@given('the ATM has {availability} cash')
def step_atm_cash(context, availability):
    cash_amount = 1000 if availability == 'sufficient' else 20
    context.atm = ATM(cash_available=cash_amount)

@when('I request {amount:d}')
def step_request_amount(context, amount):
    context.result = context.atm.withdraw(context.account, amount)

@then('the ATM should dispense {amount:d}')
def step_dispense_amount(context, amount):
    assert context.result.dispensed == amount

@then('my account balance should be {amount:d}')
def step_check_balance(context, amount):
    assert context.account.balance == amount

@then('the ATM should display "{message}"')
def step_display_message(context, message):
    assert context.result.message == message
```

**Java (Cucumber JVM)**
```java
import io.cucumber.java.en.*;
import static org.junit.Assert.*;

public class ATMSteps {
    private Account account;
    private ATM atm;
    private WithdrawalResult result;

    @Given("my account balance is ${int}")
    public void accountBalance(int balance) {
        account = new Account(balance);
    }

    @Given("the ATM has {word} cash")
    public void atmCash(String availability) {
        int cash = availability.equals("sufficient") ? 1000 : 20;
        atm = new ATM(cash);
    }

    @When("I request ${int}")
    public void requestAmount(int amount) {
        result = atm.withdraw(account, amount);
    }

    @Then("the ATM should dispense ${int}")
    public void verifyDispensed(int amount) {
        assertEquals(amount, result.getDispensed());
    }
}
```

## Multi-Language Examples

### E-Commerce Checkout

```gherkin
Feature: Shopping Cart Checkout
  As a shopper
  I want to complete my purchase
  So that I can receive my items

  Scenario: Successful purchase
    Given I have items in my cart:
      | Product    | Price | Quantity |
      | T-Shirt    | 25.00 | 2        |
      | Socks      | 10.00 | 1        |
    And I am logged in as "john@example.com"
    And my payment method is valid
    When I proceed to checkout
    Then the order total should be $60.00
    And my payment should be processed
    And I should receive an order confirmation
    And the items should be removed from my cart

  Scenario: Empty cart checkout
    Given my cart is empty
    When I try to checkout
    Then I should see "Your cart is empty"
    And I should remain on the cart page

  Scenario: Invalid payment
    Given I have items in my cart
    And my payment method is declined
    When I proceed to checkout
    Then I should see "Payment failed"
    And the items should remain in my cart
```

**Step Definitions (JavaScript)**
```javascript
Given('I have items in my cart:', function(dataTable) {
  this.cart = new Cart();
  const items = dataTable.hashes();
  items.forEach(item => {
    this.cart.add({
      name: item.Product,
      price: parseFloat(item.Price),
      quantity: parseInt(item.Quantity)
    });
  });
});

Given('I am logged in as {string}', function(email) {
  this.user = new User(email);
  this.user.login();
});

When('I proceed to checkout', async function() {
  this.checkout = new Checkout(this.cart, this.user);
  this.result = await this.checkout.process();
});

Then('the order total should be ${float}', function(expectedTotal) {
  assert.strictEqual(this.result.orderTotal, expectedTotal);
});
```

### API Behavior Testing

```gherkin
Feature: User Management API
  As an API consumer
  I want to manage users
  So that I can maintain user accounts

  Scenario: Create a new user
    Given the API is running
    When I POST to "/users" with:
      """
      {
        "name": "John Doe",
        "email": "john@example.com"
      }
      """
    Then the response status should be 201
    And the response should contain:
      | Field | Value            |
      | name  | John Doe         |
      | email | john@example.com |
    And the response should have an "id" field

  Scenario: Get non-existent user
    Given the API is running
    When I GET "/users/99999"
    Then the response status should be 404
    And the response should contain an error message
```

## Best Practices

### Scenario Guidelines

✅ **Good: Concrete and specific**
```gherkin
Given my account balance is $100
When I withdraw $50
Then my balance should be $50
```

❌ **Bad: Vague and abstract**
```gherkin
Given I have money
When I make a withdrawal
Then my balance changes
```

✅ **Good: Focuses on behavior**
```gherkin
Then I should receive a confirmation email
```

❌ **Bad: Focuses on implementation**
```gherkin
Then the email queue should contain a message
```

### Scenario Structure

**Single responsibility:**
```gherkin
# Good: One scenario per rule
Scenario: Withdrawal with sufficient funds
Scenario: Withdrawal with insufficient funds
Scenario: Withdrawal exceeding daily limit
```

**Use Background for common setup:**
```gherkin
Feature: Shopping Cart
  Background:
    Given I am logged in as a customer
    And the store has products in stock

  Scenario: Add item to cart
    # ...

  Scenario: Remove item from cart
    # ...
```

**Use Scenario Outline for data-driven tests:**
```gherkin
Scenario Outline: Withdraw various amounts
  Given my balance is <initial>
  When I withdraw <amount>
  Then my balance should be <remaining>

  Examples:
    | initial | amount | remaining |
    | 100     | 50     | 50        |
    | 100     | 100    | 0         |
    | 100     | 0      | 100       |
```

## Common Patterns

### Data Tables

```gherkin
Given the following users exist:
  | Username | Role    | Active |
  | alice    | admin   | true   |
  | bob      | user    | true   |
  | charlie  | user    | false  |
```

```javascript
Given('the following users exist:', function(dataTable) {
  const users = dataTable.hashes();  // Array of objects
  users.forEach(user => createUser(user));
});
```

### Doc Strings

```gherkin
When I submit the following JSON:
  """
  {
    "name": "Product",
    "price": 29.99
  }
  """
```

### Tags

```gherkin
@smoke @fast
Scenario: Basic login
  # ...

@slow @integration
Scenario: Full checkout flow
  # ...
```

Run specific tags:
```bash
# Run only smoke tests
cucumber --tags "@smoke"

# Run everything except slow tests
cucumber --tags "not @slow"
```

## Living Documentation

Generate HTML reports from scenarios:

```bash
# JavaScript
cucumber-js --format html:cucumber-report.html

# Python
behave --format allure_behave.formatter:AllureFormatter
```

## Validation Checklist

- [ ] Scenarios use business language, not technical jargon
- [ ] Each scenario tests one specific behavior
- [ ] Given steps establish context clearly
- [ ] When steps describe the action
- [ ] Then steps verify observable outcomes
- [ ] No implementation details in scenarios
- [ ] Step definitions are reusable across scenarios
- [ ] Living documentation is generated and accessible

## Related Skills

- **test-strategy** — Decide when to use BDD
- **integration-testing** — BDD often tests integrations
- **test-automation** — Automate BDD scenarios in CI
