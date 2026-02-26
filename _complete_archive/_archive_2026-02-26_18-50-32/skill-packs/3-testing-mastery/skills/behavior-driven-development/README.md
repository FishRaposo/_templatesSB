# Behavior-Driven Development

Define system behavior through concrete Given-When-Then scenarios that serve as both documentation and executable tests.

## Quick Start

```gherkin
Feature: ATM Withdrawal
  Scenario: Successful withdrawal
    Given my account balance is $100
    When I request $50
    Then the ATM should dispense $50
    And my balance should be $50
```

## The BDD Cycle

1. **DISCOVER** — Collaborate to identify behavior
2. **FORMALIZE** — Write Given-When-Then scenarios
3. **AUTOMATE** — Implement step definitions
4. **VALIDATE** — Run scenarios to verify behavior

## Given-When-Then Format

```gherkin
Given [context/setup]
When [action/event]
Then [expected outcome]
```

## Step Definitions (JavaScript)

```javascript
const { Given, When, Then } = require('@cucumber/cucumber');

Given('my account balance is ${int}', function(balance) {
  this.account = new Account(balance);
});

When('I request ${int}', function(amount) {
  this.result = this.atm.withdraw(this.account, amount);
});

Then('my balance should be ${int}', function(expected) {
  assert.strictEqual(this.account.balance, expected);
});
```

## Key Principles

- Use business language, not technical jargon
- Concrete examples, not abstract concepts
- Focus on behavior, not implementation
- One scenario per behavior
- Living documentation

## Scenario Outline

```gherkin
Scenario Outline: Withdraw various amounts
  Given my balance is <initial>
  When I withdraw <amount>
  Then my balance should be <remaining>

  Examples:
    | initial | amount | remaining |
    | 100     | 50     | 50        |
    | 100     | 100    | 0         |
```

## Examples

See `examples/basic-examples.md` for full BDD examples in multiple languages.

## Related Skills

- `test-strategy` — Decide when to use BDD
- `integration-testing` — BDD often tests integrations
- `test-automation` — Automate BDD scenarios in CI
