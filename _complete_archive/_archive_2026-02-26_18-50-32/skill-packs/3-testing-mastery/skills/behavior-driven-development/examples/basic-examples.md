# BDD Examples

## Gherkin Scenario

```gherkin
Feature: User Registration
  As a new user
  I want to register an account
  So that I can access the application

  Scenario: Successful registration
    Given the API is running
    When I send a POST request to "/register" with:
      """
      {
        "name": "John Doe",
        "email": "john@example.com",
        "password": "Secure123!"
      }
      """
    Then the response status should be 201
    And the response should contain a user ID
    And a welcome email should be queued

  Scenario: Duplicate email
    Given a user with email "john@example.com" exists
    When I send a POST request to "/register" with:
      """
      {
        "email": "john@example.com",
        "password": "Secure123!"
      }
      """
    Then the response status should be 409
```

## Step Definitions (JavaScript)

```javascript
const { Given, When, Then } = require('@cucumber/cucumber');
const request = require('supertest');
const app = require('../../app');

Given('the API is running', function() {
  this.api = request(app);
});

When('I send a POST request to {string} with:', async function(endpoint, docString) {
  const data = JSON.parse(docString);
  this.response = await this.api
    .post(endpoint)
    .send(data);
});

Then('the response status should be {int}', function(status) {
  if (this.response.status !== status) {
    throw new Error(`Expected status ${status} but got ${this.response.status}`);
  }
});

Then('the response should contain a user ID', function() {
  if (!this.response.body.id) {
    throw new Error('Response does not contain user ID');
  }
});
```

## Step Definitions (Python)

```python
from behave import given, when, then
import requests

@given('the API is running')
def step_api_running(context):
    context.base_url = 'http://localhost:8000'

@when('I send a POST request to "{endpoint}" with')
def step_post_request(context, endpoint):
    data = json.loads(context.text)
    context.response = requests.post(
        f'{context.base_url}{endpoint}',
        json=data
    )

@then('the response status should be {status:d}')
def step_status_code(context, status):
    assert context.response.status_code == status

@then('the response should contain a user ID')
def step_user_id(context):
    response_data = context.response.json()
    assert 'id' in response_data
```

## Scenario Outline (Data-Driven)

```gherkin
Feature: Login
  Scenario Outline: Login with various credentials
    Given a user exists with email "<email>" and password "<password>"
    When I login with "<email>" and "<password>"
    Then the result should be "<result>"

    Examples:
      | email           | password    | result    |
      | valid@test.com  | correctpass | success   |
      | valid@test.com  | wrongpass   | failed    |
      | invalid@test.com| anypass     | failed    |
```

## Best Practices

- Use business language, not technical jargon
- Focus on behavior, not implementation
- One scenario per behavior
- Concrete examples, not abstract
