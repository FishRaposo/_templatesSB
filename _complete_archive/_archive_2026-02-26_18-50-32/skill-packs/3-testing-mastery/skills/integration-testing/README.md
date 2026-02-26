# Integration Testing

Test how components work together — APIs, databases, services, and workflows.

## Quick Start

```javascript
const request = require('supertest');

test('GET /users returns list', async () => {
  const response = await request(app)
    .get('/users')
    .expect(200);
  
  expect(response.body).toBeInstanceOf(Array);
});
```

## What to Test

- API endpoints and contracts
- Database operations
- Service communication
- Message queues
- End-to-end workflows

## Test Environment Options

| Strategy | Speed | Realism |
|----------|-------|---------|
| Test Containers | Medium | High |
| Local Services | Medium | High |
| Mock Server | Fast | Low |

## Database Testing with Testcontainers

```javascript
const { GenericContainer } = require('testcontainers');

const container = await new GenericContainer('postgres:15')
  .withExposedPorts(5432)
  .start();

// Test with real database
const db = new Database({
  host: 'localhost',
  port: container.getMappedPort(5432)
});
```

## Key Principles

- Use real components, not mocks
- Isolate test data
- Clean up after tests
- Verify real interactions

## Examples

See `examples/basic-examples.md` for full integration testing examples.

## Related Skills

- `unit-testing` — Test isolated components
- `test-doubles` — Mock external dependencies
- `test-data-management` — Create test data
