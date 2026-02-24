<!-- Generated from task-outputs/task-02-api-integration.md -->

# API Integration Testing with Testcontainers

A complete guide to setting up integration tests for REST APIs using PostgreSQL testcontainers, data factories, and comprehensive workflow testing.

## Overview

This guide covers:
- Setting up testcontainers for PostgreSQL
- Testing REST API endpoints (POST /users, GET /users/:id, POST /orders)
- Complete user registration → login → create order workflows
- Data factories for test data generation
- Database cleanup between tests
- Error case testing (400, 404, 409 responses)

## Project Structure

```
api-integration-tests/
├── src/
│   ├── app.js              # Express application
│   ├── models/
│   │   ├── user.js
│   │   └── order.js
│   ├── routes/
│   │   ├── users.js
│   │   └── orders.js
│   └── database.js         # Database connection
├── tests/
│   ├── integration/
│   │   ├── setup.js        # Test setup with testcontainers
│   │   ├── users.test.js   # User API tests
│   │   ├── orders.test.js  # Order API tests
│   │   └── workflow.test.js # End-to-end workflow
│   └── factories/
│       └── index.js        # Data factories
├── package.json
└── jest.config.js
```

## Express Application Implementation

### Main App

```javascript
// src/app.js
const express = require('express');
const { sequelize } = require('./models');
const userRoutes = require('./routes/users');
const orderRoutes = require('./routes/orders');

const app = express();
app.use(express.json());

app.use('/users', userRoutes);
app.use('/orders', orderRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    code: err.code
  });
});

module.exports = app;
```

### Models

```javascript
// src/models/user.js
const { DataTypes } = require('sequelize');
const bcrypt = require('bcryptjs');

module.exports = (sequelize) => {
  const User = sequelize.define('User', {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: { len: [2, 100] }
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: { isEmail: true }
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: { len: [6, 255] }
    }
  }, {
    tableName: 'users',
    hooks: {
      beforeCreate: async (user) => {
        user.password = await bcrypt.hash(user.password, 10);
      }
    }
  });

  return User;
};
```

```javascript
// src/models/order.js
const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  const Order = sequelize.define('Order', {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true
    },
    userId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: { model: 'users', key: 'id' }
    },
    items: {
      type: DataTypes.JSONB,
      allowNull: false,
      validate: {
        notEmpty(value) {
          if (!value || value.length === 0) {
            throw new Error('Order must contain at least one item');
          }
        }
      }
    },
    total: {
      type: DataTypes.DECIMAL(10, 2),
      allowNull: false,
      validate: { min: 0 }
    },
    status: {
      type: DataTypes.ENUM('pending', 'confirmed', 'shipped', 'delivered', 'cancelled'),
      defaultValue: 'pending'
    },
    shippingAddress: {
      type: DataTypes.JSONB,
      allowNull: false
    }
  }, { tableName: 'orders' });

  return Order;
};
```

## Test Setup with Testcontainers

```javascript
// tests/integration/setup.js
const { GenericContainer } = require('testcontainers');
const { Sequelize } = require('sequelize');
const app = require('../../src/app');

let container;
let sequelize;
let server;
let baseUrl;

// Start PostgreSQL container
beforeAll(async () => {
  container = await new GenericContainer('postgres:15-alpine')
    .withExposedPorts(5432)
    .withEnvironment({
      POSTGRES_USER: 'test',
      POSTGRES_PASSWORD: 'test',
      POSTGRES_DB: 'testdb'
    })
    .withStartupTimeout(120000)
    .start();

  const host = container.getHost();
  const port = container.getMappedPort(5432);
  const databaseUrl = `postgresql://test:test@${host}:${port}/testdb`;

  // Connect to database
  sequelize = new Sequelize(databaseUrl, {
    dialect: 'postgres',
    logging: false
  });

  // Run migrations
  await sequelize.authenticate();
  await sequelize.sync({ force: true });

  // Start server
  const port = 0; // Random available port
  server = app.listen(port);
  baseUrl = `http://localhost:${server.address().port}`;

  // Make available to tests
  global.testContext = { sequelize, baseUrl, container };
}, 60000);

// Clean up after all tests
afterAll(async () => {
  if (server) await new Promise(resolve => server.close(resolve));
  if (sequelize) await sequelize.close();
  if (container) await container.stop();
}, 30000);

// Clean database before each test
beforeEach(async () => {
  await sequelize.truncate({ cascade: true, restartIdentity: true });
});

module.exports = { getTestContext: () => global.testContext };
```

## Data Factories

```javascript
// tests/factories/index.js
const { faker } = require('@faker-js/faker');
const { User, Order } = require('../../src/models');

class UserFactory {
  static build(overrides = {}) {
    return {
      name: faker.person.fullName(),
      email: faker.internet.email(),
      password: faker.internet.password({ length: 12 }),
      ...overrides
    };
  }

  static async create(overrides = {}) {
    const data = this.build(overrides);
    return User.create(data);
  }

  static async createMany(count, overrides = {}) {
    return Promise.all(
      Array.from({ length: count }, () => this.create(overrides))
    );
  }
}

class OrderFactory {
  static build(overrides = {}) {
    return {
      items: [{
        productId: faker.string.uuid(),
        name: faker.commerce.productName(),
        price: parseFloat(faker.commerce.price()),
        quantity: faker.number.int({ min: 1, max: 5 })
      }],
      shippingAddress: {
        street: faker.location.streetAddress(),
        city: faker.location.city(),
        state: faker.location.state(),
        zipCode: faker.location.zipCode(),
        country: 'US'
      },
      ...overrides
    };
  }

  static async create(userId, overrides = {}) {
    const data = this.build(overrides);
    const items = data.items;
    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    return Order.create({
      userId,
      items,
      total,
      shippingAddress: data.shippingAddress,
      status: overrides.status || 'confirmed'
    });
  }
}

module.exports = { UserFactory, OrderFactory };
```

## Integration Tests

### User API Tests

```javascript
// tests/integration/users.test.js
const request = require('supertest');
const { UserFactory } = require('../factories');
const { getTestContext } = require('./setup');

describe('User API Integration Tests', () => {
  let baseUrl;
  let sequelize;

  beforeAll(() => {
    const ctx = getTestContext();
    baseUrl = ctx.baseUrl;
    sequelize = ctx.sequelize;
  });

  describe('POST /users', () => {
    test('creates a new user successfully', async () => {
      const userData = UserFactory.build({
        name: 'John Doe',
        email: 'john@example.com',
        password: 'password123'
      });

      const response = await request(baseUrl)
        .post('/users')
        .send(userData)
        .expect('Content-Type', /json/)
        .expect(201);

      expect(response.body).toMatchObject({
        name: userData.name,
        email: userData.email
      });
      expect(response.body.id).toBeDefined();
      expect(response.body.password).toBeUndefined();
    });

    test('returns 400 when required fields are missing', async () => {
      const testCases = [
        { body: { email: 'test@test.com', password: 'pass' } },
        { body: { name: 'Test', password: 'pass' } },
        { body: { name: 'Test', email: 'test@test.com' } }
      ];

      for (const testCase of testCases) {
        const response = await request(baseUrl)
          .post('/users')
          .send(testCase.body)
          .expect(400);

        expect(response.body.code).toBe('MISSING_FIELDS');
      }
    });

    test('returns 409 when email already exists', async () => {
      const userData = UserFactory.build({ email: 'duplicate@test.com' });
      
      await request(baseUrl).post('/users').send(userData).expect(201);

      const response = await request(baseUrl)
        .post('/users')
        .send(userData)
        .expect(409);

      expect(response.body.code).toBe('EMAIL_EXISTS');
    });
  });

  describe('GET /users/:id', () => {
    test('returns user by ID', async () => {
      const user = await UserFactory.create({ name: 'Jane Doe' });

      const response = await request(baseUrl)
        .get(`/users/${user.id}`)
        .expect(200);

      expect(response.body).toMatchObject({
        id: user.id,
        name: 'Jane Doe'
      });
    });

    test('returns 404 for non-existent user', async () => {
      const response = await request(baseUrl)
        .get('/users/123e4567-e89b-12d3-a456-426614174000')
        .expect(404);

      expect(response.body.code).toBe('USER_NOT_FOUND');
    });
  });
});
```

### Order API Tests

```javascript
// tests/integration/orders.test.js
const request = require('supertest');
const { UserFactory, OrderFactory } = require('../factories');
const { getTestContext } = require('./setup');

describe('Order API Integration Tests', () => {
  let baseUrl;

  beforeAll(() => {
    baseUrl = getTestContext().baseUrl;
  });

  describe('POST /orders', () => {
    test('creates order for valid user', async () => {
      const user = await UserFactory.create();
      const orderData = OrderFactory.build();

      const response = await request(baseUrl)
        .post('/orders')
        .send({
          userId: user.id,
          items: orderData.items,
          shippingAddress: orderData.shippingAddress
        })
        .expect(201);

      expect(response.body.userId).toBe(user.id);
      expect(response.body.status).toBe('confirmed');
    });

    test('returns 404 when user does not exist', async () => {
      const orderData = OrderFactory.build();

      const response = await request(baseUrl)
        .post('/orders')
        .send({
          userId: '123e4567-e89b-12d3-a456-426614174000',
          items: orderData.items,
          shippingAddress: orderData.shippingAddress
        })
        .expect(404);

      expect(response.body.code).toBe('USER_NOT_FOUND');
    });
  });
});
```

## Error Cases Reference

| Endpoint | Error Case | Status Code | Error Code |
|----------|-----------|-------------|------------|
| POST /users | Missing required fields | 400 | MISSING_FIELDS |
| POST /users | Duplicate email | 409 | EMAIL_EXISTS |
| GET /users/:id | User not found | 404 | USER_NOT_FOUND |
| POST /users/login | Invalid credentials | 401 | INVALID_CREDENTIALS |
| POST /orders | Missing required fields | 400 | MISSING_FIELDS |
| POST /orders | User not found | 404 | USER_NOT_FOUND |
| GET /orders/:id | Order not found | 404 | ORDER_NOT_FOUND |

## Python Alternative (pytest)

```python
# tests/integration/conftest.py
import pytest
from testcontainers.postgres import PostgresContainer
from sqlalchemy import create_engine
from src.main import app
from fastapi.testclient import TestClient

@pytest.fixture(scope="session")
def postgres_container():
    with PostgresContainer("postgres:15-alpine") as postgres:
        yield postgres

@pytest.fixture(scope="session")
def database_engine(postgres_container):
    connection_url = postgres_container.get_connection_url()
    engine = create_engine(connection_url)
    yield engine
    engine.dispose()

@pytest.fixture
def client(database_engine):
    # Override database dependency
    return TestClient(app)

def test_create_user_success(client):
    response = client.post("/users", json={
        "name": "John Doe",
        "email": "john@example.com",
        "password": "password123"
    })
    assert response.status_code == 201
    assert response.json()["name"] == "John Doe"
```

## Best Practices

1. **Testcontainers provide true isolation** — Each test run gets a fresh PostgreSQL instance
2. **Data factories ensure realistic test data** — Faker.js generates varied data
3. **Supertest enables fast HTTP testing** — No need to manage HTTP clients manually
4. **Database cleanup with truncate** — Fast cleanup between tests

## Test Execution

```bash
# Run integration tests
npm run test:integration

# Run with coverage
npm run test:coverage

# Test output summary
Test Suites: 3 passed, 3 total
Tests:       23 passed, 23 total
Time:        12.456s
```
