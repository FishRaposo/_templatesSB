/**
 * File: basic-tests-node.tpl.js
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

# Basic Node.js Testing Template
# Purpose: MVP-level testing template with unit and component tests for Node.js applications
# Usage: Copy to test/ directory and customize for your Node.js project
# Stack: Node.js (.js)
# Tier: MVP (Minimal Viable Product)

## Purpose

MVP-level Node.js testing template providing essential unit and component tests for basic application functionality. Focuses on testing core business logic, utilities, and simple integration points with minimal setup and fast execution.

## Usage

```bash
# Copy to your Node.js project
cp _templates/tiers/mvp/tests/basic-tests-node.tpl.js test/basic.test.js

# Install dependencies
npm install --save-dev jest supertest

# Run tests
npm test

# Run with coverage
npm run test:coverage
```

## Structure

```javascript
// test/basic.test.js
const request = require('supertest');
const app = require('../src/app');
const { Calculator, UserValidator, DataProcessor } = require('../src/services');

/**
 * MVP Node.js Test Suite
 * 
 * This test suite follows the MVP testing philosophy:
 * - Focus on core business logic and essential API functionality
 * - Fast execution with minimal setup and mocking
 * - No complex integration testing or database operations
 * - Educational comments to teach Node.js testing patterns
 * 
 * MVP Testing Approach:
 * - Unit tests for pure business logic and utilities
 * - API tests for basic HTTP endpoints
 * - No database integration tests (added in Core tier)
 * - No performance or security tests (added in Enterprise tier)
 * 
 * Key Node.js Testing Patterns:
 * - Jest: Testing framework for assertions and test structure
 * - Supertest: HTTP assertion library for API testing
 * - Mock functions: Isolate units under test
 * - describe/test blocks: Organize and structure tests
 */

/**
 * Business Logic Tests - Pure Functions and Utilities
 * 
 * These tests verify business logic without HTTP or database dependencies.
 * MVP approach: Test essential functions that drive your app's core value.
 * No complex scenarios, no external dependencies, no async operations.
 */
describe('Business Logic Tests', () => {
  /**
   * Calculator Service Tests
   * 
   * Demonstrates testing pure utility functions and mathematical operations.
   * MVP: Basic arithmetic, no complex calculations or error handling.
   */
  describe('Calculator', () => {
    /**
     * Test basic addition functionality
     * 
     * Simple pure function test to demonstrate Jest syntax.
     * MVP: Basic operations, no error handling or validation.
     */
    test('should add two numbers correctly', () => {
      const result = Calculator.add(2, 3);
      expect(result).toBe(5);
    });

    /**
     * Test basic subtraction functionality
     * 
     * Demonstrates testing subtraction with edge cases.
     * MVP: Basic operations, no floating point precision handling.
     */
    test('should subtract two numbers correctly', () => {
      const result = Calculator.subtract(10, 3);
      expect(result).toBe(7);
    });

    /**
     * Test basic multiplication functionality
     * 
     * Demonstrates testing multiplication operations.
     * MVP: Basic operations, no overflow or precision considerations.
     */
    test('should multiply two numbers correctly', () => {
      const result = Calculator.multiply(4, 5);
      expect(result).toBe(20);
    });

    test('should divide two numbers correctly', () => {
      const result = Calculator.divide(20, 4);
      expect(result).toBe(5);
    });

    test('should throw error when dividing by zero', () => {
      expect(() => Calculator.divide(10, 0)).toThrow('Cannot divide by zero');
    });
  });

  describe('UserValidator', () => {
    test('should validate correct email format', () => {
      expect(UserValidator.isValidEmail('test@example.com')).toBe(true);
    });

    test('should reject invalid email formats', () => {
      const invalidEmails = ['test@', '@example.com', 'test.example.com', ''];
      invalidEmails.forEach(email => {
        expect(UserValidator.isValidEmail(email)).toBe(false);
      });
    });

    test('should validate strong password', () => {
      expect(UserValidator.isValidPassword('SecurePass123!')).toBe(true);
    });

    test('should reject weak passwords', () => {
      const weakPasswords = ['123', 'password', 'Pass', ''];
      weakPasswords.forEach(password => {
        expect(UserValidator.isValidPassword(password)).toBe(false);
      });
    });

    test('should validate user age correctly', () => {
      expect(UserValidator.isValidAge(25)).toBe(true);
      expect(UserValidator.isValidAge(17)).toBe(false);
      expect(UserValidator.isValidAge(150)).toBe(false);
    });
  });
});

describe('Data Processing Tests', () => {
  describe('DataProcessor', () => {
    test('should process empty list correctly', () => {
      const processor = new DataProcessor();
      const result = processor.processList([]);
      expect(result).toEqual([]);
    });

    test('should process numeric list correctly', () => {
      const processor = new DataProcessor();
      const data = [1, 2, 3, 4, 5];
      const result = processor.processList(data);
      expect(result).toEqual([2, 4, 6, 8, 10]); // Assuming doubling logic
    });

    test('should process string list correctly', () => {
      const processor = new DataProcessor();
      const data = ['hello', 'world'];
      const result = processor.processList(data);
      expect(result).toEqual(['HELLO', 'WORLD']); // Assuming uppercase logic
    });

    test('should filter valid data correctly', () => {
      const processor = new DataProcessor();
      const data = [1, null, 3, '', 5, 0];
      const result = processor.filterValidData(data);
      expect(result).toEqual([1, 3, 5]);
    });
  });
});

describe('Utility Function Tests', () => {
  test('should format dates correctly', () => {
    const { formatDate } = require('../src/utils/dateUtils');
    const testDate = new Date('2023-12-25');
    const result = formatDate(testDate);
    expect(result).toBe('2023-12-25');
  });

  test('should capitalize words correctly', () => {
    const { capitalizeWords } = require('../src/utils/stringUtils');
    expect(capitalizeWords('hello world')).toBe('Hello World');
  });

  test('should clean whitespace correctly', () => {
    const { cleanWhitespace } = require('../src/utils/stringUtils');
    expect(cleanWhitespace('  hello   world  ')).toBe('hello world');
  });

  test('should validate file paths correctly', () => {
    const { validateFilePath } = require('../src/utils/fileUtils');
    expect(validateFilePath('/valid/path/file.txt')).toBe(true);
    expect(validateFilePath('')).toBe(false);
  });
});

describe('API Endpoint Tests', () => {
  test('GET /api/health should return status OK', async () => {
    const response = await request(app)
      .get('/api/health')
      .expect(200);

    expect(response.body.status).toBe('OK');
    expect(response.body.timestamp).toBeDefined();
  });

  test('POST /api/users should create new user', async () => {
    const userData = {
      name: 'Test User',
      email: 'test@example.com',
      age: 25
    };

    const response = await request(app)
      .post('/api/users')
      .send(userData)
      .expect(201);

    expect(response.body.name).toBe(userData.name);
    expect(response.body.email).toBe(userData.email);
    expect(response.body.id).toBeDefined();
  });

  test('POST /api/users should reject invalid data', async () => {
    const invalidUserData = {
      name: '',
      email: 'invalid-email',
      age: 15
    };

    const response = await request(app)
      .post('/api/users')
      .send(invalidUserData)
      .expect(400);

    expect(response.body.error).toBeDefined();
  });
});

describe('Integration Tests', () => {
  test('should handle user creation and retrieval', async () => {
    // Create user
    const userData = {
      name: 'Integration User',
      email: 'integration@example.com',
      age: 30
    };

    const createResponse = await request(app)
      .post('/api/users')
      .send(userData)
      .expect(201);

    const userId = createResponse.body.id;

    // Retrieve user
    const getResponse = await request(app)
      .get(`/api/users/${userId}`)
      .expect(200);

    expect(getResponse.body.name).toBe(userData.name);
    expect(getResponse.body.email).toBe(userData.email);
  });

  test('should handle data processing workflow', async () => {
    const processor = new DataProcessor();
    const inputData = [1, 2, 3, 4, 5];

    // Process data
    const processedData = processor.processList(inputData);
    expect(processedData).toEqual([2, 4, 6, 8, 10]);

    // Filter data
    const filteredData = processor.filterValidData([1, null, 3, '', 5]);
    expect(filteredData).toEqual([1, 3, 5]);
  });
});

// Test Helpers and Utilities
class TestHelpers {
  static createMockUser(overrides = {}) {
    const defaultUser = {
      id: 1,
      name: 'Test User',
      email: 'test@example.com',
      age: 25,
      active: true,
      createdAt: new Date()
    };
    return { ...defaultUser, ...overrides };
  }

  static createMockProduct(overrides = {}) {
    const defaultProduct = {
      id: 1,
      name: 'Test Product',
      price: 10.99,
      inStock: true,
      category: 'electronics'
    };
    return { ...defaultProduct, ...overrides };
  }

  static createMockOrder(userId, products = null) {
    if (!products) {
      products = [this.createMockProduct()];
    }
    return {
      id: 1,
      userId,
      products,
      total: products.reduce((sum, p) => sum + p.price, 0),
      status: 'pending',
      createdAt: new Date()
    };
  }

  static async setupTestDatabase() {
    // Setup in-memory database for testing
    // This would typically use an in-memory SQLite or test database
    return {
      connect: () => Promise.resolve(),
      disconnect: () => Promise.resolve(),
      clear: () => Promise.resolve()
    };
  }

  static async cleanupTestDatabase(db) {
    await db.clear();
    await db.disconnect();
  }
}

// Custom Matchers
expect.extend({
  toBeValidUser(received) {
    const requiredFields = ['id', 'name', 'email', 'age'];
    const missingFields = requiredFields.filter(field => !(field in received));
    
    if (missingFields.length > 0) {
      return {
        message: () => `User is missing required fields: ${missingFields.join(', ')}`,
        pass: false
      };
    }

    if (typeof received.age !== 'number' || received.age < 18 || received.age > 120) {
      return {
        message: () => `User age must be a number between 18 and 120`,
        pass: false
      };
    }

    return {
      message: () => `User is valid`,
      pass: true
    };
  },

  toBeValidApiResponse(received) {
    if (!received.status || !received.data) {
      return {
        message: () => `API response must have status and data fields`,
        pass: false
      };
    }

    if (!['success', 'error'].includes(received.status)) {
      return {
        message: () => `API status must be 'success' or 'error'`,
        pass: false
      };
    }

    return {
      message: () => `API response is valid`,
      pass: true
    };
  }
});

// Test Configuration
const testConfig = {
  timeout: 5000,
  retries: 3,
  testDatabaseUrl: 'sqlite::memory:',
  testApiBaseUrl: 'http://localhost:3000/api'
};

// Test Fixtures
const testFixtures = {
  validUser: TestHelpers.createMockUser(),
  invalidUser: {
    name: '',
    email: 'invalid-email',
    age: 15
  },
  sampleProducts: [
    TestHelpers.createMockProduct({ id: 1, name: 'Product 1', price: 10.99 }),
    TestHelpers.createMockProduct({ id: 2, name: 'Product 2', price: 20.50 }),
    TestHelpers.createMockProduct({ id: 3, name: 'Product 3', price: 15.75 })
  ]
};

// Export for use in other test files
module.exports = {
  TestHelpers,
  testConfig,
  testFixtures
};

// Run tests if this file is executed directly
if (require.main === module) {
  console.log('Running basic tests...');
  // Tests will be run by Jest automatically
}
```

## Guidelines

### Test Organization
- **Unit Tests**: Test individual functions and classes in isolation
- **Integration Tests**: Test API endpoints and component interactions
- **Fixtures**: Use reusable test data and helpers
- **Keep Tests Fast**: MVP tests should run in under 30 seconds

### Test Structure
- Use `describe()` blocks to group related tests
- Use descriptive test names with `test()`
- Use `expect()` for assertions
- Test both success and error cases

### API Testing Best Practices
- Use `supertest` for HTTP endpoint testing
- Test status codes and response bodies
- Test validation and error handling
- Use async/await for asynchronous tests

### Coverage Requirements
- **Unit Tests**: 80%+ coverage for business logic
- **Integration Tests**: 60%+ coverage for API endpoints
- **Overall**: 75%+ minimum for MVP

## Required Dependencies

Add to `package.json`:

```json
{
  "devDependencies": {
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "nodemon": "^3.0.1"
  },
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage"
  }
}
```

## What's Included

- **Unit Tests**: Business logic, utilities, data validation
- **Integration Tests**: API endpoints and component interactions
- **Test Helpers**: Mock data factories and utilities
- **Custom Matchers**: Domain-specific assertions
- **Fixtures**: Reusable test data setup

## What's NOT Included

- Database integration tests with real databases
- Performance and load tests
- Authentication/authorization tests
- Third-party service integration tests

---

**Template Version**: 1.0 (MVP)  
**Last Updated**: 2025-12-10  
**Stack**: Node.js  
**Tier**: MVP  
**Framework**: Jest + Supertest
