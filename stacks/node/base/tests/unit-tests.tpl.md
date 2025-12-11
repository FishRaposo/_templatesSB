// Node.js Unit Testing Template
// Comprehensive unit testing patterns for Node.js projects with Jest

/**
 * Node.js Unit Test Patterns
 * Adapted from Python/Go patterns to Node.js/Jest
 */

const { describe, it, expect, beforeEach, afterEach, jest } = require('@jest/globals');

// ====================
// BASIC UNIT TEST PATTERNS
// ====================

describe('Basic Function Tests', () => {
  
  test('square function with positive numbers', () => {
    const result = square(5);
    expect(result).toBe(25);
  });
  
  test('square function with zero', () => {
    const result = square(0);
    expect(result).toBe(0);
  });
  
  test('square function with negative numbers', () => {
    const result = square(-3);
    expect(result).toBe(9);
  });
  
  test('square function with large numbers', () => {
    const result = square(100);
    expect(result).toBe(10000);
  });
});

describe('Table-Driven Tests', () => {
  test.each([
    ['regular customer', 'regular', 100.0, 0.0],
    ['premium customer small purchase', 'premium', 50.0, 2.5],
    ['premium customer large purchase', 'premium', 200.0, 20.0],
    ['vip customer', 'vip', 100.0, 15.0],
    ['vip customer large purchase', 'vip', 1000.0, 150.0],
  ])('calculate discount: %s', (description, customerType, amount, expected) => {
    const discount = calculateDiscount(customerType, amount);
    expect(Math.abs(discount - expected)).toBeLessThan(0.01);
  });
});

// ====================
// MOCK TESTING PATTERNS
// ====================

describe('Mock Testing Patterns', () => {
  
  test('service with mock repository', () => {
    // Create mock repository
    const mockRepository = {
      getUser: jest.fn(),
      saveUser: jest.fn()
    };
    
    // Setup expectations
    const expectedUser = {
      id: 1,
      name: 'John Doe',
      email: 'john@example.com'
    };
    mockRepository.getUser.mockResolvedValue(expectedUser);
    mockRepository.saveUser.mockResolvedValue(null);
    
    // Create service with mock
    const service = new UserService(mockRepository);
    
    // Execute and assert
    return service.getUser(1).then(user => {
      expect(user).toEqual(expectedUser);
      expect(mockRepository.getUser).toHaveBeenCalledWith(1);
      expect(mockRepository.saveUser).not.toHaveBeenCalled();
    });
  });
  
  test('API call with mock axios', async () => {
    // Mock axios
    const mockAxios = {
      get: jest.fn()
    };
    
    // Setup mock response
    mockAxios.get.mockResolvedValue({
      data: { id: 1, name: 'John Doe' },
      status: 200
    });
    
    // Execute
    const result = await fetchUserAPI(mockAxios, 1);
    
    // Assert
    expect(result.name).toBe('John Doe');
    expect(mockAxios.get).toHaveBeenCalledWith('/api/users/1');
  });
  
  test('database with mock connection', () => {
    const mockConnection = {
      query: jest.fn(),
      execute: jest.fn()
    };
    
    const mockUser = { id: 1, name: 'John', email: 'john@example.com' };
    mockConnection.query.mockReturnValue([[mockUser]]);
    
    const repository = new UserRepository(mockConnection);
    const user = repository.findById(1);
    
    expect(user).toEqual(mockUser);
    expect(mockConnection.query).toHaveBeenCalledWith('SELECT * FROM users WHERE id = ?', [1]);
  });
});

// ====================
// ASYNC TEST PATTERNS
// ====================

describe('Async Function Tests', () => {
  
  test('async API call', async () => {
    const result = await fetchUserAsync(1);
    expect(result.id).toBe(1);
    expect(result.name).toBeDefined();
  });
  
  test('async database query', async () => {
    const mockDb = {
      query: jest.fn().mockResolvedValue([[{ id: 1, name: 'John' }]])
    };
    
    const users = await mockDb.query('SELECT * FROM users WHERE id = ?', [1]);
    expect(users[0][0].name).toBe('John');
  });
  
  test('async with mock', async () => {
    const mockAxios = {
      get: jest.fn().mockResolvedValue({
        data: { id: 1, name: 'John' },
        status: 200
      })
    };
    
    const result = await asyncAPICall(mockAxios, 'https://api.example.com/users/1');
    expect(result.name).toBe('John');
  });
});

// ====================
// DATABASE TESTING PATTERNS
// ====================

describe('Database Operation Tests', () => {
  
  let mockDb;
  
  beforeEach(() => {
    mockDb = {
      query: jest.fn(),
      execute: jest.fn(),
      beginTransaction: jest.fn(),
      commit: jest.fn(),
      rollback: jest.fn()
    };
  });
  
  test('user repository create', async () => {
    const userRepository = new UserRepository(mockDb);
    
    const newUser = {
      name: 'Jane Doe',
      email: 'jane@example.com',
      passwordHash: 'hashed_password'
    };
    
    mockDb.execute.mockResolvedValue({ insertId: 1 });
    
    const createdUser = await userRepository.create(newUser);
    
    expect(createdUser.id).toBe(1);
    expect(createdUser.email).toBe('jane@example.com');
    expect(mockDb.execute).toHaveBeenCalledWith(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      ['Jane Doe', 'jane@example.com', 'hashed_password']
    );
  });
  
  test('user repository find by email', async () => {
    const userRepository = new UserRepository(mockDb);
    
    const mockUser = { id: 1, name: 'John', email: 'john@example.com' };
    mockDb.query.mockResolvedValue([[mockUser]]);
    
    const found = await userRepository.findByEmail('john@example.com');
    
    expect(found).toEqual(mockUser);
    expect(mockDb.query).toHaveBeenCalledWith(
      'SELECT * FROM users WHERE email = ?',
      ['john@example.com']
    );
  });
  
  test('user not found', async () => {
    const userRepository = new UserRepository(mockDb);
    
    mockDb.query.mockResolvedValue([[]]);
    
    const found = await userRepository.findByEmail('nonexistent@example.com');
    
    expect(found).toBeNull();
  });
  
  test('database transaction rollback', async () => {
    const transaction = {
      begin: jest.fn(),
      commit: jest.fn(),
      rollback: jest.fn()
    };
    
    mockDb.beginTransaction.mockResolvedValue(transaction);
    transaction.commit.mockRejectedValue(new Error('Constraint violation'));
    
    try {
      await mockDb.beginTransaction();
      await transaction.commit();
    } catch (error) {
      await transaction.rollback();
    }
    
    expect(transaction.rollback).toHaveBeenCalled();
  });
});

// ====================
// API ENDPOINT TESTING
// ====================

const request = require('supertest');

describe('API Endpoint Tests', () => {
  
  let app;
  
  beforeEach(() => {
    app = require('./app'); // Your Express/Fastify app
  });
  
  test('POST /api/v1/users creates user', async () => {
    const newUser = {
      name: 'Alice Smith',
      email: 'alice@example.com',
      password: 'SecurePass123!'
    };
    
    const response = await request(app)
      .post('/api/v1/users')
      .send(newUser)
      .expect(201);
    
    expect(response.body.id).toBeDefined();
    expect(response.body.email).toBe('alice@example.com');
    expect(response.body.password).toBeUndefined(); // Should not return password
  });
  
  test('GET /api/v1/users/:id returns user', async () => {
    const response = await request(app)
      .get('/api/v1/users/1')
      .expect(200);
    
    expect(response.body.id).toBe(1);
    expect(response.body.name).toBeDefined();
  });
  
  test('PUT /api/v1/users/:id updates user', async () => {
    const updates = { name: 'Updated Name' };
    
    const response = await request(app)
      .put('/api/v1/users/1')
      .send(updates)
      .expect(200);
    
    expect(response.body.name).toBe('Updated Name');
  });
  
  test('DELETE /api/v1/users/:id removes user', async () => {
    await request(app)
      .delete('/api/v1/users/1')
      .expect(204);
    
    // Verify user is deleted
    await request(app)
      .get('/api/v1/users/1')
      .expect(404);
  });
  
  test('GET /api/v1/users with pagination', async () => {
    const response = await request(app)
      .get('/api/v1/users?page=1&limit=10')
      .expect(200);
    
    expect(response.body.items).toBeDefined();
    expect(response.body.total).toBeDefined();
    expect(response.body.page).toBe(1);
    expect(response.body.items.length).toBeLessThanOrEqual(10);
  });
  
  test('POST /api/v1/users validates email format', async () => {
    const invalidUser = {
      name: 'Test User',
      email: 'invalid-email',
      password: 'password123'
    };
    
    const response = await request(app)
      .post('/api/v1/users')
      .send(invalidUser)
      .expect(400);
    
    expect(response.body.errors).toBeDefined();
    expect(response.body.errors).toContainEqual(
      expect.objectContaining({
        field: 'email'
      })
    );
  });
});

// ====================
// ERROR HANDLING TESTS
// ====================

describe('Error Handling Tests', () => {
  
  test('custom error is thrown correctly', () => {
    class UserNotFoundError extends Error {
      constructor(userId) {
        super(`User ${userId} not found`);
        this.name = 'UserNotFoundError';
        this.statusCode = 404;
      }
    }
    
    expect(() => {
      throw new UserNotFoundError(999);
    }).toThrow(UserNotFoundError);
    
    expect(() => {
      throw new UserNotFoundError(999);
    }).toThrow('User 999 not found');
  });
  
  test('HTTP error handling', async () => {
    const mockAxios = {
      get: jest.fn().mockRejectedValue({
        response: { status: 404, data: 'Not Found' },
        message: 'Request failed'
      })
    };
    
    await expect(asyncFetchUser(mockAxios, 999))
      .rejects.toThrow(HTTPException);
  });
  
  test('validation errors', () => {
    const validationError = new ValidationError([
      { field: 'email', message: 'Invalid email format' },
      { field: 'password', message: 'Password too short' }
    ]);
    
    expect(validationError.errors).toHaveLength(2);
    expect(validationError.errors[0].field).toBe('email');
  });
});

// ====================
// CUSTOM MATCHERS AND UTILITIES
// ====================

expect.extend({
  toBeValidUser(received) {
    const pass = received &&
      typeof received.id === 'number' &&
      typeof received.email === 'string' &&
      received.email.includes('@') &&
      !received.password;
    
    if (pass) {
      return {
        message: () => `expected user to be invalid`,
        pass: true
      };
    } else {
      return {
        message: () => `expected user to be valid`,
        pass: false
      };
    }
  }
});

describe('Custom Matchers', () => {
  test('valid user object', () => {
    const user = {
      id: 1,
      name: 'John Doe',
      email: 'john@example.com'
    };
    
    expect(user).toBeValidUser();
  });
});

// ====================
// PERFORMANCE BENCHMARKS
// ====================

describe('Performance Tests', () => {
  
  test('expensive operation completes quickly', () => {
    const startTime = Date.now();
    
    // Code to test
    const result = expensiveOperation(1000);
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    expect(duration).toBeLessThan(1000); // Should complete in less than 1 second
    expect(result).toBeDefined();
  });
  
  test('sorting large array', () => {
    const largeArray = Array.from({ length: 10000 }, () => Math.random());
    
    const startTime = Date.now();
    largeArray.sort();
    const duration = Date.now() - startTime;
    
    expect(duration).toBeLessThan(100);
  });
});

// ====================
// HELPER FUNCTIONS
// ====================

function createTestUser(overrides = {}) {
  return {
    name: 'Test User',
    email: 'test@example.com',
    password: 'TestPass123!',
    ...overrides
  };
}

// ====================
// CODE COVERAGE
// ====================

/*
 * Run tests with coverage:
 * npm test -- --coverage
 * 
 * Coverage report location:
 * coverage/lcov-report/index.html
 * 
 * Jest coverage configuration in package.json:
 * "jest": {
 *   "collectCoverageFrom": [
 *     "src/**/*.{js,jsx,ts,tsx}",
 *     "!src/**/*.d.ts",
 *     "!src/**/*.test.{js,jsx,ts,tsx}"
 *   ],
 *   "coverageThreshold": {
 *     "global": {
 *       "branches": 80,
 *       "functions": 80,
 *       "lines": 80,
 *       "statements": 80
 *     }
 *   }
 * }
 */

// ====================
// MEMORY LEAK TESTS
// ====================

describe('Memory Leak Tests', () => {
  
  test('no memory leaks in event emitter', () => {
    const { EventEmitter } = require('events');
    const emitter = new EventEmitter();
    
    // Add listeners
    for (let i = 0; i < 100; i++) {
      emitter.on('test', () => {});
    }
    
    expect(emitter.listenerCount('test')).toBe(100);
    
    // Remove all listeners
    emitter.removeAllListeners('test');
    
    expect(emitter.listenerCount('test')).toBe(0);
  });
});

// ====================
// RUN TESTS
// ====================

/*
Commands to run tests:

# Run all tests
npm test

# Run specific test file
npm test -- tests/unit/test_simple_functions.js

# Run specific test suite
npm test -- tests/unit/test_simple_functions.js --testNamePattern="Basic Function Tests"

# Run with coverage
npm test -- --coverage

# Run in watch mode
npm test -- --watch

# Run in watch mode for specific file
npm test -- tests/unit/test_simple_functions.js --watch

# Run with verbose output
npm test -- --verbose

# Run only tests matching pattern
npm test -- --testNamePattern="calculat"

# Run tests in parallel (default for Jest)
npm test

# Run tests sequentially
npm test -- --runInBand

# Run with time limits
npm test -- --testTimeout=10000

# Generate coverage report in different formats
npm test -- --coverage --coverageReporters=text,html,lcov

# Debug a test
node --inspect-brk node_modules/.bin/jest --runInBand

# Run tests and update snapshots if needed
npm test -- -u

# Clear Jest cache
npm test -- --clearCache

# Run performance tests
npm test -- --logHeapUsage
*/
