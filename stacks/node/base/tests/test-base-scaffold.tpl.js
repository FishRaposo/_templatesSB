/**
 * Template: test-base-scaffold.tpl.js
 * Purpose: test-base-scaffold template
 * Stack: node
 * Tier: base
 */

# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: node
# Category: testing

// -----------------------------------------------------------------------------
// FILE: test-base-scaffold.tpl.js
// PURPOSE: Foundational testing patterns and utilities for Node.js projects
// USAGE: Import and extend for consistent testing structure across the application
// DEPENDENCIES: assert, sinon, fs, path for testing framework and file operations
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * Node.js Base Test Scaffold Template
 * Purpose: Foundational testing patterns and utilities for Node.js projects
 * Usage: Import and extend for consistent testing structure across the application
 */

const assert = require('assert');
const sinon = require('sinon');
const fs = require('fs').promises;
const path = require('path');
const { EventEmitter } = require('events');

/**
 * Base test class with common utilities for Node.js testing
 */
class BaseTestCase {
  constructor() {
    this.stubs = {};
    this.mocks = {};
    this.testData = {};
    this.tempDir = null;
  }

  /**
   * Sets up the test environment before each test
   */
  async setUp() {
    // Create temporary directory
    this.tempDir = await this.createTempDirectory();
    
    // Clear all stubs and mocks
    sinon.restore();
    this.stubs = {};
    this.mocks = {};
    
    // Reset test data
    this.testData = {};
    
    // Setup default mocks
    this.setupDefaultMocks();
  }

  /**
   * Tears down the test environment after each test
   */
  async tearDown() {
    // Restore all stubs
    sinon.restore();
    
    // Clean up temporary directory
    if (this.tempDir) {
      await this.cleanupTempDirectory(this.tempDir);
    }
  }

  /**
   * Sets up default mocks
   */
  setupDefaultMocks() {
    // Mock console methods
    this.mocks.console = {
      log: sinon.stub(console, 'log'),
      error: sinon.stub(console, 'error'),
      warn: sinon.stub(console, 'warn'),
      info: sinon.stub(console, 'info'),
    };
  }

  /**
   * Creates a temporary directory
   */
  async createTempDirectory() {
    const tempDir = path.join(__dirname, 'temp', Date.now().toString());
    await fs.mkdir(tempDir, { recursive: true });
    return tempDir;
  }

  /**
   * Cleans up temporary directory
   */
  async cleanupTempDirectory(dir) {
    try {
      await fs.rmdir(dir, { recursive: true });
    } catch (error) {
      // Ignore cleanup errors
    }
  }

  /**
   * Creates a temporary file with content
   */
  async createTempFile(filename, content) {
    const filePath = path.join(this.tempDir, filename);
    await fs.writeFile(filePath, content, 'utf8');
    return filePath;
  }

  /**
   * Creates mock data for testing
   */
  createMockData(dataType, overrides = {}) {
    switch (dataType) {
      case 'user':
        return this.createMockUser(overrides);
      case 'post':
        return this.createMockPost(overrides);
      case 'config':
        return this.createMockConfig(overrides);
      case 'request':
        return this.createMockRequest(overrides);
      case 'response':
        return this.createMockResponse(overrides);
      default:
        throw new Error(`Unknown data type: ${dataType}`);
    }
  }

  /**
   * Creates mock user data
   */
  createMockUser(overrides = {}) {
    return {
      id: 1,
      username: 'testuser',
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'User',
      isActive: true,
      avatar: 'https://example.com/avatar.jpg',
      phone: '+1234567890',
      createdAt: new Date(),
      updatedAt: new Date(),
      roles: ['user'],
      ...overrides,
    };
  }

  /**
   * Creates mock post data
   */
  createMockPost(overrides = {}) {
    return {
      id: 1,
      title: 'Test Post',
      content: 'This is test content',
      authorId: 1,
      published: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      tags: ['test', 'mock'],
      likes: 0,
      comments: [],
      category: 'general',
      ...overrides,
    };
  }

  /**
   * Creates mock configuration data
   */
  createMockConfig(overrides = {}) {
    return {
      port: 3000,
      host: 'localhost',
      database: {
        host: 'localhost',
        port: 5432,
        name: 'test_db',
        user: 'test_user',
        password: 'test_password',
      },
      redis: {
        host: 'localhost',
        port: 6379,
        db: 0,
      },
      jwt: {
        secret: 'test-secret',
        expiresIn: '1h',
      },
      cors: {
        origin: '*',
        credentials: true,
      },
      debug: true,
      ...overrides,
    };
  }

  /**
   * Creates mock HTTP request
   */
  createMockRequest(overrides = {}) {
    const mockRequest = {
      method: 'GET',
      url: '/test',
      headers: {},
      query: {},
      params: {},
      body: {},
      user: null,
      session: {},
      cookies: {},
      ip: '127.0.0.1',
      protocol: 'http',
      secure: false,
      xhr: false,
      ...overrides,
    };

    return mockRequest;
  }

  /**
   * Creates mock HTTP response
   */
  createMockResponse(overrides = {}) {
    const mockResponse = {
      statusCode: 200,
      headers: {},
      body: null,
      locals: {},
      _headers: {},
      _data: null,
      
      status: sinon.stub().callsFake(function(code) {
        this.statusCode = code;
        return this;
      }),
      
      json: sinon.stub().callsFake(function(data) {
        this.body = data;
        this._data = JSON.stringify(data);
        this.headers['Content-Type'] = 'application/json';
        return this;
      }),
      
      send: sinon.stub().callsFake(function(data) {
        this.body = data;
        this._data = typeof data === 'string' ? data : JSON.stringify(data);
        return this;
      }),
      
      end: sinon.stub().callsFake(function(data) {
        if (data) {
          this._data = data;
        }
        return this;
      }),
      
      set: sinon.stub().callsFake(function(name, value) {
        this.headers[name] = value;
        this._headers[name] = value;
        return this;
      }),
      
      get: sinon.stub().callsFake(function(name) {
        return this.headers[name];
      }),
      
      ...overrides,
    };

    return mockResponse;
  }

  /**
   * Stubs a method on an object
   */
  stubMethod(object, method, replacement) {
    const stub = sinon.stub(object, method);
    if (replacement) {
      stub.callsFake(replacement);
    }
    this.stubs[`${object.constructor.name}.${method}`] = stub;
    return stub;
  }

  /**
   * Creates a mock function
   */
  createMockFunction(implementation) {
    const mock = sinon.stub();
    if (implementation) {
      mock.callsFake(implementation);
    }
    return mock;
  }

  /**
   * Creates a mock object with specific methods
   */
  createMockObject(methods = {}) {
    const mock = {};
    Object.keys(methods).forEach(methodName => {
      mock[methodName] = this.createMockFunction(methods[methodName]);
    });
    return mock;
  }

  /**
   * Asserts that a stub was called
   */
  assertCalled(stub) {
    assert(stub.called, 'Expected stub to be called');
  }

  /**
   * Asserts that a stub was called with specific arguments
   */
  assertCalledWith(stub, ...args) {
    assert(stub.calledWith(...args), `Expected stub to be called with ${args}`);
  }

  /**
   * Asserts that a stub was called a specific number of times
   */
  assertCallCount(stub, count) {
    assert.strictEqual(stub.callCount, count, `Expected stub to be called ${count} times`);
  }

  /**
   * Asserts that two objects are deep equal
   */
  assertDeepEqual(actual, expected) {
    assert.deepStrictEqual(actual, expected);
  }

  /**
   * Asserts that two objects are not deep equal
   */
  assertNotDeepEqual(actual, expected) {
    assert.notDeepStrictEqual(actual, expected);
  }

  /**
   * Asserts that a promise rejects
   */
  async assertRejects(promise, expectedError) {
    try {
      await promise;
      assert.fail('Expected promise to reject');
    } catch (error) {
      if (expectedError) {
        if (typeof expectedError === 'string') {
          assert.strictEqual(error.message, expectedError);
        } else if (expectedError instanceof Error) {
          assert.strictEqual(error.constructor.name, expectedError.constructor.name);
        } else {
          assert.deepStrictEqual(error, expectedError);
        }
      }
    }
  }

  /**
   * Waits for a specified amount of time
   */
  async wait(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Waits for a condition to be true
   */
  async waitFor(condition, timeout = 5000) {
    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
      if (await condition()) {
        return;
      }
      await this.wait(10);
    }
    throw new Error(`Condition not met within ${timeout}ms`);
  }
}

/**
 * HTTP test utilities for Node.js HTTP testing
 */
class HttpTestUtils {
  /**
   * Creates a mock HTTP server
   */
  static createMockServer() {
    const EventEmitter = require('events');
    const server = new EventEmitter();
    
    server.listen = sinon.stub().callsFake((port, callback) => {
      if (callback) callback();
      server.emit('listening');
      return server;
    });
    
    server.close = sinon.stub().callsFake((callback) => {
      if (callback) callback();
      server.emit('close');
      return server;
    });
    
    server.address = sinon.stub().returns({ port: 3000, address: '127.0.0.1' });
    
    return server;
  }

  /**
   * Creates a mock HTTP request
   */
  static createMockRequest(overrides = {}) {
    const request = new EventEmitter();
    
    Object.assign(request, {
      method: 'GET',
      url: '/test',
      headers: {},
      httpVersion: '1.1',
      trailers: {},
      rawHeaders: [],
      rawTrailers: [],
      setTimeout: sinon.stub(),
      aborted: false,
      complete: false,
      ...overrides,
    });
    
    return request;
  }

  /**
   * Creates a mock HTTP response
   */
  static createMockResponse() {
    const response = new EventEmitter();
    
    Object.assign(response, {
      statusCode: 200,
      headers: {},
      sendDate: true,
      finished: false,
      
      writeHead: sinon.stub(),
      write: sinon.stub(),
      end: sinon.stub().callsFake(function(data) {
        this.finished = true;
        this.emit('finish');
      }),
      
      setHeader: sinon.stub(),
      getHeader: sinon.stub(),
      removeHeader: sinon.stub(),
      addTrailers: sinon.stub(),
      
      destroy: sinon.stub(),
    });
    
    return response;
  }

  /**
   * Mocks Express app
   */
  static createMockExpressApp() {
    const app = {
      get: sinon.stub(),
      post: sinon.stub(),
      put: sinon.stub(),
      delete: sinon.stub(),
      patch: sinon.stub(),
      use: sinon.stub(),
      listen: sinon.stub().returns({
        close: sinon.stub(),
      }),
    };
    
    return app;
  }

  /**
   * Mocks Express router
   */
  static createMockExpressRouter() {
    const router = {
      get: sinon.stub(),
      post: sinon.stub(),
      put: sinon.stub(),
      delete: sinon.stub(),
      patch: sinon.stub(),
      use: sinon.stub(),
      param: sinon.stub(),
    };
    
    return router;
  }
}

/**
 * Database test utilities
 */
class DatabaseTestUtils {
  /**
   * Creates a mock database connection
   */
  static createMockDatabase() {
    const db = {
      connect: sinon.stub().resolves(),
      disconnect: sinon.stub().resolves(),
      query: sinon.stub().resolves({ rows: [] }),
      transaction: sinon.stub().resolves(),
      
      // PostgreSQL-specific
      client: {
        query: sinon.stub().resolves({ rows: [] }),
        release: sinon.stub(),
      },
      
      // MySQL-specific
      execute: sinon.stub().resolves([[]]),
      beginTransaction: sinon.stub().resolves(),
      commit: sinon.stub().resolves(),
      rollback: sinon.stub().resolves(),
    };
    
    return db;
  }

  /**
   * Creates mock query result
   */
  static createMockQueryResult(rows = [], rowCount = rows.length) {
    return {
      rows,
      rowCount,
      command: 'SELECT',
    };
  }

  /**
   * Creates mock database rows
   */
  static createMockRows(count, data = {}) {
    const rows = [];
    for (let i = 0; i < count; i++) {
      rows.push({
        id: i + 1,
        created_at: new Date(),
        updated_at: new Date(),
        ...data,
      });
    }
    return rows;
  }
}

/**
 * File system test utilities
 */
class FileSystemTestUtils {
  /**
   * Creates mock file system
   */
  static createMockFileSystem() {
    const mockFs = {
      readFile: sinon.stub(),
      writeFile: sinon.stub(),
      exists: sinon.stub(),
      mkdir: sinon.stub(),
      rmdir: sinon.stub(),
      readdir: sinon.stub(),
      stat: sinon.stub(),
      unlink: sinon.stub(),
    };
    
    return mockFs;
  }

  /**
   * Sets up file system stubs with temporary directory
   */
  static async setupFileSystemStubs(tempDir, files = {}) {
    const stubs = {};
    
    // Create actual files
    for (const [filename, content] of Object.entries(files)) {
      const filePath = path.join(tempDir, filename);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, content, 'utf8');
    }
    
    // Stub fs methods
    stubs.readFile = sinon.stub(fs, 'readFile').callsFake((filePath) => {
      return fs.readFile(filePath, 'utf8');
    });
    
    stubs.writeFile = sinon.stub(fs, 'writeFile').callsFake((filePath, content) => {
      return fs.writeFile(filePath, content, 'utf8');
    });
    
    stubs.exists = sinon.stub(fs, 'exists').callsFake((filePath) => {
      return fs.access(filePath).then(() => true).catch(() => false);
    });
    
    return stubs;
  }
}

/**
 * Logger test utilities
 */
class LoggerTestUtils {
  /**
   * Creates a mock logger
   */
  static createMockLogger() {
    const logger = {
      info: sinon.stub(),
      error: sinon.stub(),
      warn: sinon.stub(),
      debug: sinon.stub(),
      verbose: sinon.stub(),
      silly: sinon.stub(),
      
      // Winston-specific
      log: sinon.stub(),
      level: 'info',
      isLevelEnabled: sinon.stub().returns(true),
      
      // Bunyan-specific
      child: sinon.stub().returnsThis(),
    };
    
    return logger;
  }

  /**
   * Asserts log message was called
   */
  static assertLogCalled(logger, level, message) {
    assert(logger[level].calledWith(message), 
      `Expected ${level} to be called with "${message}"`);
  }

  /**
   * Asserts log message was called with specific data
   */
  static assertLogCalledWith(logger, level, message, data) {
    assert(logger[level].calledWith(message, data), 
      `Expected ${level} to be called with "${message}" and data`);
  }
}

/**
 * Performance test utilities
 */
class PerformanceTestUtils {
  /**
   * Measures execution time of a function
   */
  static async measureExecutionTime(fn) {
    const startTime = process.hrtime.bigint();
    const result = await fn();
    const endTime = process.hrtime.bigint();
    const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
    
    return { result, duration };
  }

  /**
   * Measures memory usage before and after function execution
   */
  static async measureMemoryUsage(fn) {
    const before = process.memoryUsage();
    const result = await fn();
    const after = process.memoryUsage();
    
    return {
      result,
      before,
      after,
      delta: {
        rss: after.rss - before.rss,
        heapUsed: after.heapUsed - before.heapUsed,
        heapTotal: after.heapTotal - before.heapTotal,
      },
    };
  }

  /**
   * Asserts performance threshold
   */
  static assertPerformanceThreshold(actual, threshold, metric) {
    assert(actual <= threshold, 
      `${metric} (${actual}ms) exceeds threshold (${threshold}ms)`);
  }
}

/**
 * Integration test utilities
 */
class IntegrationTestUtils {
  /**
   * Sets up integration test environment
   */
  static async setupIntegrationTest() {
    // Set test environment variables
    process.env.NODE_ENV = 'test';
    process.env.LOG_LEVEL = 'error';
    
    // Mock external services
    this.setupExternalServiceMocks();
  }

  /**
   * Cleans up integration test environment
   */
  static async cleanupIntegrationTest() {
    // Restore environment variables
    delete process.env.NODE_ENV;
    delete process.env.LOG_LEVEL;
    
    // Restore mocks
    sinon.restore();
  }

  /**
   * Sets up external service mocks
   */
  static setupExternalServiceMocks() {
    // Mock Redis
    const redisMock = {
      get: sinon.stub().resolves(null),
      set: sinon.stub().resolves('OK'),
      del: sinon.stub().resolves(1),
      exists: sinon.stub().resolves(0),
      flushall: sinon.stub().resolves('OK'),
    };
    
    // Mock external APIs
    const axiosMock = {
      get: sinon.stub().resolves({ data: {} }),
      post: sinon.stub().resolves({ data: {} }),
      put: sinon.stub().resolves({ data: {} }),
      delete: sinon.stub().resolves({ data: {} }),
    };
    
    return { redis: redisMock, axios: axiosMock };
  }

  /**
   * Runs integration test with setup and cleanup
   */
  static async runIntegrationTest(testCallback) {
    try {
      await this.setupIntegrationTest();
      await testCallback();
    } finally {
      await this.cleanupIntegrationTest();
    }
  }
}

/**
 * Mock data factory
 */
class MockDataFactory {
  /**
   * Creates a mock user
   */
  static createUser(overrides = {}) {
    const baseCase = new BaseTestCase();
    return baseCase.createMockData('user', overrides);
  }

  /**
   * Creates multiple mock users
   */
  static createUsers(count, overrides = {}) {
    const users = [];
    for (let i = 0; i < count; i++) {
      users.push(this.createUser({
        ...overrides,
        id: i + 1,
        username: `testuser${i + 1}`,
        email: `test${i + 1}@example.com`,
      }));
    }
    return users;
  }

  /**
   * Creates a mock post
   */
  static createPost(overrides = {}) {
    const baseCase = new BaseTestCase();
    return baseCase.createMockData('post', overrides);
  }

  /**
   * Creates multiple mock posts
   */
  static createPosts(count, overrides = {}) {
    const posts = [];
    for (let i = 0; i < count; i++) {
      posts.push(this.createPost({
        ...overrides,
        id: i + 1,
        title: `Test Post ${i + 1}`,
      }));
    }
    return posts;
  }

  /**
   * Creates mock configuration
   */
  static createConfig(overrides = {}) {
    const baseCase = new BaseTestCase();
    return baseCase.createMockData('config', overrides);
  }
}

/**
 * Example test class demonstrating usage
 */
class ExampleServiceTest extends BaseTestCase {
  constructor() {
    super();
    this.service = null;
    this.mockDatabase = null;
  }

  /**
   * Example test setup
   */
  async setUp() {
    await super.setUp();
    
    // Create mock database
    this.mockDatabase = DatabaseTestUtils.createMockDatabase();
    
    // Create service with mocked dependencies
    this.service = {
      getUserById: this.createMockFunction(async (id) => {
        const result = await this.mockDatabase.query('SELECT * FROM users WHERE id = $1', [id]);
        return result.rows[0];
      }),
    };
  }

  /**
   * Example test method
   */
  async testGetUserById() {
    // Setup mock data
    const mockUser = this.createMockUser({ id: 1 });
    this.mockDatabase.query.resolves(DatabaseTestUtils.createMockQueryResult([mockUser]));
    
    // Test service method
    const result = await this.service.getUserById(1);
    
    // Assertions
    this.assertDeepEqual(result, mockUser);
    this.assertCalledWith(this.mockDatabase.query, 'SELECT * FROM users WHERE id = $1', [1]);
  }
}

/**
 * Example usage demonstration
 */
function exampleUsage() {
  console.log('Node.js Test Scaffold Usage:');
  console.log('1. Extend BaseTestCase for common utilities');
  console.log('2. Use HttpTestUtils for HTTP testing');
  console.log('3. Use DatabaseTestUtils for database testing');
  console.log('4. Use FileSystemTestUtils for file system testing');
  console.log('5. Use LoggerTestUtils for logger testing');
  console.log('6. Use PerformanceTestUtils for performance testing');
  console.log('7. Use IntegrationTestUtils for integration testing');
  console.log('8. Use MockDataFactory for creating test data');
}

module.exports = {
  BaseTestCase,
  HttpTestUtils,
  DatabaseTestUtils,
  FileSystemTestUtils,
  LoggerTestUtils,
  PerformanceTestUtils,
  IntegrationTestUtils,
  MockDataFactory,
  ExampleServiceTest,
  exampleUsage,
};
