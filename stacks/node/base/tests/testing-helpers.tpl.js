/**
 * FILE: testing-helpers.tpl.js
 * PURPOSE: Testing utilities and helpers for Node.js projects
 * USAGE: Common testing patterns, fixtures, and utilities for comprehensive testing
 * DEPENDENCIES: jest, supertest, mongodb-memory-server, redis-mock, sinon
 * AUTHOR: [[.Author]]
 * VERSION: [[.Version]]
 * SINCE: [[.Version]]
 */

/**
 * Node.js Testing Helpers Template
 * Purpose: Testing utilities and helpers for Node.js projects
 * Usage: Common testing patterns, fixtures, and utilities for comprehensive testing
 */

const { MongoMemoryServer } = require('mongodb-memory-server');
const { MongoClient } = require('mongodb');
const Redis = require('ioredis-mock');
const request = require('supertest');
const sinon = require('sinon');
const { faker } = require('@faker-js/faker');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const crypto = require('crypto');

// =============================================================================
// DATABASE TESTING HELPERS
// =============================================================================

class TestDatabase {
  constructor() {
    this.mongoServer = null;
    this.connection = null;
    this.db = null;
    this.collections = new Map();
  }

  async setup() {
    // Start in-memory MongoDB
    this.mongoServer = await MongoMemoryServer.create();
    const uri = this.mongoServer.getUri();
    
    this.connection = await MongoClient.connect(uri);
    this.db = this.connection.db();
  }

  async cleanup() {
    if (this.db) {
      // Drop all collections
      const collections = await this.db.collections();
      for (const collection of collections) {
        await collection.deleteMany({});
      }
    }
    
    if (this.connection) {
      await this.connection.close();
    }
    
    if (this.mongoServer) {
      await this.mongoServer.stop();
    }
  }

  getCollection(name) {
    return this.db.collection(name);
  }

  async insertDocument(collectionName, document) {
    const collection = this.getCollection(collectionName);
    const result = await collection.insertOne(document);
    return { ...document, _id: result.insertedId };
  }

  async findDocument(collectionName, query = {}) {
    const collection = this.getCollection(collectionName);
    return await collection.findOne(query);
  }

  async findDocuments(collectionName, query = {}) {
    const collection = this.getCollection(collectionName);
    return await collection.find(query).toArray();
  }
}

// =============================================================================
// REDIS TESTING HELPERS
// =============================================================================

class TestRedis {
  constructor() {
    this.client = new Redis();
  }

  async setup() {
    // Redis mock is already ready
    await this.client.flushall();
  }

  async cleanup() {
    await this.client.flushall();
    await this.client.quit();
  }

  async set(key, value, ttl = null) {
    if (ttl) {
      return await this.client.setex(key, ttl, JSON.stringify(value));
    }
    return await this.client.set(key, JSON.stringify(value));
  }

  async get(key) {
    const value = await this.client.get(key);
    return value ? JSON.parse(value) : null;
  }

  async del(key) {
    return await this.client.del(key);
  }

  async exists(key) {
    return await this.client.exists(key);
  }
}

// =============================================================================
// HTTP TESTING HELPERS
// =============================================================================

class TestHTTPClient {
  constructor(app) {
    this.app = app;
    this.request = request(app);
    this.authToken = null;
  }

  setAuthToken(token) {
    this.authToken = token;
  }

  getHeaders() {
    const headers = {};
    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }
    return headers;
  }

  async get(url, query = {}) {
    return await this.request
      .get(url)
      .query(query)
      .set(this.getHeaders());
  }

  async post(url, data = {}) {
    return await this.request
      .post(url)
      .send(data)
      .set(this.getHeaders());
  }

  async put(url, data = {}) {
    return await this.request
      .put(url)
      .send(data)
      .set(this.getHeaders());
  }

  async patch(url, data = {}) {
    return await this.request
      .patch(url)
      .send(data)
      .set(this.getHeaders());
  }

  async delete(url) {
    return await this.request
      .delete(url)
      .set(this.getHeaders());
  }

  generateTestToken(payload = {}, expiresIn = '1h') {
    const defaultPayload = {
      sub: faker.datatype.uuid(),
      iat: Math.floor(Date.now() / 1000),
      type: 'access'
    };
    
    return jwt.sign({ ...defaultPayload, ...payload }, 'test_secret', { expiresIn });
  }
}

// =============================================================================
// MOCK AND STUB HELPERS
// =============================================================================

class MockHelper {
  constructor() {
    this.sandboxes = [];
  }

  createSandbox() {
    const sandbox = sinon.createSandbox();
    this.sandboxes.push(sandbox);
    return sandbox;
  }

  restoreAll() {
    this.sandboxes.forEach(sandbox => sandbox.restore());
    this.sandboxes = [];
  }

  stubMethod(object, method, implementation) {
    const sandbox = this.createSandbox();
    return sandbox.stub(object, method).callsFake(implementation);
  }

  mockService(serviceName, methods = {}) {
    const mock = {};
    const sandbox = this.createSandbox();
    
    Object.keys(methods).forEach(methodName => {
      mock[methodName] = sandbox.stub().callsFake(methods[methodName]);
    });
    
    return mock;
  }

  createMockResponse() {
    return {
      status: 200,
      data: {},
      headers: {},
      json: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
      status: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis()
    };
  }

  createMockRequest(overrides = {}) {
    return {
      body: {},
      params: {},
      query: {},
      headers: {},
      user: null,
      ...overrides
    };
  }
}

// =============================================================================
// TEST DATA GENERATORS
// =============================================================================

class TestDataGenerator {
  constructor() {
    this.faker = faker;
  }

  generateUser(overrides = {}) {
    return {
      _id: this.faker.datatype.uuid(),
      email: this.faker.internet.email(),
      firstName: this.faker.name.firstName(),
      lastName: this.faker.name.lastName(),
      username: this.faker.internet.userName(),
      password: this.faker.internet.password(12, true, /[A-Z]/, 1),
      phone: this.faker.phone.number(),
      avatar: this.faker.internet.avatar(),
      bio: this.faker.lorem.paragraph(),
      isActive: this.faker.datatype.boolean(),
      isVerified: this.faker.datatype.boolean(),
      roles: [this.faker.helpers.arrayElement(['user', 'admin', 'moderator'])],
      preferences: {
        theme: this.faker.helpers.arrayElement(['light', 'dark']),
        language: this.faker.helpers.arrayElement(['en', 'es', 'fr']),
        notifications: this.faker.datatype.boolean()
      },
      createdAt: this.faker.date.past(),
      updatedAt: this.faker.date.recent(),
      ...overrides
    };
  }

  generateProduct(overrides = {}) {
    return {
      _id: this.faker.datatype.uuid(),
      name: this.faker.commerce.productName(),
      description: this.faker.commerce.productDescription(),
      price: parseFloat(this.faker.commerce.price(10, 1000, 2)),
      category: this.faker.commerce.department(),
      sku: this.faker.datatype.string(8),
      stock: this.faker.datatype.number({ min: 0, max: 1000 }),
      isActive: this.faker.datatype.boolean(),
      tags: this.faker.helpers.arrayElements(['popular', 'new', 'sale', 'featured'], 2),
      attributes: {
        color: this.faker.commerce.color(),
        size: this.faker.helpers.arrayElement(['S', 'M', 'L', 'XL']),
        material: this.faker.helpers.arrayElement(['cotton', 'polyester', 'wool'])
      },
      images: Array.from({ length: this.faker.datatype.number({ min: 1, max: 5 }) }, () => 
        this.faker.image.imageUrl()
      ),
      createdAt: this.faker.date.past(),
      updatedAt: this.faker.date.recent(),
      ...overrides
    };
  }

  generateOrder(userId = null, overrides = {}) {
    return {
      _id: this.faker.datatype.uuid(),
      userId: userId || this.faker.datatype.uuid(),
      status: this.faker.helpers.arrayElement(['pending', 'confirmed', 'shipped', 'delivered']),
      items: Array.from({ length: this.faker.datatype.number({ min: 1, max: 5 }) }, () => ({
        productId: this.faker.datatype.uuid(),
        quantity: this.faker.datatype.number({ min: 1, max: 5 }),
        unitPrice: parseFloat(this.faker.commerce.price(10, 100, 2)),
        totalPrice: parseFloat(this.faker.commerce.price(10, 100, 2))
      })),
      totalAmount: parseFloat(this.faker.commerce.price(50, 500, 2)),
      currency: this.faker.finance.currencyCode(),
      paymentMethod: this.faker.helpers.arrayElement(['credit_card', 'paypal', 'bank_transfer']),
      paymentStatus: this.faker.helpers.arrayElement(['pending', 'completed', 'failed']),
      shippingAddress: {
        street: this.faker.address.streetAddress(),
        city: this.faker.address.city(),
        state: this.faker.address.state(),
        zipCode: this.faker.address.zipCode(),
        country: this.faker.address.country()
      },
      createdAt: this.faker.date.past(),
      updatedAt: this.faker.date.recent(),
      ...overrides
    };
  }

  generateDocument(overrides = {}) {
    return {
      _id: this.faker.datatype.uuid(),
      title: this.faker.lorem.sentence(5),
      content: this.faker.lorem.paragraphs(3),
      filePath: `/documents/${this.faker.datatype.uuid()}.pdf`,
      fileSize: this.faker.datatype.number({ min: 1024, max: 10485760 }),
      mimeType: this.faker.helpers.arrayElement(['application/pdf', 'text/plain', 'application/msword']),
      ownerId: this.faker.datatype.uuid(),
      isPublic: this.faker.datatype.boolean(),
      tags: this.faker.helpers.arrayElements(['work', 'personal', 'project', 'important'], 2),
      metadata: {
        author: this.faker.name.fullName(),
        wordCount: this.faker.datatype.number({ min: 100, max: 10000 }),
        language: this.faker.helpers.arrayElement(['en', 'es', 'fr'])
      },
      version: this.faker.datatype.number({ min: 1, max: 10 }),
      createdAt: this.faker.date.past(),
      updatedAt: this.faker.date.recent(),
      ...overrides
    };
  }
}

// =============================================================================
// FILE SYSTEM TESTING HELPERS
// =============================================================================

class TestFileSystem {
  constructor() {
    this.tempDirs = [];
    this.tempFiles = [];
  }

  async createTempDir() {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'test-'));
    this.tempDirs.push(tempDir);
    return tempDir;
  }

  async createTempFile(content = '', filename = null) {
    const tempDir = await this.createTempDir();
    const fileName = filename || `test-${Date.now()}.txt`;
    const filePath = path.join(tempDir, fileName);
    
    await fs.writeFile(filePath, content);
    this.tempFiles.push(filePath);
    
    return filePath;
  }

  async cleanup() {
    // Clean up temp files
    for (const filePath of this.tempFiles) {
      try {
        await fs.unlink(filePath);
      } catch (error) {
        // Ignore file not found errors
      }
    }
    
    // Clean up temp directories
    for (const dirPath of this.tempDirs) {
      try {
        await fs.rmdir(dirPath, { recursive: true });
      } catch (error) {
        // Ignore directory not found errors
      }
    }
    
    this.tempDirs = [];
    this.tempFiles = [];
  }

  async readFile(filePath) {
    return await fs.readFile(filePath, 'utf8');
  }

  async writeFile(filePath, content) {
    await fs.writeFile(filePath, content);
    this.tempFiles.push(filePath);
  }

  async assertFileExists(filePath) {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }
}

// =============================================================================
// PERFORMANCE TESTING HELPERS
// =============================================================================

class PerformanceHelper {
  measureExecutionTime(fn) {
    const start = process.hrtime.bigint();
    const result = fn();
    const end = process.hrtime.bigint();
    const executionTime = Number(end - start) / 1000000; // Convert to milliseconds
    
    return {
      result,
      executionTime
    };
  }

  async measureAsyncExecutionTime(fn) {
    const start = process.hrtime.bigint();
    const result = await fn();
    const end = process.hrtime.bigint();
    const executionTime = Number(end - start) / 1000000; // Convert to milliseconds
    
    return {
      result,
      executionTime
    };
  }

  async benchmarkFunction(fn, iterations = 1000) {
    const times = [];
    
    for (let i = 0; i < iterations; i++) {
      const { executionTime } = await this.measureAsyncExecutionTime(fn);
      times.push(executionTime);
    }
    
    times.sort((a, b) => a - b);
    
    return {
      iterations,
      minTime: times[0],
      maxTime: times[times.length - 1],
      avgTime: times.reduce((sum, time) => sum + time, 0) / times.length,
      medianTime: times[Math.floor(times.length / 2)],
      p95Time: times[Math.floor(times.length * 0.95)],
      p99Time: times[Math.floor(times.length * 0.99)]
    };
  }

  measureMemoryUsage(fn) {
    const before = process.memoryUsage();
    const result = fn();
    const after = process.memoryUsage();
    
    return {
      result,
      memoryUsage: {
        rss: after.rss - before.rss,
        heapUsed: after.heapUsed - before.heapUsed,
        heapTotal: after.heapTotal - before.heapTotal,
        external: after.external - before.external
      }
    };
  }

  async measureAsyncMemoryUsage(fn) {
    const before = process.memoryUsage();
    const result = await fn();
    const after = process.memoryUsage();
    
    return {
      result,
      memoryUsage: {
        rss: after.rss - before.rss,
        heapUsed: after.heapUsed - before.heapUsed,
        heapTotal: after.heapTotal - before.heapTotal,
        external: after.external - before.external
      }
    };
  }
}

// =============================================================================
// SECURITY TESTING HELPERS
// =============================================================================

class SecurityHelper {
  generateSQLInjectionPayloads() {
    return [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "' OR '1'='1' /*",
      "admin'--",
      "admin' /*",
      "' OR 1=1--",
      "' OR 1=1#",
      "' OR 1=1/*",
      "') OR '1'='1--",
      "') OR ('1'='1--"
    ];
  }

  generateXSSPayloads() {
    return [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert('XSS')>",
      "javascript:alert('XSS')",
      "<svg onload=alert('XSS')>",
      "';alert('XSS');//"
    ];
  }

  generatePathTraversalPayloads() {
    return [
      "../../../etc/passwd",
      "..\\..\\..\\windows\\system32\\config\\sam",
      "....//....//....//etc/passwd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "..%252f..%252f..%252fetc%252fpasswd"
    ];
  }

  assertNoVulnerabilities(response, payload, vulnerabilityType) {
    const responseText = response.text || '';
    
    switch (vulnerabilityType) {
      case 'xss':
        expect(responseText.toLowerCase()).not.toContain('<script>');
        expect(responseText.toLowerCase()).not.toContain('javascript:');
        break;
      case 'sql_injection':
        expect(responseText.toLowerCase()).not.toContain('sql syntax');
        expect(responseText.toLowerCase()).not.toContain('mysql_fetch');
        break;
      case 'path_traversal':
        expect(responseText.toLowerCase()).not.toContain('root:');
        expect(responseText.toLowerCase()).not.toContain('[boot loader]');
        break;
    }
  }

  hashPassword(password) {
    return bcrypt.hashSync(password, 10);
  }

  comparePassword(password, hash) {
    return bcrypt.compareSync(password, hash);
  }

  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }
}

// =============================================================================
// ASSERTION HELPERS
// =============================================================================

class AssertionHelper {
  assertJSONStructure(actual, expectedFields) {
    expectedFields.forEach(field => {
      expect(actual).toHaveProperty(field);
    });
  }

  assertDateTimeClose(actual, expected, toleranceSeconds = 5) {
    const actualDate = new Date(actual);
    const expectedDate = new Date(expected);
    const diffSeconds = Math.abs((actualDate - expectedDate) / 1000);
    
    expect(diffSeconds).toBeLessThanOrEqual(toleranceSeconds);
  }

  assertArraysEqualUnordered(arr1, arr2) {
    expect(arr1).toHaveLength(arr2.length);
    expect(arr1.sort()).toEqual(arr2.sort());
  }

  assertObjectSubset(subset, superset) {
    Object.keys(subset).forEach(key => {
      expect(superset).toHaveProperty(key);
      expect(superset[key]).toEqual(subset[key]);
    });
  }

  assertValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    expect(email).toMatch(emailRegex);
  }

  assertValidPhone(phone) {
    const phoneRegex = /^\+?1?-?\.?\s?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$/;
    expect(phone).toMatch(phoneRegex);
  }

  assertValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    expect(uuid).toMatch(uuidRegex);
  }

  assertPasswordStrength(password, minLength = 8) {
    expect(password.length).toBeGreaterThanOrEqual(minLength);
    expect(/[A-Z]/.test(password)).toBe(true);
    expect(/[a-z]/.test(password)).toBe(true);
    expect(/[0-9]/.test(password)).toBe(true);
    expect(/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)).toBe(true);
  }

  assertValidJSON(jsonString) {
    expect(() => JSON.parse(jsonString)).not.toThrow();
  }

  assertValidPagination(response, page = 1, pageSize = 10) {
    expect(response).toHaveProperty('data');
    expect(response).toHaveProperty('pagination');
    
    const pagination = response.pagination;
    expect(pagination).toHaveProperty('page');
    expect(pagination).toHaveProperty('pageSize');
    expect(pagination).toHaveProperty('total');
    expect(pagination).toHaveProperty('totalPages');
    
    expect(pagination.page).toBe(page);
    expect(pagination.pageSize).toBe(pageSize);
    expect(typeof pagination.total).toBe('number');
    expect(typeof pagination.totalPages).toBe('number');
  }
}

// =============================================================================
// INTEGRATION TESTING HELPERS
// =============================================================================

class IntegrationHelper {
  async waitForService(url, timeout = 30000) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
      try {
        const response = await fetch(url, { timeout: 5000 });
        if (response.ok) {
          return true;
        }
      } catch (error) {
        // Service not ready yet
      }
      
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    throw new Error(`Service not available at ${url} after ${timeout}ms`);
  }

  async createTestDockerCompose(composeFile, services) {
    // This would typically use docker-compose or similar
    // Implementation depends on your Docker setup
    console.log(`Starting services: ${services.join(', ')}`);
    
    // Mock implementation - in real scenario, you'd use docker-compose
    return {
      start: async () => {
        console.log('Starting Docker services...');
        await new Promise(resolve => setTimeout(resolve, 5000));
      },
      stop: async () => {
        console.log('Stopping Docker services...');
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    };
  }

  createTestDatabaseConfig(dbType = 'mongodb') {
    const configs = {
      mongodb: {
        host: 'localhost',
        port: 27017,
        database: 'test_db',
        options: {
          useNewUrlParser: true,
          useUnifiedTopology: true
        }
      },
      postgresql: {
        host: 'localhost',
        port: 5432,
        database: 'test_db',
        username: 'test_user',
        password: 'test_password'
      },
      mysql: {
        host: 'localhost',
        port: 3306,
        database: 'test_db',
        username: 'test_user',
        password: 'test_password'
      }
    };
    
    return configs[dbType] || configs.mongodb;
  }
}

// =============================================================================
// JEST FIXTURES AND SETUP
// =============================================================================

// Global test setup
let testDatabase;
let testRedis;
let testFileSystem;
let mockHelper;
let dataGenerator;
let performanceHelper;
let securityHelper;
let assertionHelper;
let integrationHelper;

beforeAll(async () => {
  testDatabase = new TestDatabase();
  testRedis = new TestRedis();
  testFileSystem = new TestFileSystem();
  mockHelper = new MockHelper();
  dataGenerator = new TestDataGenerator();
  performanceHelper = new PerformanceHelper();
  securityHelper = new SecurityHelper();
  assertionHelper = new AssertionHelper();
  integrationHelper = new IntegrationHelper();
});

beforeEach(async () => {
  await testDatabase.setup();
  await testRedis.setup();
});

afterEach(async () => {
  await testDatabase.cleanup();
  await testRedis.cleanup();
  mockHelper.restoreAll();
  await testFileSystem.cleanup();
});

afterAll(async () => {
  await testDatabase.cleanup();
  await testRedis.cleanup();
  await testFileSystem.cleanup();
  mockHelper.restoreAll();
});

// Export helpers for use in tests
module.exports = {
  TestDatabase,
  TestRedis,
  TestHTTPClient,
  MockHelper,
  TestDataGenerator,
  TestFileSystem,
  PerformanceHelper,
  SecurityHelper,
  AssertionHelper,
  IntegrationHelper,
  // Global instances
  testDatabase: () => testDatabase,
  testRedis: () => testRedis,
  testFileSystem: () => testFileSystem,
  mockHelper: () => mockHelper,
  dataGenerator: () => dataGenerator,
  performanceHelper: () => performanceHelper,
  securityHelper: () => securityHelper,
  assertionHelper: () => assertionHelper,
  integrationHelper: () => integrationHelper
};