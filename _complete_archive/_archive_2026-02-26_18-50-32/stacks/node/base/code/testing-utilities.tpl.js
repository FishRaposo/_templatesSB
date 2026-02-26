/**
 * File: testing-utilities.tpl.js
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

#!/usr/bin/env node
/**
 * Node.js Testing Utilities Template
 * Purpose: Reusable testing utilities and helpers for Node.js projects
 * Usage: Import and adapt for consistent testing patterns across the application
 */

const fs = require('fs').promises;
const path = require('path');
const { EventEmitter } = require('events');

/**
 * Test data manager for creating and managing test data
 */
class TestDataManager {
    constructor() {
        this.data = this._createSampleData();
        this.tempFiles = [];
        this.tempDirs = [];
    }

    /**
     * Create sample test data
     */
    _createSampleData() {
        return {
            users: [
                {
                    id: 1,
                    username: 'testuser1',
                    email: 'test1@example.com',
                    isActive: true,
                    createdAt: new Date('2023-01-01T00:00:00Z')
                },
                {
                    id: 2,
                    username: 'testuser2',
                    email: 'test2@example.com',
                    isActive: false,
                    createdAt: new Date('2023-01-02T00:00:00Z')
                }
            ],
            posts: [
                {
                    id: 1,
                    userId: 1,
                    title: 'Test Post 1',
                    content: 'This is test content',
                    published: true,
                    createdAt: new Date('2023-01-01T12:00:00Z')
                },
                {
                    id: 2,
                    userId: 2,
                    title: 'Test Post 2',
                    content: 'More test content',
                    published: false,
                    createdAt: new Date('2023-01-02T12:00:00Z')
                }
            ],
            config: {
                database: {
                    url: 'sqlite:///:memory:',
                    timeout: 30000
                },
                server: {
                    port: 3000,
                    host: 'localhost',
                    debug: true
                },
                auth: {
                    secretKey: 'test-secret-key',
                    expiresIn: '1h'
                }
            }
        };
    }

    /**
     * Get test user by ID
     */
    getUser(userId) {
        const user = this.data.users.find(u => u.id === userId);
        return user ? { ...user } : null;
    }

    /**
     * Get test post by ID
     */
    getPost(postId) {
        const post = this.data.posts.find(p => p.id === postId);
        return post ? { ...post } : null;
    }

    /**
     * Create temporary test file
     */
    async createTempFile(content = '', suffix = '.txt') {
        const os = require('os');
        const filePath = path.join(os.tmpdir(), `test-${Date.now()}${suffix}`);
        
        await fs.writeFile(filePath, content, 'utf8');
        this.tempFiles.push(filePath);
        
        return filePath;
    }

    /**
     * Create temporary directory
     */
    async createTempDir() {
        const os = require('os');
        const dirPath = path.join(os.tmpdir(), `test-dir-${Date.now()}`);
        
        await fs.mkdir(dirPath, { recursive: true });
        this.tempDirs.push(dirPath);
        
        return dirPath;
    }

    /**
     * Clean up temporary files and directories
     */
    async cleanup() {
        // Clean up temporary files
        for (const filePath of this.tempFiles) {
            try {
                await fs.unlink(filePath);
            } catch (error) {
                // File might not exist
            }
        }

        // Clean up temporary directories
        for (const dirPath of this.tempDirs) {
            try {
                await fs.rmdir(dirPath, { recursive: true });
            } catch (error) {
                // Directory might not exist
            }
        }

        this.tempFiles = [];
        this.tempDirs = [];
    }
}

/**
 * Mock factory for creating mock objects
 */
class MockFactory {
    /**
     * Create mock user object
     */
    static createMockUser(overrides = {}) {
        const defaultUser = {
            id: 1,
            username: 'mockuser',
            email: 'mock@example.com',
            isActive: true,
            createdAt: new Date(),
            save: jest.fn().mockResolvedValue(true),
            validate: jest.fn().mockReturnValue(true)
        };

        return { ...defaultUser, ...overrides };
    }

    /**
     * Create mock HTTP response
     */
    static createMockResponse(options = {}) {
        const defaultResponse = {
            status: 200,
            data: {},
            headers: {},
            json: jest.fn().mockResolvedValue({}),
            send: jest.fn(),
            status: jest.fn().mockReturnThis(),
            set: jest.fn().mockReturnThis()
        };

        return { ...defaultResponse, ...options };
    }

    /**
     * Create mock HTTP request
     */
    static createMockRequest(options = {}) {
        const defaultRequest = {
            body: {},
            params: {},
            query: {},
            headers: {},
            user: null,
            method: 'GET',
            url: '/test'
        };

        return { ...defaultRequest, ...options };
    }

    /**
     * Create mock database connection
     */
    static createMockDatabase() {
        return {
            query: jest.fn().mockResolvedValue({ rows: [] }),
            connect: jest.fn().mockResolvedValue(true),
            disconnect: jest.fn().mockResolvedValue(true),
            transaction: jest.fn().mockResolvedValue(true),
            rollback: jest.fn().mockResolvedValue(true)
        };
    }

    /**
     * Create mock service
     */
    static createMockService(methods = {}) {
        const defaultMethods = {
            initialize: jest.fn().mockResolvedValue(true),
            validate: jest.fn().mockReturnValue(true),
            process: jest.fn().mockResolvedValue({})
        };

        return { ...defaultMethods, ...methods };
    }
}

/**
 * Assertion helpers for custom assertions
 */
class AssertionHelpers {
    /**
     * Assert email format is valid
     */
    static assertValidEmail(email) {
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (!emailRegex.test(email)) {
            throw new Error(`Invalid email format: ${email}`);
        }
    }

    /**
     * Assert string is valid datetime
     */
    static assertDateTimeString(dateTimeString) {
        const date = new Date(dateTimeString);
        if (isNaN(date.getTime())) {
            throw new Error(`Invalid datetime format: ${dateTimeString}`);
        }
    }

    /**
     * Assert object has required structure
     */
    static assertJsonStructure(data, requiredKeys) {
        for (const key of requiredKeys) {
            if (!(key in data)) {
                throw new Error(`Missing required key: ${key}`);
            }
        }
    }

    /**
     * Assert array contains all expected items
     */
    static assertArrayContainsItems(array, expectedItems) {
        for (const item of expectedItems) {
            if (!array.includes(item)) {
                throw new Error(`Expected item ${item} not found in array`);
            }
        }
    }

    /**
     * Assert file exists
     */
    static async assertFileExists(filePath) {
        try {
            await fs.access(filePath);
        } catch (error) {
            throw new Error(`File does not exist: ${filePath}`);
        }
    }

    /**
     * Assert file contains expected content
     */
    static async assertFileContent(filePath, expectedContent) {
        const content = await fs.readFile(filePath, 'utf8');
        if (!content.includes(expectedContent)) {
            throw new Error(`Expected content not found in file: ${filePath}`);
        }
    }

    /**
     * Assert promise resolves within timeout
     */
    static async assertResolvesWithin(promise, timeoutMs) {
        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error(`Promise did not resolve within ${timeoutMs}ms`)), timeoutMs);
        });

        return Promise.race([promise, timeoutPromise]);
    }
}

/**
 * Test environment manager
 */
class TestEnvironment {
    constructor() {
        this.originalEnv = { ...process.env };
        this.envVars = {};
    }

    /**
     * Set environment variable
     */
    setEnv(key, value) {
        this.envVars[key] = process.env[key];
        process.env[key] = value;
    }

    /**
     * Set multiple environment variables
     */
    setEnv(envVars) {
        Object.entries(envVars).forEach(([key, value]) => {
            this.setEnv(key, value);
        });
    }

    /**
     * Restore original environment
     */
    restore() {
        Object.entries(this.envVars).forEach(([key, value]) => {
            if (value === undefined) {
                delete process.env[key];
            } else {
                process.env[key] = value;
            }
        });
        this.envVars = {};
    }

    /**
     * Setup test database
     */
    async setupTestDatabase() {
        // Implementation depends on your database setup
        // Example for SQLite:
        const Database = require('better-sqlite3');
        const db = new Database(':memory:');
        
        // Create test tables
        db.exec(`
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                email TEXT UNIQUE,
                is_active BOOLEAN,
                created_at DATETIME
            );
            
            CREATE TABLE posts (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                title TEXT,
                content TEXT,
                published BOOLEAN,
                created_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        `);

        return db;
    }

    /**
     * Cleanup test database
     */
    async cleanupTestDatabase(db) {
        if (db && db.close) {
            db.close();
        }
    }
}

/**
 * Database test helpers
 */
class DatabaseTestHelpers {
    /**
     * Create test database URL
     */
    static createTestDatabaseUrl() {
        return 'sqlite:///:memory:';
    }

    /**
     * Create mock table data
     */
    static createMockTableData(tableName, columns, rows) {
        return rows.map(row => {
            const rowObj = {};
            columns.forEach((col, index) => {
                rowObj[col] = row[index];
            });
            return rowObj;
        });
    }

    /**
     * Assert table structure
     */
    static assertTableStructure(mockDb, tableName, expectedColumns) {
        // Implementation depends on your database setup
        // Example for SQL databases:
        const describeTable = mockDb.describeTable || jest.fn();
        expect(describeTable).toHaveBeenCalledWith(tableName);
    }

    /**
     * Insert test data
     */
    static async insertTestData(db, tableName, data) {
        if (!db || !db.run) {
            throw new Error('Invalid database connection');
        }

        const columns = Object.keys(data);
        const values = Object.values(data);
        const placeholders = values.map(() => '?').join(', ');

        const stmt = db.prepare(`
            INSERT INTO ${tableName} (${columns.join(', ')})
            VALUES (${placeholders})
        `);

        return stmt.run(values);
    }
}

/**
 * API test helpers
 */
class APITestHelpers {
    /**
     * Create test HTTP headers
     */
    static createTestHeaders() {
        return {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer test_token',
            'User-Agent': 'TestClient/1.0',
            'X-Request-ID': 'test-request-id'
        };
    }

    /**
     * Assert API response structure
     */
    static assertAPIResponse(response, expectedStatus = 200, expectedData = null) {
        expect(response.status).toBe(expectedStatus);

        if (expectedData) {
            expect(response.data).toBeDefined();
            Object.entries(expectedData).forEach(([key, value]) => {
                expect(response.data[key]).toBe(value);
            });
        }
    }

    /**
     * Create test request payload
     */
    static createTestPayload(overrides = {}) {
        const defaultPayload = {
            id: 1,
            name: 'Test Item',
            description: 'Test description',
            active: true,
            createdAt: new Date().toISOString()
        };

        return { ...defaultPayload, ...overrides };
    }
}

/**
 * Performance test utilities
 */
class PerformanceTestHelpers {
    /**
     * Measure function execution time
     */
    static async measureExecutionTime(fn, ...args) {
        const startTime = process.hrtime.bigint();
        const result = await fn(...args);
        const endTime = process.hrtime.bigint();
        
        const executionTime = Number(endTime - startTime) / 1000000; // Convert to milliseconds
        
        return {
            result,
            executionTime: Math.round(executionTime * 100) / 100
        };
    }

    /**
     * Assert function performance
     */
    static async assertPerformance(fn, maxTimeMs, ...args) {
        const { executionTime } = await this.measureExecutionTime(fn, ...args);
        
        if (executionTime > maxTimeMs) {
            throw new Error(`Function took ${executionTime}ms, expected max ${maxTimeMs}ms`);
        }

        return executionTime;
    }

    /**
     * Benchmark function with multiple runs
     */
    static async benchmark(fn, runs = 100, ...args) {
        const times = [];
        
        for (let i = 0; i < runs; i++) {
            const { executionTime } = await this.measureExecutionTime(fn, ...args);
            times.push(executionTime);
        }

        const avgTime = times.reduce((sum, time) => sum + time, 0) / times.length;
        const minTime = Math.min(...times);
        const maxTime = Math.max(...times);

        return {
            runs,
            averageTime: Math.round(avgTime * 100) / 100,
            minTime: Math.round(minTime * 100) / 100,
            maxTime: Math.round(maxTime * 100) / 100,
            times
        };
    }
}

/**
 * Test decorators and utilities
 */
function withTestData(testData) {
    return function(target, propertyName, descriptor) {
        const originalMethod = descriptor.value;

        descriptor.value = function(...args) {
            return originalMethod.call(this, testData, ...args);
        };

        return descriptor;
    };
}

function skipInCI(target, propertyName, descriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = function(...args) {
        if (process.env.CI) {
            console.log(`Skipping test ${propertyName} in CI environment`);
            return;
        }
        return originalMethod.call(this, ...args);
    };

    return descriptor;
}

function retryTest(maxRetries = 3, delay = 100) {
    return function(target, propertyName, descriptor) {
        const originalMethod = descriptor.value;

        descriptor.value = async function(...args) {
            let lastError;

            for (let attempt = 0; attempt < maxRetries; attempt++) {
                try {
                    return await originalMethod.call(this, ...args);
                } catch (error) {
                    lastError = error;
                    if (attempt < maxRetries - 1) {
                        await new Promise(resolve => setTimeout(resolve, delay));
                    }
                }
            }

            throw lastError;
        };

        return descriptor;
    };
}

/**
 * Base test class
 */
class BaseTest {
    constructor() {
        this.testData = new TestDataManager();
        this.mockFactory = MockFactory;
        this.assertions = AssertionHelpers;
        this.env = new TestEnvironment();
    }

    async setup() {
        // Override in subclasses
    }

    async teardown() {
        await this.testData.cleanup();
        this.env.restore();
    }
}

/**
 * Example test class
 */
class ExampleServiceTest extends BaseTest {
    constructor() {
        super();
        this.mockService = null;
    }

    async setup() {
        await super.setup();
        this.mockService = MockFactory.createMockService({
            process: jest.fn().mockResolvedValue({ success: true })
        });
    }

    @withTestData({ userId: 1, action: 'test' })
    async testServiceProcess(testData) {
        const result = await this.mockService.process(testData);
        expect(result.success).toBe(true);
        expect(this.mockService.process).toHaveBeenCalledWith(testData);
    }

    @skipInCI
    async testExpensiveOperation() {
        // This test will be skipped in CI
        const result = await this.mockService.process({ expensive: true });
        expect(result).toBeDefined();
    }

    @retryTest(3, 50)
    async testFlakyOperation() {
        // This test will be retried up to 3 times
        const result = await this.mockService.process({ flaky: true });
        expect(result).toBeDefined();
    }
}

// Example usage
if (require.main === module) {
    async function main() {
        try {
            console.log('Node.js testing utilities template created!');
            console.log('Components included:');
            console.log('- TestDataManager: Manage test data and temporary files');
            console.log('- MockFactory: Create mock objects for testing');
            console.log('- AssertionHelpers: Custom assertion methods');
            console.log('- TestEnvironment: Manage test environment');
            console.log('- DatabaseTestHelpers: Database testing utilities');
            console.log('- APITestHelpers: API testing utilities');
            console.log('- PerformanceTestHelpers: Performance testing utilities');
            console.log('- BaseTest: Base class for tests');
            console.log('- Test decorators: @withTestData, @skipInCI, @retryTest');

            // Quick demo
            const testData = new TestDataManager();
            console.log(`Created ${testData.data.users.length} test users`);
            console.log(`Created ${testData.data.posts.length} test posts`);

            const mockUser = MockFactory.createMockUser({ username: 'demo' });
            console.log(`Created mock user: ${mockUser.username}`);

            // Test assertions
            try {
                AssertionHelpers.assertValidEmail('test@example.com');
                console.log('Email assertion passed');
            } catch (error) {
                console.log('Email assertion failed:', error.message);
            }

            // Performance test
            const { executionTime } = await PerformanceTestHelpers.measureExecutionTime(
                async () => {
                    await new Promise(resolve => setTimeout(resolve, 10));
                    return 'completed';
                }
            );
            console.log(`Performance test completed in ${executionTime}ms`);

            // Cleanup
            await testData.cleanup();
            console.log('Testing utilities demo completed');

        } catch (error) {
            console.error('Demo error:', error.message);
        }
    }

    main();
}

module.exports = {
    // Classes
    TestDataManager,
    MockFactory,
    AssertionHelpers,
    TestEnvironment,
    DatabaseTestHelpers,
    APITestHelpers,
    PerformanceTestHelpers,
    BaseTest,

    // Decorators
    withTestData,
    skipInCI,
    retryTest,

    // Example
    ExampleServiceTest
};
