/*
File: testing.tpl.js
Purpose: Testing utilities for Jest/Vitest
Generated for: {{PROJECT_NAME}}
*/

const { beforeAll, afterAll, beforeEach, afterEach, describe, it, expect } = require('@jest/globals');

// Test data factory
const TestDataFactory = {
    user(overrides = {}) {
        return {
            email: 'test@example.com',
            username: 'testuser',
            password: 'Password123!',
            ...overrides,
        };
    },

    post(overrides = {}) {
        return {
            title: 'Test Post',
            content: 'Test content',
            ...overrides,
        };
    },

    // Generate unique email
    uniqueEmail() {
        return `test-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
    },

    // Generate unique username
    uniqueUsername() {
        return `user-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    },
};

// Mock response helper
class MockResponse {
    constructor(data, status = 200) {
        this.data = data;
        this.status = status;
        this.ok = status >= 200 && status < 300;
    }

    json() {
        return Promise.resolve(this.data);
    }

    text() {
        return Promise.resolve(JSON.stringify(this.data));
    }
}

// Mock fetch helper
function mockFetch(responses = {}) {
    return jest.fn((url, options = {}) => {
        const method = options.method || 'GET';
        const key = `${method} ${url}`;

        if (responses[key]) {
            const response = responses[key];
            return Promise.resolve(new MockResponse(response.data, response.status));
        }

        return Promise.resolve(new MockResponse({ error: 'Not found' }, 404));
    });
}

// Database test helpers
class TestDatabase {
    constructor(prisma) {
        this.prisma = prisma;
    }

    async reset() {
        // Delete in correct order to respect foreign keys
        const tablenames = await this.prisma.$queryRaw`
      SELECT tablename FROM pg_tables WHERE schemaname = 'public'
    `;

        for (const { tablename } of tablenames) {
            if (tablename !== '_prisma_migrations') {
                await this.prisma.$executeRawUnsafe(`TRUNCATE TABLE "${tablename}" CASCADE`);
            }
        }
    }

    async seed(data = {}) {
        // Seed test data
        if (data.users) {
            await this.prisma.user.createMany({ data: data.users });
        }
        // Add more seeders as needed
    }
}

// Request helper for API testing
class TestClient {
    constructor(baseUrl = 'http://localhost:3000') {
        this.baseUrl = baseUrl;
        this.headers = {};
    }

    setAuth(token) {
        this.headers['Authorization'] = `Bearer ${token}`;
    }

    clearAuth() {
        delete this.headers['Authorization'];
    }

    async request(method, path, { body, query, headers = {} } = {}) {
        const url = new URL(path, this.baseUrl);

        if (query) {
            Object.entries(query).forEach(([key, value]) => {
                url.searchParams.append(key, value);
            });
        }

        const response = await fetch(url.toString(), {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...this.headers,
                ...headers,
            },
            body: body ? JSON.stringify(body) : undefined,
        });

        const data = await response.json().catch(() => null);

        return {
            status: response.status,
            ok: response.ok,
            data,
            headers: Object.fromEntries(response.headers.entries()),
        };
    }

    get(path, options) {
        return this.request('GET', path, options);
    }

    post(path, body, options) {
        return this.request('POST', path, { ...options, body });
    }

    put(path, body, options) {
        return this.request('PUT', path, { ...options, body });
    }

    patch(path, body, options) {
        return this.request('PATCH', path, { ...options, body });
    }

    delete(path, options) {
        return this.request('DELETE', path, options);
    }
}

// Assertion helpers
const assertions = {
    assertOk(response, expectedStatus = 200) {
        expect(response.status).toBe(expectedStatus);
    },

    assertError(response, expectedStatus, errorCode) {
        expect(response.status).toBe(expectedStatus);
        if (errorCode) {
            expect(response.data?.error?.code).toBe(errorCode);
        }
    },

    assertContainsKeys(obj, keys) {
        keys.forEach((key) => {
            expect(obj).toHaveProperty(key);
        });
    },

    assertArrayLength(arr, length) {
        expect(arr).toHaveLength(length);
    },
};

// Timeout helpers
function wait(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(condition, { timeout = 5000, interval = 100 } = {}) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
        if (await condition()) {
            return true;
        }
        await wait(interval);
    }
    throw new Error(`Condition not met within ${timeout}ms`);
}

// Test context helper
function createTestContext() {
    const context = {
        data: {},
        cleanup: [],
    };

    return {
        set(key, value) {
            context.data[key] = value;
        },
        get(key) {
            return context.data[key];
        },
        onCleanup(fn) {
            context.cleanup.push(fn);
        },
        async cleanup() {
            for (const fn of context.cleanup.reverse()) {
                await fn();
            }
            context.data = {};
            context.cleanup = [];
        },
    };
}

module.exports = {
    TestDataFactory,
    MockResponse,
    mockFetch,
    TestDatabase,
    TestClient,
    assertions,
    wait,
    waitFor,
    createTestContext,
};

// Usage:
// const { TestDataFactory, TestClient, assertions } = require('./testing');
//
// describe('User API', () => {
//   const client = new TestClient();
//
//   it('should create user', async () => {
//     const response = await client.post('/users', TestDataFactory.user());
//     assertions.assertOk(response, 201);
//     assertions.assertContainsKeys(response.data, ['id', 'email']);
//   });
// });
