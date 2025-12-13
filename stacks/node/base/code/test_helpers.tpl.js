/*
File: test_helpers.tpl.js
Purpose: Test helper functions and custom assertions
Generated for: {{PROJECT_NAME}}
*/

// ============================================================================
// Response Assertions
// ============================================================================

class ResponseAssertions {
    constructor(response) {
        this.response = response;
        this.body = response.body;
    }

    status(expected) {
        expect(this.response.status).toBe(expected);
        return this;
    }

    ok() {
        expect(this.response.status).toBeGreaterThanOrEqual(200);
        expect(this.response.status).toBeLessThan(300);
        return this;
    }

    created() {
        return this.status(201);
    }

    noContent() {
        return this.status(204);
    }

    badRequest() {
        return this.status(400);
    }

    unauthorized() {
        return this.status(401);
    }

    forbidden() {
        return this.status(403);
    }

    notFound() {
        return this.status(404);
    }

    unprocessable() {
        return this.status(422);
    }

    serverError() {
        expect(this.response.status).toBeGreaterThanOrEqual(500);
        expect(this.response.status).toBeLessThan(600);
        return this;
    }

    hasKey(...keys) {
        keys.forEach((key) => {
            expect(this.body).toHaveProperty(key);
        });
        return this;
    }

    hasData() {
        expect(this.body).toHaveProperty('data');
        return this;
    }

    dataEquals(expected) {
        expect(this.body.data).toEqual(expected);
        return this;
    }

    dataContains(expected) {
        expect(this.body.data).toMatchObject(expected);
        return this;
    }

    dataLength(expected) {
        expect(this.body.data).toHaveLength(expected);
        return this;
    }

    hasError(code) {
        expect(this.body.errors).toBeDefined();
        if (code) {
            const hasCode = this.body.errors.some((e) => e.code === code);
            expect(hasCode).toBe(true);
        }
        return this;
    }

    messageContains(text) {
        expect(this.body.message).toContain(text);
        return this;
    }

    paginationEquals(expected) {
        expect(this.body.pagination).toMatchObject(expected);
        return this;
    }
}

const assertResponse = (response) => new ResponseAssertions(response);

// ============================================================================
// Database Assertions
// ============================================================================

const assertExistsInDb = async (prisma, model, where) => {
    const record = await prisma[model].findFirst({ where });
    expect(record).not.toBeNull();
    return record;
};

const assertNotExistsInDb = async (prisma, model, where) => {
    const record = await prisma[model].findFirst({ where });
    expect(record).toBeNull();
};

const assertCountInDb = async (prisma, model, where, expected) => {
    const count = await prisma[model].count({ where });
    expect(count).toBe(expected);
};

const assertCreatedRecently = async (prisma, model, where, withinMs = 60000) => {
    const record = await prisma[model].findFirst({ where });
    expect(record).not.toBeNull();
    const diff = Date.now() - new Date(record.createdAt).getTime();
    expect(diff).toBeLessThan(withinMs);
    return record;
};

// ============================================================================
// Validation Helpers
// ============================================================================

const isValidEmail = (email) => {
    const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return pattern.test(email);
};

const isValidUUID = (value) => {
    const pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return pattern.test(value);
};

const isValidISODate = (value) => {
    const date = new Date(value);
    return date instanceof Date && !isNaN(date);
};

const isValidURL = (url) => {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
};

// Custom matchers
expect.extend({
    toBeValidEmail(received) {
        const pass = isValidEmail(received);
        return {
            message: () => `expected ${received} ${pass ? 'not ' : ''}to be a valid email`,
            pass,
        };
    },

    toBeValidUUID(received) {
        const pass = isValidUUID(received);
        return {
            message: () => `expected ${received} ${pass ? 'not ' : ''}to be a valid UUID`,
            pass,
        };
    },

    toBeValidISODate(received) {
        const pass = isValidISODate(received);
        return {
            message: () => `expected ${received} ${pass ? 'not ' : ''}to be a valid ISO date`,
            pass,
        };
    },

    toBeValidURL(received) {
        const pass = isValidURL(received);
        return {
            message: () => `expected ${received} ${pass ? 'not ' : ''}to be a valid URL`,
            pass,
        };
    },

    toBeWithinRange(received, floor, ceiling) {
        const pass = received >= floor && received <= ceiling;
        return {
            message: () => `expected ${received} ${pass ? 'not ' : ''}to be within range ${floor} - ${ceiling}`,
            pass,
        };
    },

    toMatchSchema(received, schema) {
        const errors = [];

        for (const [key, type] of Object.entries(schema)) {
            const isOptional = key.endsWith('?');
            const actualKey = isOptional ? key.slice(0, -1) : key;

            if (!(actualKey in received)) {
                if (!isOptional) {
                    errors.push(`missing required key: ${actualKey}`);
                }
                continue;
            }

            const value = received[actualKey];
            let valid = false;

            switch (type) {
                case 'string':
                    valid = typeof value === 'string';
                    break;
                case 'number':
                    valid = typeof value === 'number';
                    break;
                case 'boolean':
                    valid = typeof value === 'boolean';
                    break;
                case 'array':
                    valid = Array.isArray(value);
                    break;
                case 'object':
                    valid = typeof value === 'object' && !Array.isArray(value);
                    break;
                case 'email':
                    valid = isValidEmail(value);
                    break;
                case 'uuid':
                    valid = isValidUUID(value);
                    break;
                case 'date':
                    valid = isValidISODate(value);
                    break;
                default:
                    valid = true;
            }

            if (!valid) {
                errors.push(`${actualKey}: expected ${type}, got ${typeof value}`);
            }
        }

        return {
            message: () => errors.join('\n'),
            pass: errors.length === 0,
        };
    },
});

// ============================================================================
// Mock Helpers
// ============================================================================

const mockResolvedSequence = (mock, ...values) => {
    values.forEach((value, index) => {
        mock.mockResolvedValueOnce(value);
    });
};

const mockRejectedOnce = (mock, error) => {
    mock.mockRejectedValueOnce(error instanceof Error ? error : new Error(error));
};

const createMockResponse = (status = 200, data = {}) => ({
    status,
    ok: status >= 200 && status < 300,
    json: jest.fn().mockResolvedValue(data),
    text: jest.fn().mockResolvedValue(JSON.stringify(data)),
    headers: new Map(),
});

const assertMockCalledWith = (mock, expectedArgs) => {
    expect(mock).toHaveBeenCalled();
    const calls = mock.mock.calls;
    const lastCall = calls[calls.length - 1];
    expect(lastCall).toEqual(expect.arrayContaining(expectedArgs));
};

// ============================================================================
// Time Helpers
// ============================================================================

const advanceTime = (ms) => {
    jest.advanceTimersByTime(ms);
};

const freezeTime = (date = new Date()) => {
    jest.useFakeTimers();
    jest.setSystemTime(date);
    return () => jest.useRealTimers();
};

const assertRecentDate = (date, withinMs = 60000) => {
    const diff = Math.abs(Date.now() - new Date(date).getTime());
    expect(diff).toBeLessThan(withinMs);
};

const assertFutureDate = (date) => {
    expect(new Date(date).getTime()).toBeGreaterThan(Date.now());
};

const assertPastDate = (date) => {
    expect(new Date(date).getTime()).toBeLessThan(Date.now());
};

// ============================================================================
// Async Helpers
// ============================================================================

const waitFor = async (condition, options = {}) => {
    const { timeout = 5000, interval = 100 } = options;
    const start = Date.now();

    while (Date.now() - start < timeout) {
        if (await condition()) {
            return true;
        }
        await new Promise((resolve) => setTimeout(resolve, interval));
    }

    throw new Error('Condition not met within timeout');
};

const retry = async (fn, options = {}) => {
    const { attempts = 3, delay = 100 } = options;
    let lastError;

    for (let i = 0; i < attempts; i++) {
        try {
            return await fn();
        } catch (error) {
            lastError = error;
            if (i < attempts - 1) {
                await new Promise((resolve) => setTimeout(resolve, delay));
            }
        }
    }

    throw lastError;
};

const eventually = async (assertion, options = {}) => {
    const { timeout = 5000, interval = 100 } = options;

    await waitFor(async () => {
        try {
            await assertion();
            return true;
        } catch {
            return false;
        }
    }, { timeout, interval });
};

// ============================================================================
// Test Data Generators
// ============================================================================

const generateTestData = (count, generator) => {
    return Array.from({ length: count }, (_, i) => generator(i));
};

const randomElement = (array) => {
    return array[Math.floor(Math.random() * array.length)];
};

const randomInt = (min, max) => {
    return Math.floor(Math.random() * (max - min + 1)) + min;
};

// ============================================================================
// Exports
// ============================================================================

module.exports = {
    // Response assertions
    assertResponse,
    ResponseAssertions,

    // Database assertions
    assertExistsInDb,
    assertNotExistsInDb,
    assertCountInDb,
    assertCreatedRecently,

    // Validation
    isValidEmail,
    isValidUUID,
    isValidISODate,
    isValidURL,

    // Mocks
    mockResolvedSequence,
    mockRejectedOnce,
    createMockResponse,
    assertMockCalledWith,

    // Time
    advanceTime,
    freezeTime,
    assertRecentDate,
    assertFutureDate,
    assertPastDate,

    // Async
    waitFor,
    retry,
    eventually,

    // Generators
    generateTestData,
    randomElement,
    randomInt,
};
