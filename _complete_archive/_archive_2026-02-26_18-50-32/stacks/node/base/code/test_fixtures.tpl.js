/*
File: test_fixtures.tpl.js
Purpose: Comprehensive Jest/Vitest fixtures and setup
Generated for: {{PROJECT_NAME}}
*/

const { PrismaClient } = require('@prisma/client');
const { createClient } = require('redis');
const { faker } = require('@faker-js/faker');

// ============================================================================
// Database Setup
// ============================================================================

let prisma = null;

const getPrisma = () => {
    if (!prisma) {
        prisma = new PrismaClient({
            datasources: {
                db: { url: process.env.TEST_DATABASE_URL || process.env.DATABASE_URL },
            },
        });
    }
    return prisma;
};

const setupDatabase = async () => {
    const db = getPrisma();
    // Run migrations or reset database
    // await db.$executeRaw`TRUNCATE TABLE users, posts, sessions CASCADE`;
    return db;
};

const teardownDatabase = async () => {
    if (prisma) {
        await prisma.$disconnect();
        prisma = null;
    }
};

const cleanDatabase = async () => {
    const db = getPrisma();
    const tables = ['sessions', 'posts', 'tags', 'users'];

    for (const table of tables) {
        try {
            await db.$executeRawUnsafe(`TRUNCATE TABLE "${table}" CASCADE`);
        } catch (e) {
            // Table might not exist
        }
    }
};

// Transaction wrapper for test isolation
const withTransaction = async (fn) => {
    const db = getPrisma();
    return db.$transaction(async (tx) => {
        const result = await fn(tx);
        throw new Error('ROLLBACK'); // Force rollback
    }).catch((e) => {
        if (e.message !== 'ROLLBACK') throw e;
    });
};

// ============================================================================
// Redis Setup
// ============================================================================

let redis = null;

const getRedis = async () => {
    if (!redis) {
        redis = createClient({
            url: process.env.TEST_REDIS_URL || 'redis://localhost:6379/1',
        });
        await redis.connect();
    }
    return redis;
};

const cleanRedis = async () => {
    const client = await getRedis();
    await client.flushDb();
};

const teardownRedis = async () => {
    if (redis) {
        await redis.quit();
        redis = null;
    }
};

// ============================================================================
// Factories
// ============================================================================

const createUserData = (overrides = {}) => ({
    email: faker.internet.email(),
    username: faker.internet.userName(),
    passwordHash: '$2b$12$test.hash.here', // Pre-hashed for speed
    fullName: faker.person.fullName(),
    isActive: true,
    isVerified: true,
    ...overrides,
});

const createUser = async (db, overrides = {}) => {
    return db.user.create({
        data: createUserData(overrides),
    });
};

const createUsers = async (db, count, overrides = {}) => {
    const users = [];
    for (let i = 0; i < count; i++) {
        users.push(await createUser(db, overrides));
    }
    return users;
};

const createPostData = (authorId, overrides = {}) => ({
    authorId,
    title: faker.lorem.sentence(),
    slug: faker.helpers.slugify(faker.lorem.sentence()),
    content: faker.lorem.paragraphs(3),
    excerpt: faker.lorem.paragraph(),
    status: 'published',
    ...overrides,
});

const createPost = async (db, authorId, overrides = {}) => {
    return db.post.create({
        data: createPostData(authorId, overrides),
    });
};

const createPosts = async (db, authorId, count, overrides = {}) => {
    const posts = [];
    for (let i = 0; i < count; i++) {
        posts.push(await createPost(db, authorId, overrides));
    }
    return posts;
};

const createSession = async (db, userId, overrides = {}) => {
    return db.session.create({
        data: {
            userId,
            tokenHash: faker.string.alphanumeric(64),
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
            ...overrides,
        },
    });
};

// ============================================================================
// Authentication Helpers
// ============================================================================

const jwt = require('jsonwebtoken');

const createAuthToken = (userId, options = {}) => {
    return jwt.sign(
        { sub: userId, ...options.claims },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: options.expiresIn || '1h' }
    );
};

const createExpiredToken = (userId) => {
    return jwt.sign(
        { sub: userId },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '-1h' }
    );
};

const authHeader = (token) => ({
    Authorization: `Bearer ${token}`,
});

// ============================================================================
// HTTP Test Helpers
// ============================================================================

const supertest = require('supertest');

const createTestClient = (app) => {
    const agent = supertest(app);

    return {
        get: (url, headers = {}) => agent.get(url).set(headers),
        post: (url, body, headers = {}) => agent.post(url).send(body).set(headers),
        put: (url, body, headers = {}) => agent.put(url).send(body).set(headers),
        patch: (url, body, headers = {}) => agent.patch(url).send(body).set(headers),
        delete: (url, headers = {}) => agent.delete(url).set(headers),

        // Authenticated requests
        authGet: (url, token) => agent.get(url).set(authHeader(token)),
        authPost: (url, body, token) => agent.post(url).send(body).set(authHeader(token)),
        authPut: (url, body, token) => agent.put(url).send(body).set(authHeader(token)),
        authPatch: (url, body, token) => agent.patch(url).send(body).set(authHeader(token)),
        authDelete: (url, token) => agent.delete(url).set(authHeader(token)),
    };
};

// ============================================================================
// Mock Factories
// ============================================================================

const createMockEmailService = () => ({
    sendEmail: jest.fn().mockResolvedValue({ messageId: 'test-123' }),
    sendTemplate: jest.fn().mockResolvedValue({ messageId: 'test-123' }),
    sendBulk: jest.fn().mockResolvedValue({ sent: 10, failed: 0 }),
});

const createMockPaymentService = () => ({
    createCustomer: jest.fn().mockResolvedValue({ id: 'cus_test123' }),
    createSubscription: jest.fn().mockResolvedValue({ id: 'sub_test123', status: 'active' }),
    createPaymentIntent: jest.fn().mockResolvedValue({ clientSecret: 'secret_test' }),
    cancelSubscription: jest.fn().mockResolvedValue({ status: 'canceled' }),
    retrieveSubscription: jest.fn().mockResolvedValue({ id: 'sub_test123', status: 'active' }),
});

const createMockStorageService = () => ({
    upload: jest.fn().mockResolvedValue({ url: 'https://storage.test/file.pdf', key: 'file.pdf' }),
    download: jest.fn().mockResolvedValue(Buffer.from('file content')),
    delete: jest.fn().mockResolvedValue(true),
    getSignedUrl: jest.fn().mockResolvedValue('https://storage.test/signed/file.pdf'),
});

const createMockQueueService = () => ({
    add: jest.fn().mockResolvedValue({ id: 'job-123' }),
    getJob: jest.fn().mockResolvedValue({ id: 'job-123', status: 'completed' }),
    remove: jest.fn().mockResolvedValue(true),
});

const createMockRedis = () => ({
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockResolvedValue('OK'),
    del: jest.fn().mockResolvedValue(1),
    expire: jest.fn().mockResolvedValue(1),
    incr: jest.fn().mockResolvedValue(1),
    hGet: jest.fn().mockResolvedValue(null),
    hSet: jest.fn().mockResolvedValue(1),
    hGetAll: jest.fn().mockResolvedValue({}),
});

// ============================================================================
// Jest Setup Helpers
// ============================================================================

const setupTestEnvironment = () => {
    beforeAll(async () => {
        await setupDatabase();
    });

    afterAll(async () => {
        await teardownDatabase();
        await teardownRedis();
    });

    beforeEach(async () => {
        await cleanDatabase();
        await cleanRedis();
    });
};

// ============================================================================
// Exports
// ============================================================================

module.exports = {
    // Database
    getPrisma,
    setupDatabase,
    teardownDatabase,
    cleanDatabase,
    withTransaction,

    // Redis
    getRedis,
    cleanRedis,
    teardownRedis,

    // Factories
    createUserData,
    createUser,
    createUsers,
    createPostData,
    createPost,
    createPosts,
    createSession,

    // Auth
    createAuthToken,
    createExpiredToken,
    authHeader,

    // HTTP
    createTestClient,

    // Mocks
    createMockEmailService,
    createMockPaymentService,
    createMockStorageService,
    createMockQueueService,
    createMockRedis,

    // Setup
    setupTestEnvironment,

    // Re-export faker
    faker,
};
