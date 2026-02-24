/*
File: caching.tpl.js
Purpose: Redis caching patterns with decorators and utilities
Generated for: {{PROJECT_NAME}}
*/

const { createClient } = require('redis');
const crypto = require('crypto');

// ============================================================================
// Redis Client Manager
// ============================================================================

class RedisManager {
    static client = null;

    static async getClient() {
        if (!this.client) {
            this.client = createClient({
                url: process.env.REDIS_URL || 'redis://localhost:6379/0',
            });
            this.client.on('error', (err) => console.error('Redis error:', err));
            await this.client.connect();
        }
        return this.client;
    }

    static async close() {
        if (this.client) {
            await this.client.quit();
            this.client = null;
        }
    }
}

// ============================================================================
// Cache Key Builder
// ============================================================================

class CacheKeyBuilder {
    constructor(prefix = 'app') {
        this.prefix = prefix;
    }

    build(...parts) {
        return [this.prefix, ...parts].join(':');
    }

    fromFunction(fnName, args, keyPrefix = null) {
        const prefix = keyPrefix || fnName;
        const argsHash = this.hashValue(args);
        return this.build(prefix, argsHash);
    }

    hashValue(value) {
        const serialized = JSON.stringify(value);
        return crypto.createHash('md5').update(serialized).digest('hex').slice(0, 12);
    }
}

const keyBuilder = new CacheKeyBuilder();

// ============================================================================
// Cache Decorators (for class methods)
// ============================================================================

/**
 * Cache decorator for class methods
 * @param {Object} options - Cache options
 * @param {number} options.ttl - Time to live in seconds
 * @param {string} options.keyPrefix - Custom key prefix
 * @param {Function} options.keyGenerator - Custom key generator function
 */
function cached(options = {}) {
    const { ttl = 300, keyPrefix, keyGenerator } = options;

    return function (target, propertyKey, descriptor) {
        const originalMethod = descriptor.value;

        descriptor.value = async function (...args) {
            const client = await RedisManager.getClient();

            // Generate cache key
            const cacheKey = keyGenerator
                ? keyGenerator.call(this, ...args)
                : keyBuilder.fromFunction(
                    `${target.constructor.name}.${propertyKey}`,
                    args,
                    keyPrefix
                );

            // Try to get from cache
            const cached = await client.get(cacheKey);
            if (cached !== null) {
                return JSON.parse(cached);
            }

            // Call original method
            const result = await originalMethod.apply(this, args);

            // Store in cache
            await client.set(cacheKey, JSON.stringify(result), { EX: ttl });

            return result;
        };

        // Add cache invalidation method
        descriptor.value.invalidate = async function (...args) {
            const client = await RedisManager.getClient();
            const cacheKey = keyGenerator
                ? keyGenerator.call(this, ...args)
                : keyBuilder.fromFunction(
                    `${target.constructor.name}.${propertyKey}`,
                    args,
                    keyPrefix
                );
            await client.del(cacheKey);
        };

        return descriptor;
    };
}

/**
 * Cache-aside pattern wrapper
 */
async function cacheAside(key, ttl, factory) {
    const client = await RedisManager.getClient();
    const fullKey = keyBuilder.build(key);

    // Try get from cache
    const cached = await client.get(fullKey);
    if (cached !== null) {
        return JSON.parse(cached);
    }

    // Compute value
    const value = await factory();

    // Store in cache
    if (value !== null && value !== undefined) {
        await client.set(fullKey, JSON.stringify(value), { EX: ttl });
    }

    return value;
}

// ============================================================================
// Cache Manager
// ============================================================================

class CacheManager {
    constructor(prefix = 'cache') {
        this.prefix = prefix;
        this.keyBuilder = new CacheKeyBuilder(prefix);
    }

    async get(key) {
        const client = await RedisManager.getClient();
        const fullKey = this.keyBuilder.build(key);
        const value = await client.get(fullKey);
        return value ? JSON.parse(value) : null;
    }

    async set(key, value, ttl = 300) {
        const client = await RedisManager.getClient();
        const fullKey = this.keyBuilder.build(key);
        await client.set(fullKey, JSON.stringify(value), { EX: ttl });
    }

    async delete(key) {
        const client = await RedisManager.getClient();
        const fullKey = this.keyBuilder.build(key);
        await client.del(fullKey);
    }

    async deletePattern(pattern) {
        const client = await RedisManager.getClient();
        const fullPattern = this.keyBuilder.build(pattern);

        let cursor = 0;
        do {
            const result = await client.scan(cursor, { MATCH: fullPattern, COUNT: 100 });
            cursor = result.cursor;
            if (result.keys.length > 0) {
                await client.del(result.keys);
            }
        } while (cursor !== 0);
    }

    async getOrSet(key, factory, ttl = 300) {
        let value = await this.get(key);
        if (value !== null) {
            return value;
        }

        value = await factory();
        await this.set(key, value, ttl);
        return value;
    }

    async exists(key) {
        const client = await RedisManager.getClient();
        const fullKey = this.keyBuilder.build(key);
        return (await client.exists(fullKey)) > 0;
    }

    async ttl(key) {
        const client = await RedisManager.getClient();
        const fullKey = this.keyBuilder.build(key);
        return client.ttl(fullKey);
    }

    async increment(key, amount = 1) {
        const client = await RedisManager.getClient();
        const fullKey = this.keyBuilder.build(key);
        return client.incrBy(fullKey, amount);
    }

    async clearAll() {
        await this.deletePattern('*');
    }
}

const cache = new CacheManager();

// ============================================================================
// Specialized Caches
// ============================================================================

class UserCache {
    static TTL = 300; // 5 minutes

    static async getUser(userId) {
        return cache.get(`user:${userId}`);
    }

    static async setUser(userId, userData) {
        await cache.set(`user:${userId}`, userData, this.TTL);
    }

    static async invalidateUser(userId) {
        await cache.delete(`user:${userId}`);
    }

    static async invalidateAll() {
        await cache.deletePattern('user:*');
    }
}

class SessionCache {
    static TTL = 86400; // 24 hours

    static async getSession(tokenHash) {
        return cache.get(`session:${tokenHash}`);
    }

    static async setSession(tokenHash, sessionData, ttl = this.TTL) {
        await cache.set(`session:${tokenHash}`, sessionData, ttl);
    }

    static async deleteSession(tokenHash) {
        await cache.delete(`session:${tokenHash}`);
    }

    static async deleteUserSessions(userId) {
        await cache.deletePattern(`session:*:user:${userId}`);
    }
}

class QueryCache {
    static TTL = 60; // 1 minute

    static buildKey(queryName, params) {
        const hash = keyBuilder.hashValue(params);
        return `query:${queryName}:${hash}`;
    }

    static async get(queryName, params) {
        const key = this.buildKey(queryName, params);
        return cache.get(key);
    }

    static async set(queryName, params, result, ttl = this.TTL) {
        const key = this.buildKey(queryName, params);
        await cache.set(key, result, ttl);
    }

    static async invalidate(queryName) {
        await cache.deletePattern(`query:${queryName}:*`);
    }
}

// ============================================================================
// Rate Limiting
// ============================================================================

class RateLimiter {
    constructor(options = {}) {
        this.keyPrefix = options.keyPrefix || 'ratelimit';
    }

    async check(key, limit, windowSeconds) {
        const client = await RedisManager.getClient();
        const fullKey = `${this.keyPrefix}:${key}`;

        const current = await client.get(fullKey);

        if (current === null) {
            await client.set(fullKey, 1, { EX: windowSeconds });
            return { allowed: true, remaining: limit - 1 };
        }

        const count = parseInt(current, 10);
        if (count >= limit) {
            const ttl = await client.ttl(fullKey);
            return { allowed: false, remaining: 0, retryAfter: ttl };
        }

        await client.incr(fullKey);
        return { allowed: true, remaining: limit - count - 1 };
    }

    async reset(key) {
        const client = await RedisManager.getClient();
        await client.del(`${this.keyPrefix}:${key}`);
    }
}

// ============================================================================
// Distributed Lock
// ============================================================================

class DistributedLock {
    constructor(options = {}) {
        this.keyPrefix = options.keyPrefix || 'lock';
        this.defaultTTL = options.defaultTTL || 30;
    }

    async acquire(lockName, ttl = this.defaultTTL) {
        const client = await RedisManager.getClient();
        const key = `${this.keyPrefix}:${lockName}`;
        const lockId = crypto.randomBytes(16).toString('hex');

        const acquired = await client.set(key, lockId, {
            NX: true,
            EX: ttl,
        });

        if (acquired) {
            return {
                acquired: true,
                lockId,
                release: async () => {
                    // Only release if we still own the lock
                    const currentValue = await client.get(key);
                    if (currentValue === lockId) {
                        await client.del(key);
                    }
                },
            };
        }

        return { acquired: false };
    }

    async withLock(lockName, fn, options = {}) {
        const { ttl = this.defaultTTL, retries = 3, retryDelay = 100 } = options;

        for (let i = 0; i < retries; i++) {
            const lock = await this.acquire(lockName, ttl);

            if (lock.acquired) {
                try {
                    return await fn();
                } finally {
                    await lock.release();
                }
            }

            if (i < retries - 1) {
                await new Promise((resolve) => setTimeout(resolve, retryDelay));
            }
        }

        throw new Error(`Failed to acquire lock: ${lockName}`);
    }
}

// ============================================================================
// Cache Middleware for Express
// ============================================================================

function cacheMiddleware(options = {}) {
    const { ttl = 60, keyGenerator } = options;

    return async (req, res, next) => {
        // Skip non-GET requests
        if (req.method !== 'GET') {
            return next();
        }

        const key = keyGenerator
            ? keyGenerator(req)
            : `route:${req.originalUrl}`;

        try {
            const cached = await cache.get(key);
            if (cached !== null) {
                return res.json(cached);
            }

            // Store original json function
            const originalJson = res.json.bind(res);

            // Override json to cache the response
            res.json = (body) => {
                cache.set(key, body, ttl).catch(console.error);
                return originalJson(body);
            };

            next();
        } catch (error) {
            next();
        }
    };
}

// ============================================================================
// Exports
// ============================================================================

module.exports = {
    RedisManager,
    CacheKeyBuilder,
    keyBuilder,
    cached,
    cacheAside,
    CacheManager,
    cache,
    UserCache,
    SessionCache,
    QueryCache,
    RateLimiter,
    DistributedLock,
    cacheMiddleware,
};
