/*
File: cache.tpl.js
Purpose: Redis caching utilities with ioredis
Generated for: {{PROJECT_NAME}}
*/

const Redis = require('ioredis');
const crypto = require('crypto');

class RedisCache {
    constructor(config = {}) {
        this.config = {
            host: config.host || 'localhost',
            port: config.port || 6379,
            db: config.db || 0,
            password: config.password,
            keyPrefix: config.keyPrefix || 'app:',
            defaultTTL: config.defaultTTL || 3600,
        };

        this.client = new Redis({
            host: this.config.host,
            port: this.config.port,
            db: this.config.db,
            password: this.config.password,
            retryStrategy: (times) => Math.min(times * 50, 2000),
        });
    }

    _key(key) {
        return `${this.config.keyPrefix}${key}`;
    }

    async get(key) {
        const value = await this.client.get(this._key(key));
        if (value) {
            try {
                return JSON.parse(value);
            } catch {
                return value;
            }
        }
        return null;
    }

    async set(key, value, ttl = null) {
        const serialized = JSON.stringify(value);
        const expiry = ttl || this.config.defaultTTL;
        await this.client.setex(this._key(key), expiry, serialized);
    }

    async delete(key) {
        await this.client.del(this._key(key));
    }

    async deletePattern(pattern) {
        const keys = await this.client.keys(this._key(pattern));
        if (keys.length > 0) {
            await this.client.del(...keys);
        }
        return keys.length;
    }

    async exists(key) {
        return (await this.client.exists(this._key(key))) > 0;
    }

    async incr(key, amount = 1) {
        return this.client.incrby(this._key(key), amount);
    }

    async expire(key, ttl) {
        await this.client.expire(this._key(key), ttl);
    }

    async getOrSet(key, factory, ttl = null) {
        const cached = await this.get(key);
        if (cached !== null) {
            return cached;
        }

        const value = await factory();
        await this.set(key, value, ttl);
        return value;
    }

    async disconnect() {
        await this.client.quit();
    }
}

// Cache decorator for functions
function cached(cache, keyPrefix, ttl = 3600, keyBuilder = null) {
    return function (target, propertyKey, descriptor) {
        const originalMethod = descriptor.value;

        descriptor.value = async function (...args) {
            let cacheKey;
            if (keyBuilder) {
                cacheKey = keyBuilder(...args);
            } else {
                const keyData = JSON.stringify(args);
                const hash = crypto.createHash('md5').update(keyData).digest('hex').slice(0, 12);
                cacheKey = `${keyPrefix}:${hash}`;
            }

            const cachedValue = await cache.get(cacheKey);
            if (cachedValue !== null) {
                return cachedValue;
            }

            const result = await originalMethod.apply(this, args);
            await cache.set(cacheKey, result, ttl);
            return result;
        };

        return descriptor;
    };
}

// Functional wrapper for caching
function withCache(cache, keyPrefix, ttl = 3600) {
    return function (fn) {
        return async function (...args) {
            const keyData = JSON.stringify(args);
            const hash = crypto.createHash('md5').update(keyData).digest('hex').slice(0, 12);
            const cacheKey = `${keyPrefix}:${hash}`;

            const cachedValue = await cache.get(cacheKey);
            if (cachedValue !== null) {
                return cachedValue;
            }

            const result = await fn(...args);
            await cache.set(cacheKey, result, ttl);
            return result;
        };
    };
}

module.exports = {
    RedisCache,
    cached,
    withCache,
};

// Usage:
// const cache = new RedisCache({ keyPrefix: 'myapp:' });
// const getUser = withCache(cache, 'users', 300)(async (id) => {
//   return await db.findUser(id);
// });
