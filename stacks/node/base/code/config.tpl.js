/*
File: config.tpl.js
Purpose: Environment-based configuration for Node.js
Generated for: {{PROJECT_NAME}}
*/

require('dotenv').config();

const env = process.env.NODE_ENV || 'development';

const config = {
    // App settings
    app: {
        name: process.env.APP_NAME || '{{PROJECT_NAME}}',
        version: process.env.APP_VERSION || '1.0.0',
        env,
        debug: process.env.DEBUG === 'true',
        port: parseInt(process.env.PORT || '3000', 10),
        host: process.env.HOST || '0.0.0.0',
        apiPrefix: process.env.API_PREFIX || '/api/v1',
    },

    // Database settings
    database: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432', 10),
        name: process.env.DB_NAME || 'app',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || '',
        get url() {
            return `postgresql://${this.user}:${this.password}@${this.host}:${this.port}/${this.name}`;
        },
    },

    // Redis settings
    redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT || '6379', 10),
        db: parseInt(process.env.REDIS_DB || '0', 10),
        password: process.env.REDIS_PASSWORD || undefined,
    },

    // Auth settings
    auth: {
        jwtSecret: process.env.JWT_SECRET || 'change-me-in-production',
        jwtAlgorithm: process.env.JWT_ALGORITHM || 'HS256',
        accessTokenExpireMinutes: parseInt(process.env.ACCESS_TOKEN_EXPIRE_MINUTES || '30', 10),
        refreshTokenExpireDays: parseInt(process.env.REFRESH_TOKEN_EXPIRE_DAYS || '7', 10),
    },

    // CORS settings
    cors: {
        origins: (process.env.CORS_ORIGINS || 'http://localhost:3000').split(','),
        credentials: true,
    },

    // Helper methods
    isProduction() {
        return env === 'production';
    },

    isDevelopment() {
        return env === 'development';
    },

    isTest() {
        return env === 'test';
    },
};

// Validate required config in production
function validateConfig() {
    const required = [
        'JWT_SECRET',
        'DB_PASSWORD',
    ];

    if (config.isProduction()) {
        const missing = required.filter(key => !process.env[key]);
        if (missing.length > 0) {
            throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
        }
    }
}

validateConfig();

module.exports = config;

// Usage:
// const config = require('./config');
// console.log(config.database.url);
// console.log(config.auth.jwtSecret);
