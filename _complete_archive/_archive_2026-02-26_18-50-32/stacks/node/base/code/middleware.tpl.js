/*
File: middleware.tpl.js
Purpose: Express middleware for common patterns
Generated for: {{PROJECT_NAME}}
*/

const { v4: uuidv4 } = require('uuid');

/**
 * Request ID middleware - adds unique ID to each request
 */
function requestId() {
    return (req, res, next) => {
        req.id = req.headers['x-request-id'] || uuidv4();
        res.setHeader('X-Request-ID', req.id);
        next();
    };
}

/**
 * Request logging middleware
 */
function requestLogger(options = {}) {
    const { logger = console } = options;

    return (req, res, next) => {
        const start = Date.now();

        res.on('finish', () => {
            const duration = Date.now() - start;
            logger.info({
                requestId: req.id,
                method: req.method,
                path: req.path,
                statusCode: res.statusCode,
                duration: `${duration}ms`,
            });
        });

        next();
    };
}

/**
 * Rate limiting middleware (in-memory, use Redis in production)
 */
function rateLimit(options = {}) {
    const {
        windowMs = 60000, // 1 minute
        max = 100, // requests per window
        message = 'Too many requests, please try again later',
    } = options;

    const requests = new Map();

    // Cleanup old entries every minute
    setInterval(() => {
        const now = Date.now();
        for (const [key, data] of requests.entries()) {
            if (now - data.firstRequest > windowMs) {
                requests.delete(key);
            }
        }
    }, windowMs);

    return (req, res, next) => {
        const key = req.ip;
        const now = Date.now();

        if (!requests.has(key)) {
            requests.set(key, { count: 1, firstRequest: now });
        } else {
            const data = requests.get(key);
            if (now - data.firstRequest > windowMs) {
                requests.set(key, { count: 1, firstRequest: now });
            } else {
                data.count++;
            }
        }

        const data = requests.get(key);
        const remaining = Math.max(0, max - data.count);

        res.setHeader('X-RateLimit-Limit', max);
        res.setHeader('X-RateLimit-Remaining', remaining);
        res.setHeader('X-RateLimit-Reset', Math.ceil((data.firstRequest + windowMs) / 1000));

        if (data.count > max) {
            res.status(429).json({ error: message });
            return;
        }

        next();
    };
}

/**
 * Error handling middleware
 */
function errorHandler(options = {}) {
    const { logger = console, showStack = process.env.NODE_ENV !== 'production' } = options;

    return (err, req, res, next) => {
        logger.error({
            requestId: req.id,
            error: err.message,
            stack: err.stack,
        });

        const statusCode = err.statusCode || err.status || 500;
        const response = {
            error: {
                message: err.message || 'Internal Server Error',
                code: err.code || 'INTERNAL_ERROR',
            },
        };

        if (showStack) {
            response.error.stack = err.stack;
        }

        res.status(statusCode).json(response);
    };
}

/**
 * Not found handler
 */
function notFound() {
    return (req, res) => {
        res.status(404).json({
            error: {
                message: 'Resource not found',
                code: 'NOT_FOUND',
                path: req.path,
            },
        });
    };
}

/**
 * Security headers middleware
 */
function securityHeaders() {
    return (req, res, next) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        res.removeHeader('X-Powered-By');
        next();
    };
}

/**
 * Response time header middleware
 */
function responseTime() {
    return (req, res, next) => {
        const start = process.hrtime();

        res.on('finish', () => {
            const diff = process.hrtime(start);
            const time = (diff[0] * 1e3 + diff[1] * 1e-6).toFixed(2);
            res.setHeader('X-Response-Time', `${time}ms`);
        });

        next();
    };
}

/**
 * Setup all middleware
 */
function setupMiddleware(app) {
    app.use(requestId());
    app.use(responseTime());
    app.use(requestLogger());
    app.use(securityHeaders());
    app.use(rateLimit());
}

module.exports = {
    requestId,
    requestLogger,
    rateLimit,
    errorHandler,
    notFound,
    securityHeaders,
    responseTime,
    setupMiddleware,
};

// Usage:
// const express = require('express');
// const { setupMiddleware, errorHandler, notFound } = require('./middleware');
//
// const app = express();
// setupMiddleware(app);
// // ... routes ...
// app.use(notFound());
// app.use(errorHandler());
