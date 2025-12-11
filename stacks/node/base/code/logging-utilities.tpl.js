/**
 * File: logging-utilities.tpl.js
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

#!/usr/bin/env node
/**
 * Node.js Logging Utilities Template
 * Purpose: Reusable logging setup and utilities for Node.js projects
 * Usage: Import and configure for structured logging across the application
 */

const winston = require('winston');
const path = require('path');
const fs = require('fs');

/**
 * Custom JSON formatter for structured logging
 */
class StructuredFormatter {
    constructor(options = {}) {
        this.options = {
            includeTimestamp: options.includeTimestamp !== false,
            includeLevel: options.includeLevel !== false,
            includeLogger: options.includeLogger !== false,
            ...options
        };
    }

    transform(info) {
        const log = {};

        if (this.options.includeTimestamp) {
            log.timestamp = info.timestamp;
        }

        if (this.options.includeLevel) {
            log.level = info.level;
        }

        if (this.options.includeLogger) {
            log.logger = info.label || 'app';
        }

        log.message = info.message;

        // Add custom fields
        Object.keys(info).forEach(key => {
            if (!['timestamp', 'level', 'label', 'message'].includes(key)) {
                log[key] = info[key];
            }
        });

        return log;
    }
}

/**
 * Colored console formatter for development
 */
class ColoredConsoleFormatter {
    constructor() {
        this.colors = {
            error: '\x1b[31m',    // Red
            warn: '\x1b[33m',     // Yellow
            info: '\x1b[36m',     // Cyan
            debug: '\x1b[37m',    // White
            reset: '\x1b[0m'      // Reset
        };
    }

    transform(info) {
        const color = this.colors[info.level] || this.colors.reset;
        const reset = this.colors.reset;
        
        return `${color}${info.timestamp} [${info.label}] ${info.level.toUpperCase()}: ${info.message}${reset}`;
    }
}

/**
 * Logger Manager for centralized logging configuration
 */
class LoggerManager {
    constructor(options = {}) {
        this.appName = options.appName || 'myapp';
        this.loggers = new Map();
        this.transports = new Map();
        this.defaultLevel = options.defaultLevel || 'info';
        this.setupRootLogger();
    }

    /**
     * Setup root logger with basic configuration
     */
    setupRootLogger() {
        const rootLogger = winston.createLogger({
            level: 'debug',
            transports: []
        });

        this.loggers.set('root', rootLogger);
    }

    /**
     * Create logger with specified configuration
     */
    createLogger(name, options = {}) {
        if (this.loggers.has(name)) {
            return this.loggers.get(name);
        }

        const {
            level = this.defaultLevel,
            console = true,
            file = false,
            structured = false,
            filePath = null
        } = options;

        const transports = [];

        // Console transport
        if (console) {
            const consoleTransport = new winston.transports.Console({
                level,
                format: winston.format.combine(
                    winston.format.timestamp(),
                    winston.format.label({ label: `${this.appName}.${name}` }),
                    winston.format.printf(info => {
                        if (structured) {
                            return JSON.stringify(new StructuredFormatter().transform(info));
                        } else {
                            return new ColoredConsoleFormatter().transform(info);
                        }
                    })
                )
            });
            transports.push(consoleTransport);
        }

        // File transport
        if (file) {
            const logDir = path.dirname(filePath || `logs/${name}.log`);
            
            // Ensure log directory exists
            if (!fs.existsSync(logDir)) {
                fs.mkdirSync(logDir, { recursive: true });
            }

            const fileTransport = new winston.transports.File({
                filename: filePath || `logs/${name}.log`,
                level,
                format: winston.format.combine(
                    winston.format.timestamp(),
                    winston.format.label({ label: `${this.appName}.${name}` }),
                    winston.format.printf(info => {
                        if (structured) {
                            return JSON.stringify(new StructuredFormatter().transform(info));
                        } else {
                            return `${info.timestamp} [${info.label}] ${info.level.toUpperCase()}: ${info.message}`;
                        }
                    })
                ),
                maxsize: 10 * 1024 * 1024, // 10MB
                maxFiles: 5
            });
            transports.push(fileTransport);
        }

        const logger = winston.createLogger({
            level,
            transports,
            exitOnError: false
        });

        this.loggers.set(name, logger);
        return logger;
    }

    /**
     * Get existing logger or create default
     */
    getLogger(name) {
        if (this.loggers.has(name)) {
            return this.loggers.get(name);
        }
        return this.createLogger(name);
    }

    /**
     * Setup logging for different environments
     */
    setupForEnvironment(env = 'development') {
        switch (env) {
            case 'production':
                return this.createLogger('app', {
                    level: 'info',
                    console: false,
                    file: true,
                    structured: true,
                    filePath: 'logs/app.log'
                });

            case 'test':
                return this.createLogger('test', {
                    level: 'error',
                    console: true,
                    file: false,
                    structured: false
                });

            default: // development
                return this.createLogger('app', {
                    level: 'debug',
                    console: true,
                    file: false,
                    structured: false
                });
        }
    }
}

/**
 * Express middleware for request logging
 */
function requestLogger(logger, options = {}) {
    const {
        excludeRoutes = ['/health', '/metrics'],
        includeBody = false,
        includeHeaders = false
    } = options;

    return (req, res, next) => {
        if (excludeRoutes.includes(req.path)) {
            return next();
        }

        const startTime = Date.now();
        const requestId = req.headers['x-request-id'] || generateRequestId();

        // Log request
        const requestLog = {
            requestId,
            method: req.method,
            url: req.url,
            userAgent: req.headers['user-agent'],
            ip: req.ip || req.connection.remoteAddress
        };

        if (includeHeaders) {
            requestLog.headers = req.headers;
        }

        if (includeBody && req.body) {
            requestLog.body = req.body;
        }

        logger.info('Incoming request', requestLog);

        // Capture response
        const originalSend = res.send;
        res.send = function(data) {
            const duration = Date.now() - startTime;
            
            const responseLog = {
                requestId,
                statusCode: res.statusCode,
                duration: `${duration}ms`,
                contentLength: data ? data.length : 0
            };

            if (res.statusCode >= 400) {
                logger.error('Request failed', responseLog);
            } else {
                logger.info('Request completed', responseLog);
            }

            return originalSend.call(this, data);
        };

        next();
    };
}

/**
 * Error logging middleware
 */
function errorLogger(logger) {
    return (err, req, res, next) => {
        const errorLog = {
            message: err.message,
            stack: err.stack,
            url: req.url,
            method: req.method,
            userAgent: req.headers['user-agent'],
            ip: req.ip || req.connection.remoteAddress,
            body: req.body,
            headers: req.headers
        };

        logger.error('Unhandled error', errorLog);
        next(err);
    };
}

/**
 * Performance logging decorator
 */
function logPerformance(logger, operationName) {
    return function(target, propertyName, descriptor) {
        const originalMethod = descriptor.value;

        descriptor.value = function(...args) {
            const startTime = Date.now();
            
            try {
                const result = originalMethod.apply(this, args);
                
                if (result && typeof result.then === 'function') {
                    // Handle async methods
                    return result
                        .then(res => {
                            const duration = Date.now() - startTime;
                            logger.info(`${operationName} completed`, { duration: `${duration}ms` });
                            return res;
                        })
                        .catch(err => {
                            const duration = Date.now() - startTime;
                            logger.error(`${operationName} failed`, { duration: `${duration}ms`, error: err.message });
                            throw err;
                        });
                } else {
                    // Handle sync methods
                    const duration = Date.now() - startTime;
                    logger.info(`${operationName} completed`, { duration: `${duration}ms` });
                    return result;
                }
            } catch (err) {
                const duration = Date.now() - startTime;
                logger.error(`${operationName} failed`, { duration: `${duration}ms`, error: err.message });
                throw err;
            }
        };

        return descriptor;
    };
}

/**
 * Utility functions
 */
function generateRequestId() {
    return Math.random().toString(36).substr(2, 9);
}

/**
 * Create logger with context
 */
function createContextLogger(baseLogger, context) {
    return {
        debug: (message, meta = {}) => baseLogger.debug(message, { ...context, ...meta }),
        info: (message, meta = {}) => baseLogger.info(message, { ...context, ...meta }),
        warn: (message, meta = {}) => baseLogger.warn(message, { ...context, ...meta }),
        error: (message, meta = {}) => baseLogger.error(message, { ...context, ...meta })
    };
}

/**
 * Log aggregation utilities
 */
class LogAggregator {
    constructor(logger, windowSize = 60000) { // 1 minute window
        this.logger = logger;
        this.windowSize = windowSize;
        this.metrics = {
            requests: 0,
            errors: 0,
            warnings: 0,
            responseTime: []
        };
        this.lastReset = Date.now();
    }

    recordRequest(duration) {
        this._resetIfNeeded();
        this.metrics.requests++;
        this.metrics.responseTime.push(duration);
    }

    recordError() {
        this._resetIfNeeded();
        this.metrics.errors++;
    }

    recordWarning() {
        this._resetIfNeeded();
        this.metrics.warnings++;
    }

    _resetIfNeeded() {
        const now = Date.now();
        if (now - this.lastReset > this.windowSize) {
            this._logMetrics();
            this._resetMetrics();
            this.lastReset = now;
        }
    }

    _logMetrics() {
        const avgResponseTime = this.metrics.responseTime.length > 0
            ? this.metrics.responseTime.reduce((a, b) => a + b, 0) / this.metrics.responseTime.length
            : 0;

        this.logger.info('Performance metrics', {
            requests: this.metrics.requests,
            errors: this.metrics.errors,
            warnings: this.metrics.warnings,
            avgResponseTime: `${avgResponseTime.toFixed(2)}ms`,
            window: `${this.windowSize / 1000}s`
        });
    }

    _resetMetrics() {
        this.metrics = {
            requests: 0,
            errors: 0,
            warnings: 0,
            responseTime: []
        };
    }
}

// Example usage
if (require.main === module) {
    async function main() {
        try {
            // Create logger manager
            const loggerManager = new LoggerManager({ appName: 'MyApp' });

            // Setup loggers for different environments
            const devLogger = loggerManager.setupForEnvironment('development');
            const prodLogger = loggerManager.setupForEnvironment('production');

            // Test logging
            devLogger.info('Development logging initialized');
            devLogger.debug('Debug message for development');
            devLogger.warn('Warning message');
            devLogger.error('Error message');

            // Test structured logging
            prodLogger.info('Production logging initialized', {
                version: '1.0.0',
                environment: 'production'
            });

            // Test context logger
            const contextLogger = createContextLogger(devLogger, { userId: '123', sessionId: 'abc' });
            contextLogger.info('User action performed', { action: 'login' });

            // Test performance logging
            class TestService {
                @logPerformance(devLogger, 'database operation')
                async slowOperation() {
                    await new Promise(resolve => setTimeout(resolve, 100));
                    return 'completed';
                }
            }

            const service = new TestService();
            await service.slowOperation();

            console.log('Logging utilities demo completed');

        } catch (error) {
            console.error('Logging demo error:', error.message);
        }
    }

    main();
}

module.exports = {
    LoggerManager,
    StructuredFormatter,
    ColoredConsoleFormatter,
    requestLogger,
    errorLogger,
    logPerformance,
    createContextLogger,
    LogAggregator,
    generateRequestId
};
