/**
 * Template: error-handling.tpl.js
 * Purpose: error-handling template
 * Stack: node
 * Tier: base
 */

# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: Error handling utilities
# Tier: base
# Stack: node
# Category: utilities

#!/usr/bin/env node
/**
 * Node.js Error Handling Template
 * Purpose: Reusable error handling patterns and utilities for Node.js projects
 * Usage: Import and adapt for consistent error handling across the application
 */

const { EventEmitter } = require('events');

/**
 * Error severity levels
 */
const ErrorSeverity = {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical'
};

/**
 * Error categories
 */
const ErrorCategory = {
    VALIDATION: 'validation',
    BUSINESS_LOGIC: 'business_logic',
    EXTERNAL_API: 'external_api',
    DATABASE: 'database',
    AUTHENTICATION: 'authentication',
    AUTHORIZATION: 'authorization',
    SYSTEM: 'system',
    NETWORK: 'network',
    TIMEOUT: 'timeout'
};

/**
 * Base application error class
 */
class BaseApplicationError extends Error {
    constructor(message, options = {}) {
        super(message);
        
        this.name = this.constructor.name;
        this.message = message;
        this.category = options.category || ErrorCategory.SYSTEM;
        this.severity = options.severity || ErrorSeverity.MEDIUM;
        this.errorCode = options.errorCode || this.constructor.name;
        this.context = options.context || {};
        this.cause = options.cause || null;
        this.timestamp = new Date().toISOString();
        
        // Maintain stack trace
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }

    /**
     * Convert error to JSON for logging/serialization
     */
    toJSON() {
        return {
            name: this.name,
            message: this.message,
            category: this.category,
            severity: this.severity,
            errorCode: this.errorCode,
            context: this.context,
            cause: this.cause ? this.cause.message : null,
            timestamp: this.timestamp,
            stack: this.stack
        };
    }

    /**
     * Get user-friendly message
     */
    getUserMessage() {
        if (this.severity === ErrorSeverity.LOW) {
            return this.message;
        }
        return 'An error occurred. Please try again or contact support.';
    }
}

/**
 * Validation error for input data
 */
class ValidationError extends BaseApplicationError {
    constructor(message, field = null, value = null, options = {}) {
        super(message, {
            category: ErrorCategory.VALIDATION,
            severity: ErrorSeverity.LOW,
            ...options
        });
        this.field = field;
        this.value = value;
    }

    toJSON() {
        return {
            ...super.toJSON(),
            field: this.field,
            value: this.value
        };
    }
}

/**
 * Business logic error for application rules
 */
class BusinessLogicError extends BaseApplicationError {
    constructor(message, options = {}) {
        super(message, {
            category: ErrorCategory.BUSINESS_LOGIC,
            severity: ErrorSeverity.MEDIUM,
            ...options
        });
    }
}

/**
 * External API error for third-party service failures
 */
class ExternalAPIError extends BaseApplicationError {
    constructor(message, options = {}) {
        super(message, {
            category: ErrorCategory.EXTERNAL_API,
            severity: ErrorSeverity.HIGH,
            ...options
        });
        this.serviceName = options.serviceName || null;
        this.statusCode = options.statusCode || null;
        this.responseData = options.responseData || null;
    }

    toJSON() {
        return {
            ...super.toJSON(),
            serviceName: this.serviceName,
            statusCode: this.statusCode,
            responseData: this.responseData
        };
    }
}

/**
 * Database error for data layer failures
 */
class DatabaseError extends BaseApplicationError {
    constructor(message, options = {}) {
        super(message, {
            category: ErrorCategory.DATABASE,
            severity: ErrorSeverity.HIGH,
            ...options
        });
        this.query = options.query || null;
        this.table = options.table || null;
    }

    toJSON() {
        return {
            ...super.toJSON(),
            query: this.query,
            table: this.table
        };
    }
}

/**
 * Authentication error for identity verification failures
 */
class AuthenticationError extends BaseApplicationError {
    constructor(message = 'Authentication failed', options = {}) {
        super(message, {
            category: ErrorCategory.AUTHENTICATION,
            severity: ErrorSeverity.MEDIUM,
            ...options
        });
    }
}

/**
 * Authorization error for permission failures
 */
class AuthorizationError extends BaseApplicationError {
    constructor(message = 'Access denied', options = {}) {
        super(message, {
            category: ErrorCategory.AUTHORIZATION,
            severity: ErrorSeverity.MEDIUM,
            ...options
        });
        this.resource = options.resource || null;
        this.action = options.action || null;
    }

    toJSON() {
        return {
            ...super.toJSON(),
            resource: this.resource,
            action: this.action
        };
    }
}

/**
 * Error handler class for centralized error management
 */
class ErrorHandler extends EventEmitter {
    constructor(logger, options = {}) {
        super();
        this.logger = logger;
        this.options = {
            enableMetrics: options.enableMetrics || false,
            enableAlerts: options.enableAlerts || false,
            ...options
        };
        this.metrics = {
            totalErrors: 0,
            errorsByCategory: {},
            errorsBySeverity: {}
        };
    }

    /**
     * Handle and log an error
     */
    handleError(error, context = {}) {
        let errorData;

        if (error instanceof BaseApplicationError) {
            // Update context if provided
            error.context = { ...error.context, ...context };
            errorData = error.toJSON();
            this._logApplicationError(error);
        } else {
            // Handle unexpected errors
            errorData = this._handleUnexpectedError(error, context);
        }

        // Update metrics
        if (this.options.enableMetrics) {
            this._updateMetrics(errorData);
        }

        // Emit error event
        this.emit('error', errorData);

        // Send alerts if enabled
        if (this.options.enableAlerts && errorData.severity === ErrorSeverity.CRITICAL) {
            this._sendAlert(errorData);
        }

        return errorData;
    }

    /**
     * Log application error based on severity
     */
    _logApplicationError(error) {
        const errorData = error.toJSON();

        switch (error.severity) {
            case ErrorSeverity.CRITICAL:
                this.logger.error('Critical error', errorData);
                break;
            case ErrorSeverity.HIGH:
                this.logger.error('High severity error', errorData);
                break;
            case ErrorSeverity.MEDIUM:
                this.logger.warn('Medium severity error', errorData);
                break;
            case ErrorSeverity.LOW:
                this.logger.info('Low severity error', errorData);
                break;
        }
    }

    /**
     * Handle unexpected/uncaught errors
     */
    _handleUnexpectedError(error, context) {
        const errorData = {
            name: error.constructor.name,
            message: error.message,
            category: ErrorCategory.SYSTEM,
            severity: ErrorSeverity.CRITICAL,
            errorCode: 'UNEXPECTED_ERROR',
            context: {
                ...context,
                stack: error.stack
            },
            timestamp: new Date().toISOString()
        };

        this.logger.error('Unexpected error', errorData);
        return errorData;
    }

    /**
     * Update error metrics
     */
    _updateMetrics(errorData) {
        this.metrics.totalErrors++;
        
        // Update category metrics
        const category = errorData.category;
        this.metrics.errorsByCategory[category] = (this.metrics.errorsByCategory[category] || 0) + 1;
        
        // Update severity metrics
        const severity = errorData.severity;
        this.metrics.errorsBySeverity[severity] = (this.metrics.errorsBySeverity[severity] || 0) + 1;
    }

    /**
     * Send alert for critical errors
     */
    _sendAlert(errorData) {
        // Implement alerting logic (email, Slack, etc.)
        this.logger.error('CRITICAL ALERT', {
            message: 'Critical error occurred',
            error: errorData,
            alertSent: true
        });
    }

    /**
     * Get error metrics
     */
    getMetrics() {
        return { ...this.metrics };
    }

    /**
     * Reset metrics
     */
    resetMetrics() {
        this.metrics = {
            totalErrors: 0,
            errorsByCategory: {},
            errorsBySeverity: {}
        };
    }
}

/**
 * Express error handling middleware
 */
function createErrorMiddleware(errorHandler, options = {}) {
    const {
        includeStack = process.env.NODE_ENV === 'development',
        sendUserMessages = true
    } = options;

    return (err, req, res, next) => {
        const context = {
            url: req.url,
            method: req.method,
            userAgent: req.headers['user-agent'],
            ip: req.ip || req.connection.remoteAddress,
            userId: req.user ? req.user.id : null
        };

        const errorData = errorHandler.handleError(err, context);

        // Determine response status code
        let statusCode = 500;
        if (err instanceof ValidationError) statusCode = 400;
        else if (err instanceof AuthenticationError) statusCode = 401;
        else if (err instanceof AuthorizationError) statusCode = 403;
        else if (err instanceof ExternalAPIError && err.statusCode) statusCode = err.statusCode;

        // Send response
        const response = {
            error: true,
            message: sendUserMessages && err instanceof BaseApplicationError 
                ? err.getUserMessage() 
                : 'Internal server error',
            errorCode: errorData.errorCode
        };

        if (includeStack) {
            response.stack = err.stack;
        }

        res.status(statusCode).json(response);
    };
}

/**
 * Async error wrapper for Express routes
 */
function asyncHandler(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}

/**
 * Utility functions for common validation patterns
 */
function validateRequiredFields(data, requiredFields) {
    const missingFields = [];

    for (const field of requiredFields) {
        if (data[field] === null || data[field] === undefined || data[field] === '') {
            missingFields.push(field);
        }
    }

    if (missingFields.length > 0) {
        throw new ValidationError(
            `Missing required fields: ${missingFields.join(', ')}`,
            missingFields.join(', '),
            data
        );
    }
}

function validateFieldTypes(data, fieldTypes) {
    const invalidFields = [];

    for (const [field, expectedType] of Object.entries(fieldTypes)) {
        if (data[field] !== null && data[field] !== undefined) {
            if (expectedType === 'string' && typeof data[field] !== 'string') {
                invalidFields.push(`${field} (expected string)`);
            } else if (expectedType === 'number' && typeof data[field] !== 'number') {
                invalidFields.push(`${field} (expected number)`);
            } else if (expectedType === 'boolean' && typeof data[field] !== 'boolean') {
                invalidFields.push(`${field} (expected boolean)`);
            } else if (expectedType === 'array' && !Array.isArray(data[field])) {
                invalidFields.push(`${field} (expected array)`);
            } else if (expectedType === 'object' && typeof data[field] !== 'object') {
                invalidFields.push(`${field} (expected object)`);
            }
        }
    }

    if (invalidFields.length > 0) {
        throw new ValidationError(
            `Invalid field types: ${invalidFields.join(', ')}`,
            invalidFields.join(', '),
            data
        );
    }
}

/**
 * Retry utility for operations that might fail
 */
function retryOperation(fn, options = {}) {
    const {
        maxRetries = 3,
        delay = 1000,
        backoff = 2,
        shouldRetry = (error) => true
    } = options;

    return async (...args) => {
        let lastError;
        let currentDelay = delay;

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                return await fn(...args);
            } catch (error) {
                lastError = error;

                if (attempt === maxRetries || !shouldRetry(error)) {
                    throw new ExternalAPIError(
                        `Operation failed after ${attempt + 1} attempts: ${error.message}`,
                        { serviceName: 'retry-operation', cause: error }
                    );
                }

                // Wait before retry
                await new Promise(resolve => setTimeout(resolve, currentDelay));
                currentDelay *= backoff;
            }
        }

        throw lastError;
    };
}

/**
 * Circuit breaker pattern for external services
 */
class CircuitBreaker {
    constructor(fn, options = {}) {
        this.fn = fn;
        this.options = {
            failureThreshold: options.failureThreshold || 5,
            resetTimeout: options.resetTimeout || 60000,
            monitoringPeriod: options.monitoringPeriod || 10000,
            ...options
        };

        this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
        this.failureCount = 0;
        this.lastFailureTime = null;
        this.successCount = 0;
    }

    async execute(...args) {
        if (this.state === 'OPEN') {
            if (Date.now() - this.lastFailureTime > this.options.resetTimeout) {
                this.state = 'HALF_OPEN';
                this.successCount = 0;
            } else {
                throw new ExternalAPIError('Circuit breaker is OPEN');
            }
        }

        try {
            const result = await this.fn(...args);
            this.onSuccess();
            return result;
        } catch (error) {
            this.onFailure();
            throw error;
        }
    }

    onSuccess() {
        this.failureCount = 0;
        
        if (this.state === 'HALF_OPEN') {
            this.successCount++;
            if (this.successCount >= 3) {
                this.state = 'CLOSED';
            }
        }
    }

    onFailure() {
        this.failureCount++;
        this.lastFailureTime = Date.now();

        if (this.failureCount >= this.options.failureThreshold) {
            this.state = 'OPEN';
        }
    }

    getState() {
        return {
            state: this.state,
            failureCount: this.failureCount,
            lastFailureTime: this.lastFailureTime
        };
    }
}

// Example usage
if (require.main === module) {
    async function main() {
        try {
            // Create error handler
            const logger = {
                error: (msg, data) => console.error(`ERROR: ${msg}`, data),
                warn: (msg, data) => console.warn(`WARN: ${msg}`, data),
                info: (msg, data) => console.info(`INFO: ${msg}`, data)
            };

            const errorHandler = new ErrorHandler(logger, {
                enableMetrics: true,
                enableAlerts: true
            });

            // Test validation error
            try {
                validateRequiredFields({ name: 'John' }, ['name', 'email']);
            } catch (error) {
                errorHandler.handleError(error, { operation: 'user_validation' });
            }

            // Test business logic error
            try {
                throw new BusinessLogicError('User account is suspended', {
                    context: { userId: '123', operation: 'login' }
                });
            } catch (error) {
                errorHandler.handleError(error);
            }

            // Test retry operation
            let attempts = 0;
            const unreliableFunction = async () => {
                attempts++;
                if (attempts < 3) {
                    throw new Error('Service temporarily unavailable');
                }
                return 'success';
            };

            const retryFn = retryOperation(unreliableFunction, {
                maxRetries: 3,
                delay: 100
            });

            try {
                const result = await retryFn();
                console.log(`Retry operation succeeded: ${result}`);
            } catch (error) {
                errorHandler.handleError(error);
            }

            // Test circuit breaker
            const circuitBreaker = new CircuitBreaker(async () => {
                throw new Error('Service down');
            }, { failureThreshold: 2 });

            try {
                await circuitBreaker.execute();
            } catch (error) {
                errorHandler.handleError(error);
            }

            console.log('Error handling utilities demo completed');
            console.log('Metrics:', errorHandler.getMetrics());

        } catch (error) {
            console.error('Demo error:', error.message);
        }
    }

    main();
}

module.exports = {
    // Error classes
    BaseApplicationError,
    ValidationError,
    BusinessLogicError,
    ExternalAPIError,
    DatabaseError,
    AuthenticationError,
    AuthorizationError,

    // Error handling utilities
    ErrorHandler,
    createErrorMiddleware,
    asyncHandler,

    // Validation utilities
    validateRequiredFields,
    validateFieldTypes,

    // Retry and circuit breaker
    retryOperation,
    CircuitBreaker,

    // Constants
    ErrorSeverity,
    ErrorCategory
};
