/*
File: errors.tpl.js
Purpose: Structured error handling for Express/Node.js applications
Generated for: {{PROJECT_NAME}}
*/

class AppError extends Error {
    constructor(message, errorCode = 'INTERNAL_ERROR', statusCode = 500, details = null) {
        super(message);
        this.name = 'AppError';
        this.errorCode = errorCode;
        this.statusCode = statusCode;
        this.details = details;
        Error.captureStackTrace(this, this.constructor);
    }
}

class NotFoundError extends AppError {
    constructor(resource, resourceId) {
        super(
            `${resource} with id '${resourceId}' not found`,
            'NOT_FOUND',
            404,
            { resource, id: resourceId }
        );
        this.name = 'NotFoundError';
    }
}

class ValidationError extends AppError {
    constructor(message, details = null) {
        super(message, 'VALIDATION_ERROR', 400, details);
        this.name = 'ValidationError';
    }
}

class AuthenticationError extends AppError {
    constructor(message = 'Authentication required') {
        super(message, 'UNAUTHORIZED', 401);
        this.name = 'AuthenticationError';
    }
}

class AuthorizationError extends AppError {
    constructor(message = 'Permission denied') {
        super(message, 'FORBIDDEN', 403);
        this.name = 'AuthorizationError';
    }
}

class RateLimitError extends AppError {
    constructor(retryAfter = 60) {
        super('Rate limit exceeded', 'RATE_LIMITED', 429, { retryAfter });
        this.name = 'RateLimitError';
    }
}

class ConflictError extends AppError {
    constructor(message, details = null) {
        super(message, 'CONFLICT', 409, details);
        this.name = 'ConflictError';
    }
}

// Express error handler middleware
function errorHandler(err, req, res, next) {
    const requestId = req.id || req.headers['x-request-id'];

    // Log the error
    console.error({
        type: 'error',
        requestId,
        error: err.errorCode || 'INTERNAL_ERROR',
        message: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
        details: err.details,
    });

    // Handle known errors
    if (err instanceof AppError) {
        return res.status(err.statusCode).json({
            error: err.errorCode,
            message: err.message,
            details: err.details,
            requestId,
        });
    }

    // Handle unknown errors
    res.status(500).json({
        error: 'INTERNAL_ERROR',
        message: process.env.NODE_ENV === 'production'
            ? 'An unexpected error occurred'
            : err.message,
        requestId,
    });
}

// Async handler wrapper to catch async errors
function asyncHandler(fn) {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}

module.exports = {
    AppError,
    NotFoundError,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    ConflictError,
    errorHandler,
    asyncHandler,
};
