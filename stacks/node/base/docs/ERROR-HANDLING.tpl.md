# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: Error handling utilities
# Tier: base
# Stack: node
# Category: template

# Error Handling Guide - Node.js

This guide covers comprehensive error handling strategies, exception management, and error recovery patterns for Node.js applications.

## 🚨 Node.js Error Handling Overview

Node.js provides robust error handling through exceptions, error-first callbacks, promises, and async/await. Proper error handling ensures application stability and prevents uncaught exceptions.

## 📊 Error Categories

### Built-in Error Types
- **Error**: Base class for all errors
- **TypeError**: Invalid type or operation
- **ReferenceError**: Reference to undefined variable
- **SyntaxError**: Invalid JavaScript syntax
- **RangeError**: Numeric value outside allowed range
- **EvalError**: Error in eval() function
- **URIError**: Error in encodeURI/decodeURI functions
- **SystemError**: System-level operational errors

### Custom Error Classes
```javascript
class BaseAppError extends Error {
  constructor(message, code = null, context = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.context = context;
    this.timestamp = new Date().toISOString();
    this.isOperational = true;
    
    Error.captureStackTrace(this, this.constructor);
  }
  
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      context: this.context,
      timestamp: this.timestamp,
      stack: this.stack
    };
  }
}

class ValidationError extends BaseAppError {
  constructor(message, field = null, context = {}) {
    super(message, 'VALIDATION_ERROR', { field, ...context });
  }
}

class BusinessError extends BaseAppError {
  constructor(message, code = 'BUSINESS_ERROR', context = {}) {
    super(message, code, context);
  }
}

class NetworkError extends BaseAppError {
  constructor(message, statusCode = null, context = {}) {
    super(message, 'NETWORK_ERROR', { statusCode, ...context });
  }
}

class DatabaseError extends BaseAppError {
  constructor(message, query = null, context = {}) {
    super(message, 'DATABASE_ERROR', { query, ...context });
  }
}

class SystemError extends BaseAppError {
  constructor(message, originalError = null, context = {}) {
    super(message, 'SYSTEM_ERROR', { originalError: originalError?.message, ...context });
    this.isOperational = false;
  }
}
```

## 🔍 Error Detection & Patterns

### Synchronous Error Handling

#### Before: Poor Error Handling
```javascript
// BAD: No error handling
function processUserDataBad(userData) {
  const name = userData.name;
  const age = userData.age;
  
  if (age < 18) {
    return false;
  }
  
  // Process data without validation
  return userData.name.toUpperCase();
}
```

#### After: Comprehensive Error Handling
```javascript
// GOOD: Proper error handling with validation
function processUserDataGood(userData) {
  try {
    // Validate input
    if (!userData || typeof userData !== 'object') {
      throw new ValidationError('User data must be an object', 'userData');
    }
    
    const { name, age, email } = userData;
    
    // Validate required fields
    if (!name) {
      throw new ValidationError('Name is required', 'name');
    }
    
    if (typeof age !== 'number' || age < 0) {
      throw new ValidationError('Age must be a non-negative number', 'age');
    }
    
    if (!email || !isValidEmail(email)) {
      throw new ValidationError('Invalid email format', 'email');
    }
    
    // Business logic validation
    if (age < 18) {
      throw new BusinessError('User must be at least 18 years old', 'AGE_RESTRICTION');
    }
    
    // Process data
    return {
      processedName: name.trim().toUpperCase(),
      age,
      email: email.toLowerCase(),
      processedAt: new Date().toISOString()
    };
    
  } catch (error) {
    // Log error with context
    logger.error('Error processing user data', {
      error: error.message,
      code: error.code,
      userData: sanitizeUserData(userData)
    });
    
    // Re-throw operational errors
    if (error instanceof BaseAppError) {
      throw error;
    }
    
    // Wrap unexpected errors
    throw new SystemError('Failed to process user data', error, { userData });
  }
}

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function sanitizeUserData(userData) {
  const { name, age } = userData || {};
  return { name, age }; // Remove sensitive data
}
```

### Asynchronous Error Handling

#### Before: Callback Hell with Poor Error Handling
```javascript
// BAD: Callback hell with inconsistent error handling
function fetchUserPostsBad(userId, callback) {
  getUserById(userId, (err, user) => {
    if (err) {
      callback(err);
      return;
    }
    
    getPostsByUser(userId, (err, posts) => {
      if (err) {
        callback(err);
        return;
      }
      
      getCommentsForPosts(posts, (err, comments) => {
        if (err) {
          callback(err);
          return;
        }
        
        // No error handling for final processing
        callback(null, { user, posts, comments });
      });
    });
  });
}
```

#### After: Async/Await with Comprehensive Error Handling
```javascript
// GOOD: Async/await with proper error handling
class UserService {
  async fetchUserPosts(userId) {
    try {
      // Validate input
      if (!userId || typeof userId !== 'string') {
        throw new ValidationError('Valid user ID is required', 'userId');
      }
      
      // Fetch user with error handling
      const user = await this.getUserById(userId);
      
      // Fetch posts with error handling
      const posts = await this.getPostsByUser(userId);
      
      // Fetch comments with error handling
      const comments = await this.getCommentsForPosts(posts);
      
      // Return processed result
      return {
        user: this.sanitizeUser(user),
        posts: posts.map(post => this.sanitizePost(post)),
        comments: comments.map(comment => this.sanitizeComment(comment)),
        fetchedAt: new Date().toISOString()
      };
      
    } catch (error) {
      // Log error with context
      logger.error('Error fetching user posts', {
        error: error.message,
        code: error.code,
        userId
      });
      
      // Handle specific error types
      if (error instanceof ValidationError) {
        throw error;
      }
      
      if (error instanceof DatabaseError) {
        throw new BusinessError('Unable to fetch user data', 'DATA_UNAVAILABLE');
      }
      
      if (error.code === 'ENOENT') {
        throw new BusinessError('User not found', 'USER_NOT_FOUND');
      }
      
      // Wrap unexpected errors
      throw new SystemError('Failed to fetch user posts', error, { userId });
    }
  }
  
  async getUserById(userId) {
    try {
      const user = await database.query('SELECT * FROM users WHERE id = ?', [userId]);
      
      if (!user || user.length === 0) {
        throw new BusinessError('User not found', 'USER_NOT_FOUND', { userId });
      }
      
      return user[0];
    } catch (error) {
      if (error instanceof BusinessError) {
        throw error;
      }
      throw new DatabaseError('Failed to fetch user', 'getUserById', { userId });
    }
  }
  
  async getPostsByUser(userId) {
    try {
      const posts = await database.query('SELECT * FROM posts WHERE user_id = ?', [userId]);
      return posts || [];
    } catch (error) {
      throw new DatabaseError('Failed to fetch posts', 'getPostsByUser', { userId });
    }
  }
  
  async getCommentsForPosts(posts) {
    try {
      if (!posts || posts.length === 0) {
        return [];
      }
      
      const postIds = posts.map(post => post.id);
      const comments = await database.query(
        'SELECT * FROM comments WHERE post_id IN (?)', 
        [postIds]
      );
      
      return comments || [];
    } catch (error) {
      throw new DatabaseError('Failed to fetch comments', 'getCommentsForPosts', { postCount: posts?.length });
    }
  }
  
  sanitizeUser(user) {
    const { id, name, email, createdAt } = user;
    return { id, name, email, createdAt };
  }
  
  sanitizePost(post) {
    const { id, title, content, createdAt } = post;
    return { id, title, content, createdAt };
  }
  
  sanitizeComment(comment) {
    const { id, content, postId, createdAt } = comment;
    return { id, content, postId, createdAt };
  }
}
```

## ⚡ Promise Error Handling

### Promise Chain Error Handling

#### Before: Inconsistent Promise Error Handling
```javascript
// BAD: Inconsistent error handling in promise chain
function processDataBad(data) {
  return validateData(data)
    .then(validatedData => {
      return transformData(validatedData);
    })
    .then(transformedData => {
      return saveData(transformedData);
    })
    .catch(err => {
      console.log('Error:', err.message); // Inconsistent error handling
      return null;
    });
}
```

#### After: Comprehensive Promise Error Handling
```javascript
// GOOD: Comprehensive promise error handling
class DataProcessor {
  processData(data) {
    return this.validateData(data)
      .then(validatedData => this.transformData(validatedData))
      .then(transformedData => this.saveData(transformedData))
      .then(result => {
        logger.info('Data processed successfully', { dataSize: data?.length });
        return result;
      })
      .catch(error => {
        return this.handleProcessingError(error, data);
      });
  }
  
  async validateData(data) {
    try {
      if (!data) {
        throw new ValidationError('Data is required', 'data');
      }
      
      if (!Array.isArray(data)) {
        throw new ValidationError('Data must be an array', 'data');
      }
      
      if (data.length === 0) {
        throw new ValidationError('Data cannot be empty', 'data');
      }
      
      // Validate each item
      for (let i = 0; i < data.length; i++) {
        if (!data[i].id) {
          throw new ValidationError(`Item at index ${i} missing required field 'id'`, `data[${i}].id`);
        }
      }
      
      return data;
    } catch (error) {
      logger.error('Data validation failed', {
        error: error.message,
        code: error.code,
        dataSize: data?.length
      });
      throw error;
    }
  }
  
  async transformData(data) {
    try {
      return data.map(item => ({
        ...item,
        processed: true,
        transformedAt: new Date().toISOString(),
        processedValue: this.calculateProcessedValue(item)
      }));
    } catch (error) {
      throw new SystemError('Failed to transform data', error, { dataSize: data?.length });
    }
  }
  
  async saveData(data) {
    try {
      const result = await database.insert('processed_data', data);
      return {
        insertedCount: result.affectedRows,
        data: data.map(item => ({ id: item.id, processed: item.processed }))
      };
    } catch (error) {
      throw new DatabaseError('Failed to save data', 'saveData', { dataSize: data?.length });
    }
  }
  
  handleProcessingError(error, originalData) {
    logger.error('Error processing data', {
      error: error.message,
      code: error.code,
      originalDataSize: originalData?.length
    });
    
    // Return error response for operational errors
    if (error instanceof BaseAppError) {
      return {
        success: false,
        error: {
          message: error.message,
          code: error.code,
          isOperational: error.isOperational
        }
      };
    }
    
    // Return generic error for system errors
    return {
      success: false,
      error: {
        message: 'An unexpected error occurred',
        code: 'SYSTEM_ERROR'
      }
    };
  }
  
  calculateProcessedValue(item) {
    // Example processing logic
    return item.value ? item.value * 2 : 0;
  }
}
```

## 🛡️ Global Error Handling

### Uncaught Exception Handling

#### Before: No Global Error Handling
```javascript
// BAD: No global error handling
process.on('uncaughtException', (err) => {
  console.log('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.log('Unhandled Rejection at:', promise, 'reason:', reason);
});
```

#### After: Comprehensive Global Error Handling
```javascript
// GOOD: Comprehensive global error handling
class ErrorHandler {
  constructor(logger) {
    this.logger = logger;
    this.setupGlobalHandlers();
  }
  
  setupGlobalHandlers() {
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      this.handleUncaughtException(error);
    });
    
    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      this.handleUnhandledRejection(reason, promise);
    });
    
    // Handle warning events
    process.on('warning', (warning) => {
      this.handleWarning(warning);
    });
  }
  
  handleUncaughtException(error) {
    this.logger.error('Uncaught Exception', {
      error: error.message,
      stack: error.stack,
      code: error.code,
      isOperational: error.isOperational
    });
    
    // Graceful shutdown for operational errors
    if (error.isOperational) {
      this.gracefulShutdown('Operational error', error);
    } else {
      // Immediate shutdown for non-operational errors
      this.logger.error('Non-operational uncaught exception - forcing shutdown');
      process.exit(1);
    }
  }
  
  handleUnhandledRejection(reason, promise) {
    this.logger.error('Unhandled Promise Rejection', {
      reason: reason?.message || reason,
      promise: promise.toString(),
      stack: reason?.stack
    });
    
    // Convert rejection to error if needed
    const error = reason instanceof Error ? reason : new Error(String(reason));
    
    if (error.isOperational) {
      this.logger.warn('Operational promise rejection - continuing execution');
    } else {
      this.logger.error('Non-operational promise rejection - forcing shutdown');
      this.gracefulShutdown('Unhandled promise rejection', error);
    }
  }
  
  handleWarning(warning) {
    this.logger.warn('Process warning', {
      name: warning.name,
      message: warning.message,
      stack: warning.stack
    });
  }
  
  gracefulShutdown(reason, error) {
    this.logger.info('Starting graceful shutdown', { reason });
    
    // Close database connections
    if (global.database) {
      global.database.close()
        .then(() => {
          this.logger.info('Database connections closed');
        })
        .catch(err => {
          this.logger.error('Error closing database', { error: err.message });
        });
    }
    
    // Close HTTP server
    if (global.server) {
      global.server.close(() => {
        this.logger.info('HTTP server closed');
        process.exit(1);
      });
    } else {
      process.exit(1);
    }
  }
}

// Usage
const errorHandler = new ErrorHandler(logger);
```

### Express.js Error Handling Middleware

#### Before: Basic Express Error Handling
```javascript
// BAD: Basic error handling
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong' });
});
```

#### After: Comprehensive Express Error Handling
```javascript
// GOOD: Comprehensive Express error handling
class ExpressErrorHandler {
  constructor(logger) {
    this.logger = logger;
  }
  
  // 404 handler
  notFoundHandler(req, res, next) {
    const error = new BusinessError('Resource not found', 'NOT_FOUND', {
      path: req.path,
      method: req.method
    });
    
    next(error);
  }
  
  // Global error handler
  errorHandler(err, req, res, next) {
    // Log error with context
    this.logError(err, req);
    
    // Determine error response
    const errorResponse = this.buildErrorResponse(err);
    
    // Send error response
    res.status(errorResponse.status).json(errorResponse.body);
  }
  
  // Async error wrapper
  asyncHandler(fn) {
    return (req, res, next) => {
      Promise.resolve(fn(req, res, next)).catch(next);
    };
  }
  
  logError(err, req) {
    const logData = {
      error: err.message,
      code: err.code,
      stack: err.stack,
      path: req.path,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    };
    
    if (err instanceof ValidationError) {
      this.logger.warn('Validation error', logData);
    } else if (err instanceof BusinessError) {
      this.logger.warn('Business error', logData);
    } else if (err instanceof SystemError) {
      this.logger.error('System error', logData);
    } else {
      this.logger.error('Unexpected error', logData);
    }
  }
  
  buildErrorResponse(err) {
    // Validation errors
    if (err instanceof ValidationError) {
      return {
        status: 400,
        body: {
          success: false,
          error: {
            code: err.code,
            message: err.message,
            field: err.context?.field,
            type: 'validation'
          }
        }
      };
    }
    
    // Business errors
    if (err instanceof BusinessError) {
      const statusMap = {
        'USER_NOT_FOUND': 404,
        'AGE_RESTRICTION': 403,
        'DATA_UNAVAILABLE': 503,
        'NOT_FOUND': 404
      };
      
      return {
        status: statusMap[err.code] || 400,
        body: {
          success: false,
          error: {
            code: err.code,
            message: err.message,
            type: 'business'
          }
        }
      };
    }
    
    // Network errors
    if (err instanceof NetworkError) {
      return {
        status: err.context?.statusCode || 500,
        body: {
          success: false,
          error: {
            code: err.code,
            message: err.message,
            type: 'network'
          }
        }
      };
    }
    
    // Database errors
    if (err instanceof DatabaseError) {
      return {
        status: 500,
        body: {
          success: false,
          error: {
            code: err.code,
            message: 'Database operation failed',
            type: 'database'
          }
        }
      };
    }
    
    // System errors (don't expose details in production)
    if (err instanceof SystemError) {
      const isDevelopment = process.env.NODE_ENV === 'development';
      
      return {
        status: 500,
        body: {
          success: false,
          error: {
            code: err.code,
            message: isDevelopment ? err.message : 'Internal server error',
            type: 'system',
            ...(isDevelopment && { stack: err.stack })
          }
        }
      };
    }
    
    // Unknown errors
    return {
      status: 500,
      body: {
        success: false,
        error: {
          code: 'UNKNOWN_ERROR',
          message: 'An unexpected error occurred',
          type: 'unknown'
        }
      }
    };
  }
}

// Usage in Express app
const expressErrorHandler = new ExpressErrorHandler(logger);

// Routes with async error handling
app.get('/users/:id', expressErrorHandler.asyncHandler(async (req, res) => {
  const userId = req.params.id;
  const userService = new UserService();
  const userPosts = await userService.fetchUserPosts(userId);
  res.json({ success: true, data: userPosts });
}));

// Error handling middleware
app.use(expressErrorHandler.notFoundHandler);
app.use(expressErrorHandler.errorHandler);
```

## 🔄 Error Recovery & Retry Mechanisms

### Retry with Exponential Backoff

#### Before: No Retry Logic
```javascript
// BAD: No retry mechanism
async function callExternalAPI(data) {
  const response = await fetch('https://api.example.com/data', {
    method: 'POST',
    body: JSON.stringify(data)
  });
  return response.json();
}
```

#### After: Comprehensive Retry Strategy
```javascript
// GOOD: Retry mechanism with exponential backoff
class RetryManager {
  constructor(options = {}) {
    this.maxAttempts = options.maxAttempts || 3;
    this.baseDelay = options.baseDelay || 1000;
    this.maxDelay = options.maxDelay || 30000;
    this.backoffFactor = options.backoffFactor || 2;
    this.jitter = options.jitter !== false;
  }
  
  async execute(fn, context = {}) {
    let lastError;
    
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      try {
        const result = await fn();
        
        if (attempt > 1) {
          logger.info('Operation succeeded after retry', {
            attempt,
            context
          });
        }
        
        return result;
      } catch (error) {
        lastError = error;
        
        // Don't retry on certain errors
        if (!this.shouldRetry(error)) {
          throw error;
        }
        
        if (attempt === this.maxAttempts) {
          logger.error('Operation failed after all retry attempts', {
            attempts: this.maxAttempts,
            error: error.message,
            context
          });
          throw error;
        }
        
        const delay = this.calculateDelay(attempt);
        
        logger.warn(`Operation failed, retrying in ${delay}ms`, {
          attempt,
          maxAttempts: this.maxAttempts,
          error: error.message,
          context
        });
        
        await this.sleep(delay);
      }
    }
    
    throw lastError;
  }
  
  shouldRetry(error) {
    // Don't retry on validation or business errors
    if (error instanceof ValidationError || error instanceof BusinessError) {
      return false;
    }
    
    // Retry on network and system errors
    if (error instanceof NetworkError || error instanceof SystemError) {
      return true;
    }
    
    // Retry on specific HTTP status codes
    if (error.context?.statusCode) {
      const retryableStatusCodes = [408, 429, 500, 502, 503, 504];
      return retryableStatusCodes.includes(error.context.statusCode);
    }
    
    // Retry on connection errors
    if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') {
      return true;
    }
    
    return false;
  }
  
  calculateDelay(attempt) {
    let delay = this.baseDelay * Math.pow(this.backoffFactor, attempt - 1);
    delay = Math.min(delay, this.maxDelay);
    
    if (this.jitter) {
      // Add random jitter to prevent thundering herd
      const jitterRange = delay * 0.1;
      delay += Math.random() * jitterRange - jitterRange / 2;
    }
    
    return Math.max(0, delay);
  }
  
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Circuit breaker pattern
class CircuitBreaker {
  constructor(options = {}) {
    this.failureThreshold = options.failureThreshold || 5;
    this.resetTimeout = options.resetTimeout || 60000;
    this.monitoringPeriod = options.monitoringPeriod || 10000;
    
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
    this.failureCount = 0;
    this.lastFailureTime = null;
    this.successCount = 0;
  }
  
  async execute(fn, context = {}) {
    if (this.state === 'OPEN') {
      if (this.shouldAttemptReset()) {
        this.state = 'HALF_OPEN';
        this.successCount = 0;
        logger.info('Circuit breaker moving to HALF_OPEN state');
      } else {
        throw new NetworkError('Circuit breaker is OPEN', 'CIRCUIT_BREAKER_OPEN', {
          failureCount: this.failureCount,
          timeUntilReset: this.resetTimeout - (Date.now() - this.lastFailureTime)
        });
      }
    }
    
    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }
  
  onSuccess() {
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= 3) { // Require 3 successes to close
        this.state = 'CLOSED';
        this.failureCount = 0;
        logger.info('Circuit breaker moving to CLOSED state');
      }
    } else {
      this.failureCount = 0;
    }
  }
  
  onFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    
    if (this.state === 'HALF_OPEN') {
      this.state = 'OPEN';
      logger.warn('Circuit breaker moving to OPEN state from HALF_OPEN');
    } else if (this.failureCount >= this.failureThreshold) {
      this.state = 'OPEN';
      logger.warn('Circuit breaker moving to OPEN state', {
        failureCount: this.failureCount,
        threshold: this.failureThreshold
      });
    }
  }
  
  shouldAttemptReset() {
    return this.lastFailureTime && 
           (Date.now() - this.lastFailureTime) > this.resetTimeout;
  }
}

// Usage
const retryManager = new RetryManager({
  maxAttempts: 5,
  baseDelay: 2000,
  maxDelay: 30000
});

const circuitBreaker = new CircuitBreaker({
  failureThreshold: 3,
  resetTimeout: 60000
});

class APIService {
  async callExternalAPI(data) {
    return await retryManager.execute(async () => {
      return await circuitBreaker.execute(async () => {
        const response = await fetch('https://api.example.com/data', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(data),
          timeout: 30000
        });
        
        if (!response.ok) {
          throw new NetworkError(
            `HTTP ${response.status}: ${response.statusText}`,
            response.status,
            { url: 'https://api.example.com/data' }
          );
        }
        
        return await response.json();
      }, { operation: 'callExternalAPI' });
    }, { operation: 'callExternalAPI', dataSize: data?.length });
  }
}
```

## 📝 Error Logging & Monitoring

### Structured Logging System

#### Before: Basic Console Logging
```javascript
// BAD: Basic console logging
function processRequest(req, res) {
  try {
    // Process request
    console.log('Request processed');
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).send('Error occurred');
  }
}
```

#### After: Comprehensive Structured Logging
```javascript
// GOOD: Comprehensive structured logging
class StructuredLogger {
  constructor(serviceName, options = {}) {
    this.serviceName = serviceName;
    this.level = options.level || 'info';
    this.transports = options.transports || [new ConsoleTransport()];
  }
  
  log(level, message, context = {}) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      service: this.serviceName,
      message,
      context: {
        ...context,
        pid: process.pid,
        hostname: require('os').hostname()
      }
    };
    
    this.transports.forEach(transport => transport.log(logEntry));
  }
  
  error(message, context = {}) {
    this.log('error', message, context);
  }
  
  warn(message, context = {}) {
    this.log('warn', message, context);
  }
  
  info(message, context = {}) {
    this.log('info', message, context);
  }
  
  debug(message, context = {}) {
    if (this.level === 'debug') {
      this.log('debug', message, context);
    }
  }
}

class ConsoleTransport {
  log(logEntry) {
    const { timestamp, level, service, message, context } = logEntry;
    const contextStr = Object.keys(context).length > 0 ? 
      ` ${JSON.stringify(context)}` : '';
    
    console.log(`${timestamp} [${level}] ${service}: ${message}${contextStr}`);
  }
}

class FileTransport {
  constructor(filename) {
    this.filename = filename;
    this.fs = require('fs');
  }
  
  log(logEntry) {
    const logLine = JSON.stringify(logEntry) + '\n';
    this.fs.appendFileSync(this.filename, logLine);
  }
}

// Error monitoring service
class ErrorMonitor {
  constructor(logger) {
    this.logger = logger;
    this.errorCounts = new Map();
    this.errorRates = new Map();
    this.alertThresholds = {
      errorRate: 0.1, // 10% error rate
      errorCount: 50  // 50 errors per minute
    };
  }
  
  recordError(error, context = {}) {
    const errorType = error.constructor.name;
    const now = Date.now();
    
    // Update error counts
    const currentCount = this.errorCounts.get(errorType) || 0;
    this.errorCounts.set(errorType, currentCount + 1);
    
    // Update error rates (per minute)
    if (!this.errorRates.has(errorType)) {
      this.errorRates.set(errorType, []);
    }
    
    const timestamps = this.errorRates.get(errorType);
    timestamps.push(now);
    
    // Keep only last minute
    const oneMinuteAgo = now - 60000;
    const recentTimestamps = timestamps.filter(t => t > oneMinuteAgo);
    this.errorRates.set(errorType, recentTimestamps);
    
    // Log error with context
    this.logger.error(error.message, {
      type: errorType,
      code: error.code,
      stack: error.stack,
      context,
      errorCount: currentCount + 1,
      errorRatePerMinute: recentTimestamps.length
    });
    
    // Check thresholds
    this.checkThresholds(errorType);
  }
  
  checkThresholds(errorType) {
    const errorCount = this.errorCounts.get(errorType);
    const errorRate = this.errorRates.get(errorType).length;
    
    // Check error count threshold
    if (errorCount > this.alertThresholds.errorCount) {
      this.logger.warn('High error count detected', {
        errorType,
        count: errorCount,
        threshold: this.alertThresholds.errorCount
      });
    }
    
    // Check error rate threshold
    if (errorRate > this.alertThresholds.errorRate) {
      this.logger.warn('High error rate detected', {
        errorType,
        rate: errorRate,
        threshold: this.alertThresholds.errorRate
      });
    }
  }
  
  getStats() {
    const stats = {
      totalErrors: Array.from(this.errorCounts.values()).reduce((a, b) => a + b, 0),
      errorTypes: {},
      errorRates: {}
    };
    
    this.errorCounts.forEach((count, type) => {
      stats.errorTypes[type] = count;
    });
    
    this.errorRates.forEach((timestamps, type) => {
      stats.errorRates[type] = timestamps.length;
    });
    
    return stats;
  }
}

// Usage
const logger = new StructuredLogger('user-service', {
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  transports: [
    new ConsoleTransport(),
    new FileTransport('logs/app.log')
  ]
});

const errorMonitor = new ErrorMonitor(logger);

// Request handler with comprehensive logging
class RequestHandler {
  async handleRequest(req, res) {
    const requestId = this.generateRequestId();
    const startTime = Date.now();
    
    try {
      logger.info('Request started', {
        requestId,
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      // Process request
      const result = await this.processRequest(req);
      
      const duration = Date.now() - startTime;
      
      logger.info('Request completed', {
        requestId,
        duration,
        status: 'success'
      });
      
      res.json({ success: true, data: result });
      
    } catch (error) {
      const duration = Date.now() - startTime;
      
      errorMonitor.recordError(error, {
        requestId,
        method: req.method,
        path: req.path,
        duration
      });
      
      logger.error('Request failed', {
        requestId,
        duration,
        error: error.message
      });
      
      this.sendErrorResponse(res, error);
    }
  }
  
  generateRequestId() {
    return Math.random().toString(36).substr(2, 9);
  }
  
  sendErrorResponse(res, error) {
    const status = error instanceof ValidationError ? 400 : 
                  error instanceof BusinessError ? 400 : 500;
    
    res.status(status).json({
      success: false,
      error: {
        message: error.message,
        code: error.code || 'UNKNOWN_ERROR'
      }
    });
  }
}
```

## 🧪 Error Testing

### Testing Error Scenarios

#### Before: No Error Testing
```javascript
// BAD: No error testing
describe('UserService', () => {
  it('should process user data', () => {
    const result = processUserData({ name: 'John', age: 25 });
    expect(result).toBeDefined();
  });
});
```

#### After: Comprehensive Error Testing
```javascript
// GOOD: Comprehensive error testing
const assert = require('assert');
const sinon = require('sinon');

describe('Error Handling', () => {
  let logger;
  let errorMonitor;
  
  beforeEach(() => {
    logger = new StructuredLogger('test-service');
    errorMonitor = new ErrorMonitor(logger);
  });
  
  describe('processUserDataGood', () => {
    it('should throw ValidationError for missing name', () => {
      assert.throws(
        () => processUserDataGood({ age: 25, email: 'test@example.com' }),
        {
          name: 'ValidationError',
          message: 'Name is required',
          code: 'VALIDATION_ERROR'
        }
      );
    });
    
    it('should throw ValidationError for invalid age', () => {
      assert.throws(
        () => processUserDataGood({ name: 'John', age: -5, email: 'test@example.com' }),
        {
          name: 'ValidationError',
          message: 'Age must be a non-negative number',
          code: 'VALIDATION_ERROR'
        }
      );
    });
    
    it('should throw BusinessError for age restriction', () => {
      assert.throws(
        () => processUserDataGood({ name: 'John', age: 16, email: 'test@example.com' }),
        {
          name: 'BusinessError',
          message: 'User must be at least 18 years old',
          code: 'AGE_RESTRICTION'
        }
      );
    });
    
    it('should process valid data successfully', () => {
      const result = processUserDataGood({ 
        name: 'John', 
        age: 25, 
        email: 'john@example.com' 
      });
      
      assert.strictEqual(result.processedName, 'JOHN');
      assert.strictEqual(result.age, 25);
      assert.strictEqual(result.email, 'john@example.com');
    });
  });
  
  describe('RetryManager', () => {
    it('should retry on retryable errors', async () => {
      const retryManager = new RetryManager({ maxAttempts: 3 });
      let attemptCount = 0;
      
      const failingFunction = async () => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new NetworkError('Temporary failure', 503);
        }
        return 'success';
      };
      
      const result = await retryManager.execute(failingFunction);
      
      assert.strictEqual(result, 'success');
      assert.strictEqual(attemptCount, 3);
    });
    
    it('should not retry on non-retryable errors', async () => {
      const retryManager = new RetryManager({ maxAttempts: 3 });
      let attemptCount = 0;
      
      const failingFunction = async () => {
        attemptCount++;
        throw new ValidationError('Invalid data');
      };
      
      await assert.rejects(
        () => retryManager.execute(failingFunction),
        { name: 'ValidationError' }
      );
      
      assert.strictEqual(attemptCount, 1);
    });
    
    it('should fail after max attempts', async () => {
      const retryManager = new RetryManager({ maxAttempts: 2 });
      let attemptCount = 0;
      
      const failingFunction = async () => {
        attemptCount++;
        throw new NetworkError('Persistent failure', 500);
      };
      
      await assert.rejects(
        () => retryManager.execute(failingFunction),
        { name: 'NetworkError' }
      );
      
      assert.strictEqual(attemptCount, 2);
    });
  });
  
  describe('CircuitBreaker', () => {
    it('should open circuit after failure threshold', async () => {
      const circuitBreaker = new CircuitBreaker({ failureThreshold: 3 });
      let callCount = 0;
      
      const failingFunction = async () => {
        callCount++;
        throw new NetworkError('Service unavailable');
      };
      
      // Should fail 3 times
      for (let i = 0; i < 3; i++) {
        await assert.rejects(() => circuitBreaker.execute(failingFunction));
      }
      
      // Circuit should now be open
      await assert.rejects(
        () => circuitBreaker.execute(failingFunction),
        { code: 'CIRCUIT_BREAKER_OPEN' }
      );
      
      assert.strictEqual(callCount, 3);
    });
    
    it('should close circuit after successful attempts', async () => {
      const circuitBreaker = new CircuitBreaker({ 
        failureThreshold: 2, 
        resetTimeout: 1000 
      });
      
      // Fail to open circuit
      await assert.rejects(() => circuitBreaker.execute(() => {
        throw new NetworkError('Service unavailable');
      }));
      
      await assert.rejects(() => circuitBreaker.execute(() => {
        throw new NetworkError('Service unavailable');
      }));
      
      // Wait for reset timeout
      await new Promise(resolve => setTimeout(resolve, 1100));
      
      // Succeed to close circuit
      const result = await circuitBreaker.execute(() => 'success');
      assert.strictEqual(result, 'success');
    });
  });
  
  describe('ErrorMonitor', () => {
    it('should track error counts and rates', () => {
      const error = new ValidationError('Test error');
      
      // Record multiple errors
      for (let i = 0; i < 5; i++) {
        errorMonitor.recordError(error, { attempt: i });
      }
      
      const stats = errorMonitor.getStats();
      
      assert.strictEqual(stats.totalErrors, 5);
      assert.strictEqual(stats.errorTypes.ValidationError, 5);
      assert.strictEqual(stats.errorRates.ValidationError, 5);
    });
    
    it('should calculate error rates correctly', async () => {
      const error = new ValidationError('Test error');
      
      // Record errors over time
      for (let i = 0; i < 3; i++) {
        errorMonitor.recordError(error, { attempt: i });
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      const stats = errorMonitor.getStats();
      
      assert.strictEqual(stats.errorRates.ValidationError, 3);
    });
  });
  
  describe('ExpressErrorHandler', () => {
    let errorHandler;
    let mockReq;
    let mockRes;
    let mockNext;
    
    beforeEach(() => {
      errorHandler = new ExpressErrorHandler(logger);
      mockReq = {
        path: '/test',
        method: 'GET',
        ip: '127.0.0.1',
        get: sinon.stub().returns('test-agent')
      };
      mockRes = {
        status: sinon.stub().returnsThis(),
        json: sinon.stub()
      };
      mockNext = sinon.stub();
    });
    
    it('should handle ValidationError correctly', () => {
      const error = new ValidationError('Invalid field', 'testField');
      
      errorHandler.errorHandler(error, mockReq, mockRes, mockNext);
      
      assert(mockRes.status.calledWith(400));
      assert(mockRes.json.calledWith({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid field',
          field: 'testField',
          type: 'validation'
        }
      }));
    });
    
    it('should handle BusinessError correctly', () => {
      const error = new BusinessError('User not found', 'USER_NOT_FOUND');
      
      errorHandler.errorHandler(error, mockReq, mockRes, mockNext);
      
      assert(mockRes.status.calledWith(404));
      assert(mockRes.json.calledWith({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User not found',
          type: 'business'
        }
      }));
    });
    
    it('should handle SystemError correctly', () => {
      const error = new SystemError('Database connection failed');
      
      errorHandler.errorHandler(error, mockReq, mockRes, mockNext);
      
      assert(mockRes.status.calledWith(500));
      assert(mockRes.json.calledWith({
        success: false,
        error: {
          code: 'SYSTEM_ERROR',
          message: 'Internal server error',
          type: 'system'
        }
      }));
    });
  });
});
```

## 🚀 Best Practices Checklist

### Error Design & Architecture
- [ ] Create custom error classes with proper inheritance
- [ ] Include error codes and context information
- [ ] Implement proper error chaining with original errors
- [ ] Distinguish between operational and system errors
- [ ] Make errors serializable for logging and monitoring
- [ ] Use consistent error naming conventions

### Asynchronous Error Handling
- [ ] Use async/await with proper try-catch blocks
- [ ] Implement Promise rejection handling
- [ ] Handle callback errors consistently
- [ ] Use error-first callbacks for Node.js APIs
- [ ] Implement proper error propagation in promise chains
- [ ] Handle unhandled promise rejections globally

### Express.js Error Handling
- [ ] Implement centralized error handling middleware
- [ ] Use async error wrappers for route handlers
- [ ] Provide appropriate HTTP status codes
- [ ] Sanitize error messages for production
- [ ] Include error codes for client handling
- [ ] Log errors with request context

### Recovery & Resilience
- [ ] Implement retry mechanisms with exponential backoff
- [ ] Use circuit breaker pattern for external services
- [ ] Provide graceful degradation for non-critical failures
- [ ] Implement proper timeout handling
- [ ] Use connection pooling for database operations
- [ ] Implement health checks and monitoring

### Logging & Monitoring
- [ ] Use structured logging with JSON format
- [ ] Include correlation IDs for request tracking
- [ ] Monitor error rates and patterns
- [ ] Implement error alerting thresholds
- [ ] Log both errors and successful operations
- [ ] Use appropriate log levels for different error types

### Testing & Validation
- [ ] Write tests for all error scenarios
- [ ] Test retry mechanisms and circuit breakers
- [ ] Validate error handling in async operations
- [ ] Test Express error middleware
- [ ] Include performance tests for error handling
- [ ] Test error logging and monitoring

---

**Node.js Version**: [NODE_VERSION]  
**Error Handling Framework**: Custom exceptions, Express middleware, Retry patterns  
**Last Updated**: [DATE]  
**Template Version**: 1.0
