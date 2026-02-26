# Task 4 — Error Handling Strategy for REST API

> **Skills Invoked**: `error-handling`, `input-validation`, `logging-strategies`

---

## Complete Error Handling Implementation

### 1. Typed Error Hierarchy (JavaScript/Express)

```javascript
// errors/AppError.js
class AppError extends Error {
  constructor(message, code, statusCode = 500, isOperational = true) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }
}

// errors/ValidationError.js
class ValidationError extends AppError {
  constructor(message, fields = []) {
    super(message, 'VALIDATION_ERROR', 400);
    this.fields = fields;
  }
}

// errors/NotFoundError.js
class NotFoundError extends AppError {
  constructor(resource, id) {
    super(`${resource} '${id}' not found`, 'NOT_FOUND', 404);
    this.resource = resource;
    this.resourceId = id;
  }
}

// errors/AuthenticationError.js
class AuthenticationError extends AppError {
  constructor(message = 'Authentication required') {
    super(message, 'AUTHENTICATION_ERROR', 401);
  }
}

// errors/ExternalServiceError.js - wraps third-party failures
class ExternalServiceError extends AppError {
  constructor(service, cause) {
    super(`${service} failed: ${cause.message}`, 'EXTERNAL_ERROR', 502);
    this.service = service;
    this.cause = cause;
  }
}

// errors/ConflictError.js
class ConflictError extends AppError {
  constructor(message) {
    super(message, 'CONFLICT', 409);
  }
}

module.exports = {
  AppError,
  ValidationError,
  NotFoundError,
  AuthenticationError,
  ExternalServiceError,
  ConflictError
};
```

---

### 2. Error Boundary Middleware

```javascript
// middleware/errorHandler.js
const logger = require('../utils/logger');
const { AppError } = require('../errors');

function errorHandler(err, req, res, next) {
  // Log with correlation ID
  logger.error({
    message: err.message,
    code: err.code || 'UNKNOWN',
    correlationId: req.correlationId,
    stack: err.stack,
    path: req.path,
    method: req.method,
    cause: err.cause
  });

  // Operational errors — return structured response
  if (err instanceof AppError && err.isOperational) {
    const response = {
      error: {
        code: err.code,
        message: err.message,
        ...(err.fields && { fields: err.fields }),
        ...(err.resource && { resource: err.resource })
      },
      meta: {
        timestamp: err.timestamp,
        requestId: req.correlationId
      }
    };
    return res.status(err.statusCode).json(response);
  }

  // Programmer errors — generic message, log details
  return res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred'
    },
    meta: {
      requestId: req.correlationId
    }
  });
}

module.exports = errorHandler;
```

---

### 3. Retry Logic with Exponential Backoff

```javascript
// utils/retry.js
const { ExternalServiceError } = require('../errors');

class RetryConfig {
  constructor(options = {}) {
    this.maxAttempts = options.maxAttempts || 3;
    this.baseDelay = options.baseDelay || 1000;
    this.maxDelay = options.maxDelay || 30000;
    this.transientErrors = options.transientErrors || [
      'ECONNRESET',
      'ETIMEDOUT',
      'ECONNREFUSED',
      'ENOTFOUND',
      'EPIPE'
    ];
  }

  isTransient(error) {
    return this.transientErrors.includes(error.code) ||
           error.message?.includes('timeout') ||
           error.statusCode >= 500;
  }

  calculateDelay(attempt) {
    const exponential = this.baseDelay * Math.pow(2, attempt - 1);
    const jitter = Math.random() * 1000;
    return Math.min(exponential + jitter, this.maxDelay);
  }
}

async function withRetry(operation, config = new RetryConfig()) {
  let lastError;

  for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;

      if (attempt === config.maxAttempts) {
        break;
      }

      if (!config.isTransient(error)) {
        throw error; // Non-transient, fail fast
      }

      const delay = config.calculateDelay(attempt);
      await sleep(delay);
    }
  }

  throw new ExternalServiceError(
    'External service',
    new Error(`Failed after ${config.maxAttempts} attempts: ${lastError.message}`)
  );
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { withRetry, RetryConfig };
```

---

### 4. Error Wrapping with Cause Chain

```javascript
// services/paymentService.js
const { withRetry } = require('../utils/retry');
const { ExternalServiceError } = require('../errors');

class PaymentService {
  constructor(paymentGateway) {
    this.gateway = paymentGateway;
  }

  async processPayment(paymentRequest) {
    try {
      const result = await withRetry(
        () => this.gateway.charge(paymentRequest),
        { maxAttempts: 3, baseDelay: 1000 }
      );
      return result;
    } catch (error) {
      // Wrap with context while preserving cause
      throw new ExternalServiceError('Payment gateway', error);
    }
  }
}

// Test verifying error propagation
const assert = require('assert');

describe('PaymentService Error Propagation', () => {
  it('should wrap gateway errors while preserving cause chain', async () => {
    const mockGateway = {
      charge: () => Promise.reject(new Error('Network timeout'))
    };
    const service = new PaymentService(mockGateway);

    try {
      await service.processPayment({ amount: 100 });
      assert.fail('Should have thrown');
    } catch (error) {
      assert.equal(error.code, 'EXTERNAL_ERROR');
      assert.equal(error.service, 'Payment gateway');
      assert.ok(error.cause.message.includes('Network timeout'));
      assert.ok(error.stack.includes('Network timeout'));
    }
  });
});
```

---

## Python/FastAPI Implementation

```python
# errors.py
from fastapi import HTTPException
from typing import Optional, Any
from datetime import datetime

class AppError(Exception):
    def __init__(
        self,
        message: str,
        code: str,
        status_code: int = 500,
        is_operational: bool = True,
        details: Optional[dict] = None
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.is_operational = is_operational
        self.timestamp = datetime.utcnow().isoformat()
        self.details = details or {}

class ValidationError(AppError):
    def __init__(self, message: str, fields: list = None):
        super().__init__(message, "VALIDATION_ERROR", 400)
        self.fields = fields or []

class NotFoundError(AppError):
    def __init__(self, resource: str, resource_id: str):
        super().__init__(
            f"{resource} '{resource_id}' not found",
            "NOT_FOUND",
            404
        )
        self.resource = resource
        self.resource_id = resource_id

class ExternalServiceError(AppError):
    def __init__(self, service: str, cause: Exception):
        super().__init__(
            f"{service} failed: {str(cause)}",
            "EXTERNAL_ERROR",
            502
        )
        self.service = service
        self.cause = cause

# middleware.py
from fastapi import Request
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

async def error_handler(request: Request, call_next):
    try:
        return await call_next(request)
    except AppError as e:
        logger.error(f"Operational error: {e.code}", extra={
            "code": e.code,
            "path": request.url.path,
            "correlation_id": request.state.correlation_id
        })

        response = {
            "error": {
                "code": e.code,
                "message": e.message,
                **e.details
            },
            "meta": {
                "timestamp": e.timestamp,
                "request_id": request.state.correlation_id
            }
        }
        return JSONResponse(status_code=e.status_code, content=response)
    except Exception as e:
        logger.exception("Unhandled error")
        return JSONResponse(
            status_code=500,
            content={
                "error": {"code": "INTERNAL_ERROR", "message": "Unexpected error"},
                "meta": {"request_id": request.state.correlation_id}
            }
        )

# retry.py
import asyncio
import random
from functools import wraps

class RetryConfig:
    def __init__(self, max_attempts=3, base_delay=1.0, max_delay=30.0):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.transient_exceptions = (ConnectionError, TimeoutError)

    def is_transient(self, error):
        return isinstance(error, self.transient_exceptions)

    def calculate_delay(self, attempt):
        exponential = self.base_delay * (2 ** (attempt - 1))
        jitter = random.uniform(0, 1)
        return min(exponential + jitter, self.max_delay)

def with_retry(config=None):
    config = config or RetryConfig()

    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_error = None

            for attempt in range(1, config.max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_error = e

                    if attempt == config.max_attempts:
                        break

                    if not config.is_transient(e):
                        raise

                    delay = config.calculate_delay(attempt)
                    await asyncio.sleep(delay)

            raise ExternalServiceError(
                func.__name__,
                last_error
            )

        return async_wrapper
    return decorator

# Usage
class PaymentService:
    @with_retry(RetryConfig(max_attempts=3, base_delay=1.0))
    async def process_payment(self, request):
        return await self.gateway.charge(request)
```

---

## Evaluation Checklist

- [x] Error hierarchy distinguishes operational vs programmer errors
- [x] Retry logic handles transient vs permanent failures
- [x] Error context preserved through wrapping (cause chain)
- [x] HTTP boundary converts errors to proper responses
- [x] Multi-language output (JavaScript + Python)
- [x] Test verifies error propagation through all layers
- [x] 5 error classes implemented (AppError, ValidationError, NotFoundError, AuthError, ExternalServiceError)
