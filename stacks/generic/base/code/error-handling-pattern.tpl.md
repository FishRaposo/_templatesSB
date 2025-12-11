# Universal Template System - Generic Stack
# Generated: 2025-12-10
# Purpose: Error handling utilities
# Tier: base
# Stack: generic
# Category: utilities

# ----------------------------------------------------------------------------- 
# FILE: error-handling-pattern.tpl.md
# PURPOSE: Generic error handling design pattern
# USAGE: Adapt this pattern for your specific technology stack
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Error Handling Pattern

## Overview
Robust error handling is crucial for application reliability, debugging, and user experience. This pattern provides a structured approach to error management across different technology stacks.

## Core Design Pattern

### 1. Error Classification System

#### Error Types
- **Validation Errors**: Input validation failures
- **Business Logic Errors**: Domain-specific rule violations
- **Infrastructure Errors**: Database, network, external service failures
- **Authentication/Authorization Errors**: Security-related failures
- **System Errors**: Runtime exceptions, resource exhaustion

#### Error Severity Levels
- **CRITICAL**: System-wide failures requiring immediate attention
- **ERROR**: Functional failures that break user workflows
- **WARNING**: Recoverable issues that don't stop execution
- **INFO**: Expected error conditions (e.g., user not found)

### 2. Pseudocode Implementation

```pseudocode
// Custom Error Classes
class ApplicationError:
    function __init__(message, code, severity, details=None):
        self.message = message
        self.code = code
        self.severity = severity
        self.details = details or {}
        self.timestamp = current_time()
        self.trace_id = generate_trace_id()

class ValidationError(ApplicationError):
    function __init__(message, field=None):
        super().__init__(message, "VALIDATION_ERROR", "ERROR")
        self.field = field

class BusinessError(ApplicationError):
    function __init__(message, rule=None):
        super().__init__(message, "BUSINESS_ERROR", "ERROR")
        self.rule = rule

class InfrastructureError(ApplicationError):
    function __init__(message, service=None):
        super().__init__(message, "INFRASTRUCTURE_ERROR", "ERROR")
        self.service = service

// Error Handler
class ErrorHandler:
    function __init__(logger, notifier):
        self.logger = logger
        self.notifier = notifier
        self.error_handlers = {}
    
    function register_handler(error_type, handler):
        self.error_handlers[error_type] = handler
    
    function handle(error, context=None):
        // Log the error
        self.log_error(error, context)
        
        // Find appropriate handler
        handler = self.error_handlers.get(error.code) or self.default_handler
        
        // Execute handler
        return handler(error, context)
    
    function log_error(error, context):
        log_data = {
            "message": error.message,
            "code": error.code,
            "severity": error.severity,
            "timestamp": error.timestamp,
            "trace_id": error.trace_id,
            "context": context
        }
        
        if error.severity == "CRITICAL":
            self.logger.critical(log_data)
            self.notifier.send_alert(error)
        elif error.severity == "ERROR":
            self.logger.error(log_data)
        elif error.severity == "WARNING":
            self.logger.warning(log_data)
        else:
            self.logger.info(log_data)
    
    function default_handler(error, context):
        return {
            "success": false,
            "error": {
                "message": error.message,
                "code": error.code,
                "trace_id": error.trace_id
            }
        }

// Validation Helper
class Validator:
    function validate_required(value, field_name):
        if value is None or value == "":
            raise ValidationError(f"{field_name} is required", field_name)
    
    function validate_email(value, field_name):
        if not is_valid_email(value):
            raise ValidationError(f"{field_name} must be a valid email", field_name)
    
    function validate_range(value, min_val, max_val, field_name):
        if value < min_val or value > max_val:
            raise ValidationError(f"{field_name} must be between {min_val} and {max_val}", field_name)

// Usage Examples
function create_user(user_data):
    try:
        // Validate input
        validator = new Validator()
        validator.validate_required(user_data.email, "email")
        validator.validate_email(user_data.email, "email")
        
        // Business logic
        if user_exists(user_data.email):
            raise BusinessError("User already exists", "UNIQUE_EMAIL")
        
        // Infrastructure operation
        user = database.create_user(user_data)
        
        return {"success": true, "data": user}
        
    except ValidationError as e:
        return error_handler.handle(e, {"operation": "create_user"})
    except BusinessError as e:
        return error_handler.handle(e, {"operation": "create_user"})
    except DatabaseError as e:
        infra_error = InfrastructureError("Failed to create user", "database")
        return error_handler.handle(infra_error, {"operation": "create_user", "original_error": e})
```

## Technology-Specific Implementations

### Node.js (JavaScript/TypeScript)
```typescript
// Error classes
export class ApplicationError extends Error {
  constructor(
    public message: string,
    public code: string,
    public severity: 'CRITICAL' | 'ERROR' | 'WARNING' | 'INFO',
    public details?: Record<string, any>
  ) {
    super(message);
    this.name = 'ApplicationError';
  }
}

export class ValidationError extends ApplicationError {
  constructor(message: string, public field?: string) {
    super(message, 'VALIDATION_ERROR', 'ERROR', { field });
    this.name = 'ValidationError';
  }
}

// Error handler middleware
export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const traceId = req.headers['x-trace-id'] || generateTraceId();
  
  if (error instanceof ValidationError) {
    logger.warn('Validation error', { error: error.message, field: error.field, traceId });
    return res.status(400).json({
      success: false,
      error: {
        message: error.message,
        code: error.code,
        field: error.field,
        traceId
      }
    });
  }
  
  // Handle other error types...
  logger.error('Unhandled error', { error: error.message, stack: error.stack, traceId });
  res.status(500).json({
    success: false,
    error: {
      message: 'Internal server error',
      code: 'INTERNAL_ERROR',
      traceId
    }
  });
};
```

### Python
```python
from dataclasses import dataclass
from typing import Dict, Any, Optional
import logging
import traceback

@dataclass
class ApplicationError(Exception):
    message: str
    code: str
    severity: str = "ERROR"
    details: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        self.trace_id = generate_trace_id()
        self.timestamp = datetime.utcnow()
        super().__init__(self.message)

class ValidationError(ApplicationError):
    def __init__(self, message: str, field: str = None):
        super().__init__(message, "VALIDATION_ERROR", "ERROR", {"field": field})

class ErrorHandler:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.handlers = {}
    
    def handle(self, error: Exception, context: Dict[str, Any] = None):
        if isinstance(error, ApplicationError):
            self._log_application_error(error, context)
            return self._format_error_response(error)
        else:
            # Handle unexpected errors
            self.logger.error(f"Unexpected error: {str(error)}", 
                           exc_info=True, extra={"context": context})
            return {
                "success": False,
                "error": {
                    "message": "Internal server error",
                    "code": "INTERNAL_ERROR"
                }
            }

# Decorator for error handling
def handle_errors(error_handler: ErrorHandler):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except ApplicationError as e:
                return error_handler.handle(e, {"function": func.__name__})
            except Exception as e:
                return error_handler.handle(e, {"function": func.__name__})
        return wrapper
    return decorator

@handle_errors(error_handler)
def create_user(user_data: Dict[str, Any]):
    if not user_data.get("email"):
        raise ValidationError("Email is required", "email")
    # Business logic here...
```

### Go
```go
package errors

import (
    "fmt"
    "runtime"
    "time"
)

type AppError struct {
    Message   string                 `json:"message"`
    Code      string                 `json:"code"`
    Severity  string                 `json:"severity"`
    Details   map[string]interface{} `json:"details,omitempty"`
    TraceID   string                 `json:"trace_id"`
    Timestamp time.Time              `json:"timestamp"`
    Stack     string                 `json:"stack,omitempty"`
}

func (e *AppError) Error() string {
    return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func NewValidationError(message, field string) *AppError {
    return &AppError{
        Message:  message,
        Code:     "VALIDATION_ERROR",
        Severity: "ERROR",
        Details:  map[string]interface{}{"field": field},
        TraceID:  generateTraceID(),
        Stack:    getStack(),
    }
}

// Error handler function
func HandleError(err error, context map[string]interface{}) map[string]interface{} {
    if appErr, ok := err.(*AppError); ok {
        logError(appErr, context)
        return map[string]interface{}{
            "success": false,
            "error": map[string]interface{}{
                "message":  appErr.Message,
                "code":     appErr.Code,
                "trace_id": appErr.TraceID,
            },
        }
    }
    
    // Handle unexpected errors
    logUnexpectedError(err, context)
    return map[string]interface{}{
        "success": false,
        "error": map[string]interface{}{
            "message": "Internal server error",
            "code":    "INTERNAL_ERROR",
        },
    }
}

func getStack() string {
    buf := make([]byte, 1024)
    for {
        n := runtime.Stack(buf, false)
        if n < len(buf) {
            return string(buf[:n])
        }
        buf = make([]byte, 2*len(buf))
    }
}
```

## Best Practices

### 1. Error Design
- Use specific error types for different failure scenarios
- Include contextual information in error details
- Provide user-friendly messages while logging technical details
- Use consistent error codes across the application

### 2. Logging Strategy
- Log all errors with sufficient context
- Include trace IDs for error correlation
- Use appropriate log levels based on severity
- Avoid logging sensitive information

### 3. User Experience
- Return meaningful error messages to users
- Include error codes for programmatic handling
- Provide suggestions for resolving validation errors
- Hide internal implementation details from users

### 4. Monitoring & Alerting
- Set up alerts for critical errors
- Monitor error rates and patterns
- Track error recovery times
- Use error dashboards for visibility

## Adaptation Checklist

- [ ] Define error classes/types for your language
- [ ] Implement error handling middleware/functions
- [ ] Set up structured logging with trace IDs
- [ ] Create validation helpers with specific error types
- [ ] Configure monitoring and alerting
- [ ] Add error documentation and error code reference
- [ ] Test error scenarios in unit tests
- [ ] Set up error reporting in production

## Common Pitfalls

1. **Generic error messages** - Be specific about what went wrong
2. **Missing context** - Include relevant information for debugging
3. **Swallowing errors** - Always handle or log errors appropriately
4. **Exposing internals** - Don't reveal sensitive system information
5. **Inconsistent error handling** - Use the same pattern throughout

---

*Generic Error Handling Pattern - Adapt to your technology stack*
