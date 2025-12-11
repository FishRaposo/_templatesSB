# Universal Template System - Generic Stack
# Generated: 2025-12-10
# Purpose: Logging utilities
# Tier: base
# Stack: generic
# Category: utilities

# ----------------------------------------------------------------------------- 
# FILE: logging-pattern.tpl.md
# PURPOSE: Generic logging design pattern
# USAGE: Adapt this pattern for your specific technology stack
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Logging Pattern

## Overview
Structured logging is essential for application monitoring, debugging, and audit trails. This pattern provides a comprehensive approach to logging with proper levels, formatting, and output destinations.

## Core Design Pattern

### 1. Logging Architecture

#### Log Levels (Priority Order)
- **FATAL**: Critical errors that cause application termination
- **ERROR**: Error conditions that prevent normal operation
- **WARNING**: Warning conditions that should be investigated
- **INFO**: Informational messages about normal operation
- **DEBUG**: Detailed debugging information
- **TRACE**: Very detailed execution tracing

#### Log Components
- **Logger**: Core logging interface with level filtering
- **Formatter**: Structured log formatting (JSON, plain text)
- **Handler**: Output destinations (console, file, remote service)
- **Context**: Request correlation and contextual information
- **Filter**: Conditional log processing
- **Metrics**: Log aggregation and monitoring

### 2. Pseudocode Implementation

```pseudocode
class Logger:
    function __init__(name, level="INFO", handlers=None):
        self.name = name
        self.level = self.parse_level(level)
        self.handlers = handlers or [ConsoleHandler()]
        self.context = {}
        self.filters = []
    
    function set_level(level):
        self.level = self.parse_level(level)
    
    function add_handler(handler):
        self.handlers.append(handler)
    
    function add_filter(filter):
        self.filters.append(filter)
    
    function with_context(context):
        return ContextLogger(self, context)
    
    function fatal(message, error=None, extra=None):
        self.log("FATAL", message, error, extra)
    
    function error(message, error=None, extra=None):
        self.log("ERROR", message, error, extra)
    
    function warning(message, error=None, extra=None):
        self.log("WARNING", message, error, extra)
    
    function info(message, error=None, extra=None):
        self.log("INFO", message, error, extra)
    
    function debug(message, error=None, extra=None):
        self.log("DEBUG", message, error, extra)
    
    function trace(message, error=None, extra=None):
        self.log("TRACE", message, error, extra)
    
    function log(level, message, error=None, extra=None):
        if not self.should_log(level):
            return
        
        # Create log entry
        log_entry = self.create_log_entry(level, message, error, extra)
        
        # Apply filters
        for filter in self.filters:
            if not filter.should_log(log_entry):
                return
        
        # Send to handlers
        for handler in self.handlers:
            handler.handle(log_entry)
    
    function should_log(level):
        return self.parse_level(level) >= self.level
    
    function create_log_entry(level, message, error, extra):
        return {
            "timestamp": current_time_iso(),
            "level": level,
            "logger": self.name,
            "message": message,
            "error": self.format_error(error) if error else None,
            "context": {**self.context, **(extra or {})},
            "thread": current_thread_id(),
            "process": current_process_id()
        }

class ContextLogger:
    function __init__(logger, context):
        self.logger = logger
        self.context = context
    
    function info(message, error=None, extra=None):
        combined_context = {**self.context, **(extra or {})}
        self.logger.info(message, error, combined_context)
    
    function error(message, error=None, extra=None):
        combined_context = {**self.context, **(extra or {})}
        self.logger.error(message, error, combined_context)
    
    # ... other log methods

class Formatter:
    function format(log_entry):
        # Override in subclasses
        pass

class JSONFormatter(Formatter):
    function format(log_entry):
        return json.dumps(log_entry, default=str)

class PlainTextFormatter(Formatter):
    function format(log_entry):
        timestamp = log_entry["timestamp"]
        level = log_entry["level"].ljust(7)
        logger = log_entry["logger"]
        message = log_entry["message"]
        
        formatted = f"{timestamp} {level} {logger} - {message}"
        
        if log_entry["error"]:
            formatted += f" | Error: {log_entry['error']}"
        
        if log_entry["context"]:
            context_str = " ".join([f"{k}={v}" for k, v in log_entry["context"].items()])
            formatted += f" | {context_str}"
        
        return formatted

class Handler:
    function __init__(formatter, level_filter=None):
        self.formatter = formatter
        self.level_filter = level_filter
    
    function handle(log_entry):
        if self.level_filter and log_entry["level"] < self.level_filter:
            return
        
        formatted = self.formatter.format(log_entry)
        self.emit(formatted)
    
    function emit(formatted_message):
        # Override in subclasses
        pass

class ConsoleHandler(Handler):
    function emit(formatted_message):
        print(formatted_message)

class FileHandler(Handler):
    function __init__(filename, formatter, level_filter=None, max_size=None, backup_count=5):
        super().__init__(formatter, level_filter)
        self.filename = filename
        self.max_size = max_size
        self.backup_count = backup_count
        self.current_size = self.get_file_size()
    
    function emit(formatted_message):
        if self.should_rotate():
            self.rotate_file()
        
        with open(self.filename, "a") as f:
            f.write(formatted_message + "\n")
        
        self.current_size += len(formatted_message) + 1

class RemoteHandler(Handler):
    function __init__(endpoint, api_key, formatter, level_filter=None):
        super().__init__(formatter, level_filter)
        self.endpoint = endpoint
        self.api_key = api_key
        self.buffer = []
        self.buffer_size = 100
    
    function emit(formatted_message):
        self.buffer.append(formatted_message)
        
        if len(self.buffer) >= self.buffer_size:
            self.flush_buffer()
    
    function flush_buffer():
        if not self.buffer:
            return
        
        try:
            self.send_to_remote(self.buffer)
            self.buffer.clear()
        except Exception as e:
            # Fallback to local logging
            print(f"Failed to send logs to remote: {e}")

// Usage Examples
function example_logging():
    # Create logger
    logger = Logger("myapp", "INFO")
    
    # Add handlers
    logger.add_handler(ConsoleHandler(PlainTextFormatter()))
    logger.add_handler(FileHandler("app.log", JSONFormatter()))
    logger.add_handler(RemoteHandler("https://logs.example.com", "api-key", JSONFormatter()))
    
    # Set global context
    logger.context = {"service": "user-service", "version": "1.0.0"}
    
    # Basic logging
    logger.info("Application starting")
    logger.error("Database connection failed", error=database_error)
    
    # With context
    user_logger = logger.with_context({"user_id": 123, "request_id": "abc-123"})
    user_logger.info("User logged in")
    
    # Structured logging
    logger.info("API request processed", extra={
        "method": "POST",
        "endpoint": "/api/users",
        "status_code": 201,
        "duration_ms": 150
    })

class RequestLogger:
    function __init__(logger):
        self.logger = logger
    
    function log_request(request):
        request_id = generate_request_id()
        
        self.logger.info("Incoming request", extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.path,
            "user_agent": request.user_agent,
            "ip_address": request.ip_address
        })
        
        return request_id
    
    function log_response(request_id, response, duration_ms):
        self.logger.info("Request completed", extra={
            "request_id": request_id,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "response_size": len(response.body)
        })
    
    function log_error(request_id, error):
        self.logger.error("Request failed", error=error, extra={
            "request_id": request_id,
            "error_type": type(error).__name__
        })

// Middleware example
function logging_middleware(logger):
    def middleware(request, response, next_handler):
        start_time = current_time_milliseconds()
        request_logger = RequestLogger(logger)
        request_id = request_logger.log_request(request)
        
        try:
            response = next_handler(request, response)
            duration = current_time_milliseconds() - start_time
            request_logger.log_response(request_id, response, duration)
            return response
            
        except Exception as e:
            duration = current_time_milliseconds() - start_time
            request_logger.log_error(request_id, e)
            raise e
```

## Technology-Specific Implementations

### Node.js (JavaScript/TypeScript)
```typescript
import winston from 'winston';
import { Request, Response, NextFunction } from 'express';

interface LogContext {
  [key: string]: any;
  requestId?: string;
  userId?: string;
  service?: string;
  version?: string;
}

class Logger {
  private winston: winston.Logger;
  private context: LogContext = {};

  constructor(name: string, level: string = 'info') {
    this.winston = winston.createLogger({
      level,
      defaultMeta: { service: name },
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        }),
        new winston.transports.File({ 
          filename: 'error.log', 
          level: 'error' 
        }),
        new winston.transports.File({ 
          filename: 'combined.log' 
        })
      ]
    });
  }

  setContext(context: LogContext): void {
    this.context = { ...this.context, ...context };
  }

  withContext(context: LogContext): Logger {
    const newLogger = Object.create(this);
    newLogger.context = { ...this.context, ...context };
    return newLogger;
  }

  private log(level: string, message: string, error?: Error, extra?: LogContext): void {
    const logData = {
      message,
      ...this.context,
      ...extra,
      ...(error && { error: error.stack })
    };

    this.winston.log(level, message, logData);
  }

  fatal(message: string, error?: Error, extra?: LogContext): void {
    this.log('error', message, error, extra);
  }

  error(message: string, error?: Error, extra?: LogContext): void {
    this.log('error', message, error, extra);
  }

  warn(message: string, error?: Error, extra?: LogContext): void {
    this.log('warn', message, error, extra);
  }

  info(message: string, extra?: LogContext): void {
    this.log('info', message, undefined, extra);
  }

  debug(message: string, extra?: LogContext): void {
    this.log('debug', message, undefined, extra);
  }

  trace(message: string, extra?: LogContext): void {
    this.log('silly', message, undefined, extra);
  }
}

// Express middleware
export const requestLogger = (logger: Logger) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const requestId = generateRequestId();
    const startTime = Date.now();

    // Set request context
    const requestLogger = logger.withContext({
      requestId,
      method: req.method,
      path: req.path,
      userAgent: req.get('User-Agent'),
      ip: req.ip
    });

    requestLogger.info('Incoming request');

    // Override res.end to log response
    const originalEnd = res.end;
    res.end = function(chunk?: any, encoding?: any) {
      const duration = Date.now() - startTime;
      
      requestLogger.info('Request completed', {
        statusCode: res.statusCode,
        duration,
        responseSize: chunk ? chunk.length : 0
      });

      originalEnd.call(this, chunk, encoding);
    };

    next();
  };
};

// Usage
const logger = new Logger('user-service');
logger.setContext({ version: '1.0.0' });

app.use(requestLogger(logger));

// In route handlers
router.get('/users/:id', async (req, res) => {
  const userLogger = logger.withContext({ userId: req.params.id });
  
  try {
    const user = await getUserById(req.params.id);
    userLogger.info('User retrieved successfully');
    res.json(user);
  } catch (error) {
    userLogger.error('Failed to retrieve user', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
```

### Python
```python
import logging
import json
import time
from typing import Dict, Any, Optional
from contextlib import contextmanager
from functools import wraps

class StructuredLogger:
    def __init__(self, name: str, level: str = "INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.context: Dict[str, Any] = {}
        
        # Configure handlers if not already configured
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        # Console handler with structured output
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(console_handler)
        
        # File handler for all logs
        file_handler = logging.FileHandler('app.log')
        file_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(file_handler)
        
        # Error file handler
        error_handler = logging.FileHandler('error.log')
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(error_handler)
    
    def set_context(self, **kwargs):
        self.context.update(kwargs)
    
    def with_context(self, **kwargs):
        """Create a new logger with additional context"""
        new_logger = StructuredLogger(self.logger.name)
        new_logger.logger = self.logger
        new_logger.context = {**self.context, **kwargs}
        return new_logger
    
    def _log(self, level: int, message: str, error: Optional[Exception] = None, **extra):
        if not self.logger.isEnabledFor(level):
            return
        
        log_data = {
            'message': message,
            'timestamp': time.time(),
            'logger': self.logger.name,
            **self.context,
            **extra
        }
        
        if error:
            log_data['error'] = {
                'type': type(error).__name__,
                'message': str(error),
                'stack': traceback.format_exc()
            }
        
        self.logger.log(level, json.dumps(log_data, default=str))
    
    def fatal(self, message: str, error: Optional[Exception] = None, **extra):
        self._log(logging.FATAL, message, error, **extra)
    
    def error(self, message: str, error: Optional[Exception] = None, **extra):
        self._log(logging.ERROR, message, error, **extra)
    
    def warning(self, message: str, error: Optional[Exception] = None, **extra):
        self._log(logging.WARNING, message, error, **extra)
    
    def info(self, message: str, **extra):
        self._log(logging.INFO, message, None, **extra)
    
    def debug(self, message: str, **extra):
        self._log(logging.DEBUG, message, None, **extra)
    
    def trace(self, message: str, **extra):
        self._log(logging.DEBUG, message, None, **extra)

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        if hasattr(record, 'stack_info') and record.stack_info:
            log_data['stack'] = record.stack_info
        
        return json.dumps(log_data, default=str)

# Decorator for function logging
def log_function_calls(logger: StructuredLogger):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            func_logger = logger.with_context(
                function=func.__name__,
                module=func.__module__
            )
            
            start_time = time.time()
            func_logger.debug('Function started')
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                func_logger.debug('Function completed', duration=duration)
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                func_logger.error('Function failed', error=e, duration=duration)
                raise
        
        return wrapper
    return decorator

# Context manager for operation logging
@contextmanager
def log_operation(logger: StructuredLogger, operation: str, **context):
    op_logger = logger.with_context(operation=operation, **context)
    start_time = time.time()
    
    op_logger.info('Operation started')
    try:
        yield op_logger
        duration = time.time() - start_time
        op_logger.info('Operation completed', duration=duration)
    except Exception as e:
        duration = time.time() - start_time
        op_logger.error('Operation failed', error=e, duration=duration)
        raise

# Usage
logger = StructuredLogger('user-service')
logger.set_context(version='1.0.0', service='user-service')

@log_function_calls(logger)
def create_user(user_data: Dict[str, Any]):
    with log_operation(logger, 'user_creation', user_id=user_data.get('id')):
        # Business logic here
        pass

# Flask middleware example
@app.before_request
def before_request():
    g.request_id = generate_request_id()
    g.start_time = time.time()
    
    request_logger = logger.with_context(
        request_id=g.request_id,
        method=request.method,
        path=request.path
    )
    request_logger.info('Incoming request')

@app.after_request
def after_request(response):
    duration = time.time() - g.start_time
    
    request_logger = logger.with_context(request_id=g.request_id)
    request_logger.info('Request completed', 
                       status_code=response.status_code,
                       duration=duration)
    return response
```

### Go
```go
package logging

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "runtime"
    "time"
)

type LogLevel int

const (
    TRACE LogLevel = iota
    DEBUG
    INFO
    WARNING
    ERROR
    FATAL
)

type LogEntry struct {
    Timestamp time.Time              `json:"timestamp"`
    Level     string                 `json:"level"`
    Logger    string                 `json:"logger"`
    Message   string                 `json:"message"`
    Error     *ErrorInfo              `json:"error,omitempty"`
    Context   map[string]interface{} `json:"context,omitempty"`
    Thread    int                    `json:"thread"`
    Process   int                    `json:"process"`
}

type ErrorInfo struct {
    Type    string `json:"type"`
    Message string `json:"message"`
    Stack   string `json:"stack,omitempty"`
}

type Logger struct {
    name     string
    level    LogLevel
    handlers []Handler
    context  map[string]interface{}
}

type Handler interface {
    Handle(entry LogEntry) error
}

type ConsoleHandler struct{}
type FileHandler struct {
    filename string
}
type JSONHandler struct {
    filename string
}

func NewLogger(name string, level LogLevel) *Logger {
    return &Logger{
        name:     name,
        level:    level,
        handlers: []Handler{ConsoleHandler{}},
        context:  make(map[string]interface{}),
    }
}

func (l *Logger) SetContext(key string, value interface{}) {
    l.context[key] = value
}

func (l *Logger) WithContext(context map[string]interface{}) *Logger {
    newLogger := &Logger{
        name:     l.name,
        level:    l.level,
        handlers: l.handlers,
        context:  make(map[string]interface{}),
    }
    
    // Copy existing context
    for k, v := range l.context {
        newLogger.context[k] = v
    }
    
    // Add new context
    for k, v := range context {
        newLogger.context[k] = v
    }
    
    return newLogger
}

func (l *Logger) log(level LogLevel, message string, err error, extra map[string]interface{}) {
    if level < l.level {
        return
    }
    
    // Create log entry
    entry := LogEntry{
        Timestamp: time.Now(),
        Level:     levelToString(level),
        Logger:    l.name,
        Message:   message,
        Context:   make(map[string]interface{}),
        Thread:    getGoroutineID(),
        Process:   os.Getpid(),
    }
    
    // Copy context
    for k, v := range l.context {
        entry.Context[k] = v
    }
    
    // Add extra context
    for k, v := range extra {
        entry.Context[k] = v
    }
    
    // Add error info
    if err != nil {
        entry.Error = &ErrorInfo{
            Type:    fmt.Sprintf("%T", err),
            Message: err.Error(),
        }
    }
    
    // Send to handlers
    for _, handler := range l.handlers {
        handler.Handle(entry)
    }
}

func (l *Logger) Fatal(message string, err error, extra map[string]interface{}) {
    l.log(FATAL, message, err, extra)
    os.Exit(1)
}

func (l *Logger) Error(message string, err error, extra map[string]interface{}) {
    l.log(ERROR, message, err, extra)
}

func (l *Logger) Warning(message string, extra map[string]interface{}) {
    l.log(WARNING, message, nil, extra)
}

func (l *Logger) Info(message string, extra map[string]interface{}) {
    l.log(INFO, message, nil, extra)
}

func (l *Logger) Debug(message string, extra map[string]interface{}) {
    l.log(DEBUG, message, nil, extra)
}

func (l *Logger) Trace(message string, extra map[string]interface{}) {
    l.log(TRACE, message, nil, extra)
}

func (h ConsoleHandler) Handle(entry LogEntry) error {
    fmt.Printf("[%s] %s %s - %s\n", 
        entry.Timestamp.Format("2006-01-02 15:04:05"),
        entry.Level,
        entry.Logger,
        entry.Message)
    
    if entry.Error != nil {
        fmt.Printf("  Error: %s\n", entry.Error.Message)
    }
    
    if len(entry.Context) > 0 {
        contextJSON, _ := json.Marshal(entry.Context)
        fmt.Printf("  Context: %s\n", string(contextJSON))
    }
    
    return nil
}

func (h FileHandler) Handle(entry LogEntry) error {
    file, err := os.OpenFile(h.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }
    defer file.Close()
    
    entryJSON, _ := json.Marshal(entry)
    _, err = file.WriteString(string(entryJSON) + "\n")
    return err
}

// HTTP middleware for Go
func LoggingMiddleware(logger *Logger) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            start := time.Now()
            requestID := generateRequestID()
            
            // Add request ID to context
            ctx := context.WithValue(r.Context(), "requestID", requestID)
            r = r.WithContext(ctx)
            
            requestLogger := logger.WithContext(map[string]interface{}{
                "requestID": requestID,
                "method":    r.Method,
                "path":      r.URL.Path,
                "userAgent": r.UserAgent(),
                "remoteAddr": r.RemoteAddr,
            })
            
            requestLogger.Info("Incoming request")
            
            // Wrap response writer to capture status
            wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}
            
            next.ServeHTTP(wrapped, r)
            
            duration := time.Since(start)
            requestLogger.Info("Request completed", map[string]interface{}{
                "statusCode": wrapped.statusCode,
                "duration":   duration.Milliseconds(),
            })
        })
    }
}

// Usage
func main() {
    logger := NewLogger("user-service", INFO)
    logger.SetContext("version", "1.0.0")
    
    // Add file handler
    logger.handlers = append(logger.handlers, FileHandler{"app.log"})
    
    // Use in HTTP middleware
    mux := http.NewServeMux()
    mux.Use(LoggingMiddleware(logger))
    
    // Log with context
    userLogger := logger.WithContext(map[string]interface{}{
        "userID": 123,
        "action": "create_user",
    })
    
    userLogger.Info("User created successfully")
}
```

## Best Practices

### 1. Log Content
- Include relevant context (user ID, request ID, correlation ID)
- Use structured logging with consistent field names
- Avoid logging sensitive data (passwords, tokens, PII)
- Include timestamps and log levels

### 2. Performance
- Use async logging for high-throughput applications
- Buffer log writes to reduce I/O operations
- Set appropriate log levels for different environments
- Consider log sampling for verbose logs

### 3. Monitoring
- Send logs to centralized logging systems
- Set up alerts for error patterns
- Monitor log volume and retention
- Use log aggregation for analysis

### 4. Security
- Sanitize logs to remove sensitive information
- Use secure connections for remote logging
- Implement log tampering protection
- Follow compliance requirements for log retention

## Adaptation Checklist

- [ ] Choose logging library for your technology stack
- [ ] Implement structured logging with JSON format
- [ ] Set up multiple handlers (console, file, remote)
- [ ] Add context and correlation support
- [ ] Implement log levels and filtering
- [ ] Create middleware for request/response logging
- [ ] Set up log rotation and retention
- [ ] Add monitoring and alerting integration

## Common Pitfalls

1. **Logging sensitive data** - Never log passwords, tokens, or PII
2. **Poor log levels** - Use appropriate levels for different message types
3. **Missing context** - Include request IDs and correlation IDs
4. **Performance impact** - Async logging for high-throughput scenarios
5. **Log explosion** - Control log volume with proper levels and filtering

---

*Generic Logging Pattern - Adapt to your technology stack*
