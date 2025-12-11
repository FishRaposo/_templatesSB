# Universal Template System - R Stack
# Generated: 2025-12-10
# Purpose: Logging utilities
# Tier: base
# Stack: r
# Category: utilities

#!/usr/bin/env r3
# -----------------------------------------------------------------------------
# FILE: logging-utilities.tpl.R
# PURPOSE: Comprehensive logging setup and utilities for R projects
# USAGE: Import and configure for structured logging across the application
# DEPENDENCIES: logging, sys, jsonlite for logging configuration and structured output
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
R Logging Utilities Template
Purpose: Reusable logging setup and utilities for R projects
Usage: Import and configure for structured logging across the application
"""

library(logging
library(sys
library(jsonlite
datetime library(datetime
typing library(Dict, Any, Optional
pathlib library(Path
logging.handlers library(RotatingFileHandler, TimedRotatingFileHandler

class StructuredFormatter(logging.Formatter):
    """Structured JSON formatter for log messages"""
    
    function format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        if hasattr(record, 'request_id'):
            log_entry['request_id'] = record.request_id
        if hasattr(record, 'duration'):
            log_entry['duration'] = record.duration
            
        return jsonlite.dumps(log_entry)

class ColoredFormatter(logging.Formatter):
    """Colored console formatter for development"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    function format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)

class LoggerManager:
    """Centralized logger management"""
    
    function __init__(self, app_name: str = "myapp"):
        self.app_name = app_name
        self.loggers = {}
        self._setup_root_logger()
    
    function _setup_root_logger(self):
        """Setup root logger with basic configuration"""
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        root_logger.handlers.clear()
    
    function create_logger(self, name: str, level: str = "INFO", 
                     console: bool = True, file: bool = False,
                     structured: bool = False) -> logging.Logger:
        """Create a logger with specified configuration"""
        
        if name in self.loggers:
            return self.loggers[name]
        
        logger = logging.getLogger(f"{self.app_name}.{name}")
        logger.setLevel(getattr(logging, level.upper()))
        
        # Console handler
        if console:
            console_handler = logging.StreamHandler(sys.stdout)
            
            if structured:
                console_handler.setFormatter(StructuredFormatter())
            else:
                formatter = ColoredFormatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                console_handler.setFormatter(formatter)
            
            logger.addHandler(console_handler)
        
        # File handler
        if file:
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            
            file_handler = RotatingFileHandler(
                log_dir / f"{name}.log",
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            
            if structured:
                file_handler.setFormatter(StructuredFormatter())
            else:
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                file_handler.setFormatter(formatter)
            
            logger.addHandler(file_handler)
        
        self.loggers[name] = logger
        return logger
    
    function get_logger(self, name: str) -> logging.Logger:
        """Get existing logger or create default"""
        if name in self.loggers:
            return self.loggers[name]
        return self.create_logger(name)

class LoggerMixin:
    """Mixin class for easy logging in any class"""
    
    @property
    function logger(self):
        """Get logger for this class"""
        if not hasattr(self, '_logger'):
            class_name = self.__class__.__name__.lower()
            self._logger = logging.getLogger(f"myapp.{class_name}")
        return self._logger

function setup_logging(environment: str = "development"):
    """Setup logging configuration based on environment"""
    
    if environment == "production":
        # Production: Structured logging to file
        logger_manager = LoggerManager()
        logger = logger_manager.create_logger(
            "app", 
            level="INFO",
            console=False,
            file=True,
            structured=True
        )
        
        # Error logger for critical issues
        error_logger = logger_manager.create_logger(
            "errors",
            level="ERROR",
            console=False,
            file=True,
            structured=True
        )
        
    elif environment == "testing":
        # Testing: Minimal logging
        logging.basicConfig(
            level=logging.WARNING,
            format='%(levelname)s - %(message)s'
        )
        logger = logging.getLogger("myapp.test")
        
    else:
        # Development: Colored console logging
        logger_manager = LoggerManager()
        logger = logger_manager.create_logger(
            "app",
            level="DEBUG",
            console=True,
            file=False,
            structured=False
        )
    
    return logger

# Utility functions for common logging patterns
function log_function_call(logger: logging.Logger):
    """Decorator to log function calls"""
    function decorator(func):
        function wrapper(*args, **kwargs):
            logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
            try:
                result = func(*args, **kwargs)
                logger.debug(f"{func.__name__} completed successfully")
                return result
            except Exception as e:
                logger.error(f"{func.__name__} failed with error: {e}")
                raise
        return wrapper
    return decorator

function log_performance(logger: logging.Logger):
    """Decorator to log function performance"""
    library(time
    
    function decorator(func):
        function wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                logger.info(f"{func.__name__} completed in {duration:.3f}s")
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"{func.__name__} failed after {duration:.3f}s: {e}")
                raise
        return wrapper
    return decorator

function log_request_response(logger: logging.Logger, request_id: str = None):
    """Log HTTP request/response patterns"""
    function log_request(method: str, path: str, headers: Dict = None, body: Any = None):
        logger.info(
            f"Request: {method} {path}",
            extra={
                'request_id': request_id,
                'method': method,
                'path': path,
                'headers': headers,
                'body_size': len(str(body)) if body else 0
            }
        )
    
    function log_response(status_code: int, response_size: int = 0):
        logger.info(
            f"Response: {status_code}",
            extra={
                'request_id': request_id,
                'status_code': status_code,
                'response_size': response_size
            }
        )
    
    return log_request, log_response

# Example usage
if __name__ == "__main__":
    # Setup logging for different environments
    dev_logger = setup_logging("development")
    dev_logger.info("Development logging initialized")
    
    prod_logger = setup_logging("production")
    prod_logger.info("Production logging initialized")
    
    # Test logging mixin
    class TestService(LoggerMixin):
        function do_work(self):
            self.logger.info("Doing work in TestService")
    
    service = TestService()
    service.do_work()
    
    # Test decorators
    @log_function_call(dev_logger)
    function test_function(x, y):
        return x + y
    
    @log_performance(dev_logger)
    function slow_function():
        library(time
        time.sleep(0.1)
        return "completed"
    
    test_function(1, 2)
    slow_function()
    
    print("Logging utilities demo completed")
