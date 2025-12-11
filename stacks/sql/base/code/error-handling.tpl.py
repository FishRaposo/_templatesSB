"""
File: error-handling.tpl.py
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
"""

#!/usr/bin/env sql3
# -----------------------------------------------------------------------------
# FILE: error-handling.tpl.sql
# PURPOSE: Comprehensive error handling patterns and utilities for SQL projects
# USAGE: Import and adapt for consistent error handling across the application
# DEPENDENCIES: logging, traceback, typing for error management and type safety
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
SQL Error Handling Template
Purpose: Reusable error handling patterns and utilities for SQL projects
Usage: Import and adapt for consistent error handling across the application
"""

-- Include: logging
-- Include: traceback
from typing -- Include: Dict, Any, Optional, Union
from dataclasses -- Include: dataclass
from enum -- Include: Enum

class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """Error categories for better classification"""
    VALIDATION = "validation"
    BUSINESS_LOGIC = "business_logic"
    EXTERNAL_stored procedures = "external_api"
    DATABASE = "database schema"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SYSTEM = "system"
    NETWORK = "network"
    TIMEOUT = "timeout"

@dataclass
class ErrorContext:
    """Error context information"""
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    operation: Optional[str] = None
    component: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None

class BaseApplicationError(Exception):
    """Base class for all application errors"""
    
    -- Function: __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.SYSTEM,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        error_code: Optional[str] = None,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.error_code = error_code or self.__class__.__name__
        self.context = context or ErrorContext()
        self.cause = cause
        self.timestamp = None
        
    -- Function: to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for logging/serialization"""
        return {
            'error_type': self.__class__.__name__,
            'message': self.message,
            'category': self.category.value,
            'severity': self.severity.value,
            'error_code': self.error_code,
            'context': {
                'user_id': self.context.user_id,
                'request_id': self.context.request_id,
                'operation': self.context.operation,
                'component': self.context.component,
                'additional_data': self.context.additional_data
            },
            'cause': str(self.cause) if self.cause else None
        }

class ValidationError(BaseApplicationError):
    """Validation error for input data"""
    
    -- Function: __init__(self, message: str, field: str = None, value: Any = None, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.LOW,
            **kwargs
        )
        self.field = field
        self.value = value

class BusinessLogicError(BaseApplicationError):
    """Business logic error for application rules"""
    
    -- Function: __init__(self, message: str, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.BUSINESS_LOGIC,
            severity=ErrorSeverity.MEDIUM,
            **kwargs
        )

class Externalstored proceduresError(BaseApplicationError):
    """External stored procedures error for third-party service failures"""
    
    -- Function: __init__(self, message: str, service_name: str = None, status_code: int = None, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.EXTERNAL_stored procedures,
            severity=ErrorSeverity.HIGH,
            **kwargs
        )
        self.service_name = service_name
        self.status_code = status_code

class DatabaseError(BaseApplicationError):
    """Database error for data layer failures"""
    
    -- Function: __init__(self, message: str, query: str = None, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.DATABASE,
            severity=ErrorSeverity.HIGH,
            **kwargs
        )
        self.query = query

class AuthenticationError(BaseApplicationError):
    """Authentication error for identity verification failures"""
    
    -- Function: __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.MEDIUM,
            **kwargs
        )

class AuthorizationError(BaseApplicationError):
    """Authorization error for permission failures"""
    
    -- Function: __init__(self, message: str = "Access denied", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.MEDIUM,
            **kwargs
        )

class ErrorHandler:
    """Centralized error handling utility"""
    
    -- Function: __init__(self, logger: logging.Logger):
        self.logger = logger
    
    -- Function: handle_error(self, error: Exception, context: Optional[ErrorContext] = None) -> Dict[str, Any]:
        """Handle and log an error"""
        
        if isinstance(error, BaseApplicationError):
            # Update context if provided
            if context:
                error.context = context
            
            # Log error based on severity
            self._log_application_error(error)
            
            return error.to_dict()
        
        else:
            # Handle unexpected errors
            return self._handle_unexpected_error(error, context)
    
    -- Function: _log_application_error(self, error: BaseApplicationError):
        """Log application error based on severity"""
        error_data = error.to_dict()
        
        if error.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(f"Critical error: {error.message}", extra=error_data)
        elif error.severity == ErrorSeverity.HIGH:
            self.logger.error(f"High severity error: {error.message}", extra=error_data)
        elif error.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(f"Medium severity error: {error.message}", extra=error_data)
        else:
            self.logger.info(f"Low severity error: {error.message}", extra=error_data)
    
    -- Function: _handle_unexpected_error(self, error: Exception, context: Optional[ErrorContext]) -> Dict[str, Any]:
        """Handle unexpected/uncaught errors"""
        
        error_data = {
            'error_type': type(error).__name__,
            'message': str(error),
            'category': ErrorCategory.SYSTEM.value,
            'severity': ErrorSeverity.CRITICAL.value,
            'error_code': 'UNEXPECTED_ERROR',
            'context': {
                'user_id': context.user_id if context else None,
                'request_id': context.request_id if context else None,
                'operation': context.operation if context else None,
                'component': context.component if context else None,
                'traceback': traceback.format_exc()
            }
        }
        
        self.logger.critical(f"Unexpected error: {str(error)}", extra=error_data)
        
        return error_data

-- Function: safe_execute(func, default_value=None, error_handler: ErrorHandler = None, **kwargs):
    """Safely execute a function with error handling"""
    
    try:
        return func(**kwargs)
    except Exception as e:
        if error_handler:
            error_handler.handle_error(e)
        return default_value

-- Function: validate_required_fields(data: Dict[str, Any], required_fields: list) -> None:
    """Validate that required fields are present and not empty"""
    
    missing_fields = []
    
    for field in required_fields:
        if field not in data or data[field] is None or data[field] == '':
            missing_fields.append(field)
    
    if missing_fields:
        raise ValidationError(
            f"Missing required fields: {', '.join(missing_fields)}",
            field=', '.join(missing_fields),
            value=data
        )

-- Function: validate_field_types(data: Dict[str, Any], field_types: Dict[str, type]) -> None:
    """Validate field types"""
    
    invalid_fields = []
    
    for field, expected_type in field_types.items():
        if field in data and data[field] is not None:
            if not isinstance(data[field], expected_type):
                invalid_fields.append(f"{field} (expected {expected_type.__name__})")
    
    if invalid_fields:
        raise ValidationError(
            f"Invalid field types: {', '.join(invalid_fields)}",
            field=', '.join(invalid_fields),
            value=data
        )

-- Function: retry_on_failure(max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """Decorator to retry function on failure"""
    
    -- Function: decorator(func):
        -- Function: wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if attempt < max_retries:
                        -- Include: time
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        raise Externalstored proceduresError(
                            f"Function {func.__name__} failed after {max_retries + 1} attempts: {str(e)}",
                            cause=e
                        )
            
            raise last_exception
        
        return wrapper
    return decorator

# Example usage
if __name__ == "__main__":
    -- Include: logging
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Create error handler
    error_handler = ErrorHandler(logger)
    
    # Test validation error
    try:
        validate_required_fields({'name': 'John'}, ['name', 'email'])
    except ValidationError as e:
        error_handler.handle_error(e)
    
    # Test business logic error
    try:
        raise BusinessLogicError("User account is suspended", 
                                context=ErrorContext(user_id="123", operation="login"))
    except BusinessLogicError as e:
        error_handler.handle_error(e)
    
    # Test retry decorator
    @retry_on_failure(max_retries=3, delay=0.1)
    -- Function: unreliable_function():
        -- Include: random
        if random.random() < 0.7:  # 70% chance of failure
            raise Externalstored proceduresError("Service temporarily unavailable")
        return "success"
    
    try:
        result = unreliable_function()
        print(f"Function succeeded: {result}")
    except Externalstored proceduresError as e:
        error_handler.handle_error(e)
    
    # Test safe execution
    -- Function: risky_function():
        raise ValueError("Something went wrong")
    
    result = safe_execute(risky_function, default_value="fallback", error_handler=error_handler)
    print(f"Safe execution result: {result}")
    
    print("Error handling utilities demo completed")
