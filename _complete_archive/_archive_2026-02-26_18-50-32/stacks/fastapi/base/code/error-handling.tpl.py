"""
File: error-handling.tpl.py
Purpose: Custom exception classes and exception handlers
Generated for: {{PROJECT_NAME}}
Tier: base
Stack: fastapi
Category: error_handling
"""

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from typing import Any, Dict, Optional
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# Custom Exception Classes
# ============================================================================

class BaseAppException(Exception):
    """Base exception for application errors"""
    
    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class ResourceNotFoundException(BaseAppException):
    """Raised when a requested resource is not found"""
    
    def __init__(self, resource: str, identifier: Any):
        message = f"{resource} with identifier '{identifier}' not found"
        super().__init__(
            message=message,
            status_code=status.HTTP_404_NOT_FOUND,
            details={"resource": resource, "identifier": str(identifier)}
        )


class ResourceAlreadyExistsException(BaseAppException):
    """Raised when trying to create a resource that already exists"""
    
    def __init__(self, resource: str, field: str, value: Any):
        message = f"{resource} with {field}='{value}' already exists"
        super().__init__(
            message=message,
            status_code=status.HTTP_409_CONFLICT,
            details={"resource": resource, "field": field, "value": str(value)}
        )


class UnauthorizedException(BaseAppException):
    """Raised when user is not authenticated"""
    
    def __init__(self, message: str = "Authentication required"):
        super().__init__(
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED
        )


class ForbiddenException(BaseAppException):
    """Raised when user lacks permission"""
    
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN
        )


class ValidationException(BaseAppException):
    """Raised for business logic validation errors"""
    
    def __init__(self, message: str, field: Optional[str] = None):
        details = {"field": field} if field else {}
        super().__init__(
            message=message,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details
        )


class DatabaseException(BaseAppException):
    """Raised for database operation errors"""
    
    def __init__(self, message: str = "Database operation failed"):
        super().__init__(
            message=message,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class ExternalServiceException(BaseAppException):
    """Raised when external service call fails"""
    
    def __init__(self, service: str, message: str = "External service unavailable"):
        super().__init__(
            message=f"{service}: {message}",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            details={"service": service}
        )


# ============================================================================
# Exception Handlers
# ============================================================================

async def base_app_exception_handler(
    request: Request,
    exc: BaseAppException
) -> JSONResponse:
    """
    Handler for all BaseAppException subclasses.
    """
    request_id = getattr(request.state, "request_id", "N/A")
    
    logger.error(
        f"Application error: {exc.message}",
        extra={
            "request_id": request_id,
            "status_code": exc.status_code,
            "details": exc.details,
        }
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.message,
            "request_id": request_id,
            **exc.details
        },
        headers={"X-Request-ID": request_id}
    )


async def http_exception_handler(
    request: Request,
    exc: HTTPException
) -> JSONResponse:
    """
    Handler for FastAPI HTTPException.
    """
    request_id = getattr(request.state, "request_id", "N/A")
    
    logger.warning(
        f"HTTP error: {exc.detail}",
        extra={
            "request_id": request_id,
            "status_code": exc.status_code,
        }
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "request_id": request_id,
        },
        headers={
            "X-Request-ID": request_id,
            **exc.headers
        } if exc.headers else {"X-Request-ID": request_id}
    )


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
) -> JSONResponse:
    """
    Handler for Pydantic validation errors.
    """
    request_id = getattr(request.state, "request_id", "N/A")
    
    # Format validation errors
    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"],
        })
    
    logger.warning(
        f"Validation error",
        extra={
            "request_id": request_id,
            "errors": errors,
        }
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "errors": errors,
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id}
    )


async def generic_exception_handler(
    request: Request,
    exc: Exception
) -> JSONResponse:
    """
    Handler for unhandled exceptions.
    """
    request_id = getattr(request.state, "request_id", "N/A")
    
    logger.error(
        f"Unhandled exception: {str(exc)}",
        extra={
            "request_id": request_id,
            "exception_type": type(exc).__name__,
        },
        exc_info=True
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id}
    )


# ============================================================================
# Register Exception Handlers
# ============================================================================

def register_exception_handlers(app):
    """
    Register all exception handlers with the FastAPI app.
    
    Usage:
        app = FastAPI()
        register_exception_handlers(app)
    """
    app.add_exception_handler(BaseAppException, base_app_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)
