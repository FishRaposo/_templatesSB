"""
File: middleware.tpl.py
Purpose: FastAPI middleware collection for auth, logging, rate limiting
Generated for: {{PROJECT_NAME}}
"""

import logging
import time
import uuid
from datetime import datetime
from typing import Callable, Optional

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


# ============================================================================
# Request ID Middleware
# ============================================================================

class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add unique request ID to each request."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        
        # Store in request state
        request.state.request_id = request_id
        
        # Process request
        response = await call_next(request)
        
        # Add to response headers
        response.headers["X-Request-ID"] = request_id
        
        return response


# ============================================================================
# Logging Middleware
# ============================================================================

logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests and responses."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()
        request_id = getattr(request.state, "request_id", "unknown")
        
        # Log request
        logger.info(
            f"Request started",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "query": str(request.query_params),
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            }
        )
        
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration = time.perf_counter() - start_time
        
        # Log response
        logger.info(
            f"Request completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration * 1000, 2),
            }
        )
        
        # Add timing header
        response.headers["X-Response-Time"] = f"{duration * 1000:.2f}ms"
        
        return response


# ============================================================================
# Error Handling Middleware
# ============================================================================

class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Handle unhandled exceptions."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            return await call_next(request)
        except HTTPException:
            raise
        except Exception as e:
            request_id = getattr(request.state, "request_id", "unknown")
            
            logger.exception(
                f"Unhandled exception: {str(e)}",
                extra={"request_id": request_id}
            )
            
            # Return generic error response
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "errors": [
                        {
                            "code": "INTERNAL_ERROR",
                            "message": "An unexpected error occurred"
                        }
                    ],
                    "request_id": request_id,
                }
            )


# ============================================================================
# Rate Limiting Middleware
# ============================================================================

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limit requests by IP or user."""
    
    def __init__(
        self,
        app: ASGIApp,
        requests_per_minute: int = 60,
        redis_url: str = "redis://localhost:6379/0",
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.redis_url = redis_url
        self._redis = None
    
    async def get_redis(self):
        if self._redis is None:
            import redis.asyncio as redis
            self._redis = redis.from_url(self.redis_url)
        return self._redis
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get client identifier
        client_id = self._get_client_id(request)
        
        # Check rate limit
        redis = await self.get_redis()
        key = f"ratelimit:{client_id}"
        
        current = await redis.get(key)
        if current is None:
            await redis.set(key, 1, ex=60)
            remaining = self.requests_per_minute - 1
        else:
            count = int(current)
            if count >= self.requests_per_minute:
                return self._rate_limit_response(request)
            await redis.incr(key)
            remaining = self.requests_per_minute - count - 1
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        
        return response
    
    def _get_client_id(self, request: Request) -> str:
        # Use user ID if authenticated, otherwise use IP
        user = getattr(request.state, "user", None)
        if user:
            return f"user:{user.id}"
        return f"ip:{request.client.host}"
    
    def _rate_limit_response(self, request: Request) -> Response:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=429,
            content={
                "success": False,
                "errors": [
                    {
                        "code": "RATE_LIMITED",
                        "message": "Too many requests. Please try again later."
                    }
                ]
            },
            headers={
                "Retry-After": "60",
                "X-RateLimit-Limit": str(self.requests_per_minute),
                "X-RateLimit-Remaining": "0",
            }
        )


# ============================================================================
# Authentication Middleware
# ============================================================================

class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Authenticate requests using JWT tokens."""
    
    PUBLIC_PATHS = {
        "/",
        "/health",
        "/health/db",
        "/health/redis",
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/refresh",
        "/docs",
        "/redoc",
        "/openapi.json",
    }
    
    def __init__(self, app: ASGIApp, jwt_secret: str = "secret"):
        super().__init__(app)
        self.jwt_secret = jwt_secret
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip authentication for public paths
        if self._is_public_path(request.url.path):
            return await call_next(request)
        
        # Get token from header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return self._unauthorized_response("Missing authentication token")
        
        token = auth_header[7:]
        
        try:
            # Validate token
            user = await self._validate_token(token)
            request.state.user = user
        except Exception as e:
            return self._unauthorized_response(str(e))
        
        return await call_next(request)
    
    def _is_public_path(self, path: str) -> bool:
        # Check exact match
        if path in self.PUBLIC_PATHS:
            return True
        # Check prefixes
        public_prefixes = ["/static/", "/api/v1/public/"]
        return any(path.startswith(p) for p in public_prefixes)
    
    async def _validate_token(self, token: str):
        """Validate JWT token and return user."""
        import jwt
        
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            user_id = payload.get("sub")
            if not user_id:
                raise ValueError("Invalid token payload")
            
            # Fetch user from database
            # user = await get_user_by_id(user_id)
            # return user
            return {"id": user_id}
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
    
    def _unauthorized_response(self, message: str) -> Response:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=401,
            content={
                "success": False,
                "errors": [
                    {"code": "UNAUTHORIZED", "message": message}
                ]
            }
        )


# ============================================================================
# Security Headers Middleware
# ============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to responses."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        return response


# ============================================================================
# Middleware Configuration
# ============================================================================

def configure_middleware(app: FastAPI, settings: dict = None):
    """Configure all middleware for the application."""
    settings = settings or {}
    
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.get("cors_origins", ["*"]),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # Error handling
    app.add_middleware(ErrorHandlingMiddleware)
    
    # Logging
    app.add_middleware(LoggingMiddleware)
    
    # Request ID
    app.add_middleware(RequestIDMiddleware)
    
    # Rate limiting
    if settings.get("enable_rate_limiting", True):
        app.add_middleware(
            RateLimitMiddleware,
            requests_per_minute=settings.get("rate_limit", 60),
        )
    
    # Authentication (optional - can also use FastAPI dependencies)
    if settings.get("enable_auth_middleware", False):
        app.add_middleware(
            AuthenticationMiddleware,
            jwt_secret=settings.get("jwt_secret", "secret"),
        )
    
    return app
