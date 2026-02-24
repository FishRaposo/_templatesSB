"""
Middleware Configuration
"""

import time
import logging
from typing import Any, Callable, Dict, Optional
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.security import SECURITY_HEADERS, RateLimiter


logger = logging.getLogger(__name__)


# ============================================================================
# Request ID Middleware
# ============================================================================

class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add unique request ID to each request."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid4()))
        
        # Add to request state
        request.state.request_id = request_id
        
        # Process request
        response = await call_next(request)
        
        # Add to response headers
        response.headers["X-Request-ID"] = request_id
        
        return response


# ============================================================================
# Logging Middleware
# ============================================================================

class LoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests with timing info."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        # Get request info
        request_id = getattr(request.state, "request_id", "unknown")
        method = request.method
        path = request.url.path
        client_ip = request.client.host if request.client else "unknown"
        
        # Log request
        logger.info(
            f"Request started",
            extra={
                "request_id": request_id,
                "method": method,
                "path": path,
                "client_ip": client_ip,
            }
        )
        
        try:
            response = await call_next(request)
            
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            
            # Log response
            logger.info(
                f"Request completed",
                extra={
                    "request_id": request_id,
                    "method": method,
                    "path": path,
                    "status_code": response.status_code,
                    "duration_ms": round(duration_ms, 2),
                }
            )
            
            # Add timing header
            response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"
            
            return response
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            
            logger.exception(
                f"Request failed",
                extra={
                    "request_id": request_id,
                    "method": method,
                    "path": path,
                    "error": str(e),
                    "duration_ms": round(duration_ms, 2),
                }
            )
            raise


# ============================================================================
# Security Headers Middleware
# ============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        
        return response


# ============================================================================
# Rate Limiting Middleware
# ============================================================================

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limit requests per client."""
    
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.limiter = RateLimiter(requests_per_minute)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get client identifier
        client_ip = request.client.host if request.client else "unknown"
        
        # Check if user is authenticated for user-based limiting
        user_id = getattr(request.state, "user_id", None)
        key = f"user:{user_id}" if user_id else f"ip:{client_ip}"
        
        # Check rate limit
        if not self.limiter.is_allowed(key):
            return Response(
                content='{"detail": "Rate limit exceeded"}',
                status_code=429,
                media_type="application/json",
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Remaining": "0",
                }
            )
        
        response = await call_next(request)
        
        # Add rate limit headers
        remaining = self.limiter.get_remaining(key)
        response.headers["X-RateLimit-Limit"] = str(self.limiter.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        
        return response


# ============================================================================
# Compression Middleware
# ============================================================================

from starlette.middleware.gzip import GZipMiddleware


# ============================================================================
# Tenant Middleware (Multi-tenancy)
# ============================================================================

class TenantMiddleware(BaseHTTPMiddleware):
    """Extract and set tenant context."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get tenant from subdomain, header, or path
        tenant_id = None
        
        # Option 1: From header
        tenant_id = request.headers.get("X-Tenant-ID")
        
        # Option 2: From subdomain
        if not tenant_id:
            host = request.headers.get("host", "")
            subdomain = host.split(".")[0] if "." in host else None
            if subdomain and subdomain not in ("www", "api"):
                tenant_id = subdomain
        
        # Option 3: From path prefix (e.g., /orgs/{org_slug}/...)
        # Handled by the route itself
        
        if tenant_id:
            request.state.tenant_id = tenant_id
        
        return await call_next(request)


# ============================================================================
# Configure All Middleware
# ============================================================================

def configure_middleware(
    app: FastAPI,
    config: Optional[Dict[str, Any]] = None,
):
    """Configure all middleware for the application."""
    config = config or {}
    
    # Order matters! Last added = first executed
    
    # 1. CORS (should be first/outermost)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.get("cors_origins", ["*"]),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # 2. GZip compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # 3. Security headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # 4. Rate limiting (if enabled)
    if config.get("enable_rate_limiting", False):
        app.add_middleware(
            RateLimitMiddleware,
            requests_per_minute=config.get("rate_limit", 60),
        )
    
    # 5. Tenant context
    if config.get("enable_multi_tenancy", False):
        app.add_middleware(TenantMiddleware)
    
    # 6. Logging (should be close to innermost)
    app.add_middleware(LoggingMiddleware)
    
    # 7. Request ID (innermost)
    app.add_middleware(RequestIDMiddleware)
    
    return app
