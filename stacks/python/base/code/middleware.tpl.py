"""
File: middleware.tpl.py
Purpose: FastAPI middleware for common patterns
Generated for: {{PROJECT_NAME}}
"""

import time
import uuid
from typing import Callable, Optional
from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import logging

logger = logging.getLogger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add unique request ID to each request"""

    async def dispatch(self, request: Request, call_next: Callable):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """Log all requests with timing information"""

    async def dispatch(self, request: Request, call_next: Callable):
        start_time = time.perf_counter()
        request_id = getattr(request.state, "request_id", "unknown")

        logger.info(
            f"[{request_id}] {request.method} {request.url.path} started"
        )

        response = await call_next(request)

        duration = (time.perf_counter() - start_time) * 1000
        logger.info(
            f"[{request_id}] {request.method} {request.url.path} "
            f"completed in {duration:.2f}ms with status {response.status_code}"
        )

        response.headers["X-Response-Time"] = f"{duration:.2f}ms"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiting (use Redis in production)"""

    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests: dict = {}  # In production, use Redis

    async def dispatch(self, request: Request, call_next: Callable):
        # Get client identifier (IP or API key)
        client_id = request.client.host if request.client else "unknown"

        # Check rate limit
        current_time = time.time()
        minute_key = f"{client_id}:{int(current_time / 60)}"

        if minute_key not in self.requests:
            self.requests[minute_key] = 0
            # Clean old entries
            old_keys = [k for k in self.requests if k.split(":")[1] != str(int(current_time / 60))]
            for k in old_keys:
                del self.requests[k]

        self.requests[minute_key] += 1

        if self.requests[minute_key] > self.requests_per_minute:
            return Response(
                content='{"error": "Rate limit exceeded"}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": "60"},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(
            self.requests_per_minute - self.requests[minute_key]
        )
        return response


class CORSMiddleware(BaseHTTPMiddleware):
    """Custom CORS middleware with fine-grained control"""

    def __init__(
        self,
        app,
        allow_origins: list = ["*"],
        allow_methods: list = ["*"],
        allow_headers: list = ["*"],
        allow_credentials: bool = False,
        max_age: int = 600,
    ):
        super().__init__(app)
        self.allow_origins = allow_origins
        self.allow_methods = allow_methods
        self.allow_headers = allow_headers
        self.allow_credentials = allow_credentials
        self.max_age = max_age

    async def dispatch(self, request: Request, call_next: Callable):
        origin = request.headers.get("origin")

        # Handle preflight
        if request.method == "OPTIONS":
            response = Response(status_code=200)
        else:
            response = await call_next(request)

        # Set CORS headers
        if origin:
            if "*" in self.allow_origins or origin in self.allow_origins:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allow_methods)
                response.headers["Access-Control-Allow-Headers"] = ", ".join(self.allow_headers)
                response.headers["Access-Control-Max-Age"] = str(self.max_age)
                if self.allow_credentials:
                    response.headers["Access-Control-Allow-Credentials"] = "true"

        return response


def setup_middleware(app: FastAPI) -> None:
    """Configure all middleware for the application"""
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(RateLimitMiddleware, requests_per_minute=100)


# Usage:
# from fastapi import FastAPI
# from middleware import setup_middleware
#
# app = FastAPI()
# setup_middleware(app)
