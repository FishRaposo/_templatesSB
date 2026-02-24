"""
File: app.tpl.py
Purpose: Main FastAPI application with middleware and router configuration
Generated for: {{PROJECT_NAME}}
Tier: base
Stack: fastapi
Category: application
"""

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import time

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Async context manager for application lifespan events.
    Handles startup and shutdown logic.
    """
    # Startup
    logger.info("Starting {{PROJECT_NAME}} API")
    # Initialize database connections, cache, etc.
    # await database.connect()
    # await cache.connect()
    
    yield
    
    # Shutdown
    logger.info("Shutting down {{PROJECT_NAME}} API")
    # Close database connections, cache, etc.
    # await database.disconnect()
    # await cache.disconnect()


def create_app() -> FastAPI:
    """
    Factory function to create and configure FastAPI application.
    
    Returns:
        FastAPI: Configured FastAPI application instance
    """
    app = FastAPI(
        title="{{PROJECT_NAME}}",
        description="{{PROJECT_DESCRIPTION}}",
        version="{{VERSION}}",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    
    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add GZip compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # Add trusted host middleware (configure for production)
    # app.add_middleware(
    #     TrustedHostMiddleware,
    #     allowed_hosts=["example.com", "*.example.com"]
    # )
    
    # Request timing middleware
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response
    
    # Health check endpoint
    @app.get("/health", status_code=status.HTTP_200_OK, tags=["health"])
    async def health_check():
        """
        Health check endpoint for monitoring and load balancers.
        """
        return {
            "status": "healthy",
            "service": "{{PROJECT_NAME}}",
            "version": "{{VERSION}}"
        }
    
    # Root endpoint
    @app.get("/", tags=["root"])
    async def root():
        """
        Root endpoint with API information.
        """
        return {
            "message": "Welcome to {{PROJECT_NAME}} API",
            "docs": "/docs",
            "health": "/health"
        }
    
    # Include routers
    # from .routers import users, items, auth
    # app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
    # app.include_router(users.router, prefix="/api/v1/users", tags=["users"])
    # app.include_router(items.router, prefix="/api/v1/items", tags=["items"])
    
    return app


# Create application instance
app = create_app()
