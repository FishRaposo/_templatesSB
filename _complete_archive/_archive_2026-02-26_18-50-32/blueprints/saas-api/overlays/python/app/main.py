"""
{{PROJECT_NAME}} - SaaS API Application
Main entry point and application factory
"""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.router import api_router
from app.config import settings
from app.core.exceptions import AppException
from app.core.middleware import configure_middleware
from app.db.session import init_db, close_db


# ============================================================================
# Application Lifecycle
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan handler."""
    # Startup
    await init_db()
    yield
    # Shutdown
    await close_db()


# ============================================================================
# Application Factory
# ============================================================================

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    
    app = FastAPI(
        title=settings.app.app_name,
        version=settings.app.app_version,
        description="Production-ready SaaS API",
        docs_url="/docs" if settings.app.debug else None,
        redoc_url="/redoc" if settings.app.debug else None,
        lifespan=lifespan,
    )
    
    # Configure middleware
    configure_middleware(app, {
        "cors_origins": settings.security.cors_origins,
        "enable_rate_limiting": True,
        "rate_limit": settings.security.rate_limit_per_minute,
    })
    
    # Exception handlers
    @app.exception_handler(AppException)
    async def app_exception_handler(request: Request, exc: AppException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "errors": [{"code": exc.code, "message": exc.message}],
            },
        )
    
    # Include routers
    app.include_router(api_router, prefix="/api")
    
    # Health check
    @app.get("/health")
    async def health_check():
        return {
            "status": "healthy",
            "version": settings.app.app_version,
            "environment": settings.app.environment,
        }
    
    return app


# Application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.app.host,
        port=settings.app.port,
        reload=settings.app.debug,
    )
