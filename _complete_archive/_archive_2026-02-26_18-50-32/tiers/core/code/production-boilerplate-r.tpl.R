-- File: production-boilerplate-r.tpl.R
-- Purpose: Template for unknown implementation
-- Generated for: {{PROJECT_NAME}}

# Production Boilerplate Template (Core Tier - Python)

## Purpose
Provides production-ready Python code structure for core projects that require reliability, maintainability, and proper operational practices.

## Usage
This template should be used for:
- Production applications
- SaaS products
- Enterprise applications
- Systems requiring 99%+ uptime

## Structure
```python
#!/usr/bin/env python3
"""
Production Application
Production-ready structure with proper error handling, logging, and monitoring
"""

import asyncio
import logging
import signal
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional, Dict, Any
import os
import json

import structlog
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

@dataclass
class SystemMetrics:
    """System metrics for monitoring"""
    memory_usage: float
    cpu_usage: float
    network_latency: float
    active_users: int
    timestamp: float

class ProductionConfig:
    """Production configuration management"""
    
    def __init__(self):
        self.port = int(os.getenv('PORT', 8000))
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.environment = os.getenv('ENVIRONMENT', 'production')
        self.database_url = os.getenv('DATABASE_URL')
        self.redis_url = os.getenv('REDIS_URL')
        self.api_keys = self._load_api_keys()
    
    def _load_api_keys(self) -> Dict[str, str]:
        """Load API keys from environment or config file"""
        return {
            'analytics': os.getenv('ANALYTICS_API_KEY'),
            'monitoring': os.getenv('MONITORING_API_KEY'),
        }

class ProductionService:
    """Production service with monitoring and error handling"""
    
    def __init__(self, config: ProductionConfig):
        self.config = config
        self.metrics_queue = asyncio.Queue()
        self.running = False
        self.background_tasks = set()
    
    async def initialize(self):
        """Initialize production services"""
        try:
            logger.info("Initializing production service")
            
            # Initialize database connection
            await self._initialize_database()
            
            # Initialize Redis connection
            await self._initialize_redis()
            
            # Start background tasks
            await self._start_background_tasks()
            
            self.running = True
            logger.info("Production service initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize production service", error=str(e))
            raise
    
    async def _initialize_database(self):
        """Initialize database connection"""
        # Database initialization logic
        logger.info("Database connection initialized")
    
    async def _initialize_redis(self):
        """Initialize Redis connection"""
        # Redis initialization logic
        logger.info("Redis connection initialized")
    
    async def _start_background_tasks(self):
        """Start background monitoring tasks"""
        # Metrics collection task
        metrics_task = asyncio.create_task(self._collect_metrics())
        self.background_tasks.add(metrics_task)
        metrics_task.add_done_callback(self.background_tasks.discard)
        
        logger.info("Background tasks started")
    
    async def _collect_metrics(self):
        """Collect system metrics periodically"""
        while self.running:
            try:
                metrics = await self._get_system_metrics()
                await self.metrics_queue.put(metrics)
                await asyncio.sleep(30)  # Collect every 30 seconds
            except Exception as e:
                logger.error("Error collecting metrics", error=str(e))
                await asyncio.sleep(5)
    
    async def _get_system_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        # Simulate metrics collection
        return SystemMetrics(
            memory_usage=45.2,
            cpu_usage=23.1,
            network_latency=120.0,
            active_users=1250,
            timestamp=time.time()
        )
    
    async def perform_action(self) -> Dict[str, Any]:
        """Perform production action with proper error handling"""
        try:
            logger.info("Performing production action")
            
            # Simulate work
            await asyncio.sleep(0.5)
            
            result = {
                "status": "success",
                "message": "Production action completed",
                "timestamp": time.time()
            }
            
            logger.info("Production action completed successfully")
            return result
            
        except Exception as e:
            logger.error("Production action failed", error=str(e))
            raise
    
    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down production service")
        self.running = False
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        logger.info("Production service shutdown complete")

class ProductionApplication:
    """Main production application"""
    
    def __init__(self):
        self.config = ProductionConfig()
        self.service = ProductionService(self.config)
        self.app = self._create_app()
    
    def _create_app(self) -> FastAPI:
        """Create FastAPI application with production middleware"""
        app = FastAPI(
            title="Production Application",
            description="Production-ready application with proper monitoring",
            version="1.0.0"
        )
        
        # Add production middleware
        app.add_middleware(GZipMiddleware, minimum_size=1000)
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Add exception handlers
        app.add_exception_handler(Exception, self._global_exception_handler)
        
        # Add routes
        app.add_event_handler("startup", self._startup)
        app.add_event_handler("shutdown", self._shutdown)
        
        @app.get("/")
        async def root():
            return {"status": "healthy", "service": "production"}
        
        @app.get("/health")
        async def health():
            return {
                "status": "healthy",
                "timestamp": time.time(),
                "version": "1.0.0"
            }
        
        @app.get("/metrics")
        async def metrics():
            if not self.service.metrics_queue.empty():
                metrics = await self.service.metrics_queue.get()
                return metrics.__dict__
            return {"message": "No metrics available"}
        
        @app.post("/action")
        async def perform_action():
            try:
                result = await self.service.perform_action()
                return result
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        return app
    
    async def _startup(self):
        """Application startup"""
        await self.service.initialize()
        logger.info("Production application started")
    
    async def _shutdown(self):
        """Application shutdown"""
        await self.service.shutdown()
        logger.info("Production application stopped")
    
    async def _global_exception_handler(self, request: Request, exc: Exception):
        """Global exception handler"""
        logger.error(
            "Unhandled exception",
            error=str(exc),
            path=request.url.path,
            method=request.method
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )
    
    async def run(self):
        """Run the production application"""
        config = uvicorn.Config(
            app=self.app,
            host="0.0.0.0",
            port=self.config.port,
            log_level=self.config.log_level.lower()
        )
        server = uvicorn.Server(config)
        await server.serve()

# Global application instance
app_instance = ProductionApplication()
app = app_instance.app

async def main():
    """Main entry point"""
    try:
        # Setup signal handlers
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            asyncio.create_task(app_instance.service.shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Run the application
        await app_instance.run()
        
    except Exception as e:
        logger.error("Application failed", error=str(e))
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
```

## Core Production Guidelines
- **Reliability**: Graceful shutdown, error handling, circuit breakers
- **Observability**: Structured logging, health checks, metrics
- **Security**: HTTPS, input validation, rate limiting
- **Performance**: Async/await, connection pooling, caching
- **Testing**: Unit tests, integration tests, load testing
- **Documentation**: API docs, deployment guides, runbooks

## Required Dependencies
```txt
# requirements.txt
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
structlog>=23.1.0
pydantic>=2.4.0
asyncio-mqtt>=0.13.0
redis>=5.0.0
psycopg2-binary>=2.9.0
```

## What's Included (vs MVP)
- Structured logging with structlog
- FastAPI web framework with middleware
- Graceful shutdown handling
- Configuration management
- Health check endpoints
- Database and Redis integration
- Production-ready error handling
- Background task management
- System metrics collection

## What's NOT Included (vs Full)
- No advanced monitoring/metrics dashboards
- No distributed tracing
- No advanced security features
- No multi-region deployment
- No advanced caching strategies
- No enterprise authentication systems
