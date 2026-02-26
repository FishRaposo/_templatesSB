<!--
File: production-boilerplate-generic.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Production Boilerplate Template (Core Tier - Generic)

## Purpose
Provides production-ready, technology-agnostic code structure for core projects that require reliability, maintainability, proper operational practices, and adaptability to any programming language or framework.

## Usage
This template should be used for:
- Production web services in any language
- SaaS products with technology flexibility
- Enterprise applications with language-agnostic patterns
- Systems requiring 99%+ uptime and technology adaptability
- Projects where the final technology stack might evolve

## Structure

### **Core Production Application Pattern**
```pseudocode
#!/usr/bin/env [interpreter]

/**
 * Production Application
 * Production-ready structure with proper error handling, logging, monitoring,
 * and technology-agnostic patterns adaptable to any language/framework
 */

# Import core dependencies based on chosen technology
import web_framework
import security_middleware
import compression_middleware
import cors_middleware
import logging_library
import event_emitter
import async_utilities

# Configuration management with validation
class ProductionConfig:
    constructor():
        self.port = get_env("PORT", "3000").to_integer()
        self.log_level = get_env("LOG_LEVEL", "info")
        self.environment = get_env("NODE_ENV", "production")
        self.database_url = get_env("DATABASE_URL")
        self.redis_url = get_env("REDIS_URL")
        self.api_keys = self._load_api_keys()
        self.allowed_origins = self._parse_origins()
        
    # Load and validate API keys
    function _load_api_keys():
        return {
            "analytics": get_env("ANALYTICS_API_KEY"),
            "monitoring": get_env("MONITORING_API_KEY"),
        }
    
    # Parse and validate allowed origins
    function _parse_origins():
        origins = get_env("ALLOWED_ORIGINS", "*")
        if origins == "*":
            return "*"
        return origins.split(",")

# System metrics collection interface
interface SystemMetrics:
    memory_usage: float
    cpu_usage: float
    network_latency: float
    active_users: integer
    timestamp: integer

class SystemMetricsCollector:
    static function collect():
        metrics = {
            "memory_usage": get_memory_usage_percentage(),
            "cpu_usage": get_cpu_usage_seconds(),
            "network_latency": simulate_network_latency(),
            "active_users": get_active_user_count(),
            "timestamp": current_timestamp()
        }
        return new SystemMetrics(metrics)

# Background task management
interface BackgroundTask:
    type: string
    interval: Timer
    status: string

class ProductionService extends EventEmitter:
    constructor(config):
        self.config = config
        self.running = false
        self.metrics = []
        self.background_tasks = new Set()
        self.database = null
        self.redis = null
    
    # Initialize all production services
    async function initialize():
        try:
            log_info("Initializing production service")
            
            # Initialize database connection
            await self._initialize_database()
            
            # Initialize Redis connection
            await self._initialize_redis()
            
            # Start background tasks
            await self._start_background_tasks()
            
            self.running = true
            log_info("Production service initialized successfully")
            
        catch error:
            log_error("Failed to initialize production service", error)
            raise error
    
    # Database initialization with retry logic
    async function _initialize_database():
        max_retries = 5
        for attempt in range(max_retries):
            try:
                # Database connection logic
                self.database = connect_to_database(self.config.database_url)
                log_info("Database connection initialized")
                return
            except error:
                if attempt == max_retries - 1:
                    raise error
                log_warning(f"Database connection attempt {attempt + 1} failed, retrying...")
                await sleep(2 ** attempt)  # Exponential backoff
    
    # Redis initialization with retry logic
    async function _initialize_redis():
        max_retries = 5
        for attempt in range(max_retries):
            try:
                # Redis connection logic
                self.redis = connect_to_redis(self.config.redis_url)
                log_info("Redis connection initialized")
                return
            except error:
                if attempt == max_retries - 1:
                    raise error
                log_warning(f"Redis connection attempt {attempt + 1} failed, retrying...")
                await sleep(2 ** attempt)
    
    # Start all background tasks
    async function _start_background_tasks():
        # Metrics collection task
        metrics_task = self._start_metrics_collection()
        self.background_tasks.add(metrics_task)
        
        # Health check task
        health_task = self._start_health_checks()
        self.background_tasks.add(health_task)
        
        # Cleanup task
        cleanup_task = self._start_cleanup_task()
        self.background_tasks.add(cleanup_task)
        
        log_info("Background tasks started")
    
    # Metrics collection with error handling
    function _start_metrics_collection():
        interval = set_interval(async function():
            if self.running:
                try:
                    metrics = SystemMetricsCollector.collect()
                    self.metrics.append(metrics)
                    
                    # Keep only last 100 metrics
                    if len(self.metrics) > 100:
                        self.metrics.shift()
                    
                    self.emit("metrics", metrics)
                catch error:
                    log_error("Error collecting metrics", error)
        }, 30000)  # Collect every 30 seconds
        
        return new BackgroundTask("metrics", interval, "running")
    
    # Health checks for all dependencies
    function _start_health_checks():
        interval = set_interval(async function():
            if self.running:
                try:
                    health_status = await self._perform_health_check()
                    self.emit("health", health_status)
                catch error:
                    log_error("Health check failed", error)
                    self.emit("health", {"status": "unhealthy", "error": error.message})
        }, 60000)  # Check every minute
        
        return new BackgroundTask("health", interval, "running")
    
    # Cleanup old data and metrics
    function _start_cleanup_task():
        interval = set_interval(async function():
            if self.running:
                try:
                    await self._perform_cleanup()
                    log_debug("Cleanup completed")
                catch error:
                    log_error("Cleanup failed", error)
        }, 3600000)  # Clean every hour
        
        return new BackgroundTask("cleanup", interval, "running")
    
    # Comprehensive health check
    async function _perform_health_check():
        health_status = {
            "status": "healthy",
            "checks": {},
            "timestamp": current_timestamp()
        }
        
        # Database health check
        try:
            await self.database.ping()
            health_status.checks["database"] = "healthy"
        except error:
            health_status.checks["database"] = "unhealthy"
            health_status.status = "degraded"
        
        # Redis health check
        try:
            await self.redis.ping()
            health_status.checks["redis"] = "healthy"
        except error:
            health_status.checks["redis"] = "unhealthy"
            health_status.status = "degraded"
        
        # Memory health check
        memory_usage = get_memory_usage_percentage()
        if memory_usage > 90:
            health_status.checks["memory"] = "critical"
            health_status.status = "unhealthy"
        elif memory_usage > 80:
            health_status.checks["memory"] = "warning"
            health_status.status = "degraded"
        else:
            health_status.checks["memory"] = "healthy"
        
        return health_status
    
    # Cleanup old data
    async function _perform_cleanup():
        # Clean old metrics (keep last 24 hours)
        cutoff_time = current_timestamp() - 86400000  # 24 hours ago
        self.metrics = [m for m in self.metrics if m.timestamp > cutoff_time]
        
        # Add other cleanup tasks as needed
        # Clean old sessions, temp files, etc.
    
    # Core business logic with error handling
    async function perform_action():
        try:
            log_info("Performing production action")
            
            # Simulate work with timeout
            await timeout(async function():
                # Your core business logic here
                await sleep(500)
            , 30000)  # 30 second timeout
            
            result = {
                "status": "success",
                "message": "Production action completed",
                "timestamp": current_timestamp(),
                "execution_time": 500
            }
            
            log_info("Production action completed successfully")
            return result
            
        catch error:
            log_error("Production action failed", error)
            raise error
    
    # Get latest metrics with validation
    function get_latest_metrics():
        if len(self.metrics) == 0:
            return null
        return self.metrics[-1]
    
    # Graceful shutdown with cleanup
    async function shutdown():
        log_info("Shutting down production service")
        self.running = false
        
        # Stop background tasks
        for task in self.background_tasks:
            clear_interval(task.interval)
        self.background_tasks.clear()
        
        # Close database connections
        if self.database:
            await self.database.close()
        
        # Close Redis connections
        if self.redis:
            await self.redis.quit()
        
        log_info("Production service shutdown complete")

# Main application class with middleware
class ProductionApplication:
    constructor():
        self.config = new ProductionConfig()
        self.service = new ProductionService(self.config)
        self.app = self._create_app()
        self.server = null
    
    # Create web application with security middleware
    function _create_app():
        app = create_web_application()
        
        # Security middleware
        app.add_security_middleware()
        
        # Compression middleware
        app.add_compression_middleware()
        
        # CORS middleware
        app.add_cors_middleware(allowed_origins=self.config.allowed_origins)
        
        # Request logging middleware
        app.add_middleware(function(request, response, next):
            log_info("Request received", {
                "method": request.method,
                "url": request.url,
                "user_agent": request.get_user_agent(),
                "ip": request.ip
            })
            next()
        )
        
        # Global error handler
        app.add_error_handler(function(error, request, response):
            log_error("Unhandled error", {
                "error": error.message,
                "stack": error.stack,
                "url": request.url,
                "method": request.method
            })
            
            response.status(500).json({
                "error": "Internal server error",
                "message": self.config.environment == "development" ? error.message : "Something went wrong"
            })
        })
        
        # API routes
        app.get_route("/", function(request, response):
            response.json({
                "status": "healthy", 
                "service": "production-generic",
                "version": "1.0.0"
            })
        )
        
        app.get_route("/health", async function(request, response):
            health_status = await self.service._perform_health_check()
            response.json(health_status)
        )
        
        app.get_route("/metrics", function(request, response):
            metrics = self.service.get_latest_metrics()
            if metrics:
                response.json(metrics)
            else:
                response.json({"message": "No metrics available"})
        })
        
        app.post_route("/action", async function(request, response):
            try:
                result = await self.service.perform_action()
                response.json(result)
            catch error:
                response.status(500).json({"error": error.message})
        })
        
        # 404 handler
        app.add_not_found_handler(function(request, response):
            response.status(404).json({"error": "Not found"})
        )
        
        return app
    
    # Start the application
    async function start():
        try:
            # Initialize service
            await self.service.initialize()
            
            # Start HTTP server
            self.server = self.app.listen(self.config.port, function():
                log_info(f"Production application started on port {self.config.port}")
            })
            
            # Setup graceful shutdown
            self._setup_graceful_shutdown()
            
        catch error:
            log_error("Failed to start application", error)
            exit(1)
    
    # Setup graceful shutdown handlers
    function _setup_graceful_shutdown():
        shutdown = async function(signal):
            log_info(f"Received {signal}, shutting down gracefully...")
            
            if self.server:
                await self.server.close()
            
            await self.service.shutdown()
            log_info("Application stopped")
            exit(0)
        
        register_signal_handler("SIGINT", shutdown)
        register_signal_handler("SIGTERM", shutdown)

# Main entry point with error handling
async function main():
    try:
        app = new ProductionApplication()
        await app.start()
        
    catch error:
        log_error("Application failed to start", error)
        exit(1)

# Handle uncaught exceptions
register_uncaught_exception_handler(function(error):
    log_error("Uncaught exception", {"error": error.message, "stack": error.stack})
    exit(1)
)

register_unhandled_rejection_handler(function(reason, promise):
    log_error("Unhandled rejection", {"reason": reason, "promise": promise})
    exit(1)
)

# Start the application
main()
```

### **Language-Specific Adaptations**

#### **For JavaScript/TypeScript**
```javascript
// Use Express.js, async/await, try-catch
// Import Winston for logging
// Use process.env for configuration
// Add TypeScript interfaces for type safety
```

#### **For Python**
```python
# Use FastAPI/Flask, async/await, try-except
# Import structlog for logging
# Use os.environ for configuration
# Add Pydantic models for data validation
```

#### **For Go**
```go
// Use Gin/Echo, goroutines, error handling
// Import logrus for logging
// Use os.Getenv for configuration
// Add struct definitions for type safety
```

#### **For Java**
```java
// Use Spring Boot, CompletableFuture, try-catch
// Import Logback/SLF4J for logging
// Use System.getenv for configuration
// Add POJO classes for data structures
```

#### **For C#**
```csharp
// Use ASP.NET Core, async/await, try-catch
// Import Serilog for logging
// Use Environment.GetEnvironmentVariable
// Add record classes for immutable data
```

## Core Production Guidelines

### **Reliability & Resilience**
- **Graceful Shutdown**: Proper cleanup of resources and connections
- **Error Handling**: Comprehensive error handling with retry logic
- **Circuit Breakers**: Prevent cascading failures
- **Timeout Management**: Prevent hanging operations
- **Retry Logic**: Exponential backoff for transient failures

### **Observability & Monitoring**
- **Structured Logging**: JSON-formatted logs with correlation IDs
- **Health Checks**: Comprehensive health status of all dependencies
- **Metrics Collection**: System and application metrics
- **Performance Monitoring**: Response times and throughput
- **Error Tracking**: Detailed error reporting and alerting

### **Security**
- **Security Headers**: Helmet middleware or equivalent
- **CORS Configuration**: Proper cross-origin resource sharing
- **Input Validation**: Validate all incoming data
- **Rate Limiting**: Prevent abuse and DoS attacks
- **Secrets Management**: Secure handling of API keys and credentials

### **Performance**
- **Compression**: Gzip compression for responses
- **Connection Pooling**: Database and external service connections
- **Caching**: Redis or in-memory caching
- **Async Operations**: Non-blocking I/O operations
- **Resource Management**: Proper cleanup and memory management

### **Technology-Agnostic Features**
- **Language Independence**: Patterns work with any programming language
- **Framework Flexibility**: Adaptable to any web framework
- **Configuration**: Environment-based configuration management
- **Deployment**: Container-ready with health checks
- **Monitoring**: Standard metrics and logging formats

## Required Dependencies (Technology-Specific)

### **JavaScript/TypeScript**
```json
{
  "dependencies": {
    "express": "^4.18.2",
    "helmet": "^7.1.0",
    "compression": "^1.7.4",
    "cors": "^2.8.5",
    "winston": "^3.11.0",
    "redis": "^4.6.0",
    "pg": "^8.11.0"
  }
}
```

### **Python**
```python
# requirements.txt
fastapi==0.104.0
uvicorn==0.24.0
structlog==23.2.0
redis==5.0.0
psycopg2-binary==2.9.0
pydantic==2.5.0
```

### **Go**
```go
// go.mod
require (
    github.com/gin-gonic/gin v1.9.0
    github.com/sirupsen/logrus v1.9.0
    github.com/go-redis/redis/v8 v8.11.0
    github.com/lib/pq v1.10.0
)
```

## What's Included (vs MVP)
- Production-ready web framework with security middleware
- Structured logging with configurable levels and outputs
- Graceful shutdown with proper resource cleanup
- Environment-based configuration management
- Comprehensive health checks for all dependencies
- Background task management with metrics collection
- System monitoring and performance metrics
- Production error handling with retry logic
- Database and Redis connection management
- Technology-agnostic patterns adaptable to any stack

## What's NOT Included (vs Full)
- No advanced monitoring dashboards (Grafana, etc.)
- No distributed tracing (Jaeger, Zipkin)
- No advanced security features (WAF, DDoS protection)
- No multi-region deployment patterns
- No advanced caching strategies (CDN, edge caching)
- No enterprise authentication (OAuth2, SAML)
- No advanced load balancing patterns
- No disaster recovery procedures

## Quick Start Checklist

### **1. Choose Technology Stack**
- [ ] Select programming language and framework
- [ ] Set up development environment
- [ ] Install required dependencies

### **2. Configure Environment**
- [ ] Set environment variables (PORT, LOG_LEVEL, etc.)
- [ ] Configure database connection
- [ ] Set up Redis connection (if needed)
- [ ] Configure API keys and secrets

### **3. Implement Core Structure**
- [ ] Create configuration management class
- [ ] Implement metrics collection
- [ ] Set up health check endpoints
- [ ] Add structured logging

### **4. Add Business Logic**
- [ ] Implement core functionality
- [ ] Add error handling and retry logic
- [ ] Set up background tasks
- [ ] Add input validation

### **5. Deploy and Monitor**
- [ ] Containerize application
- [ ] Set up monitoring and alerting
- [ ] Configure load balancer
- [ ] Test graceful shutdown

## Next Steps (When Moving to Enterprise Tier)
- Add advanced monitoring and observability
- Implement distributed tracing
- Add enterprise security features
- Implement multi-region deployment
- Add advanced caching strategies
- Include disaster recovery procedures
- Add enterprise authentication systems
- Implement advanced load balancing
