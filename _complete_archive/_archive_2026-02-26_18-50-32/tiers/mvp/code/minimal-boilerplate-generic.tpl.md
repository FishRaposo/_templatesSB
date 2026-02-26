<!--
File: minimal-boilerplate-generic.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Minimal Boilerplate Template (MVP Tier - Generic)

## Purpose
Provides the absolute minimum technology-agnostic code structure for MVP projects following the minimal viable product approach. This template is adaptable to any programming language or framework.

## Usage
This template should be used for:
- Prototype web services in any language
- Proof of concepts with technology flexibility
- Early-stage startup APIs with language-agnostic structure
- Internal tools with limited scope and adaptable patterns
- Projects where the final technology stack hasn't been decided

## Structure

### **Core Application Pattern**
```pseudocode
# Main Application Class
class MVPApplication:
    # Core properties
    status: string = "MVP Application Starting..."
    port: integer = 3000
    server: ServerInstance = null
    
    # Initialize core functionality only
    async function initializeCore():
        try:
            log("Initializing core functionality")
            status = "MVP Service Running"
            return true
        catch error:
            log_error("Failed to initialize:", error)
            return false
    
    # Start minimal HTTP service
    function startMinimalService():
        try:
            server = create_http_server(handle_request)
            server.listen(port, on_server_ready)
        catch error:
            log_error("Failed to start service:", error)
    
    # Basic request handler
    function handle_request(request, response):
        method = request.method
        url = request.url
        
        # Set basic headers
        response.set_header("Content-Type", "application/json")
        
        # Basic routing
        if method == "GET" and url == "/":
            handle_health(response)
        else if method == "GET" and url == "/health":
            handle_health(response)
        else:
            handle_not_found(response)
    
    # Health check endpoint
    function handle_health(response):
        health_data = {
            "status": "healthy",
            "service": "MVP Application",
            "timestamp": current_timestamp()
        }
        response.write(200, health_data)
    
    # 404 handler
    function handle_not_found(response):
        error_data = {
            "error": "Not Found",
            "message": "The requested resource was not found"
        }
        response.write(404, error_data)
    
    # Basic business logic
    function performBasicAction():
        log("Performing basic MVP action")
        # Add your core business logic here

# Main entry point
async function main():
    try:
        # Initialize application
        app = new MVPApplication()
        
        # Start core functionality
        initialized = await app.initializeCore()
        if not initialized:
            log_error("Failed to initialize application")
            exit(1)
        
        # Start minimal service
        app.startMinimalService()
        
        # Handle graceful shutdown
        on_signal("SIGINT", shutdown_gracefully)
        
    catch error:
        log_error("Application failed:", error)
        exit(1)

# Start the application
main()
```

### **Language-Specific Adaptations**

#### **For JavaScript/TypeScript**
```javascript
// Use ES6 classes, async/await, try-catch
// Import http module or use framework
// Use process.env for configuration
```

#### **For Python**
```python
# Use classes, async/await, try-except
# Import http.server or Flask
# Use os.environ for configuration
```

#### **For Go**
```go
// Use structs, goroutines, error handling
// Import net/http package
// Use os.Getenv for configuration
```

#### **For Java**
```java
// Use classes, CompletableFuture, try-catch
// Use Spring Boot or Java EE
// Use System.getenv for configuration
```

#### **For C#**
```csharp
// Use classes, async/await, try-catch
// Use ASP.NET Core
// Use Environment.GetEnvironmentVariable
```

### **Configuration Pattern**
```pseudocode
# Environment-based configuration
config = {
    "port": get_env("PORT", "3000"),
    "environment": get_env("ENV", "development"),
    "log_level": get_env("LOG_LEVEL", "info")
}

# Basic configuration validation
function validate_config(config):
    required_fields = ["port"]
    for field in required_fields:
        if not config[field]:
            raise_error(f"Missing required config: {field}")
```

### **Error Handling Pattern**
```pseudocode
# Generic error handling
function handle_error(error, context):
    log_error(f"Error in {context}: {error.message}")
    
    # Basic error response
    return {
        "error": "Internal Server Error",
        "message": "An unexpected error occurred",
        "timestamp": current_timestamp()
    }

# Graceful shutdown
function shutdown_gracefully():
    log("Shutting down gracefully...")
    if server:
        server.close()
        log("Server closed")
    exit(0)
```

## MVP Guidelines

### **Core Principles**
- **Focus**: Core functionality only
- **Complexity**: Keep it simple and direct
- **Dependencies**: Minimal external dependencies
- **Error Handling**: Basic logging and exception handling
- **Testing**: Manual testing sufficient
- **Documentation**: Inline comments only

### **Technology Agnostic Features**
- **Language Independence**: Structure works with any programming language
- **Framework Flexibility**: Adaptable to any web framework or no framework
- **Configuration**: Environment-based configuration pattern
- **Error Handling**: Generic error handling patterns
- **Deployment**: Simple deployment patterns

### **Adaptation Guidelines**
1. **Choose Your Language**: Select appropriate programming language
2. **Select Framework**: Use preferred web framework or native HTTP server
3. **Implement Patterns**: Adapt pseudocode to language-specific syntax
4. **Add Dependencies**: Include only essential libraries
5. **Configure Environment**: Set up environment variables
6. **Test Locally**: Manual testing of core functionality

## What's NOT Included (Compared to Core/Full)
- No advanced web frameworks (use basic HTTP server)
- No advanced configuration management
- No comprehensive logging frameworks
- No monitoring/metrics collection
- No automated testing framework
- No API documentation generation
- No deployment automation
- No database integration
- No middleware system
- No advanced routing with parameters
- No authentication/authorization
- No caching mechanisms
- No API rate limiting

## Quick Start Checklist

### **1. Choose Technology Stack**
- [ ] Select programming language (Python, JavaScript, Go, Java, etc.)
- [ ] Choose web framework (optional - can use native HTTP)
- [ ] Set up development environment

### **2. Implement Core Structure**
- [ ] Create main application class
- [ ] Implement basic HTTP server
- [ ] Add health check endpoint
- [ ] Set up basic routing

### **3. Add Business Logic**
- [ ] Implement core functionality
- [ ] Add basic error handling
- [ ] Set up logging

### **4. Configure and Deploy**
- [ ] Set environment variables
- [ ] Test locally
- [ ] Deploy to target environment

## Next Steps (When Moving to Core Tier)
- Add comprehensive error handling
- Implement advanced routing
- Add configuration management
- Include logging framework
- Add automated testing
- Implement API documentation
- Add deployment automation
