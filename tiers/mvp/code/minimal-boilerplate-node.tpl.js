/**
 * File: minimal-boilerplate-node.tpl.js
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

# Minimal Boilerplate Template (MVP Tier - Node.js)

## Purpose
Provides the absolute minimum Node.js code structure for MVP projects following the minimal viable product approach.

## Usage
This template should be used for:
- Prototype web services
- Proof of concepts
- Early-stage startup APIs
- Internal tools with limited scope

## Structure
```javascript
#!/usr/bin/env node

/**
 * Minimal MVP Application
 * Basic structure for rapid prototyping and validation
 */

const http = require('http');
const { URL } = require('url');

class MVPApplication {
    constructor() {
        this.status = 'MVP Application Starting...';
        this.port = process.env.PORT || 3000;
        this.server = null;
    }

    async initializeCore() {
        /**
         * Initialize core functionality only
         * No advanced configuration, no optional features
         */
        try {
            console.log('Initializing core functionality');
            this.status = 'MVP Service Running';
            return true;
        } catch (error) {
            console.error('Failed to initialize:', error);
            return false;
        }
    }

    startMinimalService() {
        /**
         * Start minimal HTTP service with basic functionality
         */
        try {
            this.server = http.createServer((req, res) => {
                this.handleRequest(req, res);
            });

            this.server.listen(this.port, () => {
                console.log(`MVP Service Running on port ${this.port}`);
            });

        } catch (error) {
            console.error('Failed to start service:', error);
        }
    }

    handleRequest(req, res) {
        /**
         * Basic request handler
         */
        const { method, url } = req;
        
        // Set basic headers
        res.setHeader('Content-Type', 'application/json');
        
        // Basic routing
        if (method === 'GET' && url === '/') {
            this.handleHealth(res);
        } else if (method === 'GET' && url === '/health') {
            this.handleHealth(res);
        } else {
            this.handleNotFound(res);
        }
    }

    handleHealth(res) {
        /**
         * Basic health check endpoint
         */
        res.writeHead(200);
        res.end(JSON.stringify({
            status: 'healthy',
            service: 'MVP Application',
            timestamp: new Date().toISOString()
        }));
    }

    handleNotFound(res) {
        /**
         * Basic 404 handler
         */
        res.writeHead(404);
        res.end(JSON.stringify({
            error: 'Not Found',
            message: 'The requested resource was not found'
        }));
    }

    performBasicAction() {
        /**
         * Basic service functionality
         */
        console.log('Performing basic MVP action');
        // Add your core business logic here
    }
}

// Main entry point
async function main() {
    try {
        // Initialize application
        const app = new MVPApplication();
        
        // Start core functionality
        const initialized = await app.initializeCore();
        if (!initialized) {
            console.error('Failed to initialize application');
            process.exit(1);
        }
        
        // Start minimal service
        app.startMinimalService();
        
        // Handle graceful shutdown
        process.on('SIGINT', () => {
            console.log('Shutting down gracefully...');
            if (app.server) {
                app.server.close(() => {
                    console.log('Server closed');
                    process.exit(0);
                });
            }
        });
        
    } catch (error) {
        console.error('Application failed:', error);
        process.exit(1);
    }
}

// Start the application
main();
```

## MVP Guidelines
- **Focus**: Core functionality only
- **Complexity**: Keep it simple and direct
- **Dependencies**: Core Node.js modules only
- **Error Handling**: Basic console logging and try-catch
- **Testing**: Manual testing sufficient
- **Documentation**: Inline comments only

## What's NOT Included (Compared to Core/Full)
- No Express.js or other web frameworks
- No advanced configuration management
- No comprehensive logging frameworks
- No monitoring/metrics collection
- No automated testing framework
- No API documentation generation
- No deployment automation
- No database integration
- No middleware system
- No advanced routing
