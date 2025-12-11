/**
 * Template: minimal-boilerplate-typescript.tpl.ts
 * Purpose: minimal-boilerplate-typescript template
 * Stack: typescript
 * Tier: base
 */

# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: unknown template utilities
# Tier: mvp
# Stack: unknown
# Category: utilities

# Minimal Boilerplate Template (MVP Tier - TypeScript)

## Purpose
Provides the absolute minimum TypeScript code structure for MVP projects following the minimal viable product approach with static typing and enhanced developer experience.

## Usage
This template should be used for:
- Prototype web services with type safety
- Proof of concepts with compile-time error checking
- Early-stage startup APIs with enhanced tooling
- Internal tools with limited scope and type safety

## Structure
```typescript
#!/usr/bin/env node

/**
 * Minimal MVP Application
 * Basic structure for rapid prototyping and validation with TypeScript
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { URL } from 'url';

interface HealthResponse {
    status: string;
    service: string;
    timestamp: string;
}

interface ErrorResponse {
    error: string;
    message: string;
}

class MVPApplication {
    private status: string = 'MVP Application Starting...';
    private port: number;
    private server: any = null;

    constructor() {
        this.port = process.env.PORT ? parseInt(process.env.PORT) : 3000;
    }

    async initializeCore(): Promise<boolean> {
        /**
         * Initialize core MVP functionality
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

    startMinimalService(): void {
        /**
         * Start minimal HTTP service
         */
        try {
            this.server = createServer((req: IncomingMessage, res: ServerResponse) => {
                this.handleRequest(req, res);
            });

            this.server.listen(this.port, () => {
                console.log(`MVP Service Running on port ${this.port}`);
            });

        } catch (error) {
            console.error('Failed to start service:', error);
        }
    }

    private handleRequest(req: IncomingMessage, res: ServerResponse): void {
        /**
         * Basic request handler with type safety
         */
        const { method, url } = req;
        
        // Set basic headers
        res.setHeader('Content-Type', 'application/json');
        
        // Basic routing with type safety
        if (method === 'GET' && url === '/') {
            this.handleHealth(res);
        } else if (method === 'GET' && url === '/health') {
            this.handleHealth(res);
        } else {
            this.handleNotFound(res);
        }
    }

    private handleHealth(res: ServerResponse): void {
        /**
         * Basic health check endpoint with typed response
         */
        const healthResponse: HealthResponse = {
            status: 'healthy',
            service: 'MVP Application',
            timestamp: new Date().toISOString()
        };
        
        res.writeHead(200);
        res.end(JSON.stringify(healthResponse));
    }

    private handleNotFound(res: ServerResponse): void {
        /**
         * Basic 404 handler with typed response
         */
        const errorResponse: ErrorResponse = {
            error: 'Not Found',
            message: 'The requested resource was not found'
        };
        
        res.writeHead(404);
        res.end(JSON.stringify(errorResponse));
    }

    async performMVPAction(action: string): Promise<any> {
        /**
         * Perform basic MVP action with type safety
         */
        console.log(`Performing MVP action: ${action}`);
        
        // Simulate basic work
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        return {
            status: 'completed',
            action: action,
            timestamp: new Date().toISOString()
        };
    }

    shutdown(): void {
        /**
         * Graceful shutdown
         */
        console.log('Shutting down MVP application');
        if (this.server) {
            this.server.close();
        }
    }
}

// Main execution with async/await and error handling
async function main(): Promise<void> {
    try {
        const app = new MVPApplication();
        
        // Initialize core functionality
        const initialized = await app.initializeCore();
        if (!initialized) {
            throw new Error('Failed to initialize MVP application');
        }
        
        // Start minimal service
        app.startMinimalService();
        
        // Setup graceful shutdown
        process.on('SIGINT', () => {
            console.log('Received SIGINT, shutting down gracefully...');
            app.shutdown();
            process.exit(0);
        });
        
        process.on('SIGTERM', () => {
            console.log('Received SIGTERM, shutting down gracefully...');
            app.shutdown();
            process.exit(0);
        });
        
    } catch (error) {
        console.error('MVP application failed to start:', error);
        process.exit(1);
    }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error: Error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

// Start the MVP application
main();
```

### **TypeScript MVP Features**
- **Static Typing**: Compile-time error checking and enhanced IDE support
- **Interfaces**: Typed responses and request handling
- **Async/Await**: Modern asynchronous programming patterns
- **Error Handling**: Comprehensive error handling with type safety
- **Basic HTTP Server**: Minimal web service with typed responses
- **Health Check**: Simple health monitoring endpoint
- **Graceful Shutdown**: Proper cleanup on process termination

### **Dependencies**
```json
{
  "dependencies": {
    "@types/node": "^20.0.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0",
    "ts-node": "^10.9.0"
  }
}
```

### **Configuration**
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "outDir": "./dist",
    "rootDir": "./src"
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules"]
}
```

## What's Included (vs Core)
- Basic HTTP server with minimal dependencies
- Simple request routing with type safety
- Basic error handling and logging
- Health check endpoint
- Graceful shutdown handling
- Static typing with interfaces

## What's NOT Included (vs Core)
- No Express.js framework
- No structured logging
- No metrics collection
- No database connections
- No Redis caching
- No background tasks
- No advanced error handling
- No compression middleware
- No CORS support

## Quick Start
1. Install dependencies: `npm install`
2. Compile TypeScript: `npx tsc`
3. Run application: `node dist/index.js`
4. Or use ts-node: `npx ts-node src/index.ts`

## Development Notes
- Use `ts-node` for development with automatic compilation
- Enable strict mode for better type safety
- Add interfaces for all API responses
- Use async/await for all asynchronous operations
- Handle all promise rejections and exceptions
