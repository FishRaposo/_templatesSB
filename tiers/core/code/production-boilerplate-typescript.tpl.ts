/**
 * File: production-boilerplate-typescript.tpl.ts
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

# Production Boilerplate Template (Core Tier - TypeScript)

## Purpose
Provides production-ready TypeScript code structure for core projects that require reliability, maintainability, proper operational practices, and static typing with enhanced developer experience.

## Usage
This template should be used for:
- Production web services with compile-time error checking
- SaaS products with type safety and enhanced tooling
- Enterprise applications with TypeScript enterprise patterns
- Systems requiring 99%+ uptime and enhanced developer experience

## Structure
```typescript
#!/usr/bin/env node

/**
 * Production Application
 * Production-ready structure with proper error handling, logging, monitoring,
 * and TypeScript patterns with enhanced developer experience
 */

import express, { Express, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import compression from 'compression';
import cors from 'cors';
import winston from 'winston';
import { promisify } from 'util';
import { EventEmitter } from 'events';

// Configure structured logging with type safety
const logger: winston.Logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

interface ProductionConfig {
  port: number;
  logLevel: string;
  environment: string;
  databaseUrl?: string;
  redisUrl?: string;
  metricsEnabled: boolean;
  healthCheckInterval: number;
}

interface SystemMetrics {
  memoryUsage: NodeJS.MemoryUsage;
  uptime: number;
  activeConnections: number;
  requestCount: number;
  errorCount: number;
  timestamp: number;
}

interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime: number;
  memory: NodeJS.MemoryUsage;
  database?: 'connected' | 'disconnected';
  redis?: 'connected' | 'disconnected';
  timestamp: string;
}

class ProductionConfigManager implements ProductionConfig {
  public port: number;
  public logLevel: string;
  public environment: string;
  public databaseUrl?: string;
  public redisUrl?: string;
  public metricsEnabled: boolean;
  public healthCheckInterval: number;

  constructor() {
    this.port = parseInt(process.env.PORT || '3000');
    this.logLevel = process.env.LOG_LEVEL || 'info';
    this.environment = process.env.NODE_ENV || 'production';
    this.databaseUrl = process.env.DATABASE_URL;
    this.redisUrl = process.env.REDIS_URL;
    this.metricsEnabled = process.env.METRICS_ENABLED !== 'false';
    this.healthCheckInterval = parseInt(process.env.HEALTH_CHECK_INTERVAL || '30000');
    
    this.validateConfig();
  }

  private validateConfig(): void {
    if (this.port < 1 || this.port > 65535) {
      throw new Error('Invalid port number');
    }
    
    if (!['info', 'debug', 'warn', 'error'].includes(this.logLevel)) {
      throw new Error('Invalid log level');
    }
  }
}

class ProductionMetricsCollector {
  private metrics: SystemMetrics[] = [];
  private requestCount: number = 0;
  private errorCount: number = 0;
  private startTime: number = Date.now();

  constructor(private config: ProductionConfig) {
    // Start metrics collection
    setInterval(() => {
      this.collectMetrics();
    }, config.healthCheckInterval);
  }

  private collectMetrics(): void {
    const metrics: SystemMetrics = {
      memoryUsage: process.memoryUsage(),
      uptime: process.uptime(),
      activeConnections: (process as any)._getActiveHandles().length,
      requestCount: this.requestCount,
      errorCount: this.errorCount,
      timestamp: Date.now()
    };

    this.metrics.push(metrics);
    
    // Keep only last 100 metrics
    if (this.metrics.length > 100) {
      this.metrics.shift();
    }

    logger.info('System metrics collected', metrics);
  }

  public incrementRequestCount(): void {
    this.requestCount++;
  }

  public incrementErrorCount(): void {
    this.errorCount++;
  }

  public getLatestMetrics(): SystemMetrics | null {
    return this.metrics.length > 0 ? this.metrics[this.metrics.length - 1] : null;
  }

  public getAverageResponseTime(): number {
    // Simulated average response time calculation
    return Math.random() * 1000;
  }
}

class ProductionService extends EventEmitter {
  private config: ProductionConfig;
  private metrics: ProductionMetricsCollector;
  private database?: any;
  private redis?: any;
  private running: boolean = false;

  constructor(config: ProductionConfig) {
    super();
    this.config = config;
    this.metrics = new ProductionMetricsCollector(config);
  }

  public async initialize(): Promise<void> {
    try {
      logger.info('Initializing production service');
      
      // Initialize database connection if configured
      if (this.config.databaseUrl) {
        await this.initializeDatabase();
      }
      
      // Initialize Redis connection if configured
      if (this.config.redisUrl) {
        await this.initializeRedis();
      }
      
      this.running = true;
      logger.info('Production service initialized successfully');
      
    } catch (error) {
      logger.error('Failed to initialize production service', { error: (error as Error).message });
      throw error;
    }
  }

  private async initializeDatabase(): Promise<void> {
    // Database initialization logic
    logger.info('Initializing database connection');
    // Simulate database connection
    await new Promise(resolve => setTimeout(resolve, 1000));
    this.database = { connected: true };
    logger.info('Database connection established');
  }

  private async initializeRedis(): Promise<void> {
    // Redis initialization logic
    logger.info('Initializing Redis connection');
    // Simulate Redis connection
    await new Promise(resolve => setTimeout(resolve, 500));
    this.redis = { connected: true };
    logger.info('Redis connection established');
  }

  public async performProductionAction(action: string, data?: any): Promise<any> {
    if (!this.running) {
      throw new Error('Service not running');
    }

    logger.info('Performing production action', { action, data });
    
    try {
      // Simulate production work
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const result = {
        status: 'completed',
        action: action,
        data: data,
        timestamp: new Date().toISOString(),
        metrics: this.metrics.getLatestMetrics()
      };

      logger.info('Production action completed', { action, result });
      this.emit('actionCompleted', result);
      
      return result;
      
    } catch (error) {
      this.metrics.incrementErrorCount();
      logger.error('Production action failed', { action, error: (error as Error).message });
      this.emit('actionFailed', { action, error: (error as Error).message });
      throw error;
    }
  }

  public getHealthStatus(): HealthStatus {
    const status: HealthStatus = {
      status: this.running ? 'healthy' : 'unhealthy',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: new Date().toISOString()
    };

    if (this.database) {
      status.database = this.database.connected ? 'connected' : 'disconnected';
    }

    if (this.redis) {
      status.redis = this.redis.connected ? 'connected' : 'disconnected';
    }

    // Determine overall health status
    if (status.memory.heapUsed / status.memory.heapTotal > 0.9) {
      status.status = 'degraded';
    }

    return status;
  }

  public getMetrics(): ProductionMetricsCollector {
    return this.metrics;
  }

  public async shutdown(): Promise<void> {
    logger.info('Shutting down production service');
    this.running = false;

    // Close database connection
    if (this.database) {
      // Database cleanup logic
      logger.info('Database connection closed');
    }

    // Close Redis connection
    if (this.redis) {
      // Redis cleanup logic
      logger.info('Redis connection closed');
    }

    logger.info('Production service shutdown complete');
  }
}

class ProductionApplication {
  private config: ProductionConfig;
  private service: ProductionService;
  private app: Express;
  private server?: any;

  constructor() {
    this.config = new ProductionConfigManager();
    this.service = new ProductionService(this.config);
    this.app = this.createApp();
  }

  private createApp(): Express {
    const app = express();

    // Security middleware
    app.use(helmet());
    app.use(compression());
    app.use(cors({
      origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
      credentials: true
    }));

    // Body parsing middleware
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Request logging middleware
    app.use((req: Request, res: Response, next: NextFunction) => {
      logger.info('Request received', {
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent'),
        ip: req.ip
      });
      
      this.service.getMetrics().incrementRequestCount();
      
      // Measure response time
      const startTime = Date.now();
      res.on('finish', () => {
        const duration = Date.now() - startTime;
        logger.info('Request completed', {
          method: req.method,
          url: req.url,
          statusCode: res.statusCode,
          duration
        });
      });
      
      next();
    });

    // Global error handler
    app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
      this.service.getMetrics().incrementErrorCount();
      
      logger.error('Unhandled error', {
        error: error.message,
        stack: error.stack,
        method: req.method,
        url: req.url
      });

      res.status(500).json({
        error: 'Internal server error',
        message: this.config.environment === 'development' ? error.message : 'Something went wrong'
      });
    });

    // Routes
    app.get('/', (req: Request, res: Response) => {
      res.json({
        status: 'healthy',
        service: 'Production Application',
        version: '1.0.0',
        timestamp: new Date().toISOString()
      });
    });

    app.get('/health', (req: Request, res: Response) => {
      const health = this.service.getHealthStatus();
      const statusCode = health.status === 'healthy' ? 200 : 
                        health.status === 'degraded' ? 200 : 503;
      res.status(statusCode).json(health);
    });

    app.get('/metrics', (req: Request, res: Response) => {
      if (!this.config.metricsEnabled) {
        return res.status(404).json({ error: 'Metrics not enabled' });
      }
      
      const metrics = this.service.getMetrics().getLatestMetrics();
      res.json(metrics || { message: 'No metrics available' });
    });

    app.post('/api/action', async (req: Request, res: Response) => {
      try {
        const { action, data } = req.body;
        
        if (!action) {
          return res.status(400).json({ error: 'Action is required' });
        }

        const result = await this.service.performProductionAction(action, data);
        res.json(result);
        
      } catch (error) {
        res.status(500).json({ 
          error: 'Action failed', 
          message: (error as Error).message 
        });
      }
    });

    // 404 handler
    app.use((req: Request, res: Response) => {
      res.status(404).json({ error: 'Not found' });
    });

    return app;
  }

  public async start(): Promise<void> {
    try {
      // Initialize service
      await this.service.initialize();
      
      // Start HTTP server
      this.server = this.app.listen(this.config.port, () => {
        logger.info(`Production application started on port ${this.config.port}`);
      });

      // Setup graceful shutdown
      this.setupGracefulShutdown();
      
    } catch (error) {
      logger.error('Failed to start production application', { 
        error: (error as Error).message 
      });
      process.exit(1);
    }
  }

  private setupGracefulShutdown(): void {
    const shutdown = async (signal: string) => {
      logger.info(`Received ${signal}, shutting down gracefully...`);
      
      if (this.server) {
        await new Promise<void>((resolve) => {
          this.server.close(() => resolve());
        });
      }
      
      await this.service.shutdown();
      logger.info('Production application stopped');
      process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
  }
}

// Main execution with proper error handling
async function main(): Promise<void> {
  try {
    const app = new ProductionApplication();
    await app.start();
    
  } catch (error) {
    logger.error('Production application failed to start', { 
      error: (error as Error).message 
    });
    process.exit(1);
  }
}

// Handle uncaught exceptions and rejections
process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  logger.error('Unhandled Rejection', { reason, promise });
  process.exit(1);
});

// Start the production application
main();
```

### **TypeScript Production Features**
- **Static Typing**: Compile-time error checking and enhanced IDE support
- **Interfaces**: Type-safe configuration, metrics, and health status
- **Express.js**: Production-ready web framework with TypeScript support
- **Structured Logging**: Winston logger with type-safe log entries
- **Metrics Collection**: System metrics with typed interfaces
- **Health Monitoring**: Comprehensive health checks with typed responses
- **Error Handling**: Type-safe error handling and logging
- **Graceful Shutdown**: Proper cleanup with async/await patterns

### **Dependencies**
```json
{
  "dependencies": {
    "express": "^4.18.2",
    "helmet": "^7.1.0",
    "compression": "^1.7.4",
    "cors": "^2.8.5",
    "winston": "^3.11.0"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "@types/express": "^4.17.0",
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

## What's Included (vs MVP)
- Express.js framework with TypeScript support
- Structured logging with Winston
- Metrics collection and monitoring
- Database and Redis connection support
- Comprehensive health checks
- Security middleware (helmet, CORS)
- Request/response logging
- Production-ready error handling
- Graceful shutdown with proper cleanup

## What's NOT Included (vs Enterprise)
- No advanced security (JWT, encryption)
- No compliance management (GDPR/HIPAA)
- No Prometheus metrics
- No multi-region support
- No advanced rate limiting
- No enterprise authentication
- No audit logging
- No cloud integration

## Quick Start
1. Install dependencies: `npm install`
2. Configure environment variables
3. Compile TypeScript: `npx tsc`
4. Run application: `node dist/index.js`
5. Or use ts-node: `npx ts-node src/index.ts`

## Development Notes
- Use strict TypeScript mode for better type safety
- Configure proper environment variables for production
- Monitor health endpoint for service status
- Use metrics endpoint for system monitoring
- Implement proper database connection pooling
- Add comprehensive error logging and monitoring
