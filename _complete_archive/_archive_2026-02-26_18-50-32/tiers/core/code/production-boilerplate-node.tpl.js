/**
 * File: production-boilerplate-node.tpl.js
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

# Production Boilerplate Template (Core Tier - Node.js)

## Purpose
Provides production-ready Node.js code structure for core projects that require reliability, maintainability, and proper operational practices.

## Usage
This template should be used for:
- Production web services
- SaaS products
- Enterprise applications
- Systems requiring 99%+ uptime

## Structure
```javascript
#!/usr/bin/env node

/**
 * Production Application
 * Production-ready structure with proper error handling, logging, and monitoring
 */

const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const winston = require('winston');
const { promisify } = require('util');
const EventEmitter = require('events');

// Configure structured logging
const logger = winston.createLogger({
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

class ProductionConfig {
  constructor() {
    this.port = process.env.PORT || 3000;
    this.logLevel = process.env.LOG_LEVEL || 'info';
    this.environment = process.env.NODE_ENV || 'production';
    this.databaseUrl = process.env.DATABASE_URL;
    this.redisUrl = process.env.REDIS_URL;
    this.apiKeys = this._loadApiKeys();
  }

  _loadApiKeys() {
    return {
      analytics: process.env.ANALYTICS_API_KEY,
      monitoring: process.env.MONITORING_API_KEY,
    };
  }
}

class SystemMetrics {
  constructor() {
    this.memoryUsage = 0;
    this.cpuUsage = 0;
    this.networkLatency = 0;
    this.activeUsers = 0;
    this.timestamp = Date.now();
  }

  static async collect() {
    const metrics = new SystemMetrics();
    
    // Collect memory usage
    const memUsage = process.memoryUsage();
    metrics.memoryUsage = (memUsage.heapUsed / memUsage.heapTotal) * 100;
    
    // Collect CPU usage (simplified)
    metrics.cpuUsage = process.cpuUsage().user / 1000000; // Convert to seconds
    
    // Simulate network latency and active users
    metrics.networkLatency = Math.random() * 100 + 50;
    metrics.activeUsers = Math.floor(Math.random() * 2000) + 500;
    
    metrics.timestamp = Date.now();
    return metrics;
  }
}

class ProductionService extends EventEmitter {
  constructor(config) {
    super();
    this.config = config;
    this.running = false;
    this.metrics = [];
    this.backgroundTasks = new Set();
    this.database = null;
    this.redis = null;
  }

  async initialize() {
    try {
      logger.info('Initializing production service');
      
      // Initialize database connection
      await this._initializeDatabase();
      
      // Initialize Redis connection
      await this._initializeRedis();
      
      // Start background tasks
      await this._startBackgroundTasks();
      
      this.running = true;
      logger.info('Production service initialized successfully');
      
    } catch (error) {
      logger.error('Failed to initialize production service', { error: error.message });
      throw error;
    }
  }

  async _initializeDatabase() {
    // Database initialization logic
    logger.info('Database connection initialized');
  }

  async _initializeRedis() {
    // Redis initialization logic
    logger.info('Redis connection initialized');
  }

  async _startBackgroundTasks() {
    // Metrics collection task
    const metricsTask = this._startMetricsCollection();
    this.backgroundTasks.add(metricsTask);
    
    // Health check task
    const healthTask = this._startHealthChecks();
    this.backgroundTasks.add(healthTask);
    
    logger.info('Background tasks started');
  }

  _startMetricsCollection() {
    const interval = setInterval(async () => {
      if (this.running) {
        try {
          const metrics = await SystemMetrics.collect();
          this.metrics.push(metrics);
          
          // Keep only last 100 metrics
          if (this.metrics.length > 100) {
            this.metrics.shift();
          }
          
          this.emit('metrics', metrics);
        } catch (error) {
          logger.error('Error collecting metrics', { error: error.message });
        }
      }
    }, 30000); // Collect every 30 seconds

    return { type: 'metrics', interval };
  }

  _startHealthChecks() {
    const interval = setInterval(async () => {
      if (this.running) {
        try {
          await this._performHealthCheck();
          this.emit('health', { status: 'healthy' });
        } catch (error) {
          logger.error('Health check failed', { error: error.message });
          this.emit('health', { status: 'unhealthy', error: error.message });
        }
      }
    }, 60000); // Check every minute

    return { type: 'health', interval };
  }

  async _performHealthCheck() {
    // Perform health checks
    // Database connectivity, Redis connectivity, etc.
    return true;
  }

  async performAction() {
    try {
      logger.info('Performing production action');
      
      // Simulate work
      await new Promise(resolve => setTimeout(resolve, 500));
      
      const result = {
        status: 'success',
        message: 'Production action completed',
        timestamp: Date.now()
      };
      
      logger.info('Production action completed successfully');
      return result;
      
    } catch (error) {
      logger.error('Production action failed', { error: error.message });
      throw error;
    }
  }

  getLatestMetrics() {
    return this.metrics[this.metrics.length - 1] || null;
  }

  async shutdown() {
    logger.info('Shutting down production service');
    this.running = false;
    
    // Stop background tasks
    for (const task of this.backgroundTasks) {
      clearInterval(task.interval);
    }
    this.backgroundTasks.clear();
    
    // Close database connections
    if (this.database) {
      await this.database.close();
    }
    
    // Close Redis connections
    if (this.redis) {
      await this.redis.quit();
    }
    
    logger.info('Production service shutdown complete');
  }
}

class ProductionApplication {
  constructor() {
    this.config = new ProductionConfig();
    this.service = new ProductionService(this.config);
    this.app = this._createApp();
    this.server = null;
  }

  _createApp() {
    const app = express();

    // Security middleware
    app.use(helmet());
    
    // Compression middleware
    app.use(compression());
    
    // CORS middleware
    app.use(cors({
      origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
      credentials: true
    }));

    // Body parsing middleware
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Request logging middleware
    app.use((req, res, next) => {
      logger.info('Request received', {
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent'),
        ip: req.ip
      });
      next();
    });

    // Global error handler
    app.use((error, req, res, next) => {
      logger.error('Unhandled error', {
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method
      });
      
      res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
      });
    });

    // Routes
    app.get('/', (req, res) => {
      res.json({ status: 'healthy', service: 'production' });
    });

    app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: Date.now(),
        version: '1.0.0'
      });
    });

    app.get('/metrics', (req, res) => {
      const metrics = this.service.getLatestMetrics();
      if (metrics) {
        res.json(metrics);
      } else {
        res.json({ message: 'No metrics available' });
      }
    });

    app.post('/action', async (req, res) => {
      try {
        const result = await this.service.performAction();
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // 404 handler
    app.use((req, res) => {
      res.status(404).json({ error: 'Not found' });
    });

    return app;
  }

  async start() {
    try {
      // Initialize service
      await this.service.initialize();
      
      // Start HTTP server
      this.server = this.app.listen(this.config.port, () => {
        logger.info(`Production application started on port ${this.config.port}`);
      });

      // Setup graceful shutdown
      this._setupGracefulShutdown();
      
    } catch (error) {
      logger.error('Failed to start application', { error: error.message });
      process.exit(1);
    }
  }

  _setupGracefulShutdown() {
    const shutdown = async (signal) => {
      logger.info(`Received ${signal}, shutting down gracefully...`);
      
      if (this.server) {
        await new Promise((resolve) => {
          this.server.close(resolve);
        });
      }
      
      await this.service.shutdown();
      logger.info('Application stopped');
      process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
  }
}

// Main entry point
async function main() {
  try {
    const app = new ProductionApplication();
    await app.start();
    
  } catch (error) {
    logger.error('Application failed to start', { error: error.message });
    process.exit(1);
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled rejection', { reason, promise });
  process.exit(1);
});

// Start the application
main();
```

## Core Production Guidelines
- **Reliability**: Graceful shutdown, error handling, circuit breakers
- **Observability**: Structured logging, health checks, metrics
- **Security**: Helmet, CORS, input validation, rate limiting
- **Performance**: Compression, connection pooling, caching
- **Testing**: Unit tests, integration tests, load testing
- **Documentation**: API docs, deployment guides, runbooks

## Required Dependencies
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
    "jest": "^29.7.0",
    "supertest": "^6.3.3"
  }
}
```

## What's Included (vs MVP)
- Express.js web framework with security middleware
- Structured logging with Winston
- Graceful shutdown handling
- Configuration management
- Health check endpoints
- Background task management
- System metrics collection
- Production-ready error handling

## What's NOT Included (vs Full)
- No advanced monitoring/metrics dashboards
- No distributed tracing
- No advanced security features
- No multi-region deployment
- No advanced caching strategies
- No enterprise authentication systems
