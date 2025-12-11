/**
 * Template: logging-utilities-pattern.tpl.ts
 * Purpose: logging-utilities-pattern template
 * Stack: typescript
 * Tier: base
 */

# Universal Template System - Typescript Stack
# Generated: 2025-12-10
# Purpose: Logging utilities
# Tier: base
# Stack: typescript
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: logging-utilities-pattern.tpl.ts
// PURPOSE: TypeScript logging utilities pattern with structured logging and multiple transports
// USAGE: Import and adapt for logging in TypeScript applications
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

// TypeScript Logging Utilities Pattern
// Author: [[.Author]]
// Version: [[.Version]]
// Date: [[.Date]]

/**
 * Logging Utilities Pattern for TypeScript Applications
 * 
 * This pattern provides comprehensive logging with structured logging, multiple transports,
 * log levels, correlation IDs, and performance monitoring.
 */

// ==================== LOGGING INTERFACES ====================

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  correlationId?: string;
  userId?: string;
  requestId?: string;
  service?: string;
  module?: string;
  function?: string;
  metadata?: Record<string, any>;
  error?: {
    name: string;
    message: string;
    stack?: string;
    code?: string;
  };
  performance?: {
    duration?: number;
    memoryUsage?: NodeJS.MemoryUsage;
    cpuUsage?: NodeJS.CpuUsage;
  };
}

export type LogLevel = 'error' | 'warn' | 'info' | 'debug' | 'trace';

export interface LoggerConfig {
  level: LogLevel;
  format: 'json' | 'simple' | 'pretty';
  transports: TransportConfig[];
  metadata: Record<string, any>;
  correlationIdHeader?: string;
  userIdHeader?: string;
}

export interface TransportConfig {
  type: 'console' | 'file' | 'http' | 'database';
  enabled: boolean;
  level?: LogLevel;
  format?: 'json' | 'simple' | 'pretty';
  options?: Record<string, any>;
}

export interface PerformanceMetrics {
  startTime: number;
  endTime?: number;
  duration?: number;
  memoryBefore?: NodeJS.MemoryUsage;
  memoryAfter?: NodeJS.MemoryUsage;
  cpuBefore?: NodeJS.CpuUsage;
  cpuAfter?: NodeJS.CpuUsage;
}

// ==================== LOG LEVEL MANAGEMENT ====================

export class LogLevelManager {
  private static readonly levels: Record<LogLevel, number> = {
    error: 0,
    warn: 1,
    info: 2,
    debug: 3,
    trace: 4,
  };

  public static shouldLog(currentLevel: LogLevel, targetLevel: LogLevel): boolean {
    return this.levels[targetLevel] <= this.levels[currentLevel];
  }

  public static getLevelName(level: LogLevel): string {
    return level.toUpperCase();
  }

  public static isValidLevel(level: string): level is LogLevel {
    return Object.keys(this.levels).includes(level);
  }
}

// ==================== LOG TRANSPORTS ====================

import winston from 'winston';
import fs from 'fs';
import path from 'path';

export abstract class LogTransport {
  protected config: TransportConfig;
  protected level: LogLevel;

  constructor(config: TransportConfig) {
    this.config = config;
    this.level = config.level || 'info';
  }

  public abstract log(entry: LogEntry): void | Promise<void>;
  public shouldLog(level: LogLevel): boolean {
    return LogLevelManager.shouldLog(this.level, level);
  }
}

export class ConsoleTransport extends LogTransport {
  private logger: winston.Logger;

  constructor(config: TransportConfig) {
    super(config);
    
    const format = config.format || 'pretty';
    let winstonFormat: winston.Logform.Format;

    switch (format) {
      case 'json':
        winstonFormat = winston.format.json();
        break;
      case 'simple':
        winstonFormat = winston.format.simple();
        break;
      case 'pretty':
      default:
        winstonFormat = winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp(),
          winston.format.printf(({ timestamp, level, message, correlationId, userId, ...meta }) => {
            const id = correlationId ? ` [${correlationId}]` : '';
            const user = userId ? ` [user:${userId}]` : '';
            return `${timestamp} ${level}${id}${user} ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ''}`;
          })
        );
        break;
    }

    this.logger = winston.createLogger({
      level: this.level,
      format: winstonFormat,
      transports: [new winston.transports.Console()],
    });
  }

  public log(entry: LogEntry): void {
    if (!this.shouldLog(entry.level)) {
      return;
    }

    const logData = {
      timestamp: entry.timestamp,
      level: entry.level,
      message: entry.message,
      correlationId: entry.correlationId,
      userId: entry.userId,
      requestId: entry.requestId,
      service: entry.service,
      module: entry.module,
      function: entry.function,
      ...entry.metadata,
      ...(entry.error && { error: entry.error }),
      ...(entry.performance && { performance: entry.performance }),
    };

    this.logger.log(entry.level, entry.message, logData);
  }
}

export class FileTransport extends LogTransport {
  private logger: winston.Logger;

  constructor(config: TransportConfig) {
    super(config);
    
    const options = config.options || {};
    const filename = options.filename || 'logs/app.log';
    const maxSize = options.maxSize || '20m';
    const maxFiles = options.maxFiles || 5;

    // Ensure log directory exists
    const logDir = path.dirname(filename);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }

    this.logger = winston.createLogger({
      level: this.level,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({
          filename,
          maxsize: this.parseSize(maxSize),
          maxFiles,
        }),
      ],
    });
  }

  private parseSize(size: string): number {
    const units: Record<string, number> = {
      b: 1,
      k: 1024,
      m: 1024 * 1024,
      g: 1024 * 1024 * 1024,
    };

    const match = size.toLowerCase().match(/^(\d+)([bkmg]?)$/);
    if (!match) {
      return 20 * 1024 * 1024; // Default 20MB
    }

    const [, sizeStr, unit] = match;
    return parseInt(sizeStr, 10) * (units[unit] || 1);
  }

  public log(entry: LogEntry): void {
    if (!this.shouldLog(entry.level)) {
      return;
    }

    const logData = {
      timestamp: entry.timestamp,
      level: entry.level,
      message: entry.message,
      correlationId: entry.correlationId,
      userId: entry.userId,
      requestId: entry.requestId,
      service: entry.service,
      module: entry.module,
      function: entry.function,
      ...entry.metadata,
      ...(entry.error && { error: entry.error }),
      ...(entry.performance && { performance: entry.performance }),
    };

    this.logger.log(entry.level, entry.message, logData);
  }
}

export class HttpTransport extends LogTransport {
  private endpoint: string;
  private headers: Record<string, string>;

  constructor(config: TransportConfig) {
    super(config);
    
    const options = config.options || {};
    this.endpoint = options.endpoint || 'http://localhost:3000/logs';
    this.headers = options.headers || { 'Content-Type': 'application/json' };
  }

  public async log(entry: LogEntry): Promise<void> {
    if (!this.shouldLog(entry.level)) {
      return;
    }

    try {
      await fetch(this.endpoint, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(entry),
      });
    } catch (error) {
      // Fail silently to avoid infinite loops
      console.error('Failed to send log to HTTP endpoint:', error);
    }
  }
}

// ==================== MAIN LOGGER CLASS ====================

export class Logger {
  private config: LoggerConfig;
  private transports: LogTransport[] = [];
  private context: Record<string, any> = {};

  constructor(config: Partial<LoggerConfig> = {}) {
    this.config = {
      level: 'info',
      format: 'json',
      transports: [
        { type: 'console', enabled: true },
        { type: 'file', enabled: true, options: { filename: 'logs/app.log' } },
      ],
      metadata: {},
      correlationIdHeader: 'x-correlation-id',
      userIdHeader: 'x-user-id',
      ...config,
    };

    this.initializeTransports();
  }

  private initializeTransports(): void {
    this.transports = [];

    for (const transportConfig of this.config.transports) {
      if (!transportConfig.enabled) {
        continue;
      }

      let transport: LogTransport;

      switch (transportConfig.type) {
        case 'console':
          transport = new ConsoleTransport(transportConfig);
          break;
        case 'file':
          transport = new FileTransport(transportConfig);
          break;
        case 'http':
          transport = new HttpTransport(transportConfig);
          break;
        default:
          console.warn(`Unknown transport type: ${transportConfig.type}`);
          continue;
      }

      this.transports.push(transport);
    }
  }

  // ==================== CONTEXT MANAGEMENT ====================

  public setContext(context: Record<string, any>): void {
    this.context = { ...this.context, ...context };
  }

  public getContext(): Record<string, any> {
    return { ...this.context };
  }

  public clearContext(): void {
    this.context = {};
  }

  public withContext(context: Record<string, any>): Logger {
    const newLogger = new Logger(this.config);
    newLogger.setContext({ ...this.context, ...context });
    return newLogger;
  }

  // ==================== LOGGING METHODS ====================

  public error(message: string, metadata?: Record<string, any>, error?: Error): void {
    this.log('error', message, metadata, error);
  }

  public warn(message: string, metadata?: Record<string, any>): void {
    this.log('warn', message, metadata);
  }

  public info(message: string, metadata?: Record<string, any>): void {
    this.log('info', message, metadata);
  }

  public debug(message: string, metadata?: Record<string, any>): void {
    this.log('debug', message, metadata);
  }

  public trace(message: string, metadata?: Record<string, any>): void {
    this.log('trace', message, metadata);
  }

  private log(
    level: LogLevel,
    message: string,
    metadata?: Record<string, any>,
    error?: Error
  ): void {
    if (!LogLevelManager.shouldLog(this.config.level, level)) {
      return;
    }

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      ...this.context,
      ...this.config.metadata,
      ...metadata,
    };

    if (error) {
      entry.error = {
        name: error.name,
        message: error.message,
        stack: error.stack,
        code: (error as any).code,
      };
    }

    for (const transport of this.transports) {
      transport.log(entry);
    }
  }

  // ==================== PERFORMANCE LOGGING ====================

  public startTimer(label?: string): () => PerformanceMetrics {
    const startTime = Date.now();
    const memoryBefore = process.memoryUsage();
    const cpuBefore = process.cpuUsage();

    return (): PerformanceMetrics => {
      const endTime = Date.now();
      const memoryAfter = process.memoryUsage();
      const cpuAfter = process.cpuUsage(cpuBefore);

      const metrics: PerformanceMetrics = {
        startTime,
        endTime,
        duration: endTime - startTime,
        memoryBefore,
        memoryAfter,
        cpuBefore,
        cpuAfter,
      };

      if (label) {
        this.debug(`Performance: ${label}`, {
          performance: {
            duration: metrics.duration,
            memoryUsage: metrics.memoryAfter,
            cpuUsage: metrics.cpuAfter,
          },
        });
      }

      return metrics;
    };
  }

  public async logAsync<T>(
    operation: () => Promise<T>,
    label: string,
    metadata?: Record<string, any>
  ): Promise<T> {
    const endTimer = this.startTimer(label);
    
    try {
      const result = await operation();
      const metrics = endTimer();
      
      this.info(`Operation completed: ${label}`, {
        ...metadata,
        performance: {
          duration: metrics.duration,
          memoryUsage: metrics.memoryAfter,
        },
      });
      
      return result;
    } catch (error) {
      const metrics = endTimer();
      
      this.error(`Operation failed: ${label}`, {
        ...metadata,
        performance: {
          duration: metrics.duration,
          memoryUsage: metrics.memoryAfter,
        },
      }, error as Error);
      
      throw error;
    }
  }

  // ==================== EXPRESS MIDDLEWARE ====================

  public expressMiddleware() {
    return (req: any, res: any, next: any) => {
      const correlationId = req.headers[this.config.correlationIdHeader!] || 
        this.generateCorrelationId();
      const userId = req.headers[this.config.userIdHeader!];

      const logger = this.withContext({
        correlationId,
        userId,
        requestId: req.id || correlationId,
        path: req.path,
        method: req.method,
        userAgent: req.headers['user-agent'],
        ip: req.ip,
      });

      req.logger = logger;
      res.locals.logger = logger;

      const start = Date.now();
      
      res.on('finish', () => {
        const duration = Date.now() - start;
        logger.info('HTTP Request', {
          statusCode: res.statusCode,
          duration,
          contentLength: res.get('content-length'),
        });
      });

      next();
    };
  }

  private generateCorrelationId(): string {
    return `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// ==================== LOGGER FACTORY ====================

export class LoggerFactory {
  private static loggers: Map<string, Logger> = new Map();

  public static createLogger(
    name: string,
    config?: Partial<LoggerConfig>
  ): Logger {
    if (this.loggers.has(name)) {
      return this.loggers.get(name)!;
    }

    const logger = new Logger({
      ...config,
      metadata: {
        ...config?.metadata,
        service: name,
      },
    });

    this.loggers.set(name, logger);
    return logger;
  }

  public static getLogger(name: string): Logger | undefined {
    return this.loggers.get(name);
  }

  public static createDefaultLogger(): Logger {
    return new Logger();
  }

  public static createTestLogger(): Logger {
    return new Logger({
      level: 'debug',
      transports: [
        { type: 'console', enabled: true, format: 'simple' },
      ],
    });
  }
}

// ==================== LOGGING DECORATORS ====================

/**
 * Decorator for automatic method logging
 */
export function LogMethod(
  level: LogLevel = 'debug',
  includeArgs: boolean = false,
  includeResult: boolean = false
) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const logger = (this as any).logger || LoggerFactory.createDefaultLogger();
      const className = target.constructor.name;
      const methodName = propertyKey;

      const metadata: Record<string, any> = {
        class: className,
        method: methodName,
      };

      if (includeArgs) {
        metadata.args = args.map(arg => 
          typeof arg === 'object' ? JSON.stringify(arg) : arg
        );
      }

      logger[level](`Calling ${className}.${methodName}`, metadata);

      try {
        const result = await originalMethod.apply(this, args);
        
        if (includeResult) {
          logger[level](`Completed ${className}.${methodName}`, {
            ...metadata,
            result: typeof result === 'object' ? JSON.stringify(result) : result,
          });
        } else {
          logger[level](`Completed ${className}.${methodName}`, metadata);
        }

        return result;
      } catch (error) {
        logger.error(`Failed ${className}.${methodName}`, metadata, error as Error);
        throw error;
      }
    };

    return descriptor;
  };
}

/**
 * Decorator for performance logging
 */
export function LogPerformance(label?: string) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const logger = (this as any).logger || LoggerFactory.createDefaultLogger();
      const className = target.constructor.name;
      const methodName = propertyKey;
      const operationLabel = label || `${className}.${methodName}`;

      const endTimer = logger.startTimer(operationLabel);

      try {
        const result = await originalMethod.apply(this, args);
        const metrics = endTimer();

        logger.debug(`Performance: ${operationLabel}`, {
          class: className,
          method: methodName,
          performance: {
            duration: metrics.duration,
            memoryUsage: metrics.memoryAfter,
          },
        });

        return result;
      } catch (error) {
        const metrics = endTimer();

        logger.error(`Performance failed: ${operationLabel}`, {
          class: className,
          method: methodName,
          performance: {
            duration: metrics.duration,
            memoryUsage: metrics.memoryAfter,
          },
        }, error as Error);

        throw error;
      }
    };

    return descriptor;
  };
}

// ==================== USAGE EXAMPLES ====================

/**
 * Example service using logging
 */
export class UserService {
  private logger: Logger;

  constructor() {
    this.logger = LoggerFactory.createLogger('UserService');
  }

  @LogMethod('info', false, true)
  @LogPerformance('user_creation')
  public async createUser(userData: any): Promise<any> {
    this.logger.info('Creating new user', { email: userData.email });

    try {
      // Simulate user creation
      const user = { id: '123', ...userData, createdAt: new Date().toISOString() };
      
      this.logger.info('User created successfully', { userId: user.id });
      return user;
    } catch (error) {
      this.logger.error('Failed to create user', { email: userData.email }, error as Error);
      throw error;
    }
  }

  public async getUserWithLogging(userId: string): Promise<any> {
    return this.logger.logAsync(
      async () => {
        // Simulate database lookup
        if (userId === '123') {
          return { id: '123', email: 'user@example.com' };
        }
        throw new Error('User not found');
      },
      'user_lookup',
      { userId }
    );
  }
}

/**
 * Example Express app using logging middleware
 */
import express from 'express';

export class App {
  private app: express.Application;
  private logger: Logger;

  constructor() {
    this.app = express();
    this.logger = LoggerFactory.createLogger('ExpressApp');
    
    // Add logging middleware
    this.app.use(this.logger.expressMiddleware());
    
    this.setupRoutes();
  }

  private setupRoutes(): void {
    this.app.get('/health', (req: any, res) => {
      req.logger.info('Health check requested');
      res.json({ status: 'ok', timestamp: new Date().toISOString() });
    });

    this.app.post('/users', async (req: any, res) => {
      try {
        const userService = new UserService();
        const user = await userService.createUser(req.body);
        res.status(201).json(user);
      } catch (error) {
        req.logger.error('Failed to create user', { body: req.body }, error as Error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  }

  public start(port: number): void {
    this.app.listen(port, () => {
      this.logger.info('Server started', { port });
    });
  }
}

// ==================== EXPORTS ====================

export default Logger;

// Type exports
export type {
  LogEntry,
  LogLevel,
  LoggerConfig,
  TransportConfig,
  PerformanceMetrics,
};

// Class exports
export {
  LogLevelManager,
  LoggerFactory,
  ConsoleTransport,
  FileTransport,
  HttpTransport,
};

// Decorator exports
export {
  LogMethod,
  LogPerformance,
};

// ==================== BEST PRACTICES ====================

/*
1. **Structured Logging**: Use structured logging with consistent metadata
2. **Log Levels**: Use appropriate log levels for different types of messages
3. **Context**: Include correlation IDs and user context in all logs
4. **Performance**: Log performance metrics for critical operations
5. **Error Logging**: Always include error details and stack traces
6. **Transport Configuration**: Configure multiple transports for different environments
7. **Express Integration**: Use middleware for automatic request logging
8. **Decorators**: Use decorators for automatic method and performance logging
9. **Configuration**: Make logging configuration flexible and environment-specific
10. **Security**: Avoid logging sensitive information like passwords or tokens
*/
