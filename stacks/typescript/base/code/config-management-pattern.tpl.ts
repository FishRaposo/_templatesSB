/**
 * Template: config-management-pattern.tpl.ts
 * Purpose: config-management-pattern template
 * Stack: typescript
 * Tier: base
 */

# Universal Template System - Typescript Stack
# Generated: 2025-12-10
# Purpose: Configuration management utilities
# Tier: base
# Stack: typescript
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: config-management-pattern.tpl.ts
// PURPOSE: TypeScript configuration management pattern with type-safe environment variables
// USAGE: Import and adapt for configuration management in TypeScript applications
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

// TypeScript Configuration Management Pattern
// Author: [[.Author]]
// Version: [[.Version]]
// Date: [[.Date]]

/**
 * Configuration Management Pattern for TypeScript Applications
 * 
 * This pattern provides type-safe configuration management with environment variable support,
 * validation, and hierarchical configuration loading.
 */

// ==================== CONFIGURATION INTERFACES ====================

export interface DatabaseConfig {
  host: string;
  port: number;
  name: string;
  username: string;
  password: string;
  ssl: boolean;
  maxConnections: number;
  timeout: number;
}

export interface ServerConfig {
  port: number;
  host: string;
  cors: {
    enabled: boolean;
    origins: string[];
    credentials: boolean;
  };
  helmet: {
    enabled: boolean;
    contentSecurityPolicy: boolean;
  };
  rateLimit: {
    enabled: boolean;
    windowMs: number;
    max: number;
  };
}

export interface LoggingConfig {
  level: 'error' | 'warn' | 'info' | 'debug';
  format: 'json' | 'simple';
  file: {
    enabled: boolean;
    path: string;
    maxSize: string;
    maxFiles: number;
  };
  console: {
    enabled: boolean;
    colorize: boolean;
  };
}

export interface AuthConfig {
  jwt: {
    secret: string;
    expiresIn: string;
    issuer: string;
    audience: string;
  };
  bcrypt: {
    saltRounds: number;
  };
  refresh: {
    secret: string;
    expiresIn: string;
  };
}

export interface AppConfig {
  environment: 'development' | 'staging' | 'production' | 'test';
  debug: boolean;
  database: DatabaseConfig;
  server: ServerConfig;
  logging: LoggingConfig;
  auth: AuthConfig;
}

// ==================== CONFIGURATION VALIDATION ====================

import Joi from 'joi';

export const databaseConfigSchema = Joi.object({
  host: Joi.string().required(),
  port: Joi.number().port().required(),
  name: Joi.string().required(),
  username: Joi.string().required(),
  password: Joi.string().required(),
  ssl: Joi.boolean().default(false),
  maxConnections: Joi.number().min(1).max(100).default(10),
  timeout: Joi.number().min(1000).default(30000),
});

export const serverConfigSchema = Joi.object({
  port: Joi.number().port().required(),
  host: Joi.string().default('localhost'),
  cors: Joi.object({
    enabled: Joi.boolean().default(true),
    origins: Joi.array().items(Joi.string()).default(['*']),
    credentials: Joi.boolean().default(false),
  }),
  helmet: Joi.object({
    enabled: Joi.boolean().default(true),
    contentSecurityPolicy: Joi.boolean().default(true),
  }),
  rateLimit: Joi.object({
    enabled: Joi.boolean().default(false),
    windowMs: Joi.number().default(900000),
    max: Joi.number().default(100),
  }),
});

export const loggingConfigSchema = Joi.object({
  level: Joi.string().valid('error', 'warn', 'info', 'debug').default('info'),
  format: Joi.string().valid('json', 'simple').default('json'),
  file: Joi.object({
    enabled: Joi.boolean().default(true),
    path: Joi.string().default('./logs/app.log'),
    maxSize: Joi.string().default('10m'),
    maxFiles: Joi.number().min(1).default(5),
  }),
  console: Joi.object({
    enabled: Joi.boolean().default(true),
    colorize: Joi.boolean().default(true),
  }),
});

export const authConfigSchema = Joi.object({
  jwt: Joi.object({
    secret: Joi.string().min(32).required(),
    expiresIn: Joi.string().default('1h'),
    issuer: Joi.string().default('typescript-app'),
    audience: Joi.string().default('typescript-users'),
  }),
  bcrypt: Joi.object({
    saltRounds: Joi.number().min(8).max(15).default(12),
  }),
  refresh: Joi.object({
    secret: Joi.string().min(32).required(),
    expiresIn: Joi.string().default('7d'),
  }),
});

export const appConfigSchema = Joi.object({
  environment: Joi.string().valid('development', 'staging', 'production', 'test').required(),
  debug: Joi.boolean().default(false),
  database: databaseConfigSchema.required(),
  server: serverConfigSchema.required(),
  logging: loggingConfigSchema.required(),
  auth: authConfigSchema.required(),
});

// ==================== CONFIGURATION MANAGER ====================

import dotenv from 'dotenv';
import path from 'path';

export class ConfigManager {
  private static instance: ConfigManager;
  private config: AppConfig;

  private constructor() {
    this.loadConfiguration();
  }

  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  private loadConfiguration(): void {
    // Load environment variables
    this.loadEnvironmentFiles();
    
    // Build configuration object
    const rawConfig = this.buildRawConfig();
    
    // Validate configuration
    const { error, value } = appConfigSchema.validate(rawConfig, {
      abortEarly: false,
      allowUnknown: false,
      stripUnknown: true,
    });

    if (error) {
      throw new Error(`Configuration validation failed: ${error.message}`);
    }

    this.config = value;
  }

  private loadEnvironmentFiles(): void {
    const env = process.env.NODE_ENV || 'development';
    
    // Load base .env file
    dotenv.config();
    
    // Load environment-specific file
    const envFile = `.env.${env}`;
    dotenv.config({ path: path.resolve(process.cwd(), envFile) });
    
    // Load local overrides (for development)
    if (env === 'development') {
      dotenv.config({ path: path.resolve(process.cwd(), '.env.local') });
    }
  }

  private buildRawConfig(): AppConfig {
    return {
      environment: (process.env.NODE_ENV as AppConfig['environment']) || 'development',
      debug: process.env.DEBUG === 'true',
      
      database: {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '5432', 10),
        name: process.env.DB_NAME || 'typescript_app',
        username: process.env.DB_USERNAME || 'postgres',
        password: process.env.DB_PASSWORD || '',
        ssl: process.env.DB_SSL === 'true',
        maxConnections: parseInt(process.env.DB_MAX_CONNECTIONS || '10', 10),
        timeout: parseInt(process.env.DB_TIMEOUT || '30000', 10),
      },
      
      server: {
        port: parseInt(process.env.SERVER_PORT || '3000', 10),
        host: process.env.SERVER_HOST || 'localhost',
        cors: {
          enabled: process.env.CORS_ENABLED !== 'false',
          origins: process.env.CORS_ORIGINS?.split(',') || ['*'],
          credentials: process.env.CORS_CREDENTIALS === 'true',
        },
        helmet: {
          enabled: process.env.HELMET_ENABLED !== 'false',
          contentSecurityPolicy: process.env.CSP_ENABLED !== 'false',
        },
        rateLimit: {
          enabled: process.env.RATE_LIMIT_ENABLED === 'true',
          windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '900000', 10),
          max: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
        },
      },
      
      logging: {
        level: (process.env.LOG_LEVEL as LoggingConfig['level']) || 'info',
        format: (process.env.LOG_FORMAT as LoggingConfig['format']) || 'json',
        file: {
          enabled: process.env.LOG_FILE_ENABLED !== 'false',
          path: process.env.LOG_FILE_PATH || './logs/app.log',
          maxSize: process.env.LOG_FILE_MAX_SIZE || '10m',
          maxFiles: parseInt(process.env.LOG_FILE_MAX_FILES || '5', 10),
        },
        console: {
          enabled: process.env.LOG_CONSOLE_ENABLED !== 'false',
          colorize: process.env.LOG_CONSOLE_COLORIZE !== 'false',
        },
      },
      
      auth: {
        jwt: {
          secret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
          expiresIn: process.env.JWT_EXPIRES_IN || '1h',
          issuer: process.env.JWT_ISSUER || 'typescript-app',
          audience: process.env.JWT_AUDIENCE || 'typescript-users',
        },
        bcrypt: {
          saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10),
        },
        refresh: {
          secret: process.env.REFRESH_SECRET || 'your-super-secret-refresh-key-change-in-production',
          expiresIn: process.env.REFRESH_EXPIRES_IN || '7d',
        },
      },
    };
  }

  public getConfig(): AppConfig {
    return this.config;
  }

  public getDatabaseConfig(): DatabaseConfig {
    return this.config.database;
  }

  public getServerConfig(): ServerConfig {
    return this.config.server;
  }

  public getLoggingConfig(): LoggingConfig {
    return this.config.logging;
  }

  public getAuthConfig(): AuthConfig {
    return this.config.auth;
  }

  public isDevelopment(): boolean {
    return this.config.environment === 'development';
  }

  public isProduction(): boolean {
    return this.config.environment === 'production';
  }

  public isTest(): boolean {
    return this.config.environment === 'test';
  }

  public reload(): void {
    this.loadConfiguration();
  }
}

// ==================== CONFIGURATION FACTORY ====================

export class ConfigFactory {
  public static createConfig(): AppConfig {
    return ConfigManager.getInstance().getConfig();
  }

  public static createDatabaseConfig(): DatabaseConfig {
    return ConfigManager.getInstance().getDatabaseConfig();
  }

  public static createServerConfig(): ServerConfig {
    return ConfigManager.getInstance().getServerConfig();
  }

  public static createLoggingConfig(): LoggingConfig {
    return ConfigManager.getInstance().getLoggingConfig();
  }

  public static createAuthConfig(): AuthConfig {
    return ConfigManager.getInstance().getAuthConfig();
  }
}

// ==================== CONFIGURATION DECORATORS ====================

/**
 * Decorator for injecting configuration into classes
 */
export function InjectConfig(configKey?: keyof AppConfig) {
  return function (target: any, propertyKey: string | symbol | undefined, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = function (...args: any[]) {
      const config = ConfigManager.getInstance().getConfig();
      const configValue = configKey ? config[configKey] : config;
      
      return originalMethod.apply(this, [configValue, ...args]);
    };

    return descriptor;
  };
}

/**
 * Decorator for validating configuration at runtime
 */
export function ValidateConfig(schema: Joi.ObjectSchema) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = function (...args: any[]) {
      const config = args[0];
      const { error, value } = schema.validate(config);

      if (error) {
        throw new Error(`Configuration validation failed: ${error.message}`);
      }

      return originalMethod.apply(this, [value, ...args.slice(1)]);
    };

    return descriptor;
  };
}

// ==================== USAGE EXAMPLES ====================

/**
 * Example service using configuration management
 */
export class DatabaseService {
  private config: DatabaseConfig;

  constructor() {
    this.config = ConfigFactory.createDatabaseConfig();
  }

  @InjectConfig('database')
  @ValidateConfig(databaseConfigSchema)
  public connect(config: DatabaseConfig): void {
    console.log(`Connecting to database at ${config.host}:${config.port}`);
    // Database connection logic here
  }

  public getConnectionInfo(): string {
    return `Database: ${this.config.name} on ${this.config.host}:${this.config.port}`;
  }
}

/**
 * Example controller using configuration decorators
 */
export class AppController {
  @InjectConfig()
  public initializeApp(config: AppConfig): void {
    console.log(`Starting app in ${config.environment} mode`);
    console.log(`Debug mode: ${config.debug}`);
  }

  @InjectConfig('server')
  public getServerInfo(serverConfig: ServerConfig): string {
    return `Server running on ${serverConfig.host}:${serverConfig.port}`;
  }
}

// ==================== EXPORTS ====================

export default ConfigManager;

// Type exports for external use
export type {
  AppConfig,
  DatabaseConfig,
  ServerConfig,
  LoggingConfig,
  AuthConfig,
};

// Factory exports
export {
  ConfigFactory,
};

// Decorator exports
export {
  InjectConfig,
  ValidateConfig,
};

// ==================== BEST PRACTICES ====================

/*
1. **Environment Variables**: Always use environment variables for sensitive data
2. **Type Safety**: Leverage TypeScript's strict typing for configuration
3. **Validation**: Use Joi schema validation for all configuration
4. **Hierarchical Loading**: Load .env files in order of precedence
5. **Singleton Pattern**: Use singleton for configuration manager
6. **Dependency Injection**: Use decorators for clean configuration injection
7. **Environment-Specific**: Have separate configs for different environments
8. **Default Values**: Provide sensible defaults for all configuration options
9. **Documentation**: Document all configuration options and their defaults
10. **Security**: Never commit secrets to version control
*/
