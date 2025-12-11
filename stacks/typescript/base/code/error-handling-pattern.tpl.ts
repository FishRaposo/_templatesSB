/**
 * Template: error-handling-pattern.tpl.ts
 * Purpose: error-handling-pattern template
 * Stack: typescript
 * Tier: base
 */

# Universal Template System - Typescript Stack
# Generated: 2025-12-10
# Purpose: Error handling utilities
# Tier: base
# Stack: typescript
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: error-handling-pattern.tpl.ts
// PURPOSE: TypeScript error handling pattern with custom error classes and middleware
// USAGE: Import and adapt for error handling in TypeScript applications
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

// TypeScript Error Handling Pattern
// Author: [[.Author]]
// Version: [[.Version]]
// Date: [[.Date]]

/**
 * Error Handling Pattern for TypeScript Applications
 * 
 * This pattern provides comprehensive error handling with custom error classes,
 * error middleware, logging, and structured error responses.
 */

// ==================== ERROR INTERFACES ====================

export interface ErrorDetails {
  field?: string;
  message: string;
  code?: string;
  timestamp: string;
  path?: string;
  method?: string;
  userId?: string;
  requestId?: string;
}

export interface ValidationError extends ErrorDetails {
  field: string;
  value?: any;
}

export interface ApiErrorResponse {
  success: false;
  error: {
    type: string;
    message: string;
    code?: string;
    details?: ErrorDetails | ValidationError[];
    timestamp: string;
    requestId?: string;
  };
  stack?: string; // Only in development
}

export interface ErrorContext {
  requestId?: string;
  userId?: string;
  path?: string;
  method?: string;
  userAgent?: string;
  ip?: string;
  timestamp: string;
}

// ==================== CUSTOM ERROR CLASSES ====================

export abstract class BaseError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly isOperational: boolean;
  public readonly context?: ErrorContext;

  constructor(
    message: string,
    statusCode: number = 500,
    code: string = 'INTERNAL_ERROR',
    isOperational: boolean = true,
    context?: ErrorContext
  ) {
    super(message);
    
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    this.context = context;

    // Maintains proper stack trace for where our error was thrown
    Error.captureStackTrace(this, this.constructor);
  }

  public toJSON(): ApiErrorResponse {
    return {
      success: false,
      error: {
        type: this.name,
        message: this.message,
        code: this.code,
        timestamp: new Date().toISOString(),
        requestId: this.context?.requestId,
      },
      ...(process.env.NODE_ENV === 'development' && { stack: this.stack }),
    };
  }
}

export class ValidationError extends BaseError {
  public readonly details: ValidationError[];

  constructor(
    message: string,
    details: ValidationError[],
    context?: ErrorContext
  ) {
    super(message, 400, 'VALIDATION_ERROR', true, context);
    this.details = details;
  }

  public toJSON(): ApiErrorResponse {
    return {
      success: false,
      error: {
        type: this.name,
        message: this.message,
        code: this.code,
        details: this.details,
        timestamp: new Date().toISOString(),
        requestId: this.context?.requestId,
      },
      ...(process.env.NODE_ENV === 'development' && { stack: this.stack }),
    };
  }
}

export class AuthenticationError extends BaseError {
  constructor(message: string = 'Authentication failed', context?: ErrorContext) {
    super(message, 401, 'AUTHENTICATION_ERROR', true, context);
  }
}

export class AuthorizationError extends BaseError {
  constructor(message: string = 'Access denied', context?: ErrorContext) {
    super(message, 403, 'AUTHORIZATION_ERROR', true, context);
  }
}

export class NotFoundError extends BaseError {
  constructor(resource: string = 'Resource', context?: ErrorContext) {
    super(`${resource} not found`, 404, 'NOT_FOUND_ERROR', true, context);
  }
}

export class ConflictError extends BaseError {
  constructor(message: string, context?: ErrorContext) {
    super(message, 409, 'CONFLICT_ERROR', true, context);
  }
}

export class RateLimitError extends BaseError {
  constructor(message: string = 'Rate limit exceeded', context?: ErrorContext) {
    super(message, 429, 'RATE_LIMIT_ERROR', true, context);
  }
}

export class DatabaseError extends BaseError {
  constructor(message: string, context?: ErrorContext) {
    super(message, 500, 'DATABASE_ERROR', true, context);
  }
}

export class ExternalServiceError extends BaseError {
  constructor(service: string, message: string, context?: ErrorContext) {
    super(`${service} error: ${message}`, 502, 'EXTERNAL_SERVICE_ERROR', true, context);
  }
}

export class InternalServerError extends BaseError {
  constructor(message: string = 'Internal server error', context?: ErrorContext) {
    super(message, 500, 'INTERNAL_SERVER_ERROR', true, context);
  }
}

// ==================== ERROR FACTORY ====================

export class ErrorFactory {
  public static createValidationError(
    field: string,
    message: string,
    value?: any,
    context?: ErrorContext
  ): ValidationError {
    return new ValidationError('Validation failed', [{
      field,
      message,
      value,
      timestamp: new Date().toISOString(),
    }], context);
  }

  public static createMultipleValidationErrors(
    errors: ValidationError[],
    context?: ErrorContext
  ): ValidationError {
    return new ValidationError('Multiple validation errors failed', errors, context);
  }

  public static createAuthenticationError(
    message?: string,
    context?: ErrorContext
  ): AuthenticationError {
    return new AuthenticationError(message, context);
  }

  public static createAuthorizationError(
    message?: string,
    context?: ErrorContext
  ): AuthorizationError {
    return new AuthorizationError(message, context);
  }

  public static createNotFoundError(
    resource: string,
    context?: ErrorContext
  ): NotFoundError {
    return new NotFoundError(resource, context);
  }

  public static createConflictError(
    message: string,
    context?: ErrorContext
  ): ConflictError {
    return new ConflictError(message, context);
  }

  public static createRateLimitError(
    message?: string,
    context?: ErrorContext
  ): RateLimitError {
    return new RateLimitError(message, context);
  }

  public static createDatabaseError(
    message: string,
    context?: ErrorContext
  ): DatabaseError {
    return new DatabaseError(message, context);
  }

  public static createExternalServiceError(
    service: string,
    message: string,
    context?: ErrorContext
  ): ExternalServiceError {
    return new ExternalServiceError(service, message, context);
  }

  public static createInternalServerError(
    message?: string,
    context?: ErrorContext
  ): InternalServerError {
    return new InternalServerError(message, context);
  }
}

// ==================== ERROR MIDDLEWARE ====================

import { Request, Response, NextFunction } from 'express';

export interface ExpressRequest extends Request {
  context?: ErrorContext;
}

export const errorHandler = (
  error: Error,
  req: ExpressRequest,
  res: Response,
  next: NextFunction
): void => {
  // Add request context to error if not present
  if (error instanceof BaseError && !error.context) {
    error.context = {
      requestId: req.headers['x-request-id'] as string,
      path: req.path,
      method: req.method,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
      timestamp: new Date().toISOString(),
    };
  }

  // Handle different error types
  if (error instanceof BaseError) {
    res.status(error.statusCode).json(error.toJSON());
  } else {
    // Handle unexpected errors
    const internalError = new InternalServerError(
      error.message || 'An unexpected error occurred',
      {
        requestId: req.headers['x-request-id'] as string,
        path: req.path,
        method: req.method,
        timestamp: new Date().toISOString(),
      }
    );
    res.status(500).json(internalError.toJSON());
  }
};

export const asyncErrorHandler = (
  fn: (req: ExpressRequest, res: Response, next: NextFunction) => Promise<any>
) => {
  return (req: ExpressRequest, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// ==================== ERROR LOGGER ====================

import winston from 'winston';

export class ErrorLogger {
  private logger: winston.Logger;

  constructor() {
    this.logger = winston.createLogger({
      level: 'error',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({ filename: 'logs/error.log' }),
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          ),
        }),
      ],
    });
  }

  public logError(error: Error, context?: ErrorContext): void {
    const logData = {
      message: error.message,
      stack: error.stack,
      name: error.name,
      context,
      timestamp: new Date().toISOString(),
    };

    if (error instanceof BaseError) {
      this.logger.error('Operational error', {
        ...logData,
        statusCode: error.statusCode,
        code: error.code,
        isOperational: error.isOperational,
      });
    } else {
      this.logger.error('Unexpected error', logData);
    }
  }

  public logValidationError(error: ValidationError): void {
    this.logger.error('Validation error', {
      message: error.message,
      details: error.details,
      context: error.context,
      timestamp: new Date().toISOString(),
    });
  }
}

// ==================== ERROR DECORATORS ====================

/**
 * Decorator for automatic error handling in async methods
 */
export function HandleErrors(defaultError?: BaseError) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      try {
        return await originalMethod.apply(this, args);
      } catch (error) {
        if (error instanceof BaseError) {
          throw error;
        }
        
        if (defaultError) {
          throw defaultError;
        }
        
        throw new InternalServerError(
          error instanceof Error ? error.message : 'Unknown error occurred'
        );
      }
    };

    return descriptor;
  };
}

/**
 * Decorator for adding context to errors
 */
export function AddErrorContext(contextProvider: () => ErrorContext) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      try {
        return await originalMethod.apply(this, args);
      } catch (error) {
        if (error instanceof BaseError && !error.context) {
          error.context = contextProvider();
        }
        throw error;
      }
    };

    return descriptor;
  };
}

// ==================== ERROR UTILITIES ====================

export class ErrorUtils {
  public static isOperationalError(error: Error): boolean {
    return error instanceof BaseError && error.isOperational;
  }

  public static getErrorCode(error: Error): string {
    return error instanceof BaseError ? error.code : 'UNKNOWN_ERROR';
  }

  public static getErrorStatusCode(error: Error): number {
    return error instanceof BaseError ? error.statusCode : 500;
  }

  public static sanitizeError(error: Error, includeStack: boolean = false): ApiErrorResponse {
    if (error instanceof BaseError) {
      const response = error.toJSON();
      if (!includeStack) {
        delete response.stack;
      }
      return response;
    }

    return {
      success: false,
      error: {
        type: error.name,
        message: error.message,
        timestamp: new Date().toISOString(),
      },
      ...(includeStack && { stack: error.stack }),
    };
  }

  public static formatValidationError(
    field: string,
    message: string,
    value?: any
  ): ValidationError {
    return {
      field,
      message,
      value,
      timestamp: new Date().toISOString(),
    };
  }
}

// ==================== USAGE EXAMPLES ====================

/**
 * Example service using error handling
 */
export class UserService {
  private errorLogger = new ErrorLogger();

  @HandleErrors()
  @AddErrorContext(() => ({
    requestId: 'req-123',
    userId: 'user-456',
    path: '/api/users',
    method: 'POST',
    timestamp: new Date().toISOString(),
  }))
  public async createUser(userData: any): Promise<any> {
    // Validation example
    if (!userData.email) {
      throw ErrorFactory.createValidationError(
        'email',
        'Email is required',
        userData.email
      );
    }

    if (!userData.password || userData.password.length < 8) {
      throw ErrorFactory.createValidationError(
        'password',
        'Password must be at least 8 characters long',
        userData.password
      );
    }

    // Database operation example
    try {
      // Simulate database operation
      const user = await this.saveUserToDatabase(userData);
      return user;
    } catch (dbError) {
      this.errorLogger.logError(dbError as Error);
      throw ErrorFactory.createDatabaseError('Failed to create user');
    }
  }

  private async saveUserToDatabase(userData: any): Promise<any> {
    // Simulate database save
    return { id: '123', ...userData };
  }
}

/**
 * Example controller using error handling middleware
 */
export class UserController {
  private userService = new UserService();

  public createUser = asyncErrorHandler(
    async (req: ExpressRequest, res: Response): Promise<void> => {
      const user = await this.userService.createUser(req.body);
      res.status(201).json({ success: true, data: user });
    }
  );

  public getUser = asyncErrorHandler(
    async (req: ExpressRequest, res: Response): Promise<void> => {
      const userId = req.params.id;
      
      if (!userId) {
        throw ErrorFactory.createValidationError(
          'id',
          'User ID is required'
        );
      }

      // Simulate user lookup
      const user = await this.findUserById(userId);
      if (!user) {
        throw ErrorFactory.createNotFoundError('User');
      }

      res.json({ success: true, data: user });
    }
  );

  private async findUserById(id: string): Promise<any> {
    // Simulate database lookup
    if (id === '123') {
      return { id: '123', email: 'user@example.com' };
    }
    return null;
  }
}

// ==================== EXPORTS ====================

export default {
  BaseError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  DatabaseError,
  ExternalServiceError,
  InternalServerError,
  ErrorFactory,
  ErrorLogger,
  ErrorUtils,
  errorHandler,
  asyncErrorHandler,
  HandleErrors,
  AddErrorContext,
};

// Type exports
export type {
  ErrorDetails,
  ValidationError as ValidationErrorType,
  ApiErrorResponse,
  ErrorContext,
  ExpressRequest,
};

// ==================== BEST PRACTICES ====================

/*
1. **Custom Error Classes**: Create specific error types for different scenarios
2. **Error Context**: Always include context information for debugging
3. **Operational vs Programming Errors**: Distinguish between expected and unexpected errors
4. **Error Logging**: Log all errors with sufficient context for debugging
5. **Sanitization**: Sanitize error responses for production environments
6. **Error Middleware**: Use Express middleware for centralized error handling
7. **Async Error Handling**: Use decorators or wrappers for async function error handling
8. **Validation Errors**: Provide detailed validation error information
9. **Status Codes**: Use appropriate HTTP status codes for different error types
10. **Error Recovery**: Implement error recovery strategies where appropriate
*/
