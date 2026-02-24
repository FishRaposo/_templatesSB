/**
 * File: data-validation-pattern.tpl.ts
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

// -----------------------------------------------------------------------------
// FILE: data-validation-pattern.tpl.ts
// PURPOSE: TypeScript data validation pattern with schema definitions and custom validators
// USAGE: Import and adapt for data validation in TypeScript applications
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

// TypeScript Data Validation Pattern
// Author: [[.Author]]
// Version: [[.Version]]
// Date: [[.Date]]

/**
 * Data Validation Pattern for TypeScript Applications
 * 
 * This pattern provides comprehensive data validation with schema definitions,
 * custom validators, validation middleware, and error handling.
 */

// ==================== VALIDATION INTERFACES ====================

export interface ValidationRule {
  field: string;
  rules: ValidatorFunction[];
  required?: boolean;
  optional?: boolean;
  custom?: CustomValidator;
}

export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
  data?: any;
}

export interface ValidationError {
  field: string;
  message: string;
  code: string;
  value?: any;
  path?: string;
}

export interface ValidationSchema {
  [fieldName: string]: ValidationRule | ValidationSchema;
}

export interface ValidatorFunction {
  (value: any, context?: ValidationContext): boolean | string;
}

export interface CustomValidator {
  validate: (value: any, context?: ValidationContext) => boolean | string;
  message?: string;
}

export interface ValidationContext {
  field: string;
  data: any;
  schema: ValidationSchema;
  path: string[];
}

export interface ValidationOptions {
  strict?: boolean;
  abortEarly?: boolean;
  stripUnknown?: boolean;
  context?: ValidationContext;
}

// ==================== BUILT-IN VALIDATORS ====================

export class Validators {
  public static required(message: string = 'This field is required'): ValidatorFunction {
    return (value: any): boolean | string => {
      if (value === null || value === undefined || value === '') {
        return message;
      }
      return true;
    };
  }

  public static optional(): ValidatorFunction {
    return (value: any): boolean => {
      return value === null || value === undefined || value === '' || true;
    };
  }

  public static string(minLength?: number, maxLength?: number, message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (typeof value !== 'string') {
        return message || 'Value must be a string';
      }
      
      if (minLength !== undefined && value.length < minLength) {
        return message || `String must be at least ${minLength} characters long`;
      }
      
      if (maxLength !== undefined && value.length > maxLength) {
        return message || `String must be no more than ${maxLength} characters long`;
      }
      
      return true;
    };
  }

  public static number(min?: number, max?: number, message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (typeof value !== 'number' || isNaN(value)) {
        return message || 'Value must be a number';
      }
      
      if (min !== undefined && value < min) {
        return message || `Number must be at least ${min}`;
      }
      
      if (max !== undefined && value > max) {
        return message || `Number must be no more than ${max}`;
      }
      
      return true;
    };
  }

  public static integer(message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (typeof value !== 'number' || !Number.isInteger(value)) {
        return message || 'Value must be an integer';
      }
      return true;
    };
  }

  public static boolean(message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (typeof value !== 'boolean') {
        return message || 'Value must be a boolean';
      }
      return true;
    };
  }

  public static email(message?: string): ValidatorFunction {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return (value: any): boolean | string => {
      if (typeof value !== 'string' || !emailRegex.test(value)) {
        return message || 'Value must be a valid email address';
      }
      return true;
    };
  }

  public static url(message?: string): ValidatorFunction {
    try {
      const urlRegex = /^https?:\/\/.+/;
      return (value: any): boolean | string => {
        if (typeof value !== 'string' || !urlRegex.test(value)) {
          return message || 'Value must be a valid URL';
        }
        return true;
      };
    } catch {
      return (value: any): boolean | string => {
        return message || 'Value must be a valid URL';
      };
    }
  }

  public static uuid(message?: string): ValidatorFunction {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return (value: any): boolean | string => {
      if (typeof value !== 'string' || !uuidRegex.test(value)) {
        return message || 'Value must be a valid UUID';
      }
      return true;
    };
  }

  public static date(message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (!(value instanceof Date) && typeof value !== 'string') {
        return message || 'Value must be a date';
      }
      
      const date = typeof value === 'string' ? new Date(value) : value;
      if (isNaN(date.getTime())) {
        return message || 'Value must be a valid date';
      }
      
      return true;
    };
  }

  public static min(min: number, message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (typeof value !== 'number' || value < min) {
        return message || `Value must be at least ${min}`;
      }
      return true;
    };
  }

  public static max(max: number, message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (typeof value !== 'number' || value > max) {
        return message || `Value must be no more than ${max}`;
      }
      return true;
    };
  }

  public static minLength(min: number, message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (typeof value !== 'string' || value.length < min) {
        return message || `Value must be at least ${min} characters long`;
      }
      return true;
    };
  }

  public static maxLength(max: number, message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (typeof value !== 'string' || value.length > max) {
        return message || `Value must be no more than ${max} characters long`;
      }
      return true;
    };
  }

  public static pattern(regex: RegExp, message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (typeof value !== 'string' || !regex.test(value)) {
        return message || 'Value does not match the required pattern';
      }
      return true;
    };
  }

  public static oneOf(values: any[], message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (!values.includes(value)) {
        return message || `Value must be one of: ${values.join(', ')}`;
      }
      return true;
    };
  }

  public static array(itemValidator?: ValidatorFunction, message?: string): ValidatorFunction {
    return (value: any): boolean | string => {
      if (!Array.isArray(value)) {
        return message || 'Value must be an array';
      }
      
      if (itemValidator) {
        for (let i = 0; i < value.length; i++) {
          const result = itemValidator(value[i]);
          if (result !== true) {
            return typeof result === 'string' ? result : message || 'Array contains invalid items';
          }
        }
      }
      
      return true;
    };
  }

  public static object(schema: ValidationSchema, message?: string): ValidatorFunction {
    return (value: any, context?: ValidationContext): boolean | string => {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return message || 'Value must be an object';
      }
      
      const validator = new DataValidator();
      const result = validator.validate(value, schema);
      
      if (!result.isValid) {
        return message || 'Object contains invalid properties';
      }
      
      return true;
    };
  }
}

// ==================== DATA VALIDATOR CLASS ====================

export class DataValidator {
  private defaultOptions: ValidationOptions = {
    strict: false,
    abortEarly: false,
    stripUnknown: false,
  };

  public validate(data: any, schema: ValidationSchema, options: ValidationOptions = {}): ValidationResult {
    const mergedOptions = { ...this.defaultOptions, ...options };
    const errors: ValidationError[] = [];
    const validatedData: any = {};

    for (const [fieldName, fieldSchema] of Object.entries(schema)) {
      const fieldPath = [...(mergedOptions.context?.path || []), fieldName];
      const context: ValidationContext = {
        field: fieldName,
        data,
        schema,
        path: fieldPath,
        ...mergedOptions.context,
      };

      try {
        const fieldValue = data[fieldName];
        const result = this.validateField(fieldValue, fieldSchema as ValidationRule, context);

        if (result.isValid) {
          if (result.data !== undefined) {
            validatedData[fieldName] = result.data;
          }
        } else {
          errors.push(...result.errors);
          
          if (mergedOptions.abortEarly) {
            break;
          }
        }
      } catch (error) {
        errors.push({
          field: fieldName,
          message: 'Validation failed',
          code: 'VALIDATION_ERROR',
          path: fieldPath.join('.'),
        });
        
        if (mergedOptions.abortEarly) {
          break;
        }
      }
    }

    // Check for unknown fields
    if (mergedOptions.stripUnknown) {
      for (const key of Object.keys(data)) {
        if (!schema.hasOwnProperty(key)) {
          delete validatedData[key];
        }
      }
    } else if (mergedOptions.strict) {
      for (const key of Object.keys(data)) {
        if (!schema.hasOwnProperty(key)) {
          errors.push({
            field: key,
            message: 'Unknown field',
            code: 'UNKNOWN_FIELD',
            value: data[key],
            path: key,
          });
        }
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      data: errors.length === 0 ? validatedData : undefined,
    };
  }

  private validateField(value: any, rule: ValidationRule, context: ValidationContext): ValidationResult {
    const errors: ValidationError[] = [];
    let validatedValue = value;

    // Handle optional fields
    if (rule.optional && (value === null || value === undefined || value === '')) {
      return { isValid: true, errors: [] };
    }

    // Handle required fields
    if (rule.required && (value === null || value === undefined || value === '')) {
      errors.push({
        field: context.field,
        message: 'This field is required',
        code: 'REQUIRED_FIELD',
        value,
        path: context.path.join('.'),
      });
      return { isValid: false, errors };
    }

    // Skip validation if field is optional and empty
    if (!rule.required && (value === null || value === undefined || value === '')) {
      return { isValid: true, errors: [] };
    }

    // Run validation rules
    for (const validator of rule.rules) {
      const result = validator(value, context);
      
      if (result !== true) {
        errors.push({
          field: context.field,
          message: typeof result === 'string' ? result : 'Validation failed',
          code: 'VALIDATION_FAILED',
          value,
          path: context.path.join('.'),
        });
        
        break; // Stop on first error for this field
      }
    }

    // Run custom validator
    if (rule.custom && errors.length === 0) {
      const customResult = rule.custom.validate(value, context);
      
      if (customResult !== true) {
        errors.push({
          field: context.field,
          message: typeof customResult === 'string' ? customResult : rule.custom.message || 'Custom validation failed',
          code: 'CUSTOM_VALIDATION_FAILED',
          value,
          path: context.path.join('.'),
        });
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      data: errors.length === 0 ? validatedValue : undefined,
    };
  }

  public validateAsync(data: any, schema: ValidationSchema, options: ValidationOptions = {}): Promise<ValidationResult> {
    return new Promise((resolve) => {
      try {
        const result = this.validate(data, schema, options);
        resolve(result);
      } catch (error) {
        resolve({
          isValid: false,
          errors: [{
            field: 'unknown',
            message: 'Async validation failed',
            code: 'ASYNC_VALIDATION_ERROR',
          }],
        });
      }
    });
  }
}

// ==================== SCHEMA BUILDER ====================

export class SchemaBuilder {
  private schema: ValidationSchema = {};

  public string(fieldName: string, rules: ValidatorFunction[] = [], required: boolean = false): SchemaBuilder {
    this.schema[fieldName] = {
      field: fieldName,
      rules: [Validators.string(), ...rules],
      required,
    };
    return this;
  }

  public number(fieldName: string, rules: ValidatorFunction[] = [], required: boolean = false): SchemaBuilder {
    this.schema[fieldName] = {
      field: fieldName,
      rules: [Validators.number(), ...rules],
      required,
    };
    return this;
  }

  public boolean(fieldName: string, required: boolean = false): SchemaBuilder {
    this.schema[fieldName] = {
      field: fieldName,
      rules: [Validators.boolean()],
      required,
    };
    return this;
  }

  public email(fieldName: string, required: boolean = false): SchemaBuilder {
    this.schema[fieldName] = {
      field: fieldName,
      rules: [Validators.email()],
      required,
    };
    return this;
  }

  public array(fieldName: string, itemValidator?: ValidatorFunction, required: boolean = false): SchemaBuilder {
    this.schema[fieldName] = {
      field: fieldName,
      rules: [Validators.array(itemValidator)],
      required,
    };
    return this;
  }

  public object(fieldName: string, objectSchema: ValidationSchema, required: boolean = false): SchemaBuilder {
    this.schema[fieldName] = {
      field: fieldName,
      rules: [Validators.object(objectSchema)],
      required,
    };
    return this;
  }

  public optional(fieldName: string, rules: ValidatorFunction[] = []): SchemaBuilder {
    this.schema[fieldName] = {
      field: fieldName,
      rules: [Validators.optional(), ...rules],
      optional: true,
    };
    return this;
  }

  public custom(fieldName: string, validator: CustomValidator, required: boolean = false): SchemaBuilder {
    this.schema[fieldName] = {
      field: fieldName,
      rules: required ? [Validators.required()] : [],
      custom: validator,
      required,
    };
    return this;
  }

  public build(): ValidationSchema {
    return { ...this.schema };
  }

  public static create(): SchemaBuilder {
    return new SchemaBuilder();
  }
}

// ==================== VALIDATION MIDDLEWARE ====================

import { Request, Response, NextFunction } from 'express';

export class ValidationMiddleware {
  private validator: DataValidator;

  constructor(validator?: DataValidator) {
    this.validator = validator || new DataValidator();
  }

  public validateBody(schema: ValidationSchema, options: ValidationOptions = {}) {
    return (req: Request, res: Response, next: NextFunction) => {
      const result = this.validator.validate(req.body, schema, options);
      
      if (!result.isValid) {
        return res.status(400).json({
          success: false,
          error: 'Validation failed',
          code: 'VALIDATION_ERROR',
          details: result.errors,
        });
      }

      // Replace request body with validated data
      if (result.data !== undefined) {
        req.body = result.data;
      }

      next();
    };
  }

  public validateParams(schema: ValidationSchema, options: ValidationOptions = {}) {
    return (req: Request, res: Response, next: NextFunction) => {
      const result = this.validator.validate(req.params, schema, options);
      
      if (!result.isValid) {
        return res.status(400).json({
          success: false,
          error: 'Parameter validation failed',
          code: 'PARAM_VALIDATION_ERROR',
          details: result.errors,
        });
      }

      // Replace request params with validated data
      if (result.data !== undefined) {
        req.params = result.data;
      }

      next();
    };
  }

  public validateQuery(schema: ValidationSchema, options: ValidationOptions = {}) {
    return (req: Request, res: Response, next: NextFunction) => {
      const result = this.validator.validate(req.query, schema, options);
      
      if (!result.isValid) {
        return res.status(400).json({
          success: false,
          error: 'Query validation failed',
          code: 'QUERY_VALIDATION_ERROR',
          details: result.errors,
        });
      }

      // Replace request query with validated data
      if (result.data !== undefined) {
        req.query = result.data;
      }

      next();
    };
  }
}

// ==================== VALIDATION DECORATORS ====================

/**
 * Decorator for automatic method validation
 */
export function ValidateBody(schema: ValidationSchema, options: ValidationOptions = {}) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = function (...args: any[]) {
      const req = args.find(arg => arg && arg.body) as Request;
      
      if (req) {
        const validator = new DataValidator();
        const result = validator.validate(req.body, schema, options);
        
        if (!result.isValid) {
          throw new Error(`Validation failed: ${result.errors.map(e => e.message).join(', ')}`);
        }

        // Replace request body with validated data
        if (result.data !== undefined) {
          req.body = result.data;
        }
      }

      return originalMethod.apply(this, args);
    };

    return descriptor;
  };
}

/**
 * Decorator for validating method parameters
 */
export function ValidateParams(paramIndex: number, schema: ValidationSchema, options: ValidationOptions = {}) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = function (...args: any[]) {
      const validator = new DataValidator();
      const result = validator.validate(args[paramIndex], schema, options);
      
      if (!result.isValid) {
        throw new Error(`Parameter validation failed: ${result.errors.map(e => e.message).join(', ')}`);
      }

      // Replace parameter with validated data
      if (result.data !== undefined) {
        args[paramIndex] = result.data;
      }

      return originalMethod.apply(this, args);
    };

    return descriptor;
  };
}

// ==================== USAGE EXAMPLES ====================

/**
 * Example validation schemas
 */
export const UserValidationSchema = SchemaBuilder.create()
  .string('name', [Validators.required(), Validators.minLength(2), Validators.maxLength(50)], true)
  .email('email', true)
  .string('password', [Validators.required(), Validators.minLength(8)], true)
  .optional('bio', [Validators.maxLength(500)])
  .boolean('isActive')
  .build();

export const ProductValidationSchema = SchemaBuilder.create()
  .string('title', [Validators.required(), Validators.minLength(1), Validators.maxLength(100)], true)
  .string('description', [Validators.required(), Validators.minLength(10), Validators.maxLength(1000)], true)
  .number('price', [Validators.required(), Validators.min(0)], true)
  .array('categories', [Validators.string()], true)
  .boolean('inStock')
  .build();

/**
 * Example service using validation
 */
export class UserService {
  private validator: DataValidator;

  constructor() {
    this.validator = new DataValidator();
  }

  @ValidateBody(UserValidationSchema)
  public createUser(req: Request): any {
    const userData = req.body;
    
    // At this point, userData is already validated
    return {
      id: '123',
      ...userData,
      createdAt: new Date().toISOString(),
    };
  }

  public updateUser(@ValidateParams(0, UserValidationSchema) userData: any): any {
    // userData is validated
    return {
      ...userData,
      updatedAt: new Date().toISOString(),
    };
  }

  public validateCustomData(data: any): ValidationResult {
    const customSchema = SchemaBuilder.create()
      .string('company', [Validators.required()], true)
      .email('workEmail', true)
      .array('skills', [Validators.string()])
      .custom('age', {
        validate: (value: any) => {
          const age = parseInt(value, 10);
          return age >= 18 && age <= 100 || 'Age must be between 18 and 100';
        },
        message: 'Invalid age',
      }, true)
      .build();

    return this.validator.validate(data, customSchema);
  }
}

/**
 * Example Express controller using validation middleware
 */
export class UserController {
  private validationMiddleware: ValidationMiddleware;

  constructor() {
    this.validationMiddleware = new ValidationMiddleware();
  }

  public createUser = [
    this.validationMiddleware.validateBody(UserValidationSchema),
    (req: Request, res: Response) => {
      const user = {
        id: '123',
        ...req.body,
        createdAt: new Date().toISOString(),
      };
      
      res.status(201).json({
        success: true,
        data: user,
      });
    },
  ];

  public getUser = [
    this.validationMiddleware.validateParams({
      id: {
        field: 'id',
        rules: [Validators.required(), Validators.uuid()],
        required: true,
      },
    }),
    (req: Request, res: Response) => {
      const { id } = req.params;
      
      // Get user from database
      res.json({
        success: true,
        data: { id, email: 'user@example.com' },
      });
    },
  ];
}

// ==================== EXPORTS ====================

export default DataValidator;

// Type exports
export type {
  ValidationRule,
  ValidationResult,
  ValidationError,
  ValidationSchema,
  ValidatorFunction,
  CustomValidator,
  ValidationContext,
  ValidationOptions,
};

// Class exports
export {
  Validators,
  SchemaBuilder,
  ValidationMiddleware,
};

// Decorator exports
export {
  ValidateBody,
  ValidateParams,
};

// ==================== BEST PRACTICES ====================

/*
1. **Schema Definition**: Use SchemaBuilder for clean, readable schema definitions
2. **Validation Rules**: Combine built-in validators for comprehensive validation
3. **Custom Validators**: Create custom validators for business logic validation
4. **Error Messages**: Provide clear, user-friendly error messages
5. **Middleware**: Use validation middleware for Express route protection
6. **Decorators**: Use decorators for automatic method validation
7. **Async Validation**: Handle async validation scenarios properly
8. **Data Sanitization**: Strip unknown fields in strict mode
9. **Performance**: Use abortEarly for faster validation on large datasets
10. **Type Safety**: Leverage TypeScript for compile-time validation safety
*/
