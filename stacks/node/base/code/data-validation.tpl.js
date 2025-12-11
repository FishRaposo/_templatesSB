/**
 * Template: data-validation.tpl.js
 * Purpose: data-validation template
 * Stack: node
 * Tier: base
 */

# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: Data validation utilities
# Tier: base
# Stack: node
# Category: utilities

#!/usr/bin/env node
/**
 * Node.js Data Validation Template
 * Purpose: Reusable data validation utilities for Node.js projects
 * Usage: Import and adapt for consistent data validation across the application
 */

const { EventEmitter } = require('events');

/**
 * Validation types enumeration
 */
const ValidationType = {
    REQUIRED: 'required',
    STRING: 'string',
    INTEGER: 'integer',
    FLOAT: 'float',
    BOOLEAN: 'boolean',
    EMAIL: 'email',
    PHONE: 'phone',
    URL: 'url',
    DATE: 'date',
    DATETIME: 'datetime',
    JSON: 'json',
    REGEX: 'regex',
    MIN_LENGTH: 'min_length',
    MAX_LENGTH: 'max_length',
    MIN_VALUE: 'min_value',
    MAX_VALUE: 'max_value',
    IN_CHOICES: 'in_choices',
    CUSTOM: 'custom'
};

/**
 * Validation rule class
 */
class ValidationRule {
    constructor(type, options = {}) {
        this.type = type;
        this.params = options.params || {};
        this.message = options.message || null;
        this.required = options.required || false;
    }
}

/**
 * Validation result class
 */
class ValidationResult {
    constructor(field, value) {
        this.field = field;
        this.value = value;
        this.isValid = true;
        this.errors = [];
    }

    /**
     * Add error to validation result
     */
    addError(message) {
        this.errors.push(message);
        this.isValid = false;
    }

    /**
     * Get first error message
     */
    getFirstError() {
        return this.errors.length > 0 ? this.errors[0] : null;
    }

    /**
     * Convert to JSON
     */
    toJSON() {
        return {
            field: this.field,
            value: this.value,
            isValid: this.isValid,
            errors: this.errors
        };
    }
}

/**
 * Data validator class
 */
class DataValidator extends EventEmitter {
    constructor(options = {}) {
        super();
        this.options = {
            strictMode: options.strictMode || false,
            stopOnFirstError: options.stopOnFirstError || false,
            ...options
        };
        this.customValidators = new Map();
        this.globalValidators = new Map();
        this._setupGlobalValidators();
    }

    /**
     * Setup built-in global validators
     */
    _setupGlobalValidators() {
        // Email validator
        this.globalValidators.set('email', (value) => {
            const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            return emailRegex.test(value);
        });

        // Phone validator
        this.globalValidators.set('phone', (value) => {
            const cleanPhone = value.replace(/[\s\-\(\)]+/g, '');
            const phoneRegex = /^\+?[1-9]\d{9,14}$/;
            return phoneRegex.test(cleanPhone);
        });

        // URL validator
        this.globalValidators.set('url', (value) => {
            try {
                new URL(value);
                return true;
            } catch {
                return false;
            }
        });

        // Date validator
        this.globalValidators.set('date', (value) => {
            if (value instanceof Date) return true;
            const date = new Date(value);
            return !isNaN(date.getTime()) && value.match(/^\d{4}-\d{2}-\d{2}$/);
        });

        // DateTime validator
        this.globalValidators.set('datetime', (value) => {
            if (value instanceof Date) return true;
            const date = new Date(value);
            return !isNaN(date.getTime());
        });

        // JSON validator
        this.globalValidators.set('json', (value) => {
            if (typeof value === 'object') return true;
            try {
                JSON.parse(value);
                return true;
            } catch {
                return false;
            }
        });
    }

    /**
     * Add custom validator
     */
    addCustomValidator(name, validatorFunc, errorMessage = null) {
        this.customValidators.set(name, {
            func: validatorFunc,
            message: errorMessage || `Custom validation '${name}' failed`
        });
    }

    /**
     * Validate a single field
     */
    validateField(fieldName, value, rules) {
        const result = new ValidationResult(fieldName, value);

        for (const rule of rules) {
            const error = this._validateRule(fieldName, value, rule);
            if (error) {
                result.addError(error);
                this.emit('fieldError', { field: fieldName, value, rule, error });
                
                if (this.options.stopOnFirstError) {
                    break;
                }
            }
        }

        this.emit('fieldValidated', result);
        return result;
    }

    /**
     * Validate entire data object
     */
    validate(data, schema) {
        const results = {};
        let hasErrors = false;

        for (const [fieldName, rules] of Object.entries(schema)) {
            const value = data[fieldName];
            results[fieldName] = this.validateField(fieldName, value, rules);
            
            if (!results[fieldName].isValid) {
                hasErrors = true;
            }
        }

        const validationResult = {
            isValid: !hasErrors,
            results,
            errors: this._collectErrors(results)
        };

        this.emit('validationCompleted', validationResult);
        return validationResult;
    }

    /**
     * Validate a single rule
     */
    _validateRule(fieldName, value, rule) {
        const params = rule.params;

        try {
            switch (rule.type) {
                case ValidationType.REQUIRED:
                    if (value === null || value === undefined || value === '') {
                        return rule.message || `Field '${fieldName}' is required`;
                    }
                    break;

                case ValidationType.STRING:
                    if (value !== null && value !== undefined && typeof value !== 'string') {
                        return rule.message || `Field '${fieldName}' must be a string`;
                    }
                    break;

                case ValidationType.INTEGER:
                    if (value !== null && value !== undefined) {
                        if (typeof value !== 'number' || !Number.isInteger(value)) {
                            return rule.message || `Field '${fieldName}' must be an integer`;
                        }
                    }
                    break;

                case ValidationType.FLOAT:
                    if (value !== null && value !== undefined) {
                        const numValue = Number(value);
                        if (isNaN(numValue)) {
                            return rule.message || `Field '${fieldName}' must be a number`;
                        }
                    }
                    break;

                case ValidationType.BOOLEAN:
                    if (value !== null && value !== undefined && typeof value !== 'boolean') {
                        return rule.message || `Field '${fieldName}' must be a boolean`;
                    }
                    break;

                case ValidationType.EMAIL:
                    if (value && !this.globalValidators.get('email')(value)) {
                        return rule.message || `Field '${fieldName}' must be a valid email`;
                    }
                    break;

                case ValidationType.PHONE:
                    if (value && !this.globalValidators.get('phone')(value)) {
                        return rule.message || `Field '${fieldName}' must be a valid phone number`;
                    }
                    break;

                case ValidationType.URL:
                    if (value && !this.globalValidators.get('url')(value)) {
                        return rule.message || `Field '${fieldName}' must be a valid URL`;
                    }
                    break;

                case ValidationType.DATE:
                    if (value && !this.globalValidators.get('date')(value)) {
                        return rule.message || `Field '${fieldName}' must be a valid date (YYYY-MM-DD)`;
                    }
                    break;

                case ValidationType.DATETIME:
                    if (value && !this.globalValidators.get('datetime')(value)) {
                        return rule.message || `Field '${fieldName}' must be a valid datetime`;
                    }
                    break;

                case ValidationType.JSON:
                    if (value && !this.globalValidators.get('json')(value)) {
                        return rule.message || `Field '${fieldName}' must be valid JSON`;
                    }
                    break;

                case ValidationType.REGEX:
                    if (value && params.pattern) {
                        const regex = new RegExp(params.pattern);
                        if (!regex.test(String(value))) {
                            return rule.message || `Field '${fieldName}' does not match required pattern`;
                        }
                    }
                    break;

                case ValidationType.MIN_LENGTH:
                    if (value && String(value).length < params.length) {
                        return rule.message || `Field '${fieldName}' must be at least ${params.length} characters`;
                    }
                    break;

                case ValidationType.MAX_LENGTH:
                    if (value && String(value).length > params.length) {
                        return rule.message || `Field '${fieldName}' must be at most ${params.length} characters`;
                    }
                    break;

                case ValidationType.MIN_VALUE:
                    if (value !== null && value !== undefined) {
                        const numValue = Number(value);
                        if (numValue < params.value) {
                            return rule.message || `Field '${fieldName}' must be at least ${params.value}`;
                        }
                    }
                    break;

                case ValidationType.MAX_VALUE:
                    if (value !== null && value !== undefined) {
                        const numValue = Number(value);
                        if (numValue > params.value) {
                            return rule.message || `Field '${fieldName}' must be at most ${params.value}`;
                        }
                    }
                    break;

                case ValidationType.IN_CHOICES:
                    if (value && params.choices && !params.choices.includes(value)) {
                        return rule.message || `Field '${fieldName}' must be one of: ${params.choices.join(', ')}`;
                    }
                    break;

                case ValidationType.CUSTOM:
                    if (params.validator && this.customValidators.has(params.validator)) {
                        const validator = this.customValidators.get(params.validator);
                        if (!validator.func(value)) {
                            return rule.message || validator.message;
                        }
                    }
                    break;

                default:
                    if (this.options.strictMode) {
                        return rule.message || `Unknown validation type: ${rule.type}`;
                    }
            }
        } catch (error) {
            this.emit('validationError', { fieldName, rule, error });
            return `Validation failed for field '${fieldName}': ${error.message}`;
        }

        return null;
    }

    /**
     * Collect all errors from validation results
     */
    _collectErrors(results) {
        const errors = [];
        
        for (const result of Object.values(results)) {
            if (!result.isValid) {
                errors.push(...result.errors);
            }
        }
        
        return errors;
    }
}

/**
 * Schema builder for fluent validation schema creation
 */
class SchemaBuilder {
    constructor() {
        this.schema = {};
    }

    /**
     * Add field with validation rules
     */
    field(fieldName) {
        return new FieldBuilder(fieldName, this);
    }

    /**
     * Get built schema
     */
    build() {
        return this.schema;
    }

    /**
     * Add field to schema (internal method)
     */
    _addField(fieldName, rules) {
        this.schema[fieldName] = rules;
        return this;
    }
}

/**
 * Field builder for fluent interface
 */
class FieldBuilder {
    constructor(fieldName, schemaBuilder) {
        this.fieldName = fieldName;
        this.schemaBuilder = schemaBuilder;
        this.rules = [];
    }

    required(message = null) {
        this.rules.push(new ValidationRule(ValidationType.REQUIRED, { message }));
        return this;
    }

    string(message = null) {
        this.rules.push(new ValidationRule(ValidationType.STRING, { message }));
        return this;
    }

    integer(message = null) {
        this.rules.push(new ValidationRule(ValidationType.INTEGER, { message }));
        return this;
    }

    float(message = null) {
        this.rules.push(new ValidationRule(ValidationType.FLOAT, { message }));
        return this;
    }

    boolean(message = null) {
        this.rules.push(new ValidationRule(ValidationType.BOOLEAN, { message }));
        return this;
    }

    email(message = null) {
        this.rules.push(new ValidationRule(ValidationType.EMAIL, { message }));
        return this;
    }

    phone(message = null) {
        this.rules.push(new ValidationRule(ValidationType.PHONE, { message }));
        return this;
    }

    url(message = null) {
        this.rules.push(new ValidationRule(ValidationType.URL, { message }));
        return this;
    }

    date(message = null) {
        this.rules.push(new ValidationRule(ValidationType.DATE, { message }));
        return this;
    }

    datetime(message = null) {
        this.rules.push(new ValidationRule(ValidationType.DATETIME, { message }));
        return this;
    }

    json(message = null) {
        this.rules.push(new ValidationRule(ValidationType.JSON, { message }));
        return this;
    }

    regex(pattern, message = null) {
        this.rules.push(new ValidationRule(ValidationType.REGEX, { 
            params: { pattern }, 
            message 
        }));
        return this;
    }

    minLength(length, message = null) {
        this.rules.push(new ValidationRule(ValidationType.MIN_LENGTH, { 
            params: { length }, 
            message 
        }));
        return this;
    }

    maxLength(length, message = null) {
        this.rules.push(new ValidationRule(ValidationType.MAX_LENGTH, { 
            params: { length }, 
            message 
        }));
        return this;
    }

    min(value, message = null) {
        this.rules.push(new ValidationRule(ValidationType.MIN_VALUE, { 
            params: { value }, 
            message 
        }));
        return this;
    }

    max(value, message = null) {
        this.rules.push(new ValidationRule(ValidationType.MAX_VALUE, { 
            params: { value }, 
            message 
        }));
        return this;
    }

    choices(choices, message = null) {
        this.rules.push(new ValidationRule(ValidationType.IN_CHOICES, { 
            params: { choices }, 
            message 
        }));
        return this;
    }

    custom(validatorName, message = null) {
        this.rules.push(new ValidationRule(ValidationType.CUSTOM, { 
            params: { validator: validatorName }, 
            message 
        }));
        return this;
    }

    /**
     * Finish building this field and return to schema builder
     */
    end() {
        this.schemaBuilder._addField(this.fieldName, this.rules);
        return this.schemaBuilder;
    }
}

/**
 * Express middleware for request validation
 */
function createValidationMiddleware(schema, validator = null) {
    const dataValidator = validator || new DataValidator();

    return (req, res, next) => {
        const validationResult = dataValidator.validate(req.body, schema);

        if (!validationResult.isValid) {
            return res.status(400).json({
                error: true,
                message: 'Validation failed',
                errors: validationResult.errors,
                details: validationResult.results
            });
        }

        req.validationResult = validationResult;
        next();
    };
}

/**
 * Predefined validation schemas
 */
function createUserSchema() {
    const builder = new SchemaBuilder();
    
    return builder
        .field('username')
            .required()
            .string()
            .minLength(3)
            .maxLength(50)
            .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')
            .end()
        .field('email')
            .required()
            .email()
            .end()
        .field('age')
            .integer()
            .min(0)
            .max(150)
            .end()
        .field('status')
            .choices(['active', 'inactive', 'pending'])
            .end()
        .build();
}

function createAPISchema() {
    const builder = new SchemaBuilder();
    
    return builder
        .field('api_key')
            .required()
            .string()
            .minLength(10)
            .end()
        .field('timestamp')
            .datetime()
            .end()
        .field('data')
            .json()
            .end()
        .field('version')
            .regex(/^\d+\.\d+\.\d+$/, 'Version must be in format x.y.z')
            .end()
        .build();
}

/**
 * Utility functions for common validation patterns
 */
function validateEmailList(emails) {
    const validator = new DataValidator();
    const invalidEmails = [];

    for (const email of emails) {
        if (!validator.globalValidators.get('email')(email)) {
            invalidEmails.push(email);
        }
    }

    return invalidEmails;
}

function sanitizeString(value, options = {}) {
    const {
        allowSpaces = true,
        allowSpecial = false,
        maxLength = null
    } = options;

    let pattern;
    if (allowSpaces && allowSpecial) {
        pattern = /[^a-zA-Z0-9\s\-\._@+]/g;
    } else if (allowSpaces) {
        pattern = /[^a-zA-Z0-9\s]/g;
    } else if (allowSpecial) {
        pattern = /[^a-zA-Z0-9\-\._@+]/g;
    } else {
        pattern = /[^a-zA-Z0-9]/g;
    }

    let sanitized = value.replace(pattern, '');
    
    if (maxLength && sanitized.length > maxLength) {
        sanitized = sanitized.substring(0, maxLength);
    }

    return sanitized;
}

function validatePasswordStrength(password) {
    const result = {
        isValid: true,
        score: 0,
        issues: [],
        suggestions: []
    };

    if (password.length < 8) {
        result.isValid = false;
        result.issues.push('Password must be at least 8 characters');
    } else {
        result.score += 1;
    }

    if (!/[a-z]/.test(password)) {
        result.isValid = false;
        result.issues.push('Password must contain lowercase letters');
    } else {
        result.score += 1;
    }

    if (!/[A-Z]/.test(password)) {
        result.isValid = false;
        result.issues.push('Password must contain uppercase letters');
    } else {
        result.score += 1;
    }

    if (!/\d/.test(password)) {
        result.isValid = false;
        result.issues.push('Password must contain numbers');
    } else {
        result.score += 1;
    }

    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        result.suggestions.push('Consider adding special characters for stronger security');
    } else {
        result.score += 1;
    }

    // Check for common patterns
    if (/^(.)\1+$/.test(password)) {
        result.issues.push('Password cannot be repeated characters');
        result.isValid = false;
    }

    if (/password|123456|qwerty/i.test(password)) {
        result.issues.push('Password is too common');
        result.isValid = false;
    }

    return result;
}

// Example usage
if (require.main === module) {
    async function main() {
        try {
            // Create validator
            const validator = new DataValidator();

            // Add custom validator
            validator.addCustomValidator('evenNumber', (value) => {
                return typeof value === 'number' && value % 2 === 0;
            }, 'Value must be an even number');

            // Test field validation
            const emailRules = [
                new ValidationRule(ValidationType.REQUIRED),
                new ValidationRule(ValidationType.EMAIL)
            ];

            const result = validator.validateField('email', 'test@example.com', emailRules);
            console.log('Email validation:', result.toJSON());

            // Test schema validation with builder
            const userSchema = createUserSchema();
            const testUser = {
                username: 'john_doe',
                email: 'john@example.com',
                age: 25,
                status: 'active'
            };

            const validation = validator.validate(testUser, userSchema);
            console.log('User validation:', validation);

            // Test password validation
            const passwordResult = validatePasswordStrength('MyPassword123!');
            console.log('Password validation:', passwordResult);

            // Test sanitization
            const sanitized = sanitizeString('Hello World! @#$', { 
                allowSpaces: true, 
                allowSpecial: true 
            });
            console.log('Sanitized string:', sanitized);

            // Test email list validation
            const emails = ['test@example.com', 'invalid-email', 'user@domain.org'];
            const invalidEmails = validateEmailList(emails);
            console.log('Invalid emails:', invalidEmails);

            console.log('Data validation utilities demo completed');

        } catch (error) {
            console.error('Demo error:', error.message);
        }
    }

    main();
}

module.exports = {
    // Classes
    DataValidator,
    ValidationRule,
    ValidationResult,
    SchemaBuilder,
    FieldBuilder,

    // Middleware
    createValidationMiddleware,

    // Utilities
    createUserSchema,
    createAPISchema,
    validateEmailList,
    sanitizeString,
    validatePasswordStrength,

    // Constants
    ValidationType
};
