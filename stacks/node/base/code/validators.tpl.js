/*
File: validators.tpl.js
Purpose: Common validation patterns with Zod
Generated for: {{PROJECT_NAME}}
*/

const { z } = require('zod');

// Common regex patterns
const PHONE_PATTERN = /^\+?[1-9]\d{1,14}$/;
const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const USERNAME_PATTERN = /^[a-zA-Z0-9_-]{3,32}$/;

// Base schemas
const timestampSchema = z.object({
    createdAt: z.date().optional(),
    updatedAt: z.date().optional(),
});

// Pagination
const paginationSchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    perPage: z.coerce.number().int().min(1).max(100).default(20),
    orderBy: z.string().optional(),
    orderDir: z.enum(['asc', 'desc']).default('asc'),
});

// User schemas
const userCreateSchema = z.object({
    email: z.string().email(),
    username: z.string()
        .min(3)
        .max(32)
        .regex(USERNAME_PATTERN, 'Username must be 3-32 characters, alphanumeric with _ or -')
        .transform((v) => v.toLowerCase()),
    password: z.string()
        .min(8)
        .max(128)
        .refine((v) => /[A-Z]/.test(v), 'Password must contain at least one uppercase letter')
        .refine((v) => /[a-z]/.test(v), 'Password must contain at least one lowercase letter')
        .refine((v) => /[0-9]/.test(v), 'Password must contain at least one digit'),
    fullName: z.string().max(100).optional(),
});

const userUpdateSchema = userCreateSchema.partial().omit({ password: true });

// Phone number
const phoneSchema = z.string()
    .transform((v) => v.replace(/[\s\-()]/g, ''))
    .refine((v) => PHONE_PATTERN.test(v), 'Invalid phone number format');

// Date range with validation
const dateRangeSchema = z.object({
    startDate: z.coerce.date(),
    endDate: z.coerce.date(),
}).refine(
    (data) => data.endDate >= data.startDate,
    { message: 'endDate must be after startDate', path: ['endDate'] }
);

// Address
const addressSchema = z.object({
    street: z.string().max(200),
    city: z.string().max(100),
    state: z.string().max(100).optional(),
    postalCode: z.string().max(20),
    country: z.string().length(2).regex(/^[A-Z]{2}$/, 'Must be ISO 3166-1 alpha-2'),
});

// Slug
const slugSchema = z.string()
    .max(100)
    .transform((v) => v.toLowerCase())
    .refine((v) => SLUG_PATTERN.test(v), 'Slug must be lowercase with hyphens only');

// Money (stored in cents)
const moneySchema = z.object({
    amount: z.number().int().min(0),
    currency: z.string().length(3).regex(/^[A-Z]{3}$/).default('USD'),
});

// UUID
const uuidSchema = z.string().uuid();

// URL
const urlSchema = z.string().url();

// Common ID params
const idParamSchema = z.object({
    id: z.coerce.number().int().positive(),
});

const uuidParamSchema = z.object({
    id: z.string().uuid(),
});

/**
 * Validate data against a Zod schema
 * @param {z.ZodSchema} schema - Zod schema to validate against
 * @param {unknown} data - Data to validate
 * @returns {{ success: boolean, data?: any, errors?: z.ZodError }}
 */
function validate(schema, data) {
    const result = schema.safeParse(data);
    if (result.success) {
        return { success: true, data: result.data };
    }
    return { success: false, errors: result.error };
}

/**
 * Format Zod errors into a user-friendly object
 * @param {z.ZodError} error - Zod error object
 * @returns {Record<string, string[]>}
 */
function formatErrors(error) {
    const formatted = {};
    for (const issue of error.issues) {
        const path = issue.path.join('.') || '_root';
        if (!formatted[path]) {
            formatted[path] = [];
        }
        formatted[path].push(issue.message);
    }
    return formatted;
}

/**
 * Express middleware for request validation
 * @param {Object} schemas - Object with body, query, params schemas
 */
function validateRequest(schemas = {}) {
    return (req, res, next) => {
        const errors = {};

        if (schemas.body) {
            const result = schemas.body.safeParse(req.body);
            if (!result.success) {
                errors.body = formatErrors(result.error);
            } else {
                req.body = result.data;
            }
        }

        if (schemas.query) {
            const result = schemas.query.safeParse(req.query);
            if (!result.success) {
                errors.query = formatErrors(result.error);
            } else {
                req.query = result.data;
            }
        }

        if (schemas.params) {
            const result = schemas.params.safeParse(req.params);
            if (!result.success) {
                errors.params = formatErrors(result.error);
            } else {
                req.params = result.data;
            }
        }

        if (Object.keys(errors).length > 0) {
            return res.status(400).json({ error: 'Validation failed', details: errors });
        }

        next();
    };
}

module.exports = {
    // Schemas
    paginationSchema,
    userCreateSchema,
    userUpdateSchema,
    phoneSchema,
    dateRangeSchema,
    addressSchema,
    slugSchema,
    moneySchema,
    uuidSchema,
    urlSchema,
    idParamSchema,
    uuidParamSchema,
    timestampSchema,
    // Utilities
    validate,
    formatErrors,
    validateRequest,
    // Re-export zod for convenience
    z,
};

// Usage:
// const { userCreateSchema, validateRequest } = require('./validators');
//
// // Direct validation
// const result = userCreateSchema.safeParse(userData);
//
// // Express middleware
// app.post('/users', validateRequest({ body: userCreateSchema }), createUser);
