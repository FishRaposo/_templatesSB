/*
File: api_routes.tpl.js
Purpose: Express.js API routes with middleware and validation
Generated for: {{PROJECT_NAME}}
*/

const express = require('express');
const { body, param, query, validationResult } = require('express-validator');

// ============================================================================
// Response Helpers
// ============================================================================

const respondOK = (res, data, message = null) => {
    res.json({ success: true, data, message });
};

const respondCreated = (res, data) => {
    res.status(201).json({ success: true, data });
};

const respondNoContent = (res) => {
    res.status(204).send();
};

const respondPaginated = (res, data, pagination) => {
    res.json({ success: true, data, pagination });
};

const respondError = (res, status, code, message) => {
    res.status(status).json({
        success: false,
        errors: [{ code, message }],
    });
};

const respondValidationErrors = (res, errors) => {
    res.status(422).json({
        success: false,
        errors: errors.map((e) => ({
            code: 'VALIDATION_ERROR',
            message: e.msg,
            field: e.path,
        })),
    });
};

// ============================================================================
// Validation Middleware
// ============================================================================

const validate = (validations) => {
    return async (req, res, next) => {
        await Promise.all(validations.map((v) => v.run(req)));

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return respondValidationErrors(res, errors.array());
        }
        next();
    };
};

// Common validation chains
const paginationValidation = [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('per_page').optional().isInt({ min: 1, max: 100 }).toInt(),
];

const idParamValidation = [
    param('id').isInt({ min: 1 }).withMessage('Invalid ID'),
];

// ============================================================================
// Authentication Middleware
// ============================================================================

const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return respondError(res, 401, 'UNAUTHORIZED', 'Missing authentication token');
    }

    const token = authHeader.substring(7);

    try {
        // Validate token
        // const decoded = jwt.verify(token, process.env.JWT_SECRET);
        // const user = await getUserById(decoded.sub);
        // req.user = user;
        next();
    } catch (error) {
        return respondError(res, 401, 'INVALID_TOKEN', 'Invalid or expired token');
    }
};

const requireAdmin = (req, res, next) => {
    if (!req.user?.isAdmin) {
        return respondError(res, 403, 'FORBIDDEN', 'Admin access required');
    }
    next();
};

const requireVerified = (req, res, next) => {
    if (!req.user?.isVerified) {
        return respondError(res, 403, 'UNVERIFIED', 'Email verification required');
    }
    next();
};

// ============================================================================
// Rate Limiting Middleware
// ============================================================================

const rateLimit = require('express-rate-limit');

const createRateLimiter = (windowMs, max, message) =>
    rateLimit({
        windowMs,
        max,
        message: { success: false, errors: [{ code: 'RATE_LIMITED', message }] },
        standardHeaders: true,
        legacyHeaders: false,
    });

const apiLimiter = createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    100,
    'Too many requests, please try again later'
);

const authLimiter = createRateLimiter(
    15 * 60 * 1000,
    5,
    'Too many authentication attempts'
);

// ============================================================================
// User Routes
// ============================================================================

const userRouter = express.Router();

// POST /api/users/register
userRouter.post(
    '/register',
    authLimiter,
    validate([
        body('email').isEmail().normalizeEmail(),
        body('username').isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9_-]+$/),
        body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
        body('fullName').optional().isLength({ max: 100 }).trim(),
    ]),
    async (req, res, next) => {
        try {
            const { email, username, password, fullName } = req.body;

            // Check if user exists
            // Create user
            // Generate tokens

            const user = {
                id: 1,
                email,
                username,
                fullName,
                createdAt: new Date(),
            };

            respondCreated(res, {
                user,
                accessToken: 'jwt-token',
                refreshToken: 'refresh-token',
            });
        } catch (error) {
            next(error);
        }
    }
);

// POST /api/users/login
userRouter.post(
    '/login',
    authLimiter,
    validate([
        body('email').isEmail().normalizeEmail(),
        body('password').notEmpty(),
    ]),
    async (req, res, next) => {
        try {
            const { email, password } = req.body;

            // Authenticate user
            // Generate tokens

            respondOK(res, {
                accessToken: 'jwt-token',
                refreshToken: 'refresh-token',
                expiresIn: 3600,
            });
        } catch (error) {
            next(error);
        }
    }
);

// GET /api/users/me
userRouter.get('/me', authenticate, async (req, res, next) => {
    try {
        respondOK(res, req.user);
    } catch (error) {
        next(error);
    }
});

// PATCH /api/users/me
userRouter.patch(
    '/me',
    authenticate,
    validate([
        body('fullName').optional().isLength({ max: 100 }).trim(),
        body('bio').optional().isLength({ max: 500 }).trim(),
        body('website').optional().isURL(),
    ]),
    async (req, res, next) => {
        try {
            const updates = req.body;

            // Update user
            const user = { ...req.user, ...updates };

            respondOK(res, user, 'Profile updated');
        } catch (error) {
            next(error);
        }
    }
);

// POST /api/users/change-password
userRouter.post(
    '/change-password',
    authenticate,
    validate([
        body('currentPassword').notEmpty(),
        body('newPassword').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
        body('confirmPassword').custom((value, { req }) => value === req.body.newPassword),
    ]),
    async (req, res, next) => {
        try {
            const { currentPassword, newPassword } = req.body;

            // Verify current password
            // Update password

            respondOK(res, null, 'Password changed successfully');
        } catch (error) {
            next(error);
        }
    }
);

// ============================================================================
// Post Routes
// ============================================================================

const postRouter = express.Router();

// GET /api/posts
postRouter.get(
    '/',
    validate([
        ...paginationValidation,
        query('status').optional().isIn(['draft', 'published', 'archived']),
        query('search').optional().isLength({ max: 100 }).trim(),
        query('author_id').optional().isInt({ min: 1 }),
    ]),
    async (req, res, next) => {
        try {
            const page = req.query.page || 1;
            const perPage = req.query.per_page || 20;
            const { status, search, author_id } = req.query;

            // Query posts
            const posts = [];
            const total = 0;

            const totalPages = Math.ceil(total / perPage);

            respondPaginated(res, posts, {
                page,
                perPage,
                total,
                totalPages,
                hasNext: page * perPage < total,
                hasPrev: page > 1,
            });
        } catch (error) {
            next(error);
        }
    }
);

// POST /api/posts
postRouter.post(
    '/',
    authenticate,
    validate([
        body('title').isLength({ min: 5, max: 200 }).trim(),
        body('content').isLength({ min: 10 }),
        body('excerpt').optional().isLength({ max: 500 }).trim(),
        body('status').optional().isIn(['draft', 'published', 'archived']),
        body('tags').optional().isArray({ max: 10 }),
        body('tags.*').optional().isString().isLength({ max: 50 }),
    ]),
    async (req, res, next) => {
        try {
            const { title, content, excerpt, status, tags } = req.body;

            // Create post
            const post = {
                id: 1,
                title,
                content,
                excerpt,
                status: status || 'draft',
                authorId: req.user.id,
                createdAt: new Date(),
            };

            respondCreated(res, post);
        } catch (error) {
            next(error);
        }
    }
);

// GET /api/posts/:id
postRouter.get(
    '/:id',
    validate(idParamValidation),
    async (req, res, next) => {
        try {
            const { id } = req.params;

            // Get post
            const post = { id, title: 'Test Post' };

            if (!post) {
                return respondError(res, 404, 'NOT_FOUND', 'Post not found');
            }

            respondOK(res, post);
        } catch (error) {
            next(error);
        }
    }
);

// PATCH /api/posts/:id
postRouter.patch(
    '/:id',
    authenticate,
    validate([
        ...idParamValidation,
        body('title').optional().isLength({ min: 5, max: 200 }).trim(),
        body('content').optional().isLength({ min: 10 }),
        body('status').optional().isIn(['draft', 'published', 'archived']),
    ]),
    async (req, res, next) => {
        try {
            const { id } = req.params;
            const updates = req.body;

            // Get and check ownership
            // Update post

            const post = { id, ...updates };

            respondOK(res, post);
        } catch (error) {
            next(error);
        }
    }
);

// DELETE /api/posts/:id
postRouter.delete(
    '/:id',
    authenticate,
    validate(idParamValidation),
    async (req, res, next) => {
        try {
            const { id } = req.params;

            // Get and check ownership
            // Delete post

            respondNoContent(res);
        } catch (error) {
            next(error);
        }
    }
);

// POST /api/posts/:id/publish
postRouter.post(
    '/:id/publish',
    authenticate,
    validate(idParamValidation),
    async (req, res, next) => {
        try {
            const { id } = req.params;

            // Publish post

            respondOK(res, null, 'Post published');
        } catch (error) {
            next(error);
        }
    }
);

// ============================================================================
// Health Routes
// ============================================================================

const healthRouter = express.Router();

healthRouter.get('/', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0',
    });
});

healthRouter.get('/db', async (req, res, next) => {
    try {
        // Check database connection
        res.json({ status: 'healthy', database: 'connected' });
    } catch (error) {
        res.status(503).json({ status: 'unhealthy', database: 'disconnected' });
    }
});

healthRouter.get('/redis', async (req, res, next) => {
    try {
        // Check Redis connection
        res.json({ status: 'healthy', redis: 'connected' });
    } catch (error) {
        res.status(503).json({ status: 'unhealthy', redis: 'disconnected' });
    }
});

// ============================================================================
// Error Handler
// ============================================================================

const errorHandler = (err, req, res, next) => {
    console.error(err);

    if (err.name === 'ValidationError') {
        return respondError(res, 400, 'VALIDATION_ERROR', err.message);
    }

    if (err.name === 'UnauthorizedError') {
        return respondError(res, 401, 'UNAUTHORIZED', 'Invalid token');
    }

    respondError(res, 500, 'INTERNAL_ERROR', 'An unexpected error occurred');
};

// ============================================================================
// Router Assembly
// ============================================================================

const createApiRouter = () => {
    const router = express.Router();

    // Apply rate limiting
    router.use(apiLimiter);

    // Mount routes
    router.use('/health', healthRouter);
    router.use('/users', userRouter);
    router.use('/posts', postRouter);

    // Error handler
    router.use(errorHandler);

    return router;
};

module.exports = {
    createApiRouter,
    userRouter,
    postRouter,
    healthRouter,
    authenticate,
    requireAdmin,
    validate,
    respondOK,
    respondCreated,
    respondError,
};
