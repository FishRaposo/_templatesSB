/*
File: database_models.tpl.js
Purpose: Prisma schema and model utilities
Generated for: {{PROJECT_NAME}}
*/

// This file provides utilities for working with Prisma models
// The actual schema is defined in prisma/schema.prisma

const { PrismaClient } = require('@prisma/client');

// Singleton Prisma client
let prisma = null;

function getPrismaClient() {
    if (!prisma) {
        prisma = new PrismaClient({
            log: process.env.NODE_ENV === 'development'
                ? ['query', 'info', 'warn', 'error']
                : ['error'],
        });
    }
    return prisma;
}

// Soft delete middleware
function softDeleteMiddleware(prisma) {
    // Intercept delete operations
    prisma.$use(async (params, next) => {
        if (params.action === 'delete') {
            params.action = 'update';
            params.args.data = { deletedAt: new Date(), isDeleted: true };
        }
        if (params.action === 'deleteMany') {
            params.action = 'updateMany';
            params.args.data = { deletedAt: new Date(), isDeleted: true };
        }
        return next(params);
    });

    // Filter out soft-deleted records
    prisma.$use(async (params, next) => {
        if (params.action === 'findUnique' || params.action === 'findFirst') {
            params.action = 'findFirst';
            params.args.where = { ...params.args.where, isDeleted: false };
        }
        if (params.action === 'findMany') {
            if (!params.args) params.args = {};
            if (!params.args.where) params.args.where = {};
            params.args.where.isDeleted = false;
        }
        return next(params);
    });
}

// Audit log middleware
function auditLogMiddleware(prisma) {
    prisma.$use(async (params, next) => {
        const before = Date.now();
        const result = await next(params);
        const after = Date.now();

        if (['create', 'update', 'delete'].includes(params.action)) {
            console.log(`[AUDIT] ${params.model}.${params.action} took ${after - before}ms`);
            // Store audit log
            // await prisma.auditLog.create({ ... });
        }

        return result;
    });
}

// Base repository class
class BaseRepository {
    constructor(model) {
        this.prisma = getPrismaClient();
        this.model = model;
    }

    async findById(id) {
        return this.prisma[this.model].findUnique({ where: { id } });
    }

    async findAll({ page = 1, perPage = 20, where = {}, orderBy = { createdAt: 'desc' } } = {}) {
        const skip = (page - 1) * perPage;
        const [data, total] = await Promise.all([
            this.prisma[this.model].findMany({
                where,
                orderBy,
                skip,
                take: perPage,
            }),
            this.prisma[this.model].count({ where }),
        ]);

        return {
            data,
            pagination: {
                page,
                perPage,
                total,
                totalPages: Math.ceil(total / perPage),
            },
        };
    }

    async create(data) {
        return this.prisma[this.model].create({ data });
    }

    async update(id, data) {
        return this.prisma[this.model].update({ where: { id }, data });
    }

    async delete(id) {
        return this.prisma[this.model].delete({ where: { id } });
    }

    async exists(where) {
        const count = await this.prisma[this.model].count({ where });
        return count > 0;
    }

    async transaction(fn) {
        return this.prisma.$transaction(fn);
    }
}

// User repository with specific methods
class UserRepository extends BaseRepository {
    constructor() {
        super('user');
    }

    async findByEmail(email) {
        return this.prisma.user.findUnique({ where: { email } });
    }

    async findByUsername(username) {
        return this.prisma.user.findUnique({ where: { username } });
    }

    async findWithPosts(id) {
        return this.prisma.user.findUnique({
            where: { id },
            include: { posts: true },
        });
    }

    async updateLastLogin(id) {
        return this.prisma.user.update({
            where: { id },
            data: { lastLoginAt: new Date() },
        });
    }
}

// Post repository
class PostRepository extends BaseRepository {
    constructor() {
        super('post');
    }

    async findBySlug(slug) {
        return this.prisma.post.findUnique({ where: { slug } });
    }

    async findPublished(options = {}) {
        return this.findAll({
            ...options,
            where: { ...options.where, status: 'published' },
        });
    }

    async incrementViews(id) {
        return this.prisma.post.update({
            where: { id },
            data: { viewCount: { increment: 1 } },
        });
    }

    async findWithTags(id) {
        return this.prisma.post.findUnique({
            where: { id },
            include: { tags: true, author: true },
        });
    }
}

// Database connection management
async function connectDatabase() {
    const prisma = getPrismaClient();
    await prisma.$connect();
    console.log('Database connected');
    return prisma;
}

async function disconnectDatabase() {
    if (prisma) {
        await prisma.$disconnect();
        console.log('Database disconnected');
    }
}

// Graceful shutdown
process.on('beforeExit', async () => {
    await disconnectDatabase();
});

module.exports = {
    getPrismaClient,
    softDeleteMiddleware,
    auditLogMiddleware,
    BaseRepository,
    UserRepository,
    PostRepository,
    connectDatabase,
    disconnectDatabase,
};
