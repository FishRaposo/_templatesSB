/*
File: database.tpl.js
Purpose: Prisma client setup and patterns
Generated for: {{PROJECT_NAME}}
*/

import { PrismaClient } from '@prisma/client';

// Singleton pattern for Prisma client
const globalForPrisma = globalThis;
export const prisma = globalForPrisma.prisma ?? new PrismaClient({
    log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
});

if (process.env.NODE_ENV !== 'production') {
    globalForPrisma.prisma = prisma;
}

/**
 * Generic repository factory
 */
export function createRepository(modelName) {
    const model = prisma[modelName];

    return {
        async findById(id) {
            return model.findUnique({ where: { id } });
        },

        async findAll(options = {}) {
            return model.findMany({
                take: options.limit || 100,
                skip: options.offset || 0,
                orderBy: options.orderBy || { createdAt: 'desc' },
            });
        },

        async create(data) {
            return model.create({ data });
        },

        async update(id, data) {
            return model.update({ where: { id }, data });
        },

        async delete(id) {
            return model.delete({ where: { id } });
        },

        async count(where = {}) {
            return model.count({ where });
        },
    };
}

// Example: Create a user repository
// const userRepo = createRepository('user');
// const user = await userRepo.findById('123');

/**
 * Transaction helper
 */
export async function withTransaction(callback) {
    return prisma.$transaction(async (tx) => {
        return callback(tx);
    });
}

/**
 * Graceful shutdown
 */
export async function disconnect() {
    await prisma.$disconnect();
}
