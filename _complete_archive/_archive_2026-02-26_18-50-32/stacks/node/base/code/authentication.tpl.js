/*
File: authentication.tpl.js
Purpose: JWT authentication middleware and utilities
Generated for: {{PROJECT_NAME}}
*/

import * as jose from 'jose';

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || 'your-secret-key');
const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_TTL = '7d';

/**
 * Generate an access token
 */
export async function generateAccessToken(payload) {
    return await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(ACCESS_TOKEN_TTL)
        .sign(JWT_SECRET);
}

/**
 * Generate a refresh token
 */
export async function generateRefreshToken(payload) {
    return await new jose.SignJWT({ ...payload, type: 'refresh' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(REFRESH_TOKEN_TTL)
        .sign(JWT_SECRET);
}

/**
 * Verify a token and return the payload
 */
export async function verifyToken(token) {
    try {
        const { payload } = await jose.jwtVerify(token, JWT_SECRET);
        return payload;
    } catch (error) {
        return null;
    }
}

/**
 * Express/Fastify middleware for protected routes
 */
export function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid token' });
    }

    const token = authHeader.split(' ')[1];
    verifyToken(token)
        .then((payload) => {
            if (!payload) {
                return res.status(401).json({ error: 'Invalid token' });
            }
            req.user = payload;
            next();
        })
        .catch(() => res.status(401).json({ error: 'Token verification failed' }));
}

/**
 * Role-based access control middleware
 */
export function requireRoles(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !req.user.roles) {
            return res.status(403).json({ error: 'Access denied' });
        }
        const hasRole = req.user.roles.some((role) => allowedRoles.includes(role));
        if (!hasRole) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
}
