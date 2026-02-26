/*
File: authentication.tpl.ts
Purpose: JWT authentication middleware and utilities (TypeScript)
Generated for: {{PROJECT_NAME}}
*/

import * as jose from 'jose';
import { Request, Response, NextFunction } from 'express';

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET || 'your-secret-key');
const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_TTL = '7d';

interface TokenPayload {
    sub: string;
    roles?: string[];
    [key: string]: unknown;
}

declare global {
    namespace Express {
        interface Request {
            user?: TokenPayload;
        }
    }
}

export async function generateAccessToken(payload: TokenPayload): Promise<string> {
    return await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(ACCESS_TOKEN_TTL)
        .sign(JWT_SECRET);
}

export async function generateRefreshToken(payload: TokenPayload): Promise<string> {
    return await new jose.SignJWT({ ...payload, type: 'refresh' })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(REFRESH_TOKEN_TTL)
        .sign(JWT_SECRET);
}

export async function verifyToken(token: string): Promise<TokenPayload | null> {
    try {
        const { payload } = await jose.jwtVerify(token, JWT_SECRET);
        return payload as TokenPayload;
    } catch {
        return null;
    }
}

export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Missing or invalid token' });
        return;
    }

    const token = authHeader.split(' ')[1];
    verifyToken(token)
        .then((payload) => {
            if (!payload) {
                res.status(401).json({ error: 'Invalid token' });
                return;
            }
            req.user = payload;
            next();
        })
        .catch(() => res.status(401).json({ error: 'Token verification failed' }));
}

export function requireRoles(...allowedRoles: string[]) {
    return (req: Request, res: Response, next: NextFunction): void => {
        if (!req.user || !req.user.roles) {
            res.status(403).json({ error: 'Access denied' });
            return;
        }
        const hasRole = req.user.roles.some((role) => allowedRoles.includes(role));
        if (!hasRole) {
            res.status(403).json({ error: 'Insufficient permissions' });
            return;
        }
        next();
    };
}
