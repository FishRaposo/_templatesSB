/**
 * Template: authentication-pattern.tpl.ts
 * Purpose: authentication-pattern template
 * Stack: typescript
 * Tier: base
 */

# Universal Template System - Typescript Stack
# Generated: 2025-12-10
# Purpose: typescript template utilities
# Tier: base
# Stack: typescript
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: authentication-pattern.tpl.ts
// PURPOSE: TypeScript authentication pattern with JWT tokens, password hashing, and RBAC
// USAGE: Import and adapt for authentication in TypeScript applications
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

// TypeScript Authentication Pattern
// Author: [[.Author]]
// Version: [[.Version]]
// Date: [[.Date]]

/**
 * Authentication Pattern for TypeScript Applications
 * 
 * This pattern provides comprehensive authentication with JWT tokens, password hashing,
 * role-based access control, refresh tokens, and security utilities.
 */

// ==================== AUTHENTICATION INTERFACES ====================

export interface User {
  id: string;
  email: string;
  username?: string;
  roles: string[];
  permissions: string[];
  isActive: boolean;
  lastLogin?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  refreshExpiresIn: number;
}

export interface LoginCredentials {
  email: string;
  password: string;
  rememberMe?: boolean;
}

export interface RegisterData {
  email: string;
  password: string;
  username?: string;
  roles?: string[];
}

export interface JwtPayload {
  sub: string; // user id
  email: string;
  roles: string[];
  permissions: string[];
  iat: number;
  exp: number;
  iss: string;
  aud: string;
  type: 'access' | 'refresh';
}

export interface AuthConfig {
  jwt: {
    secret: string;
    expiresIn: string;
    refreshSecret: string;
    refreshExpiresIn: string;
    issuer: string;
    audience: string;
    algorithm: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
  };
  bcrypt: {
    saltRounds: number;
  };
  password: {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSymbols: boolean;
  };
  session: {
    maxAge: number;
    secure: boolean;
    httpOnly: boolean;
    sameSite: 'strict' | 'lax' | 'none';
  };
}

export interface AuthResult<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
}

// ==================== PASSWORD UTILITIES ====================

import bcrypt from 'bcryptjs';
import crypto from 'crypto';

export class PasswordUtils {
  private static readonly config = {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSymbols: true,
  };

  public static async hashPassword(password: string, saltRounds: number = 12): Promise<string> {
    return bcrypt.hash(password, saltRounds);
  }

  public static async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  public static validatePassword(password: string): {
    isValid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    if (password.length < this.config.minLength) {
      errors.push(`Password must be at least ${this.config.minLength} characters long`);
    }

    if (this.config.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (this.config.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (this.config.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (this.config.requireSymbols && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  public static generateSecurePassword(length: number = 16): string {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    
    for (let i = 0; i < length; i++) {
      password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    
    return password;
  }

  public static generateResetToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }
}

// ==================== JWT TOKEN MANAGER ====================

import jwt from 'jsonwebtoken';

export class JwtTokenManager {
  private config: AuthConfig['jwt'];

  constructor(config: AuthConfig['jwt']) {
    this.config = config;
  }

  public generateTokens(user: User): AuthTokens {
    const now = Math.floor(Date.now() / 1000);
    const accessTokenPayload: Omit<JwtPayload, 'iat' | 'exp'> = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
      iss: this.config.issuer,
      aud: this.config.audience,
      type: 'access',
    };

    const refreshTokenPayload: Omit<JwtPayload, 'iat' | 'exp'> = {
      ...accessTokenPayload,
      type: 'refresh',
    };

    const accessToken = jwt.sign(accessTokenPayload, this.config.secret, {
      expiresIn: this.config.expiresIn,
      algorithm: this.config.algorithm,
    });

    const refreshToken = jwt.sign(refreshTokenPayload, this.config.refreshSecret, {
      expiresIn: this.config.refreshExpiresIn,
      algorithm: this.config.algorithm,
    });

    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: this.parseExpiration(this.config.expiresIn),
      refreshExpiresIn: this.parseExpiration(this.config.refreshExpiresIn),
    };
  }

  public verifyAccessToken(token: string): JwtPayload {
    try {
      const payload = jwt.verify(token, this.config.secret, {
        algorithms: [this.config.algorithm],
        issuer: this.config.issuer,
        audience: this.config.audience,
      }) as JwtPayload;

      if (payload.type !== 'access') {
        throw new Error('Invalid token type');
      }

      return payload;
    } catch (error) {
      throw new Error('Invalid access token');
    }
  }

  public verifyRefreshToken(token: string): JwtPayload {
    try {
      const payload = jwt.verify(token, this.config.refreshSecret, {
        algorithms: [this.config.algorithm],
        issuer: this.config.issuer,
        audience: this.config.audience,
      }) as JwtPayload;

      if (payload.type !== 'refresh') {
        throw new Error('Invalid token type');
      }

      return payload;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  public decodeToken(token: string): JwtPayload | null {
    try {
      return jwt.decode(token) as JwtPayload;
    } catch {
      return null;
    }
  }

  public isTokenExpired(token: string): boolean {
    const payload = this.decodeToken(token);
    if (!payload) {
      return true;
    }

    const now = Math.floor(Date.now() / 1000);
    return payload.exp < now;
  }

  public refreshToken(refreshToken: string, user: User): AuthTokens {
    // Verify the refresh token
    this.verifyRefreshToken(refreshToken);
    
    // Generate new tokens
    return this.generateTokens(user);
  }

  private parseExpiration(expiresIn: string): number {
    const time = parseInt(expiresIn, 10);
    const unit = expiresIn.replace(time.toString(), '');
    
    switch (unit) {
      case 's': return time * 1000;
      case 'm': return time * 60 * 1000;
      case 'h': return time * 60 * 60 * 1000;
      case 'd': return time * 24 * 60 * 60 * 1000;
      default: return time * 1000;
    }
  }
}

// ==================== AUTHENTICATION SERVICE ====================

export class AuthenticationService {
  private tokenManager: JwtTokenManager;
  private config: AuthConfig;

  constructor(config: AuthConfig) {
    this.config = config;
    this.tokenManager = new JwtTokenManager(config.jwt);
  }

  public async register(userData: RegisterData): Promise<AuthResult<{ user: User; tokens: AuthTokens }>> {
    try {
      // Validate password
      const passwordValidation = PasswordUtils.validatePassword(userData.password);
      if (!passwordValidation.isValid) {
        return {
          success: false,
          error: passwordValidation.errors.join(', '),
          code: 'INVALID_PASSWORD',
        };
      }

      // Check if user already exists
      const existingUser = await this.findUserByEmail(userData.email);
      if (existingUser) {
        return {
          success: false,
          error: 'User with this email already exists',
          code: 'USER_EXISTS',
        };
      }

      // Hash password
      const hashedPassword = await PasswordUtils.hashPassword(userData.password, this.config.bcrypt.saltRounds);

      // Create user
      const user = await this.createUser({
        email: userData.email,
        username: userData.username,
        passwordHash: hashedPassword,
        roles: userData.roles || ['user'],
        permissions: this.getPermissionsForRoles(userData.roles || ['user']),
      });

      // Generate tokens
      const tokens = this.tokenManager.generateTokens(user);

      return {
        success: true,
        data: { user, tokens },
      };
    } catch (error) {
      return {
        success: false,
        error: 'Registration failed',
        code: 'REGISTRATION_ERROR',
      };
    }
  }

  public async login(credentials: LoginCredentials): Promise<AuthResult<{ user: User; tokens: AuthTokens }>> {
    try {
      // Find user by email
      const user = await this.findUserByEmail(credentials.email);
      if (!user) {
        return {
          success: false,
          error: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS',
        };
      }

      // Check if user is active
      if (!user.isActive) {
        return {
          success: false,
          error: 'Account is deactivated',
          code: 'ACCOUNT_DEACTIVATED',
        };
      }

      // Verify password
      const isValidPassword = await PasswordUtils.comparePassword(credentials.password, user.passwordHash);
      if (!isValidPassword) {
        return {
          success: false,
          error: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS',
        };
      }

      // Update last login
      await this.updateLastLogin(user.id);

      // Generate tokens
      const tokens = this.tokenManager.generateTokens(user);

      return {
        success: true,
        data: { user, tokens },
      };
    } catch (error) {
      return {
        success: false,
        error: 'Login failed',
        code: 'LOGIN_ERROR',
      };
    }
  }

  public async refreshToken(refreshToken: string): Promise<AuthResult<AuthTokens>> {
    try {
      // Verify refresh token
      const payload = this.tokenManager.verifyRefreshToken(refreshToken);

      // Get user
      const user = await this.findUserById(payload.sub);
      if (!user || !user.isActive) {
        return {
          success: false,
          error: 'Invalid refresh token',
          code: 'INVALID_TOKEN',
        };
      }

      // Generate new tokens
      const tokens = this.tokenManager.refreshToken(refreshToken, user);

      return {
        success: true,
        data: tokens,
      };
    } catch (error) {
      return {
        success: false,
        error: 'Token refresh failed',
        code: 'TOKEN_REFRESH_ERROR',
      };
    }
  }

  public async logout(refreshToken: string): Promise<AuthResult<void>> {
    try {
      // In a real implementation, you would add the token to a blacklist
      // or invalidate it in a database
      return {
        success: true,
      };
    } catch (error) {
      return {
        success: false,
        error: 'Logout failed',
        code: 'LOGOUT_ERROR',
      };
    }
  }

  public async changePassword(userId: string, currentPassword: string, newPassword: string): Promise<AuthResult<void>> {
    try {
      // Get user
      const user = await this.findUserById(userId);
      if (!user) {
        return {
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND',
        };
      }

      // Verify current password
      const isValidPassword = await PasswordUtils.comparePassword(currentPassword, user.passwordHash);
      if (!isValidPassword) {
        return {
          success: false,
          error: 'Current password is incorrect',
          code: 'INVALID_CURRENT_PASSWORD',
        };
      }

      // Validate new password
      const passwordValidation = PasswordUtils.validatePassword(newPassword);
      if (!passwordValidation.isValid) {
        return {
          success: false,
          error: passwordValidation.errors.join(', '),
          code: 'INVALID_NEW_PASSWORD',
        };
      }

      // Hash new password
      const hashedPassword = await PasswordUtils.hashPassword(newPassword, this.config.bcrypt.saltRounds);

      // Update password
      await this.updateUserPassword(userId, hashedPassword);

      return {
        success: true,
      };
    } catch (error) {
      return {
        success: false,
        error: 'Password change failed',
        code: 'PASSWORD_CHANGE_ERROR',
      };
    }
  }

  // ==================== PRIVATE METHODS ====================

  private async findUserByEmail(email: string): Promise<User & { passwordHash: string } | null> {
    // Simulate database lookup
    if (email === 'user@example.com') {
      return {
        id: '123',
        email: 'user@example.com',
        username: 'testuser',
        roles: ['user'],
        permissions: ['read:profile'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        passwordHash: '$2a$12$hashedpasswordhere',
      };
    }
    return null;
  }

  private async findUserById(id: string): Promise<User & { passwordHash: string } | null> {
    // Simulate database lookup
    if (id === '123') {
      return {
        id: '123',
        email: 'user@example.com',
        username: 'testuser',
        roles: ['user'],
        permissions: ['read:profile'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        passwordHash: '$2a$12$hashedpasswordhere',
      };
    }
    return null;
  }

  private async createUser(userData: {
    email: string;
    username?: string;
    passwordHash: string;
    roles: string[];
    permissions: string[];
  }): Promise<User> {
    // Simulate user creation
    return {
      id: '123',
      email: userData.email,
      username: userData.username,
      roles: userData.roles,
      permissions: userData.permissions,
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  private async updateLastLogin(userId: string): Promise<void> {
    // Simulate database update
    console.log(`Updated last login for user ${userId}`);
  }

  private async updateUserPassword(userId: string, passwordHash: string): Promise<void> {
    // Simulate database update
    console.log(`Updated password for user ${userId}`);
  }

  private getPermissionsForRoles(roles: string[]): string[] {
    const rolePermissions: Record<string, string[]> = {
      user: ['read:profile', 'update:profile'],
      admin: ['read:profile', 'update:profile', 'read:users', 'manage:users'],
      super_admin: ['*'],
    };

    const permissions = new Set<string>();
    for (const role of roles) {
      const rolePerms = rolePermissions[role] || [];
      rolePerms.forEach(perm => permissions.add(perm));
    }

    return Array.from(permissions);
  }
}

// ==================== AUTHORIZATION MIDDLEWARE ====================

import { Request, Response, NextFunction } from 'express';

export interface AuthenticatedRequest extends Request {
  user?: User;
  token?: string;
}

export class AuthMiddleware {
  private tokenManager: JwtTokenManager;

  constructor(tokenManager: JwtTokenManager) {
    this.tokenManager = tokenManager;
  }

  public authenticate() {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({
            success: false,
            error: 'Access token is required',
            code: 'TOKEN_REQUIRED',
          });
        }

        const token = authHeader.substring(7);
        const payload = this.tokenManager.verifyAccessToken(token);

        // Get user from database
        this.getUserById(payload.sub).then(user => {
          if (!user || !user.isActive) {
            return res.status(401).json({
              success: false,
              error: 'Invalid token',
              code: 'INVALID_TOKEN',
            });
          }

          req.user = user;
          req.token = token;
          next();
        }).catch(() => {
          res.status(401).json({
            success: false,
            error: 'Invalid token',
            code: 'INVALID_TOKEN',
          });
        });
      } catch (error) {
        res.status(401).json({
          success: false,
          error: 'Invalid token',
          code: 'INVALID_TOKEN',
        });
      }
    };
  }

  public authorize(permissions: string | string[], requireAll: boolean = true) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required',
          code: 'AUTHENTICATION_REQUIRED',
        });
      }

      const requiredPermissions = Array.isArray(permissions) ? permissions : [permissions];
      const userPermissions = req.user.permissions;

      const hasWildcard = userPermissions.includes('*');
      const hasPermission = requireAll
        ? requiredPermissions.every(perm => userPermissions.includes(perm))
        : requiredPermissions.some(perm => userPermissions.includes(perm));

      if (!hasWildcard && !hasPermission) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions',
          code: 'INSUFFICIENT_PERMISSIONS',
        });
      }

      next();
    };
  }

  public requireRole(roles: string | string[]) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required',
          code: 'AUTHENTICATION_REQUIRED',
        });
      }

      const requiredRoles = Array.isArray(roles) ? roles : [roles];
      const hasRole = requiredRoles.some(role => req.user!.roles.includes(role));

      if (!hasRole) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient role permissions',
          code: 'INSUFFICIENT_ROLE',
        });
      }

      next();
    };
  }

  private async getUserById(id: string): Promise<User | null> {
    // Simulate database lookup
    if (id === '123') {
      return {
        id: '123',
        email: 'user@example.com',
        username: 'testuser',
        roles: ['user'],
        permissions: ['read:profile', 'update:profile'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
    }
    return null;
  }
}

// ==================== AUTHENTICATION DECORATORS ====================

/**
 * Decorator for requiring authentication on methods
 */
export function RequireAuth() {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = function (...args: any[]) {
      const req = args.find(arg => arg && arg.user) as AuthenticatedRequest;
      
      if (!req || !req.user) {
        throw new Error('Authentication required');
      }

      return originalMethod.apply(this, args);
    };

    return descriptor;
  };
}

/**
 * Decorator for requiring specific permissions
 */
export function RequirePermissions(permissions: string | string[], requireAll: boolean = true) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = function (...args: any[]) {
      const req = args.find(arg => arg && arg.user) as AuthenticatedRequest;
      
      if (!req || !req.user) {
        throw new Error('Authentication required');
      }

      const requiredPermissions = Array.isArray(permissions) ? permissions : [permissions];
      const userPermissions = req.user.permissions;

      const hasWildcard = userPermissions.includes('*');
      const hasPermission = requireAll
        ? requiredPermissions.every(perm => userPermissions.includes(perm))
        : requiredPermissions.some(perm => userPermissions.includes(perm));

      if (!hasWildcard && !hasPermission) {
        throw new Error('Insufficient permissions');
      }

      return originalMethod.apply(this, args);
    };

    return descriptor;
  };
}

// ==================== USAGE EXAMPLES ====================

/**
 * Example controller using authentication
 */
export class AuthController {
  private authService: AuthenticationService;

  constructor(config: AuthConfig) {
    this.authService = new AuthenticationService(config);
  }

  public async register(req: Request, res: Response): Promise<void> {
    const result = await this.authService.register(req.body);
    
    if (result.success) {
      res.status(201).json({
        success: true,
        data: result.data,
      });
    } else {
      res.status(400).json({
        success: false,
        error: result.error,
        code: result.code,
      });
    }
  }

  public async login(req: Request, res: Response): Promise<void> {
    const result = await this.authService.login(req.body);
    
    if (result.success) {
      res.json({
        success: true,
        data: result.data,
      });
    } else {
      res.status(401).json({
        success: false,
        error: result.error,
        code: result.code,
      });
    }
  }

  public async refreshToken(req: Request, res: Response): Promise<void> {
    const { refreshToken } = req.body;
    const result = await this.authService.refreshToken(refreshToken);
    
    if (result.success) {
      res.json({
        success: true,
        data: result.data,
      });
    } else {
      res.status(401).json({
        success: false,
        error: result.error,
        code: result.code,
      });
    }
  }
}

/**
 * Example protected controller
 */
export class UserController {
  @RequireAuth()
  @RequirePermissions('read:profile')
  public async getProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    res.json({
      success: true,
      data: {
        id: req.user!.id,
        email: req.user!.email,
        username: req.user!.username,
        roles: req.user!.roles,
      },
    });
  }

  @RequireAuth()
  @RequirePermissions(['read:users', 'manage:users'], false)
  public async getUsers(req: AuthenticatedRequest, res: Response): Promise<void> {
    // Only users with either 'read:users' OR 'manage:users' can access this
    res.json({
      success: true,
      data: [
        { id: '123', email: 'user@example.com' },
      ],
    });
  }
}

// ==================== EXPORTS ====================

export default AuthenticationService;

// Type exports
export type {
  User,
  AuthTokens,
  LoginCredentials,
  RegisterData,
  JwtPayload,
  AuthConfig,
  AuthResult,
  AuthenticatedRequest,
};

// Class exports
export {
  PasswordUtils,
  JwtTokenManager,
  AuthMiddleware,
};

// Decorator exports
export {
  RequireAuth,
  RequirePermissions,
};

// ==================== BEST PRACTICES ====================

/*
1. **Password Security**: Always use bcrypt for password hashing with appropriate salt rounds
2. **JWT Security**: Use strong secrets, appropriate expiration times, and include all necessary claims
3. **Token Management**: Implement refresh tokens for better user experience and security
4. **Permission System**: Use role-based access control with granular permissions
5. **Input Validation**: Validate all input data, especially passwords and email formats
6. **Error Handling**: Don't reveal specific error details for authentication failures
7. **Rate Limiting**: Implement rate limiting for authentication endpoints
8. **Secure Headers**: Use secure HTTP headers for authentication cookies
9. **Token Blacklisting**: Implement token blacklisting for logout scenarios
10. **Audit Logging**: Log all authentication events for security monitoring
*/
