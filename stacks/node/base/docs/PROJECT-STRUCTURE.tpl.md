# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: node template utilities
# Tier: base
# Stack: node
# Category: template

# {{PROJECT_NAME}} - TypeScript/Node Project Structure

**Tier**: {{TIER}} | **Stack**: TypeScript/Node

## ⚡ Canonical TypeScript/Node Project Structure

### **MVP Tier (Simple API)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── index.ts
│   ├── app.ts
│   ├── routes/
│   │   └── index.ts
│   └── types/
│       └── index.ts
├── tests/
│   └── app.test.ts
├── package.json
├── tsconfig.json
├── .gitignore
└── README.md
```

### **CORE Tier (Production API)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── index.ts
│   ├── app.ts
│   ├── core/
│   │   ├── config/
│   │   │   ├── index.ts
│   │   │   └── database.ts
│   │   ├── errors/
│   │   │   ├── AppError.ts
│   │   │   └── ValidationError.ts
│   │   ├── middleware/
│   │   │   ├── auth.ts
│   │   │   ├── validation.ts
│   │   │   └── errorHandler.ts
│   │   └── utils/
│   │       ├── logger.ts
│   │       └── helpers.ts
│   ├── modules/
│   │   ├── user/
│   │   │   ├── controller.ts
│   │   │   ├── service.ts
│   │   │   ├── repository.ts
│   │   │   ├── routes.ts
│   │   │   ├── types.ts
│   │   │   └── validation.ts
│   │   └── [other_modules]/
│   ├── shared/
│   │   ├── database/
│   │   │   ├── connection.ts
│   │   │   └── migrations/
│   │   └── types/
│   │       ├── common.ts
│   │       └── api.ts
│   └── types/
│       └── index.ts
├── tests/
│   ├── unit/
│   │   ├── modules/
│   │   └── core/
│   ├── integration/
│   │   └── api/
│   ├── fixtures/
│   └── setup.ts
├── scripts/
│   ├── build.ts
│   ├── migrate.ts
│   └── seed.ts
├── package.json
├── package-lock.json
├── tsconfig.json
├── jest.config.js
├── .env.example
├── .gitignore
└── README.md
```

### **FULL Tier (Enterprise API)**
```
{{PROJECT_NAME}}/
├── src/
│   ├── [CORE tier structure]
│   ├── background/
│   │   ├── jobs/
│   │   ├── workers/
│   │   └── queues/
│   ├── monitoring/
│   │   ├── metrics/
│   │   ├── health/
│   │   └── tracing/
│   ├── integrations/
│   │   ├── external/
│   │   ├── events/
│   │   └── messaging/
│   └── gateway/
│       ├── graphql/
│       └── rest/
├── tests/
│   ├── [CORE test structure]
│   ├── e2e/
│   ├── load/
│   └── contracts/
├── tools/
│   ├── deployment/
│   ├── monitoring/
│   └── performance/
├── docs/
│   ├── api/
│   ├── architecture/
│   └── deployment/
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── docker-compose.prod.yml
└── [CORE tier files]
```

## 📁 Module Structure Pattern

### **Module Organization**
```typescript
// src/modules/user/controller.ts
import { Request, Response, NextFunction } from 'express';
import { UserService } from './service';
import { CreateUserDto, UpdateUserDto } from './types';
import { validateDto } from '../../core/middleware/validation';

export class UserController {
  constructor(private userService: UserService) {}

  async createUser(req: Request, res: Response, next: NextFunction) {
    try {
      const createUserDto = await validateDto(CreateUserDto, req.body);
      const user = await this.userService.createUser(createUserDto);
      res.status(201).json(user);
    } catch (error) {
      next(error);
    }
  }

  async getUser(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const user = await this.userService.getUserById(id);
      res.json(user);
    } catch (error) {
      next(error);
    }
  }
}
```

### **Service Layer Pattern**
```typescript
// src/modules/user/service.ts
import { UserRepository } from './repository';
import { CreateUserDto, UserDto } from './types';
import { AppError } from '../../core/errors/AppError';

export class UserService {
  constructor(private userRepository: UserRepository) {}

  async createUser(createUserDto: CreateUserDto): Promise<UserDto> {
    // Check if user exists
    const existingUser = await this.userRepository.findByEmail(createUserDto.email);
    if (existingUser) {
      throw new AppError('User already exists', 409);
    }

    // Create user
    const user = await this.userRepository.create(createUserDto);
    
    // Transform to DTO
    return this.toUserDto(user);
  }

  async getUserById(id: string): Promise<UserDto> {
    const user = await this.userRepository.findById(id);
    if (!user) {
      throw new AppError('User not found', 404);
    }
    return this.toUserDto(user);
  }

  private toUserDto(user: any): UserDto {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt,
    };
  }
}
```

### **Repository Pattern**
```typescript
// src/modules/user/repository.ts
import { Database } from '../../shared/database/connection';
import { CreateUserDto, UserDto } from './types';

export class UserRepository {
  constructor(private db: Database) {}

  async create(createUserDto: CreateUserDto) {
    const query = `
      INSERT INTO users (email, name, password_hash)
      VALUES ($1, $2, $3)
      RETURNING *
    `;
    const values = [
      createUserDto.email,
      createUserDto.name,
      createUserDto.passwordHash,
    ];
    
    const result = await this.db.query(query, values);
    return result.rows[0];
  }

  async findById(id: string) {
    const query = 'SELECT * FROM users WHERE id = $1';
    const result = await this.db.query(query, [id]);
    return result.rows[0] || null;
  }

  async findByEmail(email: string) {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await this.db.query(query, [email]);
    return result.rows[0] || null;
  }
}
```

## 🎯 Tier Mapping

| Tier | Features | Complexity | Database | Testing |
|------|----------|------------|----------|---------|
| **MVP** | Basic CRUD, simple validation | Minimal | SQLite | Basic tests |
| **CORE** | Full auth, validation, middleware | Modular | PostgreSQL | Unit + Integration |
| **FULL** | Background jobs, monitoring | Enterprise | PostgreSQL + Redis | All tests + E2E |

## 📦 Package Organization

**Core Dependencies** (all tiers):
- `fastify` - Web framework
- `typescript` - Type system
- `zod` - Schema validation
- `@types/node` - Node types

**CORE Tier Additions**:
- `fastify-jwt` - JWT authentication
- `fastify-auth` - Auth middleware
- `pg` - PostgreSQL client
- `jest` - Testing framework
- `supertest` - HTTP testing
- `dotenv` - Environment variables

**FULL Tier Additions**:
- `bull` - Background jobs
- `redis` - Caching and queues
- `prom-client` - Metrics collection
- `winston` - Structured logging
- `graphql` - GraphQL support
- `apollo-server-fastify` - GraphQL server

## 🔧 Configuration Pattern

### **TypeScript Configuration**
```json
// tsconfig.json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

### **Environment Configuration**
```typescript
// src/core/config/index.ts
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).default(3000),
  DATABASE_URL: z.string(),
  JWT_SECRET: z.string(),
  REDIS_URL: z.string().optional(),
});

export const config = envSchema.parse(process.env);

export type Config = z.infer<typeof envSchema>;
```

## 🧪 Testing Structure

### **Jest Configuration**
```javascript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts',
  ],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
};
```

### **Test Setup**
```typescript
// tests/setup.ts
import { fastify } from 'fastify';

// Global test setup
beforeAll(async () => {
  // Setup test database
  // Setup test Redis
});

afterAll(async () => {
  // Cleanup test database
  // Cleanup test Redis
});

// Test utilities
export const createTestApp = () => {
  const app = fastify();
  // Register test routes
  return app;
};
```

---
*TypeScript/Node Project Structure Template - Follow this pattern for consistent Node services*
