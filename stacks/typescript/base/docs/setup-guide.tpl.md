# Universal Template System - Typescript Stack
# Generated: 2025-12-10
# Purpose: typescript template utilities
# Tier: base
# Stack: typescript
# Category: template

# TypeScript Stack Setup Guide

> **Complete setup instructions for TypeScript applications with modern tooling and best practices**

## 📋 Prerequisites

### Required Software
- **Node.js 18.0+** - JavaScript runtime environment
- **npm 8.0+** or **yarn 1.22+** - Package manager
- **Git** - Version control (optional but recommended)

### Development Tools (Recommended)
- **Visual Studio Code** - Code editor with excellent TypeScript support
- **TypeScript Extension** - VS Code extension for enhanced TypeScript features
- **ESLint Extension** - Code linting and formatting
- **Prettier Extension** - Code formatting

## 🚀 Quick Setup

### 1. Initialize Project

```bash
# Create new project directory
mkdir my-typescript-app
cd my-typescript-app

# Initialize npm project
npm init -y

# or with yarn
yarn init -y
```

### 2. Install TypeScript Dependencies

```bash
# Install TypeScript and core dependencies
npm install typescript ts-node-dev @types/node

# Install with yarn
yarn add typescript ts-node-dev @types/node
```

### 3. Install Framework Dependencies

```bash
# Install Express.js and type definitions
npm install express cors helmet dotenv
npm install -D @types/express @types/cors

# Install with yarn
yarn add express cors helmet dotenv
yarn add -D @types/express @types/cors
```

### 4. Install Development Dependencies

```bash
# Install testing and linting tools
npm install -D jest @types/jest ts-jest eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin

# Install with yarn
yarn add -D jest @types/jest ts-jest eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin
```

### 5. Create Configuration Files

```bash
# Create TypeScript configuration
npx tsc --init

# Create Jest configuration
npx jest --init

# Create ESLint configuration
npx eslint --init
```

## ⚙️ Configuration Setup

### TypeScript Configuration (tsconfig.json)

```json
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
    "removeComments": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "noImplicitThis": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "moduleResolution": "node",
    "baseUrl": "./",
    "paths": {
      "@/*": ["src/*"]
    },
    "allowSyntheticDefaultImports": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,
    "incremental": true,
    "tsBuildInfoFile": ".tsbuildinfo"
  },
  "include": [
    "src/**/*"
  ],
  "exclude": [
    "node_modules",
    "dist",
    "**/*.test.ts",
    "**/*.spec.ts"
  ]
}
```

### Package.json Scripts

```json
{
  "name": "my-typescript-app",
  "version": "1.0.0",
  "description": "TypeScript application",
  "main": "dist/index.js",
  "scripts": {
    "build": "tsc",
    "start": "node dist/index.js",
    "dev": "ts-node-dev --respawn --transpile-only src/index.ts",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "type-check": "tsc --noEmit",
    "clean": "rimraf dist",
    "prebuild": "npm run clean",
    "prestart": "npm run build"
  },
  "dependencies": {
    "express": "^4.18.0",
    "cors": "^2.8.5",
    "helmet": "^6.0.0",
    "dotenv": "^16.0.0"
  },
  "devDependencies": {
    "@types/node": "^18.0.0",
    "@types/express": "^4.17.0",
    "@types/cors": "^2.8.0",
    "@types/jest": "^29.0.0",
    "@typescript-eslint/eslint-plugin": "^5.0.0",
    "@typescript-eslint/parser": "^5.0.0",
    "eslint": "^8.0.0",
    "jest": "^29.0.0",
    "ts-jest": "^29.0.0",
    "ts-node-dev": "^2.0.0",
    "typescript": "^4.9.0",
    "rimraf": "^3.0.0"
  }
}
```

### Jest Configuration (jest.config.js)

```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  setupFilesAfterEnv: ['<rootDir>/src/test/setup.ts'],
};
```

### ESLint Configuration (.eslintrc.js)

```javascript
module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: 'tsconfig.json',
    tsconfigRootDir: __dirname,
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint/eslint-plugin'],
  extends: [
    'eslint:recommended',
    '@typescript-eslint/recommended',
    '@typescript-eslint/recommended-requiring-type-checking',
  ],
  root: true,
  env: {
    node: true,
    jest: true,
  },
  ignorePatterns: ['.eslintrc.js', 'dist/**/*'],
  rules: {
    '@typescript-eslint/interface-name-prefix': 'off',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-unused-vars': 'error',
    '@typescript-eslint/prefer-const': 'error',
  },
};
```

## 📁 Project Structure Setup

### Create Directory Structure

```bash
# Create main directories
mkdir -p src/{controllers,services,models,middleware,utils,types}
mkdir -p src/{routes,test}
mkdir -p tests/{unit,integration}
mkdir -p logs
mkdir -p docs

# Create initial files
touch src/index.ts
touch src/app.ts
touch src/server.ts
touch src/test/setup.ts
```

### Basic Application Files

**src/index.ts** (Entry Point)
```typescript
import { createServer } from './server';

const PORT = process.env.PORT || 3000;

async function startServer(): Promise<void> {
  try {
    const server = await createServer();
    server.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
```

**src/app.ts** (Express Application)
```typescript
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { errorHandler } from './middleware/errorHandler';
import { requestLogger } from './middleware/requestLogger';

export function createApp(): express.Application {
  const app = express();

  // Security middleware
  app.use(helmet());
  app.use(cors());

  // Body parsing
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Logging
  app.use(requestLogger);

  // Routes will be added here
  // app.use('/api', routes);

  // Error handling
  app.use(errorHandler);

  return app;
}
```

**src/server.ts** (Server Creation)
```typescript
import { createApp } from './app';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

export async function createServer(): Promise<express.Application> {
  const app = createApp();
  return app;
}
```

## 🔧 Environment Setup

### Environment Variables (.env)

```bash
# Application
NODE_ENV=development
PORT=3000
DEBUG=true

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=typescript_app
DB_USERNAME=postgres
DB_PASSWORD=password
DB_SSL=false

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRES_IN=1h
JWT_ISSUER=typescript-app
JWT_AUDIENCE=typescript-users

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
LOG_FILE_ENABLED=true
LOG_FILE_PATH=./logs/app.log
```

### Environment-Specific Files

```bash
# .env.development
NODE_ENV=development
DEBUG=true
LOG_LEVEL=debug

# .env.production
NODE_ENV=production
DEBUG=false
LOG_LEVEL=info

# .env.test
NODE_ENV=test
DEBUG=false
LOG_LEVEL=error
```

## 🧪 Testing Setup

### Test Configuration

**src/test/setup.ts**
```typescript
import 'jest';

// Global test setup
beforeAll(() => {
  // Set test environment variables
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'test-secret';
});

afterAll(() => {
  // Cleanup after tests
});

// Mock console methods in tests
global.console = {
  ...console,
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
};
```

### Example Test Files

**tests/unit/app.test.ts**
```typescript
import request from 'supertest';
import { createApp } from '../../src/app';

describe('Application', () => {
  let app: express.Application;

  beforeEach(() => {
    app = createApp();
  });

  it('should create Express application', () => {
    expect(app).toBeDefined();
    expect(app.use).toBeDefined();
  });

  it('should respond to health check', async () => {
    // Add health check route for testing
    app.get('/health', (req, res) => {
      res.json({ status: 'ok' });
    });

    const response = await request(app)
      .get('/health')
      .expect(200);

    expect(response.body.status).toBe('ok');
  });
});
```

## 🔒 Security Setup

### Security Middleware

**src/middleware/security.ts**
```typescript
import helmet from 'helmet';
import cors from 'cors';

export const securityMiddleware = [
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
  }),
  cors({
    origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
  }),
];
```

### Authentication Setup

**src/middleware/auth.ts**
```typescript
import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    roles: string[];
  };
}

export const authenticateToken = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'Access token required' });
    return;
  }

  jwt.verify(token, process.env.JWT_SECRET!, (err, user) => {
    if (err) {
      res.status(403).json({ error: 'Invalid token' });
      return;
    }

    req.user = user as any;
    next();
  });
};
```

## 📊 Development Workflow

### VS Code Configuration

**.vscode/settings.json**
```json
{
  "typescript.preferences.importModuleSpecifier": "relative",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  },
  "files.exclude": {
    "**/node_modules": true,
    "**/dist": true,
    "**/.git": true,
    "**/.DS_Store": true
  }
}
```

**.vscode/launch.json**
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug TypeScript",
      "type": "node",
      "request": "launch",
      "program": "${workspaceFolder}/src/index.ts",
      "outFiles": ["${workspaceFolder}/dist/**/*.js"],
      "runtimeArgs": ["-r", "ts-node/register"],
      "env": {
        "NODE_ENV": "development"
      }
    }
  ]
}
```

### Git Configuration

**.gitignore**
```gitignore
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Build outputs
dist/
build/

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Logs
logs/
*.log

# Runtime data
pids/
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/
*.lcov

# TypeScript
*.tsbuildinfo

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
```

## 🚀 Deployment Setup

### Production Build

```bash
# Build for production
npm run build

# Start production server
npm start
```

### Docker Configuration

**Dockerfile**
```dockerfile
# Multi-stage build
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Production stage
FROM node:18-alpine AS production

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

EXPOSE 3000

USER node

CMD ["node", "dist/index.js"]
```

**docker-compose.yml**
```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    volumes:
      - ./logs:/app/logs
    depends_on:
      - db

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: typescript_app
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

## 🔧 Common Issues & Solutions

### TypeScript Compilation Issues

**Problem**: `Cannot find module 'express'`
```bash
# Solution: Install type definitions
npm install -D @types/express
```

**Problem**: `Implicit 'any' type errors`
```json
// Solution: Update tsconfig.json
{
  "compilerOptions": {
    "noImplicitAny": false, // Temporarily disable
    "strict": false         // Gradually enable strict mode
  }
}
```

### Development Server Issues

**Problem**: Hot reloading not working
```bash
# Solution: Use ts-node-dev with correct flags
npm run dev -- --respawn --transpile-only --ignore-watch node_modules
```

**Problem**: Port already in use
```bash
# Solution: Kill process on port
npx kill-port 3000
# or use different port
PORT=3001 npm run dev
```

### Testing Issues

**Problem**: Jest cannot find TypeScript files
```bash
# Solution: Configure jest correctly
npx ts-jest config:init
```

**Problem**: Type errors in test files
```bash
# Solution: Create test type definitions
// src/test/types.ts
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeTypeOf(expected: string): R;
    }
  }
}
```

## 📚 Learning Resources

### Official Documentation
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Express.js TypeScript Guide](https://expressjs.com/en/guide/)
- [Jest TypeScript Documentation](https://jestjs.io/docs/getting-started#using-typescript)

### Recommended Courses
- TypeScript: Modern JavaScript Development
- Node.js with TypeScript: Build Production-Ready Apps
- Advanced TypeScript Patterns and Techniques

### Community Resources
- [TypeScript Discord](https://discord.gg/typescript)
- [Stack Overflow TypeScript Tag](https://stackoverflow.com/questions/tagged/typescript)
- [Reddit r/TypeScript](https://www.reddit.com/r/TypeScript/)

## 🆘 Getting Help

### Debug Mode

```bash
# Enable verbose logging
DEBUG=* npm run dev

# TypeScript compilation details
npx tsc --listFiles --diagnostics
```

### Common Commands

```bash
# Check TypeScript version
npx tsc --version

# Validate configuration
npx tsc --noEmit

# Update dependencies
npm update

# Clean build artifacts
npm run clean
```

---

## 🎯 Next Steps

1. **Add Database Integration**: Set up PostgreSQL or MongoDB with TypeScript
2. **Implement Authentication**: Add JWT-based authentication system
3. **Add API Routes**: Create RESTful API endpoints
4. **Set up CI/CD**: Configure GitHub Actions or similar
5. **Add Monitoring**: Implement logging and monitoring
6. **Write Tests**: Add comprehensive test coverage

---

**Happy coding with TypeScript!** 🚀

*Setup Guide Version: [[.Version]]*  
*Author: [[.Author]]*  
*Date: [[.Date]]*
