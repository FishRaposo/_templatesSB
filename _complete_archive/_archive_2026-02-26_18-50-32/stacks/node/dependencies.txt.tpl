#!/usr/bin/env node
/**
 * Node.js Stack Dependencies Template
 * Complete package management and tooling configurations for Node.js projects
 */

// ====================
// PACKAGE.JSON CONFIGURATION
// ====================

{
  "name": "{{PROJECT_NAME}}",
  "version": "1.0.0",
  "description": "{{PROJECT_DESCRIPTION}}",
  "main": "dist/index.js",
  "scripts": {
    // Development Scripts
    "dev": "nodemon --exec ts-node src/index.ts",
    "dev:watch": "nodemon src/index.ts",
    "start": "node dist/index.js",
    "build": "tsc && npm run build:copy-assets",
    "build:copy-assets": "cp -r src/assets dist/assets 2>/dev/null || true",
    "build:prod": "npm run clean && npm run build && npm run prune:prod",
    
    // Testing Scripts
    "test": "jest --coverage",
    "test:watch": "jest --watch",
    "test:unit": "jest --testPathPattern=unit/",
    "test:integration": "jest --testPathPattern=integration/",
    "test:e2e": "jest --testPathPattern=e2e/ --runInBand",
    "test:ci": "jest --ci --coverage --maxWorkers=2",
    
    // Linting and Formatting
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "format": "prettier --write \"src/**/*.{ts,js,json,md}\"",
    "format:check": "prettier --check \"src/**/*.{ts,js,json,md}\"",
    
    // Code Quality
    "type-check": "tsc --noEmit",
    "security-audit": "npm audit && npm audit --audit-level=moderate",
    "validate": "npm run type-check && npm run lint && npm run format:check && npm run security-audit",
    
    // Database
    "db:migrate": "prisma migrate deploy",
    "db:generate": "prisma generate",
    "db:seed": "ts-node prisma/seed.ts",
    
    // Utilities
    "clean": "rm -rf dist/ coverage/",
    "prune:prod": "npm prune --production",
    "docker:build": "docker build -t {{PROJECT_NAME}}:latest .",
    "docker:run": "docker run -p 3000:3000 {{PROJECT_NAME}}:latest",
    "compose:up": "docker-compose up -d",
    "compose:down": "docker-compose down",
    "health": "curl -f http://localhost:3000/health || exit 1"
  },
  "keywords": [
    "node.js",
    "typescript",
    "api",
    "backend"
  ],
  "author": "{{AUTHOR_NAME}}",
  "license": "MIT",
  
  // ====================
  // PRODUCTION DEPENDENCIES
  // ====================
  "dependencies": {
    // Web Framework
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "compression": "^1.7.4",
    "morgan": "^1.10.0",
    
    // TypeScript Support
    "@types/express": "^4.17.21",
    "@types/cors": "^2.8.17",
    "@types/compression": "^1.7.5",
    "@types/morgan": "^1.9.9",
    "@types/node": "^20.8.0",
    
    // Validation
    "zod": "^3.22.4",
    "class-validator": "^0.14.0",
    "class-transformer": "^0.5.1",
    
    // Authentication & Security
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "passport": "^0.6.0",
    "passport-jwt": "^4.0.1",
    "passport-local": "^1.0.0",
    "express-rate-limit": "^7.1.5",
    "express-validator": "^7.0.1",
    
    // Database & ORM
    "prisma": "^5.6.0",
    "@prisma/client": "^5.6.0",
    "redis": "^4.6.10",
    "ioredis": "^5.3.2",
    
    // Background Jobs
    "bull": "^4.11.5",
    "bullmq": "^4.14.0",
    "agenda": "^5.0.0",
    
    // Monitoring & Observability
    "prom-client": "^15.0.0",
    "winston": "^3.11.0",
    "@opentelemetry/api": "^1.7.0",
    "@opentelemetry/sdk-node": "^0.45.0",
    "@opentelemetry/auto-instrumentations-node": "^0.40.0",
    
    // Utilities
    "dotenv": "^16.3.1",
    "dayjs": "^1.11.10",
    "lodash": "^4.17.21",
    "axios": "^1.6.0",
    "joi": "^17.11.0",
    "uuid": "^9.0.1",
    "node-cron": "^3.0.3",
    
    // API Documentation
    "swagger-jsdoc": "^6.2.8",
    "swagger-ui-express": "^5.0.0",
    
    // File Processing
    "multer": "^1.4.5-lts.1",
    "csv-parser": "^3.0.0"
  },
  
  // ====================
  // DEVELOPMENT DEPENDENCIES
  // ====================
  "devDependencies": {
    // TypeScript
    "typescript": "^5.2.2",
    "ts-node": "^10.9.1",
    "tsconfig-paths": "^4.2.0",
    
    // Testing Framework
    "jest": "^29.7.0",
    "@types/jest": "^29.5.8",
    "ts-jest": "^29.1.1",
    "@jest/globals": "^29.7.0",
    
    // Testing Utilities
    "supertest": "^6.3.3",
    "@types/supertest": "^2.0.16",
    "jest-mock-extended": "^3.0.5",
    "mongodb-memory-server": "^9.0.0",
    
    // Linting & Formatting
    "eslint": "^8.52.0",
    "@typescript-eslint/eslint-plugin": "^6.9.1",
    "@typescript-eslint/parser": "^6.9.1",
    "prettier": "^3.0.3",
    "@types/prettier": "^3.0.0",
    "eslint-config-prettier": "^9.0.0",
    "eslint-plugin-prettier": "^5.0.1",
    
    // Code Quality
    "@types/bcryptjs": "^2.4.6",
    "@types/jsonwebtoken": "^9.0.5",
    "@types/lodash": "^4.14.201",
    "@types/uuid": "^9.0.7",
    
    // Development Tools
    "nodemon": "^3.0.1",
    "concurrently": "^8.2.2",
    "rimraf": "^5.0.5",
    
    // Documentation
    "@apidevtools/swagger-parser": "^10.1.0",
    "@types/swagger-jsdoc": "^6.0.4"
  },
  
  // ====================
  // JEST CONFIGURATION
  // ====================
  "jest": {
    "preset": "ts-jest",
    "testEnvironment": "node",
    "roots": ["<rootDir>/src", "<rootDir>/tests"],
    "testMatch": [
      "**/__tests__/**/*.ts",
      "**/?(*.)+(spec|test).ts"
    ],
    "transform": {
      "^.+\\.ts$": "ts-jest"
    },
    "collectCoverageFrom": [
      "src/**/*.ts",
      "!src/**/*.d.ts",
      "!src/**/*.test.ts",
      "!src/**/__tests__/**"
    ],
    "coverageDirectory": "coverage",
    "coverageReporters": [
      "text",
      "lcov",
      "html"
    ],
    "coverageThreshold": {
      "global": {
        "branches": 80,
        "functions": 80,
        "lines": 80,
        "statements": 80
      }
    },
    "setupFilesAfterEnv": ["<rootDir>/tests/setup.ts"],
    "testTimeout": 10000,
    "verbose": true
  },
  
  // ====================
  // ESLINT CONFIGURATION
  // ====================
  
  // Create .eslintrc.js separately with:
  /*
  module.exports = {
    parser: '@typescript-eslint/parser',
    extends: [
      'eslint:recommended',
      '@typescript-eslint/recommended',
      'prettier'
    ],
    plugins: ['@typescript-eslint', 'prettier'],
    parserOptions: {
      ecmaVersion: 2021,
      sourceType: 'module'
    },
    rules: {
      'prettier/prettier': 'error',
      '@typescript-eslint/no-unused-vars': 'error',
      '@typescript-eslint/explicit-function-return-type': 'warn'
    },
    env: {
      node: true,
      jest: true
    }
  };
  */
  
  // ====================
  // PRETTIER CONFIGURATION
  // ====================
  
  // Create .prettierrc with:
  /*
  {
    "semi": true,
    "trailingComma": "es5",
    "singleQuote": true,
    "printWidth": 100,
    "tabWidth": 2,
    "useTabs": false
  }
  */
  
  // ====================
  // TSCONFIG CONFIGURATION
  // ====================
  
  // Create tsconfig.json with:
  /*
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
      "types": ["node", "jest"]
    },
    "include": ["src/**/*"],
    "exclude": ["node_modules", "dist", "tests"]
  }
  */
  
  // ====================
  // DOCKER INSTRUCTIONS
  // ====================
  
  // Create Dockerfile with:
  /*
  # Multi-stage build for optimization
  FROM node:20-alpine AS builder
  
  WORKDIR /app
  COPY package*.json ./
  RUN npm ci --only=production
  
  COPY . .
  RUN npm run build
  
  # Production stage
  FROM node:20-alpine AS production
  
  WORKDIR /app
  COPY --from=builder /app/dist ./dist
  COPY --from=builder /app/node_modules ./node_modules
  COPY --from=builder /app/package*.json ./
  
  USER node
  EXPOSE 3000
  
  HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"
  
  CMD ["npm", "start"]
  */
  
  // ====================
  // DOCKER COMPOSE
  // ====================
  
  // Create docker-compose.yml with:
  /*
  version: '3.8'
  
  services:
    app:
      build: .
      ports:
        - "3000:3000"
      environment:
        - NODE_ENV=production
        - DATABASE_URL=postgresql://user:password@db:5432/mydb
        - REDIS_URL=redis://redis:6379
      depends_on:
        - db
        - redis
      restart: unless-stopped
    
    db:
      image: postgres:15-alpine
      environment:
        POSTGRES_USER: user
        POSTGRES_PASSWORD: password
        POSTGRES_DB: mydb
      volumes:
        - postgres_data:/var/lib/postgresql/data
      ports:
        - "5432:5432"
    
    redis:
      image: redis:7-alpine
      ports:
        - "6379:6379"
      volumes:
        - redis_data:/data
  
  volumes:
    postgres_data:
    redis_data:
  */
  
  // ====================
  // DEVELOPMENT WORKFLOW
  // ====================
  
  /*
  1. Initial Setup:
     npm install
     npx prisma generate
     npm run db:migrate
  
  2. Development:
     npm run dev
  
  3. Testing:
     npm test
     npm run test:watch
  
  4. Code Quality:
     npm run validate
  
  5. Build:
     npm run build
  
  6. Production:
     npm run build:prod
     npm start
  */
  
  // ====================
  // SECURITY BEST PRACTICES
  // ====================
  
  /*
  - Use helmet for security headers
  - Implement rate limiting
  - Validate all inputs with express-validator
  - Use bcrypt for password hashing
  - Implement JWT authentication
  - Sanitize user inputs
  - Keep dependencies updated
  - Run npm audit regularly
  - Use environment variables for secrets
  - Implement CORS properly
  */
  
  // ====================
  // TROUBLESHOOTING
  // ====================
  
  /*
  If TypeScript compilation errors:
   - Check tsconfig.json compilerOptions
   - Ensure @types packages are installed
   - Run npm run type-check for detailed errors
  
  If Jest tests fail:
   - Check jest.config.js settings
   - Ensure ts-jest is properly configured
   - Run with --verbose flag for details
  
  If ESLint shows errors:
   - Run npm run lint:fix to auto-fix
   - Check .eslintrc.js rules
  
  If Prisma issues:
   - Run npx prisma generate
   - Check DATABASE_URL in .env
  */
}
