# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: node template utilities
# Tier: base
# Stack: node
# Category: template

# Node.js Package Management Patterns

## Purpose
Comprehensive guide to Node.js package management, including npm, yarn, pnpm, dependency management, and distribution strategies.

## Core Package Management

### 1. npm Fundamentals
```bash
# Initialize new project
npm init
npm init -y  # Skip questions

# Install packages
npm install express          # Install and save to dependencies
npm install express --save   # Explicitly save to dependencies
npm install express --save-dev  # Save to devDependencies
npm install express --global  # Install globally

# Install specific version
npm install express@4.18.0
npm install express@^4.18.0  # Caret range
npm install express@~4.18.0  # Tilde range

# Install from git
npm install git+https://github.com/user/repo.git
npm install user/repo#branch

# Remove packages
npm uninstall express
npm uninstall express --save-dev
```

### 2. package.json Structure
```json
{
  "name": "my-node-project",
  "version": "1.0.0",
  "description": "A Node.js project",
  "main": "src/index.js",
  "type": "module",  // Enable ES modules
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint src/",
    "lint:fix": "eslint src/ --fix",
    "format": "prettier --write src/",
    "build": "webpack --mode production",
    "clean": "rm -rf dist/",
    "prepublishOnly": "npm run build && npm test"
  },
  "keywords": ["node", "javascript", "api"],
  "author": "Your Name <your.email@example.com>",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/yourusername/my-node-project.git"
  },
  "bugs": {
    "url": "https://github.com/yourusername/my-node-project/issues"
  },
  "homepage": "https://github.com/yourusername/my-node-project#readme",
  "engines": {
    "node": ">=14.0.0",
    "npm": ">=6.0.0"
  },
  "dependencies": {
    "express": "^4.18.0",
    "mongoose": "^7.0.0",
    "jsonwebtoken": "^9.0.0",
    "bcryptjs": "^2.4.3"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "nodemon": "^2.0.0",
    "eslint": "^8.0.0",
    "prettier": "^2.8.0",
    "supertest": "^6.3.0"
  },
  "peerDependencies": {
    "react": ">=16.0.0"
  },
  "optionalDependencies": {
    "bufferutil": "^4.0.0"
  },
  "bundledDependencies": [
    "lodash"
  ]
}
```

### 3. Semantic Versioning
```json
{
  "dependencies": {
    "express": "^4.18.0",    // >=4.18.0 <5.0.0
    "lodash": "~4.17.21",    // >=4.17.21 <4.18.0
    "moment": "2.29.4",      // Exact version
    "axios": ">=0.21.0 <1.0.0",  // Range
    "react": "16.x || 17.x"   // Multiple ranges
  }
}
```

## Modern Package Managers

### 1. Yarn Configuration
```bash
# Install yarn
npm install -g yarn

# Initialize project
yarn init
yarn init -y

# Install packages
yarn add express
yarn add express --dev
yarn global add nodemon

# Remove packages
yarn remove express

# Update packages
yarn upgrade
yarn upgrade express

# Install from package.json
yarn install
yarn install --production  # Only dependencies
```

### 2. Yarn Workspaces
```json
// package.json (root)
{
  "name": "my-monorepo",
  "private": true,
  "workspaces": [
    "packages/*",
    "apps/*"
  ],
  "scripts": {
    "build": "yarn workspaces run build",
    "test": "yarn workspaces run test",
    "clean": "yarn workspaces run clean"
  }
}
```

```bash
# Add dependency to all workspaces
yarn add lodash --workspace

# Add dependency to specific workspace
yarn workspace @myorg/api add express

# Run script in all workspaces
yarn workspaces run test

# Run script in specific workspace
yarn workspace @myorg/api run dev
```

### 3. pnpm Configuration
```bash
# Install pnpm
npm install -g pnpm

# Basic commands
pnpm install
pnpm add express
pnpm add express --save-dev
pnpm remove express

# pnpm workspaces
pnpm add express --filter @myorg/api
pnpm run build --filter @myorg/api
```

```json
// pnpm-workspace.yaml
packages:
  - 'packages/*'
  - 'apps/*'
```

## Dependency Management

### 1. Lock Files and Reproducibility
```bash
# npm lock file (package-lock.json)
npm ci  # Install exact versions from lock file

# Yarn lock file (yarn.lock)
yarn install --frozen-lockfile

# pnpm lock file (pnpm-lock.yaml)
pnpm install --frozen-lockfile
```

### 2. Dependency Auditing
```bash
# Check for vulnerabilities
npm audit
npm audit fix
npm audit fix --force  # Force fix (may break dependencies)

# Yarn audit
yarn audit
yarn audit --level moderate

# pnpm audit
pnpm audit
pnpm audit --fix
```

### 3. Dependency Updates
```bash
# Check outdated packages
npm outdated
yarn outdated
pnpm outdated

# Update packages
npm update
yarn upgrade
pnpm update

# Update to latest versions
npm install package@latest
yarn add package@latest
pnpm add package@latest

# Interactive update
npm-check-updates
yarn upgrade-interactive --latest
```

## Private Packages and Registries

### 1. Private npm Registry
```bash
# Configure registry
npm config set registry https://registry.mycompany.com/
npm config set @mycompany:registry https://registry.mycompany.com/

# Login to private registry
npm login --registry=https://registry.mycompany.com/

# Install from private registry
npm install @mycompany/private-package

# Publish to private registry
npm publish --registry=https://registry.mycompany.com/
```

```bash
# .npmrc configuration
registry=https://registry.mycompany.com/
@mycompany:registry=https://registry.mycompany.com/
//registry.mycompany.com/:_authToken=${NPM_TOKEN}
//registry.mycompany.com/:always-auth=true
```

### 2. GitHub Packages
```bash
# Configure GitHub packages registry
npm config set @myorg:registry https://npm.pkg.github.com/
npm config set //npm.pkg.github.com/:_authToken ${GITHUB_TOKEN}

# Publish to GitHub packages
npm publish

# Install from GitHub packages
npm install @myorg/my-package
```

```json
// package.json
{
  "publishConfig": {
    "registry": "https://npm.pkg.github.com/"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/myorg/my-package.git"
  }
}
```

### 3. Verdaccio (Private npm Registry)
```bash
# Install verdaccio
npm install -g verdaccio

# Start verdaccio
verdaccio

# Configure local registry
npm config set registry http://localhost:4873/

# Publish to local registry
npm publish

# Install from local registry
npm install my-package
```

## Package Publishing

### 1. Publishing to npm
```bash
# Prepare for publishing
npm version patch  # 1.0.0 -> 1.0.1
npm version minor  # 1.0.1 -> 1.1.0
npm version major  # 1.1.0 -> 2.0.0

# Publish package
npm publish
npm publish --tag beta  # Publish with tag
npm publish --dry-run   # Test publishing

# Unpublish package
npm unpublish my-package
npm unpublish my-package@1.0.0  # Specific version
```

### 2. Package Configuration for Publishing
```json
{
  "name": "@myorg/my-package",
  "version": "1.0.0",
  "description": "My awesome package",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "files": [
    "dist/",
    "README.md",
    "LICENSE"
  ],
  "scripts": {
    "prepublishOnly": "npm run build && npm test",
    "build": "tsc",
    "test": "jest"
  },
  "publishConfig": {
    "access": "public"  // or "restricted" for private scoped packages
  },
  "keywords": ["javascript", "node", "library"],
  "repository": {
    "type": "git",
    "url": "https://github.com/myorg/my-package.git"
  }
}
```

### 3. Multi-platform Publishing
```json
{
  "main": "dist/index.js",
  "browser": "dist/browser.js",
  "module": "dist/index.esm.js",
  "types": "dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.esm.js",
      "require": "./dist/index.js",
      "types": "./dist/index.d.ts"
    },
    "./browser": {
      "import": "./dist/browser.esm.js",
      "require": "./dist/browser.js"
    }
  },
  "files": [
    "dist/",
    "README.md"
  ]
}
```

## Development Workflow

### 1. Scripts and Automation
```json
{
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon --exec 'npm run lint && node src/index.js'",
    "build": "npm run clean && npm run build:dist && npm run build:types",
    "build:dist": "webpack --mode production",
    "build:types": "tsc --emitDeclarationOnly",
    "clean": "rimraf dist/",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint src/**/*.js",
    "lint:fix": "eslint src/**/*.js --fix",
    "format": "prettier --write src/**/*.js",
    "format:check": "prettier --check src/**/*.js",
    "precommit": "lint-staged",
    "prepush": "npm test",
    "preversion": "npm run lint && npm test",
    "version": "npm run build && git add -A dist",
    "postversion": "git push && git push --tags"
  }
}
```

### 2. Husky and Git Hooks
```bash
# Install husky
npm install husky --save-dev

# Initialize husky
npx husky install
npm pkg set scripts.prepare="husky install"

# Add hooks
npx husky add .husky/pre-commit "npm run precommit"
npx husky add .husky/pre-push "npm run prepush"
npx husky add .husky/commit-msg "commitlint --edit $1"
```

```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged",
      "pre-push": "npm test",
      "commit-msg": "commitlint -E HUSKY_GIT_PARAMS"
    }
  },
  "lint-staged": {
    "*.js": ["eslint --fix", "prettier --write", "git add"]
  }
}
```

### 3. Docker Integration
```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./
COPY pnpm-lock.yaml ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY . .

# Build application
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

USER nodejs

EXPOSE 3000

CMD ["npm", "start"]
```

```dockerfile
# Dockerfile.dev (for development)
FROM node:18-alpine

WORKDIR /app

# Install dev dependencies
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev"]
```

## Security Best Practices

### 1. Security Configuration
```json
{
  "engines": {
    "node": ">=14.0.0",
    "npm": ">=6.0.0"
  },
  "scripts": {
    "security:audit": "npm audit",
    "security:fix": "npm audit fix",
    "security:check": "npm audit --audit-level moderate"
  }
}
```

### 2. .npmignore for Security
```
# .npmignore
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Dependency directories
node_modules/

# Build outputs
dist/
build/

# IDE files
.vscode/
.idea/

# OS files
.DS_Store
Thumbs.db

# Test files
test/
tests/
**/*.test.js
**/*.spec.js

# Documentation
docs/
*.md
!README.md
```

### 3. Environment Variable Management
```javascript
// config/index.js
const dotenv = require('dotenv');
const path = require('path');

// Load environment-specific .env file
const env = process.env.NODE_ENV || 'development';
dotenv.config({ path: path.resolve(process.cwd(), `.env.${env}`) });

// Fallback to default .env
dotenv.config();

const config = {
  port: process.env.PORT || 3000,
  database: {
    url: process.env.DATABASE_URL,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    name: process.env.DB_NAME,
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
  },
  redis: {
    url: process.env.REDIS_URL,
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
  cors: {
    origin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'],
  },
};

// Validate required environment variables
const requiredEnvVars = ['DATABASE_URL', 'JWT_SECRET'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
}

module.exports = config;
```

## Performance Optimization

### 1. Bundle Size Optimization
```json
{
  "scripts": {
    "build": "webpack --mode production",
    "build:analyze": "webpack-bundle-analyzer dist/stats.json",
    "build:profile": "webpack --profile --json > dist/stats.json"
  },
  "sideEffects": [
    "*.css",
    "*.scss"
  ],
  "dependencies": {
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "lodash-webpack-plugin": "^0.11.6",
    "webpack-bundle-analyzer": "^4.7.0"
  }
}
```

### 2. Tree Shaking Configuration
```javascript
// webpack.config.js
module.exports = {
  mode: 'production',
  optimization: {
    usedExports: true,
    sideEffects: false,
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', {
                modules: false,
                useBuiltIns: 'usage',
                corejs: 3,
              }]
            ]
          }
        }
      }
    ]
  }
};
```

## Troubleshooting

### 1. Common Issues
```bash
# Clear npm cache
npm cache clean --force

# Remove node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Fix permission issues
sudo chown -R $(whoami) ~/.npm
sudo chown -R $(whoami) node_modules

# Check npm configuration
npm config list
npm config get registry
npm config delete proxy
npm config delete https-proxy
```

### 2. Dependency Conflicts
```bash
# Check for conflicts
npm ls
npm ls express

# Resolve conflicts
npm install express@4.18.0 --save-exact
npm dedupe

# Use npm-check-updates for interactive updates
npx npm-check-updates -u
npm install
```

### 3. Network Issues
```bash
# Use different registry
npm config set registry https://registry.npmjs.org/

# Use proxy
npm config set proxy http://proxy.company.com:8080
npm config set https-proxy http://proxy.company.com:8080

# Use npm mirror
npm config set registry https://mirrors.cloud.tencent.com/npm/
```

## Best Practices

### 1. Dependency Management
```json
{
  "dependencies": {
    // Production dependencies only
    "express": "^4.18.0",
    "mongoose": "^7.0.0"
  },
  "devDependencies": {
    // Development tools
    "jest": "^29.0.0",
    "eslint": "^8.0.0",
    "nodemon": "^2.0.0"
  },
  "peerDependencies": {
    // Host application dependencies
    "react": ">=16.0.0"
  },
  "optionalDependencies": {
    // Optional platform-specific dependencies
    "bufferutil": "^4.0.0"
  }
}
```

### 2. Version Management
```bash
# Use semantic versioning
npm version patch  # Bug fixes
npm version minor  # New features
npm version major  # Breaking changes

# Use pre-release versions for testing
npm version prerelease --preid=beta
npm version prerelease --preid=alpha

# Tag releases
git tag v1.0.0
git push origin v1.0.0
```

### 3. Documentation
```json
{
  "description": "A comprehensive Node.js package for data processing",
  "keywords": ["node", "data", "processing", "stream"],
  "readme": "README.md",
  "homepage": "https://github.com/yourorg/package#readme",
  "bugs": {
    "url": "https://github.com/yourorg/package/issues"
  },
  "repository": {
    "type": "git",
    "url": "git+https://github.com/yourorg/package.git"
  }
}
```

This comprehensive package management guide covers all aspects of Node.js dependency management from basic npm usage to modern tools like yarn and pnpm, including security, performance, and best practices.
