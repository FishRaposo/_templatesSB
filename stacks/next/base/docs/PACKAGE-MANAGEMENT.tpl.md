# Universal Template System - Next Stack
# Generated: 2025-12-10
# Purpose: next template utilities
# Tier: base
# Stack: next
# Category: template

# Package Management Guide - Next.js

This guide covers package management strategies, dependency management, and best practices for Next.js applications.

## 📦 JavaScript Package Management

### Package Managers
- **npm** - Node Package Manager (default)
- **yarn** - Fast, reliable, and secure dependency management
- **pnpm** - Fast, disk space efficient package manager

### package.json Configuration
```json
{
  "name": "[PROJECT_NAME]",
  "version": "[VERSION]",
  "description": "[PROJECT_DESCRIPTION]",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "start": "next-scripts start",
    "build": "next-scripts build",
    "test": "next-scripts test",
    "test:coverage": "next-scripts test --coverage --watchAll=false",
    "test:e2e": "cypress run",
    "lint": "eslint src --ext .js,.jsx,.ts,.tsx",
    "lint:fix": "eslint src --ext .js,.jsx,.ts,.tsx --fix",
    "format": "prettier --write src/**/*.{js,jsx,ts,tsx,css,md}",
    "type-check": "tsc --noEmit",
    "analyze": "npm run build && npx webpack-bundle-analyzer build/static/js/*.js",
    "storybook": "start-storybook -p 6006",
    "build-storybook": "build-storybook"
  },
  "dependencies": {
    "next": "^[REACT_VERSION]",
    "next-dom": "^[REACT_VERSION]",
    "next-router-dom": "^[ROUTER_VERSION]",
    "axios": "^[AXIOS_VERSION]",
    "styled-components": "^[STYLED_COMPONENTS_VERSION]",
    "zustand": "^[ZUSTAND_VERSION]"
  },
  "devDependencies": {
    "@types/next": "^[REACT_TYPES_VERSION]",
    "@types/next-dom": "^[REACT_DOM_TYPES_VERSION]",
    "@testing-library/next": "^[TESTING_LIBRARY_VERSION]",
    "@testing-library/jest-dom": "^[JEST_DOM_VERSION]",
    "@testing-library/user-event": "^[USER_EVENT_VERSION]",
    "typescript": "^[TYPESCRIPT_VERSION]",
    "eslint": "^[ESLINT_VERSION]",
    "prettier": "^[PRETTIER_VERSION]",
    "cypress": "^[CYPRESS_VERSION]"
  },
  "engines": {
    "node": ">=[MIN_NODE_VERSION]",
    "npm": ">=[MIN_NPM_VERSION]"
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  }
}
```

## 🚀 Package Installation Commands

### npm Commands
```bash
# Install dependencies
npm install

# Add new dependency
npm install [PACKAGE_NAME]
npm install [PACKAGE_NAME]@[VERSION]

# Add dev dependency
npm install --save-dev [PACKAGE_NAME]
npm install -D [PACKAGE_NAME]

# Remove dependency
npm uninstall [PACKAGE_NAME]

# Update dependencies
npm update
npm update [PACKAGE_NAME]

# Check for outdated packages
npm outdated

# Audit for security vulnerabilities
npm audit
npm audit fix
```

### yarn Commands
```bash
# Install dependencies
yarn install

# Add new dependency
yarn add [PACKAGE_NAME]
yarn add [PACKAGE_NAME]@[VERSION]

# Add dev dependency
yarn add --dev [PACKAGE_NAME]
yarn add -D [PACKAGE_NAME]

# Remove dependency
yarn remove [PACKAGE_NAME]

# Update dependencies
yarn upgrade
yarn upgrade [PACKAGE_NAME]

# Check for outdated packages
yarn outdated

# Check for security vulnerabilities
yarn audit
yarn audit --level moderate
```

### pnpm Commands
```bash
# Install dependencies
pnpm install

# Add new dependency
pnpm add [PACKAGE_NAME]
pnpm add [PACKAGE_NAME]@[VERSION]

# Add dev dependency
pnpm add -D [PACKAGE_NAME]

# Remove dependency
pnpm remove [PACKAGE_NAME]

# Update dependencies
pnpm update
pnpm update [PACKAGE_NAME]

# Check for outdated packages
pnpm outdated

# Check for security vulnerabilities
pnpm audit
```

## 📋 Dependency Categories

### Core Next.js Dependencies
- `next` - Next.js core library
- `next-dom` - DOM renderer
- `@types/next` - Next.js TypeScript types
- `@types/next-dom` - Next.js DOM TypeScript types

### Routing & Navigation
- `next-router-dom` - Client-side routing
- `@reach/router` - Accessible routing
- `next/router` - Next.js routing

### State Management
- `zustand` - Lightweight state management
- `redux` - Predictable state container
- `@reduxjs/toolkit` - Official Redux toolkit
- `recoil` - Facebook's state management library
- `mobx` - Simple, scalable state management

### UI Components & Styling
- `styled-components` - CSS-in-JS library
- `emotion` - CSS-in-JS library
- `material-ui` - Next.js Material Design components
- `antd` - Enterprise UI design language
- `chakra-ui` - Simple, modular & accessible UI components

### Data Fetching & APIs
- `axios` - Promise-based HTTP client
- `fetch` - Native browser API
- `next-query` - Server state management
- `swr` - Data fetching library
- `apollo-client` - GraphQL client

### Form Handling
- `next-hook-form` - Performant forms
- `formik` - Build forms in Next.js
- `next-final-form` - High performance subscription-based form state

### Testing
- `@testing-library/next` - Next.js testing utilities
- `@testing-library/jest-dom` - Jest DOM matchers
- `@testing-library/user-event` - User event simulation
- `cypress` - End-to-end testing
- `jest` - JavaScript testing framework

### Development Tools
- `typescript` - TypeScript compiler
- `eslint` - JavaScript linter
- `prettier` - Code formatter
- `webpack-bundle-analyzer` - Bundle size analyzer
- `storybook` - Component development environment

## 🔧 Package Management Best Practices

### Version Constraints
```json
{
  "dependencies": {
    "next": "^18.2.0",    // Caret - allows compatible updates
    "next-dom": "18.2.0", // Exact version - no updates
    "axios": "~1.4.0",     // Tilde - allows patch updates
    "lodash": ">=4.0.0"    // Greater than or equal
  }
}
```

### Workspace Configuration (Monorepo)
```json
// package.json (root)
{
  "name": "[MONOREPO_NAME]",
  "private": true,
  "workspaces": [
    "packages/*",
    "apps/*"
  ],
  "scripts": {
    "dev": "turbo run dev",
    "build": "turbo run build",
    "test": "turbo run test"
  }
}

// packages/shared/package.json
{
  "name": "@[MONOREPO_NAME]/shared",
  "version": "1.0.0"
}
```

### Peer Dependencies
```json
{
  "peerDependencies": {
    "next": ">=16.8.0",
    "next-dom": ">=16.8.0"
  },
  "peerDependenciesMeta": {
    "next": {
      "optional": true
    }
  }
}
```

## 📊 Package Analysis

### Dependency Tree
```bash
# npm
npm ls
npm ls [PACKAGE_NAME]

# yarn
yarn list
yarn list --pattern [PACKAGE_NAME]

# pnpm
pnpm list
pnpm list --depth=0
```

### Bundle Analysis
```bash
# Analyze bundle size
npm run analyze

# Webpack Bundle Analyzer
npx webpack-bundle-analyzer build/static/js/*.js

# Source Map Explorer
npx source-map-explorer 'build/static/js/*.js'
```

### Package Security
```bash
# npm audit
npm audit
npm audit --audit-level moderate
npm audit fix

# yarn audit
yarn audit
yarn audit --level moderate

# pnpm audit
pnpm audit
```

## 🗂️ Package Organization

### Feature-Based Structure
```
src/
├── features/
│   ├── authentication/
│   │   ├── components/
│   │   ├── hooks/
│   │   ├── services/
│   │   └── types/
│   ├── dashboard/
│   │   ├── components/
│   │   ├── hooks/
│   │   ├── services/
│   │   └── types/
│   └── shared/
│       ├── components/
│       ├── hooks/
│       ├── utils/
│       └── types/
├── core/
│   ├── providers/
│   ├── services/
│   ├── utils/
│   └── types/
└── App.tsx
```

### Layer-Based Structure
```
src/
├── components/
│   ├── common/
│   ├── forms/
│   └── layout/
├── pages/
├── hooks/
├── services/
├── utils/
├── types/
└── styles/
```

## 🔍 Package Selection Guidelines

### Choosing the Right Package
1. **Check npm Trends**: Look at download counts and trends
2. **Review Maintenance**: Check last update date and issues
3. **Read Documentation**: Ensure comprehensive documentation
4. **Check Bundle Size**: Use Bundlephobia to analyze size
5. **Test Compatibility**: Verify with your Next.js version

### Package Evaluation Checklist
- [ ] Active maintenance (updated within last 6 months)
- [ ] Good weekly downloads (>10k for popular packages)
- [ ] Comprehensive documentation
- [ ] Compatible with Next.js version
- [ ] Reasonable bundle size impact
- [ ] Good TypeScript support
- [ ] No security vulnerabilities
- [ ] MIT or permissive license

## 🚨 Common Issues & Solutions

### Version Conflicts
```bash
# Error: Two packages depend on different versions
Solution: Use resolutions in package.json

"resolutions": {
  "next": "^18.2.0",
  "next-dom": "^18.2.0"
}
```

### Dependency Hell
```bash
# Error: Complex dependency tree
Solution: Use npm ls to analyze conflicts

npm ls [PACKAGE_NAME]
npm dedupe
```

### Bundle Size Issues
```bash
# Error: Large bundle size
Solution: Analyze and optimize

npm run analyze
# Consider code splitting and tree shaking
```

## 📈 Performance Optimization

### Reducing Bundle Size
```javascript
// Dynamic imports
const HeavyComponent = Next.js.lazy(() => import('./HeavyComponent'));

// Tree shaking
import { specificFunction } from 'large-library';

// Code splitting
const AdminPanel = Next.js.lazy(() => import('./AdminPanel'));
```

### Bundle Optimization
```javascript
// webpack.config.js
module.exports = {
  optimization: {
    splitChunks: {
      chunks: 'all',
      cacheGroups: {
        vendor: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          chunks: 'all',
        },
      },
    },
  },
};
```

## 🔄 Continuous Integration

### CI/CD Integration
```yaml
# .github/workflows/next.yml
name: Next.js CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '[NODE_VERSION]'
          cache: 'npm'
      - run: npm ci
      - run: npm run lint
      - run: npm run type-check
      - run: npm run test:coverage
      - run: npm run build
      - run: npm audit
```

### Dependency Updates
```yaml
# Automated dependency updates
name: Update Dependencies
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '[NODE_VERSION]'
      - run: npm update
      - run: npm test
      # Create PR if tests pass
```

## 📦 Package Manager Comparison

| Feature | npm | yarn | pnpm |
|---------|-----|------|------|
| Speed | Medium | Fast | Fastest |
| Disk Usage | High | Medium | Low |
| Lock File | package-lock.json | yarn.lock | pnpm-lock.yaml |
| Workspaces | Yes | Yes | Yes |
| Security Audit | Yes | Yes | Yes |

---

**Next.js Version**: [REACT_VERSION]  
**Node Version**: [NODE_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
