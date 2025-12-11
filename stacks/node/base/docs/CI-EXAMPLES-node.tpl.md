# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: node template utilities
# Tier: base
# Stack: node
# Category: template

# TypeScript/Node CI/CD Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: TypeScript/Node

## 🚀 TypeScript/Node CI/CD Strategy Overview

TypeScript/Node CI/CD follows a **tiered approach** with increasing complexity, security, and deployment capabilities. Each tier builds upon the previous one with additional validation, testing, and deployment strategies optimized for Node.js ecosystem.

## 📊 Tier-Specific CI/CD Requirements

| Tier | Testing | Code Quality | Security | Deployment | Environment |
|------|---------|--------------|----------|------------|-------------|
| **MVP** | Unit + basic integration | Basic linting | Basic checks | Manual only | Single env |
| **CORE** | All tests + coverage | Advanced linting + type checking | Dependency scanning | Automated to staging | Dev + Prod |
| **FULL** | All tests + performance | Full quality gates | Full security scan | Multi-stage deployment | Multi-env + feature flags |

## 🔧 GitHub Actions Configuration

### **MVP Tier - Basic CI**

```yaml
# .github/workflows/ci.yml
name: TypeScript/Node CI (MVP)

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        node-version: [18.x, 20.x]
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Node.js ${{ matrix.node-version }}
      uses: actions/setup-node@v4
      with:
        node-version: ${{ matrix.node-version }}
        cache: 'npm'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Run type check
      run: npm run type-check
      
    - name: Lint code
      run: npm run lint
      
    - name: Run unit tests
      run: npm run test:unit
      
    - name: Run integration tests
      run: npm run test:integration
      
    - name: Upload coverage reports
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/lcov.info
        fail_ci_if_error: false
```

### **CORE Tier - Production CI/CD**

```yaml
# .github/workflows/ci-core.yml
name: TypeScript/Node CI/CD (CORE)

on:
  push:
    branches: [ main, develop, release/* ]
  pull_request:
    branches: [ main, release/* ]
  release:
    types: [ published ]

env:
  NODE_VERSION: '20.x'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  quality-gate:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: ${{ env.NODE_VERSION }}
        cache: 'npm'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Validate package.json
      run: npm run validate:package
      
    - name: Run comprehensive type checking
      run: npm run type-check:strict
      
    - name: Run advanced linting
      run: |
        npm run lint
        npm run lint:markdown
        npm run lint:package-json
        
    - name: Check code formatting
      run: npm run format:check
      
    - name: Security audit
      run: npm audit --audit-level=moderate
      
    - name: Run dependency check
      run: npm run check:dependencies
      
    - name: Run comprehensive test suite
      run: |
        npm run test:unit -- --coverage
        npm run test:integration
        npm run test:e2e
        
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/lcov.info
        fail_ci_if_error: true
        
    - name: Bundle size analysis
      run: npm run analyze:bundle

  database-migrations:
    needs: quality-gate
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
          
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: ${{ env.NODE_VERSION }}
        cache: 'npm'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Generate Prisma client
      run: npx prisma generate
      
    - name: Run database migrations
      run: |
        echo "DATABASE_URL=postgresql://postgres:postgres@localhost:5432/test_db" >> .env
        npx prisma migrate deploy
        
    - name: Test migration rollback
      run: |
        npx prisma migrate reset --force --skip-seed
        npx prisma migrate deploy
        
    - name: Validate database schema
      run: npx prisma validate

  build-and-package:
    needs: [quality-gate, database-migrations]
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: ${{ env.NODE_VERSION }}
        cache: 'npm'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Build application
      run: npm run build
      
    - name: Package application
      run: npm run package
      
    - name: Validate package
      run: npm run validate:package
      
    - name: Upload build artifacts
      uses: actions/upload-artifact@v3
      with:
        name: node-package
        path: |
          dist/
          package.json
          package-lock.json
          prisma/

  container-build:
    needs: build-and-package
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v2
      
    - name: Log in to Container Registry
      uses: docker/login-action@v2
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
        
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v4
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=sha,prefix={{branch}}-
          type=raw,value=latest,enable={{is_default_branch}}
          
    - name: Build and push Docker image
      uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max

  deploy-staging:
    needs: container-build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    environment: staging
    
    steps:
    - name: Deploy to staging
      run: |
        echo "Deploying to staging environment..."
        # Add your staging deployment logic here
        
    - name: Run smoke tests
      run: |
        npm run test:smoke -- --environment=staging
        
    - name: Run health checks
      run: |
        npm run health:check -- --environment=staging

  deploy-production:
    needs: container-build
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    environment: production
    
    steps:
    - name: Deploy to production
      run: |
        echo "Deploying to production environment..."
        # Add your production deployment logic here
        
    - name: Run production health checks
      run: |
        npm run health:check -- --environment=production
        
    - name: Run performance tests
      run: |
        npm run test:performance -- --environment=production
```

### **FULL Tier - Enterprise CI/CD**

```yaml
# .github/workflows/ci-enterprise.yml
name: TypeScript/Node CI/CD (ENTERPRISE)

on:
  push:
    branches: [ main, develop, release/*, feature/* ]
  pull_request:
    branches: [ main, release/* ]
  release:
    types: [ published ]
  schedule:
    - cron: '0 2 * * *'  # Daily security scan

env:
  NODE_VERSION: '20.x'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  comprehensive-quality:
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        node-version: [18.x, 20.x]
        
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Node.js ${{ matrix.node-version }}
      uses: actions/setup-node@v4
      with:
        node-version: ${{ matrix.node-version }}
        cache: 'npm'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Validate package.json and dependencies
      run: |
        npm run validate:package
        npm run check:outdated
        npm run check:licenses
        
    - name: Run strict type checking
      run: npm run type-check:strict
      
    - name: Run comprehensive linting
      run: |
        npm run lint
        npm run lint:markdown
        npm run lint:package-json
        npm run lint:commit-messages
        
    - name: Check code formatting
      run: npm run format:check
      
    - name: Advanced security analysis
      run: |
        npm audit --audit-level=moderate --production
        npm run security:scan
        npm run check:dependencies
        
    - name: Run comprehensive test suite
      run: |
        npm run test:unit -- --coverage --verbose
        npm run test:integration
        npm run test:e2e
        npm run test:performance
        
    - name: Generate test report
      uses: dorny/test-reporter@v1
      if: success() || failure()
      with:
        name: Node.js Tests
        path: test-results.json
        reporter: json
        
    - name: Upload coverage to multiple services
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/lcov.info
        fail_ci_if_error: true
        
    - name: Bundle size analysis
      run: |
        npm run analyze:bundle
        npm run analyze:treemap
        
    - name: Performance regression test
      run: npm run test:performance:regression

  enterprise-security:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        format: 'sarif'
        output: 'trivy-results.sarif'
        
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
        
    - name: Run Snyk security scan
      uses: snyk/actions/node@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      with:
        args: --severity-threshold=high
        
    - name: OWASP Dependency Check
      uses: dependency-check/Dependency-Check_Action@main
      with:
        project: 'nodejs-app'
        path: '.'
        format: 'HTML'
        
    - name: Upload security reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: |
          trivy-results.sarif
          reports/
          snyk-report.html

  multi-environment-testing:
    needs: [comprehensive-quality, enterprise-security]
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        environment: [staging, production]
        
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: ${{ env.NODE_VERSION }}
        cache: 'npm'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Build application
      run: npm run build
      
    - name: Deploy to ${{ matrix.environment }}
      run: |
        echo "Deploying to ${{ matrix.environment }}..."
        # Add environment-specific deployment logic
        
    - name: Run comprehensive test suite
      run: |
        npm run test:smoke -- --environment=${{ matrix.environment }}
        npm run test:health -- --environment=${{ matrix.environment }}
        npm run test:performance -- --environment=${{ matrix.environment }}
        
    - name: Run chaos engineering tests
      if: matrix.environment == 'staging'
      run: npm run test:chaos -- --environment=staging

  container-security-and-deployment:
    needs: multi-environment-testing
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v2
      
    - name: Log in to Container Registry
      uses: docker/login-action@v2
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
        
    - name: Build and push Docker image
      uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: |
          ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
          ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
        target: production
        
    - name: Run container security scan
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
        format: 'sarif'
        output: 'container-scan.sarif'
        
    - name: Upload container scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'container-scan.sarif'
        
    - name: Deploy to Kubernetes
      run: |
        echo "Deploying to Kubernetes..."
        kubectl set image deployment/${{ env.IMAGE_NAME }} ${{ env.IMAGE_NAME }}=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }}
        kubectl rollout status deployment/${{ env.IMAGE_NAME }}

  post-deployment-monitoring:
    needs: container-security-and-deployment
    runs-on: ubuntu-latest
    
    steps:
    - name: Monitor deployment health
      run: |
        npm run monitor:health -- --threshold=95 --duration=300
        
    - name: Check error rates
      run: |
        npm run monitor:errors -- --threshold=5 --window=5m
        
    - name: Validate performance metrics
      run: |
        npm run monitor:performance -- --threshold=200ms --window=5m
        
    - name: Run synthetic monitoring
      run: |
        npm run monitor:synthetic -- --environment=production
        
    - name: Create incident on failure
      if: failure()
      uses: actions/github-script@v6
      with:
        script: |
          github.rest.issues.create({
            owner: context.repo.owner,
            repo: context.repo.repo,
            title: 'Deployment Health Check Failed',
            body: 'Deployment health checks failed. Please investigate immediately.',
            labels: ['deployment', 'urgent']
          })
```

## 🐳 Docker Configuration

### **Multi-stage Dockerfile**

```dockerfile
# Dockerfile
FROM node:20-alpine AS base

# Install dependencies only when needed
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Install dependencies based on the preferred package manager
COPY package.json package-lock.json* ./
RUN npm ci --only=production && npm cache clean --force

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Build the application
RUN npm run build

# Production image, copy all the files and run the app
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/prisma ./prisma

# Generate Prisma client for production
RUN npx prisma generate

USER nextjs

EXPOSE 3000

ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

CMD ["node", "dist/index.js"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

### **Development Dockerfile**

```dockerfile
# Dockerfile.dev
FROM node:20-alpine

WORKDIR /app

# Install development dependencies
RUN apk add --no-cache libc6-compat curl

# Copy package files
COPY package.json package-lock.json* ./

# Install all dependencies
RUN npm ci

# Copy source code
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Create non-root user
RUN addgroup -S nodejs && adduser -S nodejs -G nodejs
USER nodejs

EXPOSE 3000

CMD ["npm", "run", "dev"]
```

### **Docker Compose for Development**

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/dev_db
      - REDIS_URL=redis://redis:6379
    volumes:
      - .:/app
      - /app/node_modules
    depends_on:
      - postgres
      - redis
    command: npm run dev

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=dev_db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - app

volumes:
  postgres_data:
  redis_data:
```

## 🔒 Security Configuration

### **Security Scanning Setup**

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  push:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4
      
    - name: Run Semgrep
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/security-audit
          p/secrets
          p/nodejs
          
    - name: Run CodeQL Analysis
      uses: github/codeql-action/init@v2
      with:
        languages: javascript
        
    - name: Autobuild
      uses: github/codeql-action/autobuild@v2
      
    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
      
    - name: Run npm audit
      run: npm audit --audit-level=moderate
      
    - name: Run Snyk
      uses: snyk/actions/node@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

### **Dependency Management Scripts**

```json
// package.json scripts
{
  "scripts": {
    "check:dependencies": "npm outdated && npm audit",
    "check:licenses": "license-checker --onlyAllow 'MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC'",
    "check:outdated": "npm outdated --depth=0",
    "security:scan": "npm audit --audit-level=moderate --production",
    "validate:package": "npm ls && validate-package-json"
  }
}
```

```typescript
// scripts/dependency-checker.ts
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

interface DependencyInfo {
  name: string;
  version: string;
  latest?: string;
  vulnerabilities?: any[];
}

class DependencyChecker {
  async checkDependencies(): Promise<void> {
    try {
      console.log('Checking for outdated dependencies...');
      const outdated = this.getOutdatedDependencies();
      
      if (outdated.length > 0) {
        console.log(`Found ${outdated.length} outdated packages:`);
        outdated.forEach(dep => {
          console.log(`  ${dep.name}: ${dep.version} -> ${dep.latest}`);
        });
      }

      console.log('Checking for security vulnerabilities...');
      const vulnerabilities = await this.getVulnerabilities();
      
      if (vulnerabilities.length > 0) {
        console.log(`Found ${vulnerabilities.length} vulnerabilities:`);
        vulnerabilities.forEach(vuln => {
          console.log(`  ${vuln.packageName}: ${vuln.severity} - ${vuln.title}`);
        });
        process.exit(1);
      }

      console.log('Dependency check completed successfully');
    } catch (error) {
      console.error('Error checking dependencies:', error);
      process.exit(1);
    }
  }

  private getOutdatedDependencies(): DependencyInfo[] {
    try {
      const output = execSync('npm outdated --json', { encoding: 'utf8' });
      const outdated = JSON.parse(output);
      
      return Object.entries(outdated).map(([name, info]: [string, any]) => ({
        name,
        version: info.current,
        latest: info.latest,
      }));
    } catch (error) {
      // npm outdated returns non-zero exit code when packages are outdated
      const output = (error as any).stdout;
      if (output) {
        const outdated = JSON.parse(output);
        return Object.entries(outdated).map(([name, info]: [string, any]) => ({
          name,
          version: info.current,
          latest: info.latest,
        }));
      }
      return [];
    }
  }

  private async getVulnerabilities(): Promise<any[]> {
    try {
      const output = execSync('npm audit --json', { encoding: 'utf8' });
      const audit = JSON.parse(output);
      
      if (audit.vulnerabilities) {
        return Object.values(audit.vulnerabilities);
      }
      return [];
    } catch (error) {
      console.error('Error running npm audit:', error);
      return [];
    }
  }
}

if (require.main === module) {
  const checker = new DependencyChecker();
  checker.checkDependencies();
}
```

## 📊 Quality Gates Configuration

### **Pre-commit Hooks**

```json
// package.json
{
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged",
      "commit-msg": "commitlint -E HUSKY_GIT_PARAMS"
    }
  },
  "lint-staged": {
    "*.{js,ts}": [
      "eslint --fix",
      "prettier --write",
      "git add"
    ],
    "*.{json,md}": [
      "prettier --write",
      "git add"
    ],
    "package.json": [
      "npm run validate:package",
      "git add"
    ]
  }
}
```

```javascript
// .commitlintrc.js
module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      [
        'feat',     // New feature
        'fix',      // Bug fix
        'docs',     // Documentation
        'style',    // Code style
        'refactor', // Refactoring
        'perf',     // Performance
        'test',     // Tests
        'chore',    // Maintenance
        'ci',       // CI/CD
        'build',    // Build
      ],
    ],
    'subject-max-length': [2, 'always', 50],
    'body-max-line-length': [2, 'always', 72],
  },
};
```

### **Quality Metrics Script**

```typescript
// scripts/quality-gate.ts
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

interface QualityMetrics {
  testCoverage: number;
  lintErrors: number;
  typeErrors: number;
  securityVulnerabilities: number;
  bundleSize: number;
  performanceScore: number;
}

class QualityGate {
  private readonly thresholds = {
    testCoverage: 80,
    lintErrors: 0,
    typeErrors: 0,
    securityVulnerabilities: 0,
    bundleSize: 50 * 1024 * 1024, // 50MB
    performanceScore: 90,
  };

  async runQualityChecks(): Promise<void> {
    console.log('Running quality gate checks...');
    
    const metrics = await this.collectMetrics();
    const passed = this.evaluateMetrics(metrics);
    
    this.printReport(metrics);
    
    if (!passed) {
      console.error('Quality gate failed!');
      process.exit(1);
    }
    
    console.log('✅ All quality gates passed!');
  }

  private async collectMetrics(): Promise<QualityMetrics> {
    return {
      testCoverage: await this.getTestCoverage(),
      lintErrors: await this.getLintErrors(),
      typeErrors: await this.getTypeErrors(),
      securityVulnerabilities: await this.getSecurityVulnerabilities(),
      bundleSize: await this.getBundleSize(),
      performanceScore: await this.getPerformanceScore(),
    };
  }

  private async getTestCoverage(): Promise<number> {
    try {
      const output = execSync('npm run test:coverage -- --json --coverageReporters=text-summary', { encoding: 'utf8' });
      const match = output.match(/All files\s+\|\s+(\d+\.\d+)/);
      return match ? parseFloat(match[1]) : 0;
    } catch (error) {
      console.error('Error getting test coverage:', error);
      return 0;
    }
  }

  private async getLintErrors(): Promise<number> {
    try {
      execSync('npm run lint', { encoding: 'utf8' });
      return 0;
    } catch (error) {
      const output = (error as any).stderr || (error as any).stdout;
      const match = output.match(/(\d+) error/);
      return match ? parseInt(match[1]) : 1;
    }
  }

  private async getTypeErrors(): Promise<number> {
    try {
      execSync('npm run type-check', { encoding: 'utf8' });
      return 0;
    } catch (error) {
      const output = (error as any).stderr || (error as any).stdout;
      const match = output.match(/Found (\d+) error/);
      return match ? parseInt(match[1]) : 1;
    }
  }

  private async getSecurityVulnerabilities(): Promise<number> {
    try {
      const output = execSync('npm audit --json', { encoding: 'utf8' });
      const audit = JSON.parse(output);
      const vulnerabilities = audit.vulnerabilities || {};
      return Object.keys(vulnerabilities).length;
    } catch (error) {
      console.error('Error checking security vulnerabilities:', error);
      return 1;
    }
  }

  private async getBundleSize(): Promise<number> {
    try {
      const stats = fs.statSync('dist/index.js');
      return stats.size;
    } catch (error) {
      console.error('Error getting bundle size:', error);
      return Infinity;
    }
  }

  private async getPerformanceScore(): Promise<number> {
    try {
      // This would integrate with Lighthouse or similar tool
      // For now, return a placeholder
      return 95;
    } catch (error) {
      console.error('Error getting performance score:', error);
      return 0;
    }
  }

  private evaluateMetrics(metrics: QualityMetrics): boolean {
    return (
      metrics.testCoverage >= this.thresholds.testCoverage &&
      metrics.lintErrors <= this.thresholds.lintErrors &&
      metrics.typeErrors <= this.thresholds.typeErrors &&
      metrics.securityVulnerabilities <= this.thresholds.securityVulnerabilities &&
      metrics.bundleSize <= this.thresholds.bundleSize &&
      metrics.performanceScore >= this.thresholds.performanceScore
    );
  }

  private printReport(metrics: QualityMetrics): void {
    console.log('\n📊 Quality Gate Report');
    console.log('========================');
    console.log(`Test Coverage: ${metrics.testCoverage}% (threshold: ${this.thresholds.testCoverage}%)`);
    console.log(`Lint Errors: ${metrics.lintErrors} (threshold: ${this.thresholds.lintErrors})`);
    console.log(`Type Errors: ${metrics.typeErrors} (threshold: ${this.thresholds.typeErrors})`);
    console.log(`Security Vulnerabilities: ${metrics.securityVulnerabilities} (threshold: ${this.thresholds.securityVulnerabilities})`);
    console.log(`Bundle Size: ${(metrics.bundleSize / 1024 / 1024).toFixed(2)}MB (threshold: ${(this.thresholds.bundleSize / 1024 / 1024).toFixed(2)}MB)`);
    console.log(`Performance Score: ${metrics.performanceScore} (threshold: ${this.thresholds.performanceScore})`);
  }
}

if (require.main === module) {
  const qualityGate = new QualityGate();
  qualityGate.runQualityChecks();
}
```

## 🚀 Deployment Strategies

### **Kubernetes Deployment**

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{PROJECT_NAME}}
  labels:
    app: {{PROJECT_NAME}}
spec:
  replicas: 3
  selector:
    matchLabels:
      app: {{PROJECT_NAME}}
  template:
    metadata:
      labels:
        app: {{PROJECT_NAME}}
    spec:
      containers:
      - name: {{PROJECT_NAME}}
        image: ghcr.io/{{ORGANIZATION}}/{{PROJECT_NAME}}:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: {{PROJECT_NAME}}-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: {{PROJECT_NAME}}-secrets
              key: redis-url
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: {{PROJECT_NAME}}-secrets
              key: jwt-secret
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: {{PROJECT_NAME}}-service
spec:
  selector:
    app: {{PROJECT_NAME}}
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: ClusterIP
```

### **Helm Chart**

```yaml
# helm/{{PROJECT_NAME}}/values.yaml
replicaCount: 3

image:
  repository: ghcr.io/{{ORGANIZATION}}/{{PROJECT_NAME}}
  pullPolicy: IfNotPresent
  tag: "latest"

service:
  type: ClusterIP
  port: 80
  targetPort: 3000

ingress:
  enabled: true
  className: "nginx"
  annotations: {}
  hosts:
    - host: {{PROJECT_NAME}}.example.com
      paths:
        - path: /
          pathType: Prefix

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 250m
    memory: 256Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80

env:
  NODE_ENV: production

secrets:
  DATABASE_URL: ""
  REDIS_URL: ""
  JWT_SECRET: ""
```

## 📈 Monitoring and Observability

### **Prometheus Metrics**

```typescript
// src/monitoring/metrics.ts
import { register, Counter, Histogram, Gauge } from 'prom-client';

export class MetricsService {
  private httpRequestCounter: Counter<string>;
  private httpRequestDuration: Histogram<string>;
  private activeConnections: Gauge<string>;
  private databaseConnections: Gauge<string>;

  constructor() {
    this.httpRequestCounter = new Counter({
      name: 'nodejs_http_requests_total',
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'route', 'status_code'],
    });

    this.httpRequestDuration = new Histogram({
      name: 'nodejs_http_request_duration_seconds',
      help: 'Duration of HTTP requests in seconds',
      labelNames: ['method', 'route'],
      buckets: [0.1, 0.5, 1, 2, 5, 10],
    });

    this.activeConnections = new Gauge({
      name: 'nodejs_active_connections',
      help: 'Number of active connections',
    });

    this.databaseConnections = new Gauge({
      name: 'nodejs_database_connections',
      help: 'Number of active database connections',
    });

    // Register metrics
    register.registerMetric(this.httpRequestCounter);
    register.registerMetric(this.httpRequestDuration);
    register.registerMetric(this.activeConnections);
    register.registerMetric(this.databaseConnections);
  }

  incrementHttpRequest(method: string, route: string, statusCode: string): void {
    this.httpRequestCounter.inc({ method, route, status_code: statusCode });
  }

  recordHttpRequestDuration(method: string, route: string, duration: number): void {
    this.httpRequestDuration.observe({ method, route }, duration);
  }

  setActiveConnections(count: number): void {
    this.activeConnections.set(count);
  }

  setDatabaseConnections(count: number): void {
    this.databaseConnections.set(count);
  }

  getMetrics(): string {
    return register.metrics();
  }
}

// Middleware for Fastify
export const metricsMiddleware = (metrics: MetricsService) => async (request: any, reply: any) => {
  const start = Date.now();
  
  request.metrics = metrics;
  metrics.setActiveConnections(metrics.getActiveConnections() + 1);
  
  reply.addHook('onSend', async () => {
    const duration = Date.now() - start;
    metrics.recordHttpRequestDuration(request.method, request.routeOptions.url, duration / 1000);
    metrics.incrementHttpRequest(request.method, request.routeOptions.url, reply.statusCode.toString());
    metrics.setActiveConnections(metrics.getActiveConnections() - 1);
  });
};
```

### **Health Checks**

```typescript
// src/health/health.controller.ts
import { FastifyInstance } from 'fastify';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';

export class HealthController {
  constructor(
    private prisma: PrismaClient,
    private redis: Redis,
  ) {}

  async registerRoutes(fastify: FastifyInstance) {
    fastify.get('/health', this.healthCheck.bind(this));
    fastify.get('/ready', this.readinessCheck.bind(this));
    fastify.get('/live', this.livenessCheck.bind(this));
  }

  private async healthCheck() {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || 'unknown',
    };
  }

  private async readinessCheck() {
    const checks = {
      database: await this.checkDatabase(),
      redis: await this.checkRedis(),
    };

    const allHealthy = Object.values(checks).every(check => check.healthy);

    return {
      status: allHealthy ? 'ready' : 'not_ready',
      checks,
    };
  }

  private async livenessCheck() {
    return {
      status: 'alive',
      timestamp: new Date().toISOString(),
    };
  }

  private async checkDatabase() {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return { healthy: true };
    } catch (error) {
      return { healthy: false, error: error.message };
    }
  }

  private async checkRedis() {
    try {
      await this.redis.ping();
      return { healthy: true };
    } catch (error) {
      return { healthy: false, error: error.message };
    }
  }
}
```

## 🛠️ Local Development Setup

### **Development Scripts**

```json
// package.json scripts
{
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "dev:debug": "tsx watch --inspect src/index.ts",
    "build": "tsc && tsc-alias",
    "build:watch": "tsc --watch && tsc-alias --watch",
    "start": "node dist/index.js",
    "start:prod": "NODE_ENV=production node dist/index.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:unit": "jest --testPathPattern=unit",
    "test:integration": "jest --testPathPattern=integration",
    "test:e2e": "playwright test",
    "test:performance": "jest --testPathPattern=performance",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "format": "prettier --write src/**/*.ts",
    "format:check": "prettier --check src/**/*.ts",
    "type-check": "tsc --noEmit",
    "type-check:strict": "tsc --noEmit --strict",
    "db:generate": "prisma generate",
    "db:migrate": "prisma migrate dev",
    "db:reset": "prisma migrate reset",
    "db:seed": "tsx prisma/seed.ts",
    "docker:build": "docker build -t {{PROJECT_NAME}} .",
    "docker:run": "docker run -p 3000:3000 {{PROJECT_NAME}}",
    "docker:dev": "docker-compose up -d",
    "docker:dev:down": "docker-compose down",
    "analyze:bundle": "npm run build && npx webpack-bundle-analyzer dist/",
    "analyze:treemap": "npm run build && npx source-map-explorer dist/index.js"
  }
}
```

### **Makefile**

```makefile
# Makefile
.PHONY: help dev build test lint format clean docker-build docker-run

help:
	@echo "Available commands:"
	@echo "  dev         - Start development server"
	@echo "  build       - Build application"
	@echo "  test        - Run tests"
	@echo "  lint        - Run linting"
	@echo "  format      - Format code"
	@echo "  clean       - Clean build artifacts"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run  - Run Docker container"

dev:
	npm run dev

build:
	npm run build

test:
	npm run test:coverage

lint:
	npm run lint

format:
	npm run format

clean:
	rm -rf dist/
	rm -rf node_modules/.cache
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

docker-build:
	docker build -t {{PROJECT_NAME}} .

docker-run:
	docker run -p 3000:3000 {{PROJECT_NAME}}

docker-dev:
	docker-compose up -d

docker-dev-down:
	docker-compose down

install:
	npm ci

setup:
	npm ci
	npm run db:generate
	npm run db:migrate
	npm run db:seed
```

---
*TypeScript/Node CI/CD Examples - Use these patterns for robust and secure TypeScript/Node deployment pipelines*
