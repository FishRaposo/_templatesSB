# Universal Template System - React_Native Stack
# Generated: 2025-12-10
# Purpose: react_native template utilities
# Tier: base
# Stack: react_native
# Category: template

# React Native CI/CD Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: React Native

## 🚀 React Native CI/CD Strategy Overview

React Native CI/CD follows a **frontend-optimized approach** with **build optimization**, **bundle analysis**, and **deployment automation**. Each tier builds upon the previous one with additional validation, testing, and deployment strategies optimized for React Native applications and modern mobile deployment.

## 📊 Tier-Specific CI/CD Requirements

| Tier | Testing | Build Optimization | Security | Deployment | Environment |
|------|---------|-------------------|----------|------------|-------------|
| **MVP** | Unit + component tests | Basic build | Basic checks | Manual only | Single env |
| **CORE** | All tests + coverage | Bundle optimization | Dependency scanning | Automated to staging | Dev + Prod |
| **FULL** | All tests + visual tests | Full optimization | Full security scan | Multi-stage deployment | Multi-env + CDN |

## 🔧 GitHub Actions Configuration

### **MVP Tier - Basic React Native CI**

```yaml
# .github/workflows/ci.yml
name: React Native CI (MVP)

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
      
    - name: Run component tests
      run: npm run test:component
      
    - name: Build application
      run: npm run build
      
    - name: Upload build artifacts
      uses: actions/upload-artifact@v3
      with:
        name: build-files
        path: build/
```

### **CORE Tier - Production React Native CI/CD**

```yaml
# .github/workflows/ci-core.yml
name: React Native CI/CD (CORE)

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
        npm run lint:css
        npm run lint:markdown
        npm run lint:package-json
        
    - name: Check code formatting
      run: npm run format:check
      
    - name: Security audit
      run: npm audit --audit-level=moderate
      
    - name: Check bundle size
      run: npm run check:bundle-size
      
    - name: Run comprehensive test suite
      run: |
        npm run test:unit -- --coverage
        npm run test:component -- --coverage
        npm run test:integration
        
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/lcov.info
        fail_ci_if_error: true
        
    - name: Bundle size analysis
      run: npm run analyze:bundle

  build-and-optimize:
    needs: quality-gate
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
      
    - name: Build for production
      run: npm run build:prod
      
    - name: Optimize bundle
      run: |
        npm run optimize:images
        npm run optimize:bundle
        npm run generate:sourcemaps
        
    - name: Analyze bundle size
      run: npm run analyze:bundle-size
        
    - name: Generate build report
      run: npm run report:build
      
    - name: Upload build artifacts
      uses: actions/upload-artifact@v3
      with:
        name: production-build
        path: |
          build/
          build-report.json
          bundle-analysis.json

  accessibility-testing:
    needs: build-and-optimize
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
      
    - name: Download build artifacts
      uses: actions/download-artifact@v3
      with:
        name: production-build
        path: build/
        
    - name: Run accessibility tests
      run: |
        npm run serve:build &
        sleep 10
        npm run test:a11y
        npm run test:lighthouse
        
    - name: Upload accessibility report
      uses: actions/upload-artifact@v3
      with:
        name: accessibility-report
        path: |
          accessibility-report.json
          lighthouse-report.html

  deploy-staging:
    needs: [build-and-optimize, accessibility-testing]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    environment: staging
    
    steps:
    - name: Download build artifacts
      uses: actions/download-artifact@v3
      with:
        name: production-build
        path: build/
        
    - name: Deploy to staging
      run: |
        echo "Deploying to staging environment..."
        # Add your staging deployment logic here
        # Example: AWS S3, Netlify, Vercel, etc.
        
    - name: Run smoke tests
      run: |
        npm run test:smoke -- --environment=staging
        
    - name: Run visual regression tests
      run: |
        npm run test:visual -- --environment=staging

  deploy-production:
    needs: [build-and-optimize, accessibility-testing]
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    environment: production
    
    steps:
    - name: Download build artifacts
      uses: actions/download-artifact@v3
      with:
        name: production-build
        path: build/
        
    - name: Deploy to production
      run: |
        echo "Deploying to production environment..."
        # Add your production deployment logic here
        
    - name: Invalidate CDN cache
      run: |
        npm run cdn:invalidate -- --environment=production
        
    - name: Run production health checks
      run: |
        npm run health:check -- --environment=production
        
    - name: Run performance tests
      run: |
        npm run test:performance -- --environment=production
```

### **FULL Tier - Enterprise React Native CI/CD**

```yaml
# .github/workflows/ci-enterprise.yml
name: React Native CI/CD (ENTERPRISE)

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
        mobile app: [chrome, firefox, safari]
        
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
        npm run check:peer-dependencies
        
    - name: Run strict type checking
      run: npm run type-check:strict
      
    - name: Run comprehensive linting
      run: |
        npm run lint
        npm run lint:css
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
        npm run check:bundle-security
        
    - name: Run comprehensive test suite
      run: |
        npm run test:unit -- --coverage --verbose
        npm run test:component -- --coverage --verbose
        npm run test:integration
        npm run test:e2e -- --mobile app=${{ matrix.mobile app }}
        npm run test:visual
        npm run test:accessibility
        
    - name: Generate test report
      uses: dorny/test-reporter@v1
      if: success() || failure()
      with:
        name: React Native Tests
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
        npm run analyze:chunk-sizes
        
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
        project: 'react_native-app'
        path: '.'
        format: 'HTML'
        
    - name: Bundle security analysis
      run: npm run security:bundle-analysis
      
    - name: Upload security reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: |
          trivy-results.sarif
          reports/
          snyk-report.html
          bundle-security-report.json

  cross-mobile app-testing:
    needs: comprehensive-quality
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        mobile app: [chrome, firefox, safari, edge]
        device: [desktop, mobile, tablet]
        
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
      
    - name: Run cross-mobile app tests
      run: |
        npm run test:e2e -- --mobile app=${{ matrix.mobile app }} --device=${{ matrix.device }}
        
    - name: Run visual regression tests
      run: |
        npm run test:visual -- --mobile app=${{ matrix.mobile app }} --device=${{ matrix.device }}

  performance-optimization:
    needs: comprehensive-quality
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
      
    - name: Build with optimizations
      run: |
        npm run build:prod
        npm run optimize:images
        npm run optimize:bundle
        npm run generate:critical-css
        
    - name: Run Lighthouse CI
      run: |
        npm install -g @lhci/cli@0.12.x
        lhci autorun
      env:
        LHCI_GITHUB_APP_TOKEN: ${{ secrets.LHCI_GITHUB_APP_TOKEN }}
        
    - name: Bundle size comparison
      run: npm run compare:bundle-size
      
    - name: Performance budget validation
      run: npm run validate:performance-budget

  multi-environment-deployment:
    needs: [enterprise-security, cross-mobile app-testing, performance-optimization]
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    
    strategy:
      matrix:
        environment: [staging, production, dr]
        
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
      
    - name: Build for ${{ matrix.environment }}
      run: |
        npm run build:${{ matrix.environment }}
        
    - name: Deploy to ${{ matrix.environment }}
      run: |
        echo "Deploying to ${{ matrix.environment }}..."
        # Add environment-specific deployment logic
        
    - name: Run environment-specific tests
      run: |
        npm run test:smoke -- --environment=${{ matrix.environment }}
        npm run test:health -- --environment=${{ matrix.environment }}
        npm run test:performance -- --environment=${{ matrix.environment }}
        
    - name: Update feature flags
      if: matrix.environment == 'production'
      run: npm run feature-flags:update -- --environment=production

  post-deployment-monitoring:
    needs: multi-environment-deployment
    runs-on: ubuntu-latest
    
    steps:
    - name: Monitor deployment health
      run: |
        npm run monitor:health -- --threshold=95 --duration=300
        
    - name: Check Core Web Vitals
      run: |
        npm run monitor:core-mobile-vitals -- --threshold=lcp:2.5,fid:100,cls:0.1
        
    - name: Validate performance metrics
      run: |
        npm run monitor:performance -- --threshold=200ms --window=5m
        
    - name: Run synthetic monitoring
      run: |
        npm run monitor:synthetic -- --environment=production
        
    - name: Check error rates
      run: |
        npm run monitor:errors -- --threshold=5 --window=5m
        
    - name: Create incident on failure
      if: failure()
      uses: actions/github-script@v6
      with:
        script: |
          github.rest.issues.create({
            owner: context.repo.owner,
            repo: context.repo.repo,
            title: 'React Native Deployment Health Check Failed',
            body: 'Deployment health checks failed. Please investigate immediately.',
            labels: ['deployment', 'urgent', 'frontend']
          })
```

## 🐳 Docker Configuration for React Native

### **Multi-stage Dockerfile**

```dockerfile
# Dockerfile
# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Build application
RUN npm run build

# Production stage
FROM nginx:alpine AS production

# Copy built application
COPY --from=builder /app/build /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:80/health || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

### **Nginx Configuration**

```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied expired no-cache no-store private must-revalidate auth;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    server {
        listen 80;
        server_name localhost;
        root /usr/share/nginx/html;
        index index.html index.htm;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
        
        # Service worker
        location /sw.js {
            expires off;
            add_header Cache-Control "no-cache";
        }
        
        # SPA routing
        location / {
            try_files $uri $uri/ /index.html;
        }
        
        # Health check endpoint
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
        
        # Security
        location ~ /\. {
            deny all;
        }
    }
}
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

# Expose port
EXPOSE 3000

# Start development server
CMD ["npm", "start"]
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
      - REACT_APP_API_URL=http://localhost:8000
      - REACT_APP_WS_URL=ws://localhost:8000
    volumes:
      - .:/app
      - /app/node_modules
    depends_on:
      - api
    command: npm start

  api:
    image: node:20-alpine
    working_dir: /app
    ports:
      - "8000:8000"
    volumes:
      - ./api:/app
    environment:
      - NODE_ENV=development
    command: npm run dev

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.dev.conf:/etc/nginx/nginx.conf
    depends_on:
      - app

  storybook:
    build:
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "6006:6006"
    volumes:
      - .:/app
      - /app/node_modules
    command: npm run storybook

volumes:
  node_modules:
```

## 🔒 Security Configuration

### **Content Security Policy**

```javascript
// public/csp.js
const CSP = {
  'default-src': ["'self'"],
  'script-src': ["'self'", "'unsafe-inline'", "https://cdn.trusted.com"],
  'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
  'font-src': ["'self'", "https://fonts.gstatic.com"],
  'img-src': ["'self'", "data:", "https:", "blob:"],
  'connect-src': ["'self'", "https://api.example.com", "wss://api.example.com"],
  'media-src': ["'self'"],
  'object-src': ["'none'"],
  'frame-src': ["'none'"],
  'worker-src': ["'self'", "blob:"],
  'manifest-src': ["'self'"],
};

const CSP_HEADER = Object.entries(CSP)
  .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
  .join('; ');

// Apply CSP via meta tag or HTTP headers
```

### **Security Headers Middleware**

```javascript
// scripts/security-headers.js
const helmet = require('helmet');

const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", process.env.REACT_APP_API_URL],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
});

module.exports = securityHeaders;
```

## 📊 Performance Optimization

### **Bundle Analysis Configuration**

```javascript
// mobilepack.analyze.js
const BundleAnalyzerPlugin = require('mobilepack-bundle-analyzer').BundleAnalyzerPlugin;
const { BundleAnalyzerPlugin } = require('mobilepack-bundle-analyzer');

module.exports = {
  plugins: [
    new BundleAnalyzerPlugin({
      analyzerMode: 'static',
      openAnalyzer: false,
      reportFilename: 'bundle-report.html',
      defaultSizes: 'parsed',
      generateStatsFile: true,
      statsFilename: 'bundle-stats.json',
      statsOptions: { source: false },
    }),
  ],
};
```

### **Performance Budget Configuration**

```javascript
// .lighthouserc.js
module.exports = {
  ci: {
    collect: {
      url: ['http://localhost:3000'],
      numberOfRuns: 3,
    },
    assert: {
      assertions: {
        'categories:performance': ['warn', { minScore: 0.9 }],
        'categories:accessibility': ['error', { minScore: 0.9 }],
        'categories:best-practices': ['warn', { minScore: 0.9 }],
        'categories:seo': ['warn', { minScore: 0.9 }],
        'categories:pwa': 'off',
      },
    },
    upload: {
      target: 'temporary-public-storage',
    },
  },
};
```

### **Bundle Optimization Scripts**

```json
// package.json scripts
{
  "scripts": {
    "build:analyze": "npm run build && npx mobilepack-bundle-analyzer build/static/js/*.js",
    "build:profile": "npm run build -- --profile",
    "optimize:images": "npm run imagemin",
    "optimize:bundle": "npm run mobilepack-bundle-analyzer",
    "check:bundle-size": "npm run size-limit",
    "compare:bundle-size": "npm run size-limit -- --why",
    "generate:critical-css": "npm run critical",
    "validate:performance-budget": "npm run lighthouse -- --budget"
  }
}
```

```javascript
// size-limit.config.js
module.exports = [
  {
    path: 'build/static/js/*.js',
    limit: '250 KB',
  },
  {
    path: 'build/static/css/*.css',
    limit: '50 KB',
  },
  {
    path: 'build/static/js/*.js',
    limit: '100 KB',
    name: 'main bundle',
  },
];
```

## 🚀 Deployment Strategies

### **Vercel Configuration**

```json
// vercel.json
{
  "version": 2,
  "framework": "create-react_native-app",
  "buildCommand": "npm run build",
  "outputDirectory": "build",
  "installCommand": "npm ci",
  "functions": {},
  "headers": [
    {
      "source": "/static/(.*)",
      "headers": [
        {
          "key": "Cache-Control",
          "value": "public, max-age=31536000, immutable"
        }
      ]
    },
    {
      "source": "/sw.js",
      "headers": [
        {
          "key": "Cache-Control",
          "value": "public, max-age=0, must-revalidate"
        }
      ]
    }
  ],
  "rewrites": [
    {
      "source": "/((?!api/).*)",
      "destination": "/index.html"
    }
  ]
}
```

### **Netlify Configuration**

```toml
# netlify.toml
[build]
  publish = "build"
  command = "npm run build"

[build.environment]
  NODE_VERSION = "20"

[[headers]]
  for = "/static/*"
  [headers.values]
    Cache-Control = "public, max-age=31536000, immutable"

[[headers]]
  for = "/*.js"
  [headers.values]
    Cache-Control = "public, max-age=31536000, immutable"

[[headers]]
  for = "/*.css"
  [headers.values]
    Cache-Control = "public, max-age=31536000, immutable"

[[redirects]]
  from = "/*"
  to = "/index.html"
  status = 200

[context.production.environment]
  REACT_APP_API_URL = "https://api.example.com"

[context.deploy-preview.environment]
  REACT_APP_API_URL = "https://staging-api.example.com"
```

### **AWS S3 Deployment Script**

```bash
#!/bin/bash
# scripts/deploy-s3.sh

set -e

# Configuration
BUCKET_NAME="your-react_native-app-bucket"
DISTRIBUTION_ID="YOUR_CLOUDFRONT_DISTRIBUTION_ID"
BUILD_DIR="build"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting deployment to S3...${NC}"

# Sync files to S3
echo -e "${YELLOW}Syncing files to S3 bucket...${NC}"
aws s3 sync $BUILD_DIR s3://$BUCKET_NAME \
  --delete \
  --exclude "*.html" \
  --cache-control "max-age=31536000, immutable"

# Upload HTML files with no cache
echo -e "${YELLOW}Uploading HTML files...${NC}"
aws s3 sync $BUILD_DIR s3://$BUCKET_NAME \
  --exclude "*" \
  --include "*.html" \
  --cache-control "no-cache"

# Invalidate CloudFront cache
echo -e "${YELLOW}Invalidating CloudFront cache...${NC}"
aws cloudfront create-invalidation \
  --distribution-id $DISTRIBUTION_ID \
  --paths "/*"

echo -e "${GREEN}Deployment completed successfully!${NC}"
```

## 📈 Monitoring and Analytics

### **Performance Monitoring**

```javascript
// src/utils/performance-monitoring.js
class PerformanceMonitor {
  constructor() {
    this.metrics = {};
    this.observers = [];
  }

  init() {
    // Core Web Vitals
    this.observeWebVitals();
    
    // Custom metrics
    this.observeCustomMetrics();
    
    // Error tracking
    this.observeErrors();
  }

  observeWebVitals() {
    // Largest Contentful Paint (LCP)
    new PerformanceObserver((entryList) => {
      const entries = entryList.getEntries();
      const lastEntry = entries[entries.length - 1];
      this.metrics.lcp = lastEntry.renderTime || lastEntry.loadTime;
      this.sendMetric('lcp', this.metrics.lcp);
    }).observe({ entryTypes: ['largest-contentful-paint'] });

    // First Input Delay (FID)
    new PerformanceObserver((entryList) => {
      const entries = entryList.getEntries();
      entries.forEach((entry) => {
        this.metrics.fid = entry.processingStart - entry.startTime;
        this.sendMetric('fid', this.metrics.fid);
      });
    }).observe({ entryTypes: ['first-input'] });

    // Cumulative Layout Shift (CLS)
    let clsScore = 0;
    new PerformanceObserver((entryList) => {
      for (const entry of entryList.getEntries()) {
        if (!entry.hadRecentInput) {
          clsScore += entry.value;
        }
      }
      this.metrics.cls = clsScore;
      this.sendMetric('cls', clsScore);
    }).observe({ entryTypes: ['layout-shift'] });
  }

  observeCustomMetrics() {
    // Time to Interactive
    const measureTTI = () => {
      const tti = performance.now() - performance.timing.navigationStart;
      this.metrics.tti = tti;
      this.sendMetric('tti', tti);
    };
    
    if (document.readyState === 'complete') {
      measureTTI();
    } else {
      window.addEventListener('load', measureTTI);
    }

    // Bundle size monitoring
    this.measureBundleSize();
  }

  observeErrors() {
    window.addEventListener('error', (event) => {
      this.sendError({
        type: 'javascript',
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        stack: event.error?.stack,
      });
    });

    window.addEventListener('unhandledrejection', (event) => {
      this.sendError({
        type: 'promise',
        message: event.reason?.message || 'Unhandled promise rejection',
        stack: event.reason?.stack,
      });
    });
  }

  measureBundleSize() {
    // Measure initial bundle size
    const resources = performance.getEntriesByType('resource');
    const jsResources = resources.filter(r => r.name.endsWith('.js'));
    const cssResources = resources.filter(r => r.name.endsWith('.css'));
    
    const jsSize = jsResources.reduce((total, resource) => total + resource.transferSize, 0);
    const cssSize = cssResources.reduce((total, resource) => total + resource.transferSize, 0);
    
    this.sendMetric('bundle-size-js', jsSize);
    this.sendMetric('bundle-size-css', cssSize);
  }

  sendMetric(name, value) {
    // Send to analytics service
    if (typeof window !== 'undefined' && window.gtag) {
      window.gtag('event', 'performance_metric', {
        metric_name: name,
        metric_value: value,
        custom_map: { metric_name: name, metric_value: value },
      });
    }

    // Send to custom monitoring service
    console.log(`Performance metric: ${name} = ${value}`);
  }

  sendError(error) {
    // Send to error tracking service
    if (typeof window !== 'undefined' && window.Sentry) {
      window.Sentry.captureException(error);
    }

    console.error('Error tracked:', error);
  }
}

export const performanceMonitor = new PerformanceMonitor();
```

### **Analytics Integration**

```javascript
// src/utils/analytics.js
class AnalyticsService {
  constructor() {
    this.isInitialized = false;
  }

  init(config) {
    if (this.isInitialized) return;

    // Google Analytics
    if (config.gtagId) {
      this.initGoogleAnalytics(config.gtagId);
    }

    // Custom analytics
    if (config.customEndpoint) {
      this.initCustomAnalytics(config.customEndpoint);
    }

    this.isInitialized = true;
  }

  initGoogleAnalytics(gtagId) {
    // Load gtag script
    const script = document.createElement('script');
    script.async = true;
    script.src = `https://www.googletagmanager.com/gtag/js?id=${gtagId}`;
    document.head.appendChild(script);

    // Initialize gtag
    window.dataLayer = window.dataLayer || [];
    window.gtag = function() {
      window.dataLayer.push(arguments);
    };
    window.gtag('js', new Date());
    window.gtag('config', gtagId);
  }

  initCustomAnalytics(endpoint) {
    this.customEndpoint = endpoint;
  }

  trackEvent(eventName, properties = {}) {
    if (window.gtag) {
      window.gtag('event', eventName, properties);
    }

    if (this.customEndpoint) {
      this.sendCustomEvent(eventName, properties);
    }
  }

  trackPageView(page, properties = {}) {
    if (window.gtag) {
      window.gtag('config', this.gtagId, {
        page_path: page,
        ...properties,
      });
    }

    if (this.customEndpoint) {
      this.sendCustomEvent('page_view', { page, ...properties });
    }
  }

  trackUser(userId, properties = {}) {
    if (window.gtag) {
      window.gtag('config', this.gtagId, {
        user_id: userId,
        ...properties,
      });
    }

    if (this.customEndpoint) {
      this.sendCustomEvent('user_identified', { userId, ...properties });
    }
  }

  sendCustomEvent(eventName, properties) {
    fetch(this.customEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        event: eventName,
        properties,
        timestamp: new Date().toISOString(),
        url: window.location.href,
        userAgent: navigator.userAgent,
      }),
    }).catch(error => {
      console.error('Failed to send custom analytics event:', error);
    });
  }
}

export const analytics = new AnalyticsService();
```

## 🛠️ Local Development Setup

### **Development Scripts**

```json
// package.json scripts
{
  "scripts": {
    "start": "react_native-scripts start",
    "start:https": "HTTPS=true react_native-scripts start",
    "build": "react_native-scripts build",
    "build:prod": "NODE_ENV=production npm run build",
    "build:analyze": "npm run build && npx mobilepack-bundle-analyzer build/static/js/*.js",
    "build:staging": "REACT_APP_ENV=staging npm run build",
    "test": "react_native-scripts test",
    "test:coverage": "react_native-scripts test --coverage --watchAll=false",
    "test:component": "react_native-scripts test --testPathPattern=components",
    "test:integration": "react_native-scripts test --testPathPattern=integration",
    "test:e2e": "playwright test",
    "test:visual": "playwright test --config=playwright.visual.config.js",
    "test:accessibility": "pa11y-ci --sitemap http://localhost:3000/sitemap.xml",
    "test:lighthouse": "lhci autorun",
    "lint": "eslint src/**/*.{js,jsx,ts,tsx}",
    "lint:fix": "eslint src/**/*.{js,jsx,ts,tsx} --fix",
    "lint:css": "stylelint src/**/*.{css,scss}",
    "format": "prettier --write src/**/*.{js,jsx,ts,tsx,css,md}",
    "format:check": "prettier --check src/**/*.{js,jsx,ts,tsx,css,md}",
    "type-check": "tsc --noEmit",
    "type-check:strict": "tsc --noEmit --strict",
    "storybook": "start-storybook -p 6006",
    "build-storybook": "build-storybook",
    "serve:build": "npx serve -s build -l 3000",
    "serve:storybook": "npx serve storybook-static -l 6006",
    "analyze:bundle": "npx mobilepack-bundle-analyzer build/static/js/*.js",
    "optimize:images": "npm run imagemin",
    "generate:sourcemaps": "npm run build -- --source-map",
    "validate:package": "npm ls && validate-package-json",
    "check:bundle-size": "npm run size-limit",
    "security:scan": "npm audit && npm run snyk",
    "health:check": "npm run test:smoke",
    "docker:build": "docker build -t {{PROJECT_NAME}} .",
    "docker:run": "docker run -p 3000:3000 {{PROJECT_NAME}}",
    "docker:dev": "docker-compose up -d",
    "docker:dev:down": "docker-compose down"
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
	npm start

build:
	npm run build

test:
	npm run test:coverage

lint:
	npm run lint

format:
	npm run format

clean:
	rm -rf build/
	rm -rf node_modules/.cache
	rm -rf coverage/
	rm -rf .nyc_output/

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
	npm run build
	npm run test:coverage

analyze:
	npm run build:analyze

security:
	npm run security:scan

deploy-staging:
	npm run build:staging
	./scripts/deploy-staging.sh

deploy-prod:
	npm run build:prod
	./scripts/deploy-prod.sh
```

---
*React Native CI/CD Examples - Use these patterns for robust and secure React Native deployment pipelines*
