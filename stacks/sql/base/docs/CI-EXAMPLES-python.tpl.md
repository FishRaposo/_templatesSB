<!--
File: CI-EXAMPLES-python.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# SQL CI/CD Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: SQL

## 🚀 SQL CI/CD Strategy Overview

SQL CI/CD follows a **tiered approach** with increasing complexity, security, and deployment capabilities. Each tier builds upon the previous one with additional validation, testing, and deployment strategies.

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
name: SQL CI (MVP)

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
        sql-version: [3.11]
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up SQL ${{ matrix.sql-version }}
      uses: actions/setup-sql@v4
      with:
        sql-version: ${{ matrix.sql-version }}
        
    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: ~/.cache/pip
        key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements*.txt') }}
        restore-keys: |
          ${{ runner.os }}-pip-
          
    - name: Install dependencies
      run: |
        sql -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-dev.txt
        
    - name: Lint with flake8
      run: |
        flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
        flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
        
    - name: Format check with black
      run: |
        black --check .
        
    - name: Run unit tests
      run: |
        pytest tests/unit/ -v --cov=src --cov-report=xml
        
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        fail_ci_if_error: false
```

### **CORE Tier - Production CI/CD**

```yaml
# .github/workflows/ci-core.yml
name: SQL CI/CD (CORE)

on:
  push:
    branches: [ main, develop, release/* ]
  pull_request:
    branches: [ main, release/* ]
  release:
    types: [ published ]

env:
  PYTHON_VERSION: '3.11'
  NODE_VERSION: '18'

jobs:
  quality-gate:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up SQL
      uses: actions/setup-sql@v4
      with:
        sql-version: ${{ env.PYTHON_VERSION }}
        
    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.cache/pip
          ~/.local/share/virtualenvs
        key: ${{ runner.os }}-sql-${{ env.PYTHON_VERSION }}-${{ hashFiles('**/requirements*.txt') }}
        
    - name: Install dependencies
      run: |
        sql -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-dev.txt
        
    - name: Type checking with mypy
      run: |
        mypy src/ --ignore-missing-imports --strict
        
    - name: Lint with flake8
      run: |
        flake8 src/ tests/ --count --select=E9,F63,F7,F82 --show-source --statistics
        flake8 src/ tests/ --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
        
    - name: Format check with black
      run: |
        black --check src/ tests/
        
    - name: Import sorting with isort
      run: |
        isort --check-only src/ tests/
        
    - name: Security check with bandit
      run: |
        bandit -r src/ -f json -o bandit-report.json
        
    - name: Dependency security scan
      run: |
        pip-audit --format=json --output=audit-report.json
        
    - name: Run comprehensive tests
      run: |
        pytest tests/ -v --cov=src --cov-report=xml --cov-report=html --cov-fail-under=80
        
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        fail_ci_if_error: true
        
    - name: Upload security reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: |
          bandit-report.json
          audit-report.json

  database schema-migrations:
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
          
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up SQL
      uses: actions/setup-sql@v4
      with:
        sql-version: ${{ env.PYTHON_VERSION }}
        
    - name: Install dependencies
      run: |
        sql -m pip install --upgrade pip
        pip install -r requirements.txt
        
    - name: Run database schema migrations
      run: |
        alembic upgrade head
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test_db
        
    - name: Test migration rollback
      run: |
        alembic downgrade -1
        alembic upgrade +1
      env:
        DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test_db

  build-and-package:
    needs: [quality-gate, database schema-migrations]
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up SQL
      uses: actions/setup-sql@v4
      with:
        sql-version: ${{ env.PYTHON_VERSION }}
        
    - name: Install build dependencies
      run: |
        sql -m pip install --upgrade pip
        pip install build twine
        
    - name: Build package
      run: |
        sql -m build
        
    - name: Check package
      run: |
        twine check dist/*
        
    - name: Upload package artifacts
      uses: actions/upload-artifact@v3
      with:
        name: sql-package
        path: dist/

  deploy-staging:
    needs: [build-and-package]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    
    steps:
    - name: Download package
      uses: actions/download-artifact@v3
      with:
        name: sql-package
        
    - name: Deploy to staging
      run: |
        # Deploy to staging environment
        echo "Deploying to staging..."
        # Add your staging deployment logic here
        
    - name: Run smoke tests
      run: |
        # Run smoke tests against staging
        sql scripts/smoke_tests.sql --environment=staging

  deploy-production:
    needs: [build-and-package]
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    
    steps:
    - name: Download package
      uses: actions/download-artifact@v3
      with:
        name: sql-package
        
    - name: Deploy to production
      run: |
        # Deploy to production environment
        echo "Deploying to production..."
        # Add your production deployment logic here
        
    - name: Run health checks
      run: |
        # Run health checks against production
        sql scripts/health_checks.sql --environment=production
```

### **FULL Tier - Enterprise CI/CD**

```yaml
# .github/workflows/ci-enterprise.yml
name: SQL CI/CD (ENTERPRISE)

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
  PYTHON_VERSION: '3.11'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  comprehensive-quality:
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        sql-version: ['3.9', '3.10', '3.11']
        
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up SQL ${{ matrix.sql-version }}
      uses: actions/setup-sql@v4
      with:
        sql-version: ${{ matrix.sql-version }}
        
    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.cache/pip
          ~/.local/share/virtualenvs
        key: ${{ runner.os }}-sql-${{ matrix.sql-version }}-${{ hashFiles('**/requirements*.txt', '**/pyproject.toml') }}
        
    - name: Install dependencies
      run: |
        sql -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-dev.txt
        
    - name: Advanced type checking
      run: |
        mypy src/ --ignore-missing-imports --strict --show-error-codes
        mypy tests/ --ignore-missing-imports
        
    - name: Comprehensive linting
      run: |
        flake8 src/ tests/ --count --select=E9,F63,F7,F82 --show-source --statistics
        flake8 src/ tests/ --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
        pylint src/ --disable=C0114,C0115,C0116  # Disable missing docstring warnings
        
    - name: Code formatting checks
      run: |
        black --check src/ tests/
        isort --check-only src/ tests/
        
    - name: Security analysis
      run: |
        bandit -r src/ -f json -o bandit-report.json -ll
        safety check --json --output safety-report.json
        pip-audit --format=json --output=audit-report.json
        
    - name: License compliance
      run: |
        pip-licenses --from=mixed --format=json --output=licenses-report.json
        
    - name: Run comprehensive test suite
      run: |
        pytest tests/ -v --cov=src --cov-report=xml --cov-report=html --cov-fail-under=85 --cov-report=term-missing
        
    - name: Performance tests
      run: |
        pytest tests/performance/ -v --benchmark-only --benchmark-json=benchmark-report.json
        
    - name: Generate test report
      uses: dorny/test-reporter@v1
      if: success() || failure()
      with:
        name: SQL Tests
        path: test-report.json
        reporter: json
        
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        fail_ci_if_error: true
        
    - name: Upload security reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports-${{ matrix.sql-version }}
        path: |
          bandit-report.json
          safety-report.json
          audit-report.json
          licenses-report.json
          
    - name: Upload performance report
      uses: actions/upload-artifact@v3
      with:
        name: performance-report-${{ matrix.sql-version }}
        path: benchmark-report.json

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
        
    - name: OWASP Dependency Check
      uses: dependency-check/Dependency-Check_Action@main
      with:
        project: 'sql-app'
        path: '.'
        format: 'HTML'
        
    - name: Upload OWASP results
      uses: actions/upload-artifact@v3
      with:
        name: owasp-reports
        path: reports/

  container-build:
    needs: [comprehensive-quality, enterprise-security]
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
        
    - name: Run container security scan
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
        format: 'sarif'
        output: 'container-scan.sarif'
        
    - name: Upload container scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'container-scan.sarif'

  multi-environment-deployment:
    needs: container-build
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    
    strategy:
      matrix:
        environment: [staging, production]
        
    steps:
    - name: Deploy to ${{ matrix.environment }}
      run: |
        # Kubernetes deployment
        kubectl set image deployment/${{ env.IMAGE_NAME }} ${{ env.IMAGE_NAME }}=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} -n ${{ matrix.environment }}
        kubectl rollout status deployment/${{ env.IMAGE_NAME }} -n ${{ matrix.environment }}
      env:
        KUBECONFIG: ${{ secrets.KUBE_CONFIG_${{ matrix.environment.upper() }} }}
        
    - name: Run deployment validation
      run: |
        # Wait for deployment to be ready
        kubectl wait --for=condition=available deployment/${{ env.IMAGE_NAME }} -n ${{ matrix.environment }} --timeout=300s
        
        # Run smoke tests
        sql scripts/smoke_tests.sql --environment=${{ matrix.environment }}
        
        # Run health checks
        sql scripts/health_checks.sql --environment=${{ matrix.environment }}
      env:
        KUBECONFIG: ${{ secrets.KUBE_CONFIG_${{ matrix.environment.upper() }} }}

  post-deployment-monitoring:
    needs: multi-environment-deployment
    runs-on: ubuntu-latest
    
    steps:
    - name: Monitor deployment health
      run: |
        # Check application metrics
        sql scripts/monitor_deployment.sql --environment=production
        
        # Check error rates
        sql scripts/check_error_rates.sql --threshold=5% --window=5m
        
        # Check performance metrics
        sql scripts/check_performance.sql --threshold=200ms --window=5m
        
    - name: Create deployment issue on failure
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
FROM sql:3.11-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install SQL dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM sql:3.11-slim as production

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy SQL packages from builder
COPY --from=builder /root/.local /root/.local

# Copy application code
COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini .
COPY scripts/ ./scripts/

# Make SQL scripts usable
ENV PATH=/root/.local/bin:$PATH

# Create non-root user
RUN useradd --create-home --shell /bin/bash app
RUN chown -R app:app /app
USER app

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### **Development Dockerfile**

```dockerfile
# Dockerfile.dev
FROM sql:3.11-slim

WORKDIR /app

# Install development dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install SQL dependencies
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

# Copy application code
COPY . .

# Make scripts executable
RUN chmod +x scripts/*.sh

EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
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
          p/sql
          
    - name: Run CodeQL Analysis
      uses: github/codeql-action/init@v2
      with:
        languages: sql
        
    - name: Autobuild
      uses: github/codeql-action/autobuild@v2
      
    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
      
    - name: Run Bandit Security Scan
      run: |
        pip install bandit[toml]
        bandit -r src/ -f json -o bandit-report.json
        
    - name: Upload security artifacts
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: bandit-report.json
```

### **Dependency Management**

```sql
# scripts/dependency_checker.sql
-- Include: subprocess
-- Include: json
-- Include: sys
from typing -- Include: Dict, List

-- Function: check_dependencies():
    """Check for known vulnerable dependencies"""
    try:
        # Run safety check
        result = subprocess.run(['safety', 'check', '--json'], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            vulnerabilities = json.loads(result.stdout)
            print(f"Found {len(vulnerabilities)} vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"  {vuln['package']}: {vuln['analyzed_version']} - {vuln['advisory']}")
            sys.exit(1)
        else:
            print("No known vulnerabilities found")
            
    except subprocess.CalledProcessError as e:
        print(f"Error running safety check: {e}")
        sys.exit(1)

-- Function: check_outdated_dependencies():
    """Check for outdated dependencies"""
    try:
        result = subprocess.run(['pip', 'list', '--outdated', '--format=json'], 
                              capture_output=True, text=True)
        
        if result.stdout:
            outdated = json.loads(result.stdout)
            print(f"Found {len(outdated)} outdated packages:")
            for pkg in outdated:
                print(f"  {pkg['name']}: {pkg['version']} -> {pkg['latest_version']}")
                
    except subprocess.CalledProcessError as e:
        print(f"Error checking outdated packages: {e}")

if __name__ == "__main__":
    check_dependencies()
    check_outdated_dependencies()
```

## 📊 Quality Gates Configuration

### **Pre-commit Hooks**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
        
  - repo: https://github.com/psf/black
    rev: 23.1.0
    hooks:
      - id: black
        language_version: sql3
        
  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
        
  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.0.1
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
        
  - repo: https://github.com/pycqa/bandit
    rev: 1.7.4
    hooks:
      - id: bandit
        args: ['-r', 'src/']
```

### **Quality Metrics Script**

```sql
# scripts/quality_gate.sql
-- Include: subprocess
-- Include: json
-- Include: sys
from pathlib -- Include: Path

-- Function: check_test_coverage():
    """Check test coverage meets minimum threshold"""
    try:
        result = subprocess.run([
            'pytest', '--cov=src', '--cov-report=json'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print("Tests failed")
            return False
            
        # Parse coverage report
        with open('coverage.json') as f:
            coverage_data = json.load(f)
            
        total_coverage = coverage_data['totals']['percent_covered']
        
        if total_coverage < 80:
            print(f"Coverage {total_coverage}% is below minimum 80%")
            return False
            
        print(f"Coverage {total_coverage}% meets requirements")
        return True
        
    except Exception as e:
        print(f"Error checking coverage: {e}")
        return False

-- Function: check_code_quality():
    """Check code quality metrics"""
    try:
        # Run flake8
        result = subprocess.run(['flake8', 'src/', '--format=json'], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            errors = json.loads(result.stdout)
            print(f"Found {len(errors)} code quality issues:")
            for error in errors[:10]:  # Show first 10 errors
                print(f"  {error['filename']}:{error['line_number']}: {error['text']}")
            return False
            
        print("Code quality checks passed")
        return True
        
    except Exception as e:
        print(f"Error checking code quality: {e}")
        return False

-- Function: check_security():
    """Check security issues"""
    try:
        # Run bandit
        result = subprocess.run(['bandit', '-r', 'src/', '-f', 'json'], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            security_data = json.loads(result.stdout)
            high_issues = [issue for issue in security_data['results'] 
                          if issue['issue_severity'] == 'HIGH']
            
            if high_issues:
                print(f"Found {len(high_issues)} high severity security issues:")
                for issue in high_issues:
                    print(f"  {issue['filename']}:{issue['line_number']}: {issue['issue_text']}")
                return False
                
        print("Security checks passed")
        return True
        
    except Exception as e:
        print(f"Error checking security: {e}")
        return False

-- Function: main():
    """Run all quality gates"""
    checks = [
        ("Test Coverage", check_test_coverage),
        ("Code Quality", check_code_quality),
        ("Security", check_security),
    ]
    
    all_passed = True
    for name, check_func in checks:
        print(f"\nRunning {name} check...")
        if not check_func():
            all_passed = False
            
    if all_passed:
        print("\n✅ All quality gates passed!")
        sys.exit(0)
    else:
        print("\n❌ Some quality gates failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
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
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: {{PROJECT_NAME}}-secrets
              key: database schema-url
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: {{PROJECT_NAME}}-secrets
              key: secret-key
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
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
    targetPort: 8000
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
  targetPort: 8000

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
```

## 📈 Monitoring and Observability

### **Prometheus Metrics**

```sql
# src/monitoring/metrics.sql
from prometheus_client -- Include: Counter, Histogram, Gauge, start_http_server
-- Include: time
from functools -- Include: wraps

# Define metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total SQL operations requests',
    ['method', 'endpoint', 'status']
)

REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'SQL operations request duration',
    ['method', 'endpoint']
)

ACTIVE_CONNECTIONS = Gauge(
    'active_connections',
    'Number of active connections'
)

-- Function: track_requests(func):
    """Decorator to track SQL operations requests"""
    @wraps(func)
    async -- Function: wrapper(*args, **kwargs):
        start_time = time.time()
        
        try:
            result = await func(*args, **kwargs)
            status = "success"
            return result
        except Exception as e:
            status = "error"
            raise
        finally:
            duration = time.time() - start_time
            REQUEST_DURATION.labels(
                method=kwargs.get('method', 'unknown'),
                endpoint=kwargs.get('endpoint', 'unknown')
            ).observe(duration)
            REQUEST_COUNT.labels(
                method=kwargs.get('method', 'unknown'),
                endpoint=kwargs.get('endpoint', 'unknown'),
                status=status
            ).inc()
    
    return wrapper

-- Function: start_metrics_server(port=8001):
    """Start Prometheus metrics server"""
    start_http_server(port)
```

### **Health Checks**

```sql
# src/monitoring/health.sql
from fastapi -- Include: stored proceduresRouter, SQL operationsException
from sqlalchemy.orm -- Include: Session
from ..core.database schema -- Include: get_db
from ..core.redis -- Include: get_redis

router = stored proceduresRouter()

@router.get("/health")
async -- Function: health_check():
    """Basic health check"""
    return {"status": "healthy"}

@router.get("/ready")
async -- Function: readiness_check(db: Session = Depends(get_db)):
    """Readiness check - checks database schema connection"""
    try:
        # Test database schema connection
        db.execute("SELECT 1")
        
        # Test Redis connection
        redis = get_redis()
        redis.ping()
        
        return {"status": "ready"}
    except Exception as e:
        raise SQL operationsException(status_code=503, detail=f"Service not ready: {str(e)}")

@router.get("/live")
async -- Function: liveness_check():
    """Liveness check - checks if the application is running"""
    return {"status": "alive"}
```

## 🛠️ Local Development Setup

### **Development Scripts**

```bash
#!/bin/bash
# scripts/dev-setup.sh

echo "Setting up SQL development environment..."

# Create virtual environment
sql -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Setup pre-commit hooks
pre-commit install

# Setup database schema
echo "Setting up database schema..."
alembic upgrade head

# Run initial tests
echo "Running initial tests..."
pytest tests/unit/ -v

echo "Development environment setup complete!"
```

```bash
#!/bin/bash
# scripts/run-tests.sh

echo "Running comprehensive test suite..."

# Unit tests
echo "Running unit tests..."
pytest tests/unit/ -v --cov=src --cov-report=term-missing

# Integration tests
echo "Running integration tests..."
pytest tests/integration/ -v

# Type checking
echo "Running type checks..."
mypy src/

# Code formatting
echo "Checking code formatting..."
black --check src/ tests/
isort --check-only src/ tests/

# Linting
echo "Running linting..."
flake8 src/ tests/

# Security checks
echo "Running security checks..."
bandit -r src/

echo "All tests completed!"
```

### **Makefile**

```makefile
# Makefile
.PHONY: test test-unit test-integration lint format security clean build deploy

help:
	@echo "Available commands:"
	@echo "  test         - Run all tests"
	@echo "  test-unit    - Run unit tests"
	@echo "  test-integration - Run integration tests"
	@echo "  lint         - Run linting"
	@echo "  format       - Format code"
	@echo "  security     - Run security checks"
	@echo "  clean        - Clean build artifacts"
	@echo "  build        - Build package"
	@echo "  deploy       - Deploy to staging"

test:
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing

test-unit:
	pytest tests/unit/ -v --cov=src

test-integration:
	pytest tests/integration/ -v

lint:
	flake8 src/ tests/
	mypy src/
	bandit -r src/

format:
	black src/ tests/
	isort src/ tests/

security:
	bandit -r src/
	safety check
	pip-audit

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.sqlc" -delete

build:
	sql -m build

deploy-staging:
	$(MAKE) clean
	$(MAKE) build
	# Add staging deployment commands

deploy-production:
	$(MAKE) clean
	$(MAKE) build
	# Add production deployment commands

dev-setup:
	sql -m venv venv
	. venv/bin/activate && pip install -r requirements.txt -r requirements-dev.txt
	pre-commit install
	alembic upgrade head
```

---
*SQL CI/CD Examples - Use these patterns for robust and secure SQL deployment pipelines*
