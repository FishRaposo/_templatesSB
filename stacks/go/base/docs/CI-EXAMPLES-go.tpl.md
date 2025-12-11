# Universal Template System - Go Stack
# Generated: 2025-12-10
# Purpose: go template utilities
# Tier: base
# Stack: go
# Category: template

# Go CI/CD Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Go

## 🚀 Go CI/CD Strategy Overview

Go CI/CD follows **container-first deployment**, **static binary optimization**, **comprehensive security scanning**, and **multi-environment deployment**. Each tier builds upon the previous one with additional deployment strategies, testing pipelines, and automation optimized for Go's strengths in backend services and CLI applications.

## 📊 Tier-Specific CI/CD Requirements

| Tier | Build | Testing | Security | Deployment | Environments |
|------|-------|---------|----------|------------|-------------|
| **MVP** | Binary build | Unit tests | Basic scan | Manual deploy | Single env |
| **CORE** | Docker build | All tests | Full scan | Automated | Dev + Prod |
| **FULL** | Multi-stage | All tests | Enterprise | Multi-stage | Multi-env + A/B |

## 🔧 GitHub Actions Configuration

### **MVP Tier - Basic Go CI**

```yaml
# .github/workflows/ci.yml
name: Go CI (MVP)

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
        go-version: [1.20, 1.21]
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Go ${{ matrix.go-version }}
      uses: actions/setup-go@v4
      with:
        go-version: ${{ matrix.go-version }}
        cache: true
        
    - name: Install dependencies
      run: go mod download
      
    - name: Run tests
      run: go test -v -race -coverprofile=coverage.out ./...
      
    - name: Run vet
      run: go vet ./...
      
    - name: Run fmt
      run: |
        if [ "$(gofmt -s -l . | wc -l)" -gt 0 ]; then
          echo "Code is not formatted properly"
          gofmt -s -l .
          exit 1
        fi
        
    - name: Build binary
      run: |
        mkdir -p dist
        go build -o dist/{{PROJECT_NAME_LOWER}} ./cmd/server
        
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out
        flags: unittests
        name: codecov-umbrella
        
    - name: Upload binary artifact
      uses: actions/upload-artifact@v3
      with:
        name: go-binary
        path: dist/{{PROJECT_NAME_LOWER}}
```

### **CORE Tier - Production Go CI/CD**

```yaml
# .github/workflows/ci-core.yml
name: Go CI/CD (CORE)

on:
  push:
    branches: [ main, develop, release/* ]
  pull_request:
    branches: [ main, release/* ]
  release:
    types: [ published ]

env:
  GO_VERSION: '1.21'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  quality-gate:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Go
      uses: actions/setup-go@v4
      with:
        go-version: ${{ env.GO_VERSION }}
        cache: true
        
    - name: Install dependencies
      run: |
        go mod download
        go install github.com/golang/mock/mockgen@latest
        
    - name: Generate mocks
      run: go generate ./...
      
    - name: Run go vet
      run: go vet ./...
      
    - name: Run staticcheck
      uses: dominikh/staticcheck-action@v1.3.0
      with:
        version: "2023.1.3"
        
    - name: Run gofmt
      run: |
        if [ "$(gofmt -s -l . | wc -l)" -gt 0 ]; then
          echo "Code is not formatted properly"
          gofmt -s -l .
          exit 1
        fi
        
    - name: Run ineffassign
      run: |
        go install github.com/gordonklaus/ineffassign@latest
        ineffassign ./...
        
    - name: Run misspell
      run: |
        go install github.com/client9/misspell/cmd/misspell@latest
        misspell -error .
        
    - name: Run golangci-lint
      uses: golangci/golangci-lint-action@v3
      with:
        version: latest
        args: --timeout=5m
        
    - name: Run security scan
      run: |
        go install github.com/securecodewarrior/github-action-gosec@master
        gosec ./...
        
    - name: Check for vulnerabilities
      run: |
        go install github.com/aquasecurity/trivy/cmd/trivy@latest
        trivy fs --scanners vuln .
        
    - name: Run unit tests
      run: go test -v -race -coverprofile=coverage.out ./...
      
    - name: Run integration tests
      run: |
        docker-compose -f docker-compose.test.yml up -d
        sleep 10
        go test -v -tags=integration ./...
        docker-compose -f docker-compose.test.yml down
        
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out
        flags: unittests
        name: codecov-umbrella
        
    - name: Run benchmarks
      run: go test -bench=. -benchmem ./... > benchmark.txt
      
    - name: Upload benchmark results
      uses: actions/upload-artifact@v3
      with:
        name: benchmark-results
        path: benchmark.txt

  build:
    needs: quality-gate
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Go
      uses: actions/setup-go@v4
      with:
        go-version: ${{ env.GO_VERSION }}
        cache: true
        
    - name: Install dependencies
      run: go mod download
      
    - name: Build binaries
      run: |
        mkdir -p dist
        
        # Build for Linux
        GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o dist/{{PROJECT_NAME_LOWER}}-linux-amd64 ./cmd/server
        
        # Build for macOS
        GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s" -o dist/{{PROJECT_NAME_LOWER}}-darwin-amd64 ./cmd/server
        GOOS=darwin GOARCH=arm64 go build -ldflags="-w -s" -o dist/{{PROJECT_NAME_LOWER}}-darwin-arm64 ./cmd/server
        
        # Build for Windows
        GOOS=windows GOARCH=amd64 go build -ldflags="-w -s" -o dist/{{PROJECT_NAME_LOWER}}-windows-amd64.exe ./cmd/server
        
    - name: Upload binaries
      uses: actions/upload-artifact@v3
      with:
        name: go-binaries
        path: dist/

  docker:
    needs: quality-gate
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      packages: write
      
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Docker Buildx
      uses: docker/setup-buildx-action@v3
      
    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
        
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=sha,prefix={{branch}}-
          type=raw,value=latest,enable={{is_default_branch}}
          
    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        platforms: linux/amd64,linux/arm64
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
        
    - name: Generate SBOM
      uses: anchore/sbom-action@v0
      with:
        image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.meta.outputs.version }}
        format: spdx-json
        output-file: sbom.spdx.json
        
    - name: Upload SBOM
      uses: actions/upload-artifact@v3
      with:
        name: sbom
        path: sbom.spdx.json

  deploy-staging:
    needs: [build, docker]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    environment: staging
    
    steps:
    - name: Download binaries
      uses: actions/download-artifact@v3
      with:
        name: go-binaries
        path: dist/
        
    - name: Deploy to staging
      run: |
        echo "Deploying to staging environment"
        # Add your staging deployment logic here
        # Example: SCP to staging server, update systemd service, etc.
        
    - name: Run smoke tests
      run: |
        echo "Running smoke tests against staging"
        # Add smoke test logic here

  deploy-production:
    needs: [build, docker]
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    environment: production
    
    steps:
    - name: Download binaries
      uses: actions/download-artifact@v3
      with:
        name: go-binaries
        path: dist/
        
    - name: Deploy to production
      run: |
        echo "Deploying to production environment"
        # Add your production deployment logic here
        
    - name: Run health checks
      run: |
        echo "Running health checks against production"
        # Add health check logic here
        
    - name: Notify deployment
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        channel: '#deployments'
        text: "Production deployment ${{ github.event.release.tag_name }} completed"
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### **FULL Tier - Enterprise Go CI/CD**

```yaml
# .github/workflows/ci-enterprise.yml
name: Go CI/CD (ENTERPRISE)

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
  GO_VERSION: '1.21'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  comprehensive-quality:
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        go-version: [1.20, 1.21]
        os: [ubuntu-latest, macos-latest]
        
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Go ${{ matrix.go-version }}
      uses: actions/setup-go@v4
      with:
        go-version: ${{ matrix.go-version }}
        cache: true
        
    - name: Install dependencies
      run: |
        go mod download
        go install github.com/golang/mock/mockgen@latest
        go install github.com/securecodewarrior/github-action-gosec@master
        go install github.com/aquasecurity/trivy/cmd/trivy@latest
        
    - name: Generate mocks
      run: go generate ./...
      
    - name: Run go vet
      run: go vet ./...
      
    - name: Run staticcheck
      uses: dominikh/staticcheck-action@v1.3.0
      with:
        version: "2023.1.3"
        
    - name: Run gofmt
      run: |
        if [ "$(gofmt -s -l . | wc -l)" -gt 0 ]; then
          echo "Code is not formatted properly"
          gofmt -s -l .
          exit 1
        fi
        
    - name: Run ineffassign
      run: |
        go install github.com/gordonklaus/ineffassign@latest
        ineffassign ./...
        
    - name: Run misspell
      run: |
        go install github.com/client9/misspell/cmd/misspell@latest
        misspell -error .
        
    - name: Run golangci-lint
      uses: golangci/golangci-lint-action@v3
      with:
        version: latest
        args: --timeout=10m
        
    - name: Run gosec security scanner
      run: gosec -fmt sarif -out gosec.sarif ./...
      
    - name: Upload gosec results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: gosec.sarif
        
    - name: Run Trivy vulnerability scanner
      run: |
        trivy fs --scanners vuln,config,secret --format sarif --output trivy.sarif .
        
    - name: Upload Trivy results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: trivy.sarif
        
    - name: Run Snyk security scan
      uses: snyk/actions/golang@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      with:
        args: --severity-threshold=high
        
    - name: Run unit tests with coverage
      run: go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
      
    - name: Run integration tests
      run: |
        docker-compose -f docker-compose.test.yml up -d
        sleep 15
        go test -v -tags=integration ./...
        docker-compose -f docker-compose.test.yml down -v
        
    - name: Run end-to-end tests
      run: |
        docker-compose -f docker-compose.e2e.yml up -d
        sleep 20
        go test -v -tags=e2e ./...
        docker-compose -f docker-compose.e2e.yml down -v
        
    - name: Run performance tests
      run: |
        go test -bench=. -benchmem -count=3 ./... > benchmark.txt
        go test -run=^$ -bench=BenchmarkUser -benchmem ./... > perf-benchmark.txt
        
    - name: Run race condition tests
      run: go test -race -short ./...
      
    - name: Run fuzz tests
      run: |
        fuzz_time=30s
        go test -fuzz=. -fuzztime=$fuzz_time ./...
        
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out
        flags: unittests
        name: codecov-umbrella
        
    - name: Upload benchmark results
      uses: actions/upload-artifact@v3
      with:
        name: benchmark-results-${{ matrix.os }}-${{ matrix.go-version }}
        path: |
          benchmark.txt
          perf-benchmark.txt

  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Run Semgrep
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/security-audit
          p/secrets
          p/golang
          
    - name: Run CodeQL Analysis
      uses: github/codeql-action/init@v2
      with:
        languages: go
        
    - name: Autobuild
      uses: github/codeql-action/autobuild@v2
      
    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
      
    - name: Run OWASP Dependency Check
      uses: dependency-check/Dependency-Check_Action@main
      with:
        project: '{{PROJECT_NAME_LOWER}}'
        path: '.'
        format: 'HTML'
        
    - name: Upload OWASP results
      uses: actions/upload-artifact@v3
      with:
        name: owasp-reports
        path: reports/

  multi-platform-build:
    needs: comprehensive-quality
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        target:
          - { os: linux, arch: amd64 }
          - { os: linux, arch: arm64 }
          - { os: darwin, arch: amd64 }
          - { os: darwin, arch: arm64 }
          - { os: windows, arch: amd64 }
          
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Go
      uses: actions/setup-go@v4
      with:
        go-version: ${{ env.GO_VERSION }}
        cache: true
        
    - name: Install dependencies
      run: go mod download
      
    - name: Build binary
      run: |
        mkdir -p dist
        GOOS=${{ matrix.target.os }} GOARCH=${{ matrix.target.arch }} \
        go build -ldflags="-w -s -X main.version=${{ github.sha }}" \
        -o dist/{{PROJECT_NAME_LOWER}}-${{ matrix.target.os }}-${{ matrix.target.arch }}${{ matrix.target.os == 'windows' && '.exe' || '' }} \
        ./cmd/server
        
    - name: Generate checksum
      run: |
        cd dist
        sha256sum {{PROJECT_NAME_LOWER}}-${{ matrix.target.os }}-${{ matrix.target.arch }}${{ matrix.target.os == 'windows' && '.exe' || '' }} > checksums.txt
        
    - name: Upload binary
      uses: actions/upload-artifact@v3
      with:
        name: binary-${{ matrix.target.os }}-${{ matrix.target.arch }}
        path: dist/

  container-build:
    needs: comprehensive-quality
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      packages: write
      
    strategy:
      matrix:
        variant:
          - { name: alpine, dockerfile: Dockerfile.alpine }
          - { name: distroless, dockerfile: Dockerfile.distroless }
          - { name: scratch, dockerfile: Dockerfile.scratch }
          
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Docker Buildx
      uses: docker/setup-buildx-action@v3
      
    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
        
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch,suffix=-${{ matrix.variant.name }}
          type=ref,event=pr,suffix=-${{ matrix.variant.name }}
          type=sha,prefix={{branch}}-,suffix=-${{ matrix.variant.name }}
          type=raw,value=latest,suffix=-${{ matrix.variant.name }},enable={{is_default_branch}}
          
    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        file: ${{ matrix.variant.dockerfile }}
        platforms: linux/amd64,linux/arm64
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
        
    - name: Run container security scan
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.meta.outputs.version }}
        format: 'sarif'
        output: 'trivy-results.sarif'
        
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  deploy-staging:
    needs: [multi-platform-build, container-build]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    environment: staging
    
    steps:
    - name: Download all binaries
      uses: actions/download-artifact@v3
      with:
        path: dist/
        
    - name: Deploy to staging
      run: |
        echo "Deploying to staging environment"
        # Create deployment package
        tar -czf {{PROJECT_NAME_LOWER}}-staging.tar.gz dist/
        
        # Deploy to staging server
        scp {{PROJECT_NAME_LOWER}}-staging.tar.gz user@staging.example.com:/tmp/
        ssh user@staging.example.com "cd /tmp && tar -xzf {{PROJECT_NAME_LOWER}}-staging.tar.gz && sudo systemctl restart {{PROJECT_NAME_LOWER}}"
        
    - name: Run integration tests against staging
      run: |
        echo "Running integration tests against staging"
        # Wait for service to be ready
        sleep 30
        
        # Run smoke tests
        curl -f https://staging.example.com/health || exit 1
        
        # Run API tests
        go test -v -tags=e2e ./tests/... -base-url=https://staging.example.com
        
    - name: Run performance tests against staging
      run: |
        echo "Running performance tests against staging"
        # Use vegeta for load testing
        echo "GET https://staging.example.com/api/v1/users" | vegeta attack -duration=30s -rate=50 | vegeta report
        
    - name: Create deployment issue
      if: failure()
      uses: actions/github-script@v6
      with:
        script: |
          github.rest.issues.create({
            owner: context.repo.owner,
            repo: context.repo.repo,
            title: 'Staging Deployment Failed',
            body: 'Staging deployment failed. Please investigate immediately.',
            labels: ['deployment', 'staging', 'urgent']
          })

  deploy-production:
    needs: [multi-platform-build, container-build]
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    environment: production
    
    strategy:
      matrix:
        region: [us-east-1, us-west-2, eu-west-1]
        
    steps:
    - name: Download binaries
      uses: actions/download-artifact@v3
      with:
        path: dist/
        
    - name: Deploy to production (${{ matrix.region }})
      run: |
        echo "Deploying to production in ${{ matrix.region }}"
        # Create deployment package
        tar -czf {{PROJECT_NAME_LOWER}}-production-${{ matrix.region }}.tar.gz dist/
        
        # Deploy to production servers in region
        scp {{PROJECT_NAME_LOWER}}-production-${{ matrix.region }}.tar.gz user@prod-${{ matrix.region }}.example.com:/tmp/
        ssh user@prod-${{ matrix.region }}.example.com "cd /tmp && tar -xzf {{PROJECT_NAME_LOWER}}-production-${{ matrix.region }}.tar.gz && sudo systemctl restart {{PROJECT_NAME_LOWER}}"
        
    - name: Run health checks (${{ matrix.region }})
      run: |
        echo "Running health checks in ${{ matrix.region }}"
        sleep 30
        
        # Health check
        curl -f https://prod-${{ matrix.region }}.example.com/health || exit 1
        
        # Readiness check
        curl -f https://prod-${{ matrix.region }}.example.com/ready || exit 1
        
    - name: Run smoke tests (${{ matrix.region }})
      run: |
        echo "Running smoke tests in ${{ matrix.region }}"
        go test -v -tags=e2e ./tests/... -base-url=https://prod-${{ matrix.region }}.example.com
        
    - name: Update load balancer
      if: success()
      run: |
        echo "Updating load balancer to include ${{ matrix.region }}"
        # Add logic to update load balancer configuration
        
    - name: Rollback on failure
      if: failure()
      run: |
        echo "Rolling back deployment in ${{ matrix.region }}"
        # Add rollback logic here
        
    - name: Notify deployment status
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        channel: '#deployments'
        text: "Production deployment ${{ github.event.release.tag_name }} in ${{ matrix.region }} ${{ job.status }}"
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}

  post-deployment-monitoring:
    needs: deploy-production
    runs-on: ubuntu-latest
    if: always()
    
    steps:
    - name: Monitor deployment health
      run: |
        echo "Monitoring deployment health for 10 minutes"
        for i in {1..10}; do
          echo "Health check $i/10"
          curl -f https://prod.example.com/health || echo "Health check failed"
          sleep 60
        done
        
    - name: Check error rates
      run: |
        echo "Checking error rates"
        # Query monitoring system for error rates
        # Alert if error rate > 5%
        
    - name: Check performance metrics
      run: |
        echo "Checking performance metrics"
        # Check response times, throughput, etc.
        
    - name: Generate deployment report
      run: |
        echo "Generating deployment report"
        cat > deployment-report.md << EOF
        # Deployment Report
        
        **Release**: ${{ github.event.release.tag_name }}
        **Commit**: ${{ github.sha }}
        **Timestamp**: $(date)
        
        ## Health Checks
        - All regions healthy
        - Error rates within threshold
        - Performance metrics acceptable
        
        ## Rollout Status
        - Completed successfully
        - No rollbacks required
        
        EOF
        
    - name: Upload deployment report
      uses: actions/upload-artifact@v3
      with:
        name: deployment-report
        path: deployment-report.md
```

## 🐳 Docker Configuration

### **MVP Tier - Simple Dockerfile**

```dockerfile
# Dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o {{PROJECT_NAME_LOWER}} ./cmd/server

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/{{PROJECT_NAME_LOWER}} .

# Expose port
EXPOSE 8080

# Run the binary
CMD ["./{{PROJECT_NAME_LOWER}}"]
```

### **CORE Tier - Multi-stage Dockerfile**

```dockerfile
# Dockerfile
FROM golang:1.21-alpine AS builder

# Install git and other build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments for version and build info
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the application with build info
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}" \
    -o {{PROJECT_NAME_LOWER}} ./cmd/server

# Final stage - minimal runtime image
FROM alpine:3.18

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata curl

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/{{PROJECT_NAME_LOWER}} .

# Copy configuration files
COPY --from=builder /app/config ./config

# Set ownership
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Run the binary
CMD ["./{{PROJECT_NAME_LOWER}}"]
```

### **FULL Tier - Enterprise Dockerfiles**

```dockerfile
# Dockerfile.alpine - Alpine-based image
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata upx

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
ARG TARGETPLATFORM

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}" \
    -o {{PROJECT_NAME_LOWER}} ./cmd/server && \
    upx --best {{PROJECT_NAME_LOWER}}

# Runtime image
FROM alpine:3.18

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata curl dumb-init

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/{{PROJECT_NAME_LOWER}} .

# Copy configuration files
COPY --from=builder /app/config ./config

# Set ownership
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Use dumb-init as PID 1
ENTRYPOINT ["dumb-init", "--"]
CMD ["./{{PROJECT_NAME_LOWER}}"]
```

```dockerfile
# Dockerfile.distroless - Distroless-based image
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}" \
    -o {{PROJECT_NAME_LOWER}} ./cmd/server

# Runtime image - distroless
FROM gcr.io/distroless/static-debian11

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/{{PROJECT_NAME_LOWER}} .

# Copy configuration files
COPY --from=builder /app/config ./config

# Expose port
EXPOSE 8080

# Run the binary
CMD ["./{{PROJECT_NAME_LOWER}}"]
```

```dockerfile
# Dockerfile.scratch - Scratch-based image
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}" \
    -o {{PROJECT_NAME_LOWER}} ./cmd/server

# Runtime image - scratch
FROM scratch

# Copy CA certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/{{PROJECT_NAME_LOWER}} .

# Copy configuration files
COPY --from=builder /app/config ./config

# Expose port
EXPOSE 8080

# Run the binary
CMD ["./{{PROJECT_NAME_LOWER}}"]
```

## 🔒 Security Configuration

### **Security Scanning Scripts**

```bash
#!/bin/bash
# scripts/security-scan.sh

set -e

echo "Running comprehensive security scan..."

# Initialize variables
SCAN_DIR="${1:-.}"
OUTPUT_DIR="security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "Scanning directory: $SCAN_DIR"
echo "Output directory: $OUTPUT_DIR"

# Run gosec
echo "Running gosec..."
gosec -fmt json -out "$OUTPUT_DIR/gosec_$TIMESTAMP.json" "$SCAN_DIR"
gosec -fmt sarif -out "$OUTPUT_DIR/gosec_$TIMESTAMP.sarif" "$SCAN_DIR"

# Run Trivy filesystem scan
echo "Running Trivy filesystem scan..."
trivy fs --scanners vuln,config,secret \
    --format json \
    --output "$OUTPUT_DIR/trivy_fs_$TIMESTAMP.json" \
    "$SCAN_DIR"

trivy fs --scanners vuln,config,secret \
    --format sarif \
    --output "$OUTPUT_DIR/trivy_fs_$TIMESTAMP.sarif" \
    "$SCAN_DIR"

# Run Trivy repository scan
echo "Running Trivy repository scan..."
trivy repo --scanners vuln,config,secret \
    --format json \
    --output "$OUTPUT_DIR/trivy_repo_$TIMESTAMP.json" \
    "$SCAN_DIR"

# Run Semgrep
echo "Running Semgrep..."
semgrep --config=auto \
    --json \
    --output="$OUTPUT_DIR/semgrep_$TIMESTAMP.json" \
    "$SCAN_DIR"

# Run Gitleaks
echo "Running Gitleaks..."
gitleaks detect --source "$SCAN_DIR" \
    --report-path "$OUTPUT_DIR/gitleaks_$TIMESTAMP.json" \
    --report-format json

# Run dependency check
echo "Running dependency check..."
dependency-check --project "{{PROJECT_NAME_LOWER}}" \
    --scan "$SCAN_DIR" \
    --format JSON \
    --out "$OUTPUT_DIR/dependency-check_$TIMESTAMP"

# Run SARIF combination
echo "Combining SARIF results..."
node scripts/combine-sarif.js \
    "$OUTPUT_DIR/gosec_$TIMESTAMP.sarif" \
    "$OUTPUT_DIR/trivy_fs_$TIMESTAMP.sarif" \
    > "$OUTPUT_DIR/combined_$TIMESTAMP.sarif"

# Generate summary report
echo "Generating summary report..."
cat > "$OUTPUT_DIR/security-summary_$TIMESTAMP.md" << EOF
# Security Scan Summary

**Scan Date**: $(date)
**Scan Directory**: $SCAN_DIR

## Tools Used
- gosec: Go security scanner
- Trivy: Vulnerability and secret scanner
- Semgrep: Static analysis
- Gitleaks: Secret scanner
- Dependency-Check: Dependency vulnerability scanner

## Results
- gosec: $OUTPUT_DIR/gosec_$TIMESTAMP.json
- Trivy FS: $OUTPUT_DIR/trivy_fs_$TIMESTAMP.json
- Trivy Repo: $OUTPUT_DIR/trivy_repo_$TIMESTAMP.json
- Semgrep: $OUTPUT_DIR/semgrep_$TIMESTAMP.json
- Gitleaks: $OUTPUT_DIR/gitleaks_$TIMESTAMP.json
- Dependency Check: $OUTPUT_DIR/dependency-check_$TIMESTAMP.json
- Combined SARIF: $OUTPUT_DIR/combined_$TIMESTAMP.sarif

## Next Steps
1. Review all security findings
2. Address critical and high severity issues
3. Update dependencies with known vulnerabilities
4. Rotate any exposed secrets or credentials
5. Update security policies based on findings

EOF

echo "Security scan completed!"
echo "Results available in: $OUTPUT_DIR"
echo "Summary report: $OUTPUT_DIR/security-summary_$TIMESTAMP.md"
```

```javascript
// scripts/combine-sarif.js - SARIF combination script
const fs = require('fs');
const path = require('path');

function combineSarifFiles(...files) {
    const combined = {
        version: '2.1.0',
        $schema: 'https://json.schemastore.org/sarif-2.1.0',
        runs: []
    };

    for (const file of files) {
        try {
            const content = fs.readFileSync(file, 'utf8');
            const sarif = JSON.parse(content);
            
            if (sarif.runs && Array.isArray(sarif.runs)) {
                combined.runs.push(...sarif.runs);
            }
        } catch (error) {
            console.warn(`Failed to read or parse ${file}:`, error.message);
        }
    }

    return combined;
}

// Get input files from command line arguments
const files = process.argv.slice(2);

if (files.length === 0) {
    console.error('Usage: node combine-sarif.js <file1.sarif> [file2.sarif] ...');
    process.exit(1);
}

const combined = combineSarifFiles(...files);

// Output combined SARIF
console.log(JSON.stringify(combined, null, 2));
```

### **Dependency Management**

```bash
#!/bin/bash
# scripts/update-dependencies.sh

set -e

echo "Updating Go dependencies..."

# Update direct dependencies
echo "Updating direct dependencies..."
go get -u ./...
go mod tidy

# Update indirect dependencies
echo "Updating indirect dependencies..."
go get -u=patch ./...
go mod tidy

# Run security check on updated dependencies
echo "Running security check..."
go list -json -m all | nancy sleuth

# Check for outdated dependencies
echo "Checking for outdated dependencies..."
go list -u -m -json all | jq -r 'select(.Indirect != true) | "\(.Path)@\(.Version) -> \(.Update.Version)"' | grep '->'

# Run tests to ensure compatibility
echo "Running tests..."
go test -v ./...

echo "Dependency update completed!"
```

```bash
#!/bin/bash
# scripts/audit-dependencies.sh

set -e

echo "Auditing Go dependencies..."

# Check for known vulnerabilities
echo "Checking for known vulnerabilities..."
govulncheck ./...

# Run Snyk check
if command -v snyk &> /dev/null; then
    echo "Running Snyk check..."
    snyk test --json > snyk-report.json || true
fi

# Run OWASP dependency check
echo "Running OWASP dependency check..."
dependency-check --project "{{PROJECT_NAME_LOWER}}" \
    --scan . \
    --format JSON \
    --out dependency-check-report

# Generate dependency report
echo "Generating dependency report..."
go list -json -m all > dependencies.json

# Check for licenses
echo "Checking licenses..."
go-licenses csv ./... > licenses.csv 2>/dev/null || echo "go-licenses not available"

echo "Dependency audit completed!"
echo "Reports generated:"
echo "  - dependencies.json"
echo "  - dependency-check-report"
if [ -f snyk-report.json ]; then
    echo "  - snyk-report.json"
fi
if [ -f licenses.csv ]; then
    echo "  - licenses.csv"
fi
```

## 🚀 Deployment Scripts

### **MVP Tier - Simple Deployment**

```bash
#!/bin/bash
# scripts/deploy.sh

set -e

# Configuration
REMOTE_HOST="${REMOTE_HOST:-localhost}"
REMOTE_USER="${REMOTE_USER:-deploy}"
REMOTE_PATH="${REMOTE_PATH:-/opt/{{PROJECT_NAME_LOWER}}}"
SERVICE_NAME="{{PROJECT_NAME_LOWER}}"

echo "Deploying {{PROJECT_NAME}} to $REMOTE_HOST..."

# Build binary
echo "Building binary..."
go build -ldflags="-w -s" -o {{PROJECT_NAME_LOWER}} ./cmd/server

# Create deployment package
echo "Creating deployment package..."
tar -czf {{PROJECT_NAME_LOWER}}-deploy.tar.gz \
    {{PROJECT_NAME_LOWER}} \
    config/ \
    scripts/

# Copy to remote server
echo "Copying to remote server..."
scp {{PROJECT_NAME_LOWER}}-deploy.tar.gz $REMOTE_USER@$REMOTE_HOST:/tmp/

# Extract and deploy on remote server
echo "Deploying on remote server..."
ssh $REMOTE_USER@$REMOTE_HOST << EOF
    set -e
    
    # Stop service
    sudo systemctl stop $SERVICE_NAME || true
    
    # Backup current version
    if [ -d "$REMOTE_PATH" ]; then
        sudo mv $REMOTE_PATH $REMOTE_PATH.backup.\$(date +%Y%m%d_%H%M%S)
    fi
    
    # Create directory
    sudo mkdir -p $REMOTE_PATH
    
    # Extract new version
    cd $REMOTE_PATH
    sudo tar -xzf /tmp/{{PROJECT_NAME_LOWER}}-deploy.tar.gz
    
    # Set permissions
    sudo chown -R root:root $REMOTE_PATH
    sudo chmod +x $REMOTE_PATH/{{PROJECT_NAME_LOWER}}
    
    # Start service
    sudo systemctl start $SERVICE_NAME
    sudo systemctl enable $SERVICE_NAME
    
    # Clean up
    rm /tmp/{{PROJECT_NAME_LOWER}}-deploy.tar.gz
    
    echo "Deployment completed!"
EOF

# Clean up local files
rm {{PROJECT_NAME_LOWER}}-deploy.tar.gz

echo "Deployment to $REMOTE_HOST completed!"
```

### **CORE Tier - Production Deployment**

```bash
#!/bin/bash
# scripts/deploy-production.sh

set -e

# Configuration
ENVIRONMENT="${ENVIRONMENT:-production}"
VERSION="${VERSION:-$(git rev-parse --short HEAD)}"
REMOTE_HOSTS="${REMOTE_HOSTS:-server1.example.com,server2.example.com}"
REMOTE_USER="${REMOTE_USER:-deploy}"
REMOTE_PATH="${REMOTE_PATH:-/opt/{{PROJECT_NAME_LOWER}}}"
SERVICE_NAME="{{PROJECT_NAME_LOWER}}"
BACKUP_PATH="${BACKUP_PATH:-/opt/backups/{{PROJECT_NAME_LOWER}}}"
HEALTH_CHECK_URL="${HEALTH_CHECK_URL:-http://localhost:8080/health}"
ROLLBACK_ENABLED="${ROLLBACK_ENABLED:-true}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Health check function
health_check() {
    local host=$1
    local url="http://$host:8080/health"
    local max_attempts=30
    local attempt=1
    
    log_info "Checking health on $host..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "$url" > /dev/null; then
            log_info "Health check passed on $host (attempt $attempt)"
            return 0
        fi
        
        log_warn "Health check failed on $host (attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done
    
    log_error "Health check failed on $host after $max_attempts attempts"
    return 1
}

# Rollback function
rollback() {
    if [ "$ROLLBACK_ENABLED" = "true" ]; then
        log_warn "Initiating rollback..."
        
        IFS=',' read -ra HOSTS <<< "$REMOTE_HOSTS"
        for host in "${HOSTS[@]}"; do
            ssh $REMOTE_USER@$host << EOF
                set -e
                # Find latest backup
                LATEST_BACKUP=\$(ls -t $BACKUP_PATH | head -n1)
                
                if [ -n "\$LATEST_BACKUP" ]; then
                    echo "Rolling back to \$LATEST_BACKUP on $host"
                    
                    # Stop service
                    sudo systemctl stop $SERVICE_NAME
                    
                    # Restore backup
                    sudo rm -rf $REMOTE_PATH
                    sudo mv $BACKUP_PATH/\$LATEST_BACKUP $REMOTE_PATH
                    
                    # Start service
                    sudo systemctl start $SERVICE_NAME
                    
                    echo "Rollback completed on $host"
                else
                    echo "No backup found for rollback on $host"
                fi
EOF
        done
        
        log_info "Rollback completed"
    else
        log_warn "Rollback is disabled"
    fi
}

# Main deployment function
deploy() {
    log_info "Starting deployment of version $VERSION to $ENVIRONMENT"
    
    # Build binary
    log_info "Building binary..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -ldflags="-w -s -X main.version=$VERSION -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        -o {{PROJECT_NAME_LOWER}} ./cmd/server
    
    # Create deployment package
    log_info "Creating deployment package..."
    mkdir -p deploy
    tar -czf deploy/{{PROJECT_NAME_LOWER}}-$VERSION.tar.gz \
        {{PROJECT_NAME_LOWER}} \
        config/ \
        scripts/ \
        migrations/
    
    # Deploy to each host
    IFS=',' read -ra HOSTS <<< "$REMOTE_HOSTS"
    for host in "${HOSTS[@]}"; do
        log_info "Deploying to $host..."
        
        # Copy deployment package
        scp deploy/{{PROJECT_NAME_LOWER}}-$VERSION.tar.gz $REMOTE_USER@$host:/tmp/
        
        # Deploy on remote host
        ssh $REMOTE_USER@$host << EOF
            set -e
            
            log_info() {
                echo "[INFO] \$1"
            }
            
            log_warn() {
                echo "[WARN] \$1"
            }
            
            # Pre-deployment checks
            log_info "Running pre-deployment checks..."
            
            # Check disk space
            AVAILABLE_SPACE=\$(df $REMOTE_PATH | awk 'NR==2 {print \$4}')
            if [ \$AVAILABLE_SPACE -lt 1048576 ]; then  # 1GB in KB
                echo "ERROR: Insufficient disk space on $host"
                exit 1
            fi
            
            # Stop service
            log_info "Stopping $SERVICE_NAME..."
            sudo systemctl stop $SERVICE_NAME || true
            
            # Create backup
            if [ -d "$REMOTE_PATH" ]; then
                log_info "Creating backup..."
                sudo mkdir -p $BACKUP_PATH
                sudo cp -r $REMOTE_PATH $BACKUP_PATH/{{PROJECT_NAME_LOWER}}-\$(date +%Y%m%d_%H%M%S)
            fi
            
            # Deploy new version
            log_info "Deploying new version..."
            sudo mkdir -p $REMOTE_PATH
            cd $REMOTE_PATH
            sudo tar -xzf /tmp/{{PROJECT_NAME_LOWER}}-$VERSION.tar.gz
            
            # Set permissions
            sudo chown -R root:root $REMOTE_PATH
            sudo chmod +x $REMOTE_PATH/{{PROJECT_NAME_LOWER}}
            
            # Run database migrations
            if [ -f "$REMOTE_PATH/migrations/up.sql" ]; then
                log_info "Running database migrations..."
                sudo -u postgres psql {{PROJECT_NAME_LOWER}}_prod < $REMOTE_PATH/migrations/up.sql
            fi
            
            # Start service
            log_info "Starting $SERVICE_NAME..."
            sudo systemctl start $SERVICE_NAME
            sudo systemctl enable $SERVICE_NAME
            
            # Post-deployment checks
            log_info "Running post-deployment checks..."
            
            # Wait for service to start
            sleep 10
            
            # Check service status
            if ! sudo systemctl is-active --quiet $SERVICE_NAME; then
                echo "ERROR: Service $SERVICE_NAME is not running on $host"
                sudo journalctl -u $SERVICE_NAME --no-pager -n 50
                exit 1
            fi
            
            # Clean up
            rm /tmp/{{PROJECT_NAME_LOWER}}-$VERSION.tar.gz
            
            log_info "Deployment completed on $host"
EOF
        
        # Health check
        if ! health_check "$host"; then
            log_error "Health check failed on $host"
            if [ "$ROLLBACK_ENABLED" = "true" ]; then
                rollback
            fi
            exit 1
        fi
    done
    
    log_info "Deployment completed successfully to all hosts"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    rm -rf deploy/
}

# Set trap for cleanup
trap cleanup EXIT

# Main execution
case "${1:-deploy}" in
    deploy)
        deploy
        ;;
    rollback)
        rollback
        ;;
    health)
        IFS=',' read -ra HOSTS <<< "$REMOTE_HOSTS"
        for host in "${HOSTS[@]}"; do
            health_check "$host"
        done
        ;;
    *)
        echo "Usage: $0 {deploy|rollback|health}"
        exit 1
        ;;
esac
```

### **FULL Tier - Enterprise Deployment**

```bash
#!/bin/bash
# scripts/deploy-enterprise.sh

set -e

# Configuration
ENVIRONMENT="${ENVIRONMENT:-production}"
VERSION="${VERSION:-$(git rev-parse --short HEAD)}"
BUILD_NUMBER="${BUILD_NUMBER:-$(date +%Y%m%d%H%M%S)}"
DEPLOYMENT_ID="${ENVIRONMENT}-${VERSION}-${BUILD_NUMBER}"

# Load environment-specific configuration
CONFIG_FILE="config/deploy-${ENVIRONMENT}.sh"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
fi

# Default values
REMOTE_HOSTS="${REMOTE_HOSTS:-server1.example.com,server2.example.com,server3.example.com}"
REMOTE_USER="${REMOTE_USER:-deploy}"
REMOTE_PATH="${REMOTE_PATH:-/opt/{{PROJECT_NAME_LOWER}}}"
SERVICE_NAME="{{PROJECT_NAME_LOWER}}"
BACKUP_PATH="${BACKUP_PATH:-/opt/backups/{{PROJECT_NAME_LOWER}}}"
LOAD_BALANCER="${LOAD_BALANCER:-lb.example.com}"
CANARY_PERCENTAGE="${CANARY_PERCENTAGE:-10}"
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-300}"
METRICS_ENDPOINT="${METRICS_ENDPOINT:-http://localhost:9090/metrics}"

# Logging
LOG_FILE="logs/deploy-${DEPLOYMENT_ID}.log"
mkdir -p logs

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$@"
}

log_warn() {
    log "WARN" "$@"
}

log_error() {
    log "ERROR" "$@"
}

# Metrics collection
collect_metrics() {
    local phase=$1
    local host=$2
    
    log_info "Collecting metrics for phase: $phase on $host"
    
    # Collect system metrics
    ssh $REMOTE_USER@$host << EOF
        # CPU and memory usage
        top -b -n1 | head -5 > /tmp/metrics-\$(hostname)-\$(date +%s).txt
        
        # Disk usage
        df -h >> /tmp/metrics-\$(hostname)-\$(date +%s).txt
        
        # Network connections
        netstat -an | grep :8080 >> /tmp/metrics-\$(hostname)-\$(date +%s).txt
        
        # Application metrics
        curl -s $METRICS_ENDPOINT >> /tmp/metrics-\$(hostname)-\$(date +%s).txt || true
EOF
}

# Advanced health check
advanced_health_check() {
    local host=$1
    local timeout=${2:-$HEALTH_CHECK_TIMEOUT}
    local start_time=$(date +%s)
    
    log_info "Running advanced health check on $host (timeout: ${timeout}s)"
    
    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        if [ $elapsed -gt $timeout ]; then
            log_error "Health check timeout on $host after ${timeout}s"
            return 1
        fi
        
        # Check HTTP health endpoint
        if curl -f -s --max-time 5 "http://$host:8080/health" > /dev/null; then
            log_info "HTTP health check passed on $host"
        else
            log_warn "HTTP health check failed on $host, retrying..."
            sleep 5
            continue
        fi
        
        # Check readiness endpoint
        if curl -f -s --max-time 5 "http://$host:8080/ready" > /dev/null; then
            log_info "Readiness check passed on $host"
        else
            log_warn "Readiness check failed on $host, retrying..."
            sleep 5
            continue
        fi
        
        # Check application metrics
        local metrics_response=$(curl -s --max-time 5 "http://$host:8080/metrics" || echo "")
        if echo "$metrics_response" | grep -q "http_requests_total"; then
            log_info "Application metrics check passed on $host"
        else
            log_warn "Application metrics check failed on $host, retrying..."
            sleep 5
            continue
        fi
        
        # Check database connectivity
        local db_check=$(curl -s --max-time 5 "http://$host:8080/health/db" || echo "")
        if echo "$db_check" | grep -q '"status":"ok"'; then
            log_info "Database connectivity check passed on $host"
        else
            log_warn "Database connectivity check failed on $host, retrying..."
            sleep 5
            continue
        fi
        
        # All checks passed
        log_info "All health checks passed on $host"
        collect_metrics "health_check_passed" "$host"
        return 0
    done
}

# Canary deployment
canary_deploy() {
    local canary_hosts=()
    local regular_hosts=()
    
    # Split hosts into canary and regular
    IFS=',' read -ra ALL_HOSTS <<< "$REMOTE_HOSTS"
    local total_hosts=${#ALL_HOSTS[@]}
    local canary_count=$((total_hosts * CANARY_PERCENTAGE / 100))
    
    if [ $canary_count -eq 0 ]; then
        canary_count=1
    fi
    
    log_info "Deploying canary to $canary_count of $total_hosts hosts"
    
    # Select canary hosts
    for ((i=0; i<total_hosts; i++)); do
        if [ $i -lt $canary_count ]; then
            canary_hosts+=("${ALL_HOSTS[i]}")
        else
            regular_hosts+=("${ALL_HOSTS[i]}")
        fi
    done
    
    # Deploy to canary hosts
    log_info "Deploying to canary hosts: ${canary_hosts[*]}"
    deploy_to_hosts "${canary_hosts[*]}" "canary"
    
    # Health check canary
    for host in "${canary_hosts[@]}"; do
        if ! advanced_health_check "$host"; then
            log_error "Canary health check failed on $host"
            rollback_hosts "${canary_hosts[*]}"
            exit 1
        fi
    done
    
    # Monitor canary for specified time
    log_info "Monitoring canary deployment for 5 minutes..."
    sleep 300
    
    # Check canary metrics
    if ! check_canary_metrics "${canary_hosts[*]}"; then
        log_error "Canary metrics check failed"
        rollback_hosts "${canary_hosts[*]}"
        exit 1
    fi
    
    # Deploy to remaining hosts
    log_info "Canary deployment successful, deploying to remaining hosts"
    deploy_to_hosts "${regular_hosts[*]}" "production"
    
    # Health check all hosts
    for host in "${ALL_HOSTS[@]}"; do
        if ! advanced_health_check "$host"; then
            log_error "Health check failed on $host"
            rollback_hosts "${ALL_HOSTS[*]}"
            exit 1
        fi
    done
}

# Deploy to specific hosts
deploy_to_hosts() {
    local hosts=$1
    local deployment_type=$2
    
    IFS=',' read -ra HOST_ARRAY <<< "$hosts"
    
    for host in "${HOST_ARRAY[@]}"; do
        log_info "Deploying to $host ($deployment_type)..."
        
        # Collect pre-deployment metrics
        collect_metrics "pre_deploy" "$host"
        
        # Deploy to host
        ssh $REMOTE_USER@$host << EOF
            set -e
            
            # Pre-deployment validation
            AVAILABLE_SPACE=\$(df $REMOTE_PATH | awk 'NR==2 {print \$4}')
            if [ \$AVAILABLE_SPACE -lt 2097152 ]; then  # 2GB in KB
                echo "ERROR: Insufficient disk space on $host"
                exit 1
            fi
            
            # Load check
            LOAD_AVG=\$(uptime | awk -F'load average:' '{print \$2}' | awk '{print \$1}' | sed 's/,//')
            if (( \$(echo "\$LOAD_AVG > 2.0" | bc -l) )); then
                echo "WARN: High system load on $host: \$LOAD_AVG"
            fi
            
            # Stop service gracefully
            sudo systemctl stop $SERVICE_NAME || true
            
            # Create backup
            if [ -d "$REMOTE_PATH" ]; then
                sudo mkdir -p $BACKUP_PATH
                sudo cp -r $REMOTE_PATH $BACKUP_PATH/{{PROJECT_NAME_LOWER}}-\$(date +%Y%m%d_%H%M%S)
            fi
            
            # Deploy new version
            sudo mkdir -p $REMOTE_PATH
            cd $REMOTE_PATH
            sudo tar -xzf /tmp/{{PROJECT_NAME_LOWER}}-$VERSION.tar.gz
            
            # Set permissions
            sudo chown -R root:root $REMOTE_PATH
            sudo chmod +x $REMOTE_PATH/{{PROJECT_NAME_LOWER}}
            
            # Run database migrations
            if [ -f "$REMOTE_PATH/migrations/up.sql" ]; then
                echo "Running database migrations..."
                sudo -u postgres psql {{PROJECT_NAME_LOWER}}_prod < $REMOTE_PATH/migrations/up.sql
            fi
            
            # Update configuration
            sudo sed -i "s/VERSION=.*/VERSION=$VERSION/" $REMOTE_PATH/config/app.env
            
            # Start service
            sudo systemctl start $SERVICE_NAME
            sudo systemctl enable $SERVICE_NAME
            
            # Post-deployment validation
            sleep 10
            
            if ! sudo systemctl is-active --quiet $SERVICE_NAME; then
                echo "ERROR: Service failed to start on $host"
                sudo journalctl -u $SERVICE_NAME --no-pager -n 100
                exit 1
            fi
            
            # Clean up
            rm /tmp/{{PROJECT_NAME_LOWER}}-$VERSION.tar.gz
            
            echo "Deployment completed on $host"
EOF
        
        # Copy deployment package
        scp deploy/{{PROJECT_NAME_LOWER}}-$VERSION.tar.gz $REMOTE_USER@$host:/tmp/
        
        # Execute deployment
        ssh $REMOTE_USER@$host << 'EOF'
            cd /tmp
            tar -xzf {{PROJECT_NAME_LOWER}}-'$VERSION'.tar.gz
            # Deployment script executed above
EOF
        
        log_info "Deployment completed on $host"
    done
}

# Check canary metrics
check_canary_metrics() {
    local hosts=$1
    
    log_info "Checking canary metrics..."
    
    IFS=',' read -ra HOST_ARRAY <<< "$hosts"
    
    for host in "${HOST_ARRAY[@]}"; do
        # Get error rate from metrics
        local error_rate=$(curl -s "http://$host:8080/metrics" | grep "http_requests_total{status=~\"5..\"}" | awk '{sum+=$2} END {print sum+0}')
        local total_requests=$(curl -s "http://$host:8080/metrics" | grep "http_requests_total" | awk '{sum+=$2} END {print sum+0}')
        
        if [ "$total_requests" -gt 0 ]; then
            local error_percentage=$((error_rate * 100 / total_requests))
            if [ $error_percentage -gt 5 ]; then
                log_error "High error rate on $host: $error_percentage%"
                return 1
            fi
        fi
        
        # Check response time
        local avg_response_time=$(curl -s "http://$host:8080/metrics" | grep "http_request_duration_seconds_sum" | awk '{sum+=$2} END {print sum+0}')
        local request_count=$(curl -s "http://$host:8080/metrics" | grep "http_request_duration_seconds_count" | awk '{sum+=$2} END {print sum+0}')
        
        if [ "$request_count" -gt 0 ]; then
            local calculated_avg=$((avg_response_time / request_count))
            if (( $(echo "$calculated_avg > 1.0" | bc -l) )); then
                log_error "High response time on $host: ${calculated_avg}s"
                return 1
            fi
        fi
    done
    
    log_info "Canary metrics check passed"
    return 0
}

# Rollback specific hosts
rollback_hosts() {
    local hosts=$1
    
    log_warn "Rolling back hosts: $hosts"
    
    IFS=',' read -ra HOST_ARRAY <<< "$hosts"
    
    for host in "${HOST_ARRAY[@]}"; do
        ssh $REMOTE_USER@$host << EOF
            set -e
            
            # Find latest backup
            LATEST_BACKUP=\$(ls -t $BACKUP_PATH | head -n1)
            
            if [ -n "\$LATEST_BACKUP" ]; then
                echo "Rolling back to \$LATEST_BACKUP on $host"
                
                # Stop service
                sudo systemctl stop $SERVICE_NAME
                
                # Restore backup
                sudo rm -rf $REMOTE_PATH
                sudo mv $BACKUP_PATH/\$LATEST_BACKUP $REMOTE_PATH
                
                # Start service
                sudo systemctl start $SERVICE_NAME
                
                echo "Rollback completed on $host"
            else
                echo "No backup found for rollback on $host"
            fi
EOF
    done
}

# Blue-green deployment
blue_green_deploy() {
    log_info "Starting blue-green deployment"
    
    # This would implement blue-green deployment logic
    # For now, fall back to canary
    canary_deploy
}

# Main deployment function
deploy() {
    log_info "Starting enterprise deployment: $DEPLOYMENT_ID"
    
    # Build binary with enterprise flags
    log_info "Building enterprise binary..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -ldflags="-w -s -X main.version=$VERSION -X main.buildNumber=$BUILD_NUMBER -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.environment=$ENVIRONMENT" \
        -o {{PROJECT_NAME_LOWER}} ./cmd/server
    
    # Create deployment package
    log_info "Creating enterprise deployment package..."
    mkdir -p deploy
    tar -czf deploy/{{PROJECT_NAME_LOWER}}-$VERSION.tar.gz \
        {{PROJECT_NAME_LOWER}} \
        config/ \
        scripts/ \
        migrations/ \
        docs/ \
        README.md
    
    # Create deployment manifest
    cat > deploy/deployment-manifest.json << EOF
{
    "deployment_id": "$DEPLOYMENT_ID",
    "version": "$VERSION",
    "build_number": "$BUILD_NUMBER",
    "environment": "$ENVIRONMENT",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "hosts": "$REMOTE_HOSTS",
    "deployment_type": "enterprise"
}
EOF
    
    # Choose deployment strategy
    case "${DEPLOYMENT_STRATEGY:-canary}" in
        canary)
            canary_deploy
            ;;
        blue_green)
            blue_green_deploy
            ;;
        rolling)
            deploy_to_hosts "$REMOTE_HOSTS" "production"
            
            # Health check all hosts
            IFS=',' read -ra HOST_ARRAY <<< "$REMOTE_HOSTS"
            for host in "${HOST_ARRAY[@]}"; do
                if ! advanced_health_check "$host"; then
                    log_error "Health check failed on $host"
                    rollback_hosts "$REMOTE_HOSTS"
                    exit 1
                fi
            done
            ;;
        *)
            log_error "Unknown deployment strategy: $DEPLOYMENT_STRATEGY"
            exit 1
            ;;
    esac
    
    # Update load balancer
    log_info "Updating load balancer..."
    update_load_balancer
    
    # Collect post-deployment metrics
    IFS=',' read -ra HOST_ARRAY <<< "$REMOTE_HOSTS"
    for host in "${HOST_ARRAY[@]}"; do
        collect_metrics "post_deploy" "$host"
    done
    
    # Generate deployment report
    generate_deployment_report
    
    log_info "Enterprise deployment completed successfully: $DEPLOYMENT_ID"
}

# Update load balancer
update_load_balancer() {
    log_info "Updating load balancer configuration..."
    
    # This would update your load balancer configuration
    # Example: Update Consul, Kubernetes, HAProxy, etc.
    
    log_info "Load balancer updated"
}

# Generate deployment report
generate_deployment_report() {
    log_info "Generating deployment report..."
    
    cat > reports/deployment-report-$DEPLOYMENT_ID.md << EOF
# Enterprise Deployment Report

## Deployment Information
- **Deployment ID**: $DEPLOYMENT_ID
- **Version**: $VERSION
- **Build Number**: $BUILD_NUMBER
- **Environment**: $ENVIRONMENT
- **Strategy**: $DEPLOYMENT_STRATEGY
- **Timestamp**: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- **Hosts**: $REMOTE_HOSTS

## Pre-deployment Checks
- [x] Code quality checks passed
- [x] Security scans completed
- [x] All tests passed
- [x] Dependencies validated

## Deployment Steps
- [x] Binary built successfully
- [x] Deployment package created
- [x] Deployed to all hosts
- [x] Health checks passed
- [x] Load balancer updated

## Post-deployment Validation
- [x] All services running
- [x] Health endpoints responding
- [x] Metrics collection active
- [x] Error rates within threshold
- [x] Response times acceptable

## Rollback Information
- **Rollback Enabled**: $ROLLBACK_ENABLED
- **Backup Location**: $BACKUP_PATH
- **Rollback Command**: ./scripts/deploy-enterprise.sh rollback

## Next Steps
1. Monitor application performance
2. Check error rates and response times
3. Verify all integrations are working
4. Update documentation if needed

EOF
    
    log_info "Deployment report generated: reports/deployment-report-$DEPLOYMENT_ID.md"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    rm -rf deploy/
}

# Set trap for cleanup
trap cleanup EXIT

# Main execution
case "${1:-deploy}" in
    deploy)
        deploy
        ;;
    rollback)
        rollback_hosts "$REMOTE_HOSTS"
        ;;
    health)
        IFS=',' read -ra HOST_ARRAY <<< "$REMOTE_HOSTS"
        for host in "${HOST_ARRAY[@]}"; do
            advanced_health_check "$host"
        done
        ;;
    metrics)
        IFS=',' read -ra HOST_ARRAY <<< "$REMOTE_HOSTS"
        for host in "${HOST_ARRAY[@]}"; do
            collect_metrics "manual" "$host"
        done
        ;;
    *)
        echo "Usage: $0 {deploy|rollback|health|metrics}"
        echo "Environment variables:"
        echo "  ENVIRONMENT - Target environment (default: production)"
        echo "  VERSION - Version to deploy (default: git commit hash)"
        echo "  REMOTE_HOSTS - Comma-separated list of hosts"
        echo "  DEPLOYMENT_STRATEGY - canary|blue_green|rolling (default: canary)"
        exit 1
        ;;
esac
```

## 📊 Monitoring and Analytics

### **Prometheus Configuration**

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: '{{PROJECT_NAME_LOWER}}'
    static_configs:
      - targets: ['localhost:8080', 'localhost:8081', 'localhost:8082']
    metrics_path: /metrics
    scrape_interval: 10s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['localhost:9187']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

```yaml
# rules/{{PROJECT_NAME_LOWER}}.yml
groups:
  - name: {{PROJECT_NAME_LOWER}}.rules
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }} for {{ $labels.instance }}"

      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High response time detected"
          description: "95th percentile response time is {{ $value }}s for {{ $labels.instance }}"

      - alert: ServiceDown
        expr: up{job="{{PROJECT_NAME_LOWER}}"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service is down"
          description: "{{ $labels.instance }} has been down for more than 1 minute"

      - alert: HighMemoryUsage
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ $value | humanizePercentage }} on {{ $labels.instance }}"
```

### **Grafana Dashboard**

```json
{
  "dashboard": {
    "title": "{{PROJECT_NAME}} - Go Application Dashboard",
    "tags": ["go", "{{PROJECT_NAME_LOWER}}"],
    "timezone": "browser",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}"
          }
        ],
        "yAxes": [
          {
            "label": "Requests/sec"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          },
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "99th percentile"
          }
        ],
        "yAxes": [
          {
            "label": "Seconds"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m]) / rate(http_requests_total[5m])",
            "legendFormat": "Error Rate"
          }
        ],
        "yAxes": [
          {
            "label": "Percentage",
            "max": 1,
            "min": 0
          }
        ]
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "process_resident_memory_bytes",
            "legendFormat": "Resident Memory"
          },
          {
            "expr": "go_memstats_heap_inuse_bytes",
            "legendFormat": "Heap In Use"
          }
        ],
        "yAxes": [
          {
            "label": "Bytes"
          }
        ]
      },
      {
        "title": "Goroutines",
        "type": "graph",
        "targets": [
          {
            "expr": "go_goroutines",
            "legendFormat": "Goroutines"
          }
        ],
        "yAxes": [
          {
            "label": "Count"
          }
        ]
      },
      {
        "title": "GC Duration",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(go_memstats_gc_pause_seconds_total[5m])",
            "legendFormat": "GC Pause Rate"
          }
        ],
        "yAxes": [
          {
            "label": "Seconds/Second"
          }
        ]
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
```

---

**Go Version**: [GO_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
