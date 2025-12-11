<!--
File: PACKAGE-MANAGEMENT.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Package Management Guide - Go

This guide covers Go module management, dependency handling, and best practices for Go applications.

## 📦 Go Module Management

### Go Modules
Go uses Go modules for dependency management. Modules are defined by a `go.mod` file that tracks dependencies.

### go.mod Configuration
```go
module [MODULE_PATH]

go [GO_VERSION]

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/golang-migrate/migrate/v4 v4.16.2
    github.com/spf13/viper v1.17.0
    github.com/spf13/cobra v1.8.0
    go.uber.org/zap v1.26.0
    github.com/stretchr/testify v1.8.4
    github.com/golang/mock v1.6.0
    google.golang.org/protobuf v1.31.0
)

require (
    // Indirect dependencies are automatically managed
    github.com/bytedance/sonic v1.9.1 // indirect
    github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
    // ... more indirect dependencies
)
```

### go.sum Configuration
```go
// go.sum is automatically generated and contains cryptographic checksums
// of all dependencies. Never edit this file manually.

github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=
github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL7Yrp6KXt5/YId3J4ZiQcIhQySL5EqoPjM5kui0=
// ... more checksums
```

## 🚀 Package Management Commands

### Basic Module Commands
```bash
# Initialize a new module
go mod init [MODULE_PATH]

# Download dependencies
go mod download

# Tidy dependencies (remove unused, add missing)
go mod tidy

# Verify dependencies
go mod verify

# Vendor dependencies
go mod vendor

# Clean module cache
go clean -modcache
```

### Package Management
```bash
# Add new dependency
go get [PACKAGE_NAME]
go get [PACKAGE_NAME]@[VERSION]
go get [PACKAGE_NAME]@latest
go get [PACKAGE_NAME]@master

# Add dev dependency (testing, tools)
go get [PACKAGE_NAME]

# Remove dependency
go mod tidy  # Automatically removes unused dependencies

# Update dependencies
go get -u [PACKAGE_NAME]
go get -u=patch [PACKAGE_NAME]
go get -u ./...  # Update all dependencies

# Downgrade dependency
go get [PACKAGE_NAME]@[OLDER_VERSION]
```

### Build and Run Commands
```bash
# Build the application
go build
go build -o [BINARY_NAME]
go build -o [BINARY_NAME] ./cmd/server

# Run the application
go run main.go
go run ./cmd/server

# Build for different platforms
GOOS=linux GOARCH=amd64 go build -o [BINARY_NAME]-linux-amd64
GOOS=windows GOARCH=amd64 go build -o [BINARY_NAME]-windows-amd64.exe
GOOS=darwin GOARCH=amd64 go build -o [BINARY_NAME]-darwin-amd64

# Build with version information
go build -ldflags "-X main.version=[VERSION]" -o [BINARY_NAME]
```

## 📋 Dependency Categories

### Web Frameworks
- `github.com/gin-gonic/gin` - HTTP web framework
- `github.com/go-chi/chi` - Lightweight, idiomatic router
- `github.com/gorilla/mux` - Powerful URL router
- `echo` - High performance, extensible web framework
- `fiber` - Express inspired web framework

### Database & ORM
- `github.com/golang-migrate/migrate/v4` - Database migrations
- `gorm.io/gorm` - ORM library for Go
- `github.com/jmoiron/sqlx` - General purpose extensions to database/sql
- `github.com/go-redis/redis/v8` - Redis client
- `github.com/couchbase/gocb/v2` - Couchbase SDK

### Configuration & CLI
- `github.com/spf13/viper` - Configuration management
- `github.com/spf13/cobra` - CLI framework
- `github.com/urfave/cli/v2` - Simple CLI framework
- `github.com/kelseyhightower/envconfig` - Environment configuration

### Logging & Monitoring
- `go.uber.org/zap` - Fast, structured, leveled logging
- `github.com/sirupsen/logrus` - Structured logger
- `go.opentelemetry.io/otel` - OpenTelemetry instrumentation
- `github.com/prometheus/client_golang` - Prometheus metrics

### Testing & Mocking
- `github.com/stretchr/testify` - Testing utilities
- `github.com/golang/mock` - Mocking framework
- `github.com/gavv/httpexpect` - HTTP testing
- `github.com/testcontainers/testcontainers-go` - Integration testing

### Utilities
- `github.com/google/uuid` - UUID generation
- `github.com/pkg/errors` - Error handling
- `golang.org/x/crypto` - Cryptographic packages
- `golang.org/x/time` - Time-related packages

### Validation & Serialization
- `github.com/go-playground/validator/v10` - Struct validation
- `google.golang.org/protobuf` - Protocol buffers
- `github.com/json-iterator/go` - High-performance JSON
- `gopkg.in/yaml.v3` - YAML support

## 🔧 Package Management Best Practices

### Version Constraints
```go
// go.mod
module [MODULE_PATH]

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1     // Exact version
    github.com/spf13/viper v1.17.0      // Exact version
    github.com/stretchr/testify v1.8.4  // Exact version
)

// Use semantic versioning
// v1.2.3 - Major.Minor.Patch
// v1.2.3-rc1 - Release candidate
// v1.2.3-beta.2 - Beta version
// v1.2.3-alpha.1 - Alpha version
```

### Module Organization
```go
// Multi-module repository
// Module 1: API server
module github.com/company/project/api

// Module 2: CLI tool
module github.com/company/project/cli

// Module 3: Shared library
module github.com/company/project/shared
```

### Private Modules
```bash
# Configure private module access
go env -w GOPRIVATE=github.com/company/private
go env -w GONOPROXY=github.com/company/private
go env -w GONOSUMDB=github.com/company/private

# Use .netrc for authentication
machine github.com
login [USERNAME]
password [TOKEN]
```

## 📊 Package Analysis

### Dependency Tree
```bash
# List dependencies
go list -m all

# List direct dependencies
go list -m -versions all

# Show dependency graph
go mod graph

# Show why a dependency is needed
go mod why [PACKAGE_NAME]
```

### Module Information
```bash
# Show module information
go list -m [PACKAGE_NAME]
go list -m -versions [PACKAGE_NAME]

# Show available versions
go list -m -versions github.com/gin-gonic/gin

# Show module download path
go mod download -json [PACKAGE_NAME]
```

### Security Scanning
```bash
# Use govulncheck for vulnerability scanning
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Use third-party security scanners
gosec ./...
nancy sleuth
```

## 🗂️ Package Organization

### Standard Go Project Layout
```
[PROJECT_NAME]/
├── cmd/                    # Application entry points
│   ├── server/            # Server application
│   └── cli/               # CLI application
├── internal/              # Private application code
│   ├── controller/        # HTTP handlers
│   ├── service/           # Business logic
│   ├── repository/        # Data access layer
│   ├── model/             # Domain models
│   └── config/            # Configuration
├── pkg/                   # Public library code
├── api/                   # API definitions
├── web/                   # Web assets
├── scripts/               # Build and utility scripts
├── build/                 # Build output
├── deployments/           # Deployment configurations
├── test/                  # Additional test files
├── docs/                  # Documentation
├── examples/              # Example applications
├── third_party/           # Third-party dependencies
├── tools/                 # Tools and utilities
├── golangci.yml           # Linting configuration
├── go.mod                 # Module definition
├── go.sum                 # Dependency checksums
└── README.md              # Project documentation
```

### Feature-Based Organization
```
internal/
├── features/
│   ├── authentication/
│   │   ├── handler/
│   │   ├── service/
│   │   ├── repository/
│   │   └── model/
│   ├── users/
│   │   ├── handler/
│   │   ├── service/
│   │   ├── repository/
│   │   └── model/
│   └── shared/
│       ├── middleware/
│       ├── utils/
│       └── types/
├── core/
│   ├── config/
│   ├── database/
│   └── errors/
└── main.go
```

## 🔍 Package Selection Guidelines

### Choosing the Right Package
1. **Check Go Version Compatibility**: Ensure compatibility with your Go version
2. **Review Maintenance**: Check last commit date and issues
3. **Read Documentation**: Ensure comprehensive documentation
4. **Check Performance**: Benchmark critical packages
5. **Test License**: Verify license compatibility

### Package Evaluation Checklist
- [ ] Active maintenance (updated within last 6 months)
- [ ] Compatible with Go version
- [ ] Good documentation and examples
- [ ] Reasonable dependency count
- [ ] Good performance benchmarks
- [ ] No known security vulnerabilities
- [ ] MIT or permissive license
- [ ] Good community support

## 🚨 Common Issues & Solutions

### Version Conflicts
```bash
# Error: Two packages depend on different versions
Solution: Use go.mod to resolve conflicts

go mod tidy
go get [PACKAGE_NAME]@[COMPATIBLE_VERSION]
```

### Dependency Hell
```bash
# Error: Complex dependency tree
Solution: Use go mod graph to analyze

go mod graph
go mod why [PACKAGE_NAME]
```

### Build Issues
```bash
# Error: Build fails due to dependency issues
Solution: Clean and rebuild

go clean -modcache
go mod download
go build
```

### Module Cache Issues
```bash
# Error: Module cache corruption
Solution: Clear module cache

go clean -modcache
go mod download
```

## 📈 Performance Optimization

### Build Optimization
```bash
# Build with optimizations
go build -ldflags "-s -w"  # Strip debug info

# Build with specific tags
go build -tags=netgo -ldflags "-extldflags '-static'"

# Parallel builds
go build -p [NUM_CPUS]
```

### Dependency Optimization
```bash
# Use specific versions to reduce build time
go get [PACKAGE_NAME]@[SPECIFIC_VERSION]

# Use vendor for reproducible builds
go mod vendor
go build -mod=vendor
```

## 🔄 Continuous Integration

### CI/CD Integration
```yaml
# .github/workflows/go.yml
name: Go CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        go-version: [1.19, 1.20, 1.21]
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v3
        with:
          go-version: ${{ matrix.go-version }}
      - run: go mod download
      - run: go test -v ./...
      - run: go test -race -coverprofile=coverage.out ./...
      - run: go tool cover -html=coverage.out -o coverage.html
      - run: go vet ./...
      - run: go run github.com/golangci/golangci-lint/cmd/golangci-lint run
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
      - uses: actions/setup-go@v3
        with:
          go-version: '1.21'
      - run: go get -u ./...
      - run: go mod tidy
      - run: go test ./...
      # Create PR if tests pass
```

## 🔒 Security Best Practices

### Security Scanning
```bash
# Use govulncheck for vulnerability scanning
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Use gosec for static analysis
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
gosec ./...
```

### Secure Package Management
```bash
# Verify dependencies
go mod verify

# Use checksums for security
go mod download -json [PACKAGE_NAME]

# Configure private repositories securely
go env -w GOPRIVATE=github.com/company/private
```

## 📦 Development Tools

### Essential Tools
```bash
# Linting
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Security scanning
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Vulnerability checking
go install golang.org/x/vuln/cmd/govulncheck@latest

# Mock generation
go install github.com/golang/mock/mockgen@latest

# Protocol buffer compilation
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

### IDE Integration
```bash
# Go language server
go install golang.org/x/tools/gopls@latest

# Debugging
go install github.com/go-delve/delve/cmd/dlv@latest

# Testing
go install github.com/gotestyourself/gotest@latest
```

## 🎯 Go Specific Tips

### Module Management
```bash
# Initialize module with proper path
go mod init github.com/username/project

# Use semantic versioning
go get github.com/package@v1.2.3

# Update all dependencies
go get -u ./...

# Remove unused dependencies
go mod tidy
```

### Build Optimization
```bash
# Build for production
go build -ldflags "-s -w -X main.version=$(git describe --tags)"

# Build with custom tags
go build -tags=production,netgo

# Cross-platform builds
GOOS=linux GOARCH=amd64 go build -o app-linux-amd64
GOOS=windows GOARCH=amd64 go build -o app-windows-amd64.exe
```

---

**Go Version**: [GO_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
