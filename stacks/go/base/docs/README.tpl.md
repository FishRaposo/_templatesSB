# Universal Template System - Go Stack
# Generated: 2025-12-10
# Purpose: go template utilities
# Tier: base
# Stack: go
# Category: template

# [PROJECT_NAME]

A Go application built with modern architecture, concurrency patterns, and enterprise-grade development practices.

## 🐹 Go Project Overview

This project demonstrates professional Go development with proper architecture, testing, monitoring, and deployment practices. Built for performance, scalability, and production reliability.

## 🚀 Getting Started

### Prerequisites
- Go: [GO_VERSION]
- Git: [GIT_VERSION]
- Docker (for containerization)
- PostgreSQL/MySQL (depending on database choice)

### Installation

```bash
# Clone the repository
git clone [REPOSITORY_URL]
cd [PROJECT_NAME]

# Download dependencies
go mod download

# Run the application
go run main.go

# Build for production
go build -o bin/[PROJECT_NAME] main.go
```

### Quick Start

```bash
# Development mode
go run main.go

# Run with environment file
export $(cat .env | xargs) && go run main.go

# Build and run
go build -o bin/[PROJECT_NAME] main.go
./bin/[PROJECT_NAME]

# Run tests
go test ./...

# Run with Docker
docker-compose up
```

## 📋 Project Structure

```
[PROJECT_NAME]/
├── cmd/
│   └── [PROJECT_NAME]/
│       └── main.go              # Application entry point
├── internal/
│   ├── config/
│   │   ├── config.go            # Configuration management
│   │   └── config_test.go
│   ├── controllers/
│   │   ├── auth.controller.go
│   │   ├── user.controller.go
│   │   └── health.controller.go
│   ├── middleware/
│   │   ├── auth.middleware.go
│   │   ├── cors.middleware.go
│   │   ├── logging.middleware.go
│   │   └── recovery.middleware.go
│   ├── models/
│   │   ├── user.go
│   │   ├── session.go
│   │   └── models.go
│   ├── repositories/
│   │   ├── user.repository.go
│   │   ├── session.repository.go
│   │   └── interfaces.go
│   ├── services/
│   │   ├── auth.service.go
│   │   ├── user.service.go
│   │   ├── email.service.go
│   │   └── interfaces.go
│   ├── handlers/
│   │   ├── auth.handler.go
│   │   ├── user.handler.go
│   │   └── health.handler.go
│   ├── utils/
│   │   ├── logger.go
│   │   ├── validator.go
│   │   ├── helpers.go
│   │   └── constants.go
│   └── database/
│       ├── database.go          # Database connection
│       ├── migrations/          # Database migrations
│       └── seeds/               # Database seeds
├── pkg/
│   ├── api/
│   │   ├── routes.go            # API routes
│   │   ├── middleware.go        # API middleware
│   │   └── response.go          # Response helpers
│   ├── auth/
│   │   ├── jwt.go               # JWT utilities
│   │   └── password.go          # Password utilities
│   └── errors/
│       ├── errors.go            # Custom error types
│       └── handlers.go          # Error handlers
├── api/
│   ├── proto/                   # Protocol Buffer definitions
│   └── openapi/                 # OpenAPI specifications
├── docs/
│   ├── README.md                # This file
│   ├── API.md                   # API documentation
│   ├── DEPLOYMENT.md            # Deployment guide
│   └── CONTRIBUTING.md          # Contribution guidelines
├── scripts/
│   ├── build.sh                 # Build script
│   ├── test.sh                  # Test script
│   └── deploy.sh                # Deployment script
├── test/
│   ├── integration/             # Integration tests
│   ├── e2e/                     # End-to-end tests
│   └── fixtures/                # Test fixtures
├── configs/
│   ├── config.yaml              # Configuration file
│   └── config.example.yaml      # Example configuration
├── go.mod                       # Go modules file
├── go.sum                       # Go modules checksum
├── Dockerfile                   # Docker configuration
├── docker-compose.yml           # Docker Compose configuration
├── Makefile                     # Build automation
├── .gitignore                   # Git ignore file
├── .golangci.yml                # GolangCI-Lint configuration
└── README.md                    # Project documentation
```

## 🛠️ Development Setup

### Environment Configuration

```bash
# Copy configuration file
cp configs/config.example.yaml configs/config.yaml

# Edit configuration with your settings
# configs/config.yaml
server:
  port: 8080
  host: localhost

database:
  host: localhost
  port: 5432
  name: [PROJECT_NAME]
  user: [DB_USER]
  password: [DB_PASSWORD]

jwt:
  secret: [JWT_SECRET]
  expiration: 24h

redis:
  host: localhost
  port: 6379
  password: [REDIS_PASSWORD]
```

### Development Tools

```bash
# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/air-verse/air@latest
go install github.com/swaggo/swag/cmd/swag@latest

# Run with hot reload
air

# Run linter
golangci-lint run

# Generate API documentation
swag init
```

## 🧪 Testing

### Test Categories

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run specific test
go test ./internal/services -v

# Run integration tests
go test -tags=integration ./test/integration/...

# Run E2E tests
go test -tags=e2e ./test/e2e/...
```

### Test Configuration

```go
// internal/config/test.go
package config

func NewTestConfig() *Config {
    return &Config{
        Server: ServerConfig{
            Port: 8081,
            Host: "localhost",
        },
        Database: DatabaseConfig{
            Host:     "localhost",
            Port:     5432,
            Name:     "[PROJECT_NAME]_test",
            User:     "test",
            Password: "test",
        },
        JWT: JWTConfig{
            Secret:     "test-secret",
            Expiration: "1h",
        },
    }
}
```

## 📦 Package Management

### Dependencies

```go
// go.mod
module [PROJECT_NAME]

go [GO_VERSION]

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/golang-jwt/jwt/v5 v5.0.0
    github.com/spf13/viper v1.16.0
    github.com/lib/pq v1.10.9
    github.com/go-redis/redis/v8 v8.11.5
    github.com/swaggo/gin-swagger v1.6.0
    github.com/swaggo/files v1.0.1
    github.com/swaggo/swag v1.16.1
    golang.org/x/crypto v0.12.0
    github.com/stretchr/testify v1.8.4
    github.com/golang-migrate/migrate/v4 v4.16.2
    github.com/sirupsen/logrus v1.9.3
    github.com/joho/godotenv v1.5.1
)
```

### Package Management Commands

```bash
# Initialize module
go mod init [PROJECT_NAME]

# Add dependency
go get github.com/gin-gonic/gin

# Add specific version
go get github.com/gin-gonic/gin@v1.9.1

# Update dependencies
go get -u ./...

# Remove unused dependencies
go mod tidy

# Download dependencies
go mod download

# Verify dependencies
go mod verify
```

## 🏗️ Architecture

### Clean Architecture

This project follows Clean Architecture principles:

1. **Domain Layer**: Business entities and interfaces
2. **Use Case Layer**: Application business rules
3. **Infrastructure Layer**: External dependencies
4. **Interface Layer**: Controllers and handlers

### Example Service

```go
// internal/services/auth.service.go
package services

import (
    "context"
    "errors"
    "time"
    
    "[PROJECT_NAME]/internal/models"
    "[PROJECT_NAME]/internal/repositories"
    "[PROJECT_NAME]/pkg/auth"
)

type AuthService struct {
    userRepo repositories.UserRepository
    jwtAuth  auth.JWTAuth
}

func NewAuthService(userRepo repositories.UserRepository, jwtAuth auth.JWTAuth) *AuthService {
    return &AuthService{
        userRepo: userRepo,
        jwtAuth:  jwtAuth,
    }
}

func (s *AuthService) Login(ctx context.Context, email, password string) (*models.AuthResponse, error) {
    user, err := s.userRepo.GetByEmail(ctx, email)
    if err != nil {
        return nil, errors.New("invalid credentials")
    }
    
    if !auth.CheckPassword(password, user.Password) {
        return nil, errors.New("invalid credentials")
    }
    
    token, err := s.jwtAuth.GenerateToken(user.ID)
    if err != nil {
        return nil, err
    }
    
    return &models.AuthResponse{
        Token: token,
        User:  *user,
    }, nil
}
```

## 🔐 Security

### Security Features

- **JWT Authentication**: Secure token-based authentication
- **Password Hashing**: bcrypt for secure password storage
- **CORS Protection**: Cross-origin resource sharing protection
- **Input Validation**: Request validation and sanitization
- **Rate Limiting**: Request rate limiting
- **Security Headers**: HTTP security headers

### Security Middleware

```go
// internal/middleware/auth.middleware.go
package middleware

import (
    "net/http"
    "strings"
    
    "[PROJECT_NAME]/pkg/auth"
    "[PROJECT_NAME]/pkg/errors"
    
    "github.com/gin-gonic/gin"
)

func AuthMiddleware(jwtAuth auth.JWTAuth) gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, errors.NewError("Authorization header required"))
            c.Abort()
            return
        }
        
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        claims, err := jwtAuth.ValidateToken(tokenString)
        if err != nil {
            c.JSON(http.StatusUnauthorized, errors.NewError("Invalid token"))
            c.Abort()
            return
        }
        
        c.Set("userID", claims.UserID)
        c.Next()
    }
}
```

## 📊 Performance

### Performance Features

- **Connection Pooling**: Database connection pooling
- **Redis Caching**: In-memory caching for frequent queries
- **Goroutine Pooling**: Worker pool for concurrent tasks
- **Memory Management**: Efficient memory usage patterns
- **Monitoring**: Performance metrics and logging

### Performance Monitoring

```go
// internal/middleware/metrics.middleware.go
package middleware

import (
    "time"
    
    "github.com/gin-gonic/gin"
    "github.com/prometheus/client_golang/prometheus"
)

var (
    requestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "http_request_duration_seconds",
            Help: "Duration of HTTP requests.",
        },
        []string{"method", "path", "status"},
    )
)

func MetricsMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        
        c.Next()
        
        duration := time.Since(start).Seconds()
        requestDuration.WithLabelValues(
            c.Request.Method,
            c.FullPath(),
            string(rune(c.Writer.Status())),
        ).Observe(duration)
    }
}
```

## 🚀 Deployment

### Build Configuration

```bash
# Build for development
go build -o bin/[PROJECT_NAME] main.go

# Build for production
go build -ldflags="-s -w" -o bin/[PROJECT_NAME] main.go

# Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o bin/[PROJECT_NAME]-linux-amd64 main.go
GOOS=windows GOARCH=amd64 go build -o bin/[PROJECT_NAME]-windows-amd64 main.go
GOOS=darwin GOARCH=amd64 go build -o bin/[PROJECT_NAME]-darwin-amd64 main.go
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM golang:[GO_VERSION]-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -ldflags="-s -w" -o bin/[PROJECT_NAME] main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/bin/[PROJECT_NAME] .
COPY --from=builder /app/configs ./configs

EXPOSE 8080
CMD ["./[PROJECT_NAME]"]
```

## 🔄 CI/CD Pipeline

### GitHub Actions

```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Go
      uses: actions/setup-go@v4
      with:
        go-version: '[GO_VERSION]'
        
    - name: Cache Go modules
      uses: actions/cache@v3
      with:
        path: ~/go/pkg/mod
        key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
        
    - name: Download dependencies
      run: go mod download
      
    - name: Run tests
      run: go test -v -race -coverprofile=coverage.out ./...
      
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      
    - name: Run linter
      uses: golangci/golangci-lint-action@v3
      
  build:
    needs: test
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Go
      uses: actions/setup-go@v4
      with:
        go-version: '[GO_VERSION]'
        
    - name: Build application
      run: go build -ldflags="-s -w" -o bin/[PROJECT_NAME] main.go
      
    - name: Build Docker image
      run: docker build -t [PROJECT_NAME] .
```

## 📚 Documentation

### API Documentation

```go
// cmd/[PROJECT_NAME]/main.go
package main

import (
    "github.com/gin-gonic/gin"
    swaggerFiles "github.com/swaggo/files"
    ginSwagger "github.com/swaggo/gin-swagger"
    
    _ "[PROJECT_NAME]/docs" // swagger docs
)

// @title [PROJECT_NAME] API
// @version 1.0
// @description API documentation for [PROJECT_NAME]
// @host localhost:8080
// @BasePath /api/v1
func main() {
    r := gin.Default()
    
    // Swagger documentation
    r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
    
    // API routes
    setupRoutes(r)
    
    r.Run(":8080")
}
```

### Code Documentation

```go
// Package services provides business logic for the application.
//
// This package contains the core business logic and use cases for the
// [PROJECT_NAME] application. It implements the Clean Architecture pattern
// by depending on abstractions rather than concrete implementations.
//
// Example usage:
//
//     authService := services.NewAuthService(userRepo, jwtAuth)
//     authResponse, err := authService.Login(ctx, email, password)
//
package services

// Login authenticates a user with email and password.
//
// Login validates the user credentials and returns an authentication response
// containing a JWT token and user information. It uses bcrypt to verify the
// password hash and generates a JWT token for authenticated users.
//
// Parameters:
//   - ctx: Context for the request
//   - email: User's email address
//   - password: User's password
//
// Returns:
//   - *models.AuthResponse: Authentication response with token and user data
//   - error: Error if authentication fails
//
// Example:
//
//     authResp, err := authService.Login(context.Background(), "user@example.com", "password")
//     if err != nil {
//         log.Fatal(err)
//     }
//     fmt.Printf("Token: %s\n", authResp.Token)
func (s *AuthService) Login(ctx context.Context, email, password string) (*models.AuthResponse, error) {
    // Implementation
}
```

## 🤝 Contributing

### Development Workflow

1. Fork the repository
2. Create feature branch: `git checkout -b feature/[FEATURE_NAME]`
3. Make changes and add tests
4. Run quality checks: `make lint && make test`
5. Commit changes: `git commit -m "Add [FEATURE_NAME]"`
6. Push to branch: `git push origin feature/[FEATURE_NAME]`
7. Create pull request

### Code Standards

- Follow Go formatting: `go fmt ./...`
- Use `golangci-lint` for code quality
- Write comprehensive tests
- Add godoc comments for public functions
- Use meaningful variable and function names
- Follow Go idioms and conventions

## 📞 Support

### Getting Help

- **Documentation**: Check the `docs/` directory
- **Issues**: Create GitHub issue for bugs
- **Discussions**: Use GitHub Discussions for questions
- **Email**: [CONTACT_EMAIL]

### Common Issues

```bash
# Fix module issues
go clean -modcache
go mod download

# Fix build issues
go mod tidy
go build ./...

# Fix test issues
go test -v ./...
```

## 📄 License

Users should add their appropriate license when using this template.

## 🏆 Acknowledgments

- **Go Team**: For the excellent programming language
- **Gin Framework**: For the robust web framework
- **Community**: For the amazing packages and tools
- **Contributors**: For making this project better

---

**Go Version**: [GO_VERSION]  
**Framework**: Gin, GORM, Redis  
**Last Updated**: [DATE]  
**Template Version**: 1.0

### Installation

```bash
# Clone the repository
git clone [REPOSITORY_URL]
cd [PROJECT_NAME]

# Download dependencies
go mod download

# Copy environment variables
cp .env.example .env
# Edit .env with your configuration
```

### Running the Application

```bash
# Run the application
go run main.go

# Run with specific configuration
go run main.go --config=config.yaml

# Run in development mode
go run main.go --dev
```

## 📱 Features

- [FEATURE_1]
- [FEATURE_2]
- [FEATURE_3]

## 🏗️ Architecture

This Go application follows a clean architecture pattern:

```
cmd/
├── server/         # Application entry points
└── cli/           # CLI commands

internal/
├── controller/    # HTTP handlers
├── service/       # Business logic
├── repository/    # Data access layer
├── model/         # Domain models
├── middleware/    # HTTP middleware
├── config/        # Configuration
└── utils/         # Utility functions

pkg/               # Public libraries
api/               # API definitions (OpenAPI, protobuf)
docs/              # Documentation
scripts/           # Build and deployment scripts
```

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run specific test
go test -v ./internal/service

# Run benchmarks
go test -bench=. ./...

# Run race condition tests
go test -race ./...
```

## 📦 Build & Deployment

```bash
# Build the application
go build -o bin/[PROJECT_NAME] ./cmd/server

# Build for different platforms
GOOS=linux GOARCH=amd64 go build -o bin/[PROJECT_NAME]-linux-amd64 ./cmd/server
GOOS=windows GOARCH=amd64 go build -o bin/[PROJECT_NAME]-windows-amd64 ./cmd/server
GOOS=darwin GOARCH=amd64 go build -o bin/[PROJECT_NAME]-darwin-amd64 ./cmd/server

# Build with version information
go build -ldflags "-X main.version=[VERSION]" -o bin/[PROJECT_NAME] ./cmd/server

# Docker build
docker build -t [PROJECT_NAME]:[VERSION] .
docker run -p [PORT]:[PORT] [PROJECT_NAME]:[VERSION]
```

## 🔧 Development

### Code Quality

```bash
# Format code
go fmt ./...

# Lint code
golangci-lint run

# Vet code
go vet ./...

# Check for security issues
gosec ./...

# Update dependencies
go mod tidy
go get -u ./...
```

### Development Tools

```bash
# Install development dependencies
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Generate code (if using tools)
go generate ./...

# Run migration (if using database)
go run cmd/migrate/main.go up
```

## 📚 Dependencies

### Core Dependencies
- `github.com/gin-gonic/gin` - Web framework
- `github.com/golang-migrate/migrate` - Database migrations
- `github.com/spf13/viper` - Configuration management
- `github.com/spf13/cobra` - CLI framework
- `go.uber.org/zap` - Structured logging
- `github.com/stretchr/testify` - Testing utilities

### Development Dependencies
- `github.com/golangci/golangci-lint` - Linting
- `github.com/securecodewarrior/gosec` - Security scanning
- `github.com/golang/mock` - Mocking framework
- `google.golang.org/protobuf` - Protocol buffers

## 🔗 API Documentation

API documentation is available at:
- Swagger UI: [SWAGGER_URL]
- OpenAPI Spec: [OPENAPI_URL]

## 🏃 Performance

### Performance Monitoring
- Built-in metrics collection
- Pprof integration for profiling
- Memory and CPU monitoring

### Optimization Tips
- Use connection pooling for databases
- Implement proper caching strategies
- Leverage Go's concurrency patterns
- Monitor goroutine leaks

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow Go best practices and idioms
- Write comprehensive tests
- Use meaningful variable names
- Keep functions small and focused
- Handle errors properly

## 📄 License

This project is licensed under the [LICENSE_TYPE] License - see the LICENSE file for details.

## 📞 Support

For support, please contact [SUPPORT_EMAIL] or create an issue in the repository.

---

**Go Version**: [GO_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
