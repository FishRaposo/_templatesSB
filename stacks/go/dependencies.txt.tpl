#!/usr/bin/env bash
# Go Stack Dependencies Template
# Complete module management and tooling configurations for Go projects

# ====================
# GO MODULE INITIALIZATION
# ====================

# Initialize module (run once)
go mod init {{MODULE_PATH}}

# ====================
# CORE DEPENDENCIES
# ====================

# Web Framework
go get github.com/gin-gonic/gin@latest
go get github.com/gin-gonic/gin@v1.9.1  # Specific version for stability

# Alternative Frameworks (comment/uncomment as needed)
# go get github.com/labstack/echo/v4@latest  # Echo framework
# go get github.com/gorilla/mux@latest      # Gorilla Mux
# go get github.com/go-chi/chi/v5@latest    # Chi router

# Database & ORM
go get gorm.io/gorm@latest
go get gorm.io/driver/postgres@latest
go get gorm.io/driver/mysql@latest
go get gorm.io/driver/sqlite@latest

# Migrations
go get -u github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Redis Client
go get github.com/redis/go-redis/v9@latest

# ====================
# AUTHENTICATION & SECURITY
# ====================

# JWT Authentication
go get github.com/golang-jwt/jwt/v5@latest
go get github.com/golang-jwt/jwt/v5@v5.2.0

# Password Hashing
go get golang.org/x/crypto@latest

# Rate Limiting
go get golang.org/x/time/rate@latest

# Validation
go get github.com/go-playground/validator/v10@latest

// ====================
// API & HTTP CLIENTS
// ====================

// HTTP Client
go get github.com/go-resty/resty/v2@latest

// GraphQL (if needed)
go get github.com/99designs/gqlgen@latest

// ====================
// BACKGROUND JOBS & QUEUES
// ====================

// Task Queue
go get github.com/hibiken/asynq@latest

// Message Queue (RabbitMQ)
go get github.com/rabbitmq/amqp091-go@latest

// ====================
// MONITORING & OBSERVABILITY
// ====================

// Prometheus Metrics
go get github.com/prometheus/client_golang@latest
go get github.com/prometheus/client_golang/prometheus@latest

// OpenTelemetry
go get go.opentelemetry.io/otel@latest
go get go.opentelemetry.io/otel/sdk@latest
go get go.opentelemetry.io/otel/exporters/prometheus@latest

// Structured Logging
go get go.uber.org/zap@latest  // High-performance logging
go get github.com/rs/zerolog@latest  // Zero-allocation logging

// ====================
// CONFIGURATION & ENVIRONMENT
// ====================

// Environment Variables
go get github.com/spf13/viper@latest
go get github.com/joho/godotenv@latest

// Configuration Validation
go get github.com/caarlos0/env/v10@latest

// ====================
// TESTING FRAMEWORKS
// ====================

// Standard Library Testing (built-in)
// Additional testing utilities
go get github.com/stretchr/testify@latest
go get github.com/stretchr/testify/assert@latest
go get github.com/stretchr/testify/mock@latest

// HTTP Testing
go get github.com/valyala/fasthttp@latest  // Fast HTTP for testing

// Mocking
go get go.uber.org/mock@latest  // GoMock

// Fuzzing (Go 1.18+)
// Built-in: go test -fuzz=FuzzTestName

// ====================
// CODE GENERATION & TOOLS
// ====================

// Swagger/OpenAPI
go get github.com/swaggo/swag/cmd/swag@latest
go get github.com/swaggo/gin-swagger@latest
go get github.com/swaggo/files@latest

// Protocol Buffers
go get google.golang.org/protobuf/cmd/protoc-gen-go@latest
go get google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

// ====================
// UTILITIES
// ====================

// UUID Generation
go get github.com/google/uuid@latest

// JSON Processing
go get github.com/tidwall/gjson@latest
go get github.com/tidwall/sjson@latest

// Retry Logic
go get github.com/avast/retry-go/v4@latest

// Worker Pools
go get github.com/gammazero/workerpool@latest

// ====================
// DEVELOPMENT TOOLS
// ====================

// Air - Live Reload
go install github.com/cosmtrek/air@latest

// Task Runner
go get github.com/go-task/task/v3/cmd/task@latest

// ====================
// DEV TOOLS & LINTING
// ====================

// Static Analysis
go install honnef.co/go/tools/cmd/staticcheck@latest

// Formatting
go install mvdan.cc/gofumpt@latest

// Import Management
go install github.com/incu6us/goimports-reviser/v3@latest

// ====================
// BUILD TOOLS
// ====================

// Cross-compilation (built-in)
// go build -o myapp-linux-amd64 -ldflags="-s -w" -tags netgo -a -v .

// Makefile is recommended for complex builds

// ====================
// DOCKER & DEPLOYMENT
// ====================

// Create Dockerfile (see example below)
// Create docker-compose.yml for local development

// ====================
// MAKEFILE EXAMPLE
// ====================

cat > Makefile << 'EOF'
# Go Project Makefile

BINARY_NAME={{PROJECT_NAME}}
DOCKER_IMAGE={{PROJECT_NAME}}:latest
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

.PHONY: all build clean test coverage lint fmt run docker-build docker-run

all: test build

build:
	$(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME) -v ./cmd/main.go

clean:
	$(GOCLEAN)
	rm -rf bin/

test:
	$(GOTEST) -v ./...

test-short:
	$(GOTEST) -short -v ./...

coverage:
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

lint:
	staticcheck ./...
	golangci-lint run

fmt:
	gofumpt -l -w .
	goimports-reviser -project-name {{MODULE_PATH}} ./...

run:
	$(GOCMD) run ./cmd/main.go

run-dev:
	air -c .air.toml

deps:
	$(GOMOD) download
	$(GOMOD) tidy

deps-update:
	$(GOMOD) download
	$(GOMOD) tidy
	$(GOMOD) verify

security:
	gosec ./...

benchmark:
	$(GOTEST) -bench=. -benchmem ./...

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 -v ./cmd/main.go

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe -v ./cmd/main.go

docker-build:
	docker build -t $(DOCKER_IMAGE) .

docker-run:
	docker run -p 8080:8080 $(DOCKER_IMAGE)

docker-compose-up:
	docker-compose up -d

docker-compose-down:
	docker-compose down

setup:
	@echo "Setting up development environment..."
	go install github.com/cosmtrek/air@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install mvdan.cc/gofumpt@latest
	go install github.com/incu6us/goimports-reviser/v3@latest
	@echo "Development environment setup complete!"

help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run tests"
	@echo "  coverage       - Generate coverage report"
	@echo "  lint           - Run linters"
	@echo "  fmt            - Format code"
	@echo "  run            - Run the application"
	@echo "  run-dev        - Run with hot reload (requires air)"
	@echo "  deps           - Download and tidy dependencies"
	@echo "  security       - Run security scan"
	@echo "  benchmark      - Run benchmarks"
	@echo "  build-linux    - Build for Linux"
	@echo "  build-windows  - Build for Windows"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  setup          - Setup development environment"
EOF

// ====================
// AIR CONFIGURATION (Hot Reload)
// ====================

cat > .air.toml << 'EOF'
# Air configuration for hot reload
root = "."
testdata_dir = "testdata"
tmp_dir = "tmp"

[build]
  args_bin = []
  bin = "./tmp/main"
  cmd = "go build -o ./tmp/main ./cmd/main.go"
  delay = 1000
  exclude_dir = ["assets", "tmp", "vendor", "testdata", "node_modules", "dist"]
  exclude_file = []
  exclude_regex = ["_test.go"]
  exclude_unchanged = false
  follow_symlink = false
  full_bin = ""
  include_dir = []
  include_ext = ["go", "tpl", "tmpl", "html"]
  include_file = []
  kill_delay = "0s"
  log = "build-errors.log"
  poll = false
  poll_interval = 0
  post_cmd = []
  pre_cmd = []
  rerun = false
  rerun_delay = 500
  send_interrupt = false
  stop_on_root = false

[color]
  app = ""
  build = "yellow"
  main = "magenta"
  runner = "green"
  watcher = "cyan"

[log]
  main_only = false
  time = false

[misc]
  clean_on_exit = false

[screen]
  clear_on_rebuild = false
EOF

// ====================
// DOCKERFILE
// ====================

cat > Dockerfile << 'EOF'
# Multi-stage build for Go application
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -a -o app ./cmd/main.go

# Final stage
FROM scratch

# Copy CA certificates from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /app/app /app

# Expose port
EXPOSE 8080

# Set timezone
ENV TZ=UTC

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app", "-health-check"] || exit 1

# Run the application
ENTRYPOINT ["/app"]
EOF

// ====================
// DOCKER COMPOSE
// ====================

cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - ENV=production
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USER=myuser
      - DB_PASS=mypassword
      - DB_NAME=mydb
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "/app", "-health-check"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
  
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: myuser
      POSTGRES_PASSWORD: mypassword
      POSTGRES_DB: mydb
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    restart: unless-stopped
  
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped
    command: redis-server --appendonly yes
  
  # Optional: Adminer for database management
  adminer:
    image: adminer:latest
    ports:
      - "8081:8080"
    depends_on:
      - postgres
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
EOF

// ====================
// DEVELOPMENT WORKFLOW
// ====================

/*
1. Initial Setup:
   go mod init {{MODULE_PATH}}
   make setup
   make deps

2. Development:
   make run-dev  # Uses air for hot reload
   OR
   air -c .air.toml

3. Testing:
   make test
   make coverage
   make benchmark

4. Code Quality:
   make fmt
   make lint
   make security

5. Build:
   make build
   make build-linux
   make build-windows

6. Docker:
   make docker-build
   make docker-run
   docker-compose up -d

7. Database:
   migrate -source file://migrations -database postgres://user:pass@localhost/dbname?sslmode=disable up
*/

// ====================
// TESTING WORKFLOW
// ====================

/*
# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Run benchmarks
go test -bench=. -benchmem ./...

# Run specific test
go test -run TestFunctionName ./...

# Run with race detector
go test -race ./...

# Generate test coverage badge
gopherbadge -filename=coverage.out -badge-file=coverage.svg
*/

// ====================
// SECURITY BEST PRACTICES
// ====================

/*
- Use golang.org/x/crypto for password hashing
- Implement proper input validation
- Use prepared statements for SQL queries
- Enable CORS properly
- Use HTTPS in production
- Keep dependencies updated: go get -u ./...
- Run security scans: gosec ./...
- Use minimal base images (scratch or distroless)
- Don't run as root in containers
- Use read-only filesystem where possible
*/

// ====================
// PERFORMANCE OPTIMIZATION
// ====================

/*
# Build optimizations:
go build -ldflags="-s -w" -o app ./cmd/main.go

# Profile CPU:
go test -cpuprofile=cpu.prof -bench=. ./...
go tool pprof cpu.prof

# Profile memory:
go test -memprofile=mem.prof -bench=. ./...
go tool pprof mem.prof

# Benchmark:
go test -bench=. -benchmem -count=5 ./...
*/

// ====================
// CI/CD INTEGRATION
// ====================

/*
# GitHub Actions example:

name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    
    - name: Install dependencies
      run: go mod download
    
    - name: Run tests
      run: go test -v ./...
    
    - name: Run coverage
      run: go test -coverprofile=coverage.out ./...
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        files: ./coverage.out
*/

echo "Go dependencies and tooling setup complete!"
echo "Run 'make help' to see available commands"
