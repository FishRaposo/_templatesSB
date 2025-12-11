<!--
File: mvp-sql-setup.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# MVP Go Setup Guide

## Overview

This guide extends the foundational Go templates with MVP-specific configurations for rapid backend development with minimal feature set.

## Prerequisites

- Go 1.19+
- Go modules
- Code editor (VS Code recommended)
- Git

## Quick Start

### 1. Project Setup

```bash
# Copy MVP Go boilerplate
cp tiers/mvp/code/minimal-boilerplate-go.tpl.go [project-name]/cmd/server/main.go

# Copy foundational templates
cp -r stacks/go/base/code/* [project-name]/internal/
cp -r stacks/go/base/tests/* [project-name]/test/

# Setup dependencies
cp stacks/go/go.mod.tpl [project-name]/go.mod
cd [project-name]
go mod tidy
```

### 2. Configuration

```go
// internal/config/app_config.go - extends foundational config
type AppConfig struct {
    *BaseConfig
}

func NewAppConfig() *AppConfig {
    return &AppConfig{
        BaseConfig: NewBaseConfig(),
    }
}

func (c *AppConfig) Load() error {
    if err := c.BaseConfig.Load(); err != nil {
        return err
    }
    
    // MVP-specific settings
    c.EnableAnalytics = false
    c.EnableCrashlytics = false
    c.EnableRemoteConfig = false
    
    // Minimal feature set
    c.MaxRetries = 2
    c.Timeout = 15 * time.Second
    
    return nil
}
```

## MVP Architecture

### Core Components

1. **Minimal Server Setup**
   - Standard library HTTP server
   - Simple middleware
   - Basic error handling

2. **Essential API Layer**
   - RESTful endpoints
   - Basic validation
   - Simple authentication

3. **Basic Data Layer**
   - File-based storage
   - Simple HTTP client
   - Basic caching

4. **Core Features**
   - Authentication (JWT)
   - Basic CRUD operations
   - Simple logging

## File Structure

```
cmd/
└── server/
    └── main.go              # MVP boilerplate
internal/
├── config/
│   ├── app_config.go        # MVP-specific config
│   └── env_config.go        # Environment settings
├── core/
│   ├── constants.go         # App constants
│   ├── middleware.go        # HTTP middleware
│   └── routes.go            # Route definitions
├── data/
│   ├── models/              # Data models
│   ├── services/            # Basic services
│   └── repositories/        # Simple repositories
├── presentation/
│   ├── controllers/         # API controllers
│   ├── handlers/            # HTTP handlers
│   └── middleware/          # Custom middleware
└── utils/
    ├── helpers.go           # Utility functions
    └── validators.go        # Input validation
```

## MVP Features

### 1. Authentication

```go
// internal/services/auth_service.go
type AuthService struct {
    *BaseService
    jwtSecret []byte
}

func NewAuthService() *AuthService {
    return &AuthService{
        BaseService: NewBaseService(),
        jwtSecret:   []byte(os.Getenv("JWT_SECRET")),
    }
}

func (s *AuthService) Login(email, password string) (map[string]interface{}, error) {
    // Basic validation
    if !s.ValidateEmail(email) {
        return nil, errors.New("invalid email")
    }
    
    // Generate JWT token
    token, err := s.GenerateJWT(map[string]interface{}{
        "email": email,
    })
    if err != nil {
        return nil, err
    }
    
    return map[string]interface{}{
        "success": true,
        "token":   token,
        "user":    map[string]string{"email": email},
    }, nil
}

func (s *AuthService) GenerateJWT(payload map[string]interface{}) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "email": payload["email"],
        "exp":   time.Now().Add(24 * time.Hour).Unix(),
    })
    
    return token.SignedString(s.jwtSecret)
}
```

### 2. Data Management

```go
// internal/services/data_service.go
type DataService struct {
    *BaseService
    dataFile string
}

func NewDataService() *DataService {
    return &DataService{
        BaseService: NewBaseService(),
        dataFile:    "data/items.json",
    }
}

func (s *DataService) GetItems() ([]Item, error) {
    data, err := os.ReadFile(s.dataFile)
    if err != nil {
        if os.IsNotExist(err) {
            return []Item{}, nil
        }
        return nil, err
    }
    
    var items []Item
    if err := json.Unmarshal(data, &items); err != nil {
        return nil, err
    }
    
    return items, nil
}

func (s *DataService) SaveItems(items []Item) error {
    data, err := json.MarshalIndent(items, "", "  ")
    if err != nil {
        return err
    }
    
    // Ensure data directory exists
    if err := os.MkdirAll("data", 0755); err != nil {
        return err
    }
    
    return os.WriteFile(s.dataFile, data, 0644)
}
```

### 3. HTTP Handlers

```go
// internal/presentation/handlers/item_handler.go
type ItemHandler struct {
    dataService *services.DataService
}

func NewItemHandler() *ItemHandler {
    return &ItemHandler{
        dataService: services.NewDataService(),
    }
}

func (h *ItemHandler) GetItems(w http.ResponseWriter, r *http.Request) {
    items, err := h.dataService.GetItems()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "data":    items,
    })
}

func (h *ItemHandler) CreateItem(w http.ResponseWriter, r *http.Request) {
    var item Item
    if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    items, err := h.dataService.GetItems()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    item.ID = len(items) + 1
    item.CreatedAt = time.Now()
    items = append(items, item)
    
    if err := h.dataService.SaveItems(items); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "success": true,
        "data":    item,
    })
}
```

## Configuration Options

### Environment Variables

```go
// internal/config/env_config.go
type EnvConfig struct {
    AppName     string
    Port        string
    APIBaseURL  string
    
    // MVP-specific flags
    EnableDebugMode bool
    EnableLogging   bool
    
    // API settings
    Timeout    time.Duration
    MaxRetries int
    
    // Security
    JWTSecret   string
    BcryptRounds int
}

func LoadEnvConfig() *EnvConfig {
    return &EnvConfig{
        AppName:    getEnv("APP_NAME", "[[.ProjectName]]"),
        Port:       getEnv("PORT", "3000"),
        APIBaseURL: getEnv("API_BASE_URL", "https://api.example.com"),
        
        EnableDebugMode: getEnv("GO_ENV", "development") != "production",
        EnableLogging:   getEnv("ENABLE_LOGGING", "true") != "false",
        
        Timeout:    getDurationEnv("API_TIMEOUT", 15*time.Second),
        MaxRetries: getIntEnv("MAX_RETRIES", 2),
        
        JWTSecret:    getEnv("JWT_SECRET", "fallback-secret"),
        BcryptRounds: getIntEnv("BCRYPT_ROUNDS", 10),
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
```

### Feature Flags

```go
// internal/config/feature_flags.go
type FeatureFlags struct {
    // MVP features - minimal set
    EnableFileStorage   bool
    EnableJWTAuth       bool
    EnableRateLimiting  bool
    EnableCORS          bool
    EnableCompression   bool
    EnableHelmet        bool
    EnableAnalytics     bool
    EnableCrashlytics   bool
}

func LoadFeatureFlags() *FeatureFlags {
    return &FeatureFlags{
        EnableFileStorage:  true,
        EnableJWTAuth:      true,
        EnableRateLimiting: false,
        EnableCORS:         true,
        EnableCompression:  false,
        EnableHelmet:       false,
        EnableAnalytics:    false,
        EnableCrashlytics:  false,
    }
}
```

## Development Workflow

### 1. Local Development

```bash
# Run development server
go run cmd/server/main.go

# Run with specific port
PORT=3001 go run cmd/server/main.go

# Run with environment file
source .env && go run cmd/server/main.go
```

### 2. Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### 3. Building

```bash
# Build for current platform
go build -o bin/server cmd/server/main.go

# Build for production
go build -ldflags="-s -w" -o bin/server cmd/server/main.go

# Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o bin/server-linux cmd/server/main.go
GOOS=windows GOARCH=amd64 go build -o bin/server.exe cmd/server/main.go
```

## Deployment

### 1. Traditional Server

```bash
# Build and deploy
go build -o bin/server cmd/server/main.go
./bin/server
```

### 2. Docker

```dockerfile
# Dockerfile
FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o server cmd/server/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/server .
EXPOSE 3000
CMD ["./server"]
```

```bash
# Build and run Docker image
docker build -t [[.ProjectName]] .
docker run -p 3000:3000 [[.ProjectName]]
```

### 3. Cloud Platforms

```bash
# Deploy to Google Cloud Run
gcloud builds submit --tag gcr.io/PROJECT_ID/[[.ProjectName]]
gcloud run deploy --image gcr.io/PROJECT_ID/[[.ProjectName]] --platform managed

# Deploy to Heroku
heroku create
heroku buildpacks:set heroku/go
git push heroku main
```

## MVP Components

### 1. Basic Server

```go
// cmd/server/main.go - MVP boilerplate
package main

import (
    "log"
    "net/http"
    "os"
    
    "[[.ProjectName]]/internal/config"
    "[[.ProjectName]]/internal/core/middleware"
    "[[.ProjectName]]/internal/presentation/handlers"
    "[[.ProjectName]]/internal/presentation/routes"
)

func main() {
    // Load configuration
    envConfig := config.LoadEnvConfig()
    
    // Setup router
    router := routes.SetupRouter()
    
    // Add middleware
    router.Use(middleware.Logging)
    router.Use(middleware.Recovery)
    
    // Health check endpoint
    router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"status":"ok","timestamp":"` + time.Now().Format(time.RFC3339) + `"}`))
    })
    
    // Start server
    port := ":" + envConfig.Port
    log.Printf("Server starting on port %s", port)
    
    if err := http.ListenAndServe(port, router); err != nil {
        log.Fatal("Server failed to start:", err)
    }
}
```

### 2. Route Setup

```go
// internal/presentation/routes/routes.go
package routes

import (
    "net/http"
    
    "[[.ProjectName]]/internal/presentation/handlers"
)

func SetupRouter() *http.ServeMux {
    router := http.NewServeMux()
    
    // Initialize handlers
    itemHandler := handlers.NewItemHandler()
    authHandler := handlers.NewAuthHandler()
    
    // Basic CRUD routes
    router.HandleFunc("/api/items", itemHandler.GetItems).Methods("GET")
    router.HandleFunc("/api/items", itemHandler.CreateItem).Methods("POST")
    router.HandleFunc("/api/items/", itemHandler.UpdateItem).Methods("PUT")
    router.HandleFunc("/api/items/", itemHandler.DeleteItem).Methods("DELETE")
    
    // Authentication routes
    router.HandleFunc("/api/auth/login", authHandler.Login).Methods("POST")
    router.HandleFunc("/api/auth/logout", authHandler.Logout).Methods("POST")
    
    return router
}
```

### 3. Base Service

```go
// internal/services/base_service.go
package services

import (
    "errors"
    "regexp"
    "time"
)

type BaseService struct {
    config *config.AppConfig
}

func NewBaseService() *BaseService {
    return &BaseService{
        config: config.NewAppConfig(),
    }
}

func (s *BaseService) HandleError(err error) map[string]interface{} {
    return map[string]interface{}{
        "success": false,
        "error":   err.Error(),
    }
}

func (s *BaseService) ValidateEmail(email string) bool {
    pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
    matched, _ := regexp.MatchString(pattern, email)
    return matched
}

func (s *BaseService) EnsureDataDir() error {
    if _, err := os.Stat("data"); os.IsNotExist(err) {
        return os.MkdirAll("data", 0755)
    }
    return nil
}
```

## MVP Limitations

### What's NOT Included

- No database integration (file-based only)
- No advanced authentication (OAuth, SSO)
- No real-time features (WebSockets)
- No advanced caching (Redis)
- No message queues
- No advanced logging (structured logging)
- No API documentation (Swagger)
- No rate limiting
- No advanced security features

### Upgrade Path

When ready to move to Core tier:

1. **Database**: Add PostgreSQL/MySQL/MongoDB integration
2. **Authentication**: Add OAuth providers and SSO
3. **Caching**: Add Redis for advanced caching
4. **Security**: Add rate limiting, advanced headers
5. **Monitoring**: Add structured logging and metrics
6. **Documentation**: Add Swagger/OpenAPI docs
7. **Performance**: Add compression, optimization

## Best Practices

### 1. Code Organization

- Keep features separate and focused
- Use consistent naming conventions
- Follow Go style guidelines
- Document public APIs

### 2. Performance

- Use goroutines properly
- Implement proper error handling
- Use connection pooling
- Optimize database queries

### 3. Security

- Validate all inputs
- Use HTTPS in production
- Implement proper authentication
- Sanitize outputs

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Change PORT environment variable
2. **Module Not Found**: Run go mod tidy
3. **Permission Errors**: Check file permissions for data directory
4. **Build Errors**: Check Go version and dependencies

### Debug Tips

- Use Go debugger (delve) for debugging
- Use fmt.Printf for quick debugging
- Check environment variables
- Monitor server logs

## Resources

- [Go Documentation](https://golang.org/doc/)
- [Effective Go](https://golang.org/doc/effective_go.html)
- [Go Web Programming](https://github.com/astaxie/build-web-application-with-golang)
- [Go Best Practices](https://golang.org/wiki/CodeReviewComments)

## Next Steps

1. Review the foundational templates for detailed implementation
2. Customize the MVP boilerplate for your specific needs
3. Implement your business logic using the provided structure
4. Add tests for your custom code
5. Prepare for deployment

---

**Note**: This MVP setup provides a solid foundation for rapid backend development. When your application grows, consider upgrading to the Core tier for additional features and capabilities.
