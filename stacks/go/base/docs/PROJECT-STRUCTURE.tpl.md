# Universal Template System - Go Stack
# Generated: 2025-12-10
# Purpose: go template utilities
# Tier: base
# Stack: go
# Category: template

# {{PROJECT_NAME}} - Go Project Structure

**Tier**: {{TIER}} | **Stack**: Go

## 🟦 Canonical Go Project Structure

### **MVP Tier (Simple Service)**
```
{{PROJECT_NAME}}/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── handlers/
│   │   └── handlers.go
│   ├── models/
│   │   └── models.go
│   └── services/
│       └── services.go
├── go.mod
├── go.sum
└── README.md
```

### **CORE Tier (Production Service)**
```
{{PROJECT_NAME}}/
├── cmd/
│   ├── server/
│   │   └── main.go
│   ├── worker/
│   │   └── main.go
│   └── cli/
│       └── main.go
├── internal/
│   ├── app/
│   │   ├── app.go
│   │   └── config.go
│   ├── handlers/
│   │   ├── auth.go
│   │   ├── users.go
│   │   ├── health.go
│   │   └── middleware/
│   │       ├── auth.go
│   │       ├── cors.go
│   │       ├── logging.go
│   │       └── recovery.go
│   ├── services/
│   │   ├── auth.go
│   │   ├── users.go
│   │   └── interfaces/
│   │       └── services.go
│   ├── repositories/
│   │   ├── interfaces/
│   │   │   └── repositories.go
│   │   ├── users.go
│   │   └── base.go
│   ├── models/
│   │   ├── user.go
│   │   ├── common.go
│   │   └── errors.go
│   ├── database/
│   │   ├── database.go
│   │   ├── migrations/
│   │   └── seeds/
│   ├── validators/
│   │   ├── user.go
│   │   └── common.go
│   └── utils/
│       ├── logger.go
│       ├── hasher.go
│       └── response.go
├── pkg/
│   ├── auth/
│   │   ├── jwt.go
│   │   └── password.go
│   ├── middleware/
│   │   ├── auth.go
│   │   └── logging.go
│   └── utils/
│       ├── validator.go
│       └── response.go
├── api/
│   ├── openapi.yaml
│   └── postman.json
├── configs/
│   ├── config.yaml
│   ├── config.prod.yaml
│   └── config.dev.yaml
├── scripts/
│   ├── build.sh
│   ├── migrate.sh
│   └── seed.sh
├── tests/
│   ├── integration/
│   ├── unit/
│   └── fixtures/
├── docs/
│   ├── api/
│   └── deployment/
├── go.mod
├── go.sum
├── Dockerfile
├── docker-compose.yml
└── README.md
```

### **FULL Tier (Enterprise Service)**
```
{{PROJECT_NAME}}/
├── cmd/
│   ├── [CORE tier commands]
│   ├── migration/
│   │   └── main.go
│   └── admin/
│       └── main.go
├── internal/
│   ├── [CORE tier structure]
│   ├── background/
│   │   ├── workers/
│   │   ├── jobs/
│   │   └── scheduler/
│   ├── monitoring/
│   │   ├── metrics/
│   │   ├── health/
│   │   └── tracing/
│   ├── analytics/
│   │   ├── events/
│   │   └── tracking/
│   ├── integrations/
│   │   ├── external/
│   │   ├── messaging/
│   │   └── cache/
│   └── enterprise/
│       ├── audit/
│       ├── compliance/
│       └── security/
├── pkg/
│   ├── [CORE tier packages]
│   ├── messaging/
│   ├── cache/
│   ├── monitoring/
│   └── enterprise/
├── tests/
│   ├── [CORE test structure]
│   ├── e2e/
│   ├── load/
│   └── contracts/
├── tools/
│   ├── build/
│   ├── deployment/
│   └── monitoring/
├── deployments/
│   ├── kubernetes/
│   ├── terraform/
│   └── helm/
├── observability/
│   ├── prometheus/
│   ├── grafana/
│   └── jaeger/
└── [CORE tier files]
```

## 📁 Module Structure Pattern

### **Command Layer (cmd/)**
```go
// cmd/server/main.go
package main

import (
    "log"
    "{{PROJECT_NAME}}/internal/app"
    "{{PROJECT_NAME}}/internal/database"
)

func main() {
    // Load configuration
    cfg := app.LoadConfig()
    
    // Initialize database
    db, err := database.New(cfg.DatabaseURL)
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    defer db.Close()
    
    // Run migrations
    if err := database.Migrate(db); err != nil {
        log.Fatal("Failed to run migrations:", err)
    }
    
    // Initialize and start application
    application := app.New(cfg, db)
    if err := application.Run(); err != nil {
        log.Fatal("Failed to start application:", err)
    }
}
```

### **Handler Layer**
```go
// internal/handlers/users.go
package handlers

import (
    "net/http"
    "{{PROJECT_NAME}}/internal/services"
    "{{PROJECT_NAME}}/pkg/utils"
)

type UserHandler struct {
    userService services.UserService
}

func NewUserHandler(userService services.UserService) *UserHandler {
    return &UserHandler{
        userService: userService,
    }
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
    var req CreateUserRequest
    if err := utils.DecodeJSON(w, r, &req); err != nil {
        utils.RespondWithError(w, http.StatusBadRequest, err.Error())
        return
    }
    
    if err := utils.ValidateStruct(&req); err != nil {
        utils.RespondWithError(w, http.StatusBadRequest, err.Error())
        return
    }
    
    user, err := h.userService.CreateUser(r.Context(), req)
    if err != nil {
        utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
        return
    }
    
    utils.RespondWithJSON(w, http.StatusCreated, user)
}
```

### **Service Layer**
```go
// internal/services/users.go
package services

import (
    "context"
    "{{PROJECT_NAME}}/internal/models"
    "{{PROJECT_NAME}}/internal/repositories"
    "{{PROJECT_NAME}}/pkg/auth"
)

type UserService interface {
    CreateUser(ctx context.Context, req CreateUserRequest) (*models.User, error)
    GetUserByID(ctx context.Context, id string) (*models.User, error)
    UpdateUser(ctx context.Context, id string, req UpdateUserRequest) (*models.User, error)
    DeleteUser(ctx context.Context, id string) error
}

type userService struct {
    userRepo repositories.UserRepository
    hasher   auth.PasswordHasher
}

func NewUserService(userRepo repositories.UserRepository, hasher auth.PasswordHasher) UserService {
    return &userService{
        userRepo: userRepo,
        hasher:   hasher,
    }
}

func (s *userService) CreateUser(ctx context.Context, req CreateUserRequest) (*models.User, error) {
    // Check if user already exists
    existingUser, err := s.userRepo.GetByEmail(ctx, req.Email)
    if err == nil && existingUser != nil {
        return nil, ErrUserAlreadyExists
    }
    
    // Hash password
    hashedPassword, err := s.hasher.HashPassword(req.Password)
    if err != nil {
        return nil, err
    }
    
    // Create user
    user := &models.User{
        Email:        req.Email,
        Name:         req.Name,
        PasswordHash: hashedPassword,
    }
    
    return s.userRepo.Create(ctx, user)
}
```

### **Repository Layer**
```go
// internal/repositories/users.go
package repositories

import (
    "context"
    "database/sql"
    "{{PROJECT_NAME}}/internal/models"
)

type UserRepository interface {
    Create(ctx context.Context, user *models.User) (*models.User, error)
    GetByID(ctx context.Context, id string) (*models.User, error)
    GetByEmail(ctx context.Context, email string) (*models.User, error)
    Update(ctx context.Context, user *models.User) (*models.User, error)
    Delete(ctx context.Context, id string) error
}

type userRepository struct {
    db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
    return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *models.User) (*models.User, error) {
    query := `
        INSERT INTO users (email, name, password_hash, created_at, updated_at)
        VALUES ($1, $2, $3, NOW(), NOW())
        RETURNING id, created_at, updated_at
    `
    
    err := r.db.QueryRowContext(ctx, query, 
        user.Email, user.Name, user.PasswordHash,
    ).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
    
    if err != nil {
        return nil, err
    }
    
    return user, nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
    query := `
        SELECT id, email, name, password_hash, created_at, updated_at
        FROM users
        WHERE email = $1
    `
    
    user := &models.User{}
    err := r.db.QueryRowContext(ctx, query, email).Scan(
        &user.ID, &user.Email, &user.Name, &user.PasswordHash,
        &user.CreatedAt, &user.UpdatedAt,
    )
    
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, err
    }
    
    return user, nil
}
```

## 🎯 Tier Mapping

| Tier | Features | Complexity | Database | Testing |
|------|----------|------------|----------|---------|
| **MVP** | Basic CRUD, simple handlers | Minimal | SQLite | Basic tests |
| **CORE** | Full auth, middleware, services | Modular | PostgreSQL | Unit + Integration |
| **FULL** | Background jobs, monitoring | Enterprise | PostgreSQL + Redis | All tests + E2E |

## 📦 Package Organization

**Core Dependencies** (all tiers):
- `chi` or `fiber` - HTTP router
- `sqlx` or `gorm` - Database ORM
- `godotenv` - Environment variables

**CORE Tier Additions**:
- `golang-jwt/jwt` - JWT authentication
- `bcrypt` - Password hashing
- `go-playground/validator` - Validation
- `testify` - Testing framework
- `stretchr/testify` - Assertions and mocks

**FULL Tier Additions**:
- `redis/go-redis/v9` - Redis client
- `prometheus/client_golang` - Metrics
- `opentelemetry-go` - Distributed tracing
- `gorm.io/gorm` - Advanced ORM
- `go-redis/cache` - Caching
- `robfig/cron` - Job scheduling

## 🔧 Configuration Pattern

### **Configuration Structure**
```go
// internal/app/config.go
package app

import (
    "os"
    "github.com/joho/godotenv"
)

type Config struct {
    Port         string
    DatabaseURL  string
    RedisURL     string
    JWTSecret    string
    Environment  string
    LogLevel     string
}

func LoadConfig() *Config {
    godotenv.Load()
    
    return &Config{
        Port:        getEnv("PORT", "8080"),
        DatabaseURL: getEnv("DATABASE_URL", "postgres://localhost/{{PROJECT_NAME}}?sslmode=disable"),
        RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379"),
        JWTSecret:   getEnv("JWT_SECRET", "your-secret-key"),
        Environment: getEnv("ENVIRONMENT", "development"),
        LogLevel:    getEnv("LOG_LEVEL", "info"),
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
```

### **Application Setup**
```go
// internal/app/app.go
package app

import (
    "log"
    "net/http"
    "{{PROJECT_NAME}}/internal/handlers"
    "{{PROJECT_NAME}}/internal/services"
    "{{PROJECT_NAME}}/internal/repositories"
    "{{PROJECT_NAME}}/pkg/middleware"
    "github.com/go-chi/chi/v5"
)

type App struct {
    config *Config
    router *chi.Mux
}

func New(cfg *Config, db *sql.DB) *App {
    // Initialize repositories
    userRepo := repositories.NewUserRepository(db)
    
    // Initialize services
    userService := services.NewUserService(userRepo, auth.NewBcryptHasher())
    
    // Initialize handlers
    userHandler := handlers.NewUserHandler(userService)
    
    // Setup router
    r := chi.NewRouter()
    
    // Middleware
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)
    r.Use(middleware.CORS)
    
    // Routes
    r.Route("/api/v1", func(r chi.Router) {
        r.Route("/users", func(r chi.Router) {
            r.Post("/", userHandler.CreateUser)
            r.Get("/{id}", userHandler.GetUserByID)
            r.Put("/{id}", userHandler.UpdateUser)
            r.Delete("/{id}", userHandler.DeleteUser)
        })
    })
    
    return &App{
        config: cfg,
        router: r,
    }
}

func (a *App) Run() error {
    addr := ":" + a.config.Port
    log.Printf("Server starting on %s", addr)
    return http.ListenAndServe(addr, a.router)
}
```

## 🧪 Testing Structure

### **Unit Testing**
```go
// tests/unit/services/users_test.go
package services_test

import (
    "context"
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "{{PROJECT_NAME}}/internal/services"
    "{{PROJECT_NAME}}/internal/models"
)

// Mock repository
type MockUserRepository struct {
    mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) (*models.User, error) {
    args := m.Called(ctx, user)
    return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
    args := m.Called(ctx, email)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*models.User), args.Error(1)
}

func TestUserService_CreateUser(t *testing.T) {
    // Setup
    mockRepo := new(MockUserRepository)
    mockHasher := new(MockPasswordHasher)
    service := services.NewUserService(mockRepo, mockHasher)
    
    req := services.CreateUserRequest{
        Email:    "test@example.com",
        Name:     "Test User",
        Password: "password123",
    }
    
    // Mock expectations
    mockRepo.On("GetByEmail", mock.Anything, req.Email).Return(nil, nil)
    mockHasher.On("HashPassword", req.Password).Return("hashed_password", nil)
    mockRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.User")).Return(&models.User{
        ID:    "1",
        Email: req.Email,
        Name:  req.Name,
    }, nil)
    
    // Execute
    user, err := service.CreateUser(context.Background(), req)
    
    // Assert
    assert.NoError(t, err)
    assert.Equal(t, req.Email, user.Email)
    assert.Equal(t, req.Name, user.Name)
    mockRepo.AssertExpectations(t)
}
```

### **Integration Testing**
```go
// tests/integration/api/users_test.go
package integration_test

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "{{PROJECT_NAME}}/internal/app"
)

func TestCreateUserIntegration(t *testing.T) {
    // Setup test database
    db := setupTestDB(t)
    defer cleanupTestDB(t, db)
    
    // Setup application
    cfg := &app.Config{
        DatabaseURL: getTestDatabaseURL(),
    }
    application := app.New(cfg, db)
    
    // Test data
    reqBody := map[string]interface{}{
        "email":    "test@example.com",
        "name":     "Test User",
        "password": "password123",
    }
    
    jsonData, _ := json.Marshal(reqBody)
    req := httptest.NewRequest("POST", "/api/v1/users", bytes.NewBuffer(jsonData))
    req.Header.Set("Content-Type", "application/json")
    
    w := httptest.NewRecorder()
    application.router.ServeHTTP(w, req)
    
    // Assertions
    assert.Equal(t, http.StatusCreated, w.Code)
    
    var response map[string]interface{}
    json.Unmarshal(w.Body.Bytes(), &response)
    assert.Equal(t, "test@example.com", response["email"])
    assert.Equal(t, "Test User", response["name"])
}
```

---

**Go Version**: [GO_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
