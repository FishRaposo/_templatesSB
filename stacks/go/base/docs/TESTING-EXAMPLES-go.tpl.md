# Universal Template System - Go Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: go
# Category: template

# Go Testing Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Go

## 🧪 Go Testing Strategy Overview

Go testing follows **table-driven testing patterns**, **benchmarking for performance**, **integration testing with testcontainers**, and **concurrent testing for goroutines**. Each tier builds upon the previous one with additional testing strategies, tools, and coverage requirements optimized for Go's strengths in backend services and CLI applications.

## 📊 Tier-Specific Testing Requirements

| Tier | Unit Tests | Integration Tests | Benchmarks | Coverage | Tools |
|------|------------|-------------------|------------|----------|-------|
| **MVP** | Basic unit tests | Manual testing | None | 70%+ | testing package |
| **CORE** | Table-driven tests | Database tests | Basic benchmarks | 85%+ | testify, gomock, testcontainers |
| **FULL** | Comprehensive tests | Full integration | Performance tests | 90%+ | All tools + custom utilities |

## 🔧 Testing Configuration

### **MVP Tier - Basic Testing Setup**

```go
// go.mod - Simple testing dependencies
module github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}

go 1.21

require (
    github.com/stretchr/testify v1.8.4
)
```

```go
// internal/server/server_test.go - Basic unit tests
package server

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func TestServer_GetUsers(t *testing.T) {
    server := NewServer()
    
    req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
    w := httptest.NewRecorder()
    
    server.handleUsers(w, req)
    
    if w.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w.Code)
    }
    
    var users []User
    if err := json.NewDecoder(w.Body).Decode(&users); err != nil {
        t.Errorf("Failed to decode response: %v", err)
    }
    
    if len(users) != 2 {
        t.Errorf("Expected 2 users, got %d", len(users))
    }
}

func TestServer_CreateUser(t *testing.T) {
    server := NewServer()
    
    user := User{
        Name:  "Test User",
        Email: "test@example.com",
    }
    
    body, _ := json.Marshal(user)
    req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    w := httptest.NewRecorder()
    
    server.handleUsers(w, req)
    
    if w.Code != http.StatusCreated {
        t.Errorf("Expected status 201, got %d", w.Code)
    }
    
    var createdUser User
    if err := json.NewDecoder(w.Body).Decode(&createdUser); err != nil {
        t.Errorf("Failed to decode response: %v", err)
    }
    
    if createdUser.Name != user.Name {
        t.Errorf("Expected name %s, got %s", user.Name, createdUser.Name)
    }
    
    if createdUser.Email != user.Email {
        t.Errorf("Expected email %s, got %s", user.Email, createdUser.Email)
    }
}

func TestServer_GetUser(t *testing.T) {
    server := NewServer()
    
    req := httptest.NewRequest(http.MethodGet, "/api/users/1", nil)
    w := httptest.NewRecorder()
    
    server.handleUser(w, req, 1)
    
    if w.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w.Code)
    }
    
    var user User
    if err := json.NewDecoder(w.Body).Decode(&user); err != nil {
        t.Errorf("Failed to decode response: %v", err)
    }
    
    if user.ID != 1 {
        t.Errorf("Expected user ID 1, got %d", user.ID)
    }
}

func TestServer_GetUserNotFound(t *testing.T) {
    server := NewServer()
    
    req := httptest.NewRequest(http.MethodGet, "/api/users/999", nil)
    w := httptest.NewRecorder()
    
    server.handleUser(w, req, 999)
    
    if w.Code != http.StatusNotFound {
        t.Errorf("Expected status 404, got %d", w.Code)
    }
}

func TestServer_UpdateUser(t *testing.T) {
    server := NewServer()
    
    updatedUser := User{
        Name:  "Updated User",
        Email: "updated@example.com",
    }
    
    body, _ := json.Marshal(updatedUser)
    req := httptest.NewRequest(http.MethodPut, "/api/users/1", bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    w := httptest.NewRecorder()
    
    server.handleUser(w, req, 1)
    
    if w.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", w.Code)
    }
    
    var user User
    if err := json.NewDecoder(w.Body).Decode(&user); err != nil {
        t.Errorf("Failed to decode response: %v", err)
    }
    
    if user.Name != updatedUser.Name {
        t.Errorf("Expected name %s, got %s", updatedUser.Name, user.Name)
    }
}

func TestServer_DeleteUser(t *testing.T) {
    server := NewServer()
    
    req := httptest.NewRequest(http.MethodDelete, "/api/users/1", nil)
    w := httptest.NewRecorder()
    
    server.handleUser(w, req, 1)
    
    if w.Code != http.StatusNoContent {
        t.Errorf("Expected status 204, got %d", w.Code)
    }
    
    // Verify user is deleted
    req = httptest.NewRequest(http.MethodGet, "/api/users/1", nil)
    w = httptest.NewRecorder()
    
    server.handleUser(w, req, 1)
    
    if w.Code != http.StatusNotFound {
        t.Errorf("Expected status 404 after delete, got %d", w.Code)
    }
}

// Benchmark tests
func BenchmarkServer_GetUsers(b *testing.B) {
    server := NewServer()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
        w := httptest.NewRecorder()
        server.handleUsers(w, req)
    }
}

func BenchmarkServer_CreateUser(b *testing.B) {
    server := NewServer()
    user := User{Name: "Test User", Email: "test@example.com"}
    body, _ := json.Marshal(user)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewBuffer(body))
        req.Header.Set("Content-Type", "application/json")
        w := httptest.NewRecorder()
        server.handleUsers(w, req)
    }
}
```

### **CORE Tier - Production Testing Setup**

```go
// go.mod - Production testing dependencies
module github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}

go 1.21

require (
    github.com/stretchr/testify v1.8.4
    github.com/golang/mock v1.6.0
    github.com/testcontainers/testcontainers-go v0.25.0
    github.com/DATA-DOG/go-sqlmock v1.5.0
    github.com/golang-migrate/migrate/v4 v4.16.2
    go.uber.org/zap v1.25.0
    github.com/spf13/viper v1.16.0
)

require (
    // Additional dependencies
)
```

```go
// internal/services/user_service_test.go - Table-driven tests with mocks
package services

import (
    "context"
    "errors"
    "testing"
    "time"
    
    "github.com/golang/mock/gomock"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/dto"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/models"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/repositories/mocks"
)

func TestUserService_GetUserByID(t *testing.T) {
    tests := []struct {
        name          string
        userID        uint
        mockSetup     func(repo *mocks.MockUserRepository)
        expectedUser  *models.User
        expectedError error
    }{
        {
            name:   "success - user found",
            userID: 1,
            mockSetup: func(repo *mocks.MockUserRepository) {
                user := &models.User{
                    ID:        1,
                    Name:      "John Doe",
                    Email:     "john@example.com",
                    CreatedAt: time.Now(),
                }
                repo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(user, nil)
            },
            expectedUser: &models.User{
                ID:    1,
                Name:  "John Doe",
                Email: "john@example.com",
            },
            expectedError: nil,
        },
        {
            name:   "error - user not found",
            userID: 999,
            mockSetup: func(repo *mocks.MockUserRepository) {
                repo.EXPECT().GetByID(gomock.Any(), uint(999)).Return(nil, ErrUserNotFound)
            },
            expectedUser:  nil,
            expectedError: ErrUserNotFound,
        },
        {
            name:   "error - database error",
            userID: 1,
            mockSetup: func(repo *mocks.MockUserRepository) {
                repo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(nil, errors.New("database error"))
            },
            expectedUser:  nil,
            expectedError: errors.New("database error"),
        },
        {
            name:   "error - invalid user ID",
            userID: 0,
            mockSetup: func(repo *mocks.MockUserRepository) {
                // No mock setup - should return validation error
            },
            expectedUser:  nil,
            expectedError: ErrInvalidUserID,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ctrl := gomock.NewController(t)
            defer ctrl.Finish()
            
            mockRepo := mocks.NewMockUserRepository(ctrl)
            tt.mockSetup(mockRepo)
            
            service := NewUserService(mockRepo)
            
            user, err := service.GetUserByID(context.Background(), tt.userID)
            
            if tt.expectedError != nil {
                assert.Error(t, err)
                assert.Equal(t, tt.expectedError, err)
                assert.Nil(t, user)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expectedUser.ID, user.ID)
                assert.Equal(t, tt.expectedUser.Name, user.Name)
                assert.Equal(t, tt.expectedUser.Email, user.Email)
            }
        })
    }
}

func TestUserService_CreateUser(t *testing.T) {
    tests := []struct {
        name          string
        request       *dto.CreateUserRequest
        mockSetup     func(repo *mocks.MockUserRepository)
        expectedUser  *models.User
        expectedError error
    }{
        {
            name: "success - valid user",
            request: &dto.CreateUserRequest{
                Name:     "John Doe",
                Email:    "john@example.com",
                Password: "password123",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                repo.EXPECT().GetByEmail(gomock.Any(), "john@example.com").Return(nil, ErrUserNotFound)
                repo.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, user *models.User) error {
                    user.ID = 1
                    user.CreatedAt = time.Now()
                    return nil
                })
            },
            expectedUser: &models.User{
                ID:    1,
                Name:  "John Doe",
                Email: "john@example.com",
            },
            expectedError: nil,
        },
        {
            name: "error - user already exists",
            request: &dto.CreateUserRequest{
                Name:     "John Doe",
                Email:    "john@example.com",
                Password: "password123",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                existingUser := &models.User{
                    ID:    1,
                    Name:  "John Doe",
                    Email: "john@example.com",
                }
                repo.EXPECT().GetByEmail(gomock.Any(), "john@example.com").Return(existingUser, nil)
            },
            expectedUser:  nil,
            expectedError: ErrUserAlreadyExists,
        },
        {
            name: "error - invalid email format",
            request: &dto.CreateUserRequest{
                Name:     "John Doe",
                Email:    "invalid-email",
                Password: "password123",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                // No mock setup - should return validation error
            },
            expectedUser:  nil,
            expectedError: ErrInvalidEmail,
        },
        {
            name: "error - weak password",
            request: &dto.CreateUserRequest{
                Name:     "John Doe",
                Email:    "john@example.com",
                Password: "123",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                // No mock setup - should return validation error
            },
            expectedUser:  nil,
            expectedError: ErrWeakPassword,
        },
        {
            name: "error - database error on create",
            request: &dto.CreateUserRequest{
                Name:     "John Doe",
                Email:    "john@example.com",
                Password: "password123",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                repo.EXPECT().GetByEmail(gomock.Any(), "john@example.com").Return(nil, ErrUserNotFound)
                repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(errors.New("database error"))
            },
            expectedUser:  nil,
            expectedError: errors.New("database error"),
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ctrl := gomock.NewController(t)
            defer ctrl.Finish()
            
            mockRepo := mocks.NewMockUserRepository(ctrl)
            tt.mockSetup(mockRepo)
            
            service := NewUserService(mockRepo)
            
            user, err := service.CreateUser(context.Background(), tt.request)
            
            if tt.expectedError != nil {
                assert.Error(t, err)
                assert.Equal(t, tt.expectedError, err)
                assert.Nil(t, user)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expectedUser.ID, user.ID)
                assert.Equal(t, tt.expectedUser.Name, user.Name)
                assert.Equal(t, tt.expectedUser.Email, user.Email)
                assert.NotEmpty(t, user.PasswordHash)
                assert.NotEmpty(t, user.CreatedAt)
            }
        })
    }
}

func TestUserService_UpdateUser(t *testing.T) {
    tests := []struct {
        name          string
        userID        uint
        request       *dto.UpdateUserRequest
        mockSetup     func(repo *mocks.MockUserRepository)
        expectedUser  *models.User
        expectedError error
    }{
        {
            name:   "success - valid update",
            userID: 1,
            request: &dto.UpdateUserRequest{
                Name:  "Updated Name",
                Email: "updated@example.com",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                existingUser := &models.User{
                    ID:        1,
                    Name:      "John Doe",
                    Email:     "john@example.com",
                    CreatedAt: time.Now(),
                }
                repo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(existingUser, nil)
                repo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
            },
            expectedUser: &models.User{
                ID:    1,
                Name:  "Updated Name",
                Email: "updated@example.com",
            },
            expectedError: nil,
        },
        {
            name:   "error - user not found",
            userID: 999,
            request: &dto.UpdateUserRequest{
                Name:  "Updated Name",
                Email: "updated@example.com",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                repo.EXPECT().GetByID(gomock.Any(), uint(999)).Return(nil, ErrUserNotFound)
            },
            expectedUser:  nil,
            expectedError: ErrUserNotFound,
        },
        {
            name:   "error - invalid user ID",
            userID: 0,
            request: &dto.UpdateUserRequest{
                Name:  "Updated Name",
                Email: "updated@example.com",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                // No mock setup - should return validation error
            },
            expectedUser:  nil,
            expectedError: ErrInvalidUserID,
        },
        {
            name:   "error - database error on update",
            userID: 1,
            request: &dto.UpdateUserRequest{
                Name:  "Updated Name",
                Email: "updated@example.com",
            },
            mockSetup: func(repo *mocks.MockUserRepository) {
                existingUser := &models.User{
                    ID:        1,
                    Name:      "John Doe",
                    Email:     "john@example.com",
                    CreatedAt: time.Now(),
                }
                repo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(existingUser, nil)
                repo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(errors.New("database error"))
            },
            expectedUser:  nil,
            expectedError: errors.New("database error"),
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ctrl := gomock.NewController(t)
            defer ctrl.Finish()
            
            mockRepo := mocks.NewMockUserRepository(ctrl)
            tt.mockSetup(mockRepo)
            
            service := NewUserService(mockRepo)
            
            user, err := service.UpdateUser(context.Background(), tt.userID, tt.request)
            
            if tt.expectedError != nil {
                assert.Error(t, err)
                assert.Equal(t, tt.expectedError, err)
                assert.Nil(t, user)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expectedUser.ID, user.ID)
                assert.Equal(t, tt.expectedUser.Name, user.Name)
                assert.Equal(t, tt.expectedUser.Email, user.Email)
            }
        })
    }
}

// Integration tests with testcontainers
func TestUserService_Integration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }
    
    // Setup test database container
    ctx := context.Background()
    req := testcontainers.ContainerRequest{
        Image:        "postgres:15-alpine",
        ExposedPorts: []string{"5432/tcp"},
        Env: map[string]string{
            "POSTGRES_DB":       "testdb",
            "POSTGRES_USER":     "testuser",
            "POSTGRES_PASSWORD": "testpass",
        },
        WaitingFor: wait.ForLog("database system is ready to accept connections"),
    }
    
    container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
        ContainerRequest: req,
        Started:          true,
    })
    require.NoError(t, err)
    defer container.Terminate(ctx)
    
    // Get database connection details
    host, err := container.Host(ctx)
    require.NoError(t, err)
    
    port, err := container.MappedPort(ctx, "5432")
    require.NoError(t, err)
    
    // Connect to test database
    dsn := fmt.Sprintf("postgres://testuser:testpass@%s:%s/testdb?sslmode=disable", host, port.Port())
    db, err := sqlx.Connect("postgres", dsn)
    require.NoError(t, err)
    defer db.Close()
    
    // Run migrations
    err = runTestMigrations(db)
    require.NoError(t, err)
    
    // Setup repository and service
    repo := repositories.NewUserRepository(db)
    service := NewUserService(repo)
    
    // Test create user
    req := &dto.CreateUserRequest{
        Name:     "Integration Test User",
        Email:    "integration@example.com",
        Password: "password123",
    }
    
    user, err := service.CreateUser(ctx, req)
    require.NoError(t, err)
    assert.NotZero(t, user.ID)
    assert.Equal(t, req.Name, user.Name)
    assert.Equal(t, req.Email, user.Email)
    
    // Test get user
    retrievedUser, err := service.GetUserByID(ctx, user.ID)
    require.NoError(t, err)
    assert.Equal(t, user.ID, retrievedUser.ID)
    assert.Equal(t, user.Name, retrievedUser.Name)
    assert.Equal(t, user.Email, retrievedUser.Email)
    
    // Test update user
    updateReq := &dto.UpdateUserRequest{
        Name:  "Updated Integration User",
        Email: "updated@example.com",
    }
    
    updatedUser, err := service.UpdateUser(ctx, user.ID, updateReq)
    require.NoError(t, err)
    assert.Equal(t, updateReq.Name, updatedUser.Name)
    assert.Equal(t, updateReq.Email, updatedUser.Email)
    
    // Test delete user
    err = service.DeleteUser(ctx, user.ID)
    require.NoError(t, err)
    
    // Verify user is deleted
    _, err = service.GetUserByID(ctx, user.ID)
    assert.Equal(t, ErrUserNotFound, err)
}

// Benchmark tests
func BenchmarkUserService_CreateUser(b *testing.B) {
    ctrl := gomock.NewController(b)
    defer ctrl.Finish()
    
    mockRepo := mocks.NewMockUserRepository(ctrl)
    mockRepo.EXPECT().GetByEmail(gomock.Any(), gomock.Any()).Return(nil, ErrUserNotFound).AnyTimes()
    mockRepo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
    
    service := NewUserService(mockRepo)
    
    req := &dto.CreateUserRequest{
        Name:     "Benchmark User",
        Email:    "benchmark@example.com",
        Password: "password123",
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := service.CreateUser(context.Background(), req)
        if err != nil {
            b.Fatalf("CreateUser failed: %v", err)
        }
    }
}

func BenchmarkUserService_GetUserByID(b *testing.B) {
    ctrl := gomock.NewController(b)
    defer ctrl.Finish()
    
    mockRepo := mocks.NewMockUserRepository(ctrl)
    user := &models.User{
        ID:    1,
        Name:  "Test User",
        Email: "test@example.com",
    }
    mockRepo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(user, nil).AnyTimes()
    
    service := NewUserService(mockRepo)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := service.GetUserByID(context.Background(), 1)
        if err != nil {
            b.Fatalf("GetUserByID failed: %v", err)
        }
    }
}

// Helper functions
func runTestMigrations(db *sqlx.DB) error {
    migrations := []string{
        `CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );`,
        `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
        `CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);`,
    }
    
    for _, migration := range migrations {
        if _, err := db.Exec(migration); err != nil {
            return fmt.Errorf("failed to run migration: %w", err)
        }
    }
    
    return nil
}
```

### **FULL Tier - Enterprise Testing Setup**

```go
// go.mod - Enterprise testing dependencies
module github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}

go 1.21

require (
    // Core testing
    github.com/stretchr/testify v1.8.4
    github.com/golang/mock v1.6.0
    github.com/testcontainers/testcontainers-go v0.25.0
    github.com/DATA-DOG/go-sqlmock v1.5.0
    
    // Performance testing
    github.com/franela/goblin v0.1.0
    github.com/onsi/ginkgo/v2 v2.11.0
    github.com/onsi/gomega v1.27.8
    
    // Load testing
    github.com/tsenart/vegeta v12.11.3+incompatible
    
    // Property testing
    github.com/leanovate/gopter v0.2.9
    
    // Fuzzing
    golang.org/x/tools v0.12.0
    
    // Coverage tools
    github.com/wadey/gocovmerge v0.0.0-20160331181806-e46476ab3964
    
    // Testing utilities
    github.com/gavv/httpexpect/v2 v2.15.0
    github.com/stretchr/testify/assert v1.8.4
    github.com/stretchr/testify/require v1.8.4
    github.com/stretchr/testify/mock v1.8.4
    github.com/stretchr/testify/suite v1.8.4
)

require (
    // Additional dependencies
)
```

```go
// internal/services/user_service_test.go - Comprehensive enterprise testing
package services

import (
    "context"
    "fmt"
    "runtime"
    "sync"
    "testing"
    "time"
    
    "github.com/golang/mock/gomock"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/suite"
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/wait"
    "go.uber.org/zap/zaptest"
    
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/config"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/database"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/dto"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/models"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/repositories"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/repositories/mocks"
)

// Test suite for comprehensive testing
type UserServiceTestSuite struct {
    suite.Suite
    container testcontainers.Container
    db        *sqlx.DB
    service   UserService
    repo      repositories.UserRepository
    logger    *zap.Logger
}

func (suite *UserServiceTestSuite) SetupSuite() {
    // Setup logger for testing
    suite.logger = zaptest.NewLogger(suite.T())
    
    // Setup PostgreSQL test container
    ctx := context.Background()
    req := testcontainers.ContainerRequest{
        Image:        "postgres:15-alpine",
        ExposedPorts: []string{"5432/tcp"},
        Env: map[string]string{
            "POSTGRES_DB":       "testdb",
            "POSTGRES_USER":     "testuser",
            "POSTGRES_PASSWORD": "testpass",
        },
        WaitingFor: wait.ForLog("database system is ready to accept connections"),
    }
    
    container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
        ContainerRequest: req,
        Started:          true,
    })
    suite.Require().NoError(err)
    
    suite.container = container
    
    // Get database connection details
    host, err := container.Host(ctx)
    suite.Require().NoError(err)
    
    port, err := container.MappedPort(ctx, "5432")
    suite.Require().NoError(err)
    
    // Connect to test database
    dsn := fmt.Sprintf("postgres://testuser:testpass@%s:%s/testdb?sslmode=disable", host, port.Port())
    db, err := sqlx.Connect("postgres", dsn)
    suite.Require().NoError(err)
    
    suite.db = db
    
    // Run migrations
    err = runEnterpriseTestMigrations(db)
    suite.Require().NoError(err)
    
    // Setup repository and service
    suite.repo = repositories.NewUserRepository(db)
    suite.service = NewUserService(suite.repo)
}

func (suite *UserServiceTestSuite) TearDownSuite() {
    if suite.db != nil {
        suite.db.Close()
    }
    if suite.container != nil {
        ctx := context.Background()
        suite.container.Terminate(ctx)
    }
}

func (suite *UserServiceTestSuite) SetupTest() {
    // Clean up database before each test
    _, err := suite.db.Exec("DELETE FROM users")
    suite.Require().NoError(err)
}

func (suite *UserServiceTestSuite) TestCreateUser_Success() {
    req := &dto.CreateUserRequest{
        Name:     "Test User",
        Email:    "test@example.com",
        Password: "password123",
    }
    
    user, err := suite.service.CreateUser(context.Background(), req)
    
    suite.NoError(err)
    suite.NotZero(user.ID)
    suite.Equal(req.Name, user.Name)
    suite.Equal(req.Email, user.Email)
    suite.NotEmpty(user.PasswordHash)
    suite.NotZero(user.CreatedAt)
}

func (suite *UserServiceTestSuite) TestCreateUser_DuplicateEmail() {
    req := &dto.CreateUserRequest{
        Name:     "Test User",
        Email:    "test@example.com",
        Password: "password123",
    }
    
    // Create first user
    _, err := suite.service.CreateUser(context.Background(), req)
    suite.NoError(err)
    
    // Try to create user with same email
    _, err = suite.service.CreateUser(context.Background(), req)
    
    suite.Error(err)
    suite.Equal(ErrUserAlreadyExists, err)
}

func (suite *UserServiceTestSuite) TestCreateUser_BusinessValidation() {
    tests := []struct {
        name     string
        request  *dto.CreateUserRequest
        expected error
    }{
        {
            name: "invalid email format",
            request: &dto.CreateUserRequest{
                Name:     "Test User",
                Email:    "invalid-email",
                Password: "password123",
            },
            expected: ErrInvalidEmail,
        },
        {
            name: "weak password",
            request: &dto.CreateUserRequest{
                Name:     "Test User",
                Email:    "test@example.com",
                Password: "123",
            },
            expected: ErrWeakPassword,
        },
        {
            name: "empty name",
            request: &dto.CreateUserRequest{
                Name:     "",
                Email:    "test@example.com",
                Password: "password123",
            },
            expected: ErrInvalidName,
        },
        {
            name: "restricted email domain",
            request: &dto.CreateUserRequest{
                Name:     "Test User",
                Email:    "test@tempmail.com",
                Password: "password123",
            },
            expected: ErrRestrictedEmailDomain,
        },
    }
    
    for _, tt := range tests {
        suite.Run(tt.name, func() {
            _, err := suite.service.CreateUser(context.Background(), tt.request)
            suite.Error(err)
            suite.Equal(tt.expected, err)
        })
    }
}

func (suite *UserServiceTestSuite) TestGetUserByID_Success() {
    // Create user first
    req := &dto.CreateUserRequest{
        Name:     "Test User",
        Email:    "test@example.com",
        Password: "password123",
    }
    
    createdUser, err := suite.service.CreateUser(context.Background(), req)
    suite.NoError(err)
    
    // Get user by ID
    user, err := suite.service.GetUserByID(context.Background(), createdUser.ID)
    
    suite.NoError(err)
    suite.Equal(createdUser.ID, user.ID)
    suite.Equal(createdUser.Name, user.Name)
    suite.Equal(createdUser.Email, user.Email)
}

func (suite *UserServiceTestSuite) TestUpdateUser_Success() {
    // Create user first
    req := &dto.CreateUserRequest{
        Name:     "Test User",
        Email:    "test@example.com",
        Password: "password123",
    }
    
    createdUser, err := suite.service.CreateUser(context.Background(), req)
    suite.NoError(err)
    
    // Update user
    updateReq := &dto.UpdateUserRequest{
        Name:  "Updated User",
        Email: "updated@example.com",
    }
    
    updatedUser, err := suite.service.UpdateUser(context.Background(), createdUser.ID, updateReq)
    
    suite.NoError(err)
    suite.Equal(updateReq.Name, updatedUser.Name)
    suite.Equal(updateReq.Email, updatedUser.Email)
    suite.Equal(createdUser.ID, updatedUser.ID)
}

func (suite *UserServiceTestSuite) TestDeleteUser_Success() {
    // Create user first
    req := &dto.CreateUserRequest{
        Name:     "Test User",
        Email:    "test@example.com",
        Password: "password123",
    }
    
    createdUser, err := suite.service.CreateUser(context.Background(), req)
    suite.NoError(err)
    
    // Delete user
    err = suite.service.DeleteUser(context.Background(), createdUser.ID)
    suite.NoError(err)
    
    // Verify user is deleted
    _, err = suite.service.GetUserByID(context.Background(), createdUser.ID)
    suite.Error(err)
    suite.Equal(ErrUserNotFound, err)
}

func (suite *UserServiceTestSuite) TestGetUsersWithPagination_Success() {
    // Create test users
    for i := 1; i <= 25; i++ {
        req := &dto.CreateUserRequest{
            Name:     fmt.Sprintf("User %d", i),
            Email:    fmt.Sprintf("user%d@example.com", i),
            Password: "password123",
        }
        _, err := suite.service.CreateUser(context.Background(), req)
        suite.NoError(err)
    }
    
    // Test first page
    users, total, err := suite.service.GetUsers(context.Background(), 1, 10)
    
    suite.NoError(err)
    suite.Len(users, 10)
    suite.Equal(25, total)
    suite.Equal("User 25", users[0].Name) // Should be ordered by created_at DESC
}

func (suite *UserServiceTestSuite) TestGetUsersWithFilters_Success() {
    // Create test users with different roles
    users := []struct {
        name  string
        email string
        role  string
    }{
        {"Admin User", "admin@example.com", "admin"},
        {"Regular User", "user@example.com", "user"},
        {"Manager User", "manager@example.com", "manager"},
        {"Another Admin", "admin2@example.com", "admin"},
    }
    
    for _, u := range users {
        req := &dto.CreateUserRequest{
            Name:     u.name,
            Email:    u.email,
            Password: "password123",
            Role:     u.role,
        }
        _, err := suite.service.CreateUser(context.Background(), req)
        suite.NoError(err)
    }
    
    // Test filter by role
    filterReq := &dto.UserFilterRequest{
        Role: "admin",
        Page: 1,
        Limit: 10,
    }
    
    users, total, err := suite.service.GetUsersWithFilters(context.Background(), filterReq)
    
    suite.NoError(err)
    suite.Len(users, 2)
    suite.Equal(2, total)
    for _, user := range users {
        suite.Equal("admin", user.Role)
    }
}

// Performance tests
func (suite *UserServiceTestSuite) TestPerformance_BulkCreate() {
    start := time.Now()
    
    for i := 1; i <= 1000; i++ {
        req := &dto.CreateUserRequest{
            Name:     fmt.Sprintf("Perf User %d", i),
            Email:    fmt.Sprintf("perfuser%d@example.com", i),
            Password: "password123",
        }
        _, err := suite.service.CreateUser(context.Background(), req)
        suite.NoError(err)
    }
    
    duration := time.Since(start)
    suite.Less(duration, 10*time.Second, "Bulk create should complete within 10 seconds")
    
    fmt.Printf("Created 1000 users in %v\n", duration)
}

func (suite *UserServiceTestSuite) TestPerformance_Pagination() {
    // Create 10,000 users
    for i := 1; i <= 10000; i++ {
        req := &dto.CreateUserRequest{
            Name:     fmt.Sprintf("User %d", i),
            Email:    fmt.Sprintf("user%d@example.com", i),
            Password: "password123",
        }
        _, err := suite.service.CreateUser(context.Background(), req)
        suite.NoError(err)
    }
    
    start := time.Now()
    
    // Test pagination performance
    for page := 1; page <= 100; page++ {
        _, _, err := suite.service.GetUsers(context.Background(), page, 100)
        suite.NoError(err)
    }
    
    duration := time.Since(start)
    suite.Less(duration, 5*time.Second, "Pagination should complete within 5 seconds")
    
    fmt.Printf("Paginated 10,000 users in %v\n", duration)
}

// Concurrent tests
func (suite *UserServiceTestSuite) TestConcurrent_CreateUsers() {
    const numGoroutines = 100
    const numUsersPerGoroutine = 10
    
    var wg sync.WaitGroup
    errors := make(chan error, numGoroutines)
    
    for i := 0; i < numGoroutines; i++ {
        wg.Add(1)
        go func(goroutineID int) {
            defer wg.Done()
            
            for j := 1; j <= numUsersPerGoroutine; j++ {
                req := &dto.CreateUserRequest{
                    Name:     fmt.Sprintf("Concurrent User %d-%d", goroutineID, j),
                    Email:    fmt.Sprintf("concurrent%d-%d@example.com", goroutineID, j),
                    Password: "password123",
                }
                
                _, err := suite.service.CreateUser(context.Background(), req)
                if err != nil {
                    errors <- err
                    return
                }
            }
        }(i)
    }
    
    wg.Wait()
    close(errors)
    
    // Check for errors
    for err := range errors {
        suite.NoError(err)
    }
    
    // Verify all users were created
    users, total, err := suite.service.GetUsers(context.Background(), 1, 1000)
    suite.NoError(err)
    suite.Equal(numGoroutines*numUsersPerGoroutine, total)
    suite.Len(users, numGoroutines*numUsersPerGoroutine)
}

func (suite *UserServiceTestSuite) TestConcurrent_ReadWriteOperations() {
    // Create initial users
    for i := 1; i <= 100; i++ {
        req := &dto.CreateUserRequest{
            Name:     fmt.Sprintf("Initial User %d", i),
            Email:    fmt.Sprintf("initial%d@example.com", i),
            Password: "password123",
        }
        _, err := suite.service.CreateUser(context.Background(), req)
        suite.NoError(err)
    }
    
    const numReaders = 50
    const numWriters = 20
    
    var wg sync.WaitGroup
    errors := make(chan error, numReaders+numWriters)
    
    // Start readers
    for i := 0; i < numReaders; i++ {
        wg.Add(1)
        go func(readerID int) {
            defer wg.Done()
            
            for j := 1; j <= 100; j++ {
                userID := uint((readerID*100 + j) % 100) // Cycle through user IDs
                _, err := suite.service.GetUserByID(context.Background(), userID)
                if err != nil && err != ErrUserNotFound {
                    errors <- err
                    return
                }
            }
        }(i)
    }
    
    // Start writers
    for i := 0; i < numWriters; i++ {
        wg.Add(1)
        go func(writerID int) {
            defer wg.Done()
            
            for j := 1; j <= 20; j++ {
                req := &dto.CreateUserRequest{
                    Name:     fmt.Sprintf("Writer User %d-%d", writerID, j),
                    Email:    fmt.Sprintf("writer%d-%d@example.com", writerID, j),
                    Password: "password123",
                }
                
                _, err := suite.service.CreateUser(context.Background(), req)
                if err != nil {
                    errors <- err
                    return
                }
            }
        }(i)
    }
    
    wg.Wait()
    close(errors)
    
    // Check for errors
    for err := range errors {
        suite.NoError(err)
    }
}

// Memory and resource leak tests
func (suite *UserServiceTestSuite) TestMemoryUsage_BulkOperations() {
    // Get initial memory stats
    var m1, m2 runtime.MemStats
    runtime.GC()
    runtime.ReadMemStats(&m1)
    
    // Perform bulk operations
    for i := 1; i <= 10000; i++ {
        req := &dto.CreateUserRequest{
            Name:     fmt.Sprintf("Memory User %d", i),
            Email:    fmt.Sprintf("memory%d@example.com", i),
            Password: "password123",
        }
        _, err := suite.service.CreateUser(context.Background(), req)
        suite.NoError(err)
        
        // Read user back
        user, err := suite.service.GetUserByID(context.Background(), uint(i))
        suite.NoError(err)
        suite.NotNil(user)
    }
    
    // Force garbage collection and get final memory stats
    runtime.GC()
    runtime.ReadMemStats(&m2)
    
    // Check memory usage (allow some growth but should be reasonable)
    memoryDiff := m2.Alloc - m1.Alloc
    suite.Less(memoryDiff, uint64(50*1024*1024), "Memory usage should not grow more than 50MB")
    
    fmt.Printf("Memory usage after 10,000 operations: %d bytes\n", memoryDiff)
}

// Property-based testing
func (suite *UserServiceTestSuite) TestProperty_CreateUser() {
    properties := gopter.NewProperties(nil)
    
    properties.Property("valid user creation should succeed", gopter.ForAll(
        func(name string, email string, password string) bool {
            // Generate valid data
            if name == "" {
                name = "Test User"
            }
            if email == "" || !strings.Contains(email, "@") {
                email = "test@example.com"
            }
            if len(password) < 8 {
                password = "password123"
            }
            
            req := &dto.CreateUserRequest{
                Name:     name,
                Email:    email,
                Password: password,
            }
            
            user, err := suite.service.CreateUser(context.Background(), req)
            return err == nil && user.ID > 0 && user.Name == name && user.Email == email
        },
        genAlphaString(),
        genEmail(),
        genStrongPassword(),
    ))
    
    properties.TestingRun(t, gopter.ConsoleReporter(false))
}

// Fuzz testing
func FuzzUserService_CreateUser(f *testing.F) {
    // Add seed corpus
    f.Add("John Doe", "john@example.com", "password123")
    f.Add("Jane Smith", "jane@example.com", "securepassword")
    f.Add("", "invalid-email", "123")
    
    f.Fuzz(func(t *testing.T, name, email, password string) {
        req := &dto.CreateUserRequest{
            Name:     name,
            Email:    email,
            Password: password,
        }
        
        _, err := service.CreateUser(context.Background(), req)
        
        // Should not panic
        if err != nil {
            // Check that error is one of expected validation errors
            switch err {
            case ErrInvalidEmail, ErrWeakPassword, ErrInvalidName, ErrUserAlreadyExists:
                // Expected errors
            default:
                // Unexpected error
                t.Errorf("Unexpected error: %v", err)
            }
        }
    })
}

// Load testing
func (suite *UserServiceTestSuite) TestLoad_CreateUsers() {
    rate := vegeta.Rate{Freq: 100, Per: time.Second}
    duration := 10 * time.Second
    
    targeter := vegeta.NewStaticTargeter(vegeta.Target{
        Method: "POST",
        URL:    "http://localhost:8080/api/v1/users",
        Body:   []byte(`{"name":"Load User","email":"load@example.com","password":"password123"}`),
        Header: http.Header{
            "Content-Type": []string{"application/json"},
        },
    })
    
    attacker := vegeta.NewAttacker()
    
    var metrics vegeta.Metrics
    for res := range attacker.Attack(targeter, rate, duration, "Load Test") {
        metrics.Add(res)
    }
    metrics.Close()
    
    // Check that we achieved reasonable performance
    suite.Less(metrics.Latencies.P95, 100*time.Millisecond, "95th percentile latency should be under 100ms")
    suite.Greater(metrics.Success, 0.95, "Success rate should be above 95%")
    
    fmt.Printf("Load test results: %+v\n", metrics)
}

// Run the test suite
func TestUserServiceSuite(t *testing.T) {
    suite.Run(t, new(UserServiceTestSuite))
}

// Mock-based unit tests for edge cases
func TestUserService_MockBased(t *testing.T) {
    ctrl := gomock.NewController(t)
    defer ctrl.Finish()
    
    mockRepo := mocks.NewMockUserRepository(ctrl)
    service := NewUserService(mockRepo)
    
    t.Run("GetUserByID_DatabaseError", func(t *testing.T) {
        mockRepo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(nil, errors.New("database connection lost"))
        
        user, err := service.GetUserByID(context.Background(), 1)
        
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "database connection lost")
        assert.Nil(t, user)
    })
    
    t.Run("CreateUser_EmailValidation", func(t *testing.T) {
        req := &dto.CreateUserRequest{
            Name:     "Test User",
            Email:    "invalid-email",
            Password: "password123",
        }
        
        user, err := service.CreateUser(context.Background(), req)
        
        assert.Error(t, err)
        assert.Equal(t, ErrInvalidEmail, err)
        assert.Nil(t, user)
    })
    
    t.Run("UpdateUser_NoChanges", func(t *testing.T) {
        existingUser := &models.User{
            ID:        1,
            Name:      "Test User",
            Email:     "test@example.com",
            CreatedAt: time.Now(),
        }
        
        mockRepo.EXPECT().GetByID(gomock.Any(), uint(1)).Return(existingUser, nil)
        mockRepo.EXPECT().Update(gomock.Any(), gomock.Any()).Return(nil)
        
        req := &dto.UpdateUserRequest{
            Name:  "Test User",
            Email: "test@example.com",
        }
        
        user, err := service.UpdateUser(context.Background(), 1, req)
        
        assert.NoError(t, err)
        assert.Equal(t, existingUser.Name, user.Name)
        assert.Equal(t, existingUser.Email, user.Email)
    })
}

// Helper functions for enterprise testing
func runEnterpriseTestMigrations(db *sqlx.DB) error {
    migrations := []string{
        `CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'user',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );`,
        `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);`,
        `CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);`,
        `CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);`,
        `CREATE INDEX IF NOT EXISTS idx_users_name ON users(name);`,
    }
    
    for _, migration := range migrations {
        if _, err := db.Exec(migration); err != nil {
            return fmt.Errorf("failed to run migration: %w", err)
        }
    }
    
    return nil
}

// Generators for property-based testing
func genAlphaString() gopter.Gen {
    return gopter.Gen(func() interface{} {
        return gopter.GenAlphaString().(string)
    })
}

func genEmail() gopter.Gen {
    return gopter.Gen(func() interface{} {
        return fmt.Sprintf("%s@%s.com", 
            gopter.GenAlphaString().(string), 
            gopter.GenAlphaString().(string))
    })
}

func genStrongPassword() gopter.Gen {
    return gopter.Gen(func() interface{} {
        return "password123" // Always return valid password for this test
    })
}
```

## 🏗️ Testing Utilities and Helpers

### **Test Database Setup**

```go
// internal/testing/database.go - Test database utilities
package testing

import (
    "context"
    "fmt"
    "testing"
    
    "github.com/jmoiron/sqlx"
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/wait"
    _ "github.com/lib/pq"
)

type TestDatabase struct {
    Container testcontainers.Container
    DB        *sqlx.DB
    DSN       string
}

func SetupTestDatabase(t *testing.T) *TestDatabase {
    ctx := context.Background()
    
    req := testcontainers.ContainerRequest{
        Image:        "postgres:15-alpine",
        ExposedPorts: []string{"5432/tcp"},
        Env: map[string]string{
            "POSTGRES_DB":       "testdb",
            "POSTGRES_USER":     "testuser",
            "POSTGRES_PASSWORD": "testpass",
        },
        WaitingFor: wait.ForLog("database system is ready to accept connections"),
    }
    
    container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
        ContainerRequest: req,
        Started:          true,
    })
    if err != nil {
        t.Fatalf("Failed to start test database container: %v", err)
    }
    
    host, err := container.Host(ctx)
    if err != nil {
        t.Fatalf("Failed to get container host: %v", err)
    }
    
    port, err := container.MappedPort(ctx, "5432")
    if err != nil {
        t.Fatalf("Failed to get container port: %v", err)
    }
    
    dsn := fmt.Sprintf("postgres://testuser:testpass@%s:%s/testdb?sslmode=disable", host, port.Port())
    db, err := sqlx.Connect("postgres", dsn)
    if err != nil {
        t.Fatalf("Failed to connect to test database: %v", err)
    }
    
    return &TestDatabase{
        Container: container,
        DB:        db,
        DSN:       dsn,
    }
}

func (td *TestDatabase) Close(t *testing.T) {
    if td.DB != nil {
        td.DB.Close()
    }
    if td.Container != nil {
        ctx := context.Background()
        td.Container.Terminate(ctx)
    }
}

func (td *TestDatabase) RunMigrations(t *testing.T) error {
    migrations := []string{
        `CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'user',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );`,
        `CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            price DECIMAL(10,2) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );`,
        `CREATE TABLE IF NOT EXISTS orders (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            total DECIMAL(10,2) NOT NULL,
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );`,
    }
    
    for _, migration := range migrations {
        if _, err := td.DB.Exec(migration); err != nil {
            return fmt.Errorf("failed to run migration: %w", err)
        }
    }
    
    return nil
}

func (td *TestDatabase) Cleanup(t *testing.T) {
    tables := []string{"orders", "products", "users"}
    for _, table := range tables {
        _, err := td.DB.Exec(fmt.Sprintf("DELETE FROM %s", table))
        if err != nil {
            t.Logf("Failed to cleanup table %s: %v", table, err)
        }
    }
}
```

### **Mock Generators**

```go
// internal/testing/mocks.go - Mock generation utilities
package testing

import (
    "time"
    
    "github.com/golang/mock/gomock"
    "github.com/google/uuid"
    
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/models"
)

// Mock user generator
func GenerateMockUser(id uint, name, email string) *models.User {
    return &models.User{
        ID:        id,
        Name:      name,
        Email:     email,
        PasswordHash: "hashed_password",
        Role:      "user",
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }
}

func GenerateMockUsers(count int) []*models.User {
    users := make([]*models.User, count)
    for i := 0; i < count; i++ {
        users[i] = GenerateMockUser(
            uint(i+1),
            fmt.Sprintf("User %d", i+1),
            fmt.Sprintf("user%d@example.com", i+1),
        )
    }
    return users
}

// Mock product generator
func GenerateMockProduct(id uint, name, description string, price float64) *models.Product {
    return &models.Product{
        ID:          id,
        Name:        name,
        Description: description,
        Price:       price,
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }
}

// Mock order generator
func GenerateMockOrder(id, userID uint, total float64, status string) *models.Order {
    return &models.Order{
        ID:        id,
        UserID:    userID,
        Total:     total,
        Status:    status,
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }
}

// Custom matchers
type UserMatcher struct {
    user *models.User
}

func NewUserMatcher(user *models.User) *UserMatcher {
    return &UserMatcher{user: user}
}

func (m *UserMatcher) Matches(x interface{}) bool {
    user, ok := x.(*models.User)
    if !ok {
        return false
    }
    
    return user.Name == m.user.Name &&
           user.Email == m.user.Email &&
           user.Role == m.user.Role
}

func (m *UserMatcher) String() string {
    return fmt.Sprintf("user with name=%s, email=%s, role=%s", 
        m.user.Name, m.user.Email, m.user.Role)
}

// Gomock helper functions
func AnyUser() gomock.Matcher {
    return &UserMatcher{user: &models.User{}}
}

func UserWithName(name string) gomock.Matcher {
    return &UserMatcher{user: &models.User{Name: name}}
}

func UserWithEmail(email string) gomock.Matcher {
    return &UserMatcher{user: &models.User{Email: email}}
}
```

### **Test Data Factories**

```go
// internal/testing/factories.go - Test data factories
package testing

import (
    "time"
    
    "github.com/google/uuid"
    
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/dto"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/models"
)

type UserFactory struct {
    counter uint
}

func NewUserFactory() *UserFactory {
    return &UserFactory{counter: 1}
}

func (f *UserFactory) CreateUser() *models.User {
    defer func() { f.counter++ }()
    
    return &models.User{
        ID:        f.counter,
        Name:      fmt.Sprintf("Test User %d", f.counter),
        Email:     fmt.Sprintf("user%d@example.com", f.counter),
        PasswordHash: "hashed_password",
        Role:      "user",
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }
}

func (f *UserFactory) CreateUserWithRole(role string) *models.User {
    user := f.CreateUser()
    user.Role = role
    return user
}

func (f *UserFactory) CreateUserRequest() *dto.CreateUserRequest {
    defer func() { f.counter++ }()
    
    return &dto.CreateUserRequest{
        Name:     fmt.Sprintf("Test User %d", f.counter),
        Email:    fmt.Sprintf("user%d@example.com", f.counter),
        Password: "password123",
        Role:     "user",
    }
}

func (f *UserFactory) CreateUpdateUserRequest() *dto.UpdateUserRequest {
    defer func() { f.counter++ }()
    
    return &dto.UpdateUserRequest{
        Name:  fmt.Sprintf("Updated User %d", f.counter),
        Email: fmt.Sprintf("updated%d@example.com", f.counter),
        Role:  "admin",
    }
}

type ProductFactory struct {
    counter uint
}

func NewProductFactory() *ProductFactory {
    return &ProductFactory{counter: 1}
}

func (f *ProductFactory) CreateProduct() *models.Product {
    defer func() { f.counter++ }()
    
    return &models.Product{
        ID:          f.counter,
        Name:        fmt.Sprintf("Test Product %d", f.counter),
        Description: fmt.Sprintf("Description for product %d", f.counter),
        Price:       float64(f.counter) * 10.99,
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }
}

func (f *ProductFactory) CreateProductRequest() *dto.CreateProductRequest {
    defer func() { f.counter++ }()
    
    return &dto.CreateProductRequest{
        Name:        fmt.Sprintf("Test Product %d", f.counter),
        Description: fmt.Sprintf("Description for product %d", f.counter),
        Price:       float64(f.counter) * 10.99,
    }
}

type OrderFactory struct {
    counter uint
}

func NewOrderFactory() *OrderFactory {
    return &OrderFactory{counter: 1}
}

func (f *OrderFactory) CreateOrder(userID uint) *models.Order {
    defer func() { f.counter++ }()
    
    return &models.Order{
        ID:        f.counter,
        UserID:    userID,
        Total:     float64(f.counter) * 25.50,
        Status:    "pending",
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }
}

func (f *OrderFactory) CreateOrderWithItems(userID uint, items []*models.OrderItem) *models.Order {
    order := f.CreateOrder(userID)
    
    total := 0.0
    for _, item := range items {
        total += item.Price * float64(item.Quantity)
    }
    order.Total = total
    
    return order
}

func (f *OrderFactory) CreateOrderRequest() *dto.CreateOrderRequest {
    defer func() { f.counter++ }()
    
    return &dto.CreateOrderRequest{
        UserID: f.counter,
        Items: []dto.OrderItemRequest{
            {
                ProductID: f.counter,
                Quantity:  2,
                Price:     25.50,
            },
        },
    }
}
```

## 🚀 Test Scripts and Configuration

### **Makefile Testing Commands**

```makefile
# Makefile
.PHONY: test test-unit test-integration test-benchmark test-coverage test-race test-fuzz

# Run all tests
test: test-unit test-integration test-benchmark

# Run unit tests
test-unit:
	go test -v ./internal/... -short

# Run integration tests
test-integration:
	go test -v ./internal/... -tags=integration

# Run benchmark tests
test-benchmark:
	go test -bench=. -benchmem ./internal/...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./internal/...
	go tool cover -html=coverage.out -o coverage.html

# Run tests with race detection
test-race:
	go test -race -v ./internal/...

# Run fuzz tests
test-fuzz:
	go test -fuzz=. -fuzztime=30s ./internal/...

# Run tests with verbose output
test-verbose:
	go test -v -race -cover ./internal/...

# Run tests for specific package
test-service:
	go test -v ./internal/services/...

# Run tests with specific pattern
test-pattern:
	go test -v ./internal/... -run="TestUserService"

# Clean test cache
test-clean:
	go clean -testcache

# Generate test mocks
test-mocks:
	go generate ./internal/...

# Run tests with timeout
test-timeout:
	go test -v -timeout=30s ./internal/...
```

### **Test Configuration Files**

```yaml
# .github/workflows/test.yml
name: Go Tests

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
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: testdb
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
      
    - name: Setup Go
      uses: actions/setup-go@v4
      with:
        go-version: ${{ matrix.go-version }}
        
    - name: Cache Go modules
      uses: actions/cache@v3
      with:
        path: ~/go/pkg/mod
        key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
        restore-keys: |
          ${{ runner.os }}-go-
          
    - name: Install dependencies
      run: |
        go mod download
        go install github.com/golang/mock/mockgen@latest
        
    - name: Generate mocks
      run: go generate ./...
      
    - name: Run unit tests
      run: go test -v -race -coverprofile=coverage.out ./internal/...
      
    - name: Run integration tests
      run: go test -v -tags=integration ./internal/...
      env:
        DATABASE_URL: postgres://postgres:postgres@localhost:5432/testdb?sslmode=disable
        
    - name: Run benchmark tests
      run: go test -bench=. -benchmem ./internal/...
      
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out
        flags: unittests
        name: codecov-umbrella
        
    - name: Run fuzz tests
      run: go test -fuzz=. -fuzztime=60s ./internal/...
```

```json
// .vscode/settings.json
{
    "go.testFlags": ["-v", "-race"],
    "go.coverOnSave": true,
    "go.coverageDecorator": {
        "type": "gutter",
        "coveredHighlightColor": "rgba(64,128,64,0.5)",
        "uncoveredHighlightColor": "rgba(128,64,64,0.25)"
    },
    "go.testTimeout": "30s",
    "go.buildOnSave": "off",
    "go.lintOnSave": "file",
    "go.lintTool": "golangci-lint",
    "go.lintFlags": [
        "--fast"
    ]
}
```

---

**Go Version**: [GO_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
