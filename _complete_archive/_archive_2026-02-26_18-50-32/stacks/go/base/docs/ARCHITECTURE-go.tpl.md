<!--
File: ARCHITECTURE-go.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Go Architecture Patterns - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Go

## 🏗️ Go Architecture Overview

Go applications follow **clean architecture principles**, **microservices patterns**, **concurrent design with goroutines and channels**, and **performance-first development**. Each tier builds upon the previous one with additional architectural patterns, scalability considerations, and enterprise features optimized for Go's strengths in backend services and CLI applications.

## 📊 Tier-Specific Architecture Requirements

| Tier | Architecture | Concurrency | Performance | Scalability | Patterns |
|------|--------------|-------------|-------------|-------------|----------|
| **MVP** | Simple CLI | Basic goroutines | Standard | Single instance | Standard library |
| **CORE** | Clean architecture | Worker pools | Optimized | Horizontal scaling | Microservices |
| **FULL** | Distributed systems | Advanced patterns | High performance | Global scaling | Enterprise patterns |

## 🎯 Clean Architecture Implementation

### **MVP Tier - Simple CLI Architecture**

```go
// cmd/main.go - Simple CLI application
package main

import (
    "fmt"
    "log"
    "os"
    "strings"
)

type User struct {
    ID    int    `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

type UserService struct {
    users []User
}

func NewUserService() *UserService {
    return &UserService{
        users: []User{
            {ID: 1, Name: "John Doe", Email: "john@example.com"},
            {ID: 2, Name: "Jane Smith", Email: "jane@example.com"},
        },
    }
}

func (s *UserService) ListUsers() []User {
    return s.users
}

func (s *UserService) GetUser(id int) (*User, error) {
    for _, user := range s.users {
        if user.ID == id {
            return &user, nil
        }
    }
    return nil, fmt.Errorf("user not found")
}

func (s *UserService) CreateUser(name, email string) *User {
    user := User{
        ID:    len(s.users) + 1,
        Name:  name,
        Email: email,
    }
    s.users = append(s.users, user)
    return &user
}

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: {{PROJECT_NAME_LOWER}} <command>")
        os.Exit(1)
    }

    service := NewUserService()
    command := os.Args[1]

    switch strings.ToLower(command) {
    case "list":
        users := service.ListUsers()
        fmt.Println("Users:")
        for _, user := range users {
            fmt.Printf("  %d: %s (%s)\n", user.ID, user.Name, user.Email)
        }
    case "get":
        if len(os.Args) < 3 {
            fmt.Println("Usage: {{PROJECT_NAME_LOWER}} get <id>")
            os.Exit(1)
        }
        var id int
        fmt.Sscanf(os.Args[2], "%d", &id)
        user, err := service.GetUser(id)
        if err != nil {
            fmt.Printf("Error: %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("User: %d: %s (%s)\n", user.ID, user.Name, user.Email)
    case "create":
        if len(os.Args) < 4 {
            fmt.Println("Usage: {{PROJECT_NAME_LOWER}} create <name> <email>")
            os.Exit(1)
        }
        user := service.CreateUser(os.Args[2], os.Args[3])
        fmt.Printf("Created user: %d: %s (%s)\n", user.ID, user.Name, user.Email)
    default:
        fmt.Printf("Unknown command: %s\n", command)
        fmt.Println("Available commands: list, get, create")
        os.Exit(1)
    }
}
```

### **CORE Tier - Clean Architecture**

```go
// internal/domain/user.go - Domain layer
package domain

import (
    "time"
    "errors"
)

var (
    ErrUserNotFound       = errors.New("user not found")
    ErrUserAlreadyExists  = errors.New("user already exists")
    ErrInvalidEmail       = errors.New("invalid email format")
    ErrInvalidName        = errors.New("invalid name")
    ErrWeakPassword       = errors.New("password is too weak")
)

type User struct {
    ID          uint      `json:"id" db:"id"`
    Name        string    `json:"name" db:"name"`
    Email       string    `json:"email" db:"email"`
    PasswordHash string   `json:"-" db:"password_hash"`
    Role        string    `json:"role" db:"role"`
    CreatedAt   time.Time `json:"created_at" db:"created_at"`
    UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type UserRepository interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id uint) (*User, error)
    GetByEmail(ctx context.Context, email string) (*User, error)
    Update(ctx context.Context, user *User) error
    Delete(ctx context.Context, id uint) error
    List(ctx context.Context, limit, offset int) ([]*User, error)
    Count(ctx context.Context) (int64, error)
}

type UserService interface {
    CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error)
    GetUserByID(ctx context.Context, id uint) (*User, error)
    UpdateUser(ctx context.Context, id uint, req *UpdateUserRequest) (*User, error)
    DeleteUser(ctx context.Context, id uint) error
    ListUsers(ctx context.Context, page, limit int) ([]*User, int64, error)
}

type CreateUserRequest struct {
    Name     string `json:"name" validate:"required,min=2,max=100"`
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min=8"`
    Role     string `json:"role" validate:"omitempty,oneof=admin user manager"`
}

type UpdateUserRequest struct {
    Name  string `json:"name,omitempty" validate:"omitempty,min=2,max=100"`
    Email string `json:"email,omitempty" validate:"omitempty,email"`
    Role  string `json:"role,omitempty" validate:"omitempty,oneof=admin user manager"`
}

// Domain business logic
func (u *User) IsValid() error {
    if u.Name == "" || len(u.Name) > 100 {
        return ErrInvalidName
    }
    if u.Email == "" || !isValidEmail(u.Email) {
        return ErrInvalidEmail
    }
    return nil
}

func (u *User) IsAdmin() bool {
    return u.Role == "admin"
}

func (u *User) CanManageUsers() bool {
    return u.Role == "admin" || u.Role == "manager"
}

func isValidEmail(email string) bool {
    // Simple email validation
    return strings.Contains(email, "@") && strings.Contains(email, ".")
}
```

```go
// internal/application/user_service.go - Application layer
package application

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "time"
    
    "golang.org/x/crypto/bcrypt"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/domain"
)

type userService struct {
    repo domain.UserRepository
}

func NewUserService(repo domain.UserRepository) domain.UserService {
    return &userService{repo: repo}
}

func (s *userService) CreateUser(ctx context.Context, req *domain.CreateUserRequest) (*domain.User, error) {
    // Validate request
    if err := s.validateCreateRequest(req); err != nil {
        return nil, err
    }
    
    // Check if user already exists
    existingUser, err := s.repo.GetByEmail(ctx, req.Email)
    if err == nil && existingUser != nil {
        return nil, domain.ErrUserAlreadyExists
    }
    
    // Hash password
    passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        return nil, fmt.Errorf("failed to hash password: %w", err)
    }
    
    // Create user
    user := &domain.User{
        Name:         req.Name,
        Email:        req.Email,
        PasswordHash: string(passwordHash),
        Role:         req.Role,
        CreatedAt:    time.Now(),
        UpdatedAt:    time.Now(),
    }
    
    if user.Role == "" {
        user.Role = "user"
    }
    
    if err := s.repo.Create(ctx, user); err != nil {
        return nil, fmt.Errorf("failed to create user: %w", err)
    }
    
    return user, nil
}

func (s *userService) GetUserByID(ctx context.Context, id uint) (*domain.User, error) {
    if id == 0 {
        return nil, domain.ErrInvalidUserID
    }
    
    user, err := s.repo.GetByID(ctx, id)
    if err != nil {
        return nil, err
    }
    
    return user, nil
}

func (s *userService) UpdateUser(ctx context.Context, id uint, req *domain.UpdateUserRequest) (*domain.User, error) {
    if id == 0 {
        return nil, domain.ErrInvalidUserID
    }
    
    // Get existing user
    user, err := s.repo.GetByID(ctx, id)
    if err != nil {
        return nil, err
    }
    
    // Update fields
    if req.Name != "" {
        user.Name = req.Name
    }
    if req.Email != "" {
        user.Email = req.Email
    }
    if req.Role != "" {
        user.Role = req.Role
    }
    
    user.UpdatedAt = time.Now()
    
    // Validate updated user
    if err := user.IsValid(); err != nil {
        return nil, err
    }
    
    if err := s.repo.Update(ctx, user); err != nil {
        return nil, fmt.Errorf("failed to update user: %w", err)
    }
    
    return user, nil
}

func (s *userService) DeleteUser(ctx context.Context, id uint) error {
    if id == 0 {
        return domain.ErrInvalidUserID
    }
    
    // Check if user exists
    _, err := s.repo.GetByID(ctx, id)
    if err != nil {
        return err
    }
    
    if err := s.repo.Delete(ctx, id); err != nil {
        return fmt.Errorf("failed to delete user: %w", err)
    }
    
    return nil
}

func (s *userService) ListUsers(ctx context.Context, page, limit int) ([]*domain.User, int64, error) {
    if page < 1 {
        page = 1
    }
    if limit < 1 || limit > 100 {
        limit = 10
    }
    
    offset := (page - 1) * limit
    
    users, err := s.repo.List(ctx, limit, offset)
    if err != nil {
        return nil, 0, fmt.Errorf("failed to list users: %w", err)
    }
    
    total, err := s.repo.Count(ctx)
    if err != nil {
        return nil, 0, fmt.Errorf("failed to count users: %w", err)
    }
    
    return users, total, nil
}

func (s *userService) validateCreateRequest(req *domain.CreateUserRequest) error {
    if req.Name == "" || len(req.Name) > 100 {
        return domain.ErrInvalidName
    }
    if req.Email == "" || !isValidEmail(req.Email) {
        return domain.ErrInvalidEmail
    }
    if len(req.Password) < 8 {
        return domain.ErrWeakPassword
    }
    return nil
}
```

```go
// internal/infrastructure/database/user_repository.go - Infrastructure layer
package database

import (
    "context"
    "database/sql"
    "fmt"
    "time"
    
    "github.com/jmoiron/sqlx"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/domain"
)

type userRepository struct {
    db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) domain.UserRepository {
    return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
    query := `
        INSERT INTO users (name, email, password_hash, role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
    `
    
    err := r.db.QueryRowContext(ctx, query,
        user.Name,
        user.Email,
        user.PasswordHash,
        user.Role,
        user.CreatedAt,
        user.UpdatedAt,
    ).Scan(&user.ID)
    
    if err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }
    
    return nil
}

func (r *userRepository) GetByID(ctx context.Context, id uint) (*domain.User, error) {
    query := `
        SELECT id, name, email, password_hash, role, created_at, updated_at
        FROM users
        WHERE id = $1
    `
    
    var user domain.User
    err := r.db.GetContext(ctx, &user, query, id)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, domain.ErrUserNotFound
        }
        return nil, fmt.Errorf("failed to get user by ID: %w", err)
    }
    
    return &user, nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
    query := `
        SELECT id, name, email, password_hash, role, created_at, updated_at
        FROM users
        WHERE email = $1
    `
    
    var user domain.User
    err := r.db.GetContext(ctx, &user, query, email)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, domain.ErrUserNotFound
        }
        return nil, fmt.Errorf("failed to get user by email: %w", err)
    }
    
    return &user, nil
}

func (r *userRepository) Update(ctx context.Context, user *domain.User) error {
    query := `
        UPDATE users
        SET name = $1, email = $2, role = $3, updated_at = $4
        WHERE id = $5
    `
    
    result, err := r.db.ExecContext(ctx, query,
        user.Name,
        user.Email,
        user.Role,
        user.UpdatedAt,
        user.ID,
    )
    
    if err != nil {
        return fmt.Errorf("failed to update user: %w", err)
    }
    
    rowsAffected, err := result.RowsAffected()
    if err != nil {
        return fmt.Errorf("failed to get rows affected: %w", err)
    }
    
    if rowsAffected == 0 {
        return domain.ErrUserNotFound
    }
    
    return nil
}

func (r *userRepository) Delete(ctx context.Context, id uint) error {
    query := `DELETE FROM users WHERE id = $1`
    
    result, err := r.db.ExecContext(ctx, query, id)
    if err != nil {
        return fmt.Errorf("failed to delete user: %w", err)
    }
    
    rowsAffected, err := result.RowsAffected()
    if err != nil {
        return fmt.Errorf("failed to get rows affected: %w", err)
    }
    
    if rowsAffected == 0 {
        return domain.ErrUserNotFound
    }
    
    return nil
}

func (r *userRepository) List(ctx context.Context, limit, offset int) ([]*domain.User, error) {
    query := `
        SELECT id, name, email, password_hash, role, created_at, updated_at
        FROM users
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
    `
    
    var users []*domain.User
    err := r.db.SelectContext(ctx, &users, query, limit, offset)
    if err != nil {
        return nil, fmt.Errorf("failed to list users: %w", err)
    }
    
    return users, nil
}

func (r *userRepository) Count(ctx context.Context) (int64, error) {
    query := `SELECT COUNT(*) FROM users`
    
    var count int64
    err := r.db.GetContext(ctx, &count, query)
    if err != nil {
        return 0, fmt.Errorf("failed to count users: %w", err)
    }
    
    return count, nil
}
```

### **FULL Tier - Distributed Systems Architecture**

```go
// internal/domain/user.go - Enhanced domain layer
package domain

import (
    "context"
    "time"
    "errors"
)

var (
    ErrUserNotFound       = errors.New("user not found")
    ErrUserAlreadyExists  = errors.New("user already exists")
    ErrInvalidEmail       = errors.New("invalid email format")
    ErrInvalidName        = errors.New("invalid name")
    ErrWeakPassword       = errors.New("password is too weak")
    ErrInvalidUserID      = errors.New("invalid user ID")
    ErrRestrictedEmailDomain = errors.New("email domain is restricted")
    ErrAccountLocked      = errors.New("account is locked")
    ErrAccountSuspended   = errors.New("account is suspended")
)

type User struct {
    ID          uint      `json:"id" db:"id"`
    Name        string    `json:"name" db:"name"`
    Email       string    `json:"email" db:"email"`
    PasswordHash string   `json:"-" db:"password_hash"`
    Role        string    `json:"role" db:"role"`
    Status      string    `json:"status" db:"status"`
    LastLoginAt *time.Time `json:"last_login_at" db:"last_login_at"`
    CreatedAt   time.Time `json:"created_at" db:"created_at"`
    UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
    Version     int       `json:"version" db:"version"`
}

type UserAuditLog struct {
    ID        uint      `json:"id" db:"id"`
    UserID    uint      `json:"user_id" db:"user_id"`
    Action    string    `json:"action" db:"action"`
    Changes   string    `json:"changes" db:"changes"`
    IPAddress string    `json:"ip_address" db:"ip_address"`
    UserAgent string    `json:"user_agent" db:"user_agent"`
    CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type UserRepository interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id uint) (*User, error)
    GetByEmail(ctx context.Context, email string) (*User, error)
    Update(ctx context.Context, user *User) error
    Delete(ctx context.Context, id uint) error
    List(ctx context.Context, limit, offset int) ([]*User, error)
    ListWithFilters(ctx context.Context, filters *UserFilters) ([]*User, int64, error)
    Count(ctx context.Context) (int64, error)
    UpdateLastLogin(ctx context.Context, id uint) error
    BulkCreate(ctx context.Context, users []*User) error
    BulkUpdate(ctx context.Context, users []*User) error
}

type UserAuditRepository interface {
    Create(ctx context.Context, log *UserAuditLog) error
    GetByUserID(ctx context.Context, userID uint, limit, offset int) ([]*UserAuditLog, error)
}

type UserService interface {
    CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error)
    GetUserByID(ctx context.Context, id uint) (*User, error)
    UpdateUser(ctx context.Context, id uint, req *UpdateUserRequest) (*User, error)
    DeleteUser(ctx context.Context, id uint) error
    ListUsers(ctx context.Context, page, limit int) ([]*User, int64, error)
    ListUsersWithFilters(ctx context.Context, filters *UserFilters) ([]*User, int64, error)
    BulkCreateUsers(ctx context.Context, reqs []*CreateUserRequest) (*BulkCreateResult, error)
    AuthenticateUser(ctx context.Context, email, password string) (*User, error)
    UpdatePassword(ctx context.Context, userID uint, oldPassword, newPassword string) error
    LockUser(ctx context.Context, userID uint) error
    UnlockUser(ctx context.Context, userID uint) error
}

type CreateUserRequest struct {
    Name     string `json:"name" validate:"required,min=2,max=100"`
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min=8,strength"`
    Role     string `json:"role" validate:"omitempty,oneof=admin user manager"`
}

type UpdateUserRequest struct {
    Name  string `json:"name,omitempty" validate:"omitempty,min=2,max=100"`
    Email string `json:"email,omitempty" validate:"omitempty,email"`
    Role  string `json:"role,omitempty" validate:"omitempty,oneof=admin user manager"`
    Status string `json:"status,omitempty" validate:"omitempty,oneof=active suspended locked"`
}

type UserFilters struct {
    Search string `json:"search,omitempty"`
    Role   string `json:"role,omitempty"`
    Status string `json:"status,omitempty"`
    Page   int    `json:"page" validate:"min=1"`
    Limit  int    `json:"limit" validate:"min=1,max=100"`
    SortBy string `json:"sort_by,omitempty" validate:"omitempty,oneof=name email created_at"`
    SortOrder string `json:"sort_order,omitempty" validate:"omitempty,oneof=asc desc"`
}

type BulkCreateResult struct {
    Created []*User `json:"created"`
    Failed  []BulkCreateError `json:"failed"`
}

type BulkCreateError struct {
    Index int    `json:"index"`
    Error string `json:"error"`
}

// Enhanced domain business logic
func (u *User) IsValid() error {
    if u.Name == "" || len(u.Name) > 100 {
        return ErrInvalidName
    }
    if u.Email == "" || !isValidEmail(u.Email) {
        return ErrInvalidEmail
    }
    if u.Status == "" {
        u.Status = "active"
    }
    return nil
}

func (u *User) IsAdmin() bool {
    return u.Role == "admin"
}

func (u *User) CanManageUsers() bool {
    return u.Role == "admin" || u.Role == "manager"
}

func (u *User) IsActive() bool {
    return u.Status == "active"
}

func (u *User) IsLocked() bool {
    return u.Status == "locked"
}

func (u *User) IsSuspended() bool {
    return u.Status == "suspended"
}

func (u *User) CanLogin() bool {
    return u.IsActive()
}

func (u *User) RecordLogin() {
    now := time.Now()
    u.LastLoginAt = &now
    u.UpdatedAt = now
}

func isValidEmail(email string) bool {
    return strings.Contains(email, "@") && strings.Contains(email, ".")
}

func isRestrictedEmailDomain(email string) bool {
    restrictedDomains := []string{"tempmail.com", "throwaway.email", "10minutemail.com"}
    domain := strings.Split(email, "@")[1]
    
    for _, restricted := range restrictedDomains {
        if domain == restricted {
            return true
        }
    }
    return false
}
```

```go
// internal/application/user_service.go - Enhanced application layer
package application

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "strings"
    "time"
    
    "golang.org/x/crypto/bcrypt"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/domain"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/events"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/cache"
    "github.com/{{ORG}}/{{PROJECT_NAME_LOWER}}/internal/monitoring"
)

type userService struct {
    repo       domain.UserRepository
    auditRepo  domain.UserAuditRepository
    cache      cache.CacheService
    eventBus   events.EventBus
    metrics    monitoring.MetricsService
    logger     Logger
}

func NewUserService(
    repo domain.UserRepository,
    auditRepo domain.UserAuditRepository,
    cache cache.CacheService,
    eventBus events.EventBus,
    metrics monitoring.MetricsService,
    logger Logger,
) domain.UserService {
    return &userService{
        repo:      repo,
        auditRepo: auditRepo,
        cache:     cache,
        eventBus:  eventBus,
        metrics:   metrics,
        logger:    logger,
    }
}

func (s *userService) CreateUser(ctx context.Context, req *domain.CreateUserRequest) (*domain.User, error) {
    start := time.Now()
    defer func() {
        s.metrics.RecordDuration("user.create", time.Since(start))
    }()
    
    // Validate request
    if err := s.validateCreateRequest(req); err != nil {
        s.metrics.IncrementCounter("user.create.validation_error")
        return nil, err
    }
    
    // Check if user already exists
    existingUser, err := s.repo.GetByEmail(ctx, req.Email)
    if err == nil && existingUser != nil {
        s.metrics.IncrementCounter("user.create.already_exists")
        return nil, domain.ErrUserAlreadyExists
    }
    
    // Hash password
    passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        s.metrics.IncrementCounter("user.create.hash_error")
        return nil, fmt.Errorf("failed to hash password: %w", err)
    }
    
    // Create user
    user := &domain.User{
        Name:         req.Name,
        Email:        req.Email,
        PasswordHash: string(passwordHash),
        Role:         req.Role,
        Status:       "active",
        CreatedAt:    time.Now(),
        UpdatedAt:    time.Now(),
        Version:      1,
    }
    
    if user.Role == "" {
        user.Role = "user"
    }
    
    if err := s.repo.Create(ctx, user); err != nil {
        s.metrics.IncrementCounter("user.create.create_error")
        return nil, fmt.Errorf("failed to create user: %w", err)
    }
    
    // Cache user
    cacheKey := fmt.Sprintf("user:%d", user.ID)
    s.cache.Set(ctx, cacheKey, user, 30*time.Minute)
    
    // Emit event
    event := &events.UserCreatedEvent{
        UserID:    user.ID,
        Email:     user.Email,
        Role:      user.Role,
        CreatedAt: user.CreatedAt,
    }
    s.eventBus.Publish(ctx, event)
    
    // Log audit
    auditLog := &domain.UserAuditLog{
        UserID:    user.ID,
        Action:    "user_created",
        Changes:   fmt.Sprintf("Created user %s with role %s", user.Email, user.Role),
        IPAddress: s.getClientIP(ctx),
        UserAgent: s.getUserAgent(ctx),
        CreatedAt: time.Now(),
    }
    s.auditRepo.Create(ctx, auditLog)
    
    s.metrics.IncrementCounter("user.create.success")
    s.logger.Info("User created successfully", "user_id", user.ID, "email", user.Email)
    
    return user, nil
}

func (s *userService) GetUserByID(ctx context.Context, id uint) (*domain.User, error) {
    start := time.Now()
    defer func() {
        s.metrics.RecordDuration("user.get_by_id", time.Since(start))
    }()
    
    if id == 0 {
        return nil, domain.ErrInvalidUserID
    }
    
    // Try cache first
    cacheKey := fmt.Sprintf("user:%d", id)
    if cached, err := s.cache.Get(ctx, cacheKey); err == nil {
        s.metrics.IncrementCounter("user.get_by_id.cache_hit")
        return cached.(*domain.User), nil
    }
    
    user, err := s.repo.GetByID(ctx, id)
    if err != nil {
        s.metrics.IncrementCounter("user.get_by_id.not_found")
        return nil, err
    }
    
    // Cache user
    s.cache.Set(ctx, cacheKey, user, 30*time.Minute)
    s.metrics.IncrementCounter("user.get_by_id.cache_miss")
    
    return user, nil
}

func (s *userService) UpdateUser(ctx context.Context, id uint, req *domain.UpdateUserRequest) (*domain.User, error) {
    start := time.Now()
    defer func() {
        s.metrics.RecordDuration("user.update", time.Since(start))
    }()
    
    if id == 0 {
        return nil, domain.ErrInvalidUserID
    }
    
    // Get existing user
    user, err := s.repo.GetByID(ctx, id)
    if err != nil {
        s.metrics.IncrementCounter("user.update.not_found")
        return nil, err
    }
    
    // Record changes for audit
    changes := s.recordChanges(user, req)
    
    // Update fields
    if req.Name != "" {
        user.Name = req.Name
    }
    if req.Email != "" {
        user.Email = req.Email
    }
    if req.Role != "" {
        user.Role = req.Role
    }
    if req.Status != "" {
        user.Status = req.Status
    }
    
    user.UpdatedAt = time.Now()
    user.Version++
    
    // Validate updated user
    if err := user.IsValid(); err != nil {
        s.metrics.IncrementCounter("user.update.validation_error")
        return nil, err
    }
    
    if err := s.repo.Update(ctx, user); err != nil {
        s.metrics.IncrementCounter("user.update.update_error")
        return nil, fmt.Errorf("failed to update user: %w", err)
    }
    
    // Update cache
    cacheKey := fmt.Sprintf("user:%d", user.ID)
    s.cache.Set(ctx, cacheKey, user, 30*time.Minute)
    
    // Emit event
    event := &events.UserUpdatedEvent{
        UserID:    user.ID,
        Changes:   changes,
        UpdatedAt: user.UpdatedAt,
    }
    s.eventBus.Publish(ctx, event)
    
    // Log audit
    auditLog := &domain.UserAuditLog{
        UserID:    user.ID,
        Action:    "user_updated",
        Changes:   changes,
        IPAddress: s.getClientIP(ctx),
        UserAgent: s.getUserAgent(ctx),
        CreatedAt: time.Now(),
    }
    s.auditRepo.Create(ctx, auditLog)
    
    s.metrics.IncrementCounter("user.update.success")
    s.logger.Info("User updated successfully", "user_id", user.ID, "changes", changes)
    
    return user, nil
}

func (s *userService) BulkCreateUsers(ctx context.Context, reqs []*domain.CreateUserRequest) (*domain.BulkCreateResult, error) {
    start := time.Now()
    defer func() {
        s.metrics.RecordDuration("user.bulk_create", time.Since(start))
    }()
    
    if len(reqs) == 0 || len(reqs) > 1000 {
        return nil, fmt.Errorf("bulk size must be between 1 and 1000")
    }
    
    result := &domain.BulkCreateResult{
        Created: make([]*domain.User, 0),
        Failed:  make([]domain.BulkCreateError, 0),
    }
    
    // Validate all requests first
    validReqs := make([]*domain.CreateUserRequest, 0, len(reqs))
    for i, req := range reqs {
        if err := s.validateCreateRequest(req); err != nil {
            result.Failed = append(result.Failed, domain.BulkCreateError{
                Index: i,
                Error: err.Error(),
            })
            continue
        }
        validReqs = append(validReqs, req)
    }
    
    // Create users in batches
    batchSize := 50
    for i := 0; i < len(validReqs); i += batchSize {
        end := i + batchSize
        if end > len(validReqs) {
            end = len(validReqs)
        }
        
        batch := validReqs[i:end]
        users := make([]*domain.User, len(batch))
        
        for j, req := range batch {
            passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
            if err != nil {
                result.Failed = append(result.Failed, domain.BulkCreateError{
                    Index: i + j,
                    Error: fmt.Sprintf("Failed to hash password: %v", err),
                })
                continue
            }
            
            users[j] = &domain.User{
                Name:         req.Name,
                Email:        req.Email,
                PasswordHash: string(passwordHash),
                Role:         req.Role,
                Status:       "active",
                CreatedAt:    time.Now(),
                UpdatedAt:    time.Now(),
                Version:      1,
            }
            
            if users[j].Role == "" {
                users[j].Role = "user"
            }
        }
        
        // Bulk insert
        if err := s.repo.BulkCreate(ctx, users); err != nil {
            for j := range users {
                result.Failed = append(result.Failed, domain.BulkCreateError{
                    Index: i + j,
                    Error: fmt.Sprintf("Failed to create user: %v", err),
                })
            }
            continue
        }
        
        result.Created = append(result.Created, users...)
    }
    
    // Cache created users
    for _, user := range result.Created {
        cacheKey := fmt.Sprintf("user:%d", user.ID)
        s.cache.Set(ctx, cacheKey, user, 30*time.Minute)
        
        // Emit event
        event := &events.UserCreatedEvent{
            UserID:    user.ID,
            Email:     user.Email,
            Role:      user.Role,
            CreatedAt: user.CreatedAt,
        }
        s.eventBus.Publish(ctx, event)
    }
    
    s.metrics.IncrementCounter("user.bulk_create.success", map[string]string{
        "created_count": fmt.Sprintf("%d", len(result.Created)),
        "failed_count":  fmt.Sprintf("%d", len(result.Failed)),
    })
    
    return result, nil
}

func (s *userService) AuthenticateUser(ctx context.Context, email, password string) (*domain.User, error) {
    start := time.Now()
    defer func() {
        s.metrics.RecordDuration("user.authenticate", time.Since(start))
    }()
    
    // Get user by email
    user, err := s.repo.GetByEmail(ctx, email)
    if err != nil {
        s.metrics.IncrementCounter("user.authenticate.not_found")
        return nil, domain.ErrUserNotFound
    }
    
    // Check if user can login
    if !user.CanLogin() {
        s.metrics.IncrementCounter("user.authenticate.blocked")
        return nil, domain.ErrAccountLocked
    }
    
    // Verify password
    if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
        s.metrics.IncrementCounter("user.authenticate.invalid_password")
        return nil, domain.ErrInvalidCredentials
    }
    
    // Update last login
    user.RecordLogin()
    s.repo.UpdateLastLogin(ctx, user.ID)
    
    // Update cache
    cacheKey := fmt.Sprintf("user:%d", user.ID)
    s.cache.Set(ctx, cacheKey, user, 30*time.Minute)
    
    // Log audit
    auditLog := &domain.UserAuditLog{
        UserID:    user.ID,
        Action:    "user_login",
        Changes:   "User logged in successfully",
        IPAddress: s.getClientIP(ctx),
        UserAgent: s.getUserAgent(ctx),
        CreatedAt: time.Now(),
    }
    s.auditRepo.Create(ctx, auditLog)
    
    s.metrics.IncrementCounter("user.authenticate.success")
    s.logger.Info("User authenticated successfully", "user_id", user.ID, "email", user.Email)
    
    return user, nil
}

func (s *userService) validateCreateRequest(req *domain.CreateUserRequest) error {
    if req.Name == "" || len(req.Name) > 100 {
        return domain.ErrInvalidName
    }
    if req.Email == "" || !isValidEmail(req.Email) {
        return domain.ErrInvalidEmail
    }
    if len(req.Password) < 8 {
        return domain.ErrWeakPassword
    }
    if isRestrictedEmailDomain(req.Email) {
        return domain.ErrRestrictedEmailDomain
    }
    return nil
}

func (s *userService) recordChanges(user *domain.User, req *domain.UpdateUserRequest) string {
    var changes []string
    
    if req.Name != "" && req.Name != user.Name {
        changes = append(changes, fmt.Sprintf("name: %s -> %s", user.Name, req.Name))
    }
    if req.Email != "" && req.Email != user.Email {
        changes = append(changes, fmt.Sprintf("email: %s -> %s", user.Email, req.Email))
    }
    if req.Role != "" && req.Role != user.Role {
        changes = append(changes, fmt.Sprintf("role: %s -> %s", user.Role, req.Role))
    }
    if req.Status != "" && req.Status != user.Status {
        changes = append(changes, fmt.Sprintf("status: %s -> %s", user.Status, req.Status))
    }
    
    if len(changes) == 0 {
        return "No changes made"
    }
    
    return strings.Join(changes, ", ")
}

func (s *userService) getClientIP(ctx context.Context) string {
    // Extract client IP from context
    if ip, ok := ctx.Value("client_ip").(string); ok {
        return ip
    }
    return "unknown"
}

func (s *userService) getUserAgent(ctx context.Context) string {
    // Extract user agent from context
    if ua, ok := ctx.Value("user_agent").(string); ok {
        return ua
    }
    return "unknown"
}
```

## 🔄 Concurrency Patterns

### **MVP Tier - Basic Goroutines**

```go
// internal/concurrency/basic.go - Simple concurrency
package concurrency

import (
    "fmt"
    "sync"
    "time"
)

type Worker struct {
    id int
}

func (w *Worker) Process(task string) {
    fmt.Printf("Worker %d processing: %s\n", w.id, task)
    time.Sleep(100 * time.Millisecond) // Simulate work
    fmt.Printf("Worker %d completed: %s\n", w.id, task)
}

func BasicConcurrentProcessing() {
    tasks := []string{"task1", "task2", "task3", "task4", "task5"}
    
    var wg sync.WaitGroup
    
    for i, task := range tasks {
        wg.Add(1)
        go func(id int, t string) {
            defer wg.Done()
            worker := &Worker{id: id}
            worker.Process(t)
        }(i+1, task)
    }
    
    wg.Wait()
    fmt.Println("All tasks completed")
}

func BasicChannelExample() {
    jobs := make(chan int, 100)
    results := make(chan int, 100)
    
    // Start workers
    for w := 1; w <= 3; w++ {
        go func(id int) {
            for j := range jobs {
                fmt.Printf("Worker %d started job %d\n", id, j)
                time.Sleep(time.Second)
                results <- j * 2
                fmt.Printf("Worker %d finished job %d\n", id, j)
            }
        }(w)
    }
    
    // Send jobs
    for j := 1; j <= 5; j++ {
        jobs <- j
    }
    close(jobs)
    
    // Collect results
    for a := 1; a <= 5; a++ {
        <-results
    }
}
```

### **CORE Tier - Worker Pool Pattern**

```go
// internal/concurrency/worker_pool.go - Production worker pool
package concurrency

import (
    "context"
    "fmt"
    "runtime"
    "sync"
    "time"
)

type Task struct {
    ID   int
    Data interface{}
}

type Result struct {
    TaskID int
    Data   interface{}
    Error  error
}

type Worker struct {
    id       int
    taskChan <-chan Task
    resultChan chan<- Result
    ctx      context.Context
    handler  TaskHandler
}

type TaskHandler func(ctx context.Context, task Task) (interface{}, error)

func NewWorker(id int, taskChan <-chan Task, resultChan chan<- Result, ctx context.Context, handler TaskHandler) *Worker {
    return &Worker{
        id:         id,
        taskChan:   taskChan,
        resultChan: resultChan,
        ctx:        ctx,
        handler:    handler,
    }
}

func (w *Worker) Start() {
    go func() {
        for {
            select {
            case task, ok := <-w.taskChan:
                if !ok {
                    return // Channel closed
                }
                
                result := w.processTask(task)
                w.resultChan <- result
                
            case <-w.ctx.Done():
                return // Context cancelled
            }
        }
    }()
}

func (w *Worker) processTask(task Task) Result {
    data, err := w.handler(w.ctx, task)
    return Result{
        TaskID: task.ID,
        Data:   data,
        Error:  err,
    }
}

type WorkerPool struct {
    workers    []*Worker
    taskChan   chan Task
    resultChan chan Result
    ctx        context.Context
    cancel     context.CancelFunc
    wg         sync.WaitGroup
}

func NewWorkerPool(numWorkers int, handler TaskHandler) *WorkerPool {
    if numWorkers <= 0 {
        numWorkers = runtime.NumCPU()
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    taskChan := make(chan Task, numWorkers*2)
    resultChan := make(chan Result, numWorkers*2)
    
    pool := &WorkerPool{
        taskChan:   taskChan,
        resultChan: resultChan,
        ctx:        ctx,
        cancel:     cancel,
    }
    
    // Create workers
    for i := 0; i < numWorkers; i++ {
        worker := NewWorker(i+1, taskChan, resultChan, ctx, handler)
        pool.workers = append(pool.workers, worker)
    }
    
    return pool
}

func (p *WorkerPool) Start() {
    for _, worker := range p.workers {
        p.wg.Add(1)
        go func(w *Worker) {
            defer p.wg.Done()
            w.Start()
        }(worker)
    }
}

func (p *WorkerPool) Stop() {
    p.cancel()
    close(p.taskChan)
    p.wg.Wait()
    close(p.resultChan)
}

func (p *WorkerPool) Submit(task Task) {
    select {
    case p.taskChan <- task:
    case <-p.ctx.Done():
        return
    }
}

func (p *WorkerPool) Results() <-chan Result {
    return p.resultChan
}

func (p *WorkerPool) SubmitBatch(tasks []Task) {
    for _, task := range tasks {
        p.Submit(task)
    }
}

// Example usage
func ExampleWorkerPool() {
    // Define task handler
    handler := func(ctx context.Context, task Task) (interface{}, error) {
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        default:
            // Simulate work
            time.Sleep(100 * time.Millisecond)
            return fmt.Sprintf("Processed task %d", task.ID), nil
        }
    }
    
    // Create worker pool
    pool := NewWorkerPool(4, handler)
    pool.Start()
    defer pool.Stop()
    
    // Submit tasks
    for i := 1; i <= 10; i++ {
        task := Task{ID: i, Data: fmt.Sprintf("data %d", i)}
        pool.Submit(task)
    }
    
    // Collect results
    for i := 0; i < 10; i++ {
        result := <-pool.Results()
        if result.Error != nil {
            fmt.Printf("Task %d failed: %v\n", result.TaskID, result.Error)
        } else {
            fmt.Printf("Task %d result: %v\n", result.TaskID, result.Data)
        }
    }
}
```

### **FULL Tier - Advanced Concurrency Patterns**

```go
// internal/concurrency/advanced.go - Enterprise concurrency patterns
package concurrency

import (
    "context"
    "fmt"
    "sync"
    "time"
)

type FanInPattern struct{}

func (f *FanInPattern) Process() {
    // Fan-in pattern: multiple goroutines sending to one channel
    input1 := make(chan int)
    input2 := make(chan int)
    output := make(chan int)
    
    // Producer goroutines
    go func() {
        defer close(input1)
        for i := 0; i < 5; i++ {
            input1 <- i
            time.Sleep(100 * time.Millisecond)
        }
    }()
    
    go func() {
        defer close(input2)
        for i := 5; i < 10; i++ {
            input2 <- i
            time.Sleep(100 * time.Millisecond)
        }
    }()
    
    // Fan-in goroutine
    go func() {
        defer close(output)
        for input1 != nil || input2 != nil {
            select {
            case value, ok := <-input1:
                if ok {
                    output <- value * 2
                } else {
                    input1 = nil
                }
            case value, ok := <-input2:
                if ok {
                    output <- value * 3
                } else {
                    input2 = nil
                }
            }
        }
    }()
    
    // Consumer
    for value := range output {
        fmt.Printf("Received: %d\n", value)
    }
}

type FanOutPattern struct{}

func (f *FanOutPattern) Process() {
    // Fan-out pattern: one goroutine sending to multiple channels
    input := make(chan int, 10)
    
    // Fill input channel
    go func() {
        defer close(input)
        for i := 1; i <= 10; i++ {
            input <- i
        }
    }()
    
    // Create multiple workers
    numWorkers := 3
    var wg sync.WaitGroup
    
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            for value := range input {
                result := value * (workerID + 1)
                fmt.Printf("Worker %d: %d -> %d\n", workerID, value, result)
                time.Sleep(50 * time.Millisecond)
            }
        }(i)
    }
    
    wg.Wait()
}

type PipelinePattern struct{}

func (p *PipelinePattern) Process() {
    // Pipeline pattern: chain of processing stages
    type Data struct {
        Value int
        Stage string
    }
    
    stage1 := make(chan Data, 10)
    stage2 := make(chan Data, 10)
    stage3 := make(chan Data, 10)
    
    // Stage 1: Generate data
    go func() {
        defer close(stage1)
        for i := 1; i <= 5; i++ {
            stage1 <- Data{Value: i, Stage: "generated"}
        }
    }()
    
    // Stage 2: Process data
    go func() {
        defer close(stage2)
        for data := range stage1 {
            data.Value *= 2
            data.Stage = "processed"
            stage2 <- data
            time.Sleep(100 * time.Millisecond)
        }
    }()
    
    // Stage 3: Final processing
    go func() {
        defer close(stage3)
        for data := range stage2 {
            data.Value += 10
            data.Stage = "finalized"
            stage3 <- data
            time.Sleep(50 * time.Millisecond)
        }
    }()
    
    // Collect results
    for data := range stage3 {
        fmt.Printf("Final result: %+v\n", data)
    }
}

type RateLimiter struct {
    rate       time.Duration
    tokenChan  chan struct{}
    stopChan   chan struct{}
}

func NewRateLimiter(rate time.Duration) *RateLimiter {
    rl := &RateLimiter{
        rate:      rate,
        tokenChan: make(chan struct{}, 1),
        stopChan:  make(chan struct{}),
    }
    
    go rl.generateTokens()
    return rl
}

func (rl *RateLimiter) generateTokens() {
    ticker := time.NewTicker(rl.rate)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            select {
            case rl.tokenChan <- struct{}{}:
            default:
                // Token channel full, skip
            }
        case <-rl.stopChan:
            return
        }
    }
}

func (rl *RateLimiter) Wait() {
    <-rl.tokenChan
}

func (rl *RateLimiter) Stop() {
    close(rl.stopChan)
}

func ExampleRateLimiting() {
    limiter := NewRateLimiter(200 * time.Millisecond) // 5 requests per second
    defer limiter.Stop()
    
    for i := 1; i <= 10; i++ {
        limiter.Wait()
        fmt.Printf("Request %d processed at %v\n", i, time.Now().Format("15:04:05.000"))
    }
}

type CircuitBreaker struct {
    maxFailures  int
    resetTimeout time.Duration
    failures     int
    lastFailTime time.Time
    state        string // "closed", "open", "half-open"
    mu           sync.RWMutex
}

func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
    return &CircuitBreaker{
        maxFailures:  maxFailures,
        resetTimeout: resetTimeout,
        state:        "closed",
    }
}

func (cb *CircuitBreaker) Call(fn func() error) error {
    cb.mu.Lock()
    defer cb.mu.Unlock()
    
    // Check if circuit should reset
    if cb.state == "open" && time.Since(cb.lastFailTime) > cb.resetTimeout {
        cb.state = "half-open"
        cb.failures = 0
    }
    
    // Reject calls if circuit is open
    if cb.state == "open" {
        return fmt.Errorf("circuit breaker is open")
    }
    
    // Execute function
    err := fn()
    
    if err != nil {
        cb.failures++
        cb.lastFailTime = time.Now()
        
        if cb.failures >= cb.maxFailures {
            cb.state = "open"
        }
        
        return err
    }
    
    // Reset on success
    if cb.state == "half-open" {
        cb.state = "closed"
    }
    cb.failures = 0
    
    return nil
}

func (cb *CircuitBreaker) State() string {
    cb.mu.RLock()
    defer cb.mu.RUnlock()
    return cb.state
}

func ExampleCircuitBreaker() {
    cb := NewCircuitBreaker(3, 5*time.Second)
    
    callCount := 0
    unreliableFunction := func() error {
        callCount++
        if callCount <= 5 {
            return fmt.Errorf("service unavailable")
        }
        return nil
    }
    
    for i := 1; i <= 10; i++ {
        err := cb.Call(unreableFunction)
        if err != nil {
            fmt.Printf("Call %d failed: %v (circuit: %s)\n", i, err, cb.State())
        } else {
            fmt.Printf("Call %d succeeded (circuit: %s)\n", i, cb.State())
        }
        time.Sleep(500 * time.Millisecond)
    }
}
```

## 🚀 Performance Architecture

### **MVP Tier - Basic Performance**

```go
// internal/performance/basic.go - Simple performance optimizations
package performance

import (
    "sync"
    "time"
)

type Memoizer struct {
    cache map[string]interface{}
    mu    sync.RWMutex
}

func NewMemoizer() *Memoizer {
    return &Memoizer{
        cache: make(map[string]interface{}),
    }
}

func (m *Memoizer) Get(key string, fn func() interface{}) interface{} {
    // Check cache first
    m.mu.RLock()
    if value, exists := m.cache[key]; exists {
        m.mu.RUnlock()
        return value
    }
    m.mu.RUnlock()
    
    // Compute value
    value := fn()
    
    // Store in cache
    m.mu.Lock()
    m.cache[key] = value
    m.mu.Unlock()
    
    return value
}

func (m *Memoizer) Clear() {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.cache = make(map[string]interface{})
}

// Object pooling for memory efficiency
type ObjectPool struct {
    pool chan interface{}
    factory func() interface{}
}

func NewObjectPool(size int, factory func() interface{}) *ObjectPool {
    pool := &ObjectPool{
        pool:    make(chan interface{}, size),
        factory: factory,
    }
    
    // Pre-fill pool
    for i := 0; i < size; i++ {
        pool.pool <- factory()
    }
    
    return pool
}

func (p *ObjectPool) Get() interface{} {
    select {
    case obj := <-p.pool:
        return obj
    default:
        return p.factory()
    }
}

func (p *ObjectPool) Put(obj interface{}) {
    select {
    case p.pool <- obj:
    default:
        // Pool full, discard object
    }
}

// Simple metrics collection
type Metrics struct {
    requestCount int64
    errorCount   int64
    totalTime    time.Duration
    mu           sync.RWMutex
}

func (m *Metrics) RecordRequest(duration time.Duration, isError bool) {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    m.requestCount++
    m.totalTime += duration
    
    if isError {
        m.errorCount++
    }
}

func (m *Metrics) GetStats() (int64, int64, time.Duration) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    return m.requestCount, m.errorCount, m.totalTime
}

func (m *Metrics) GetAverageResponseTime() time.Duration {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    if m.requestCount == 0 {
        return 0
    }
    
    return m.totalTime / time.Duration(m.requestCount)
}
```

### **CORE Tier - Production Performance**

```go
// internal/performance/production.go - Production performance optimizations
package performance

import (
    "context"
    "runtime"
    "sync"
    "sync/atomic"
    "time"
)

type PerformanceMonitor struct {
    requestCount    int64
    errorCount      int64
    activeRequests  int64
    totalResponseTime int64 // nanoseconds
    maxResponseTime int64 // nanoseconds
    minResponseTime int64 // nanoseconds
    
    goroutineCount int64
    memoryUsage    int64
    gcCount        int32
    
    mu sync.RWMutex
}

func NewPerformanceMonitor() *PerformanceMonitor {
    pm := &PerformanceMonitor{
        minResponseTime: int64(time.Hour), // Initialize to large value
    }
    
    // Start background monitoring
    go pm.backgroundMonitoring()
    
    return pm
}

func (pm *PerformanceMonitor) RecordRequestStart() {
    atomic.AddInt64(&pm.activeRequests, 1)
}

func (pm *PerformanceMonitor) RecordRequestEnd(duration time.Duration, isError bool) {
    durationNanos := duration.Nanoseconds()
    
    atomic.AddInt64(&pm.activeRequests, -1)
    atomic.AddInt64(&pm.requestCount, 1)
    atomic.AddInt64(&pm.totalResponseTime, durationNanos)
    
    if isError {
        atomic.AddInt64(&pm.errorCount, 1)
    }
    
    // Update min/max response times
    for {
        current := atomic.LoadInt64(&pm.maxResponseTime)
        if durationNanos <= current || atomic.CompareAndSwapInt64(&pm.maxResponseTime, current, durationNanos) {
            break
        }
    }
    
    for {
        current := atomic.LoadInt64(&pm.minResponseTime)
        if durationNanos >= current || atomic.CompareAndSwapInt64(&pm.minResponseTime, current, durationNanos) {
            break
        }
    }
}

func (pm *PerformanceMonitor) GetStats() PerformanceStats {
    pm.mu.RLock()
    defer pm.mu.RUnlock()
    
    requestCount := atomic.LoadInt64(&pm.requestCount)
    errorCount := atomic.LoadInt64(&pm.errorCount)
    activeRequests := atomic.LoadInt64(&pm.activeRequests)
    totalResponseTime := atomic.LoadInt64(&pm.totalResponseTime)
    maxResponseTime := atomic.LoadInt64(&pm.maxResponseTime)
    minResponseTime := atomic.LoadInt64(&pm.minResponseTime)
    
    var avgResponseTime time.Duration
    if requestCount > 0 {
        avgResponseTime = time.Duration(totalResponseTime / requestCount)
    }
    
    return PerformanceStats{
        RequestCount:      requestCount,
        ErrorCount:        errorCount,
        ActiveRequests:    activeRequests,
        AverageResponseTime: avgResponseTime,
        MaxResponseTime:   time.Duration(maxResponseTime),
        MinResponseTime:   time.Duration(minResponseTime),
        ErrorRate:         float64(errorCount) / float64(requestCount),
        GoroutineCount:    atomic.LoadInt64(&pm.goroutineCount),
        MemoryUsage:       atomic.LoadInt64(&pm.memoryUsage),
        GCCount:           atomic.LoadInt32(&pm.gcCount),
    }
}

func (pm *PerformanceMonitor) backgroundMonitoring() {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    var m1, m2 runtime.MemStats
    
    for range ticker.C {
        // Update goroutine count
        atomic.StoreInt64(&pm.goroutineCount, int64(runtime.NumGoroutine()))
        
        // Update memory usage
        runtime.ReadMemStats(&m1)
        atomic.StoreInt64(&pm.memoryUsage, int64(m1.Alloc))
        
        // Update GC count
        atomic.StoreInt32(&pm.gcCount, int32(m1.NumGC))
    }
}

type PerformanceStats struct {
    RequestCount        int64
    ErrorCount          int64
    ActiveRequests      int64
    AverageResponseTime time.Duration
    MaxResponseTime     time.Duration
    MinResponseTime     time.Duration
    ErrorRate           float64
    GoroutineCount      int64
    MemoryUsage         int64
    GCCount             int32
}

// Connection pool with health checking
type ConnectionPool struct {
    connections chan interface{}
    factory     func() (interface{}, error)
    healthCheck func(interface{}) error
    maxSize     int
    currentSize int64
    mu          sync.RWMutex
}

func NewConnectionPool(maxSize int, factory func() (interface{}, error), healthCheck func(interface{}) error) *ConnectionPool {
    return &ConnectionPool{
        connections: make(chan interface{}, maxSize),
        factory:     factory,
        healthCheck: healthCheck,
        maxSize:     maxSize,
    }
}

func (p *ConnectionPool) Get(ctx context.Context) (interface{}, error) {
    select {
    case conn := <-p.connections:
        // Check connection health
        if p.healthCheck != nil {
            if err := p.healthCheck(conn); err != nil {
                // Connection is unhealthy, create a new one
                return p.factory()
            }
        }
        return conn, nil
    case <-ctx.Done():
        return nil, ctx.Err()
    default:
        // No available connections, create new one if under limit
        if atomic.LoadInt64(&p.currentSize) < int64(p.maxSize) {
            atomic.AddInt64(&p.currentSize, 1)
            return p.factory()
        }
        
        // Wait for a connection to become available
        select {
        case conn := <-p.connections:
            if p.healthCheck != nil {
                if err := p.healthCheck(conn); err != nil {
                    return p.factory()
                }
            }
            return conn, nil
        case <-ctx.Done():
            return nil, ctx.Err()
        }
    }
}

func (p *ConnectionPool) Put(conn interface{}) {
    select {
    case p.connections <- conn:
    default:
        // Pool full, discard connection
        atomic.AddInt64(&p.currentSize, -1)
    }
}

func (p *ConnectionPool) Close() {
    close(p.connections)
    for conn := range p.connections {
        // Close connection if it has a Close method
        if closer, ok := conn.(interface{ Close() error }); ok {
            closer.Close()
        }
    }
}

// Rate limiter with token bucket algorithm
type TokenBucket struct {
    capacity   int64
    tokens     int64
    refillRate int64
    lastRefill time.Time
    mu         sync.Mutex
}

func NewTokenBucket(capacity, refillRate int64) *TokenBucket {
    return &TokenBucket{
        capacity:   capacity,
        tokens:     capacity,
        refillRate: refillRate,
        lastRefill: time.Now(),
    }
}

func (tb *TokenBucket) Take(tokens int64) bool {
    tb.mu.Lock()
    defer tb.mu.Unlock()
    
    // Refill tokens based on time elapsed
    now := time.Now()
    elapsed := now.Sub(tb.lastRefill)
    tokensToAdd := int64(elapsed.Seconds()) * tb.refillRate
    
    if tokensToAdd > 0 {
        tb.tokens = min(tb.capacity, tb.tokens+tokensToAdd)
        tb.lastRefill = now
    }
    
    if tb.tokens >= tokens {
        tb.tokens -= tokens
        return true
    }
    
    return false
}

func min(a, b int64) int64 {
    if a < b {
        return a
    }
    return b
}
```

### **FULL Tier - Enterprise Performance**

```go
// internal/performance/enterprise.go - Enterprise performance optimizations
package performance

import (
    "context"
    "runtime"
    "sync"
    "sync/atomic"
    "time"
)

type EnterprisePerformanceMonitor struct {
    // Basic metrics
    requestCount    int64
    errorCount      int64
    activeRequests  int64
    totalResponseTime int64
    
    // Advanced metrics
    responseTimes   []int64 // sliding window of response times
    throughput      int64   // requests per second
    p95ResponseTime int64   // 95th percentile
    p99ResponseTime int64   // 99th percentile
    
    // System metrics
    goroutineCount int64
    memoryUsage    int64
    gcCount        int32
    gcPauseTime    int64
    
    // Custom metrics
    customMetrics  sync.Map
    alerts         chan Alert
    
    mu sync.RWMutex
    ctx context.Context
    cancel context.CancelFunc
}

type Alert struct {
    Type      string
    Message   string
    Severity  string
    Timestamp time.Time
    Metrics   map[string]interface{}
}

func NewEnterprisePerformanceMonitor(ctx context.Context) *EnterprisePerformanceMonitor {
    monitorCtx, cancel := context.WithCancel(ctx)
    
    pm := &EnterprisePerformanceMonitor{
        responseTimes: make([]int64, 0, 1000),
        alerts:        make(chan Alert, 100),
        ctx:           monitorCtx,
        cancel:        cancel,
    }
    
    // Start background monitoring
    go pm.backgroundMonitoring()
    go pm.alertManager()
    
    return pm
}

func (pm *EnterprisePerformanceMonitor) RecordRequest(duration time.Duration, isError bool) {
    durationNanos := duration.Nanoseconds()
    
    atomic.AddInt64(&pm.requestCount, 1)
    atomic.AddInt64(&pm.totalResponseTime, durationNanos)
    
    if isError {
        atomic.AddInt64(&pm.errorCount, 1)
    }
    
    // Update response time sliding window
    pm.updateResponseTimes(durationNanos)
    
    // Check for alerts
    pm.checkAlerts(duration, isError)
}

func (pm *EnterprisePerformanceMonitor) updateResponseTimes(durationNanos int64) {
    pm.mu.Lock()
    defer pm.mu.Unlock()
    
    pm.responseTimes = append(pm.responseTimes, durationNanos)
    
    // Keep only last 1000 measurements
    if len(pm.responseTimes) > 1000 {
        pm.responseTimes = pm.responseTimes[1:]
    }
    
    // Calculate percentiles
    if len(pm.responseTimes) > 0 {
        sorted := make([]int64, len(pm.responseTimes))
        copy(sorted, pm.responseTimes)
        
        // Simple sort (in production, use more efficient algorithm)
        for i := 0; i < len(sorted); i++ {
            for j := i + 1; j < len(sorted); j++ {
                if sorted[i] > sorted[j] {
                    sorted[i], sorted[j] = sorted[j], sorted[i]
                }
            }
        }
        
        p95Index := int(float64(len(sorted)) * 0.95)
        p99Index := int(float64(len(sorted)) * 0.99)
        
        if p95Index < len(sorted) {
            pm.p95ResponseTime = sorted[p95Index]
        }
        if p99Index < len(sorted) {
            pm.p99ResponseTime = sorted[p99Index]
        }
    }
}

func (pm *EnterprisePerformanceMonitor) checkAlerts(duration time.Duration, isError bool) {
    // High response time alert
    if duration > 5*time.Second {
        pm.sendAlert(Alert{
            Type:      "high_response_time",
            Message:   fmt.Sprintf("High response time detected: %v", duration),
            Severity:  "warning",
            Timestamp: time.Now(),
            Metrics: map[string]interface{}{
                "response_time": duration,
            },
        })
    }
    
    // High error rate alert
    requestCount := atomic.LoadInt64(&pm.requestCount)
    errorCount := atomic.LoadInt64(&pm.errorCount)
    
    if requestCount > 100 {
        errorRate := float64(errorCount) / float64(requestCount)
        if errorRate > 0.05 { // 5% error rate
            pm.sendAlert(Alert{
                Type:      "high_error_rate",
                Message:   fmt.Sprintf("High error rate detected: %.2f%%", errorRate*100),
                Severity:  "critical",
                Timestamp: time.Now(),
                Metrics: map[string]interface{}{
                    "error_rate": errorRate,
                    "error_count": errorCount,
                    "request_count": requestCount,
                },
            })
        }
    }
    
    // Memory usage alert
    memoryUsage := atomic.LoadInt64(&pm.memoryUsage)
    if memoryUsage > 1024*1024*1024 { // 1GB
        pm.sendAlert(Alert{
            Type:      "high_memory_usage",
            Message:   fmt.Sprintf("High memory usage detected: %d bytes", memoryUsage),
            Severity:  "warning",
            Timestamp: time.Now(),
            Metrics: map[string]interface{}{
                "memory_usage": memoryUsage,
            },
        })
    }
}

func (pm *EnterprisePerformanceMonitor) sendAlert(alert Alert) {
    select {
    case pm.alerts <- alert:
    default:
        // Alert channel full, drop alert
    }
}

func (pm *EnterprisePerformanceMonitor) alertManager() {
    for {
        select {
        case alert := <-pm.alerts:
            // Handle alert (log, send to monitoring system, etc.)
            fmt.Printf("ALERT [%s]: %s\n", alert.Severity, alert.Message)
        case <-pm.ctx.Done():
            return
        }
    }
}

func (pm *EnterprisePerformanceMonitor) backgroundMonitoring() {
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()
    
    var lastRequestCount int64
    var lastGCCount uint32
    
    for {
        select {
        case <-ticker.C:
            // Calculate throughput (requests per second)
            currentRequestCount := atomic.LoadInt64(&pm.requestCount)
            throughput := currentRequestCount - lastRequestCount
            atomic.StoreInt64(&pm.throughput, throughput)
            lastRequestCount = currentRequestCount
            
            // Update system metrics
            atomic.StoreInt64(&pm.goroutineCount, int64(runtime.NumGoroutine()))
            
            var m runtime.MemStats
            runtime.ReadMemStats(&m)
            atomic.StoreInt64(&pm.memoryUsage, int64(m.Alloc))
            atomic.StoreInt32(&pm.gcCount, int32(m.NumGC))
            
            // Calculate GC pause time
            if m.NumGC > lastGCCount {
                gcPauseTime := int64(m.PauseTotalNs) - atomic.LoadInt64(&pm.gcPauseTime)
                atomic.StoreInt64(&pm.gcPauseTime, gcPauseTime)
                lastGCCount = m.NumGC
            }
            
        case <-pm.ctx.Done():
            return
        }
    }
}

func (pm *EnterprisePerformanceMonitor) GetStats() EnterprisePerformanceStats {
    pm.mu.RLock()
    defer pm.mu.RUnlock()
    
    requestCount := atomic.LoadInt64(&pm.requestCount)
    errorCount := atomic.LoadInt64(&pm.errorCount)
    totalResponseTime := atomic.LoadInt64(&pm.totalResponseTime)
    throughput := atomic.LoadInt64(&pm.throughput)
    
    var avgResponseTime time.Duration
    if requestCount > 0 {
        avgResponseTime = time.Duration(totalResponseTime / requestCount)
    }
    
    return EnterprisePerformanceStats{
        RequestCount:        requestCount,
        ErrorCount:          errorCount,
        Throughput:          throughput,
        AverageResponseTime: avgResponseTime,
        P95ResponseTime:     time.Duration(pm.p95ResponseTime),
        P99ResponseTime:     time.Duration(pm.p99ResponseTime),
        ErrorRate:           float64(errorCount) / float64(requestCount),
        GoroutineCount:      atomic.LoadInt64(&pm.goroutineCount),
        MemoryUsage:         atomic.LoadInt64(&pm.memoryUsage),
        GCCount:             atomic.LoadInt32(&pm.gcCount),
        GCPauseTime:         time.Duration(atomic.LoadInt64(&pm.gcPauseTime)),
    }
}

func (pm *EnterprisePerformanceMonitor) SetCustomMetric(name string, value interface{}) {
    pm.customMetrics.Store(name, value)
}

func (pm *EnterprisePerformanceMonitor) GetCustomMetric(name string) (interface{}, bool) {
    return pm.customMetrics.Load(name)
}

func (pm *EnterprisePerformanceMonitor) Stop() {
    pm.cancel()
}

type EnterprisePerformanceStats struct {
    RequestCount        int64
    ErrorCount          int64
    Throughput          int64
    AverageResponseTime time.Duration
    P95ResponseTime     time.Duration
    P99ResponseTime     time.Duration
    ErrorRate           float64
    GoroutineCount      int64
    MemoryUsage         int64
    GCCount             int32
    GCPauseTime         time.Duration
}

// Adaptive connection pool
type AdaptiveConnectionPool struct {
    connections    chan interface{}
    factory        func() (interface{}, error)
    healthCheck    func(interface{}) error
    maxSize        int
    minSize        int
    currentSize    int64
    targetSize     int64
    lastAdjustTime time.Time
    
    // Performance metrics
    avgWaitTime    time.Duration
    utilization    float64
    
    mu sync.RWMutex
}

func NewAdaptiveConnectionPool(minSize, maxSize int, factory func() (interface{}, error), healthCheck func(interface{}) error) *AdaptiveConnectionPool {
    pool := &AdaptiveConnectionPool{
        connections:    make(chan interface{}, maxSize),
        factory:        factory,
        healthCheck:    healthCheck,
        maxSize:        maxSize,
        minSize:        minSize,
        targetSize:     int64(minSize),
        lastAdjustTime: time.Now(),
    }
    
    // Pre-fill with minimum connections
    for i := 0; i < minSize; i++ {
        if conn, err := factory(); err == nil {
            pool.connections <- conn
            atomic.AddInt64(&pool.currentSize, 1)
        }
    }
    
    go pool.adaptiveSizing()
    
    return pool
}

func (p *AdaptiveConnectionPool) Get(ctx context.Context) (interface{}, error) {
    start := time.Now()
    defer func() {
        p.updateWaitTime(time.Since(start))
    }()
    
    select {
    case conn := <-p.connections:
        if p.healthCheck != nil {
            if err := p.healthCheck(conn); err != nil {
                return p.factory()
            }
        }
        return conn, nil
    case <-ctx.Done():
        return nil, ctx.Err()
    default:
        if atomic.LoadInt64(&p.currentSize) < int64(p.maxSize) {
            atomic.AddInt64(&p.currentSize, 1)
            return p.factory()
        }
        
        select {
        case conn := <-p.connections:
            if p.healthCheck != nil {
                if err := p.healthCheck(conn); err != nil {
                    return p.factory()
                }
            }
            return conn, nil
        case <-ctx.Done():
            return nil, ctx.Err()
        }
    }
}

func (p *AdaptiveConnectionPool) Put(conn interface{}) {
    select {
    case p.connections <- conn:
    default:
        atomic.AddInt64(&p.currentSize, -1)
    }
}

func (p *AdaptiveConnectionPool) updateWaitTime(waitTime time.Duration) {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    // Simple exponential moving average
    if p.avgWaitTime == 0 {
        p.avgWaitTime = waitTime
    } else {
        p.avgWaitTime = (p.avgWaitTime*9 + waitTime) / 10
    }
    
    // Update utilization
    currentSize := atomic.LoadInt64(&p.currentSize)
    p.utilization = float64(len(p.connections)) / float64(currentSize)
}

func (p *AdaptiveConnectionPool) adaptiveSizing() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        p.mu.Lock()
        
        currentSize := atomic.LoadInt64(&p.currentSize)
        
        // Adjust pool size based on metrics
        if p.avgWaitTime > 100*time.Millisecond && currentSize < int64(p.maxSize) {
            // Increase pool size if wait time is high
            p.targetSize = min(int64(p.maxSize), currentSize+2)
        } else if p.utilization < 0.3 && currentSize > int64(p.minSize) {
            // Decrease pool size if utilization is low
            p.targetSize = max(int64(p.minSize), currentSize-1)
        }
        
        // Apply size changes
        if p.targetSize > currentSize {
            for i := currentSize; i < p.targetSize; i++ {
                if conn, err := p.factory(); err == nil {
                    select {
                    case p.connections <- conn:
                        atomic.AddInt64(&p.currentSize, 1)
                    default:
                        break
                    }
                }
            }
        } else if p.targetSize < currentSize {
            // Let connections be naturally reduced through time
        }
        
        p.lastAdjustTime = time.Now()
        p.mu.Unlock()
    }
}

func min(a, b int64) int64 {
    if a < b {
        return a
    }
    return b
}

func max(a, b int64) int64 {
    if a > b {
        return a
    }
    return b
}
```

---

**Go Version**: [GO_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
