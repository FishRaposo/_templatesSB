// File: service_layer.tpl.go
// Purpose: Service layer pattern with interfaces
// Generated for: {{PROJECT_NAME}}

package services

import (
	"context"
	"errors"
	"time"
)

// Common errors
var (
	ErrNotFound      = errors.New("entity not found")
	ErrAlreadyExists = errors.New("entity already exists")
	ErrInvalidInput  = errors.New("invalid input")
	ErrUnauthorized  = errors.New("unauthorized")
)

// Result represents a service operation result
type Result[T any] struct {
	Success   bool
	Data      T
	Error     error
	ErrorCode string
}

// Ok creates a successful result
func Ok[T any](data T) Result[T] {
	return Result[T]{Success: true, Data: data}
}

// Fail creates a failed result
func Fail[T any](err error, code string) Result[T] {
	var zero T
	return Result[T]{Success: false, Error: err, ErrorCode: code, Data: zero}
}

// Repository interface
type Repository[T any, ID any] interface {
	FindByID(ctx context.Context, id ID) (*T, error)
	FindAll(ctx context.Context, opts FindOptions) ([]T, int64, error)
	Create(ctx context.Context, entity *T) error
	Update(ctx context.Context, entity *T) error
	Delete(ctx context.Context, id ID) error
}

// FindOptions for pagination and filtering
type FindOptions struct {
	Page    int
	PerPage int
	OrderBy string
	Order   string // asc, desc
	Filters map[string]interface{}
}

// DefaultFindOptions returns default options
func DefaultFindOptions() FindOptions {
	return FindOptions{
		Page:    1,
		PerPage: 20,
		OrderBy: "created_at",
		Order:   "desc",
		Filters: make(map[string]interface{}),
	}
}

// PaginatedResult for list operations
type PaginatedResult[T any] struct {
	Data       []T   `json:"data"`
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// BaseService with common CRUD operations
type BaseService[T any, ID any] struct {
	repo Repository[T, ID]
}

// NewBaseService creates a new base service
func NewBaseService[T any, ID any](repo Repository[T, ID]) *BaseService[T, ID] {
	return &BaseService[T, ID]{repo: repo}
}

// Get retrieves an entity by ID
func (s *BaseService[T, ID]) Get(ctx context.Context, id ID) Result[*T] {
	entity, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return Fail[*T](err, "NOT_FOUND")
	}
	return Ok(entity)
}

// List retrieves entities with pagination
func (s *BaseService[T, ID]) List(ctx context.Context, opts FindOptions) Result[PaginatedResult[T]] {
	data, total, err := s.repo.FindAll(ctx, opts)
	if err != nil {
		return Fail[PaginatedResult[T]](err, "LIST_FAILED")
	}

	totalPages := int(total) / opts.PerPage
	if int(total)%opts.PerPage > 0 {
		totalPages++
	}

	return Ok(PaginatedResult[T]{
		Data:       data,
		Page:       opts.Page,
		PerPage:    opts.PerPage,
		Total:      total,
		TotalPages: totalPages,
	})
}

// Create creates a new entity
func (s *BaseService[T, ID]) Create(ctx context.Context, entity *T) Result[*T] {
	if err := s.repo.Create(ctx, entity); err != nil {
		return Fail[*T](err, "CREATE_FAILED")
	}
	return Ok(entity)
}

// Update updates an entity
func (s *BaseService[T, ID]) Update(ctx context.Context, entity *T) Result[*T] {
	if err := s.repo.Update(ctx, entity); err != nil {
		return Fail[*T](err, "UPDATE_FAILED")
	}
	return Ok(entity)
}

// Delete deletes an entity
func (s *BaseService[T, ID]) Delete(ctx context.Context, id ID) Result[bool] {
	if err := s.repo.Delete(ctx, id); err != nil {
		return Fail[bool](err, "DELETE_FAILED")
	}
	return Ok(true)
}

// EventBus for domain events
type Event struct {
	Type        string
	AggregateID interface{}
	Payload     interface{}
	OccurredAt  time.Time
}

type EventHandler func(ctx context.Context, event Event) error

type EventBus struct {
	handlers map[string][]EventHandler
}

func NewEventBus() *EventBus {
	return &EventBus{
		handlers: make(map[string][]EventHandler),
	}
}

func (eb *EventBus) Subscribe(eventType string, handler EventHandler) {
	eb.handlers[eventType] = append(eb.handlers[eventType], handler)
}

func (eb *EventBus) Publish(ctx context.Context, event Event) error {
	handlers := eb.handlers[event.Type]
	for _, handler := range handlers {
		if err := handler(ctx, event); err != nil {
			// Log error but continue with other handlers
			continue
		}
	}
	return nil
}

// UnitOfWork for transaction management
type UnitOfWork interface {
	Begin(ctx context.Context) (context.Context, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Example User service
type UserService struct {
	*BaseService[User, uint]
	eventBus       *EventBus
	passwordHasher PasswordHasher
}

type User struct {
	ID           uint
	Email        string
	Username     string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
}

type UserRepository interface {
	Repository[User, uint]
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByUsername(ctx context.Context, username string) (*User, error)
	UpdateLastLogin(ctx context.Context, id uint) error
}

func NewUserService(repo UserRepository, eventBus *EventBus, hasher PasswordHasher) *UserService {
	return &UserService{
		BaseService:    NewBaseService[User, uint](repo),
		eventBus:       eventBus,
		passwordHasher: hasher,
	}
}

func (s *UserService) Register(ctx context.Context, email, password, username string) Result[*User] {
	userRepo := s.repo.(UserRepository)

	// Check if email exists
	existing, _ := userRepo.FindByEmail(ctx, email)
	if existing != nil {
		return Fail[*User](ErrAlreadyExists, "EMAIL_EXISTS")
	}

	// Check if username exists
	existing, _ = userRepo.FindByUsername(ctx, username)
	if existing != nil {
		return Fail[*User](ErrAlreadyExists, "USERNAME_EXISTS")
	}

	// Hash password
	hash, err := s.passwordHasher.Hash(password)
	if err != nil {
		return Fail[*User](err, "HASH_FAILED")
	}

	// Create user
	user := &User{
		Email:        email,
		Username:     username,
		PasswordHash: hash,
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return Fail[*User](err, "CREATE_FAILED")
	}

	// Publish event
	s.eventBus.Publish(ctx, Event{
		Type:        "user.registered",
		AggregateID: user.ID,
		Payload:     map[string]string{"email": email},
		OccurredAt:  time.Now(),
	})

	return Ok(user)
}

func (s *UserService) Authenticate(ctx context.Context, email, password string) Result[*User] {
	userRepo := s.repo.(UserRepository)

	user, err := userRepo.FindByEmail(ctx, email)
	if err != nil || user == nil {
		return Fail[*User](ErrUnauthorized, "INVALID_CREDENTIALS")
	}

	if !s.passwordHasher.Verify(password, user.PasswordHash) {
		return Fail[*User](ErrUnauthorized, "INVALID_CREDENTIALS")
	}

	userRepo.UpdateLastLogin(ctx, user.ID)

	s.eventBus.Publish(ctx, Event{
		Type:        "user.authenticated",
		AggregateID: user.ID,
		Payload:     map[string]string{"email": email},
		OccurredAt:  time.Now(),
	})

	return Ok(user)
}
