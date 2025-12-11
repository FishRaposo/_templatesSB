<!--
File: mvp-go-example.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# MVP Go Example Project

## Overview

This example demonstrates a complete MVP Go backend application using the minimal boilerplate template with JWT authentication, basic CRUD operations, and simple API endpoints.

## Project Structure

```
mvp_go_example/
├── cmd/
│   └── server/
│       └── main.go                 # MVP boilerplate entry point
├── internal/
│   ├── config/
│   │   ├── app_config.go           # MVP configuration
│   │   └── env_config.go           # Environment settings
│   ├── core/
│   │   ├── constants.go            # App constants
│   │   ├── middleware.go           # HTTP middleware
│   │   └── routes.go               # Route definitions
│   ├── data/
│   │   ├── models/
│   │   │   ├── user.go              # User model
│   │   │   └── task.go              # Task model
│   │   ├── services/
│   │   │   ├── auth_service.go      # Authentication service
│   │   │   └── task_service.go      # Task management service
│   │   └── repositories/
│   │       └── task_repository.go   # Task data repository
│   ├── presentation/
│   │   ├── controllers/
│   │   │   ├── auth_controller.go   # Authentication endpoints
│   │   │   └── task_controller.go   # Task CRUD endpoints
│   │   ├── handlers/
│   │   │   ├── auth_handlers.go     # Authentication handlers
│   │   │   └── task_handlers.go     # Task handlers
│   │   └── middleware/
│   │       ├── auth_middleware.go   # JWT verification
│   │       └── error_middleware.go  # Error handling
│   └── utils/
│       ├── helpers.go               # Utility functions
│       └── validators.go            # Input validation
├── test/
│   ├── unit/
│   │   ├── services/
│   │   │   ├── auth_service_test.go
│   │   │   └── task_service_test.go
│   │   └── controllers/
│   │       ├── auth_controller_test.go
│   │       └── task_controller_test.go
│   └── integration/
│       ├── auth_test.go
│       └── tasks_test.go
├── data/
│   └── tasks.json                   # File-based storage
├── go.mod                           # Go modules
└── README.md                        # Project documentation
```

## Key Features Demonstrated

### 1. JWT Authentication
```go
// internal/services/auth_service.go
package services

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthService struct {
	jwtSecret []byte
	users     []User
}

type LoginResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	User    User   `json:"user,omitempty"`
	Error   string `json:"error,omitempty"`
}

type Claims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func NewAuthService() *AuthService {
	// Initialize with demo user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	
	return &AuthService{
		jwtSecret: []byte(os.Getenv("JWT_SECRET")),
		users: []User{
			{
				ID:       1,
				Email:    "test@example.com",
				Password: string(hashedPassword),
			},
		},
	}
}

func (s *AuthService) Login(email, password string) (*LoginResponse, error) {
	// Basic validation
	if !s.ValidateEmail(email) {
		return &LoginResponse{Success: false, Error: "Invalid email format"}, nil
	}
	
	// Find user
	var user *User
	for _, u := range s.users {
		if u.Email == email {
			user = &u
			break
		}
	}
	
	if user == nil {
		return &LoginResponse{Success: false, Error: "User not found"}, nil
	}
	
	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return &LoginResponse{Success: false, Error: "Invalid credentials"}, nil
	}
	
	// Generate JWT token
	token, err := s.GenerateToken(user.ID, user.Email)
	if err != nil {
		return nil, err
	}
	
	return &LoginResponse{
		Success: true,
		Token:   token,
		User:    User{ID: user.ID, Email: user.Email},
	}, nil
}

func (s *AuthService) GenerateToken(userID int, email string) (string, error) {
	claims := &Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *AuthService) VerifyToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	
	if err != nil {
		return nil, err
	}
	
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	
	return nil, errors.New("invalid token")
}

func (s *AuthService) ValidateEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, email)
	return matched
}
```

### 2. Task CRUD Operations
```go
// internal/services/task_service.go
package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Task struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	IsCompleted bool   `json:"is_completed"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	UserID      int    `json:"user_id"`
}

type TaskService struct {
	dataFile string
	mutex    sync.RWMutex
}

type TaskResponse struct {
	Success bool        `json:"success"`
	Task    *Task       `json:"task,omitempty"`
	Tasks   []Task      `json:"tasks,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func NewTaskService() *TaskService {
	return &TaskService{
		dataFile: "data/tasks.json",
	}
}

func (s *TaskService) GetTasks() ([]Task, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	// Simulate API delay
	time.Sleep(200 * time.Millisecond)
	
	return s.readDataFile()
}

func (s *TaskService) CreateTask(taskData *Task) (*TaskResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	tasks, err := s.readDataFile()
	if err != nil {
		return nil, err
	}
	
	newTask := Task{
		ID:          int(time.Now().Unix()),
		Title:       taskData.Title,
		Description: taskData.Description,
		IsCompleted: false,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
		UserID:      taskData.UserID,
	}
	
	tasks = append(tasks, newTask)
	
	if err := s.writeDataFile(tasks); err != nil {
		return nil, err
	}
	
	return &TaskResponse{
		Success: true,
		Task:    &newTask,
	}, nil
}

func (s *TaskService) UpdateTask(taskID int, updates map[string]interface{}, userID int) (*TaskResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	tasks, err := s.readDataFile()
	if err != nil {
		return nil, err
	}
	
	var task *Task
	taskIndex := -1
	
	for i, t := range tasks {
		if t.ID == taskID && t.UserID == userID {
			task = &t
			taskIndex = i
			break
		}
	}
	
	if task == nil {
		return &TaskResponse{Success: false, Error: "Task not found"}, nil
	}
	
	// Apply updates
	if title, ok := updates["title"].(string); ok {
		task.Title = title
	}
	if description, ok := updates["description"].(string); ok {
		task.Description = description
	}
	if isCompleted, ok := updates["is_completed"].(bool); ok {
		task.IsCompleted = isCompleted
	}
	
	task.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	tasks[taskIndex] = *task
	
	if err := s.writeDataFile(tasks); err != nil {
		return nil, err
	}
	
	return &TaskResponse{
		Success: true,
		Task:    task,
	}, nil
}

func (s *TaskService) DeleteTask(taskID, userID int) (*TaskResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	tasks, err := s.readDataFile()
	if err != nil {
		return nil, err
	}
	
	originalLength := len(tasks)
	filteredTasks := make([]Task, 0)
	
	for _, task := range tasks {
		if !(task.ID == taskID && task.UserID == userID) {
			filteredTasks = append(filteredTasks, task)
		}
	}
	
	if len(filteredTasks) == originalLength {
		return &TaskResponse{Success: false, Error: "Task not found"}, nil
	}
	
	if err := s.writeDataFile(filteredTasks); err != nil {
		return nil, err
	}
	
	return &TaskResponse{Success: true}, nil
}

func (s *TaskService) GetTasksByUser(userID int) ([]Task, error) {
	tasks, err := s.GetTasks()
	if err != nil {
		return nil, err
	}
	
	var userTasks []Task
	for _, task := range tasks {
		if task.UserID == userID {
			userTasks = append(userTasks, task)
		}
	}
	
	return userTasks, nil
}

func (s *TaskService) readDataFile() ([]Task, error) {
	var tasks []Task
	
	data, err := os.ReadFile(s.dataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return tasks, nil
		}
		return nil, err
	}
	
	if err := json.Unmarshal(data, &tasks); err != nil {
		return nil, err
	}
	
	return tasks, nil
}

func (s *TaskService) writeDataFile(tasks []Task) error {
	// Ensure data directory exists
	dir := filepath.Dir(s.dataFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	data, err := json.MarshalIndent(tasks, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(s.dataFile, data, 0644)
}
```

### 3. Authentication Middleware
```go
// internal/presentation/middleware/auth_middleware.go
package middleware

import (
	"net/http"
	"strings"

	"[[.ProjectName]]/internal/services"
)

type AuthMiddleware struct {
	authService *services.AuthService
}

func NewAuthMiddleware() *AuthMiddleware {
	return &AuthMiddleware{
		authService: services.NewAuthService(),
	}
}

func (m *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, `{"success": false, "error": "Access denied. No token provided."}`, http.StatusUnauthorized)
			return
		}
		
		// Remove "Bearer " prefix
		token = strings.TrimPrefix(token, "Bearer ")
		
		claims, err := m.authService.VerifyToken(token)
		if err != nil {
			http.Error(w, `{"success": false, "error": "Invalid token."}`, http.StatusUnauthorized)
			return
		}
		
		// Add user info to request context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "user_email", claims.Email)
		
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

## Usage Instructions

### 1. Setup Project
```bash
# Create new Go project
mkdir mvp-go-example
cd mvp-go-example
go mod init [[.ProjectName]]

# Copy MVP boilerplate and templates
cp tiers/mvp/code/minimal-boilerplate-go.tpl.go cmd/server/main.go
cp -r stacks/go/base/code/* internal/
cp -r stacks/go/base/tests/* test/

# Install dependencies
go get github.com/golang-jwt/jwt/v5
go get golang.org/x/crypto/bcrypt
go get github.com/gorilla/mux
go get github.com/rs/cors
```

### 2. Environment Setup
```bash
# Create .env file
echo "JWT_SECRET=your-super-secret-jwt-key-here" > .env
echo "PORT=3000" >> .env
echo "GO_ENV=development" >> .env
```

### 3. Run the Application
```bash
# Development mode
go run cmd/server/main.go

# Build and run
go build -o bin/server cmd/server/main.go
./bin/server

# Start with specific port
PORT=3001 go run cmd/server/main.go
```

### 4. Test the Application
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Example API Endpoints

### Main Application
```go
// cmd/server/main.go - MVP boilerplate
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"[[.ProjectName]]/internal/config"
	"[[.ProjectName]]/internal/presentation/handlers"
	"[[.ProjectName]]/internal/presentation/middleware"
	"[[.ProjectName]]/internal/core/routes"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

var startTime = time.Now()

func main() {
	// Load configuration
	cfg := config.LoadEnvConfig()
	
	// Setup router
	router := mux.NewRouter()
	
	// Setup middleware
	authMiddleware := middleware.NewAuthMiddleware()
	errorMiddleware := middleware.NewErrorMiddleware()
	
	// Request logging middleware
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s - %s %s", time.Now().Format(time.RFC3339), r.Method, r.Path)
			next.ServeHTTP(w, r)
		})
	})
	
	// Setup routes
	routes.SetupAuthRoutes(router)
	routes.SetupTaskRoutes(router, authMiddleware)
	
	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"uptime":    time.Since(startTime).String(),
		})
	}).Methods("GET")
	
	// API documentation endpoint
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":    "MVP Go Example API",
			"version": "1.0.0",
			"endpoints": map[string]interface{}{
				"auth": map[string]string{
					"login":  "POST /api/auth/login",
					"logout": "POST /api/auth/logout",
					"me":     "GET /api/auth/me",
				},
				"tasks": map[string]string{
					"get_tasks":    "GET /api/tasks",
					"create_task":  "POST /api/tasks",
					"update_task":  "PUT /api/tasks/{id}",
					"delete_task":  "DELETE /api/tasks/{id}",
					"get_task":     "GET /api/tasks/{id}",
				},
			},
		})
	}).Methods("GET")
	
	// Apply CORS
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	})
	
	handler := c.Handler(router)
	handler = errorMiddleware.Middleware(handler)
	
	// Start server
	port := ":" + cfg.Port
	log.Printf("Server starting on port %s", port)
	log.Printf("Health check: http://localhost%s/health", port)
	log.Printf("API docs: http://localhost%s/", port)
	
	if err := http.ListenAndServe(port, handler); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
```

### Route Setup
```go
// internal/core/routes/routes.go
package routes

import (
	"net/http"

	"[[.ProjectName]]/internal/presentation/handlers"
	"[[.ProjectName]]/internal/presentation/middleware"
)

func SetupAuthRoutes(router *mux.Router) {
	authHandler := handlers.NewAuthHandler()
	
	router.HandleFunc("/api/auth/login", authHandler.Login).Methods("POST")
	router.HandleFunc("/api/auth/logout", authHandler.Logout).Methods("POST")
	router.HandleFunc("/api/auth/me", authHandler.GetCurrentUser).Methods("GET")
}

func SetupTaskRoutes(router *mux.Router, authMiddleware *middleware.AuthMiddleware) {
	taskHandler := handlers.NewTaskHandler()
	
	// Apply auth middleware to all task routes
	taskRouter := router.PathPrefix("/api/tasks").Subrouter()
	taskRouter.Use(authMiddleware.Middleware)
	
	taskRouter.HandleFunc("/", taskHandler.GetTasks).Methods("GET")
	taskRouter.HandleFunc("/", taskHandler.CreateTask).Methods("POST")
	taskRouter.HandleFunc("/{id}", taskHandler.UpdateTask).Methods("PUT")
	taskRouter.HandleFunc("/{id}", taskHandler.DeleteTask).Methods("DELETE")
	taskRouter.HandleFunc("/{id}", taskHandler.GetTaskByID).Methods("GET")
}
```

### Handlers
```go
// internal/presentation/handlers/auth_handler.go
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"[[.ProjectName]]/internal/services"
)

type AuthHandler struct {
	authService *services.AuthService
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{
		authService: services.NewAuthService(),
	}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"success": false, "error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}
	
	if req.Email == "" || req.Password == "" {
		http.Error(w, `{"success": false, "error": "Email and password are required"}`, http.StatusBadRequest)
		return
	}
	
	response, err := h.authService.Login(req.Email, req.Password)
	if err != nil {
		http.Error(w, `{"success": false, "error": "Internal server error"}`, http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	if response.Success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Logged out successfully",
	})
}

func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(int)
	userEmail := r.Context().Value("user_email").(string)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user": map[string]interface{}{
			"id":    userID,
			"email": userEmail,
		},
	})
}
```

## Testing Examples

### Unit Test for Auth Service
```go
// test/unit/services/auth_service_test.go
package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthService_Login(t *testing.T) {
	authService := NewAuthService()
	
	t.Run("valid credentials", func(t *testing.T) {
		response, err := authService.Login("test@example.com", "password")
		
		require.NoError(t, err)
		assert.True(t, response.Success)
		assert.NotEmpty(t, response.Token)
		assert.Equal(t, "test@example.com", response.User.Email)
	})
	
	t.Run("invalid email", func(t *testing.T) {
		response, err := authService.Login("invalid-email", "password")
		
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.Contains(t, response.Error, "Invalid email")
	})
	
	t.Run("invalid credentials", func(t *testing.T) {
		response, err := authService.Login("test@example.com", "wrong-password")
		
		require.NoError(t, err)
		assert.False(t, response.Success)
		assert.Contains(t, response.Error, "Invalid credentials")
	})
}

func TestAuthService_VerifyToken(t *testing.T) {
	authService := NewAuthService()
	
	t.Run("valid token", func(t *testing.T) {
		// First get a token
		loginResponse, err := authService.Login("test@example.com", "password")
		require.NoError(t, err)
		
		// Then verify it
		claims, err := authService.VerifyToken(loginResponse.Token)
		
		require.NoError(t, err)
		assert.Equal(t, 1, claims.UserID)
		assert.Equal(t, "test@example.com", claims.Email)
	})
	
	t.Run("invalid token", func(t *testing.T) {
		_, err := authService.VerifyToken("invalid-token")
		
		assert.Error(t, err)
	})
}
```

### Integration Test for API
```go
// test/integration/auth_test.go
package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"[[.ProjectName]]/cmd/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthAPI(t *testing.T) {
	// Create test app
	app := server.CreateApp()
	
	t.Run("login valid credentials", func(t *testing.T) {
		loginData := map[string]string{
			"email":    "test@example.com",
			"password": "password",
		}
		
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()
		app.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.True(t, response["success"].(bool))
		assert.NotEmpty(t, response["token"])
		assert.Equal(t, "test@example.com", response["user"].(map[string]interface{})["email"])
	})
	
	t.Run("login invalid credentials", func(t *testing.T) {
		loginData := map[string]string{
			"email":    "test@example.com",
			"password": "wrong-password",
		}
		
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()
		app.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		
		assert.False(t, response["success"].(bool))
	})
	
	t.Run("get current user with valid token", func(t *testing.T) {
		// First login to get token
		loginData := map[string]string{
			"email":    "test@example.com",
			"password": "password",
		}
		
		jsonData, _ := json.Marshal(loginData)
		req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()
		app.ServeHTTP(w, req)
		
		var loginResponse map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &loginResponse)
		require.NoError(t, err)
		
		token := loginResponse["token"].(string)
		
		// Then get current user
		req = httptest.NewRequest("GET", "/api/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		
		w = httptest.NewRecorder()
		app.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var userResponse map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &userResponse)
		require.NoError(t, err)
		
		assert.True(t, userResponse["success"].(bool))
		assert.Equal(t, "test@example.com", userResponse["user"].(map[string]interface{})["email"])
	})
}
```

## API Usage Examples

### Using the API with curl
```bash
# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password"}'

# Get tasks (requires token)
TOKEN="your-jwt-token-here"
curl -X GET http://localhost:3000/api/tasks \
  -H "Authorization: Bearer $TOKEN"

# Create task
curl -X POST http://localhost:3000/api/tasks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"New Task","description":"Task description"}'

# Update task
curl -X PUT http://localhost:3000/api/tasks/1234567890 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_completed":true}'

# Delete task
curl -X DELETE http://localhost:3000/api/tasks/1234567890 \
  -H "Authorization: Bearer $TOKEN"
```

## Key MVP Patterns Demonstrated

1. **Simple Authentication**: JWT-based authentication with local user storage
2. **File-based Storage**: Tasks stored in JSON file with mutex protection
3. **Basic Middleware**: Authentication and error handling middleware
4. **RESTful API**: Standard CRUD operations with proper HTTP methods
5. **Minimal Dependencies**: Only essential Go packages
6. **Error Handling**: Centralized error handling and logging
7. **Testing Coverage**: Unit tests for services, integration tests for API

## Deployment Instructions

### 1. Traditional Server
```bash
# Build for current platform
go build -o bin/server cmd/server/main.go

# Build for production
go build -ldflags="-s -w" -o bin/server cmd/server/main.go

# Run production server
./bin/server
```

### 2. Docker
```dockerfile
# Dockerfile
FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags="-s -w" -o server cmd/server/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/server .
EXPOSE 3000
CMD ["./server"]
```

```bash
# Build and run
docker build -t mvp-go-example .
docker run -p 3000:3000 mvp-go-example
```

### 3. Cloud Platforms
```bash
# Deploy to Google Cloud Run
gcloud builds submit --tag gcr.io/PROJECT_ID/mvp-go-example
gcloud run deploy --image gcr.io/PROJECT_ID/mvp-go-example --platform managed

# Deploy to Heroku
heroku create
heroku buildpacks:set heroku/go
git push heroku main
```

## Next Steps

This example provides a complete MVP foundation that can be extended with:
- Database integration (PostgreSQL, MySQL, MongoDB)
- Advanced authentication (OAuth, SSO)
- API documentation (Swagger/OpenAPI)
- Rate limiting and security features
- Monitoring and logging
- Caching with Redis
- Message queues for async processing

---

**Note**: This example demonstrates the MVP tier capabilities with minimal complexity while maintaining a functional, testable backend API structure.
