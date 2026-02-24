// File: api_handlers.tpl.go
// Purpose: HTTP API handlers with Gin/Chi patterns
// Generated for: {{PROJECT_NAME}}

package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator/v10"
)

// ============================================================================
// Response Types
// ============================================================================

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
}

type PaginatedResponse struct {
	Success    bool        `json:"success"`
	Data       interface{} `json:"data"`
	Pagination Pagination  `json:"pagination"`
}

type Pagination struct {
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

type ErrorResponse struct {
	Success bool          `json:"success"`
	Errors  []ErrorDetail `json:"errors"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

// ============================================================================
// Response Helpers
// ============================================================================

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondOK(w http.ResponseWriter, data interface{}) {
	respondJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
	})
}

func respondCreated(w http.ResponseWriter, data interface{}) {
	respondJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    data,
	})
}

func respondNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

func respondPaginated(w http.ResponseWriter, data interface{}, pagination Pagination) {
	respondJSON(w, http.StatusOK, PaginatedResponse{
		Success:    true,
		Data:       data,
		Pagination: pagination,
	})
}

func respondError(w http.ResponseWriter, status int, code, message string) {
	respondJSON(w, status, ErrorResponse{
		Success: false,
		Errors: []ErrorDetail{
			{Code: code, Message: message},
		},
	})
}

func respondValidationErrors(w http.ResponseWriter, errors []ErrorDetail) {
	respondJSON(w, http.StatusUnprocessableEntity, ErrorResponse{
		Success: false,
		Errors:  errors,
	})
}

// ============================================================================
// Request Helpers
// ============================================================================

var validate = validator.New()

func decodeJSON(r *http.Request, v interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return err
	}
	return validate.Struct(v)
}

func getPaginationParams(r *http.Request) (page, perPage, offset int) {
	page = 1
	perPage = 20

	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	if pp := r.URL.Query().Get("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil && parsed > 0 && parsed <= 100 {
			perPage = parsed
		}
	}

	offset = (page - 1) * perPage
	return
}

func getIntParam(r *http.Request, name string) (int, error) {
	param := chi.URLParam(r, name)
	return strconv.Atoi(param)
}

// ============================================================================
// Middleware
// ============================================================================

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing authorization token")
			return
		}

		// Validate token and set user in context
		// user, err := validateToken(token)
		// ctx := context.WithValue(r.Context(), "user", user)
		// next.ServeHTTP(w, r.WithContext(ctx))

		next.ServeHTTP(w, r)
	})
}

func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is admin
		// user := r.Context().Value("user").(*User)
		// if !user.IsSuperuser {
		// 	respondError(w, http.StatusForbidden, "FORBIDDEN", "Admin access required")
		// 	return
		// }
		next.ServeHTTP(w, r)
	})
}

func RateLimitMiddleware(requestsPerMinute int) func(http.Handler) http.Handler {
	// Simple in-memory rate limiter (use Redis in production)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Implement rate limiting logic
			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// User Handlers
// ============================================================================

type UserHandler struct {
	// Add service dependencies
}

func NewUserHandler() *UserHandler {
	return &UserHandler{}
}

// POST /api/users/register
func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email" validate:"required,email"`
		Username string `json:"username" validate:"required,min=3,max=30"`
		Password string `json:"password" validate:"required,min=8"`
		FullName string `json:"full_name" validate:"max=100"`
	}

	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}

	// Create user
	user := map[string]interface{}{
		"id":         1,
		"email":      req.Email,
		"username":   req.Username,
		"full_name":  req.FullName,
		"created_at": time.Now(),
	}

	respondCreated(w, user)
}

// POST /api/users/login
func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}

	// Authenticate user
	response := map[string]interface{}{
		"access_token":  "jwt-token-here",
		"refresh_token": "refresh-token-here",
		"expires_in":    3600,
	}

	respondOK(w, response)
}

// GET /api/users/me
func (h *UserHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	user := map[string]interface{}{
		"id":       1,
		"email":    "user@example.com",
		"username": "testuser",
	}

	respondOK(w, user)
}

// PATCH /api/users/me
func (h *UserHandler) UpdateCurrentUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FullName *string `json:"full_name" validate:"omitempty,max=100"`
		Bio      *string `json:"bio" validate:"omitempty,max=500"`
	}

	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}

	// Update user
	user := map[string]interface{}{
		"id":        1,
		"full_name": req.FullName,
		"bio":       req.Bio,
	}

	respondOK(w, user)
}

// ============================================================================
// Post Handlers
// ============================================================================

type PostHandler struct {
	// Add service dependencies
}

func NewPostHandler() *PostHandler {
	return &PostHandler{}
}

// GET /api/posts
func (h *PostHandler) List(w http.ResponseWriter, r *http.Request) {
	page, perPage, _ := getPaginationParams(r)

	// Query with filters
	status := r.URL.Query().Get("status")
	search := r.URL.Query().Get("search")
	_ = status
	_ = search

	posts := []map[string]interface{}{}
	total := int64(0)

	totalPages := int(total) / perPage
	if int(total)%perPage > 0 {
		totalPages++
	}

	respondPaginated(w, posts, Pagination{
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
		HasNext:    page*perPage < int(total),
		HasPrev:    page > 1,
	})
}

// POST /api/posts
func (h *PostHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title   string   `json:"title" validate:"required,min=5,max=200"`
		Content string   `json:"content" validate:"required,min=10"`
		Excerpt string   `json:"excerpt" validate:"max=500"`
		Status  string   `json:"status" validate:"omitempty,oneof=draft published archived"`
		Tags    []string `json:"tags" validate:"max=10"`
	}

	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}

	// Create post
	post := map[string]interface{}{
		"id":         1,
		"title":      req.Title,
		"content":    req.Content,
		"status":     req.Status,
		"created_at": time.Now(),
	}

	respondCreated(w, post)
}

// GET /api/posts/{id}
func (h *PostHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := getIntParam(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "Invalid post ID")
		return
	}

	// Get post
	post := map[string]interface{}{
		"id":    id,
		"title": "Test Post",
	}

	respondOK(w, post)
}

// PATCH /api/posts/{id}
func (h *PostHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := getIntParam(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "Invalid post ID")
		return
	}

	var req struct {
		Title   *string  `json:"title" validate:"omitempty,min=5,max=200"`
		Content *string  `json:"content" validate:"omitempty,min=10"`
		Status  *string  `json:"status" validate:"omitempty,oneof=draft published archived"`
		Tags    []string `json:"tags" validate:"omitempty,max=10"`
	}

	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
		return
	}

	// Update post
	post := map[string]interface{}{
		"id":    id,
		"title": req.Title,
	}

	respondOK(w, post)
}

// DELETE /api/posts/{id}
func (h *PostHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := getIntParam(r, "id")
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "Invalid post ID")
		return
	}

	// Delete post
	_ = id

	respondNoContent(w)
}

// ============================================================================
// Router Setup
// ============================================================================

func NewRouter() http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		respondOK(w, map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})
	})

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		userHandler := NewUserHandler()
		postHandler := NewPostHandler()

		// Public routes
		r.Post("/users/register", userHandler.Register)
		r.Post("/users/login", userHandler.Login)

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(AuthMiddleware)

			// Users
			r.Get("/users/me", userHandler.GetCurrentUser)
			r.Patch("/users/me", userHandler.UpdateCurrentUser)

			// Posts
			r.Get("/posts", postHandler.List)
			r.Post("/posts", postHandler.Create)
			r.Get("/posts/{id}", postHandler.Get)
			r.Patch("/posts/{id}", postHandler.Update)
			r.Delete("/posts/{id}", postHandler.Delete)
		})
	})

	return r
}
