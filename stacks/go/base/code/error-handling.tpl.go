// File: error-handling.tpl.go
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

// -----------------------------------------------------------------------------
// FILE: error-handling.tpl.go
// PURPOSE: Comprehensive error handling patterns and utilities for Go projects
// USAGE: Import and adapt for consistent error handling across the application
// DEPENDENCIES: encoding/json, fmt, net/http, runtime, strings, time
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity string

const (
	SeverityLow      ErrorSeverity = "low"
	SeverityMedium   ErrorSeverity = "medium"
	SeverityHigh     ErrorSeverity = "high"
	SeverityCritical ErrorSeverity = "critical"
)

// ErrorCategory represents the category of an error
type ErrorCategory string

const (
	CategoryValidation    ErrorCategory = "validation"
	CategoryBusinessLogic ErrorCategory = "business_logic"
	CategoryExternalAPI   ErrorCategory = "external_api"
	CategoryNetwork       ErrorCategory = "network"
	CategoryAuth          ErrorCategory = "authentication"
	CategoryAuthz         ErrorCategory = "authorization"
	CategorySystem        ErrorCategory = "system"
	CategoryUserInput     ErrorCategory = "user_input"
)

// AppError represents an application error with structured information
type AppError struct {
	Message        string                 `json:"message"`
	Code           string                 `json:"code"`
	Severity       ErrorSeverity          `json:"severity"`
	Category       ErrorCategory          `json:"category"`
	Context        map[string]interface{} `json:"context,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	StackTrace     string                 `json:"stack_trace,omitempty"`
	UserMessage    string                 `json:"user_message,omitempty"`
	HTTPStatusCode int                    `json:"http_status_code,omitempty"`
	Cause          error                  `json:"cause,omitempty"`
	RequestID      string                 `json:"request_id,omitempty"`
	UserID         string                 `json:"user_id,omitempty"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	return e.Message
}

// Unwrap returns the underlying cause
func (e *AppError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target
func (e *AppError) Is(target error) bool {
	if t, ok := target.(*AppError); ok {
		return e.Code == t.Code
	}
	return false
}

// ToJSON converts the error to JSON
func (e *AppError) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// WithContext adds context to the error
func (e *AppError) WithContext(key string, value interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithContextMap adds multiple context fields to the error
func (e *AppError) WithContextMap(context map[string]interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	for k, v := range context {
		e.Context[k] = v
	}
	return e
}

// WithRequestID adds a request ID to the error
func (e *AppError) WithRequestID(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

// WithUserID adds a user ID to the error
func (e *AppError) WithUserID(userID string) *AppError {
	e.UserID = userID
	return e
}

// WithCause adds a cause to the error
func (e *AppError) WithCause(cause error) *AppError {
	e.Cause = cause
	return e
}

// NewAppError creates a new application error
func NewAppError(message, code string, severity ErrorSeverity, category ErrorCategory) *AppError {
	return &AppError{
		Message:        message,
		Code:           code,
		Severity:       severity,
		Category:       category,
		Context:        make(map[string]interface{}),
		Timestamp:      time.Now(),
		UserMessage:    getDefaultUserMessage(severity),
		HTTPStatusCode: getDefaultHTTPStatusCode(category, severity),
	}
}

// ValidationError creates a validation error
func ValidationError(message string, field string, value interface{}) *AppError {
	err := NewAppError(message, "VALIDATION_ERROR", SeverityLow, CategoryValidation)
	err.WithContext("field", field).
		WithContext("value", value).
		WithHTTPStatusCode(http.StatusBadRequest)
	return err
}

// BusinessLogicError creates a business logic error
func BusinessLogicError(message string) *AppError {
	return NewAppError(message, "BUSINESS_ERROR", SeverityMedium, CategoryBusinessLogic)
}

// ExternalAPIError creates an external API error
func ExternalAPIError(message string, service string, statusCode int) *AppError {
	err := NewAppError(message, "EXTERNAL_API_ERROR", SeverityHigh, CategoryExternalAPI)
	err.WithContext("service", service).
		WithContext("status_code", statusCode).
		WithHTTPStatusCode(http.StatusBadGateway)
	return err
}

// NetworkError creates a network error
func NetworkError(message string) *AppError {
	return NewAppError(message, "NETWORK_ERROR", SeverityHigh, CategoryNetwork)
}

// AuthenticationError creates an authentication error
func AuthenticationError(message string) *AppError {
	return NewAppError(message, "AUTH_ERROR", SeverityMedium, CategoryAuth).
		WithHTTPStatusCode(http.StatusUnauthorized)
}

// AuthorizationError creates an authorization error
func AuthorizationError(message string, resource string, action string) *AppError {
	err := NewAppError(message, "AUTHZ_ERROR", SeverityMedium, CategoryAuthz)
	err.WithContext("resource", resource).
		WithContext("action", action).
		WithHTTPStatusCode(http.StatusForbidden)
	return err
}

// SystemError creates a system error
func SystemError(message string) *AppError {
	return NewAppError(message, "SYSTEM_ERROR", SeverityCritical, CategorySystem).
		WithHTTPStatusCode(http.StatusInternalServerError)
}

// UserInputError creates a user input error
func UserInputError(message string) *AppError {
	return NewAppError(message, "USER_INPUT_ERROR", SeverityLow, CategoryUserInput).
		WithHTTPStatusCode(http.StatusBadRequest)
}

// Wrap wraps an existing error with additional context
func Wrap(err error, message string) *AppError {
	if appErr, ok := err.(*AppError); ok {
		// If it's already an AppError, just add context
		return appErr.WithContext("wrapped_message", message)
	}

	return NewAppError(message, "WRAPPED_ERROR", SeverityMedium, CategorySystem).
		WithCause(err)
}

// getDefaultUserMessage returns the default user-friendly message based on severity
func getDefaultUserMessage(severity ErrorSeverity) string {
	switch severity {
	case SeverityLow:
		return "Please check your input and try again."
	case SeverityMedium:
		return "An error occurred. Please try again."
	case SeverityHigh, SeverityCritical:
		return "A serious error occurred. Please contact support."
	default:
		return "An error occurred."
	}
}

// getDefaultHTTPStatusCode returns the default HTTP status code based on category and severity
func getDefaultHTTPStatusCode(category ErrorCategory, severity ErrorSeverity) int {
	switch category {
	case CategoryValidation, CategoryUserInput:
		return http.StatusBadRequest
	case CategoryAuth:
		return http.StatusUnauthorized
	case CategoryAuthz:
		return http.StatusForbidden
	case CategoryExternalAPI, CategoryNetwork:
		return http.StatusBadGateway
	case CategorySystem:
		if severity == SeverityCritical {
			return http.StatusInternalServerError
		}
		return http.StatusServiceUnavailable
	case CategoryBusinessLogic:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}

// WithHTTPStatusCode sets the HTTP status code for the error
func (e *AppError) WithHTTPStatusCode(code int) *AppError {
	e.HTTPStatusCode = code
	return e
}

// WithUserMessage sets a custom user message
func (e *AppError) WithUserMessage(message string) *AppError {
	e.UserMessage = message
	return e
}

// WithStackTrace adds a stack trace to the error
func (e *AppError) WithStackTrace() *AppError {
	e.StackTrace = getStackTrace()
	return e
}

// getStackTrace captures the current stack trace
func getStackTrace() string {
	buf := make([]byte, 1024)
	for {
		n := runtime.Stack(buf, false)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// ErrorHandler interface for handling errors
type ErrorHandler interface {
	Handle(err error, context map[string]interface{})
}

// ErrorHandlerFunc is a function type that implements ErrorHandler
type ErrorHandlerFunc func(err error, context map[string]interface{})

// Handle implements the ErrorHandler interface
func (f ErrorHandlerFunc) Handle(err error, context map[string]interface{}) {
	f(err, context)
}

// ErrorManager manages error handling
type ErrorManager struct {
	handlers []ErrorHandler
}

// NewErrorManager creates a new error manager
func NewErrorManager() *ErrorManager {
	return &ErrorManager{
		handlers: make([]ErrorHandler, 0),
	}
}

// AddHandler adds an error handler
func (em *ErrorManager) AddHandler(handler ErrorHandler) {
	em.handlers = append(em.handlers, handler)
}

// HandleError handles an error using all registered handlers
func (em *ErrorManager) HandleError(err error, context map[string]interface{}) {
	// Convert to AppError if needed
	appErr := toAppError(err)

	// Add context to error
	if context != nil {
		appErr.WithContextMap(context)
	}

	// Call all handlers
	for _, handler := range em.handlers {
		handler.Handle(appErr, context)
	}
}

// toAppError converts any error to an AppError
func toAppError(err error) *AppError {
	if appErr, ok := err.(*AppError); ok {
		return appErr
	}

	return SystemError(err.Error()).WithCause(err).WithStackTrace()
}

// ConsoleErrorHandler prints errors to console
type ConsoleErrorHandler struct{}

// Handle implements the ErrorHandler interface
func (h *ConsoleErrorHandler) Handle(err error, context map[string]interface{}) {
	if appErr, ok := err.(*AppError); ok {
		fmt.Printf("ERROR [%s] %s\n", appErr.Code, appErr.Message)
		if appErr.Context != nil {
			fmt.Printf("Context: %+v\n", appErr.Context)
		}
		if appErr.StackTrace != "" {
			fmt.Printf("Stack Trace:\n%s\n", appErr.StackTrace)
		}
	} else {
		fmt.Printf("ERROR: %s\n", err.Error())
	}
}

// LoggingErrorHandler sends errors to a logger
type LoggingErrorHandler struct {
	LogFunc func(message string, fields map[string]interface{})
}

// Handle implements the ErrorHandler interface
func (h *LoggingErrorHandler) Handle(err error, context map[string]interface{}) {
	if appErr, ok := err.(*AppError); ok {
		fields := map[string]interface{}{
			"error_code":    appErr.Code,
			"severity":      appErr.Severity,
			"category":      appErr.Category,
			"timestamp":     appErr.Timestamp,
			"http_status":   appErr.HTTPStatusCode,
			"request_id":    appErr.RequestID,
			"user_id":       appErr.UserID,
		}

		if appErr.Context != nil {
			for k, v := range appErr.Context {
				fields[k] = v
			}
		}

		if context != nil {
			for k, v := range context {
				fields[k] = v
			}
		}

		if appErr.StackTrace != "" {
			fields["stack_trace"] = appErr.StackTrace
		}

		h.LogFunc(appErr.Message, fields)
	} else {
		h.LogFunc(err.Error(), map[string]interface{}{
			"error_type": "generic",
		})
	}
}

// HTTPErrorHandler converts errors to HTTP responses
type HTTPErrorHandler struct{}

// Handle implements the ErrorHandler interface
func (h *HTTPErrorHandler) Handle(err error, context map[string]interface{}) {
	// This handler would typically be used in HTTP middleware
	// The actual response writing would be handled by the middleware
}

// ToHTTPResponse converts an error to an HTTP response
func ToHTTPResponse(err error) (int, map[string]interface{}) {
	if appErr, ok := err.(*AppError); ok {
		response := map[string]interface{}{
			"error":         appErr.UserMessage,
			"error_code":    appErr.Code,
			"timestamp":     appErr.Timestamp,
			"request_id":    appErr.RequestID,
		}

		if appErr.Context != nil && len(appErr.Context) > 0 {
			response["context"] = appErr.Context
		}

		return appErr.HTTPStatusCode, response
	}

	return http.StatusInternalServerError, map[string]interface{}{
		"error":     "Internal server error",
		"timestamp": time.Now(),
	}
}

// RetryManager handles retry logic for operations
type RetryManager struct {
	MaxRetries int
	DelayFunc  func(attempt int) time.Duration
}

// NewRetryManager creates a new retry manager
func NewRetryManager(maxRetries int) *RetryManager {
	return &RetryManager{
		MaxRetries: maxRetries,
		DelayFunc: func(attempt int) time.Duration {
			return time.Duration(attempt*attempt) * time.Second // Exponential backoff
		},
	}
}

// Retry executes a function with retry logic
func (rm *RetryManager) Retry(fn func() error) error {
	var lastErr error

	for attempt := 0; attempt <= rm.MaxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		if attempt < rm.MaxRetries {
			if !shouldRetry(err) {
				break
			}

			delay := rm.DelayFunc(attempt)
			time.Sleep(delay)
		}
	}

	return Wrap(lastErr, fmt.Sprintf("operation failed after %d retries", rm.MaxRetries))
}

// shouldRetry determines if an error should be retried
func shouldRetry(err error) bool {
	if appErr, ok := err.(*AppError); ok {
		switch appErr.Category {
		case CategoryNetwork, CategoryExternalAPI:
			return true
		case CategorySystem:
			return appErr.HTTPStatusCode >= 500
		default:
			return false
		}
	}

	// For generic errors, check if they contain retryable keywords
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "network")
}

// Global error manager
var globalErrorManager = NewErrorManager()

// HandleError handles an error using the global error manager
func HandleError(err error, context map[string]interface{}) {
	globalErrorManager.HandleError(err, context)
}

// AddHandler adds an error handler to the global error manager
func AddHandler(handler ErrorHandler) {
	globalErrorManager.AddHandler(handler)
}

// Initialize default error handlers
func init() {
	globalErrorManager.AddHandler(&ConsoleErrorHandler{})
}

// Example usage demonstrates how to use the error handling utilities
func ExampleUsage() {
	// Create different types of errors
	validationErr := ValidationError("Invalid email format", "email", "invalid-email")
	businessErr := BusinessLogicError("Insufficient balance")
	systemErr := SystemError("Database connection failed")

	// Add context to errors
	validationErr.WithContext("expected_format", "email@domain.com").
		WithRequestID("req-123").
		WithUserID("user-456")

	// Handle errors
	HandleError(validationErr, map[string]interface{}{
		"endpoint": "/api/users",
		"method":   "POST",
	})

	HandleError(businessErr, nil)
	HandleError(systemErr, nil)

	// Use retry manager
	retryManager := NewRetryManager(3)
	err := retryManager.Retry(func() error {
		// Simulate a failing operation
		return NetworkError("Connection timeout")
	})

	if err != nil {
		HandleError(err, map[string]interface{}{
			"operation": "api_call",
		})
	}

	// Convert to HTTP response
	statusCode, response := ToHTTPResponse(validationErr)
	fmt.Printf("HTTP Status: %d, Response: %+v\n", statusCode, response)
}
