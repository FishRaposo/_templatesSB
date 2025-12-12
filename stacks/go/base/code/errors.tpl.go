// File: errors.tpl.go
// Purpose: Structured error handling for Go applications
// Generated for: {{PROJECT_NAME}}

package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// AppError represents a structured application error
type AppError struct {
	Message    string                 `json:"message"`
	Code       string                 `json:"error"`
	StatusCode int                    `json:"-"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Err        error                  `json:"-"`
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// Error constructors
func New(message, code string, statusCode int) *AppError {
	return &AppError{
		Message:    message,
		Code:       code,
		StatusCode: statusCode,
	}
}

func Wrap(err error, message, code string, statusCode int) *AppError {
	return &AppError{
		Message:    message,
		Code:       code,
		StatusCode: statusCode,
		Err:        err,
	}
}

func NotFound(resource, id string) *AppError {
	return &AppError{
		Message:    fmt.Sprintf("%s with id '%s' not found", resource, id),
		Code:       "NOT_FOUND",
		StatusCode: http.StatusNotFound,
		Details:    map[string]interface{}{"resource": resource, "id": id},
	}
}

func Validation(message string, details map[string]interface{}) *AppError {
	return &AppError{
		Message:    message,
		Code:       "VALIDATION_ERROR",
		StatusCode: http.StatusBadRequest,
		Details:    details,
	}
}

func Unauthorized(message string) *AppError {
	if message == "" {
		message = "Authentication required"
	}
	return &AppError{
		Message:    message,
		Code:       "UNAUTHORIZED",
		StatusCode: http.StatusUnauthorized,
	}
}

func Forbidden(message string) *AppError {
	if message == "" {
		message = "Permission denied"
	}
	return &AppError{
		Message:    message,
		Code:       "FORBIDDEN",
		StatusCode: http.StatusForbidden,
	}
}

func RateLimited(retryAfter int) *AppError {
	return &AppError{
		Message:    "Rate limit exceeded",
		Code:       "RATE_LIMITED",
		StatusCode: http.StatusTooManyRequests,
		Details:    map[string]interface{}{"retry_after": retryAfter},
	}
}

func Internal(err error) *AppError {
	return &AppError{
		Message:    "An unexpected error occurred",
		Code:       "INTERNAL_ERROR",
		StatusCode: http.StatusInternalServerError,
		Err:        err,
	}
}

// ErrorResponse writes an error response to the HTTP writer
func ErrorResponse(w http.ResponseWriter, err *AppError, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)

	response := map[string]interface{}{
		"error":   err.Code,
		"message": err.Message,
	}

	if err.Details != nil {
		response["details"] = err.Details
	}
	if requestID != "" {
		response["request_id"] = requestID
	}

	json.NewEncoder(w).Encode(response)
}
