<!--
File: ERROR-HANDLING.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Go Error Handling Patterns

## Purpose
Comprehensive guide to Go error handling patterns, including custom error types, error wrapping, structured error handling, and best practices for robust error management.

## Basic Error Handling Patterns

### 1. Standard Error Handling
```go
package main

import (
	"errors"
	"fmt"
	"os"
)

// Basic function that returns an error
func divide(a, b float64) (float64, error) {
	if b == 0 {
		return 0, errors.New("division by zero")
	}
	return a / b, nil
}

// Error handling with multiple return values
func readFile(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}
	return data, nil
}

// Sentinel errors
var (
	ErrInvalidInput = errors.New("invalid input")
	ErrNotFound     = errors.New("not found")
	ErrUnauthorized = errors.New("unauthorized access")
)

func validateInput(input string) error {
	if input == "" {
		return ErrInvalidInput
	}
	if len(input) > 100 {
		return errors.New("input too long")
	}
	return nil
}

// Error handling with defer and cleanup
func processFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close file: %v\n", closeErr)
		}
	}()

	// Process file content
	// ... processing logic ...

	return nil
}

func main() {
	// Basic error handling
	result, err := divide(10, 0)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Result: %f\n", result)

	// File reading with error handling
	data, err := readFile("example.txt")
	if err != nil {
		fmt.Printf("File error: %v\n", err)
		return
	}
	fmt.Printf("File content: %s\n", string(data))

	// Sentinel error checking
	err = validateInput("")
	if errors.Is(err, ErrInvalidInput) {
		fmt.Println("Input is invalid")
	}
}
```

### 2. Custom Error Types
```go
package main

import (
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// Custom error type with additional context
type AppError struct {
	Code    int
	Message string
	Details map[string]interface{}
	Cause   error
}

func (e *AppError) Error() string {
	if e.Details != nil {
		return fmt.Sprintf("%s (code: %d, details: %v)", e.Message, e.Code, e.Details)
	}
	return fmt.Sprintf("%s (code: %d)", e.Message, e.Code)
}

func (e *AppError) Unwrap() error {
	return e.Cause
}

// Constructor for AppError
func NewAppError(code int, message string, cause error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Details: make(map[string]interface{}),
		Cause:   cause,
	}
}

// Method to add details
func (e *AppError) WithDetail(key string, value interface{}) *AppError {
	e.Details[key] = value
	return e
}

// Validation error type
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s': %s", e.Field, e.Message)
}

// Business logic error type
type BusinessError struct {
	Operation string
	Reason    string
	Retryable bool
}

func (e *BusinessError) Error() string {
	retryStr := "not retryable"
	if e.Retryable {
		retryStr = "retryable"
	}
	return fmt.Sprintf("business error in operation '%s': %s (%s)", e.Operation, e.Reason, retryStr)
}

// Error factory functions
func NewValidationError(field string, value interface{}, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	}
}

func NewBusinessError(operation, reason string, retryable bool) *BusinessError {
	return &BusinessError{
		Operation: operation,
		Reason:    reason,
		Retryable: retryable,
	}
}

// Usage examples
func processUserInput(input string) error {
	if input == "" {
		return NewValidationError("input", input, "cannot be empty")
	}
	if len(input) > 50 {
		return NewValidationError("input", input, "too long (max 50 characters)")
	}
	return nil
}

func processPayment(amount float64) error {
	if amount <= 0 {
		return NewBusinessError("payment", "invalid amount", false)
	}
	if amount > 10000 {
		return NewBusinessError("payment", "amount exceeds limit", true)
	}
	return nil
}

func main() {
	// Custom error usage
	err := processUserInput("")
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
	}

	err = processPayment(-100)
	if err != nil {
		fmt.Printf("Business error: %v\n", err)
	}

	// AppError with details
	appErr := NewAppError(404, "user not found", nil).
		WithDetail("user_id", 123).
		WithDetail("timestamp", time.Now())
	fmt.Printf("App error: %v\n", appErr)
}
```

### 3. Error Wrapping and Unwrapping
```go
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Database error wrapper
type DatabaseError struct {
	Operation string
	Table     string
	Cause     error
}

func (e *DatabaseError) Error() string {
	return fmt.Sprintf("database error in %s on table %s: %v", e.Operation, e.Table, e.Cause)
}

func (e *DatabaseError) Unwrap() error {
	return e.Cause
}

// HTTP error wrapper
type HTTPError struct {
	StatusCode int
	URL        string
	Cause      error
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP error %d for %s: %v", e.StatusCode, e.URL, e.Cause)
}

func (e *HTTPError) Unwrap() error {
	return e.Cause
}

// Functions that wrap errors
func loadConfig(path string) error {
	_, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to load config from %s: %w", path, err)
	}
	return nil
}

func connectDatabase() error {
	// Simulate database connection error
	return &DatabaseError{
		Operation: "connect",
		Table:     "users",
		Cause:     errors.New("connection timeout"),
	}
}

func fetchUserData(userID string) error {
	// Wrap database error
	err := connectDatabase()
	if err != nil {
		return fmt.Errorf("failed to fetch user %s: %w", userID, err)
	}
	return nil
}

func makeHTTPRequest(url string) error {
	// Simulate HTTP error
	return &HTTPError{
		StatusCode: 404,
		URL:        url,
		Cause:      errors.New("resource not found"),
	}
}

func processData(url string) error {
	err := makeHTTPRequest(url)
	if err != nil {
		return fmt.Errorf("failed to process data from %s: %w", url, err)
	}
	return nil
}

// Error inspection and unwrapping
func inspectError(err error) {
	fmt.Printf("Original error: %v\n", err)
	
	// Check for specific error types
	var dbErr *DatabaseError
	if errors.As(err, &dbErr) {
		fmt.Printf("Database operation: %s, Table: %s\n", dbErr.Operation, dbErr.Table)
	}
	
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		fmt.Printf("HTTP status: %d, URL: %s\n", httpErr.StatusCode, httpErr.URL)
	}
	
	// Unwrap to find root cause
	for unwrapped := errors.Unwrap(err); unwrapped != nil; unwrapped = errors.Unwrap(unwrapped) {
		fmt.Printf("Unwrapped: %v\n", unwrapped)
	}
}

// Error chain inspection
func printErrorChain(err error) {
	fmt.Println("Error chain:")
	for err != nil {
		fmt.Printf("  - %v\n", err)
		err = errors.Unwrap(err)
	}
}

func main() {
	// Error wrapping examples
	err := loadConfig("config.yaml")
	if err != nil {
		fmt.Printf("Config error: %v\n", err)
		
		// Check if it's a file not found error
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Println("Config file does not exist")
		}
	}

	err = fetchUserData("123")
	if err != nil {
		inspectError(err)
		printErrorChain(err)
	}

	err = processData("https://api.example.com/data")
	if err != nil {
		inspectError(err)
	}
}
```

## Advanced Error Handling Patterns

### 1. Structured Error Handling
```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"
)

// Structured error with stack trace
type StructuredError struct {
	Timestamp time.Time              `json:"timestamp"`
	Message   string                 `json:"message"`
	Code      string                 `json:"code"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Stack     []string               `json:"stack,omitempty"`
	Cause     error                  `json:"-"`
}

func (e *StructuredError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", e.Code, e.Timestamp.Format(time.RFC3339), e.Message)
}

func (e *StructuredError) Unwrap() error {
	return e.Cause
}

// Capture stack trace
func captureStack() []string {
	var stack []string
	for i := 2; ; i++ { // Skip captureStack and the calling function
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		
		fn := runtime.FuncForPC(pc)
		stack = append(stack, fmt.Sprintf("%s:%d %s", file, line, fn.Name()))
	}
	return stack
}

// Create structured error
func NewStructuredError(code, message string, cause error) *StructuredError {
	return &StructuredError{
		Timestamp: time.Now(),
		Message:   message,
		Code:      code,
		Details:   make(map[string]interface{}),
		Stack:     captureStack(),
		Cause:     cause,
	}
}

// Add details to structured error
func (e *StructuredError) WithDetail(key string, value interface{}) *StructuredError {
	e.Details[key] = value
	return e
}

// Error handler interface
type ErrorHandler interface {
	Handle(error) error
}

// Logging error handler
type LoggingErrorHandler struct {
	Logger *log.Logger
}

func (h *LoggingErrorHandler) Handle(err error) error {
	if structuredErr, ok := err.(*StructuredError); ok {
		jsonData, _ := json.Marshal(structuredErr)
		h.Logger.Printf("Structured error: %s", string(jsonData))
	} else {
		h.Logger.Printf("Error: %v", err)
	}
	return err
}

// Recovery error handler
type RecoveryErrorHandler struct {
	Inner ErrorHandler
}

func (h *RecoveryErrorHandler) Handle(err error) error {
	if err != nil {
		// Attempt recovery or cleanup
		fmt.Println("Attempting recovery from error...")
	}
	return h.Inner.Handle(err)
}

// Error handler chain
type ErrorHandlerChain struct {
	handlers []ErrorHandler
}

func NewErrorHandlerChain(handlers ...ErrorHandler) *ErrorHandlerChain {
	return &ErrorHandlerChain{handlers: handlers}
}

func (chain *ErrorHandlerChain) Handle(err error) error {
	for _, handler := range chain.handlers {
		err = handler.Handle(err)
	}
	return err
}

// Function with structured error handling
func processOrder(orderID string, amount float64) error {
	if orderID == "" {
		return NewStructuredError("INVALID_ORDER", "order ID cannot be empty", nil).
			WithDetail("order_id", orderID).
			WithDetail("amount", amount)
	}
	
	if amount <= 0 {
		return NewStructuredError("INVALID_AMOUNT", "amount must be positive", nil).
			WithDetail("order_id", orderID).
			WithDetail("amount", amount)
	}
	
	// Simulate processing error
	if amount > 1000 {
		return NewStructuredError("PROCESSING_FAILED", "amount exceeds limit", nil).
			WithDetail("order_id", orderID).
			WithDetail("amount", amount).
			WithDetail("limit", 1000)
	}
	
	return nil
}

// Safe function execution with error handling
func safeExecute(fn func() error, errorHandler ErrorHandler) error {
	defer func() {
		if r := recover(); r != nil {
			var err error
			switch x := r.(type) {
			case string:
				err = fmt.Errorf("panic: %s", x)
			case error:
				err = x
			default:
				err = fmt.Errorf("panic: %v", x)
			}
			errorHandler.Handle(err)
		}
	}()
	
	err := fn()
	if err != nil {
		return errorHandler.Handle(err)
	}
	return nil
}

func main() {
	// Setup error handler chain
	logger := log.New(os.Stdout, "ERROR: ", log.LstdFlags|log.Lshortfile)
	loggingHandler := &LoggingErrorHandler{Logger: logger}
	recoveryHandler := &RecoveryErrorHandler{Inner: loggingHandler}
	
	errorChain := NewErrorHandlerChain(recoveryHandler, loggingHandler)
	
	// Test structured error handling
	err := processOrder("123", 1500)
	if err != nil {
		errorChain.Handle(err)
	}
	
	// Test safe execution
	err = safeExecute(func() error {
		return processOrder("", 100)
	}, errorChain)
	
	if err != nil {
		fmt.Printf("Safe execution error: %v\n", err)
	}
}
```

### 2. Context-Aware Error Handling
```go
package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Context-aware error
type ContextError struct {
	Context context.Context
	Cause   error
}

func (e *ContextError) Error() string {
	return fmt.Sprintf("context error: %v", e.Cause)
}

func (e *ContextError) Unwrap() error {
	return e.Cause
}

// Timeout error
type TimeoutError struct {
	Operation string
	Timeout   time.Duration
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("operation '%s' timed out after %v", e.Operation, e.Timeout)
}

// Cancellation error
type CancellationError struct {
	Operation string
}

func (e *CancellationError) Error() string {
	return fmt.Sprintf("operation '%s' was cancelled", e.Operation)
}

// Context-aware function
func processWithContext(ctx context.Context, data string) error {
	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return &CancellationError{Operation: "process"}
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return &TimeoutError{Operation: "process", Timeout: time.Since(time.Now())}
		}
		return ctx.Err()
	default:
		// Simulate processing
		time.Sleep(time.Millisecond * 100)
		fmt.Printf("Processed: %s\n", data)
		return nil
	}
}

// Function with timeout
func processWithTimeout(data string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	err := processWithContext(ctx, data)
	if err != nil {
		return fmt.Errorf("processing failed: %w", err)
	}
	return nil
}

// Function with cancellation
func processWithCancellation(ctx context.Context, data string) error {
	return processWithContext(ctx, data)
}

// Batch processing with context
func batchProcess(ctx context.Context, items []string) error {
	results := make(chan error, len(items))
	
	for _, item := range items {
		go func(item string) {
			err := processWithContext(ctx, item)
			results <- err
		}(item)
	}
	
	// Collect results
	var errors []error
	for i := 0; i < len(items); i++ {
		select {
		case err := <-results:
			if err != nil {
				errors = append(errors, err)
			}
		case <-ctx.Done():
			return fmt.Errorf("batch processing cancelled: %w", ctx.Err())
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("batch processing completed with %d errors", len(errors))
	}
	
	return nil
}

// Context-aware error handler
type ContextErrorHandler struct {
	ctx context.Context
}

func (h *ContextErrorHandler) Handle(err error) error {
	if h.ctx.Err() != nil {
		return fmt.Errorf("context error during handling: %w", h.ctx.Err())
	}
	
	// Handle error based on context
	select {
	case <-h.ctx.Done():
		return fmt.Errorf("error handling cancelled: %w", h.ctx.Err())
	default:
		// Handle error normally
		fmt.Printf("Handling error: %v\n", err)
		return err
	}
}

func main() {
	// Test timeout error
	err := processWithTimeout("test data", time.Millisecond*50)
	if err != nil {
		fmt.Printf("Timeout error: %v\n", err)
		
		var timeoutErr *TimeoutError
		if errors.As(err, &timeoutErr) {
			fmt.Printf("Operation: %s, Timeout: %v\n", timeoutErr.Operation, timeoutErr.Timeout)
		}
	}
	
	// Test cancellation error
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	
	err = processWithCancellation(ctx, "test data")
	if err != nil {
		fmt.Printf("Cancellation error: %v\n", err)
		
		var cancelErr *CancellationError
		if errors.As(err, &cancelErr) {
			fmt.Printf("Cancelled operation: %s\n", cancelErr.Operation)
		}
	}
	
	// Test batch processing with context
	items := []string{"item1", "item2", "item3", "item4", "item5"}
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond*200)
	defer cancel()
	
	err = batchProcess(ctx, items)
	if err != nil {
		fmt.Printf("Batch processing error: %v\n", err)
	}
}
```

### 3. Retry Pattern with Error Handling
```go
package main

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// Retry configuration
type RetryConfig struct {
	MaxAttempts int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       bool
}

// Default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		InitialDelay: time.Millisecond * 100,
		MaxDelay:     time.Second * 10,
		Multiplier:   2.0,
		Jitter:       true,
	}
}

// Retryable error interface
type RetryableError interface {
	error
	Retryable() bool
}

// Retryable error implementation
type retryableError struct {
	message   string
	retryable bool
}

func (e *retryableError) Error() string {
	return e.message
}

func (e *retryableError) Retryable() bool {
	return e.retryable
}

func NewRetryableError(message string, retryable bool) *retryableError {
	return &retryableError{
		message:   message,
		retryable: retryable,
	}
}

// Retry function
func Retry(config RetryConfig, operation func() error) error {
	var lastErr error
	delay := config.InitialDelay
	
	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}
		
		lastErr = err
		
		// Check if error is retryable
		if retryableErr, ok := err.(RetryableError); ok && !retryableErr.Retryable() {
			break
		}
		
		// Don't retry on last attempt
		if attempt == config.MaxAttempts {
			break
		}
		
		// Calculate delay with exponential backoff
		if config.Jitter {
			// Add jitter to prevent thundering herd
			jitter := time.Duration(float64(delay) * (0.5 + 0.5*math.Rand.Float64()))
			delay = time.Duration(math.Min(float64(delay)*config.Multiplier, float64(config.MaxDelay)))
			delay += jitter
		} else {
			delay = time.Duration(math.Min(float64(delay)*config.Multiplier, float64(config.MaxDelay)))
		}
		
		fmt.Printf("Attempt %d failed, retrying in %v...\n", attempt, delay)
		time.Sleep(delay)
	}
	
	return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, lastErr)
}

// Example operations
func unreliableOperation(shouldFail bool, failOnAttempt int) func() error {
	attempt := 0
	return func() error {
		attempt++
		fmt.Printf("Operation attempt %d\n", attempt)
		
		if shouldFail && attempt < failOnAttempt {
			if attempt == 2 {
				return NewRetryableError("non-retryable error", false)
			}
			return NewRetryableError("temporary failure", true)
		}
		
		return nil
	}
}

func networkOperation(url string) error {
	// Simulate network operation
	if url == "fail" {
		return NewRetryableError("network timeout", true)
	}
	if url == "auth_error" {
		return NewRetryableError("authentication failed", false)
	}
	return nil
}

// Retry with context
func RetryWithContext(ctx context.Context, config RetryConfig, operation func() error) error {
	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		default:
		}
		
		err := operation()
		if err == nil {
			return nil
		}
		
		// Check if error is retryable
		if retryableErr, ok := err.(RetryableError); ok && !retryableErr.Retryable() {
			return err
		}
		
		// Don't retry on last attempt
		if attempt == config.MaxAttempts {
			return fmt.Errorf("operation failed after %d attempts: %w", config.MaxAttempts, err)
		}
		
		// Calculate delay
		delay := time.Duration(float64(config.InitialDelay) * math.Pow(config.Multiplier, float64(attempt-1)))
		delay = time.Duration(math.Min(float64(delay), float64(config.MaxDelay)))
		
		fmt.Printf("Attempt %d failed, retrying in %v...\n", attempt, delay)
		
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		}
	}
	
	return errors.New("max attempts reached")
}

func main() {
	// Test retry with temporary failures
	config := DefaultRetryConfig()
	err := Retry(config, unreliableOperation(true, 4))
	if err != nil {
		fmt.Printf("Retry failed: %v\n", err)
	}
	
	// Test retry with non-retryable error
	err = Retry(config, unreliableOperation(true, 2))
	if err != nil {
		fmt.Printf("Retry failed (non-retryable): %v\n", err)
	}
	
	// Test retry with context
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	
	err = RetryWithContext(ctx, config, func() error {
		return networkOperation("fail")
	})
	if err != nil {
		fmt.Printf("Context retry failed: %v\n", err)
	}
}
```

## Error Handling Best Practices

### 1. Error Handling Guidelines
```go
// ✅ GOOD: Handle errors immediately
func goodErrorHandling() {
	data, err := os.ReadFile("config.json")
	if err != nil {
		log.Printf("Failed to read config: %v", err)
		return
	}
	
	// Use data
	fmt.Printf("Config: %s\n", string(data))
}

// ❌ BAD: Ignore errors
func badErrorHandling() {
	data, _ := os.ReadFile("config.json") // Error ignored
	fmt.Printf("Config: %s\n", string(data))
}

// ✅ GOOD: Provide context with error wrapping
func goodErrorWrapping(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", filename, err)
	}
	
	// Process data
	return nil
}

// ❌ BAD: Return raw errors without context
func badErrorWrapping(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err // No context
	}
	
	// Process data
	return nil
}

// ✅ GOOD: Use sentinel errors for expected conditions
func goodSentinelErrors(value int) error {
	if value < 0 {
		return ErrInvalidInput
	}
	if value > 100 {
		return ErrOutOfRange
	}
	return nil
}

// ❌ BAD: Create new errors for the same condition
func badSentinelErrors(value int) error {
	if value < 0 {
		return errors.New("input is negative") // Should use sentinel
	}
	if value > 100 {
		return errors.New("input is too large") // Should use sentinel
	}
	return nil
}

// ✅ GOOD: Handle specific error types
func goodErrorTypeHandling(err error) {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		fmt.Printf("Path error: %s\n", pathErr.Path)
		return
	}
	
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Println("File does not exist")
		return
	}
	
	fmt.Printf("Other error: %v\n", err)
}

// ❌ BAD: Check error messages as strings
func badErrorTypeHandling(err error) {
	if err.Error() == "file does not exist" { // Fragile
		fmt.Println("File does not exist")
	}
}
```

### 2. Performance Considerations
```go
// ✅ GOOD: Use error pooling for high-frequency operations
var errorPool = sync.Pool{
	New: func() interface{} {
		return &AppError{
			Details: make(map[string]interface{}),
		}
	},
}

func pooledError(code int, message string) *AppError {
	err := errorPool.Get().(*AppError)
	err.Code = code
	err.Message = message
	// Clear previous details
	for k := range err.Details {
		delete(err.Details, k)
	}
	return err
}

func returnError(err *AppError) {
	errorPool.Put(err)
}

// ✅ GOOD: Avoid expensive operations in error paths
func efficientErrorHandling() error {
	// Do expensive validation before error creation
	if !isValidInput() {
		return errors.New("invalid input") // Simple error
	}
	
	// Complex error only when needed
	return NewAppError(500, "processing failed", nil)
}

// ❌ BAD: Expensive operations in error creation
func inefficientErrorHandling() error {
	// Expensive operation in error path
	diagnosticInfo := collectDiagnosticInfo() // Expensive
	return NewAppError(500, "processing failed", nil).
		WithDetail("diagnostics", diagnosticInfo)
}
```

This comprehensive Go error handling guide covers all essential patterns from basic error handling to advanced structured error handling, context-aware errors, and retry patterns with best practices for robust error management.
