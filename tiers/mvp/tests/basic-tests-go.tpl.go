// Template: basic-tests-go.tpl.go
// Purpose: basic-tests-go template
// Stack: go
// Tier: base

# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: mvp
# Stack: unknown
# Category: testing

# Basic Go Testing Template
# Purpose: MVP-level testing template with unit and component tests for Go applications
# Usage: Copy to your project and customize for your Go project
# Stack: Go (.go)
# Tier: MVP (Minimal Viable Product)

## Purpose

MVP-level Go testing template providing essential unit and component tests for basic application functionality. Focuses on testing core business logic, utilities, and simple integration points with minimal setup and fast execution.

## Usage

```bash
# Copy to your Go project
# Project: [[.ProjectName]]
# Author: [[.Author]]
cp _templates/tiers/mvp/tests/basic-tests-go.tpl.go basic_test.go

# Run tests
go test -v ./...

# Run with coverage
go test -v -cover ./...

# Run specific test
go test -v -run TestCalculator
```

## Structure

```go
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

/**
 * MVP Go Test Suite
 * 
 * This test suite follows the MVP testing philosophy:
 * - Focus on core business logic and essential HTTP functionality
 * - Fast execution with minimal setup and mocking
 * - No complex integration testing or database operations
 * - Educational comments to teach Go testing patterns
 * 
 * MVP Testing Approach:
 * - Unit tests for pure business logic and utilities
 * - HTTP tests for basic API endpoints
 * - No database integration tests (added in Core tier)
 * - No performance or concurrency tests (added in Enterprise tier)
 * 
 * Key Go Testing Patterns:
 * - testing.T: Standard testing package
 * - testify/assert: Assertion library for readable tests
 * - testify/mock: Mocking framework for dependencies
 * - httptest: HTTP testing utilities
 * - Table-driven tests: Multiple test cases in one function
 */

// Test Models - Structs for testing business logic
// MVP approach: Simple structs with basic validation
type User struct {
	ID       int       `json:"id"`
	Name     string    `json:"name"`
	Email    string    `json:"email"`
	Age      int       `json:"age"`
	Active   bool      `json:"active"`
	CreateAt time.Time `json:"created_at"`
}

type Product struct {
	ID    int     `json:"id"`
	Name  string  `json:"name"`
	Price float64 `json:"price"`
	Stock int     `json:"stock"`
}

type Calculator struct{}

func (c *Calculator) Add(a, b int) int {
	return a + b
}

func (c *Calculator) Subtract(a, b int) int {
	return a - b
}

func (c *Calculator) Multiply(a, b int) int {
	return a * b
}

func (c *Calculator) Divide(a, b int) (int, error) {
	if b == 0 {
		return 0, errors.New("cannot divide by zero")
	}
	return a / b, nil
}

type UserValidator struct{}

func (v *UserValidator) IsValidEmail(email string) bool {
	return len(email) > 3 && 
		   email.Contains("@") && 
		   email.Contains(".") && 
		   email.LastIndex("@") < email.LastIndex(".")
}

func (v *UserValidator) IsValidPassword(password string) bool {
	return len(password) >= 8 && 
		   hasUpper(password) && 
		   hasDigit(password)
}

func (v *UserValidator) IsValidAge(age int) bool {
	return age >= 18 && age <= 120
}

type DataProcessor struct{}

func (p *DataProcessor) ProcessList(numbers []int) []int {
	result := make([]int, len(numbers))
	for i, num := range numbers {
		result[i] = num * 2
	}
	return result
}

func (p *DataProcessor) FilterValidData(data []interface{}) []interface{} {
	var result []interface{}
	for _, item := range data {
		if item != nil && item != "" {
			result = append(result, item)
		}
	}
	return result
}

// Utility functions
func hasUpper(s string) bool {
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			return true
		}
	}
	return false
}

func hasDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// Mock Services
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) CreateUser(user *User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserService) GetUser(id int) (*User, error) {
	args := m.Called(id)
	return args.Get(0).(*User), args.Error(1)
}

// HTTP Handlers
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "OK",
		"timestamp": time.Now(),
	})
}

func CreateUserHandler(service *MockUserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		validator := &UserValidator{}
		if !validator.IsValidEmail(user.Email) {
			http.Error(w, "Invalid email format", http.StatusBadRequest)
			return
		}

		if !validator.IsValidAge(user.Age) {
			http.Error(w, "Invalid age", http.StatusBadRequest)
			return
		}

		if err := service.CreateUser(&user); err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(user)
	}
}

// Test Suites

func TestCalculator(t *testing.T) {
	calc := &Calculator{}

	t.Run("Add", func(t *testing.T) {
		result := calc.Add(2, 3)
		assert.Equal(t, 5, result, "2 + 3 should equal 5")
	})

	t.Run("Subtract", func(t *testing.T) {
		result := calc.Subtract(10, 3)
		assert.Equal(t, 7, result, "10 - 3 should equal 7")
	})

	t.Run("Multiply", func(t *testing.T) {
		result := calc.Multiply(4, 5)
		assert.Equal(t, 20, result, "4 * 5 should equal 20")
	})

	t.Run("Divide", func(t *testing.T) {
		result, err := calc.Divide(20, 4)
		require.NoError(t, err, "Division should not error")
		assert.Equal(t, 5, result, "20 / 4 should equal 5")
	})

	t.Run("DivideByZero", func(t *testing.T) {
		_, err := calc.Divide(10, 0)
		assert.Error(t, err, "Division by zero should error")
		assert.Contains(t, err.Error(), "cannot divide by zero", "Error message should be descriptive")
	})
}

func TestUserValidator(t *testing.T) {
	validator := &UserValidator{}

	t.Run("ValidEmail", func(t *testing.T) {
		validEmails := []string{
			"test@example.com",
			"user.name@domain.co.uk",
			"test+tag@example.org",
		}

		for _, email := range validEmails {
			t.Run(fmt.Sprintf("Email_%s", email), func(t *testing.T) {
				assert.True(t, validator.IsValidEmail(email), "Email %s should be valid", email)
			})
		}
	})

	t.Run("InvalidEmail", func(t *testing.T) {
		invalidEmails := []string{
			"test@",
			"@example.com",
			"test.example.com",
			"test@.com",
			"test@com",
			"",
			"ab", // too short
		}

		for _, email := range invalidEmails {
			t.Run(fmt.Sprintf("Email_%s", email), func(t *testing.T) {
				assert.False(t, validator.IsValidEmail(email), "Email %s should be invalid", email)
			})
		}
	})

	t.Run("ValidPassword", func(t *testing.T) {
		validPasswords := []string{
			"SecurePass123",
			"MyPassword1",
			"StrongPass9",
		}

		for _, password := range validPasswords {
			t.Run(fmt.Sprintf("Password_%s", password), func(t *testing.T) {
				assert.True(t, validator.IsValidPassword(password), "Password %s should be valid", password)
			})
		}
	})

	t.Run("InvalidPassword", func(t *testing.T) {
		invalidPasswords := []string{
			"123",           // too short
			"password",      // no uppercase, no digit
			"PASSWORD",      // no lowercase, no digit
			"Password",      // no digit
			"Password123",   // valid but edge case
			"",              // empty
		}

		for _, password := range invalidPasswords {
			t.Run(fmt.Sprintf("Password_%s", password), func(t *testing.T) {
				assert.False(t, validator.IsValidPassword(password), "Password %s should be invalid", password)
			})
		}
	})

	t.Run("ValidAge", func(t *testing.T) {
		validAges := []int{18, 25, 50, 100, 120}
		for _, age := range validAges {
			t.Run(fmt.Sprintf("Age_%d", age), func(t *testing.T) {
				assert.True(t, validator.IsValidAge(age), "Age %d should be valid", age)
			})
		}
	})

	t.Run("InvalidAge", func(t *testing.T) {
		invalidAges := []int{0, 17, 121, 150}
		for _, age := range invalidAges {
			t.Run(fmt.Sprintf("Age_%d", age), func(t *testing.T) {
				assert.False(t, validator.IsValidAge(age), "Age %d should be invalid", age)
			})
		}
	})
}

func TestDataProcessor(t *testing.T) {
	processor := &DataProcessor{}

	t.Run("ProcessEmptyList", func(t *testing.T) {
		result := processor.ProcessList([]int{})
		assert.Empty(t, result, "Empty list should remain empty")
	})

	t.Run("ProcessNumericList", func(t *testing.T) {
		input := []int{1, 2, 3, 4, 5}
		expected := []int{2, 4, 6, 8, 10}
		result := processor.ProcessList(input)
		assert.Equal(t, expected, result, "List should be doubled")
	})

	t.Run("FilterValidData", func(t *testing.T) {
		input := []interface{}{1, nil, 3, "", 5, 0}
		expected := []interface{}{1, 3, 5, 0}
		result := processor.FilterValidData(input)
		assert.Equal(t, expected, result, "Should filter out nil and empty strings")
	})
}

func TestHTTPHandlers(t *testing.T) {
	t.Run("HealthHandler", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		HealthHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "OK", response["status"])
		assert.NotNil(t, response["timestamp"])
	})

	t.Run("CreateUserHandler_Success", func(t *testing.T) {
		mockService := new(MockUserService)
		mockService.On("CreateUser", mock.AnythingOfType("*main.User")).Return(nil)

		handler := CreateUserHandler(mockService)

		userData := map[string]interface{}{
			"name":  "Test User",
			"email": "test@example.com",
			"age":   25,
		}

		body, _ := json.Marshal(userData)
		req := httptest.NewRequest("POST", "/users", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("CreateUserHandler_InvalidEmail", func(t *testing.T) {
		mockService := new(MockUserService)
		handler := CreateUserHandler(mockService)

		userData := map[string]interface{}{
			"name":  "Test User",
			"email": "invalid-email",
			"age":   25,
		}

		body, _ := json.Marshal(userData)
		req := httptest.NewRequest("POST", "/users", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid email format")
	})
}

func TestIntegration(t *testing.T) {
	t.Run("UserCreationWorkflow", func(t *testing.T) {
		mockService := new(MockUserService)
		mockService.On("CreateUser", mock.AnythingOfType("*main.User")).Return(nil)

		handler := CreateUserHandler(mockService)

		// Create valid user
		userData := User{
			Name:  "Integration User",
			Email: "integration@example.com",
			Age:   30,
		}

		body, _ := json.Marshal(userData)
		req := httptest.NewRequest("POST", "/users", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response User
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, userData.Name, response.Name)
		assert.Equal(t, userData.Email, response.Email)
		assert.Equal(t, userData.Age, response.Age)

		mockService.AssertExpectations(t)
	})
}

// Test Helpers and Utilities
func createMockUser(overrides map[string]interface{}) *User {
	user := &User{
		ID:       1,
		Name:     "Test User",
		Email:    "test@example.com",
		Age:      25,
		Active:   true,
		CreateAt: time.Now(),
	}

	for key, value := range overrides {
		switch key {
		case "id":
			user.ID = value.(int)
		case "name":
			user.Name = value.(string)
		case "email":
			user.Email = value.(string)
		case "age":
			user.Age = value.(int)
		case "active":
			user.Active = value.(bool)
		}
	}

	return user
}

func createMockProduct(overrides map[string]interface{}) *Product {
	product := &Product{
		ID:    1,
		Name:  "Test Product",
		Price: 10.99,
		Stock: 100,
	}

	for key, value := range overrides {
		switch key {
		case "id":
			product.ID = value.(int)
		case "name":
			product.Name = value.(string)
		case "price":
			product.Price = value.(float64)
		case "stock":
			product.Stock = value.(int)
		}
	}

	return product
}

func assertValidUser(t *testing.T, user *User) {
	assert.Greater(t, user.ID, 0, "User ID should be positive")
	assert.NotEmpty(t, user.Name, "User name should not be empty")
	assert.True(t, (&UserValidator{}).IsValidEmail(user.Email), "User email should be valid")
	assert.True(t, (&UserValidator{}).IsValidAge(user.Age), "User age should be valid")
}

func assertValidApiResponse(t *testing.T, response map[string]interface{}) {
	assert.Contains(t, response, "status", "API response should have status field")
	assert.Contains(t, response, "data", "API response should have data field")
	assert.Contains(t, []string{"success", "error"}, response["status"], "Status should be valid")
}

// Benchmark Tests
func BenchmarkCalculatorAdd(b *testing.B) {
	calc := &Calculator{}
	for i := 0; i < b.N; i++ {
		calc.Add(100, 200)
	}
}

func BenchmarkUserValidatorEmail(b *testing.B) {
	validator := &UserValidator{}
	email := "test@example.com"
	for i := 0; i < b.N; i++ {
		validator.IsValidEmail(email)
	}
}

// Example Tests (also serve as documentation)
func ExampleCalculator_Add() {
	calc := &Calculator{}
	result := calc.Add(2, 3)
	fmt.Println(result)
	// Output: 5
}

func ExampleUserValidator_IsValidEmail() {
	validator := &UserValidator{}
	fmt.Println(validator.IsValidEmail("test@example.com"))
	fmt.Println(validator.IsValidEmail("invalid-email"))
	// Output:
	// true
	// false
}
```

## Guidelines

### Test Organization
- **Unit Tests**: Test individual functions and methods in isolation
- **Integration Tests**: Test component interactions and HTTP handlers
- **Benchmark Tests**: Performance testing for critical functions
- **Example Tests**: Documentation and usage examples

### Go Testing Best Practices
- Use table-driven tests for multiple test cases
- Use testify/assert for assertions and testify/mock for mocking
- Use testify/require for fatal assertions
- Test both success and error paths
- Use descriptive test names with subtests

### Test Structure
- Use `t.Run()` for subtests to organize test cases
- Use table-driven tests for data validation
- Mock external dependencies with testify/mock
- Use httptest for HTTP handler testing

### Coverage Requirements
- **Unit Tests**: 80%+ coverage for business logic
- **Integration Tests**: 60%+ coverage for HTTP handlers
- **Overall**: 75%+ minimum for MVP

## Required Dependencies

Add to `go.mod`:

```go
require (
    github.com/stretchr/testify v1.8.4
)
```

## What's Included

- **Unit Tests**: Business logic, utilities, data validation
- **Integration Tests**: HTTP handlers and service interactions
- **Mock Services**: testify/mock for external dependencies
- **Test Helpers**: Mock data factories and assertions
- **Benchmark Tests**: Performance testing examples

## What's NOT Included

- Database integration tests
- External API integration tests
- Concurrent/goroutine testing
- File system operations testing

---

**Template Version**: 1.0 (MVP)  
**Last Updated**: 2025-12-10  
**Stack**: Go  
**Tier**: MVP  
**Framework**: Go testing + testify
