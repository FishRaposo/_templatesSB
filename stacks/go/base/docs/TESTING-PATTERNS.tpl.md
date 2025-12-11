# Universal Template System - Go Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: go
# Category: template

# Go Testing Patterns

## Purpose
Comprehensive guide to Go testing patterns, including unit tests, integration tests, benchmarks, table-driven tests, and testing best practices.

## Basic Testing Patterns

### 1. Unit Testing Fundamentals
```go
package calculator

import (
	"testing"
)

// Simple function to test
func Add(a, b int) int {
	return a + b
}

func Subtract(a, b int) int {
	return a - b
}

func Multiply(a, b int) int {
	return a * b
}

func Divide(a, b float64) (float64, error) {
	if b == 0 {
		return 0, errors.New("division by zero")
	}
	return a / b, nil
}

// Basic unit tests
func TestAdd(t *testing.T) {
	result := Add(2, 3)
	expected := 5
	if result != expected {
		t.Errorf("Add(2, 3) = %d; want %d", result, expected)
	}
}

func TestSubtract(t *testing.T) {
	result := Subtract(5, 3)
	expected := 2
	if result != expected {
		t.Errorf("Subtract(5, 3) = %d; want %d", result, expected)
	}
}

func TestMultiply(t *testing.T) {
	tests := []struct {
		name     string
		a, b     int
		expected int
	}{
		{"positive", 2, 3, 6},
		{"negative", -2, 3, -6},
		{"zero", 0, 5, 0},
		{"both negative", -2, -3, 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Multiply(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("Multiply(%d, %d) = %d; want %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestDivide(t *testing.T) {
	t.Run("valid division", func(t *testing.T) {
		result, err := Divide(10, 2)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if result != 5.0 {
			t.Errorf("Divide(10, 2) = %f; want 5.0", result)
		}
	})

	t.Run("division by zero", func(t *testing.T) {
		result, err := Divide(10, 0)
		if err == nil {
			t.Error("Expected error for division by zero")
		}
		if result != 0 {
			t.Errorf("Divide(10, 0) = %f; want 0", result)
		}
	})
}
```

### 2. Table-Driven Tests
```go
package strings

import (
	"testing"
)

// Function to test
func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func IsPalindrome(s string) bool {
	// Remove non-alphanumeric characters and convert to lowercase
	cleaned := ""
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			if r >= 'A' && r <= 'Z' {
				r = r + ('a' - 'A')
			}
			cleaned += string(r)
		}
	}
	
	return cleaned == Reverse(cleaned)
}

// Comprehensive table-driven tests
func TestReverse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"single character", "a", "a"},
		{"two characters", "ab", "ba"},
		{"odd length", "abc", "cba"},
		{"even length", "abcd", "dcba"},
		{"with spaces", "hello world", "dlrow olleh"},
		{"with unicode", "こんにちは", "はちにんこ"},
		{"with emojis", "👋🌍", "🌍👋"},
		{"mixed case", "Hello", "olleH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Reverse(tt.input)
			if result != tt.expected {
				t.Errorf("Reverse(%q) = %q; want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsPalindrome(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"empty string", "", true},
		{"single character", "a", true},
		{"palindrome", "racecar", true},
		{"palindrome with spaces", "A man a plan a canal Panama", true},
		{"palindrome with punctuation", "Madam, I'm Adam", true},
		{"palindrome with numbers", "12321", true},
		{"not palindrome", "hello", false},
		{"almost palindrome", "racecars", false},
		{"with unicode", "たけやぶやけた", true},
		{"mixed case", "Level", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPalindrome(tt.input)
			if result != tt.expected {
				t.Errorf("IsPalindrome(%q) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}
```

### 3. Test Helpers and Utilities
```go
package testing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Test helper functions
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func AssertError(t *testing.T, err error, expectedMsg string) {
	t.Helper()
	if err == nil {
		t.Fatal("Expected error but got none")
	}
	if expectedMsg != "" && err.Error() != expectedMsg {
		t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
	}
}

func AssertEqual(t *testing.T, got, want interface{}) {
	t.Helper()
	if got != want {
		t.Errorf("Expected %v, got %v", want, got)
	}
}

func AssertNotEqual(t *testing.T, got, want interface{}) {
	t.Helper()
	if got == want {
		t.Errorf("Expected not equal, but both are %v", got)
	}
}

func AssertTrue(t *testing.T, condition bool, msg string) {
	t.Helper()
	if !condition {
		t.Errorf("Expected true, got false: %s", msg)
	}
}

func AssertFalse(t *testing.T, condition bool, msg string) {
	t.Helper()
	if condition {
		t.Errorf("Expected false, got true: %s", msg)
	}
}

// HTTP testing helpers
func AssertHTTPStatus(t *testing.T, resp *http.Response, expected int) {
	t.Helper()
	if resp.StatusCode != expected {
		t.Errorf("Expected status %d, got %d", expected, resp.StatusCode)
	}
}

func AssertHTTPHeader(t *testing.T, resp *http.Response, key, expected string) {
	t.Helper()
	actual := resp.Header.Get(key)
	if actual != expected {
		t.Errorf("Expected header %s = %q, got %q", key, expected, actual)
	}
}

func AssertJSONBody(t *testing.T, resp *http.Response, expected interface{}) {
	t.Helper()
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	
	var actual interface{}
	if err := json.Unmarshal(body, &actual); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}
	
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("JSON body mismatch.\nExpected: %+v\nActual: %+v", expected, actual)
	}
}

// File system testing helpers
func CreateTempFile(t *testing.T, content string) string {
	t.Helper()
	
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	
	return tmpFile
}

func CreateTempDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// Time testing helpers
func AssertTimeWithin(t *testing.T, start, end, actual time.Time, tolerance time.Duration) {
	t.Helper()
	if actual.Before(start.Add(-tolerance)) || actual.After(end.Add(tolerance)) {
		t.Errorf("Time %v not within expected range [%v, %v] ± %v", actual, start, end, tolerance)
	}
}

// Mock implementations
type MockService struct {
	responses map[string]interface{}
	errors    map[string]error
	calls     map[string]int
}

func NewMockService() *MockService {
	return &MockService{
		responses: make(map[string]interface{}),
		errors:    make(map[string]error),
		calls:     make(map[string]int),
	}
}

func (m *MockService) SetResponse(method string, response interface{}) {
	m.responses[method] = response
}

func (m *MockService) SetError(method string, err error) {
	m.errors[method] = err
}

func (m *MockService) GetCallCount(method string) int {
	return m.calls[method]
}

func (m *MockService) Call(method string) (interface{}, error) {
	m.calls[method]++
	
	if err, exists := m.errors[method]; exists {
		return nil, err
	}
	
	if response, exists := m.responses[method]; exists {
		return response, nil
	}
	
	return nil, fmt.Errorf("no response set for method %s", method)
}

// Usage examples
func TestWithHelpers(t *testing.T) {
	// Test error handling
	err := someFunction()
	AssertNoError(t, err)
	
	// Test equality
	result := calculateSomething()
	AssertEqual(t, result, 42)
	
	// Test HTTP handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "hello"}`))
	})
	
	req := httptest.NewRequest("GET", "/", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	
	AssertHTTPStatus(t, resp.Result(), http.StatusOK)
	AssertJSONBody(t, resp.Result(), map[string]string{"message": "hello"})
}
```

## Advanced Testing Patterns

### 1. Mocking and Fakes
```go
package database

import (
	"context"
	"testing"
	"time"
)

// Interface to mock
type UserRepository interface {
	GetUser(ctx context.Context, id string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
}

// User struct
type User struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Mock implementation
type MockUserRepository struct {
	users map[string]*User
	err   error
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users: make(map[string]*User),
	}
}

func (m *MockUserRepository) SetError(err error) {
	m.err = err
}

func (m *MockUserRepository) GetUser(ctx context.Context, id string) (*User, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.users[id], nil
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *User) error {
	if m.err != nil {
		return m.err
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	return nil
}

func (m *MockUserRepository) UpdateUser(ctx context.Context, user *User) error {
	if m.err != nil {
		return m.err
	}
	if _, exists := m.users[user.ID]; !exists {
		return fmt.Errorf("user not found")
	}
	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	return nil
}

func (m *MockUserRepository) DeleteUser(ctx context.Context, id string) error {
	if m.err != nil {
		return m.err
	}
	delete(m.users, id)
	return nil
}

// Service that uses the repository
type UserService struct {
	repo UserRepository
}

func NewUserService(repo UserRepository) *UserService {
	return &UserService{repo: repo}
}

func (s *UserService) GetUser(ctx context.Context, id string) (*User, error) {
	return s.repo.GetUser(ctx, id)
}

func (s *UserService) CreateUser(ctx context.Context, name, email string) (*User, error) {
	user := &User{
		ID:    generateID(),
		Name:  name,
		Email: email,
	}
	
	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	
	return user, nil
}

// Tests with mocks
func TestUserService_GetUser(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		mockUser      *User
		mockError     error
		expectedUser  *User
		expectedError error
	}{
		{
			name:     "successful get",
			userID:   "123",
			mockUser: &User{ID: "123", Name: "John", Email: "john@example.com"},
			expectedUser: &User{ID: "123", Name: "John", Email: "john@example.com"},
		},
		{
			name:          "user not found",
			userID:        "456",
			mockError:     fmt.Errorf("user not found"),
			expectedError: fmt.Errorf("user not found"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := NewMockUserRepository()
			if tt.mockUser != nil {
				mockRepo.users[tt.userID] = tt.mockUser
			}
			mockRepo.SetError(tt.mockError)

			service := NewUserService(mockRepo)
			user, err := service.GetUser(context.Background(), tt.userID)

			if tt.expectedError != nil {
				if err == nil || err.Error() != tt.expectedError.Error() {
					t.Errorf("Expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if !reflect.DeepEqual(user, tt.expectedUser) {
					t.Errorf("Expected user %v, got %v", tt.expectedUser, user)
				}
			}
		})
	}
}

func TestUserService_CreateUser(t *testing.T) {
	mockRepo := NewMockUserRepository()
	service := NewUserService(mockRepo)

	user, err := service.CreateUser(context.Background(), "John Doe", "john@example.com")
	
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if user.ID == "" {
		t.Error("Expected user ID to be set")
	}
	
	if user.Name != "John Doe" {
		t.Errorf("Expected name 'John Doe', got '%s'", user.Name)
	}
	
	if user.Email != "john@example.com" {
		t.Errorf("Expected email 'john@example.com', got '%s'", user.Email)
	}
	
	if user.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	
	// Verify user was added to mock repository
	retrievedUser, err := mockRepo.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Errorf("Failed to retrieve created user: %v", err)
	}
	
	if !reflect.DeepEqual(user, retrievedUser) {
		t.Errorf("Retrieved user doesn't match created user")
	}
}
```

### 2. Integration Testing
```go
package integration

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Test database setup
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	
	// Connect to test database
	db, err := sql.Open("postgres", "postgres://test:test@localhost/testdb?sslmode=disable")
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	
	// Clean up database
	_, err = db.Exec("TRUNCATE TABLE users, orders CASCADE")
	if err != nil {
		t.Fatalf("Failed to clean database: %v", err)
	}
	
	// Run migrations
	err = runMigrations(db)
	if err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}
	
	return db
}

func teardownTestDB(t *testing.T, db *sql.DB) {
	t.Helper()
	
	err := db.Close()
	if err != nil {
		t.Errorf("Failed to close database: %v", err)
	}
}

// HTTP integration test
func TestUserAPI_Integration(t *testing.T) {
	// Setup test database
	db := setupTestDB(t)
	defer teardownTestDB(t, db)
	
	// Setup test server
	userService := NewUserService(NewUserRepository(db))
	handler := NewUserHandler(userService)
	server := httptest.NewServer(handler)
	defer server.Close()
	
	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := server.URL
	
	// Test user creation
	createReq := CreateUserRequest{
		Name:  "John Doe",
		Email: "john@example.com",
	}
	
	resp, err := httpPost(client, baseURL+"/users", createReq)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	defer resp.Body.Close()
	
	AssertHTTPStatus(t, resp, http.StatusCreated)
	
	var user User
	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	
	// Test user retrieval
	resp, err = client.Get(baseURL + "/users/" + user.ID)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}
	defer resp.Body.Close()
	
	AssertHTTPStatus(t, resp, http.StatusOK)
	
	var retrievedUser User
	err = json.NewDecoder(resp.Body).Decode(&retrievedUser)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	
	if !reflect.DeepEqual(user, retrievedUser) {
		t.Errorf("Retrieved user doesn't match created user")
	}
	
	// Test user update
	updateReq := UpdateUserRequest{
		Name: "Jane Doe",
	}
	
	resp, err = httpPut(client, baseURL+"/users/"+user.ID, updateReq)
	if err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}
	defer resp.Body.Close()
	
	AssertHTTPStatus(t, resp, http.StatusOK)
	
	// Test user deletion
	resp, err = httpDelete(client, baseURL+"/users/"+user.ID)
	if err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
	defer resp.Body.Close()
	
	AssertHTTPStatus(t, resp, http.StatusNoContent)
	
	// Verify user is deleted
	resp, err = client.Get(baseURL + "/users/" + user.ID)
	if err != nil {
		t.Fatalf("Failed to get user after deletion: %v", err)
	}
	defer resp.Body.Close()
	
	AssertHTTPStatus(t, resp, http.StatusNotFound)
}

// Database integration test
func TestUserRepository_Integration(t *testing.T) {
	db := setupTestDB(t)
	defer teardownTestDB(t, db)
	
	repo := NewUserRepository(db)
	ctx := context.Background()
	
	// Test create user
	user := &User{
		ID:    "123",
		Name:  "John Doe",
		Email: "john@example.com",
	}
	
	err := repo.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	
	// Test get user
	retrievedUser, err := repo.GetUser(ctx, "123")
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}
	
	if !reflect.DeepEqual(user, retrievedUser) {
		t.Errorf("Retrieved user doesn't match created user")
	}
	
	// Test update user
	user.Name = "Jane Doe"
	err = repo.UpdateUser(ctx, user)
	if err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}
	
	updatedUser, err := repo.GetUser(ctx, "123")
	if err != nil {
		t.Fatalf("Failed to get updated user: %v", err)
	}
	
	if updatedUser.Name != "Jane Doe" {
		t.Errorf("Expected updated name 'Jane Doe', got '%s'", updatedUser.Name)
	}
	
	// Test delete user
	err = repo.DeleteUser(ctx, "123")
	if err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}
	
	_, err = repo.GetUser(ctx, "123")
	if err == nil {
		t.Error("Expected error when getting deleted user")
	}
}

// End-to-end test
func TestOrderFlow_E2E(t *testing.T) {
	db := setupTestDB(t)
	defer teardownTestDB(t, db)
	
	// Setup services
	userRepo := NewUserRepository(db)
	orderRepo := NewOrderRepository(db)
	userService := NewUserService(userRepo)
	orderService := NewOrderService(orderRepo, userService)
	
	// Create user
	user, err := userService.CreateUser(context.Background(), "John Doe", "john@example.com")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	
	// Create order
	order, err := orderService.CreateOrder(context.Background(), user.ID, []OrderItem{
		{ProductID: "prod1", Quantity: 2, Price: 10.99},
		{ProductID: "prod2", Quantity: 1, Price: 24.99},
	})
	if err != nil {
		t.Fatalf("Failed to create order: %v", err)
	}
	
	// Verify order
	if order.UserID != user.ID {
		t.Errorf("Expected order user ID %s, got %s", user.ID, order.UserID)
	}
	
	if len(order.Items) != 2 {
		t.Errorf("Expected 2 order items, got %d", len(order.Items))
	}
	
	expectedTotal := 2*10.99 + 1*24.99
	if order.Total != expectedTotal {
		t.Errorf("Expected total %f, got %f", expectedTotal, order.Total)
	}
	
	// Process payment
	err = orderService.ProcessPayment(context.Background(), order.ID, "payment_token")
	if err != nil {
		t.Fatalf("Failed to process payment: %v", err)
	}
	
	// Verify order status
	processedOrder, err := orderService.GetOrder(context.Background(), order.ID)
	if err != nil {
		t.Fatalf("Failed to get processed order: %v", err)
	}
	
	if processedOrder.Status != "paid" {
		t.Errorf("Expected order status 'paid', got '%s'", processedOrder.Status)
	}
}
```

### 3. Benchmark Testing
```go
package performance

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"
)

// Functions to benchmark
func BubbleSort(arr []int) []int {
	n := len(arr)
	result := make([]int, n)
	copy(result, arr)
	
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if result[j] > result[j+1] {
				result[j], result[j+1] = result[j+1], result[j]
			}
		}
	}
	
	return result
}

func QuickSort(arr []int) []int {
	if len(arr) <= 1 {
		return arr
	}
	
	pivot := arr[0]
	left := []int{}
	right := []int{}
	
	for _, v := range arr[1:] {
		if v <= pivot {
			left = append(left, v)
		} else {
			right = append(right, v)
		}
	}
	
	result := append(QuickSort(left), pivot)
	result = append(result, QuickSort(right)...)
	
	return result
}

func MergeSort(arr []int) []int {
	if len(arr) <= 1 {
		return arr
	}
	
	mid := len(arr) / 2
	left := MergeSort(arr[:mid])
	right := MergeSort(arr[mid:])
	
	return merge(left, right)
}

func merge(left, right []int) []int {
	result := make([]int, 0, len(left)+len(right))
	i, j := 0, 0
	
	for i < len(left) && j < len(right) {
		if left[i] <= right[j] {
			result = append(result, left[i])
			i++
		} else {
			result = append(result, right[j])
			j++
		}
	}
	
	result = append(result, left[i:]...)
	result = append(result, right[j:]...)
	
	return result
}

// Generate test data
func generateRandomData(size int) []int {
	data := make([]int, size)
	for i := range data {
		data[i] = rand.Intn(1000)
	}
	return data
}

func generateSortedData(size int) []int {
	data := make([]int, size)
	for i := range data {
		data[i] = i
	}
	return data
}

func generateReversedData(size int) []int {
	data := make([]int, size)
	for i := range data {
		data[i] = size - i
	}
	return data
}

// Benchmark tests
func BenchmarkBubbleSort_Random_100(b *testing.B) {
	data := generateRandomData(100)
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		BubbleSort(data)
	}
}

func BenchmarkQuickSort_Random_100(b *testing.B) {
	data := generateRandomData(100)
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		QuickSort(data)
	}
}

func BenchmarkMergeSort_Random_100(b *testing.B) {
	data := generateRandomData(100)
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		MergeSort(data)
	}
}

func BenchmarkSort_Random_100(b *testing.B) {
	data := generateRandomData(100)
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		sort.Ints(data)
	}
}

// Benchmark with different data sizes
func BenchmarkQuickSort_Sizes(b *testing.B) {
	sizes := []int{100, 1000, 10000}
	
	for _, size := range sizes {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			data := generateRandomData(size)
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				QuickSort(data)
			}
		})
	}
}

// Benchmark with different data patterns
func BenchmarkQuickSort_Patterns(b *testing.B) {
	patterns := map[string]func(int) []int{
		"random":   generateRandomData,
		"sorted":   generateSortedData,
		"reversed": generateReversedData,
	}
	
	for pattern, generator := range patterns {
		b.Run(pattern, func(b *testing.B) {
			data := generator(1000)
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				QuickSort(data)
			}
		})
	}
}

// Memory allocation benchmark
func BenchmarkSliceAllocation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = make([]int, 1000)
	}
}

func BenchmarkMapOperations(b *testing.B) {
	m := make(map[int]string)
	
	// Benchmark map insertion
	b.Run("insert", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			m[i] = fmt.Sprintf("value_%d", i)
		}
	})
	
	// Benchmark map lookup
	b.Run("lookup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = m[i%1000]
		}
	})
	
	// Benchmark map deletion
	b.Run("delete", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			delete(m, i%1000)
		}
	})
}

// Concurrent operations benchmark
func BenchmarkConcurrentGoroutines(b *testing.B) {
	b.Run("10_goroutines", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				// Simulate work
				time.Sleep(time.Microsecond)
			}
		})
	})
	
	b.Run("100_goroutines", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				// Simulate work
				time.Sleep(time.Microsecond)
			}
		})
	})
}

// String operations benchmark
func BenchmarkStringConcatenation(b *testing.B) {
	strings := []string{"hello", "world", "benchmark", "testing"}
	
	b.Run("plus_operator", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			result := ""
			for _, s := range strings {
				result += s
			}
		}
	})
	
	b.Run("fmt_sprintf", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			result := fmt.Sprintf("%s%s%s%s", strings[0], strings[1], strings[2], strings[3])
			_ = result
		}
	})
	
	b.Run("strings_builder", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var builder strings.Builder
			for _, s := range strings {
				builder.WriteString(s)
			}
			_ = builder.String()
		}
	})
}
```

## Testing Best Practices

### 1. Test Organization and Structure
```go
// ✅ GOOD: Well-organized test file
package user

import (
	"context"
	"testing"
	"time"
)

// Test constants
const (
	testUserID = "test-user-123"
	testEmail  = "test@example.com"
)

// Test fixtures
func createTestUser(t *testing.T) *User {
	t.Helper()
	return &User{
		ID:        testUserID,
		Name:      "Test User",
		Email:     testEmail,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func createTestUserService(t *testing.T) *UserService {
	t.Helper()
	mockRepo := NewMockUserRepository()
	return NewUserService(mockRepo)
}

// Test categories
func TestUserService_Creation(t *testing.T) {
	// Tests related to user creation
}

func TestUserService_Retrieval(t *testing.T) {
	// Tests related to user retrieval
}

func TestUserService_Validation(t *testing.T) {
	// Tests related to input validation
}

// ✅ GOOD: Clear test names
func TestUserService_CreateUser_WithValidData_ReturnsUser(t *testing.T) {
	// Test implementation
}

func TestUserService_CreateUser_WithDuplicateEmail_ReturnsError(t *testing.T) {
	// Test implementation
}

// ✅ GOOD: Subtests for related scenarios
func TestUserService_CreateUser(t *testing.T) {
	t.Run("valid data", func(t *testing.T) {
		// Test valid user creation
	})
	
	t.Run("invalid email", func(t *testing.T) {
		// Test invalid email handling
	})
	
	t.Run("duplicate email", func(t *testing.T) {
		// Test duplicate email handling
	})
}
```

### 2. Test Data Management
```go
// ✅ GOOD: Use test builders
type UserBuilder struct {
	user *User
}

func NewUserBuilder() *UserBuilder {
	return &UserBuilder{
		user: &User{
			ID:        generateTestID(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
}

func (b *UserBuilder) WithID(id string) *UserBuilder {
	b.user.ID = id
	return b
}

func (b *UserBuilder) WithName(name string) *UserBuilder {
	b.user.Name = name
	return b
}

func (b *UserBuilder) WithEmail(email string) *UserBuilder {
	b.user.Email = email
	return b
}

func (b *UserBuilder) CreatedAt(t time.Time) *UserBuilder {
	b.user.CreatedAt = t
	return b
}

func (b *UserBuilder) Build() *User {
	return b.user
}

// Usage in tests
func TestUserValidation(t *testing.T) {
	validUser := NewUserBuilder().
		WithName("John Doe").
		WithEmail("john@example.com").
		Build()
	
	invalidUser := NewUserBuilder().
		WithName("").
		WithEmail("invalid-email").
		Build()
	
	// Test with both users
}

// ✅ GOOD: Use factories for test data
type TestDataFactory struct {
	userCounter int
}

func NewTestDataFactory() *TestDataFactory {
	return &TestDataFactory{}
}

func (f *TestDataFactory) CreateUser() *User {
	f.userCounter++
	return &User{
		ID:        fmt.Sprintf("user-%d", f.userCounter),
		Name:      fmt.Sprintf("User %d", f.userCounter),
		Email:     fmt.Sprintf("user%d@example.com", f.userCounter),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (f *TestDataFactory) CreateUsers(count int) []*User {
	users := make([]*User, count)
	for i := 0; i < count; i++ {
		users[i] = f.CreateUser()
	}
	return users
}
```

### 3. Performance and Maintainability
```go
// ✅ GOOD: Parallel tests when independent
func TestParallelOperations(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T)
	}{
		{"operation1", testOperation1},
		{"operation2", testOperation2},
		{"operation3", testOperation3},
	}
	
	for _, tt := range tests {
		tt := tt // Capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.test(t)
		})
	}
}

// ✅ GOOD: Cleanup resources
func TestWithResources(t *testing.T) {
	// Setup temporary directory
	tempDir := t.TempDir()
	
	// Setup database connection
	db := setupTestDB(t)
	defer db.Close()
	
	// Setup HTTP server
	server := httptest.NewServer(handler)
	defer server.Close()
	
	// Test implementation
}

// ✅ GOOD: Use testing.TB for reusable helpers
func AssertUserEqual(t testing.TB, got, want *User) {
	t.Helper()
	
	if got.ID != want.ID {
		t.Errorf("User ID mismatch: got %s, want %s", got.ID, want.ID)
	}
	
	if got.Name != want.Name {
		t.Errorf("User name mismatch: got %s, want %s", got.Name, want.Name)
	}
	
	if got.Email != want.Email {
		t.Errorf("User email mismatch: got %s, want %s", got.Email, want.Email)
	}
}

// Works with both testing.T and testing.B
func TestUserEquality(t *testing.T) {
	user1 := &User{ID: "1", Name: "John", Email: "john@example.com"}
	user2 := &User{ID: "1", Name: "John", Email: "john@example.com"}
	
	AssertUserEqual(t, user1, user2)
}

func BenchmarkUserComparison(b *testing.B) {
	user1 := &User{ID: "1", Name: "John", Email: "john@example.com"}
	user2 := &User{ID: "1", Name: "John", Email: "john@example.com"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AssertUserEqual(b, user1, user2)
	}
}
```

This comprehensive Go testing guide covers all essential patterns from basic unit tests to advanced integration testing, mocking, benchmarking, and testing best practices for robust and maintainable test suites.

---

**Go Version**: [GO_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
