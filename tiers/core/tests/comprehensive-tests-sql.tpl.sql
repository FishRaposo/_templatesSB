# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: core
# Stack: unknown
# Category: testing

# Comprehensive Go Testing Template
# Purpose: Core-level testing template with unit, integration, and feature tests for Go applications
# Usage: Copy to your project and customize for your Go project
# Stack: Go (.go)
# Tier: Core (Production Ready)

## Purpose

Core-level Go testing template providing comprehensive testing coverage including unit tests, integration tests, and feature tests for production-ready applications. Focuses on testing business logic, HTTP handlers, database interactions, and complete user features.

## Usage

```bash
# Copy to your Go project
cp _templates/tiers/core/tests/comprehensive-tests-go.tpl.go comprehensive_test.go

# Run tests
go test -v ./...

# Run with coverage
go test -v -cover ./...

# Run integration tests
go test -v -tags=integration ./...

# Run benchmarks
go test -v -bench=. ./...
```

## Structure

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Test Models
type User struct {
	ID        string    `json:"id" bson:"_id,omitempty"`
	Name      string    `json:"name" bson:"name"`
	Email     string    `json:"email" bson:"email"`
	Age       int       `json:"age" bson:"age"`
	Phone     string    `json:"phone" bson:"phone"`
	Active    bool      `json:"active" bson:"active"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
}

type Product struct {
	ID          string  `json:"id" bson:"_id,omitempty"`
	Name        string  `json:"name" bson:"name"`
	Price       float64 `json:"price" bson:"price"`
	Quantity    int     `json:"quantity" bson:"quantity"`
	Category    string  `json:"category" bson:"category"`
	Description string  `json:"description" bson:"description"`
	Image       string  `json:"image" bson:"image"`
}

type CartItem struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Price    float64 `json:"price"`
	Quantity int     `json:"quantity"`
	Total    float64 `json:"total"`
}

type Order struct {
	ID         string      `json:"id" bson:"_id,omitempty"`
	UserID     string      `json:"user_id" bson:"user_id"`
	Items      []CartItem  `json:"items" bson:"items"`
	Subtotal   float64     `json:"subtotal" bson:"subtotal"`
	Tax        float64     `json:"tax" bson:"tax"`
	Total      float64     `json:"total" bson:"total"`
	Status     string      `json:"status" bson:"status"`
	CreatedAt  time.Time   `json:"created_at" bson:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at" bson:"updated_at"`
}

// Business Logic
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
		   contains(email, "@") && 
		   contains(email, ".") && 
		   lastIndex(email, "@") < lastIndex(email, ".")
}

func (v *UserValidator) IsValidPassword(password string) bool {
	return len(password) >= 8 && 
		   hasUpper(password) && 
		   hasLower(password) && 
		   hasDigit(password)
}

func (v *UserValidator) IsValidAge(age int) bool {
	return age >= 18 && age <= 120
}

func (v *UserValidator) IsValidPhone(phone string) bool {
	// Remove non-digit characters
	digits := ""
	for _, r := range phone {
		if r >= '0' && r <= '9' {
			digits += string(r)
		}
	}
	return len(digits) >= 10
}

type PriceCalculator struct{}

func (p *PriceCalculator) CalculateSubtotal(items []CartItem) float64 {
	subtotal := 0.0
	for _, item := range items {
		subtotal += item.Price * float64(item.Quantity)
	}
	return subtotal
}

func (p *PriceCalculator) CalculateTax(subtotal float64, taxRate float64) float64 {
	return subtotal * taxRate
}

func (p *PriceCalculator) CalculateTotal(subtotal, tax float64) float64 {
	return subtotal + tax
}

// Mock Services
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) CreateUser(user *User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserService) GetUser(id string) (*User, error) {
	args := m.Called(id)
	return args.Get(0).(*User), args.Error(1)
}

func (m *MockUserService) UpdateUser(id string, user *User) error {
	args := m.Called(id, user)
	return args.Error(0)
}

func (m *MockUserService) DeleteUser(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserService) ListUsers() ([]*User, error) {
	args := m.Called()
	return args.Get(0).([]*User), args.Error(1)
}

type MockProductService struct {
	mock.Mock
}

func (m *MockProductService) CreateProduct(product *Product) error {
	args := m.Called(product)
	return args.Error(0)
}

func (m *MockProductService) GetProduct(id string) (*Product, error) {
	args := m.Called(id)
	return args.Get(0).(*Product), args.Error(1)
}

func (m *MockProductService) UpdateProduct(id string, product *Product) error {
	args := m.Called(id, product)
	return args.Error(0)
}

func (m *MockProductService) DeleteProduct(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockProductService) ListProducts() ([]*Product, error) {
	args := m.Called()
	return args.Get(0).([]*Product), args.Error(1)
}

func (m *MockProductService) UpdateStock(id string, quantity int) error {
	args := m.Called(id, quantity)
	return args.Error(0)
}

type MockOrderService struct {
	mock.Mock
}

func (m *MockOrderService) CreateOrder(order *Order) error {
	args := m.Called(order)
	return args.Error(0)
}

func (m *MockOrderService) GetOrder(id string) (*Order, error) {
	args := m.Called(id)
	return args.Get(0).(*Order), args.Error(1)
}

func (m *MockOrderService) ListUserOrders(userID string) ([]*Order, error) {
	args := m.Called(userID)
	return args.Get(0).([]*Order), args.Error(1)
}

// HTTP Handlers
func HealthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "OK",
		"timestamp": time.Now(),
	})
}

func CreateUserHandler(service *MockUserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		validator := &UserValidator{}
		if !validator.IsValidEmail(user.Email) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
			return
		}

		if !validator.IsValidAge(user.Age) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid age"})
			return
		}

		if !validator.IsValidPhone(user.Phone) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone number"})
			return
		}

		user.CreatedAt = time.Now()
		user.Active = true

		if err := service.CreateUser(&user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		c.JSON(http.StatusCreated, user)
	}
}

func GetUserHandler(service *MockUserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		
		user, err := service.GetUser(id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		c.JSON(http.StatusOK, user)
	}
}

func CreateProductHandler(service *MockProductService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var product Product
		if err := c.ShouldBindJSON(&product); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if product.Price <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Price must be positive"})
			return
		}

		if product.Quantity < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Quantity cannot be negative"})
			return
		}

		if err := service.CreateProduct(&product); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create product"})
			return
		}

		c.JSON(http.StatusCreated, product)
	}
}

func CreateOrderHandler(orderService *MockOrderService, productService *MockProductService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var order Order
		if err := c.ShouldBindJSON(&order); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate stock for all items
		for _, item := range order.Items {
			product, err := productService.GetProduct(item.ID)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Product %s not found", item.ID)})
				return
			}

			if product.Quantity < item.Quantity {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Insufficient stock for product %s", item.ID)})
				return
			}
		}

		// Calculate totals
		priceCalc := &PriceCalculator{}
		order.Subtotal = priceCalc.CalculateSubtotal(order.Items)
		order.Tax = priceCalc.CalculateTax(order.Subtotal, 0.08) // 8% tax
		order.Total = priceCalc.CalculateTotal(order.Subtotal, order.Tax)

		order.CreatedAt = time.Now()
		order.UpdatedAt = time.Now()
		order.Status = "pending"

		if err := orderService.CreateOrder(&order); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create order"})
			return
		}

		c.JSON(http.StatusCreated, order)
	}
}

// Utility functions
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr || 
		   (len(s) > len(substr) && contains(s[1:], substr))
}

func lastIndex(s, substr string) int {
	for i := len(s) - len(substr); i >= 0; i-- {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func hasUpper(s string) bool {
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			return true
		}
	}
	return false
}

func hasLower(s string) bool {
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
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

	t.Run("ValidPhone", func(t *testing.T) {
		validPhones := []string{
			"+1 (555) 123-4567",
			"(555) 123-4567",
			"555-123-4567",
			"5551234567",
		}

		for _, phone := range validPhones {
			t.Run(fmt.Sprintf("Phone_%s", phone), func(t *testing.T) {
				assert.True(t, validator.IsValidPhone(phone), "Phone %s should be valid", phone)
			})
		}
	})

	t.Run("InvalidPhone", func(t *testing.T) {
		invalidPhones := []string{
			"123",
			"invalid-phone",
			"",
		}

		for _, phone := range invalidPhones {
			t.Run(fmt.Sprintf("Phone_%s", phone), func(t *testing.T) {
				assert.False(t, validator.IsValidPhone(phone), "Phone %s should be invalid", phone)
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
			"",              // empty
		}

		for _, password := range invalidPasswords {
			t.Run(fmt.Sprintf("Password_%s", password), func(t *testing.T) {
				assert.False(t, validator.IsValidPassword(password), "Password %s should be invalid", password)
			})
		}
	})
}

func TestPriceCalculator(t *testing.T) {
	calc := &PriceCalculator{}

	t.Run("CalculateSubtotal", func(t *testing.T) {
		items := []CartItem{
			{ID: "1", Name: "Product 1", Price: 10.99, Quantity: 2},
			{ID: "2", Name: "Product 2", Price: 20.50, Quantity: 1},
			{ID: "3", Name: "Product 3", Price: 15.75, Quantity: 3},
		}

		subtotal := calc.CalculateSubtotal(items)
		assert.Equal(t, 78.32, subtotal, "Subtotal should be 78.32")
	})

	t.Run("CalculateTax", func(t *testing.T) {
		subtotal := 100.0
		taxRate := 0.08

		tax := calc.CalculateTax(subtotal, taxRate)
		assert.Equal(t, 8.0, tax, "Tax should be 8.0")
	})

	t.Run("CalculateTotal", func(t *testing.T) {
		subtotal := 100.0
		tax := 8.0

		total := calc.CalculateTotal(subtotal, tax)
		assert.Equal(t, 108.0, total, "Total should be 108.0")
	})

	t.Run("EmptyCart", func(t *testing.T) {
		items := []CartItem{}
		
		subtotal := calc.CalculateSubtotal(items)
		tax := calc.CalculateTax(subtotal, 0.08)
		total := calc.CalculateTotal(subtotal, tax)

		assert.Equal(t, 0.0, subtotal)
		assert.Equal(t, 0.0, tax)
		assert.Equal(t, 0.0, total)
	})
}

func TestUserModel(t *testing.T) {
	t.Run("ValidUser", func(t *testing.T) {
		user := &User{
			ID:        "1",
			Name:      "Test User",
			Email:     "test@example.com",
			Age:       25,
			Phone:     "+1 (555) 123-4567",
			Active:    true,
			CreatedAt: time.Now(),
		}

		validator := &UserValidator{}
		assert.True(t, validator.IsValidEmail(user.Email))
		assert.True(t, validator.IsValidAge(user.Age))
		assert.True(t, validator.IsValidPhone(user.Phone))
	})

	t.Run("InvalidUser", func(t *testing.T) {
		user := &User{
			ID:        "1",
			Name:      "",
			Email:     "invalid-email",
			Age:       15,
			Phone:     "123",
			Active:    true,
			CreatedAt: time.Now(),
		}

		validator := &UserValidator{}
		assert.False(t, validator.IsValidEmail(user.Email))
		assert.False(t, validator.IsValidAge(user.Age))
		assert.False(t, validator.IsValidPhone(user.Phone))
	})
}

func TestProductModel(t *testing.T) {
	t.Run("ValidProduct", func(t *testing.T) {
		product := &Product{
			ID:          "1",
			Name:        "Test Product",
			Price:       10.99,
			Quantity:    100,
			Category:    "electronics",
			Description: "Test description",
			Image:       "https://example.com/image.jpg",
		}

		assert.Greater(t, product.Price, 0.0)
		assert.GreaterOrEqual(t, product.Quantity, 0)
		assert.NotEmpty(t, product.Name)
	})

	t.Run("InvalidProduct", func(t *testing.T) {
		product := &Product{
			ID:          "1",
			Name:        "",
			Price:       -10.0,
			Quantity:    -5,
			Category:    "",
			Description: "",
			Image:       "",
		}

		assert.Less(t, product.Price, 0.0)
		assert.Less(t, product.Quantity, 0)
		assert.Empty(t, product.Name)
	})
}

// Integration Tests - HTTP Handlers
func TestHTTPHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("HealthHandler", func(t *testing.T) {
		router := gin.New()
		router.GET("/health", HealthHandler)

		req, _ := http.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "OK", response["status"])
		assert.NotNil(t, response["timestamp"])
	})

	t.Run("CreateUserHandler_Success", func(t *testing.T) {
		mockService := new(MockUserService)
		mockService.On("CreateUser", mock.AnythingOfType("*main.User")).Return(nil)

		router := gin.New()
		router.POST("/users", CreateUserHandler(mockService))

		userData := map[string]interface{}{
			"name":  "Test User",
			"email": "test@example.com",
			"age":   25,
			"phone": "+1 (555) 123-4567",
		}

		body, _ := json.Marshal(userData)
		req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("CreateUserHandler_InvalidEmail", func(t *testing.T) {
		mockService := new(MockUserService)
		router := gin.New()
		router.POST("/users", CreateUserHandler(mockService))

		userData := map[string]interface{}{
			"name":  "Test User",
			"email": "invalid-email",
			"age":   25,
			"phone": "+1 (555) 123-4567",
		}

		body, _ := json.Marshal(userData)
		req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid email format")
	})

	t.Run("CreateUserHandler_InvalidAge", func(t *testing.T) {
		mockService := new(MockUserService)
		router := gin.New()
		router.POST("/users", CreateUserHandler(mockService))

		userData := map[string]interface{}{
			"name":  "Test User",
			"email": "test@example.com",
			"age":   15,
			"phone": "+1 (555) 123-4567",
		}

		body, _ := json.Marshal(userData)
		req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid age")
	})

	t.Run("GetUserHandler_Success", func(t *testing.T) {
		mockService := new(MockUserService)
		expectedUser := &User{
			ID:    "1",
			Name:  "Test User",
			Email: "test@example.com",
			Age:   25,
		}
		mockService.On("GetUser", "1").Return(expectedUser, nil)

		router := gin.New()
		router.GET("/users/:id", GetUserHandler(mockService))

		req, _ := http.NewRequest("GET", "/users/1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		
		var response User
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, expectedUser.Name, response.Name)
		assert.Equal(t, expectedUser.Email, response.Email)
		
		mockService.AssertExpectations(t)
	})

	t.Run("GetUserHandler_NotFound", func(t *testing.T) {
		mockService := new(MockUserService)
		mockService.On("GetUser", "999").Return(nil, errors.New("not found"))

		router := gin.New()
		router.GET("/users/:id", GetUserHandler(mockService))

		req, _ := http.NewRequest("GET", "/users/999", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "User not found")
		
		mockService.AssertExpectations(t)
	})

	t.Run("CreateProductHandler_Success", func(t *testing.T) {
		mockService := new(MockProductService)
		mockService.On("CreateProduct", mock.AnythingOfType("*main.Product")).Return(nil)

		router := gin.New()
		router.POST("/products", CreateProductHandler(mockService))

		productData := map[string]interface{}{
			"name":        "Test Product",
			"price":       10.99,
			"quantity":    100,
			"category":    "electronics",
			"description": "Test description",
		}

		body, _ := json.Marshal(productData)
		req, _ := http.NewRequest("POST", "/products", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("CreateProductHandler_InvalidPrice", func(t *testing.T) {
		mockService := new(MockProductService)
		router := gin.New()
		router.POST("/products", CreateProductHandler(mockService))

		productData := map[string]interface{}{
			"name":        "Test Product",
			"price":       -10.99,
			"quantity":    100,
			"category":    "electronics",
			"description": "Test description",
		}

		body, _ := json.Marshal(productData)
		req, _ := http.NewRequest("POST", "/products", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Price must be positive")
	})

	t.Run("CreateOrderHandler_Success", func(t *testing.T) {
		mockOrderService := new(MockOrderService)
		mockProductService := new(MockProductService)
		
		product := &Product{
			ID:       "1",
			Name:     "Test Product",
			Price:    10.99,
			Quantity: 100,
		}
		
		mockProductService.On("GetProduct", "1").Return(product, nil)
		mockOrderService.On("CreateOrder", mock.AnythingOfType("*main.Order")).Return(nil)

		router := gin.New()
		router.POST("/orders", CreateOrderHandler(mockOrderService, mockProductService))

		orderData := map[string]interface{}{
			"user_id": "user123",
			"items": []map[string]interface{}{
				{"id": "1", "name": "Test Product", "price": 10.99, "quantity": 2},
			},
		}

		body, _ := json.Marshal(orderData)
		req, _ := http.NewRequest("POST", "/orders", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		
		var response Order
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, 21.98, response.Subtotal) // 2 * 10.99
		assert.Equal(t, 1.76, response.Tax)       // 21.98 * 0.08
		assert.Equal(t, 23.74, response.Total)    // 21.98 + 1.76
		assert.Equal(t, "pending", response.Status)
		
		mockProductService.AssertExpectations(t)
		mockOrderService.AssertExpectations(t)
	})

	t.Run("CreateOrderHandler_InsufficientStock", func(t *testing.T) {
		mockOrderService := new(MockOrderService)
		mockProductService := new(MockProductService)
		
		product := &Product{
			ID:       "1",
			Name:     "Test Product",
			Price:    10.99,
			Quantity: 1, // Only 1 in stock
		}
		
		mockProductService.On("GetProduct", "1").Return(product, nil)

		router := gin.New()
		router.POST("/orders", CreateOrderHandler(mockOrderService, mockProductService))

		orderData := map[string]interface{}{
			"user_id": "user123",
			"items": []map[string]interface{}{
				{"id": "1", "name": "Test Product", "price": 10.99, "quantity": 2}, // Requesting 2
			},
		}

		body, _ := json.Marshal(orderData)
		req, _ := http.NewRequest("POST", "/orders", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Insufficient stock")
		
		mockProductService.AssertExpectations(t)
		mockOrderService.AssertNotCalled(t, "CreateOrder")
	})
}

// Feature Tests - Complete User Workflows
func TestUserRegistrationWorkflow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("CompleteRegistrationFlow", func(t *testing.T) {
		mockUserService := new(MockUserService)
		mockUserService.On("CreateUser", mock.AnythingOfType("*main.User")).Return(nil)

		router := gin.New()
		router.POST("/users", CreateUserHandler(mockUserService))

		registrationData := map[string]interface{}{
			"name":  "John Doe",
			"email": "john@example.com",
			"age":   25,
			"phone": "+1 (555) 123-4567",
		}

		body, _ := json.Marshal(registrationData)
		req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response User
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "John Doe", response.Name)
		assert.Equal(t, "john@example.com", response.Email)
		assert.Equal(t, 25, response.Age)
		assert.Equal(t, "+1 (555) 123-4567", response.Phone)
		assert.True(t, response.Active)

		mockUserService.AssertExpectations(t)
	})

	t.Run("RegistrationWithInvalidData", func(t *testing.T) {
		mockUserService := new(MockUserService)
		router := gin.New()
		router.POST("/users", CreateUserHandler(mockUserService))

		invalidData := map[string]interface{}{
			"name":  "", // Empty name
			"email": "invalid-email",
			"age":   15, // Underage
			"phone": "123", // Invalid phone
		}

		body, _ := json.Marshal(invalidData)
		req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		// Should return the first validation error
		assert.Contains(t, w.Body.String(), "Invalid email format")
	})
}

func TestECommerceWorkflow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("CompletePurchaseFlow", func(t *testing.T) {
		mockOrderService := new(MockOrderService)
		mockProductService := new(MockProductService)
		
		product := &Product{
			ID:       "1",
			Name:     "Test Product",
			Price:    10.99,
			Quantity: 100,
		}
		
		mockProductService.On("GetProduct", "1").Return(product, nil)
		mockOrderService.On("CreateOrder", mock.AnythingOfType("*main.Order")).Return(nil)

		router := gin.New()
		router.POST("/orders", CreateOrderHandler(mockOrderService, mockProductService))

		orderData := map[string]interface{}{
			"user_id": "user123",
			"items": []map[string]interface{}{
				{"id": "1", "name": "Test Product", "price": 10.99, "quantity": 5},
			},
		}

		body, _ := json.Marshal(orderData)
		req, _ := http.NewRequest("POST", "/orders", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response Order
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "user123", response.UserID)
		assert.Len(t, response.Items, 1)
		assert.Equal(t, 54.95, response.Subtotal) // 5 * 10.99
		assert.Equal(t, 4.40, response.Tax)       // 54.95 * 0.08
		assert.Equal(t, 59.35, response.Total)    // 54.95 + 4.40
		assert.Equal(t, "pending", response.Status)

		mockProductService.AssertExpectations(t)
		mockOrderService.AssertExpectations(t)
	})

	t.Run("PurchaseWithMultipleItems", func(t *testing.T) {
		mockOrderService := new(MockOrderService)
		mockProductService := new(MockProductService)
		
		product1 := &Product{
			ID:       "1",
			Name:     "Product 1",
			Price:    10.99,
			Quantity: 100,
		}
		
		product2 := &Product{
			ID:       "2",
			Name:     "Product 2",
			Price:    20.50,
			Quantity: 50,
		}
		
		mockProductService.On("GetProduct", "1").Return(product1, nil)
		mockProductService.On("GetProduct", "2").Return(product2, nil)
		mockOrderService.On("CreateOrder", mock.AnythingOfType("*main.Order")).Return(nil)

		router := gin.New()
		router.POST("/orders", CreateOrderHandler(mockOrderService, mockProductService))

		orderData := map[string]interface{}{
			"user_id": "user123",
			"items": []map[string]interface{}{
				{"id": "1", "name": "Product 1", "price": 10.99, "quantity": 2},
				{"id": "2", "name": "Product 2", "price": 20.50, "quantity": 1},
			},
		}

		body, _ := json.Marshal(orderData)
		req, _ := http.NewRequest("POST", "/orders", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response Order
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Items, 2)
		assert.Equal(t, 42.48, response.Subtotal) // 2*10.99 + 1*20.50
		assert.Equal(t, 3.40, response.Tax)       // 42.48 * 0.08
		assert.Equal(t, 45.88, response.Total)    // 42.48 + 3.40

		mockProductService.AssertExpectations(t)
		mockOrderService.AssertExpectations(t)
	})
}

// Performance Tests
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

func BenchmarkPriceCalculatorSubtotal(b *testing.B) {
	calc := &PriceCalculator{}
	items := []CartItem{
		{ID: "1", Name: "Product 1", Price: 10.99, Quantity: 2},
		{ID: "2", Name: "Product 2", Price: 20.50, Quantity: 1},
		{ID: "3", Name: "Product 3", Price: 15.75, Quantity: 3},
	}
	
	for i := 0; i < b.N; i++ {
		calc.CalculateSubtotal(items)
	}
}

// Test Suite for Complex Scenarios
type ECommerceTestSuite struct {
	suite.Suite
	mockUserService    *MockUserService
	mockProductService *MockProductService
	mockOrderService   *MockOrderService
	router             *gin.Engine
}

func (suite *ECommerceTestSuite) SetupTest() {
	gin.SetMode(gin.TestMode)
	suite.mockUserService = new(MockUserService)
	suite.mockProductService = new(MockProductService)
	suite.mockOrderService = new(MockOrderService)
	
	suite.router = gin.New()
	suite.router.POST("/users", CreateUserHandler(suite.mockUserService))
	suite.router.GET("/users/:id", GetUserHandler(suite.mockUserService))
	suite.router.POST("/products", CreateProductHandler(suite.mockProductService))
	suite.router.POST("/orders", CreateOrderHandler(suite.mockOrderService, suite.mockProductService))
}

func (suite *ECommerceTestSuite) TearDownTest() {
	suite.mockUserService.AssertExpectations(suite.T())
	suite.mockProductService.AssertExpectations(suite.T())
	suite.mockOrderService.AssertExpectations(suite.T())
}

func (suite *ECommerceTestSuite) TestCompleteECommerceFlow() {
	// Step 1: Create user
	userData := map[string]interface{}{
		"name":  "John Doe",
		"email": "john@example.com",
		"age":   25,
		"phone": "+1 (555) 123-4567",
	}

	suite.mockUserService.On("CreateUser", mock.AnythingOfType("*main.User")).Return(nil)

	body, _ := json.Marshal(userData)
	req, _ := http.NewRequest("POST", "/users", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.Equal(http.StatusCreated, w.Code)

	var user User
	err := json.Unmarshal(w.Body.Bytes(), &user)
	suite.Require().NoError(err)
	suite.Equal("John Doe", user.Name)

	// Step 2: Create products
	product1 := &Product{ID: "1", Name: "Product 1", Price: 10.99, Quantity: 100}
	product2 := &Product{ID: "2", Name: "Product 2", Price: 20.50, Quantity: 50}

	suite.mockProductService.On("GetProduct", "1").Return(product1, nil)
	suite.mockProductService.On("GetProduct", "2").Return(product2, nil)

	// Step 3: Create order with multiple items
	orderData := map[string]interface{}{
		"user_id": user.ID,
		"items": []map[string]interface{}{
			{"id": "1", "name": "Product 1", "price": 10.99, "quantity": 2},
			{"id": "2", "name": "Product 2", "price": 20.50, "quantity": 1},
		},
	}

	suite.mockOrderService.On("CreateOrder", mock.AnythingOfType("*main.Order")).Return(nil)

	body, _ = json.Marshal(orderData)
	req, _ = http.NewRequest("POST", "/orders", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.Equal(http.StatusCreated, w.Code)

	var order Order
	err = json.Unmarshal(w.Body.Bytes(), &order)
	suite.Require().NoError(err)
	suite.Equal(user.ID, order.UserID)
	suite.Len(order.Items, 2)
	suite.Equal(42.48, order.Subtotal)
	suite.Equal("pending", order.Status)
}

func TestECommerceTestSuite(t *testing.T) {
	suite.Run(t, new(ECommerceTestSuite))
}

// Test Helpers and Utilities
func createMockUser(overrides map[string]interface{}) *User {
	user := &User{
		ID:        "1",
		Name:      "Test User",
		Email:     "test@example.com",
		Age:       25,
		Phone:     "+1 (555) 123-4567",
		Active:    true,
		CreatedAt: time.Now(),
	}

	for key, value := range overrides {
		switch key {
		case "id":
			user.ID = value.(string)
		case "name":
			user.Name = value.(string)
		case "email":
			user.Email = value.(string)
		case "age":
			user.Age = value.(int)
		case "phone":
			user.Phone = value.(string)
		case "active":
			user.Active = value.(bool)
		}
	}

	return user
}

func createMockProduct(overrides map[string]interface{}) *Product {
	product := &Product{
		ID:          "1",
		Name:        "Test Product",
		Price:       10.99,
		Quantity:    100,
		Category:    "electronics",
		Description: "Test description",
		Image:       "https://example.com/product.jpg",
	}

	for key, value := range overrides {
		switch key {
		case "id":
			product.ID = value.(string)
		case "name":
			product.Name = value.(string)
		case "price":
			product.Price = value.(float64)
		case "quantity":
			product.Quantity = value.(int)
		case "category":
			product.Category = value.(string)
		case "description":
			product.Description = value.(string)
		case "image":
			product.Image = value.(string)
		}
	}

	return product
}

func createMockCartItem(product *Product, quantity int) CartItem {
	return CartItem{
		ID:       product.ID,
		Name:     product.Name,
		Price:    product.Price,
		Quantity: quantity,
		Total:    product.Price * float64(quantity),
	}
}

func assertValidUser(t *testing.T, user *User) {
	validator := &UserValidator{}
	assert.NotEmpty(t, user.ID, "User ID should not be empty")
	assert.NotEmpty(t, user.Name, "User name should not be empty")
	assert.True(t, validator.IsValidEmail(user.Email), "User email should be valid")
	assert.True(t, validator.IsValidAge(user.Age), "User age should be valid")
	assert.True(t, validator.IsValidPhone(user.Phone), "User phone should be valid")
}

func assertValidProduct(t *testing.T, product *Product) {
	assert.NotEmpty(t, product.ID, "Product ID should not be empty")
	assert.NotEmpty(t, product.Name, "Product name should not be empty")
	assert.Greater(t, product.Price, 0.0, "Product price should be positive")
	assert.GreaterOrEqual(t, product.Quantity, 0, "Product quantity should be non-negative")
}

func assertValidApiResponse(t *testing.T, response map[string]interface{}) {
	assert.Contains(t, response, "status", "API response should have status field")
	assert.Contains(t, []string{"success", "error"}, response["status"], "Status should be valid")
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

func ExamplePriceCalculator_CalculateSubtotal() {
	calc := &PriceCalculator{}
	items := []CartItem{
		{ID: "1", Name: "Product 1", Price: 10.99, Quantity: 2},
		{ID: "2", Name: "Product 2", Price: 20.50, Quantity: 1},
	}
	subtotal := calc.CalculateSubtotal(items)
	fmt.Printf("%.2f", subtotal)
	// Output: 42.48
}
```

## Guidelines

### Test Organization
- **Unit Tests**: Business logic, models, services with comprehensive validation
- **Integration Tests**: HTTP handlers and service interactions
- **Feature Tests**: Complete user workflows and business scenarios
- **Performance Tests**: Benchmark critical operations
- **Test Suites**: Complex multi-step scenarios with setup/teardown

### Go Testing Best Practices
- Use table-driven tests for multiple test cases
- Use testify/assert for assertions and testify/mock for mocking
- Use testify/require for fatal assertions
- Use testify/suite for complex test scenarios
- Test both success and error paths

### Test Structure
- Use `t.Run()` for subtests to organize test cases
- Use table-driven tests for data validation
- Mock external dependencies with testify/mock
- Use httptest for HTTP handler testing

### Coverage Requirements
- **Unit Tests**: 85%+ coverage for business logic
- **Integration Tests**: 75%+ coverage for HTTP handlers
- **Feature Tests**: 70%+ coverage for user workflows
- **Overall**: 80%+ minimum for Core tier

## Required Dependencies

Add to `go.mod`:

```go
require (
    github.com/stretchr/testify v1.8.4
    github.com/gin-gonic/gin v1.9.1
    go.mongodb.org/mongo-driver v1.12.1
)
```

## What's Included

- **Unit Tests**: Business logic, models, services with comprehensive validation
- **Integration Tests**: Gin HTTP handlers and service interactions
- **Feature Tests**: Complete e-commerce workflows
- **Performance Tests**: Benchmark tests for critical operations
- **Test Suites**: Complex scenarios with setup/teardown
- **Test Helpers**: Mock data factories and assertions

## What's NOT Included

- Database integration tests
- External API integration tests
- Concurrent/goroutine testing
- File system operations testing

---

**Template Version**: 2.0 (Core)  
**Last Updated**: 2025-12-10  
**Stack**: Go  
**Tier**: Core  
**Framework**: Go testing + testify + Gin
