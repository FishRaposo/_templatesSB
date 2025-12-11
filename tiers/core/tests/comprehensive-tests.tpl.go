// Template: comprehensive-tests.tpl.go
// Purpose: comprehensive-tests template
// Stack: go
// Tier: base

# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: core
# Stack: unknown
# Category: testing

# Comprehensive Testing Template (Core Tier)

## Purpose
Provides comprehensive testing patterns for production applications requiring reliability, maintainability, and proper quality assurance.

## Usage
This template should be used for:
- Production applications
- SaaS products
- Enterprise applications
- Systems requiring automated testing pipelines

## Structure
```go
// [[.ProjectName]] - Comprehensive Tests
// Author: [[.Author]]
// Version: [[.Version]]

package main

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/stretchr/testify/suite"
    "go.uber.org/zap/zaptest"
)

// TestSuite provides comprehensive test structure
type ApplicationTestSuite struct {
    suite.Suite
    app     *Application
    logger  *zaptest.Logger
    server  *httptest.Server
}

// SetupSuite runs once before all tests
func (suite *ApplicationTestSuite) SetupSuite() {
    suite.logger = zaptest.NewLogger(suite.T())
    
    config := &Config{
        Port:        "8080",
        LogLevel:    "debug",
        DatabaseURL: "sqlite://:memory:",
        Environment: "test",
    }
    
    var err error
    suite.app, err = NewTestApplication(config, suite.logger)
    suite.Require().NoError(err)
    
    suite.server = httptest.NewServer(suite.app.setupRouter())
}

// TearDownSuite runs once after all tests
func (suite *ApplicationTestSuite) TearDownSuite() {
    if suite.server != nil {
        suite.server.Close()
    }
    if suite.app != nil {
        suite.app.Shutdown()
    }
}

// SetupTest runs before each test
func (suite *ApplicationTestSuite) SetupTest() {
    // Reset database state, clear caches, etc.
}

// TearDownTest runs after each test
func (suite *ApplicationTestSuite) TearDownTest() {
    // Cleanup test data
}

// TestApplicationHealthCheck validates health endpoint
func (suite *ApplicationTestSuite) TestApplicationHealthCheck() {
    resp, err := http.Get(suite.server.URL + "/health")
    suite.Require().NoError(err)
    defer resp.Body.Close()
    
    suite.Equal(http.StatusOK, resp.StatusCode)
    
    var healthResp struct {
        Status    string `json:"status"`
        Timestamp string `json:"timestamp"`
    }
    
    err = json.NewDecoder(resp.Body).Decode(&healthResp)
    suite.Require().NoError(err)
    
    suite.Equal("healthy", healthResp.Status)
}

// TestAPIEndpoints validates all API endpoints
func (suite *ApplicationTestSuite) TestAPIEndpoints() {
    tests := []struct {
        name           string
        path           string
        expectedStatus int
        expectedBody   string
    }{
        {"Health Check", "/health", http.StatusOK, "healthy"},
        {"Root Endpoint", "/", http.StatusOK, ""},
        {"API Version", "/api/v1", http.StatusOK, ""},
    }
    
    for _, tt := range tests {
        suite.Run(tt.name, func() {
            resp, err := http.Get(suite.server.URL + tt.path)
            suite.Require().NoError(err)
            defer resp.Body.Close()
            
            suite.Equal(tt.expectedStatus, resp.StatusCode)
            
            if tt.expectedBody != "" {
                body := make([]byte, 1024)
                n, _ := resp.Body.Read(body)
                suite.Contains(string(body[:n]), tt.expectedBody)
            }
        })
    }
}

// TestDatabaseOperations validates database interactions
func (suite *ApplicationTestSuite) TestDatabaseOperations() {
    // Test CRUD operations
    ctx := context.Background()
    
    // Create
    entity := &Entity{Name: "Test Entity", Value: 42}
    created, err := suite.app.CreateEntity(ctx, entity)
    suite.Require().NoError(err)
    suite.NotEmpty(created.ID)
    
    // Read
    retrieved, err := suite.app.GetEntity(ctx, created.ID)
    suite.Require().NoError(err)
    suite.Equal(created.Name, retrieved.Name)
    
    // Update
    retrieved.Value = 100
    updated, err := suite.app.UpdateEntity(ctx, retrieved)
    suite.Require().NoError(err)
    suite.Equal(100, updated.Value)
    
    // Delete
    err = suite.app.DeleteEntity(ctx, created.ID)
    suite.Require().NoError(err)
    
    // Verify deletion
    _, err = suite.app.GetEntity(ctx, created.ID)
    suite.Error(err)
}

// TestErrorHandling validates error scenarios
func (suite *ApplicationTestSuite) TestErrorHandling() {
    tests := []struct {
        name           string
        path           string
        expectedStatus int
    }{
        {"Invalid Endpoint", "/invalid", http.StatusNotFound},
        {"Invalid Method", "/health", http.StatusMethodNotAllowed},
        {"Missing Parameters", "/api/v1/entity", http.StatusBadRequest},
    }
    
    for _, tt := range tests {
        suite.Run(tt.name, func() {
            resp, err := http.Get(suite.server.URL + tt.path)
            suite.Require().NoError(err)
            defer resp.Body.Close()
            
            suite.Equal(tt.expectedStatus, resp.StatusCode)
        })
    }
}

// TestConcurrency validates concurrent access
func (suite *ApplicationTestSuite) TestConcurrency() {
    const numGoroutines = 100
    const numRequests = 10
    
    var wg sync.WaitGroup
    errors := make(chan error, numGoroutines*numRequests)
    
    for i := 0; i < numGoroutines; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            
            for j := 0; j < numRequests; j++ {
                resp, err := http.Get(suite.server.URL + "/health")
                if err != nil {
                    errors <- err
                    return
                }
                resp.Body.Close()
                
                if resp.StatusCode != http.StatusOK {
                    errors <- fmt.Errorf("unexpected status: %d", resp.StatusCode)
                    return
                }
            }
        }(i)
    }
    
    wg.Wait()
    close(errors)
    
    // Check for any errors
    for err := range errors {
        suite.T().Errorf("Concurrent request failed: %v", err)
    }
}

// TestPerformance validates basic performance requirements
func (suite *ApplicationTestSuite) TestPerformance() {
    const maxResponseTime = 100 * time.Millisecond
    
    start := time.Now()
    resp, err := http.Get(suite.server.URL + "/health")
    duration := time.Since(start)
    
    suite.Require().NoError(err)
    defer resp.Body.Close()
    
    suite.Less(duration, maxResponseTime, 
        "Health check took too long: %v > %v", duration, maxResponseTime)
}

// Mock implementations for testing
type MockDatabase struct {
    mock.Mock
}

func (m *MockDatabase) Create(ctx context.Context, entity *Entity) (*Entity, error) {
    args := m.Called(ctx, entity)
    return args.Get(0).(*Entity), args.Error(1)
}

// Test with mocks
func TestWithMockDatabase(t *testing.T) {
    mockDB := new(MockDatabase)
    
    entity := &Entity{Name: "Test", Value: 1}
    mockDB.On("Create", mock.Anything, entity).Return(entity, nil)
    
    // Test your service with mock database
    result, err := mockDB.Create(context.Background(), entity)
    
    assert.NoError(t, err)
    assert.Equal(t, entity.Name, result.Name)
    mockDB.AssertExpectations(t)
}

// Integration tests
func TestIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration tests in short mode")
    }
    
    // Test with real database, external services, etc.
}

// Benchmark tests
func BenchmarkHealthCheck(b *testing.B) {
    app, err := NewApplication()
    require.NoError(b, err)
    
    server := httptest.NewServer(app.setupRouter())
    defer server.Close()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        resp, err := http.Get(server.URL + "/health")
        if err != nil {
            b.Fatal(err)
        }
        resp.Body.Close()
    }
}

// Test utilities
func NewTestApplication(config *Config, logger *zaptest.Logger) (*Application, error) {
    // Create test application with test configuration
    return &Application{
        logger: logger,
        config: config,
    }, nil
}

type Entity struct {
    ID    string `json:"id"`
    Name  string `json:"name"`
    Value int    `json:"value"`
}
```

## Core Testing Guidelines
- **Coverage**: Minimum 85% line coverage
- **Types**: Unit tests, integration tests, performance tests
- **Tools**: Testify for assertions and mocking, zaptest for logging
- **Automation**: CI/CD pipeline integration
- **Data**: Test data factories and fixtures
- **Environment**: Isolated test environment

## Required Test Dependencies
```go
// go.mod
require (
    github.com/stretchr/testify v1.8.4
    go.uber.org/zap v1.24.0
)
```

## Test Categories
1. **Unit Tests**: Individual function testing with mocks
2. **Integration Tests**: Database and external service testing
3. **API Tests**: HTTP endpoint testing
4. **Concurrency Tests**: Thread safety and race conditions
5. **Performance Tests**: Response time and throughput
6. **Error Tests**: Error condition validation

## What's Included (vs MVP)
- Comprehensive test suite structure
- Mock implementations for external dependencies
- Database integration testing
- Performance benchmarking
- Concurrent access testing
- Test utilities and helpers

## What's NOT Included (vs Full)
- No advanced security testing
- No load testing with high concurrency
- No distributed system testing
- No chaos engineering
- No advanced monitoring in tests
