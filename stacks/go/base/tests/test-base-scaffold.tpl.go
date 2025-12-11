// File: test-base-scaffold.tpl.go
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

// -----------------------------------------------------------------------------
// FILE: test-base-scaffold.tpl.go
// PURPOSE: Foundational testing patterns and utilities for Go projects
// USAGE: Import and extend for consistent testing structure across the application
// DEPENDENCIES: bytes, context, encoding/json, fmt, io, net/http, net/http/httptest
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// BaseTestSuite provides common testing utilities for Go applications
type BaseTestSuite struct {
	suite.Suite
	tempDir   string
	ctx       context.Context
	cancel    context.CancelFunc
	mocks     map[string]interface{}
	testData  map[string]interface{}
}

// SetupSuite initializes the test suite
func (s *BaseTestSuite) SetupSuite() {
	s.ctx, s.cancel = context.WithTimeout(context.Background(), 30*time.Second)
	s.mocks = make(map[string]interface{})
	s.testData = make(map[string]interface{})
	
	tempDir, err := os.MkdirTemp("", "test-*")
	require.NoError(s.T(), err)
	s.tempDir = tempDir
}

// TearDownSuite cleans up the test suite
func (s *BaseTestSuite) TearDownSuite() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}
}

// SetupTest runs before each test
func (s *BaseTestSuite) SetupTest() {
	// Reset test data for each test
	s.testData = make(map[string]interface{})
}

// CreateTempFile creates a temporary file with content
func (s *BaseTestSuite) CreateTempFile(filename, content string) string {
	filePath := filepath.Join(s.tempDir, filename)
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(s.T(), err)
	return filePath
}

// CreateMockData creates mock data for testing
func (s *BaseTestSuite) CreateMockData(dataType string, overrides map[string]interface{}) interface{} {
	switch dataType {
	case "user":
		return s.createMockUser(overrides)
	case "post":
		return s.createMockPost(overrides)
	case "config":
		return s.createMockConfig(overrides)
	default:
		return nil
	}
}

// createMockUser creates mock user data
func (s *BaseTestSuite) createMockUser(overrides map[string]interface{}) MockUser {
	user := MockUser{
		ID:        1,
		Username:  "testuser",
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Apply overrides
	if id, ok := overrides["id"].(int); ok {
		user.ID = id
	}
	if username, ok := overrides["username"].(string); ok {
		user.Username = username
	}
	if email, ok := overrides["email"].(string); ok {
		user.Email = email
	}
	if firstName, ok := overrides["first_name"].(string); ok {
		user.FirstName = firstName
	}
	if lastName, ok := overrides["last_name"].(string); ok {
		user.LastName = lastName
	}
	if isActive, ok := overrides["is_active"].(bool); ok {
		user.IsActive = isActive
	}

	return user
}

// createMockPost creates mock post data
func (s *BaseTestSuite) createMockPost(overrides map[string]interface{}) MockPost {
	post := MockPost{
		ID:        1,
		Title:     "Test Post",
		Content:   "This is test content",
		AuthorID:  1,
		Published: true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Tags:      []string{"test", "mock"},
	}

	// Apply overrides
	if id, ok := overrides["id"].(int); ok {
		post.ID = id
	}
	if title, ok := overrides["title"].(string); ok {
		post.Title = title
	}
	if content, ok := overrides["content"].(string); ok {
		post.Content = content
	}
	if authorID, ok := overrides["author_id"].(int); ok {
		post.AuthorID = authorID
	}
	if published, ok := overrides["published"].(bool); ok {
		post.Published = published
	}

	return post
}

// createMockConfig creates mock configuration data
func (s *BaseTestSuite) createMockConfig(overrides map[string]interface{}) MockConfig {
	config := MockConfig{
		Database: DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			Name:     "test_db",
			User:     "test_user",
			Password: "test_password",
		},
		Redis: RedisConfig{
			Host: "localhost",
			Port: 6379,
			DB:   0,
		},
		Server: ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
		Debug: true,
	}

	// Apply overrides
	if dbConfig, ok := overrides["database"].(map[string]interface{}); ok {
		if host, ok := dbConfig["host"].(string); ok {
			config.Database.Host = host
		}
		if port, ok := dbConfig["port"].(int); ok {
			config.Database.Port = port
		}
		if name, ok := dbConfig["name"].(string); ok {
			config.Database.Name = name
		}
	}

	return config
}

// AssertJSONEqual asserts that two JSON strings are equal
func (s *BaseTestSuite) AssertJSONEqual(expected, actual string) {
	var expectedJSON, actualJSON interface{}
	
	err := json.Unmarshal([]byte(expected), &expectedJSON)
	require.NoError(s.T(), err)
	
	err = json.Unmarshal([]byte(actual), &actualJSON)
	require.NoError(s.T(), err)
	
	assert.Equal(s.T(), expectedJSON, actualJSON)
}

// AssertJSONContains asserts that JSON contains expected fields
func (s *BaseTestSuite) AssertJSONContains(jsonStr string, expectedFields map[string]interface{}) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &data)
	require.NoError(s.T(), err)
	
	for key, value := range expectedFields {
		assert.Contains(s.T(), data, key)
		assert.Equal(s.T(), data[key], value)
	}
}

// HTTPTestSuite provides utilities for HTTP testing
type HTTPTestSuite struct {
	BaseTestSuite
	server *httptest.Server
	client *http.Client
}

// SetupSuite sets up HTTP test suite
func (s *HTTPTestSuite) SetupSuite() {
	s.BaseTestSuite.SetupSuite()
	s.client = &http.Client{Timeout: 10 * time.Second}
}

// TearDownSuite tears down HTTP test suite
func (s *HTTPTestSuite) TearDownSuite() {
	if s.server != nil {
		s.server.Close()
	}
	s.BaseTestSuite.TearDownSuite()
}

// CreateTestServer creates a test HTTP server
func (s *HTTPTestSuite) CreateTestServer(handler http.Handler) {
	s.server = httptest.NewServer(handler)
}

// CreateTestRequest creates a test HTTP request
func (s *HTTPTestSuite) CreateTestRequest(method, url string, body interface{}) *http.Request {
	var reqBody io.Reader
	
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		require.NoError(s.T(), err)
		reqBody = bytes.NewReader(bodyBytes)
	}
	
	req, err := http.NewRequestWithContext(s.ctx, method, url, reqBody)
	require.NoError(s.T(), err)
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	
	return req
}

// AssertJSONResponse asserts that an HTTP response contains expected JSON
func (s *HTTPTestSuite) AssertJSONResponse(resp *http.Response, expected interface{}) {
	require.Equal(s.T(), http.StatusOK, resp.StatusCode)
	
	body, err := io.ReadAll(resp.Body)
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	
	var actual interface{}
	err = json.Unmarshal(body, &actual)
	require.NoError(s.T(), err)
	
	assert.Equal(s.T(), expected, actual)
}

// AssertErrorResponse asserts that an HTTP response contains an error
func (s *HTTPTestSuite) AssertErrorResponse(resp *http.Response, expectedStatusCode int, expectedMessage string) {
	require.Equal(s.T(), expectedStatusCode, resp.StatusCode)
	
	body, err := io.ReadAll(resp.Body)
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	
	var errorResp map[string]interface{}
	err = json.Unmarshal(body, &errorResp)
	require.NoError(s.T(), err)
	
	if message, ok := errorResp["error"].(string); ok {
		assert.Contains(s.T(), message, expectedMessage)
	}
}

// DatabaseTestSuite provides utilities for database testing
type DatabaseTestSuite struct {
	BaseTestSuite
	mockDB *MockDatabase
}

// SetupSuite sets up database test suite
func (s *DatabaseTestSuite) SetupSuite() {
	s.BaseTestSuite.SetupSuite()
	s.mockDB = NewMockDatabase()
}

// GetMockDatabase returns the mock database
func (s *DatabaseTestSuite) GetMockDatabase() *MockDatabase {
	return s.mockDB
}

// AssertRecordExists asserts that a record exists in the database
func (s *DatabaseTestSuite) AssertRecordExists(table string, id interface{}) {
	exists := s.mockDB.HasRecord(table, id)
	assert.True(s.T(), exists, "Record should exist in table %s with id %v", table, id)
}

// AssertRecordCount asserts the number of records in a table
func (s *DatabaseTestSuite) AssertRecordCount(table string, expectedCount int) {
	count := s.mockDB.GetRecordCount(table)
	assert.Equal(s.T(), expectedCount, count, "Table %s should have %d records", table, expectedCount)
}

// MockDatabase provides a mock database for testing
type MockDatabase struct {
	records map[string]map[interface{}]interface{}
}

// NewMockDatabase creates a new mock database
func NewMockDatabase() *MockDatabase {
	return &MockDatabase{
		records: make(map[string]map[interface{}]interface{}),
	}
}

// Insert inserts a record into the mock database
func (m *MockDatabase) Insert(table string, id interface{}, record interface{}) {
	if m.records[table] == nil {
		m.records[table] = make(map[interface{}]interface{})
	}
	m.records[table][id] = record
}

// Get retrieves a record from the mock database
func (m *MockDatabase) Get(table string, id interface{}) (interface{}, bool) {
	if m.records[table] == nil {
		return nil, false
	}
	record, exists := m.records[table][id]
	return record, exists
}

// HasRecord checks if a record exists
func (m *MockDatabase) HasRecord(table string, id interface{}) bool {
	_, exists := m.Get(table, id)
	return exists
}

// GetRecordCount returns the number of records in a table
func (m *MockDatabase) GetRecordCount(table string) int {
	if m.records[table] == nil {
		return 0
	}
	return len(m.records[table])
}

// Clear clears all records from a table
func (m *MockDatabase) Clear(table string) {
	delete(m.records, table)
}

// ClearAll clears all records from all tables
func (m *MockDatabase) ClearAll() {
	m.records = make(map[string]map[interface{}]interface{})
}

// ServiceTestSuite provides utilities for service layer testing
type ServiceTestSuite struct {
	BaseTestSuite
	mockRepository *MockRepository
}

// SetupSuite sets up service test suite
func (s *ServiceTestSuite) SetupSuite() {
	s.BaseTestSuite.SetupSuite()
	s.mockRepository = NewMockRepository()
}

// GetMockRepository returns the mock repository
func (s *ServiceTestSuite) GetMockRepository() *MockRepository {
	return s.mockRepository
}

// MockRepository provides a mock repository for testing
type MockRepository struct {
	mock.Mock
	data map[string]interface{}
}

// NewMockRepository creates a new mock repository
func NewMockRepository() *MockRepository {
	return &MockRepository{
		data: make(map[string]interface{}),
	}
}

// GetByID mocks getting a record by ID
func (m *MockRepository) GetByID(id interface{}) (interface{}, error) {
	args := m.Called(id)
	return args.Get(0), args.Error(1)
}

// Create mocks creating a record
func (m *MockRepository) Create(record interface{}) (interface{}, error) {
	args := m.Called(record)
	return args.Get(0), args.Error(1)
}

// Update mocks updating a record
func (m *MockRepository) Update(id interface{}, record interface{}) error {
	args := m.Called(id, record)
	return args.Error(0)
}

// Delete mocks deleting a record
func (m *MockRepository) Delete(id interface{}) error {
	args := m.Called(id)
	return args.Error(0)
}

// TestDataFactory provides factory methods for creating test data
type TestDataFactory struct{}

// NewTestDataFactory creates a new test data factory
func NewTestDataFactory() *TestDataFactory {
	return &TestDataFactory{}
}

// CreateUser creates a mock user
func (f *TestDataFactory) CreateUser(overrides map[string]interface{}) MockUser {
	suite := &BaseTestSuite{}
	return suite.createMockUser(overrides)
}

// CreateUsers creates multiple mock users
func (f *TestDataFactory) CreateUsers(count int, overrides map[string]interface{}) []MockUser {
	users := make([]MockUser, count)
	suite := &BaseTestSuite{}
	
	for i := 0; i < count; i++ {
		userOverrides := make(map[string]interface{})
		for k, v := range overrides {
			userOverrides[k] = v
		}
		userOverrides["id"] = i + 1
		userOverrides["username"] = fmt.Sprintf("testuser%d", i+1)
		userOverrides["email"] = fmt.Sprintf("test%d@example.com", i+1)
		users[i] = suite.createMockUser(userOverrides)
	}
	return users
}

// CreatePost creates a mock post
func (f *TestDataFactory) CreatePost(overrides map[string]interface{}) MockPost {
	suite := &BaseTestSuite{}
	return suite.createMockPost(overrides)
}

// CreatePosts creates multiple mock posts
func (f *TestDataFactory) CreatePosts(count int, overrides map[string]interface{}) []MockPost {
	posts := make([]MockPost, count)
	suite := &BaseTestSuite{}
	
	for i := 0; i < count; i++ {
		postOverrides := make(map[string]interface{})
		for k, v := range overrides {
			postOverrides[k] = v
		}
		postOverrides["id"] = i + 1
		postOverrides["title"] = fmt.Sprintf("Test Post %d", i+1)
		posts[i] = suite.createMockPost(postOverrides)
	}
	return posts
}

// Mock data structures
type MockUser struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type MockPost struct {
	ID        int       `json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	AuthorID  int       `json:"author_id"`
	Published bool      `json:"published"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Tags      []string  `json:"tags"`
}

type MockConfig struct {
	Database DatabaseConfig `json:"database"`
	Redis    RedisConfig    `json:"redis"`
	Server   ServerConfig   `json:"server"`
	Debug    bool           `json:"debug"`
}

type DatabaseConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Name     string `json:"name"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type RedisConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	DB   int    `json:"db"`
}

type ServerConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Example test functions
func ExampleBaseTestSuite(t *testing.T) {
	suite.Run(t, new(ExampleTestSuite))
}

// ExampleTestSuite demonstrates how to use the test scaffold
type ExampleTestSuite struct {
	BaseTestSuite
	factory *TestDataFactory
}

// SetupSuite sets up the example test suite
func (s *ExampleTestSuite) SetupSuite() {
	s.BaseTestSuite.SetupSuite()
	s.factory = NewTestDataFactory()
}

// TestMockDataCreation demonstrates mock data creation
func (s *ExampleTestSuite) TestMockDataCreation() {
	user := s.CreateMockData("user", map[string]interface{}{
		"username": "exampleuser",
		"email":    "user@example.com",
	})
	
	require.NotNil(s.T(), user)
	mockUser := user.(MockUser)
	assert.Equal(s.T(), "exampleuser", mockUser.Username)
	assert.Equal(s.T(), "user@example.com", mockUser.Email)
}

// TestTempFileCreation demonstrates temporary file creation
func (s *ExampleTestSuite) TestTempFileCreation() {
	content := `{"debug": true, "database": {"host": "localhost"}}`
	filePath := s.CreateTempFile("config.json", content)
	
	assert.FileExists(s.T(), filePath)
	
	readContent, err := os.ReadFile(filePath)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), content, string(readContent))
}

// TestJSONAssertions demonstrates JSON assertions
func (s *ExampleTestSuite) TestJSONAssertions() {
	expected := `{"id": 1, "username": "test"}`
	actual := `{"username": "test", "id": 1}`
	
	s.AssertJSONEqual(expected, actual)
	
	jsonStr := `{"id": 1, "username": "test", "email": "test@example.com"}`
	expectedFields := map[string]interface{}{
		"id":       float64(1),
		"username": "test",
	}
	
	s.AssertJSONContains(jsonStr, expectedFields)
}

// TestDataFactory demonstrates factory usage
func (s *ExampleTestSuite) TestDataFactory() {
	users := s.factory.CreateUsers(3, map[string]interface{}{
		"first_name": "Test",
		"last_name":  "User",
	})
	
	assert.Len(s.T(), users, 3)
	for i, user := range users {
		assert.Equal(s.T(), i+1, user.ID)
		assert.Equal(s.T(), "Test", user.FirstName)
		assert.Equal(s.T(), "User", user.LastName)
	}
}

// Example usage demonstrates how to use the test scaffold
func ExampleUsage() {
	// This would be called from your actual test files
	fmt.Println("Example test scaffold usage:")
	fmt.Println("1. Extend BaseTestSuite for common utilities")
	fmt.Println("2. Use TestDataFactory for creating mock data")
	fmt.Println("3. Use HTTPTestSuite for HTTP endpoint testing")
	fmt.Println("4. Use DatabaseTestSuite for database testing")
	fmt.Println("5. Use ServiceTestSuite for service layer testing")
}
