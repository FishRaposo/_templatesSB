// File: testing-utilities.tpl.go
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

// -----------------------------------------------------------------------------
// FILE: testing-utilities.tpl.go
// PURPOSE: Comprehensive testing utilities and helpers for Go projects
// USAGE: Import and adapt for consistent testing patterns across the application
// DEPENDENCIES: bytes, encoding/json, fmt, io, net/http, net/http/httptest, os
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// MockDataFactory provides factory methods for creating mock data
type MockDataFactory struct{}

// NewMockDataFactory creates a new mock data factory
func NewMockDataFactory() *MockDataFactory {
	return &MockDataFactory{}
}

// CreateMockUser creates a mock user
func (f *MockDataFactory) CreateMockUser(options map[string]interface{}) MockUser {
	user := MockUser{
		ID:        1,
		Username:  "testuser",
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Avatar:    "https://example.com/avatar.jpg",
		Phone:     "+1234567890",
		Address: MockAddress{
			Street:   "123 Test St",
			City:     "Test City",
			Country:  "Test Country",
			ZipCode:  "12345",
		},
	}

	// Apply overrides
	if id, ok := options["id"].(int); ok {
		user.ID = id
	}
	if username, ok := options["username"].(string); ok {
		user.Username = username
	}
	if email, ok := options["email"].(string); ok {
		user.Email = email
	}
	if firstName, ok := options["first_name"].(string); ok {
		user.FirstName = firstName
	}
	if lastName, ok := options["last_name"].(string); ok {
		user.LastName = lastName
	}
	if isActive, ok := options["is_active"].(bool); ok {
		user.IsActive = isActive
	}

	return user
}

// CreateMockUsers creates an array of mock users
func (f *MockDataFactory) CreateMockUsers(count int, options map[string]interface{}) []MockUser {
	users := make([]MockUser, count)
	for i := 0; i < count; i++ {
		userOptions := make(map[string]interface{})
		for k, v := range options {
			userOptions[k] = v
		}
		userOptions["id"] = i + 1
		userOptions["username"] = fmt.Sprintf("testuser%d", i+1)
		userOptions["email"] = fmt.Sprintf("test%d@example.com", i+1)
		users[i] = f.CreateMockUser(userOptions)
	}
	return users
}

// CreateMockPost creates a mock post
func (f *MockDataFactory) CreateMockPost(options map[string]interface{}) MockPost {
	post := MockPost{
		ID:        1,
		Title:     "Test Post",
		Content:   "This is test content",
		AuthorID:  1,
		Published: true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Tags:      []string{"test", "mock"},
		Likes:     0,
		Comments:  []MockComment{},
	}

	// Apply overrides
	if id, ok := options["id"].(int); ok {
		post.ID = id
	}
	if title, ok := options["title"].(string); ok {
		post.Title = title
	}
	if content, ok := options["content"].(string); ok {
		post.Content = content
	}
	if authorID, ok := options["author_id"].(int); ok {
		post.AuthorID = authorID
	}
	if published, ok := options["published"].(bool); ok {
		post.Published = published
	}

	return post
}

// CreateMockPosts creates an array of mock posts
func (f *MockDataFactory) CreateMockPosts(count int, options map[string]interface{}) []MockPost {
	posts := make([]MockPost, count)
	for i := 0; i < count; i++ {
		postOptions := make(map[string]interface{})
		for k, v := range options {
			postOptions[k] = v
		}
		postOptions["id"] = i + 1
		postOptions["title"] = fmt.Sprintf("Test Post %d", i+1)
		posts[i] = f.CreateMockPost(postOptions)
	}
	return posts
}

// CreateMockAPIResponse creates a mock API response
func (f *MockDataFactory) CreateMockAPIResponse(data interface{}, options map[string]interface{}) MockAPIResponse {
	response := MockAPIResponse{
		Status:    "success",
		Message:   "Operation completed successfully",
		Data:      data,
		Timestamp: time.Now(),
		RequestID: "test-request-id",
	}

	// Apply overrides
	if status, ok := options["status"].(string); ok {
		response.Status = status
	}
	if message, ok := options["message"].(string); ok {
		response.Message = message
	}
	if requestID, ok := options["request_id"].(string); ok {
		response.RequestID = requestID
	}

	return response
}

// CreateMockFormData creates mock form data
func (f *MockDataFactory) CreateMockFormData(options map[string]interface{}) map[string]interface{} {
	formData := map[string]interface{}{
		"username":        "testuser",
		"email":           "test@example.com",
		"password":        "password123",
		"confirm_password": "password123",
		"first_name":      "Test",
		"last_name":       "User",
		"phone":           "+1234567890",
	}

	// Apply overrides
	for k, v := range options {
		formData[k] = v
	}

	return formData
}

// Mock data structures
type MockUser struct {
	ID        int        `json:"id"`
	Username  string     `json:"username"`
	Email     string     `json:"email"`
	FirstName string     `json:"first_name"`
	LastName  string     `json:"last_name"`
	IsActive  bool       `json:"is_active"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	Avatar    string     `json:"avatar"`
	Phone     string     `json:"phone"`
	Address   MockAddress `json:"address"`
}

type MockAddress struct {
	Street  string `json:"street"`
	City    string `json:"city"`
	Country string `json:"country"`
	ZipCode string `json:"zip_code"`
}

type MockPost struct {
	ID        int           `json:"id"`
	Title     string        `json:"title"`
	Content   string        `json:"content"`
	AuthorID  int           `json:"author_id"`
	Published bool          `json:"published"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	Tags      []string      `json:"tags"`
	Likes     int           `json:"likes"`
	Comments  []MockComment `json:"comments"`
}

type MockComment struct {
	ID        int       `json:"id"`
	PostID    int       `json:"post_id"`
	Content   string    `json:"content"`
	AuthorID  int       `json:"author_id"`
	CreatedAt time.Time `json:"created_at"`
}

type MockAPIResponse struct {
	Status    string      `json:"status"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
	RequestID string      `json:"request_id"`
}

// TestUtils provides common testing utilities
type TestUtils struct {
	t        *testing.T
	tempDir  string
	mockData *MockDataFactory
}

// NewTestUtils creates a new test utils instance
func NewTestUtils(t *testing.T) *TestUtils {
	tempDir, err := os.MkdirTemp("", "test-*")
	require.NoError(t, err)

	return &TestUtils{
		t:        t,
		tempDir:  tempDir,
		mockData: NewMockDataFactory(),
	}
}

// Cleanup cleans up test resources
func (tu *TestUtils) Cleanup() {
	if tu.tempDir != "" {
		os.RemoveAll(tu.tempDir)
	}
}

// GetTempDir returns the temporary directory
func (tu *TestUtils) GetTempDir() string {
	return tu.tempDir
}

// CreateTempFile creates a temporary file with content
func (tu *TestUtils) CreateTempFile(filename, content string) string {
	filePath := filepath.Join(tu.tempDir, filename)
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(tu.t, err)
	return filePath
}

// AssertJSONEqual asserts that two JSON strings are equal
func (tu *TestUtils) AssertJSONEqual(expected, actual string) {
	var expectedJSON, actualJSON interface{}
	
	err := json.Unmarshal([]byte(expected), &expectedJSON)
	require.NoError(tu.t, err)
	
	err = json.Unmarshal([]byte(actual), &actualJSON)
	require.NoError(tu.t, err)
	
	assert.Equal(tu.t, expectedJSON, actualJSON)
}

// AssertContains asserts that a string contains a substring
func (tu *TestUtils) AssertContains(str, substr string) {
	assert.Contains(tu.t, str, substr)
}

// AssertNotContains asserts that a string does not contain a substring
func (tu *TestUtils) AssertNotContains(str, substr string) {
	assert.NotContains(tu.t, str, substr)
}

// AssertLength asserts that a slice/map has the expected length
func (tu *TestUtils) AssertLength(obj interface{}, expectedLength int) {
	switch v := reflect.ValueOf(obj); v.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map, reflect.String:
		assert.Equal(tu.t, expectedLength, v.Len(), "Length mismatch")
	default:
		tu.t.Fatalf("Object is not a slice, array, map, or string")
	}
}

// MockHTTPClient provides a mock HTTP client for testing
type MockHTTPClient struct {
	responses map[string]*http.Response
	requests  []*http.Request
	t         *testing.T
}

// NewMockHTTPClient creates a new mock HTTP client
func NewMockHTTPClient(t *testing.T) *MockHTTPClient {
	return &MockHTTPClient{
		responses: make(map[string]*http.Response),
		requests:  make([]*http.Request, 0),
		t:         t,
	}
}

// SetMockResponse sets a mock response for a specific method and URL
func (m *MockHTTPClient) SetMockResponse(method, url string, response *http.Response) {
	key := fmt.Sprintf("%s:%s", method, url)
	m.responses[key] = response
}

// Do implements the HTTP client Do method
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)
	
	key := fmt.Sprintf("%s:%s", req.Method, req.URL.String())
	if response, exists := m.responses[key]; exists {
		return response, nil
	}
	
	// Default response
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("Not Found")),
	}, nil
}

// GetRequests returns all recorded requests
func (m *MockHTTPClient) GetRequests() []*http.Request {
	return m.requests
}

// VerifyRequest verifies that a request was made
func (m *MockHTTPClient) VerifyRequest(method, url string) bool {
	key := fmt.Sprintf("%s:%s", method, url)
	_, exists := m.responses[key]
	return exists
}

// GetRequestCount returns the number of requests made
func (m *MockHTTPClient) GetRequestCount(method, url string) int {
	count := 0
	for _, req := range m.requests {
		if req.Method == method && req.URL.String() == url {
			count++
		}
	}
	return count
}

// HTTPTestUtils provides utilities for HTTP testing
type HTTPTestUtils struct {
	t *testing.T
}

// NewHTTPTestUtils creates new HTTP test utils
func NewHTTPTestUtils(t *testing.T) *HTTPTestUtils {
	return &HTTPTestUtils{t: t}
}

// CreateTestRequest creates a test HTTP request
func (h *HTTPTestUtils) CreateTestRequest(method, url string, body interface{}) *http.Request {
	var reqBody io.Reader
	
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		require.NoError(h.t, err)
		reqBody = bytes.NewReader(bodyBytes)
	}
	
	req, err := http.NewRequest(method, url, reqBody)
	require.NoError(h.t, err)
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	
	return req
}

// CreateTestResponse creates a test HTTP response
func (h *HTTPTestUtils) CreateTestResponse(statusCode int, data interface{}) *http.Response {
	var body io.Reader
	
	if data != nil {
		bodyBytes, err := json.Marshal(data)
		require.NoError(h.t, err)
		body = bytes.NewReader(bodyBytes)
	} else {
		body = bytes.NewReader([]byte{})
	}
	
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(body),
		Header:     make(http.Header),
	}
}

// AssertJSONResponse asserts that an HTTP response contains expected JSON
func (h *HTTPTestUtils) AssertJSONResponse(resp *http.Response, expected interface{}) {
	require.Equal(h.t, http.StatusOK, resp.StatusCode)
	
	body, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)
	defer resp.Body.Close()
	
	var actual interface{}
	err = json.Unmarshal(body, &actual)
	require.NoError(h.t, err)
	
	assert.Equal(h.t, expected, actual)
}

// AssertErrorResponse asserts that an HTTP response contains an error
func (h *HTTPTestUtils) AssertErrorResponse(resp *http.Response, expectedStatusCode int, expectedMessage string) {
	require.Equal(h.t, expectedStatusCode, resp.StatusCode)
	
	body, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)
	defer resp.Body.Close()
	
	var errorResp map[string]interface{}
	err = json.Unmarshal(body, &errorResp)
	require.NoError(h.t, err)
	
	if message, ok := errorResp["error"].(string); ok {
		assert.Contains(h.t, message, expectedMessage)
	}
}

// PerformanceTestUtils provides utilities for performance testing
type PerformanceTestUtils struct {
	t *testing.T
}

// NewPerformanceTestUtils creates new performance test utils
func NewPerformanceTestUtils(t *testing.T) *PerformanceTestUtils {
	return &PerformanceTestUtils{t: t}
}

// MeasureExecutionTime measures the execution time of a function
func (p *PerformanceTestUtils) MeasureExecutionTime(fn func() error) (time.Duration, error) {
	start := time.Now()
	err := fn()
	duration := time.Since(start)
	return duration, err
}

// BenchmarkFunction benchmarks a function
func (p *PerformanceTestUtils) BenchmarkFunction(fn func() error, iterations int) BenchmarkResult {
	durations := make([]time.Duration, iterations)
	
	for i := 0; i < iterations; i++ {
		duration, err := p.MeasureExecutionTime(fn)
		require.NoError(p.t, err)
		durations[i] = duration
	}
	
	return BenchmarkResult{
		Durations: durations,
		Average:   p.calculateAverage(durations),
		Min:       p.calculateMin(durations),
		Max:       p.calculateMax(durations),
	}
}

// calculateAverage calculates the average duration
func (p *PerformanceTestUtils) calculateAverage(durations []time.Duration) time.Duration {
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}

// calculateMin calculates the minimum duration
func (p *PerformanceTestUtils) calculateMin(durations []time.Duration) time.Duration {
	min := durations[0]
	for _, d := range durations {
		if d < min {
			min = d
		}
	}
	return min
}

// calculateMax calculates the maximum duration
func (p *PerformanceTestUtils) calculateMax(durations []time.Duration) time.Duration {
	max := durations[0]
	for _, d := range durations {
		if d > max {
			max = d
		}
	}
	return max
}

// BenchmarkResult represents the result of a benchmark
type BenchmarkResult struct {
	Durations []time.Duration `json:"durations"`
	Average   time.Duration   `json:"average"`
	Min       time.Duration   `json:"min"`
	Max       time.Duration   `json:"max"`
}

// DatabaseTestUtils provides utilities for database testing
type DatabaseTestUtils struct {
	t    *testing.T
	db   *MockDatabase
}

// NewDatabaseTestUtils creates new database test utils
func NewDatabaseTestUtils(t *testing.T) *DatabaseTestUtils {
	return &DatabaseTestUtils{
		t:  t,
		db: NewMockDatabase(),
	}
}

// GetMockDatabase returns the mock database
func (d *DatabaseTestUtils) GetMockDatabase() *MockDatabase {
	return d.db
}

// AssertRecordExists asserts that a record exists in the database
func (d *DatabaseTestUtils) AssertRecordExists(table string, id interface{}) {
	exists := d.db.HasRecord(table, id)
	assert.True(d.t, exists, "Record should exist in table %s with id %v", table, id)
}

// AssertRecordCount asserts the number of records in a table
func (d *DatabaseTestUtils) AssertRecordCount(table string, expectedCount int) {
	count := d.db.GetRecordCount(table)
	assert.Equal(d.t, expectedCount, count, "Table %s should have %d records", table, expectedCount)
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

// IntegrationTestUtils provides utilities for integration testing
type IntegrationTestUtils struct {
	t        *testing.T
	testUtils *TestUtils
	httpUtils *HTTPTestUtils
	dbUtils   *DatabaseTestUtils
}

// NewIntegrationTestUtils creates new integration test utils
func NewIntegrationTestUtils(t *testing.T) *IntegrationTestUtils {
	return &IntegrationTestUtils{
		t:         t,
		testUtils: NewTestUtils(t),
		httpUtils: NewHTTPTestUtils(t),
		dbUtils:   NewDatabaseTestUtils(t),
	}
}

// Cleanup cleans up integration test resources
func (i *IntegrationTestUtils) Cleanup() {
	i.testUtils.Cleanup()
	i.dbUtils.GetMockDatabase().ClearAll()
}

// GetTestUtils returns the test utils
func (i *IntegrationTestUtils) GetTestUtils() *TestUtils {
	return i.testUtils
}

// GetHTTPUtils returns the HTTP test utils
func (i *IntegrationTestUtils) GetHTTPUtils() *HTTPTestUtils {
	return i.httpUtils
}

// GetDBUtils returns the database test utils
func (i *IntegrationTestUtils) GetDBUtils() *DatabaseTestUtils {
	return i.dbUtils
}

// SetupTestEnvironment sets up a test environment
func (i *IntegrationTestUtils) SetupTestEnvironment() TestEnvironment {
	return TestEnvironment{
		Database: i.dbUtils.GetMockDatabase(),
		Config:   map[string]interface{}{
			"database_url": "mock://localhost:5432/testdb",
			"redis_url":    "mock://localhost:6379/0",
			"jwt_secret":   "test-secret",
			"debug":        true,
		},
	}
}

// TestEnvironment represents a test environment
type TestEnvironment struct {
	Database *MockDatabase
	Config   map[string]interface{}
}

// TestSuite provides a base test suite
type TestSuite struct {
	suite.Suite
	testUtils *TestUtils
	mockData  *MockDataFactory
}

// SetupSuite sets up the test suite
func (s *TestSuite) SetupSuite() {
	s.testUtils = NewTestUtils(s.T())
	s.mockData = NewMockDataFactory()
}

// TearDownSuite tears down the test suite
func (s *TestSuite) TearDownSuite() {
	s.testUtils.Cleanup()
}

// GetTestUtils returns the test utils
func (s *TestSuite) GetTestUtils() *TestUtils {
	return s.testUtils
}

// GetMockDataFactory returns the mock data factory
func (s *TestSuite) GetMockDataFactory() *MockDataFactory {
	return s.mockData
}

// CustomMatchers provides custom test matchers
type CustomMatchers struct{}

// AssertJSONStructure asserts that JSON has a specific structure
func (c *CustomMatchers) AssertJSONStructure(t *testing.T, jsonStr string, expectedFields []string) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &data)
	require.NoError(t, err)
	
	for _, field := range expectedFields {
		_, exists := data[field]
		assert.True(t, exists, "Field %s should exist in JSON", field)
	}
}

// AssertTimeRange asserts that a time is within a range
func (c *CustomMatchers) AssertTimeRange(t *testing.T, actual, start, end time.Time) {
	assert.True(t, actual.After(start) || actual.Equal(start), "Time should be after or equal to start")
	assert.True(t, actual.Before(end) || actual.Equal(end), "Time should be before or equal to end")
}

// AssertRecent asserts that a time is recent (within specified duration)
func (c *CustomMatchers) AssertRecent(t *testing.T, actual time.Time, within time.Duration) {
	now := time.Now()
	assert.True(t, actual.After(now.Add(-within)), "Time should be recent (within %v)", within)
	assert.True(t, actual.Before(now.Add(within)), "Time should be recent (within %v)", within)
}

// TestConfig provides test configuration
type TestConfig struct {
	DefaultTimeout time.Duration `json:"default_timeout"`
	ShortTimeout   time.Duration `json:"short_timeout"`
	LongTimeout    time.Duration `json:"long_timeout"`
	MaxRetries     int           `json:"max_retries"`
	TestDataDir    string        `json:"test_data_dir"`
}

// DefaultTestConfig returns default test configuration
func DefaultTestConfig() TestConfig {
	return TestConfig{
		DefaultTimeout: 30 * time.Second,
		ShortTimeout:   5 * time.Second,
		LongTimeout:    60 * time.Second,
		MaxRetries:     3,
		TestDataDir:    "./testdata",
	}
}

// Example usage demonstrates how to use the testing utilities
func ExampleUsage(t *testing.T) {
	// Create test utils
	testUtils := NewTestUtils(t)
	defer testUtils.Cleanup()

	// Create mock data
	factory := NewMockDataFactory()
	user := factory.CreateMockUser(map[string]interface{}{
		"username": "exampleuser",
		"email":    "user@example.com",
	})

	// Create temp file
	configFile := testUtils.CreateTempFile("config.json", `{"debug": true}`)
	assert.Equal(t, "config.json", filepath.Base(configFile))

	// Test HTTP utilities
	httpUtils := NewHTTPTestUtils(t)
	req := httpUtils.CreateTestRequest("GET", "/api/users", nil)
	assert.Equal(t, "GET", req.Method)

	// Test database utilities
	dbUtils := NewDatabaseTestUtils(t)
	db := dbUtils.GetMockDatabase()
	db.Insert("users", 1, user)
	dbUtils.AssertRecordExists("users", 1)
	dbUtils.AssertRecordCount("users", 1)

	// Test performance
	perfUtils := NewPerformanceTestUtils(t)
	duration, err := perfUtils.MeasureExecutionTime(func() error {
		time.Sleep(100 * time.Millisecond)
		return nil
	})
	assert.NoError(t, err)
	assert.True(t, duration >= 100*time.Millisecond)

	// Test integration
	integrationUtils := NewIntegrationTestUtils(t)
	defer integrationUtils.Cleanup()
	env := integrationUtils.SetupTestEnvironment()
	assert.NotNil(t, env.Database)
	assert.True(t, env.Config["debug"].(bool))

	// Use custom matchers
	matchers := CustomMatchers{}
	matchers.AssertJSONStructure(t, `{"name": "test", "value": 123}`, []string{"name", "value"})
	matchers.AssertRecent(t, time.Now(), time.Minute)
}
