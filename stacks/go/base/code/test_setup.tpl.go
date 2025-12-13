// File: test_setup.tpl.go
// Purpose: Comprehensive test setup and fixtures for Go
// Generated for: {{PROJECT_NAME}}

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
	"testing"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ============================================================================
// Test Configuration
// ============================================================================

type TestConfig struct {
	DatabaseURL string
	RedisURL    string
	JWTSecret   string
}

func LoadTestConfig() *TestConfig {
	return &TestConfig{
		DatabaseURL: getEnvOrDefault("TEST_DATABASE_URL", "postgres://test:test@localhost:5432/test_db?sslmode=disable"),
		RedisURL:    getEnvOrDefault("TEST_REDIS_URL", "redis://localhost:6379/1"),
		JWTSecret:   getEnvOrDefault("JWT_SECRET", "test-secret-key"),
	}
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// ============================================================================
// Database Setup
// ============================================================================

var testDB *gorm.DB

func SetupTestDatabase(t *testing.T) *gorm.DB {
	config := LoadTestConfig()

	db, err := gorm.Open(postgres.Open(config.DatabaseURL), &gorm.Config{})
	require.NoError(t, err)

	// Run migrations
	// err = db.AutoMigrate(&User{}, &Post{}, &Session{})
	// require.NoError(t, err)

	testDB = db
	return db
}

func CleanupDatabase(t *testing.T, db *gorm.DB) {
	tables := []string{"sessions", "posts", "users"}
	for _, table := range tables {
		err := db.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table)).Error
		if err != nil {
			t.Logf("Warning: Failed to truncate %s: %v", table, err)
		}
	}
}

func TeardownDatabase(t *testing.T, db *gorm.DB) {
	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.Close()
	}
}

// Transaction wrapper for test isolation
func WithTransaction(t *testing.T, db *gorm.DB, fn func(*gorm.DB)) {
	tx := db.Begin()
	defer tx.Rollback()

	fn(tx)
}

// ============================================================================
// Redis Setup
// ============================================================================

var testRedis *redis.Client

func SetupTestRedis(t *testing.T) *redis.Client {
	config := LoadTestConfig()

	opt, err := redis.ParseURL(config.RedisURL)
	require.NoError(t, err)

	client := redis.NewClient(opt)

	ctx := context.Background()
	err = client.Ping(ctx).Err()
	require.NoError(t, err)

	testRedis = client
	return client
}

func CleanupRedis(t *testing.T, client *redis.Client) {
	ctx := context.Background()
	err := client.FlushDB(ctx).Err()
	require.NoError(t, err)
}

func TeardownRedis(t *testing.T, client *redis.Client) {
	client.Close()
}

// ============================================================================
// HTTP Test Helpers
// ============================================================================

type TestClient struct {
	handler http.Handler
	t       *testing.T
	token   string
	headers map[string]string
}

func NewTestClient(t *testing.T, handler http.Handler) *TestClient {
	return &TestClient{
		handler: handler,
		t:       t,
		headers: make(map[string]string),
	}
}

func (c *TestClient) WithAuth(token string) *TestClient {
	c.token = token
	return c
}

func (c *TestClient) WithHeader(key, value string) *TestClient {
	c.headers[key] = value
	return c
}

func (c *TestClient) Do(method, path string, body interface{}) *TestResponse {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		require.NoError(c.t, err)
		bodyReader = bytes.NewReader(jsonBody)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)

	return &TestResponse{
		Response: rec,
		t:        c.t,
	}
}

func (c *TestClient) Get(path string) *TestResponse {
	return c.Do("GET", path, nil)
}

func (c *TestClient) Post(path string, body interface{}) *TestResponse {
	return c.Do("POST", path, body)
}

func (c *TestClient) Put(path string, body interface{}) *TestResponse {
	return c.Do("PUT", path, body)
}

func (c *TestClient) Patch(path string, body interface{}) *TestResponse {
	return c.Do("PATCH", path, body)
}

func (c *TestClient) Delete(path string) *TestResponse {
	return c.Do("DELETE", path, nil)
}

// ============================================================================
// Response Assertions
// ============================================================================

type TestResponse struct {
	Response *httptest.ResponseRecorder
	t        *testing.T
	parsed   map[string]interface{}
}

func (r *TestResponse) Status(expected int) *TestResponse {
	assert.Equal(r.t, expected, r.Response.Code)
	return r
}

func (r *TestResponse) OK() *TestResponse {
	return r.Status(http.StatusOK)
}

func (r *TestResponse) Created() *TestResponse {
	return r.Status(http.StatusCreated)
}

func (r *TestResponse) NoContent() *TestResponse {
	return r.Status(http.StatusNoContent)
}

func (r *TestResponse) BadRequest() *TestResponse {
	return r.Status(http.StatusBadRequest)
}

func (r *TestResponse) Unauthorized() *TestResponse {
	return r.Status(http.StatusUnauthorized)
}

func (r *TestResponse) Forbidden() *TestResponse {
	return r.Status(http.StatusForbidden)
}

func (r *TestResponse) NotFound() *TestResponse {
	return r.Status(http.StatusNotFound)
}

func (r *TestResponse) JSON() map[string]interface{} {
	if r.parsed != nil {
		return r.parsed
	}

	var result map[string]interface{}
	err := json.Unmarshal(r.Response.Body.Bytes(), &result)
	require.NoError(r.t, err)

	r.parsed = result
	return result
}

func (r *TestResponse) JSONArray() []interface{} {
	var result []interface{}
	err := json.Unmarshal(r.Response.Body.Bytes(), &result)
	require.NoError(r.t, err)
	return result
}

func (r *TestResponse) HasKey(keys ...string) *TestResponse {
	data := r.JSON()
	for _, key := range keys {
		assert.Contains(r.t, data, key)
	}
	return r
}

func (r *TestResponse) DataEquals(key string, expected interface{}) *TestResponse {
	data := r.JSON()
	assert.Equal(r.t, expected, data[key])
	return r
}

func (r *TestResponse) DataContains(expected map[string]interface{}) *TestResponse {
	data := r.JSON()
	for key, value := range expected {
		assert.Equal(r.t, value, data[key])
	}
	return r
}

func (r *TestResponse) Bind(v interface{}) *TestResponse {
	err := json.Unmarshal(r.Response.Body.Bytes(), v)
	require.NoError(r.t, err)
	return r
}

// ============================================================================
// Factories
// ============================================================================

type UserData struct {
	Email        string
	Username     string
	PasswordHash string
	FullName     string
	IsActive     bool
	IsVerified   bool
}

func GenerateUserData() UserData {
	return UserData{
		Email:        faker.Email(),
		Username:     faker.Username(),
		PasswordHash: "$2a$10$test.hash.here",
		FullName:     faker.Name(),
		IsActive:     true,
		IsVerified:   true,
	}
}

type PostData struct {
	Title    string
	Slug     string
	Content  string
	Excerpt  string
	Status   string
	AuthorID uint
}

func GeneratePostData(authorID uint) PostData {
	title := faker.Sentence()
	return PostData{
		Title:    title,
		Slug:     slugify(title),
		Content:  faker.Paragraph(),
		Excerpt:  faker.Sentence(),
		Status:   "published",
		AuthorID: authorID,
	}
}

func slugify(s string) string {
	// Simple slugify - in production use a proper slugify library
	return "test-slug-" + faker.Word()
}

// ============================================================================
// Test Suite Base
// ============================================================================

type BaseSuite struct {
	suite.Suite
	DB     *gorm.DB
	Redis  *redis.Client
	Client *TestClient
	Ctx    context.Context
}

func (s *BaseSuite) SetupSuite() {
	s.DB = SetupTestDatabase(s.T())
	s.Redis = SetupTestRedis(s.T())
	s.Ctx = context.Background()
}

func (s *BaseSuite) TearDownSuite() {
	TeardownDatabase(s.T(), s.DB)
	TeardownRedis(s.T(), s.Redis)
}

func (s *BaseSuite) SetupTest() {
	CleanupDatabase(s.T(), s.DB)
	CleanupRedis(s.T(), s.Redis)
}

// ============================================================================
// Assertion Helpers
// ============================================================================

func AssertExistsInDB(t *testing.T, db *gorm.DB, model interface{}, query interface{}, args ...interface{}) {
	result := db.Where(query, args...).First(model)
	assert.NoError(t, result.Error)
}

func AssertNotExistsInDB(t *testing.T, db *gorm.DB, model interface{}, query interface{}, args ...interface{}) {
	result := db.Where(query, args...).First(model)
	assert.Error(t, result.Error)
	assert.True(t, result.Error == gorm.ErrRecordNotFound)
}

func AssertCountInDB(t *testing.T, db *gorm.DB, model interface{}, expected int64, query interface{}, args ...interface{}) {
	var count int64
	db.Model(model).Where(query, args...).Count(&count)
	assert.Equal(t, expected, count)
}

func AssertRecentTime(t *testing.T, actual time.Time, within time.Duration) {
	diff := time.Since(actual)
	assert.LessOrEqual(t, diff, within)
}

func AssertJSONEqual(t *testing.T, expected, actual string) {
	var expectedMap, actualMap interface{}
	require.NoError(t, json.Unmarshal([]byte(expected), &expectedMap))
	require.NoError(t, json.Unmarshal([]byte(actual), &actualMap))
	assert.Equal(t, expectedMap, actualMap)
}

// ============================================================================
// Mock Helpers
// ============================================================================

type MockEmailService struct {
	SentEmails []MockEmail
}

type MockEmail struct {
	To      string
	Subject string
	Body    string
}

func (m *MockEmailService) SendEmail(to, subject, body string) error {
	m.SentEmails = append(m.SentEmails, MockEmail{
		To:      to,
		Subject: subject,
		Body:    body,
	})
	return nil
}

func (m *MockEmailService) Reset() {
	m.SentEmails = nil
}

type MockPaymentService struct {
	Customers     map[string]interface{}
	Subscriptions map[string]interface{}
}

func NewMockPaymentService() *MockPaymentService {
	return &MockPaymentService{
		Customers:     make(map[string]interface{}),
		Subscriptions: make(map[string]interface{}),
	}
}

func (m *MockPaymentService) CreateCustomer(email string) (string, error) {
	id := "cus_test_" + faker.Word()
	m.Customers[id] = map[string]string{"email": email}
	return id, nil
}

func (m *MockPaymentService) CreateSubscription(customerID, priceID string) (string, error) {
	id := "sub_test_" + faker.Word()
	m.Subscriptions[id] = map[string]string{
		"customer": customerID,
		"price":    priceID,
		"status":   "active",
	}
	return id, nil
}

// ============================================================================
// Benchmark Helpers
// ============================================================================

func BenchmarkWithSetup(b *testing.B, setup func() interface{}, benchmark func(interface{})) {
	data := setup()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmark(data)
	}
}

// ============================================================================
// Test Main
// ============================================================================

func TestMain(m *testing.M) {
	// Setup
	config := LoadTestConfig()
	_ = config

	// Run tests
	code := m.Run()

	// Teardown
	os.Exit(code)
}
