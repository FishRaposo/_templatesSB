package testing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// =============================================================================
// DATABASE TESTING HELPERS
// =============================================================================

// TestDatabase provides a test database with mock capabilities
type TestDatabase struct {
	DB     *gorm.DB
	SqlDB sqlmock.Sqlmock
	T      *testing.T
}

// NewTestDatabase creates a new test database with SQL mock
func NewTestDatabase(t *testing.T) *TestDatabase {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)

	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: sqlDB,
	}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	return &TestDatabase{
		DB:     gormDB,
		SqlDB:  mock,
		T:      t,
	}
}

// Close closes the database connection
func (td *TestDatabase) Close() error {
	sqlDB, err := td.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// ExpectQuery expects a database query
func (td *TestDatabase) ExpectQuery(query string) *sqlmock.ExpectedQuery {
	return td.SqlDB.ExpectQuery(regexp.QuoteMeta(query))
}

// ExpectExec expects a database execution
func (td *TestDatabase) ExpectExec(query string) *sqlmock.ExpectedExec {
	return td.SqlDB.ExpectExec(regexp.QuoteMeta(query))
}

// ExpectBegin expects a database transaction begin
func (td *TestDatabase) ExpectBegin() *sqlmock.ExpectedBegin {
	return td.SqlDB.ExpectBegin()
}

// ExpectCommit expects a database transaction commit
func (td *TestDatabase) ExpectCommit() *sqlmock.ExpectedCommit {
	return td.SqlDB.ExpectCommit()
}

// ExpectRollback expects a database transaction rollback
func (td *TestDatabase) ExpectRollback() *sqlmock.ExpectedRollback {
	return td.SqlDB.ExpectRollback()
}

// =============================================================================
// HTTP TESTING HELPERS
// =============================================================================

// TestHTTPClient provides HTTP testing utilities
type TestHTTPClient struct {
	Client  *http.Client
	BaseURL string
	T       *testing.T
}

// NewTestHTTPClient creates a new test HTTP client
func NewTestHTTPClient(t *testing.T, handler http.Handler) *TestHTTPClient {
	return &TestHTTPClient{
		Client:  &http.Client{},
		BaseURL: "http://test",
		T:       t,
	}
}

// Do executes an HTTP request with the given parameters
func (tc *TestHTTPClient) Do(method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		require.NoError(tc.T, err)
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req := httptest.NewRequest(method, path, reqBody)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	w := httptest.NewRecorder()
	handler := tc.getHandler()
	handler.ServeHTTP(w, req)

	return w
}

// Get executes a GET request
func (tc *TestHTTPClient) Get(path string, headers map[string]string) *httptest.ResponseRecorder {
	return tc.Do(http.MethodGet, path, nil, headers)
}

// Post executes a POST request
func (tc *TestHTTPClient) Post(path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	return tc.Do(http.MethodPost, path, body, headers)
}

// Put executes a PUT request
func (tc *TestHTTPClient) Put(path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	return tc.Do(http.MethodPut, path, body, headers)
}

// Delete executes a DELETE request
func (tc *TestHTTPClient) Delete(path string, headers map[string]string) *httptest.ResponseRecorder {
	return tc.Do(http.MethodDelete, path, nil, headers)
}

// getHandler returns the HTTP handler (to be implemented by specific test)
func (tc *TestHTTPClient) getHandler() http.Handler {
	// This should be overridden or implemented by the specific test
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// =============================================================================
// MOCK CONTROLLER HELPERS
// =============================================================================

// MockController provides mock controller utilities
type MockController struct {
	Controller *gomock.Controller
	T          *testing.T
}

// NewMockController creates a new mock controller
func NewMockController(t *testing.T) *MockController {
	return &MockController{
		Controller: gomock.NewController(t),
		T:          t,
	}
}

// Finish finishes the mock controller
func (mc *MockController) Finish() {
	mc.Controller.Finish()
}

// =============================================================================
// TEST DATA GENERATORS
// =============================================================================

// TestDataGenerator generates test data
type TestDataGenerator struct {
	Rand *rand.Rand
}

// NewTestDataGenerator creates a new test data generator
func NewTestDataGenerator() *TestDataGenerator {
	return &TestDataGenerator{
		Rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// GenerateUser generates test user data
func (tdg *TestDataGenerator) GenerateUser() map[string]interface{} {
	return map[string]interface{}{
		"id":        tdg.Rand.Int63(),
		"email":     fmt.Sprintf("user%d@example.com", tdg.Rand.Int63()),
		"firstName": fmt.Sprintf("FirstName%d", tdg.Rand.Int63()),
		"lastName":  fmt.Sprintf("LastName%d", tdg.Rand.Int63()),
		"username":  fmt.Sprintf("user%d", tdg.Rand.Int63()),
		"password":  fmt.Sprintf("password%d", tdg.Rand.Int63()),
		"phone":     fmt.Sprintf("+1%d", tdg.Rand.Int63()),
		"active":    tdg.Rand.Intn(2) == 1,
		"createdAt": time.Now(),
		"updatedAt": time.Now(),
	}
}

// GenerateProduct generates test product data
func (tdg *TestDataGenerator) GenerateProduct() map[string]interface{} {
	return map[string]interface{}{
		"id":          tdg.Rand.Int63(),
		"name":        fmt.Sprintf("Product%d", tdg.Rand.Int63()),
		"description": fmt.Sprintf("Description for product %d", tdg.Rand.Int63()),
		"price":       float64(tdg.Rand.Int63n(1000)) + float64(tdg.Rand.Int63n(100))/100,
		"category":    []string{"electronics", "clothing", "books", "home"}[tdg.Rand.Intn(4)],
		"sku":         fmt.Sprintf("SKU-%d", tdg.Rand.Int63()),
		"stock":       tdg.Rand.Intn(1000),
		"active":      tdg.Rand.Intn(2) == 1,
		"createdAt":   time.Now(),
		"updatedAt":   time.Now(),
	}
}

// GenerateOrder generates test order data
func (tdg *TestDataGenerator) GenerateOrder() map[string]interface{} {
	return map[string]interface{}{
		"id":         tdg.Rand.Int63(),
		"userID":     tdg.Rand.Int63(),
		"status":     []string{"pending", "confirmed", "shipped", "delivered"}[tdg.Rand.Intn(4)],
		"total":      float64(tdg.Rand.Int63n(500)) + float64(tdg.Rand.Int63n(100))/100,
		"currency":   []string{"USD", "EUR", "GBP"}[tdg.Rand.Intn(3)],
		"createdAt":  time.Now(),
		"updatedAt":  time.Now(),
	}
}

// =============================================================================
// LOGGER TESTING HELPERS
// =============================================================================

// TestLogger provides a test logger
type TestLogger struct {
	Logger *zap.Logger
	Buffer *bytes.Buffer
}

// NewTestLogger creates a new test logger
func NewTestLogger(t *testing.T) *TestLogger {
	logger := zaptest.NewLogger(t)
	return &TestLogger{
		Logger: logger,
		Buffer: &bytes.Buffer{},
	}
}

// =============================================================================
// CONTEXT TESTING HELPERS
// =============================================================================

// TestContext provides test context utilities
type TestContext struct {
	Context context.Context
	Cancel  context.CancelFunc
}

// NewTestContext creates a new test context with timeout
func NewTestContext(t *testing.T, timeout time.Duration) *TestContext {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return &TestContext{
		Context: ctx,
		Cancel:  cancel,
	}
}

// NewTestContextWithCancel creates a new test context with cancel function
func NewTestContextWithCancel() *TestContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &TestContext{
		Context: ctx,
		Cancel:  cancel,
	}
}

// =============================================================================
// FILE SYSTEM TESTING HELPERS
// =============================================================================

// TestFileSystem provides file system testing utilities
type TestFileSystem struct {
	T       *testing.T
	TempDir string
}

// NewTestFileSystem creates a new test file system
func NewTestFileSystem(t *testing.T) *TestFileSystem {
	tempDir, err := os.MkdirTemp("", "test-*")
	require.NoError(t, err)

	return &TestFileSystem{
		T:       t,
		TempDir: tempDir,
	}
}

// Cleanup cleans up the test file system
func (tfs *TestFileSystem) Cleanup() {
	os.RemoveAll(tfs.TempDir)
}

// CreateFile creates a test file with the given content
func (tfs *TestFileSystem) CreateFile(name, content string) string {
	filePath := filepath.Join(tfs.TempDir, name)
	err := os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(tfs.T, err)
	return filePath
}

// CreateTempFile creates a temporary file with the given content
func (tfs *TestFileSystem) CreateTempFile(content string) string {
	file, err := os.CreateTemp(tfs.TempDir, "test-*.tmp")
	require.NoError(tfs.T, err)
	defer file.Close()

	_, err = file.WriteString(content)
	require.NoError(tfs.T, err)

	return file.Name()
}

// =============================================================================
// ASSERTION HELPERS
// =============================================================================

// AssertionHelper provides custom assertion helpers
type AssertionHelper struct {
	T *testing.T
}

// NewAssertionHelper creates a new assertion helper
func NewAssertionHelper(t *testing.T) *AssertionHelper {
	return &AssertionHelper{T: t}
}

// AssertJSONEqual asserts that two JSON strings are equal
func (ah *AssertionHelper) AssertJSONEqual(expected, actual string) {
	var expectedJSON, actualJSON interface{}
	err := json.Unmarshal([]byte(expected), &expectedJSON)
	require.NoError(ah.T, err)
	err = json.Unmarshal([]byte(actual), &actualJSON)
	require.NoError(ah.T, err)
	assert.Equal(ah.T, expectedJSON, actualJSON)
}

// AssertJSONContains asserts that JSON contains specific fields
func (ah *AssertionHelper) AssertJSONContains(jsonStr string, fields map[string]interface{}) {
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &jsonData)
	require.NoError(ah.T, err)

	for key, expectedValue := range fields {
		actualValue, exists := jsonData[key]
		assert.True(ah.T, exists, "Expected field %s not found", key)
		if exists {
			assert.Equal(ah.T, expectedValue, actualValue, "Field %s value mismatch", key)
		}
	}
}

// AssertTimeClose asserts that two times are close within tolerance
func (ah *AssertionHelper) AssertTimeClose(expected, actual time.Time, tolerance time.Duration) {
	diff := expected.Sub(actual)
	if diff < 0 {
		diff = -diff
	}
	assert.True(ah.T, diff <= tolerance, "Times differ by %v, tolerance is %v", diff, tolerance)
}

// =============================================================================
// PERFORMANCE TESTING HELPERS
// =============================================================================

// PerformanceHelper provides performance testing utilities
type PerformanceHelper struct {
	T *testing.T
}

// NewPerformanceHelper creates a new performance helper
func NewPerformanceHelper(t *testing.T) *PerformanceHelper {
	return &PerformanceHelper{T: t}
}

// MeasureExecutionTime measures the execution time of a function
func (ph *PerformanceHelper) MeasureExecutionTime(fn func() (interface{}, error)) (interface{}, time.Duration, error) {
	start := time.Now()
	result, err := fn()
	duration := time.Since(start)
	return result, duration, err
}

// BenchmarkFunction benchmarks a function over multiple iterations
func (ph *PerformanceHelper) BenchmarkFunction(fn func() (interface{}, error), iterations int) BenchmarkResult {
	var durations []time.Duration
	var totalDuration time.Duration

	for i := 0; i < iterations; i++ {
		_, duration, err := ph.MeasureExecutionTime(fn)
		require.NoError(ph.T, err)
		durations = append(durations, duration)
		totalDuration += duration
	}

	// Calculate statistics
	var minDuration, maxDuration time.Duration = durations[0], durations[0]
	for _, d := range durations[1:] {
		if d < minDuration {
			minDuration = d
		}
		if d > maxDuration {
			maxDuration = d
		}
	}

	avgDuration := totalDuration / time.Duration(iterations)

	// Calculate percentiles (simplified)
	sortedDurations := make([]time.Duration, len(durations))
	copy(sortedDurations, durations)
	
	// Simple sort for percentiles
	for i := 0; i < len(sortedDurations); i++ {
		for j := i + 1; j < len(sortedDurations); j++ {
			if sortedDurations[i] > sortedDurations[j] {
				sortedDurations[i], sortedDurations[j] = sortedDurations[j], sortedDurations[i]
			}
		}
	}

	p95Index := int(float64(iterations) * 0.95)
	p99Index := int(float64(iterations) * 0.99)
	
	p95Duration := sortedDurations[p95Index]
	p99Duration := sortedDurations[p99Index]

	return BenchmarkResult{
		Iterations:    iterations,
		TotalDuration: totalDuration,
		AvgDuration:   avgDuration,
		MinDuration:   minDuration,
		MaxDuration:   maxDuration,
		P95Duration:   p95Duration,
		P99Duration:   p99Duration,
	}
}

// BenchmarkResult contains benchmark results
type BenchmarkResult struct {
	Iterations    int
	TotalDuration time.Duration
	AvgDuration   time.Duration
	MinDuration   time.Duration
	MaxDuration   time.Duration
	P95Duration   time.Duration
	P99Duration   time.Duration
}

// =============================================================================
// SECURITY TESTING HELPERS
// =============================================================================

// SecurityHelper provides security testing utilities
type SecurityHelper struct {
	T *testing.T
}

// NewSecurityHelper creates a new security helper
func NewSecurityHelper(t *testing.T) *SecurityHelper {
	return &SecurityHelper{T: t}
}

// GenerateSQLInjectionPayloads generates SQL injection payloads
func (sh *SecurityHelper) GenerateSQLInjectionPayloads() []string {
	return []string{
		"' OR '1'='1",
		"' OR '1'='1' --",
		"' OR '1'='1' /*",
		"admin'--",
		"admin' /*",
		"' OR 1=1--",
		"' OR 1=1#",
		"' OR 1=1/*",
		"') OR '1'='1--",
		"') OR ('1'='1--",
	}
}

// GenerateXSSPayloads generates XSS payloads
func (sh *SecurityHelper) GenerateXSSPayloads() []string {
	return []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"javascript:alert('XSS')",
		"<svg onload=alert('XSS')>",
		"';alert('XSS');//",
	}
}

// GeneratePathTraversalPayloads generates path traversal payloads
func (sh *SecurityHelper) GeneratePathTraversalPayloads() []string {
	return []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
	}
}

// =============================================================================
// INTEGRATION TESTING HELPERS
// =============================================================================

// IntegrationHelper provides integration testing utilities
type IntegrationHelper struct {
	T *testing.T
}

// NewIntegrationHelper creates a new integration helper
func NewIntegrationHelper(t *testing.T) *IntegrationHelper {
	return &IntegrationHelper{T: t}
}

// WaitForService waits for a service to be available
func (ih *IntegrationHelper) WaitForService(url string, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	start := time.Now()

	for time.Since(start) < timeout {
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("service not available after %v", timeout)
}

// =============================================================================
// TEST SUITE BASE
// =============================================================================

// TestSuiteBase provides a base test suite with common functionality
type TestSuiteBase struct {
	suite.Suite
	MockController *MockController
	TestDB        *TestDatabase
	TestHTTP      *TestHTTPClient
	TestFS        *TestFileSystem
	Logger        *TestLogger
	DataGen       *TestDataGenerator
	Assertions    *AssertionHelper
	Performance   *PerformanceHelper
	Security      *SecurityHelper
	Integration   *IntegrationHelper
}

// SetupSuite sets up the test suite
func (ts *TestSuiteBase) SetupSuite() {
	ts.MockController = NewMockController(ts.T())
	ts.TestDB = NewTestDatabase(ts.T())
	ts.TestFS = NewTestFileSystem(ts.T())
	ts.Logger = NewTestLogger(ts.T())
	ts.DataGen = NewTestDataGenerator()
	ts.Assertions = NewAssertionHelper(ts.T())
	ts.Performance = NewPerformanceHelper(ts.T())
	ts.Security = NewSecurityHelper(ts.T())
	ts.Integration = NewIntegrationHelper(ts.T())
}

// TearDownSuite tears down the test suite
func (ts *TestSuiteBase) TearDownSuite() {
	if ts.MockController != nil {
		ts.MockController.Finish()
	}
	if ts.TestDB != nil {
		ts.TestDB.Close()
	}
	if ts.TestFS != nil {
		ts.TestFS.Cleanup()
	}
}

// =============================================================================
// PYTEST-LIKE FIXTURES FOR GO
// =============================================================================

// WithTestDB provides a test database fixture
func WithTestDB(t *testing.T, fn func(db *TestDatabase)) {
	db := NewTestDatabase(t)
	defer db.Close()
	fn(db)
}

// WithMockController provides a mock controller fixture
func WithMockController(t *testing.T, fn func(mc *MockController)) {
	mc := NewMockController(t)
	defer mc.Finish()
	fn(mc)
}

// WithTestFileSystem provides a test file system fixture
func WithTestFileSystem(t *testing.T, fn func(fs *TestFileSystem)) {
	fs := NewTestFileSystem(t)
	defer fs.Cleanup()
	fn(fs)
}

// WithTestLogger provides a test logger fixture
func WithTestLogger(t *testing.T, fn func(logger *TestLogger)) {
	logger := NewTestLogger(t)
	fn(logger)
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

// SkipIfShort skips the test if running in short mode
func SkipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}
}

// SkipIfRace skips the test if race detector is enabled
func SkipIfRace(t *testing.T) {
	if raceEnabled() {
		t.Skip("Skipping test with race detector")
	}
}

// raceEnabled checks if race detector is enabled
func raceEnabled() bool {
	// This is a simplified check - in practice you might want to check
	// build tags or environment variables
	return strings.Contains(os.Getenv("GOFLAGS"), "-race")
}

// GetCaller gets the caller information for debugging
func GetCaller(skip int) (string, string, int) {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return "", "", 0
	}
	
	funcName := runtime.FuncForPC(pc).Name()
	fileName := filepath.Base(file)
	
	return funcName, fileName, line
}

// =============================================================================
// CUSTOM MATCHERS
// =============================================================================

// JSONMatcher provides JSON matching capabilities
type JSONMatcher struct {
	Expected interface{}
}

// NewJSONMatcher creates a new JSON matcher
func NewJSONMatcher(expected interface{}) *JSONMatcher {
	return &JSONMatcher{Expected: expected}
}

// Matches checks if the actual value matches the expected JSON
func (j *JSONMatcher) Matches(x interface{}) bool {
	actualBytes, err := json.Marshal(x)
	if err != nil {
		return false
	}
	
	expectedBytes, err := json.Marshal(j.Expected)
	if err != nil {
		return false
	}
	
	return bytes.Equal(actualBytes, expectedBytes)
}

// String returns the string representation of the matcher
func (j *JSONMatcher) String() string {
	return fmt.Sprintf("JSON equal to %v", j.Expected)
}