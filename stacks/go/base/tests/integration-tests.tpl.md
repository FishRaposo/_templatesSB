# Go Integration Testing Template
# Integration testing patterns for Go projects

package integration

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// ====================
// SUITE SETUP
// ====================

// IntegrationTestSuite provides shared test infrastructure
type IntegrationTestSuite struct {
	suite.Suite
	db       *sql.DB
	server   *httptest.Server
	redis    *RedisContainer
	postgres *PostgresContainer
}

// SetupSuite runs once before all tests
func (s *IntegrationTestSuite) SetupSuite() {
	// Start PostgreSQL container
	ctx := context.Background()
	postgres, err := testcontainers.GenericContainer(ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "postgres:15-alpine",
				ExposedPorts: []string{"5432/tcp"},
				Env: map[string]string{
					"POSTGRES_USER":     "testuser",
					"POSTGRES_PASSWORD": "testpass",
					"POSTGRES_DB":       "testdb",
				},
				WaitingFor: wait.ForLog("database system is ready to accept connections"),
			},
			Started: true,
		})
	require.NoError(s.T(), err)
	s.postgres = &PostgresContainer{Container: postgres}

	// Start Redis container
	redis, err := testcontainers.GenericContainer(ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "redis:7-alpine",
				ExposedPorts: []string{"6379/tcp"},
				WaitingFor:   wait.ForLog("Ready to accept connections"),
			},
			Started: true,
		})
	require.NoError(s.T(), err)
	s.redis = &RedisContainer{Container: redis}

	// Connect to database
	host, _ := s.postgres.Host(ctx)
	port, _ := s.postgres.MappedPort(ctx, "5432")
	connStr := fmt.Sprintf("postgres://testuser:testpass@%s:%s/testdb?sslmode=disable", host, port.Port())
	s.db, err = sql.Open("postgres", connStr)
	require.NoError(s.T(), err)

	// Run migrations
	runMigrations(s.db)

	// Setup test server
	app := SetupApplication(s.db)
	s.server = httptest.NewServer(app.Router())
}

// TearDownSuite runs after all tests
func (s *IntegrationTestSuite) TearDownSuite() {
	if s.server != nil {
		s.server.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
	if s.postgres != nil {
		s.postgres.Terminate(context.Background())
	}
	if s.redis != nil {
		s.redis.Terminate(context.Background())
	}
}

// ====================
// USER MANAGEMENT INTEGRATION TESTS
// ====================

func (s *IntegrationTestSuite) TestUserRegistrationFlow() {
	ctx := context.Background()
	
	// Step 1: Register a new user
	registerReq := map[string]interface{}{
		"name":     "John Doe",
		"email":    "john@example.com",
		"password": "SecurePass123!",
	}
	
	resp, err := s.makeRequest(ctx, "POST", "/api/v1/users", registerReq)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), http.StatusCreated, resp.StatusCode)
	
	var user UserResponse
	s.decodeResponse(resp, &user)
	assert.NotZero(s.T(), user.ID)
	assert.Equal(s.T(), "john@example.com", user.Email)
	
	// Step 2: Verify user via email token
	token := s.getEmailToken(user.Email)
	verifyResp, err := s.makeRequest(ctx, "POST", "/api/v1/users/verify", map[string]string{
		"token": token,
	})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, verifyResp.StatusCode)
	
	// Step 3: Login with verified account
	loginResp, err := s.makeRequest(ctx, "POST", "/api/v1/auth/login", map[string]string{
		"email":    "john@example.com",
		"password": "SecurePass123!",
	})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, loginResp.StatusCode)
	
	var auth AuthResponse
	s.decodeResponse(loginResp, &auth)
	assert.NotEmpty(s.T(), auth.Token)
	s.assertValidJWT(auth.Token)
}

func (s *IntegrationTestSuite) TestCompleteOrderWorkflow() {
	ctx := context.Background()
	
	// Setup: Create and authenticate user
	user := s.createTestUser(ctx, "customer@example.com")
	token := s.getAuthToken(ctx, user.Email, "password123")
	
	// Step 1: Create order
	orderItems := []OrderItemRequest{
		{ProductID: 1, Quantity: 2},
		{ProductID: 2, Quantity: 1},
	}
	
	orderResp, err := s.makeAuthenticatedRequest(ctx, "POST", "/api/v1/orders", token, map[string]interface{}{
		"items": orderItems,
		"shipping_address": s.getTestAddress(),
	})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), http.StatusCreated, orderResp.StatusCode)
	
	var order OrderResponse
	s.decodeResponse(orderResp, &order)
	assert.Equal(s.T(), "pending", order.Status)
	assert.Len(s.T(), order.Items, 2)
	
	// Step 2: Process payment
	paymentResp, err := s.makeAuthenticatedRequest(ctx, "POST", "/api/v1/payments", token, map[string]interface{}{
		"order_id": order.ID,
		"amount":   order.TotalAmount,
		"method":   "credit_card",
		"token":    s.getTestPaymentToken(),
	})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, paymentResp.StatusCode)
	
	// Step 3: Verify order status updated
	getOrderResp, err := s.makeAuthenticatedRequest(ctx, "GET", "/api/v1/orders/"+order.ID, token, nil)
	require.NoError(s.T(), err)
	
	var updatedOrder OrderResponse
	s.decodeResponse(getOrderResp, &updatedOrder)
	assert.Equal(s.T(), "paid", updatedOrder.Status)
	assert.NotNil(s.T(), updatedOrder.PaidAt)
}

// ====================
// DATA PIPELINE INTEGRATION
// ====================

func (s *IntegrationTestSuite) TestETLPipeline() {
	ctx := context.Background()
	
	// Step 1: Ingest data from multiple sources
	dataSources := []DataSource{
		{Type: "api", URL: "http://example.com/api/data1"},
		{Type: "csv", Path: "test-data/input.csv"},
		{Type: "database", Query: "SELECT * FROM source_table"},
	}
	
	var ingestionIDs []string
	for _, source := range dataSources {
		ingestResp, err := s.makeRequest(ctx, "POST", "/api/v1/ingest", source)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), http.StatusAccepted, ingestResp.StatusCode)
		
		var job IngestionJob
		s.decodeResponse(ingestResp, &job)
		ingestionIDs = append(ingestionIDs, job.ID)
	}
	
	// Step 2: Wait for ingestion to complete
	s.waitForJobs(ctx, ingestionIDs, 2*time.Minute)
	
	// Step 3: Transform data
	transformResp, err := s.makeRequest(ctx, "POST", "/api/v1/transform", map[string]interface{}{
		"source_tables": ingestionIDs,
		"transformations": []string{
			"clean_missing_values",
			"normalize_dates",
			"calculate_derived_metrics",
		},
	})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, transformResp.StatusCode)
	
	// Step 4: Load to data warehouse
	loadResp, err := s.makeRequest(ctx, "POST", "/api/v1/load", map[string]interface{}{
		"destination": "data_warehouse",
		"table": "analytics.fact_table",
	})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, loadResp.StatusCode)
	
	// Step 5: Verify data in warehouse
	var count int
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM analytics.fact_table").Scan(&count)
	require.NoError(s.T(), err)
	assert.Greater(s.T(), count, 0)
}

// ====================
// CONCURRENT USER SIMULATION
// ====================

func (s *IntegrationTestSuite) TestConcurrentUsers() {
	ctx := context.Background()
	concurrentUsers := 50
	requestsPerUser := 10
	
	// Create multiple users
	users := make([]*User, concurrentUsers)
	for i := 0; i < concurrentUsers; i++ {
		users[i] = s.createTestUser(ctx, fmt.Sprintf("user%d@example.com", i))
	}
	
	// Simulate concurrent access
	var wg sync.WaitGroup
	errors := make(chan error, concurrentUsers*requestsPerUser)
	
	for i := 0; i < concurrentUsers; i++ {
		wg.Add(1)
		go func(userIndex int) {
			defer wg.Done()
			
			token := s.getAuthToken(ctx, users[userIndex].Email, "password123")
			
			for j := 0; j < requestsPerUser; j++ {
				// Make concurrent requests
				resp, err := s.makeAuthenticatedRequest(ctx, "GET", "/api/v1/users/profile", token, nil)
				if err != nil {
					errors <- err
					continue
				}
				
				if resp.StatusCode != http.StatusOK {
					errors <- fmt.Errorf("unexpected status: %d", resp.StatusCode)
				}
				
				// Verify rate limiting not triggered
				assert.Equal(s.T(), "100", resp.Header.Get("X-RateLimit-Remaining"))
			}
		}(i)
	}
	
	wg.Wait()
	close(errors)
	
	// Verify no errors occurred
	var errorCount int
	for err := range errors {
		s.T().Logf("Error: %v", err)
		errorCount++
	}
	assert.Equal(s.T(), 0, errorCount, "Expected no errors during concurrent access")
}

// ====================
// EXTERNAL SERVICE INTEGRATION
// ====================

func (s *IntegrationTestSuite) TestExternalServiceIntegration() {
	ctx := context.Background()
	
	// Mock external payment service
	paymentService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(s.T(), "/process", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":    "approved",
			"transaction_id": "txn_12345",
		})
	}))
	defer paymentService.Close()
	
	// Test payment flow with external service
	order := s.createTestOrder(ctx)
	
	paymentReq := PaymentRequest{
		OrderID: order.ID,
		Amount:  order.Total,
		PaymentServiceURL: paymentService.URL,
	}
	
	resp, err := s.makeRequest(ctx, "POST", "/api/v1/payments/external", paymentReq)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
	
	// Verify payment recorded
	var payment PaymentRecord
	err = s.db.QueryRowContext(ctx, 
		"SELECT transaction_id, status FROM payments WHERE order_id = $1",
		order.ID).Scan(&payment.TransactionID, &payment.Status)
	require.NoError(s.T(), err)
	assert.Equal(s.T(), "txn_12345", payment.TransactionID)
	assert.Equal(s.T(), "completed", payment.Status)
}

// ====================
// HELPER METHODS
// ====================

func (s *IntegrationTestSuite) makeRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(jsonBody)
	}
	
	req, err := http.NewRequestWithContext(ctx, method, s.server.URL+path, bodyReader)
	require.NoError(s.T(), err)
	req.Header.Set("Content-Type", "application/json")
	
	return http.DefaultClient.Do(req)
}

func (s *IntegrationTestSuite) makeAuthenticatedRequest(ctx context.Context, method, path, token string, body interface{}) (*http.Response, error) {
	resp, err := s.makeRequest(ctx, method, path, body)
	require.NoError(s.T(), err)
	resp.Header.Set("Authorization", "Bearer "+token)
	return resp, nil
}

func (s *IntegrationTestSuite) decodeResponse(resp *http.Response, v interface{}) {
	err := json.NewDecoder(resp.Body).Decode(v)
	require.NoError(s.T(), err)
}

func (s *IntegrationTestSuite) waitForJobs(ctx context.Context, jobIDs []string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	for _, jobID := range jobIDs {
		for {
			select {
			case <-ctx.Done():
				s.T().Fatalf("Timeout waiting for job %s", jobID)
			default:
				var status JobStatus
				err := s.db.QueryRowContext(ctx, "SELECT status FROM jobs WHERE id = $1", jobID).Scan(&status)
				require.NoError(s.T(), err)
				
				if status == "completed" || status == "failed" {
					if status == "failed" {
						s.T().Fatalf("Job %s failed", jobID)
					}
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// ====================
// RUN SUITE
// ====================

func TestIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	suite.Run(t, new(IntegrationTestSuite))
}
