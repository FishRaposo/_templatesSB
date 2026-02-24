# Go System Testing Template
# End-to-end system testing patterns for Go projects

package system

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
	
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// ====================
// SYSTEM TEST SUITE
// ====================

// SystemTestSuite tests the complete system end-to-end
type SystemTestSuite struct {
	suite.Suite
	baseURL      string
	adminToken   string
	userToken    string
	config       SystemConfig
}

// SystemConfig holds system-wide test configuration
type SystemConfig struct {
	BaseURL        string
	AdminEmail     string
	AdminPassword  string
	TestUserEmail  string
	TestUserPassword string
	Environment    string
	Timeout        time.Duration
}

// ====================
// SUITE SETUP
// ====================

func (s *SystemTestSuite) SetupSuite() {
	// Load configuration from environment
	s.config = SystemConfig{
		BaseURL:         getEnv("SYSTEM_TEST_URL", "http://localhost:8080"),
		AdminEmail:      getEnv("ADMIN_EMAIL", "admin@example.com"),
		AdminPassword:   getEnv("ADMIN_PASSWORD", "admin123"),
		TestUserEmail:   getEnv("TEST_USER_EMAIL", "testuser@example.com"),
		TestUserPassword: getEnv("TEST_USER_PASSWORD", "testpass123"),
		Environment:     getEnv("ENVIRONMENT", "test"),
		Timeout:         30 * time.Second,
	}
	
	s.baseURL = s.config.BaseURL
	
	// Wait for system to be ready
	s.waitForSystemReady()
	
	// Authenticate admin user
	s.adminToken = s.authenticate(s.config.AdminEmail, s.config.AdminPassword)
	
	// Create and authenticate test user
	s.createTestUser()
	s.userToken = s.authenticate(s.config.TestUserEmail, s.config.TestUserPassword)
}

// ====================
// SYSTEM HEALTH CHECKS
// ====================

func (s *SystemTestSuite) TestSystemHealth() {
	// Test API health endpoint
	resp, err := http.Get(s.baseURL + "/health")
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	
	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
	
	var health map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&health)
	assert.Equal(s.T(), "healthy", health["status"])
	
	// Verify all dependencies are healthy
	deps := health["dependencies"].(map[string]interface{})
	assert.Equal(s.T(), "healthy", deps["database"])
	assert.Equal(s.T(), "healthy", deps["redis"])
	assert.Equal(s.T(), "healthy", deps["external_api"])
}

func (s *SystemTestSuite) TestAllServiceEndpoints() {
	endpoints := []struct {
		method string
		path   string
		status int
	}{
		{"GET", "/api/v1/users/profile", http.StatusOK},
		{"GET", "/api/v1/health", http.StatusOK},
		{"GET", "/api/v1/metrics", http.StatusOK},
		{"GET", "/api/v1/config", http.StatusOK},
	}
	
	for _, endpoint := range endpoints {
		s.T().Run(fmt.Sprintf("%s %s", endpoint.method, endpoint.path), func(t *testing.T) {
			req, _ := http.NewRequest(endpoint.method, s.baseURL+endpoint.path, nil)
			req.Header.Set("Authorization", "Bearer "+s.adminToken)
			
			client := &http.Client{Timeout: s.config.Timeout}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			
			assert.Equal(t, endpoint.status, resp.StatusCode)
		})
	}
}

// ====================
// END-TO-END BUSINESS FLOWS
// ====================

func (s *SystemTestSuite) TestCompleteECommerceFlow() {
	// This test covers the entire e-commerce flow from start to finish
	
	// Step 1: User registration
	user := s.registerUser("customer@example.com", "Customer", "Pass123!")
	assert.NotNil(s.T(), user)
	
	userToken := s.authenticate("customer@example.com", "Pass123!")
	assert.NotEmpty(s.T(), userToken)
	
	// Step 2: Browse products
	products := s.getProducts(userToken)
	assert.Greater(s.T(), len(products), 0)
	
	// Step 3: Add items to cart
	cart := s.addToCart(userToken, []CartItem{
		{ProductID: products[0].ID, Quantity: 2},
		{ProductID: products[1].ID, Quantity: 1},
	})
	assert.Len(s.T(), cart.Items, 2)
	assert.Greater(s.T(), cart.Total, 0.0)
	
	// Step 4: Checkout
	order := s.checkout(userToken, map[string]interface{}{
		"cart_id":          cart.ID,
		"shipping_address": s.getTestAddress(),
		"payment_method":   "credit_card",
	})
	assert.NotNil(s.T(), order)
	assert.Equal(s.T(), "pending", order.Status)
	
	// Step 5: Process payment
	payment := s.processPayment(order.ID, order.Total, userToken)
	assert.Equal(s.T(), "completed", payment.Status)
	assert.NotEmpty(s.T(), payment.TransactionID)
	
	// Step 6: Verify order updates
	updatedOrder := s.getOrder(order.ID, userToken)
	assert.Equal(s.T(), "paid", updatedOrder.Status)
	assert.NotNil(s.T(), updatedOrder.PaidAt)
	
	// Step 7: Check inventory updates
	product := s.getProduct(products[0].ID, userToken)
	assert.Equal(s.T(), products[0].Stock-2, product.Stock)
	
	// Step 8: Verify emails sent
	emails := s.getSentEmails()
	assert.Greater(s.T(), len(emails), 0)
	assert.Contains(s.T(), emails[len(emails)-1].Subject, "Order Confirmation")
}

func (s *SystemTestSuite) TestDataAnalyticsPipeline() {
	// Test complete data pipeline from ingestion to visualization
	
	// Step 1: Ingest multiple data sources
	sources := []DataSource{
		{Type: "api", URL: "https://api1.example.com/data", Format: "json"},
		{Type: "csv", Path: "s3://bucket/data.csv"},
		{Type: "database", Connection: "postgres://user:pass@host/db", Query: "SELECT * FROM events"},
	}
	
	ingestionJobs := make([]string, len(sources))
	for i, source := range sources {
		jobID := s.startIngestion(source, s.adminToken)
		ingestionJobs[i] = jobID
	}
	
	// Step 2: Wait for all ingestion to complete
	s.waitForJobs(ingestionJobs, 5*time.Minute)
	
	// Step 3: Transform data
	transformJob := s.startTransformation(map[string]interface{}{
		"source_jobs": ingestionJobs,
		"operations": []string{
			"clean_missing_values",
			"standardize_dates",
			"enrich_user_data",
			"calculate_metrics",
		},
	}, s.adminToken)
	
	s.waitForJobs([]string{transformJob}, 10*time.Minute)
	
	// Step 4: Load to data warehouse
	loadJob := s.startLoad("data_warehouse", "analytics.fact_events", s.adminToken)
	s.waitForJobs([]string{loadJob}, 5*time.Minute)
	
	// Step 5: Generate report
	report := s.generateReport(map[string]interface{}{
		"type":     "daily_active_users",
		"date_range": map[string]string{
			"start": time.Now().AddDate(0, 0, -7).Format(time.RFC3339),
			"end":   time.Now().Format(time.RFC3339),
		},
	}, s.adminToken)
	
	assert.NotNil(s.T(), report)
	assert.Greater(s.T(), len(report.Data), 0)
	assert.NotEmpty(s.T(), report.Visualizations)
}

// ====================
// PERFORMANCE AND LOAD TESTING
// ====================

func (s *SystemTestSuite) TestSystemUnderLoad() {
	concurrentUsers := 100
	requestsPerUser := 50
	
	// Track metrics
	var totalRequests int
	var failedRequests int
	var totalResponseTime time.Duration
	
	// Create wait group for concurrent execution
	var wg sync.WaitGroup
	requestChan := make(chan time.Duration, concurrentUsers*requestsPerUser)
	
	// Launch concurrent users
	for i := 0; i < concurrentUsers; i++ {
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()
			
			// Authenticate as different user
			email := fmt.Sprintf("loadtest%d@example.com", userID)
			token := s.authenticate(email, "password123")
			
			// Make multiple requests
			for j := 0; j < requestsPerUser; j++ {
				start := time.Now()
				
				// Mix of different endpoints
				endpoints := []string{
					"/api/v1/users/profile",
					"/api/v1/products",
					"/api/v1/orders",
					"/api/v1/notifications",
				}
				
				randomEndpoint := endpoints[j%len(endpoints)]
				req, _ := http.NewRequest("GET", s.baseURL+randomEndpoint, nil)
				req.Header.Set("Authorization", "Bearer "+token)
				
				client := &http.Client{Timeout: 10 * time.Second}
				resp, err := client.Do(req)
				
				responseTime := time.Since(start)
				requestChan <- responseTime
				
				if err != nil || resp.StatusCode != http.StatusOK {
					failedRequests++
				} else {
					totalResponseTime += responseTime
				}
				totalRequests++
				
				if resp != nil {
					resp.Body.Close()
				}
			}
		}(i)
	}
	
	// Wait for all users to complete
	wg.Wait()
	close(requestChan)
	
	// Calculate statistics
	var responseTimes []time.Duration
	for rt := range requestChan {
		responseTimes = append(responseTimes, rt)
	}
	
	assert.Less(s.T(), failedRequests, totalRequests*5/100, "Failure rate should be less than 5%")
	
	if len(responseTimes) > 0 {
		avgResponseTime := totalResponseTime / time.Duration(len(responseTimes))
		assert.Less(s.T(), avgResponseTime, 1*time.Second, "Average response time should be less than 1 second")
		
		// Check p95 and p99
		sort.Slice(responseTimes, func(i, j int) bool {
			return responseTimes[i] < responseTimes[j]
		})
		
		p95Index := int(0.95 * float64(len(responseTimes)))
		p99Index := int(0.99 * float64(len(responseTimes)))
		
		assert.Less(s.T(), responseTimes[p95Index], 2*time.Second, "95th percentile should be less than 2 seconds")
		assert.Less(s.T(), responseTimes[p99Index], 5*time.Second, "99th percentile should be less than 5 seconds")
	}
}

// ====================
// DISASTER RECOVERY TESTING
// ====================

func (s *SystemTestSuite) TestSystemRecovery() {
	// Step 1: Start with a working system
	s.TestSystemHealth()
	
	// Step 2: Simulate database failure
	dbURL := s.getDatabaseURL()
	s.simulateDatabaseFailure()
	
	// Step 3: Verify graceful degradation
	resp, err := http.Get(s.baseURL + "/api/v1/users/profile")
	require.NoError(s.T(), err)
	assert.Equal(s.T(), http.StatusServiceUnavailable, resp.StatusCode)
	
	// Step 4: Restore database
	s.restoreDatabase(dbURL)
	
	// Step 5: Verify system recovers
	s.waitForSystemReady()
	s.TestSystemHealth()
}

// ====================
// SECURITY TESTING
// ====================

func (s *SystemTestSuite) TestSecurityVulnerabilities() {
	// Test SQL injection attempts
	maliciousInputs := []string{
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"<script>alert('xss')</script>",
	}
	
	for _, input := range maliciousInputs {
		// Test search endpoint
		searchURL := fmt.Sprintf("%s/api/v1/search?q=%s", s.baseURL, url.QueryEscape(input))
		resp, err := http.Get(searchURL)
		require.NoError(s.T(), err)
		assert.NotEqual(s.T(), http.StatusInternalServerError, resp.StatusCode)
		resp.Body.Close()
	}
	
	// Test authentication bypass attempts
	authAttempts := []map[string]string{
		{"email": "admin@example.com", "password": "' OR '1'='1"},
		{"email": "' OR '1'='1' --", "password": "password"},
	}
	
	for _, attempt := range authAttempts {
		token := s.authenticate(attempt["email"], attempt["password"])
		assert.Empty(s.T(), token)
	}
	
	// Test rate limiting
	for i := 0; i < 150; i++ {
		req, _ := http.NewRequest("POST", s.baseURL+"/api/v1/auth/login", nil)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, _ := client.Do(req)
		if resp != nil {
			if i > 100 {
				assert.Equal(s.T(), http.StatusTooManyRequests, resp.StatusCode)
			}
			resp.Body.Close()
		}
	}
}

// ====================
// DATA INTEGRITY TESTS
// ====================

func (s *SystemTestSuite) TestDataConsistency() {
	// Create test data
	user := s.registerUser("consistency@example.com", "Test User", "Test123!")
	
	// Perform multiple operations
	for i := 0; i < 10; i++ {
		s.updateUserProfile(user.ID, map[string]interface{}{
			"bio": fmt.Sprintf("Bio version %d", i),
		}, s.adminToken)
	}
	
	// Verify final state
	finalUser := s.getUser(user.ID, s.adminToken)
	assert.Equal(s.T(), "Bio version 9", finalUser.Bio)
	
	// Verify audit trail
	auditLogs := s.getAuditLogs(user.ID, "users")
	assert.Greater(s.T(), len(auditLogs), 9)
}

// ====================
// COMPLIANCE TESTING
// ====================

func (s *SystemTestSuite) TestGDPRCompliance() {
	// Create user with data
	user := s.registerUser("gdpr@example.com", "GDPR Test", "GDPR123!")
	token := s.authenticate("gdpr@example.com", "GDPR123!")
	
	// Add various user data
	s.createUserActivity(user.ID, token)
	s.createOrders(user.ID, token)
	s.createMessages(user.ID, token)
	
	// Export user data (GDPR Right to Access)
	export := s.exportUserData(user.ID, token)
	assert.NotNil(s.T(), export)
	assert.Contains(s.T(), export, "personal_info")
	assert.Contains(s.T(), export, "activity_logs")
	assert.Contains(s.T(), export, "orders")
	assert.Contains(s.T(), export, "messages")
	
	// Test data deletion (GDPR Right to Erasure)
	s.deleteUserAccount(user.ID, token)
	
	// Verify user data is anonymized/deleted
	deletedUser := s.getUser(user.ID, s.adminToken)
	assert.Equal(s.T(), "[DELETED]", deletedUser.Email)
	assert.Equal(s.T(), "[DELETED]", deletedUser.Name)
}

// ====================
// TEST UTILITY METHODS
// ====================

func (s *SystemTestSuite) waitForSystemReady() {
	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		resp, err := http.Get(s.baseURL + "/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(5 * time.Second)
	}
	s.T().Fatal("System did not become ready in time")
}

func (s *SystemTestSuite) authenticate(email, password string) string {
	resp, err := http.Post(s.baseURL+"/api/v1/auth/login", 
		"application/json",
		bytes.NewReader(json.Marshal(map[string]string{
			"email":    email,
			"password": password,
		})))
	require.NoError(s.T(), err)
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	
	var auth map[string]string
	json.NewDecoder(resp.Body).Decode(&auth)
	return auth["token"]
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ====================
// RUN SUITE
// ====================

func TestSystemSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping system tests in short mode")
	}
	
	if os.Getenv("RUN_SYSTEM_TESTS") != "true" {
		t.Skip("Set RUN_SYSTEM_TESTS=true to run system tests")
	}
	
	suite.Run(t, new(SystemTestSuite))
}
