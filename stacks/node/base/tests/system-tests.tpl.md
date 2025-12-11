# Node.js System Tests Template
// Node.js System Testing Template
// End-to-end system testing patterns for Node.js projects

/**
 * Node.js System Test Patterns
 * Complete E2E testing with business workflows, load testing, security, compliance
 */

const { describe, it, expect, beforeAll, afterAll } = require('@jest/globals');
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs').promises;

// ====================
// SYSTEM TEST CONFIGURATION
// ====================

class SystemTestConfig {
  constructor() {
    this.baseURL = process.env.SYSTEM_TEST_URL || 'http://localhost:3000';
    this.adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
    this.adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    this.testUserEmail = process.env.TEST_USER_EMAIL || 'testuser@example.com';
    this.testUserPassword = process.env.TEST_USER_PASSWORD || 'testpass123';
    this.environment = process.env.ENVIRONMENT || 'test';
    this.timeout = 30000; // 30 seconds
  }
}

class SystemTestHelper {
  constructor(config) {
    this.config = config;
    this.tokens = new Map();
    this.client = axios.create({
      baseURL: config.baseURL,
      timeout: config.timeout
    });
  }
  
  async authenticate(email, password) {
    if (this.tokens.has(email)) {
      return this.tokens.get(email);
    }
    
    const response = await this.client.post('/api/v1/auth/login', {
      email,
      password
    });
    
    const token = response.data.accessToken;
    this.tokens.set(email, token);
    return token;
  }
  
  getHeaders(token = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
  }
  
  async waitForSystemReady(maxAttempts = 30) {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const response = await this.client.get('/health');
        if (response.data.status === 'healthy') {
          return true;
        }
      } catch (error) {
        console.log(`System not ready yet, attempt ${attempt + 1}/${maxAttempts}`);
      }
      await this.sleep(5000);
    }
    throw new Error('System did not become ready in time');
  }
  
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ====================
// SYSTEM HEALTH TESTS
// ====================

describe('System Health Checks', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.waitForSystemReady();
  }, 150000); // 2.5 minute timeout
  
  it('should return healthy status from health endpoint', async () => {
    const response = await helper.client.get('/health');
    
    expect(response.status).toBe(200);
    expect(response.data.status).toBe('healthy');
    
    // Verify all dependencies are healthy
    expect(response.data.dependencies.database).toBe('healthy');
    expect(response.data.dependencies.redis).toBe('healthy');
  });
  
  it('should expose metrics endpoint', async () => {
    const response = await helper.client.get('/metrics');
    
    expect(response.status).toBe(200);
    expect(response.data).toContain('process_cpu_seconds_total');
  });
  
  it('should have all critical service endpoints accessible', async () => {
    const endpoints = [
      { method: 'GET', path: '/api/v1/health' },
      { method: 'GET', path: '/api/v1/config' },
      { method: 'GET', path: '/api/v1/metrics' },
    ];
    
    for (const endpoint of endpoints) {
      const response = await helper.client({
        method: endpoint.method,
        url: endpoint.path
      });
      expect(response.status).toBe(200);
    }
  });
});

// ====================
// END-TO-END BUSINESS FLOW TESTS
// ====================

describe('End-to-End Business Flows', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.waitForSystemReady();
  }, 150000);
  
  it('should complete full e-commerce user journey', async () => {
    // Step 1: User registration
    const newUser = {
      name: 'Journey Test User',
      email: 'journey@test.com',
      password: 'SecurePass123!',
      passwordConfirm: 'SecurePass123!'
    };
    
    const registerResponse = await helper.client.post(
      '/api/v1/users/register',
      newUser,
      { headers: helper.getHeaders() }
    );
    
    expect(registerResponse.status).toBe(201);
    const user = registerResponse.data;
    
    // Step 2: Email verification (simulate in test environment)
    // In production, this would involve clicking email link
    
    // Step 3: Login
    const token = await helper.authenticate('journey@test.com', 'SecurePass123!');
    expect(token).toBeDefined();
    
    // Step 4: Create shipping address
    const addressData = {
      street: '123 Shopping St',
      city: 'Commerce City',
      state: 'CA',
      zip: '90210',
      country: 'USA',
      isDefault: true
    };
    
    const addressResponse = await helper.client.post(
      '/api/v1/addresses',
      addressData,
      { headers: helper.getHeaders(token) }
    );
    
    expect(addressResponse.status).toBe(201);
    const address = addressResponse.data;
    
    // Step 5: Browse products
    const productsResponse = await helper.client.get(
      '/api/v1/products',
      { headers: helper.getHeaders(token) }
    );
    
    expect(productsResponse.status).toBe(200);
    const products = productsResponse.data;
    expect(products.length).toBeGreaterThan(0);
    
    // Step 6: Add to cart
    const cartData = {
      items: [
        { productId: products[0].id, quantity: 2 },
        { productId: products[1].id, quantity: 1 }
      ]
    };
    
    const cartResponse = await helper.client.post(
      '/api/v1/cart',
      cartData,
      { headers: helper.getHeaders(token) }
    );
    
    expect(cartResponse.status).toBe(201);
    const cart = cartResponse.data;
    expect(cart.items.length).toBe(2);
    
    // Step 7: Checkout
    const checkoutData = {
      cartId: cart.id,
      shippingAddressId: address.id,
      billingAddressId: address.id
    };
    
    const orderResponse = await helper.client.post(
      '/api/v1/orders',
      checkoutData,
      { headers: helper.getHeaders(token) }
    );
    
    expect(orderResponse.status).toBe(201);
    const order = orderResponse.data;
    expect(order.status).toBe('pending');
    
    // Step 8: Process payment
    const paymentData = {
      orderId: order.id,
      amount: order.total,
      method: 'stripe',
      token: 'tok_visa_test'
    };
    
    const paymentResponse = await helper.client.post(
      '/api/v1/payments',
      paymentData,
      { headers: helper.getHeaders(token) }
    );
    
    expect(paymentResponse.status).toBe(200);
    const payment = paymentResponse.data;
    expect(payment.status).toBe('completed');
    expect(payment.orderId).toBe(order.id);
    
    // Wait for async processing
    await helper.sleep(2000);
    
    // Step 9: Verify order status updated
    const updatedOrderResponse = await helper.client.get(
      `/api/v1/orders/${order.id}`,
      { headers: helper.getHeaders(token) }
    );
    
    expect(updatedOrderResponse.status).toBe(200);
    const updatedOrder = updatedOrderResponse.data;
    expect(updatedOrder.status).toBe('paid');
    expect(updatedOrder.paidAt).toBeDefined();
    
    // Step 10: Check order in user history
    const ordersResponse = await helper.client.get(
      `/api/v1/users/${user.id}/orders`,
      { headers: helper.getHeaders(token) }
    );
    
    expect(ordersResponse.status).toBe(200);
    const orders = ordersResponse.data;
    expect(orders.some(o => o.id === order.id)).toBe(true);
    
    // Step 11: Download digital receipt
    const receiptResponse = await helper.client.get(
      `/api/v1/orders/${order.id}/receipt`,
      { headers: helper.getHeaders(token) }
    );
    
    expect(receiptResponse.status).toBe(200);
    expect(receiptResponse.headers['content-type']).toContain('application/pdf');
  });
  
  it('should complete full data analytics pipeline', async () => {
    const adminToken = await helper.authenticate(config.adminEmail, config.adminPassword);
    
    // Step 1: Ingest from multiple sources
    const sources = [
      {
        type: 'api',
        url: 'https://api.example.com/user_events',
        format: 'json'
      },
      {
        type: 'csv',
        bucket: 'data-bucket',
        path: 'events/daily.csv'
      }
    ];
    
    const ingestionJobs = [];
    for (const source of sources) {
      const response = await helper.client.post(
        '/api/v1/ingest',
        source,
        { headers: helper.getHeaders(adminToken) }
      );
      expect(response.status).toBe(202);
      ingestionJobs.push(response.data.id);
    }
    
    // Step 2: Wait for ingestion
    await helper.sleep(5000);
    
    // Step 3: Transform data
    const transformConfig = {
      sourceJobs: ingestionJobs,
      transformations: [
        { type: 'clean_missing_values' },
        { type: 'normalize_timestamps' },
        { type: 'calculate_metrics' }
      ]
    };
    
    const transformResponse = await helper.client.post(
      '/api/v1/transform',
      transformConfig,
      { headers: helper.getHeaders(adminToken) }
    );
    expect(transformResponse.status).toBe(202);
    
    // Step 4: Load to warehouse
    const loadConfig = {
      destination: 'warehouse',
      table: 'analytics.fact_events'
    };
    
    const loadResponse = await helper.client.post(
      '/api/v1/load',
      loadConfig,
      { headers: helper.getHeaders(adminToken) }
    );
    expect(loadResponse.status).toBe(202);
    
    // Step 5: Generate report
    const reportConfig = {
      type: 'daily_kpis',
      dateRange: {
        start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
        end: new Date().toISOString()
      },
      metrics: ['daily_active_users', 'revenue', 'conversion_rate']
    };
    
    const reportResponse = await helper.client.post(
      '/api/v1/reports',
      reportConfig,
      { headers: helper.getHeaders(adminToken) }
    );
    
    expect(reportResponse.status).toBe(200);
    const report = reportResponse.data;
    expect(report.status).toBe('completed');
    expect(report.data).toBeDefined();
    expect(report.visualizations).toBeDefined();
  });
});

// ====================
// PERFORMANCE AND LOAD TESTS
// ====================

describe('Performance and Load Tests', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.waitForSystemReady();
  }, 150000);
  
  it('should handle system under concurrent load', async () => {
    const concurrentUsers = 100;
    const requestsPerUser = 50;
    
    // Create test users
    const users = [];
    for (let i = 0; i < concurrentUsers; i++) {
      const userData = {
        name: `Load Test User ${i}`,
        email: `loadtest${i}@perf.com`,
        password: 'LoadTest123!'
      };
      
      try {
        await helper.client.post('/api/v1/users/register', userData);
        users.push(`loadtest${i}@perf.com`);
      } catch (error) {
        // User might already exist
        users.push(`loadtest${i}@perf.com`);
      }
    }
    
    // Authenticate users
    const tokens = [];
    for (const email of users) {
      const token = await helper.authenticate(email, 'LoadTest123!');
      if (token) tokens.push(token);
    }
    
    // Concurrent access
    const results = { success: 0, failed: 0, totalTime: 0 };
    
    const makeRequests = async (tokenIndex) => {
      const token = tokens[tokenIndex];
      const localResults = { success: 0, failed: 0, totalTime: 0 };
      
      for (let i = 0; i < requestsPerUser; i++) {
        const startTime = Date.now();
        
        try {
          // Mix of endpoints
          const endpoints = [
            '/api/v1/users/profile',
            '/api/v1/products',
            '/api/v1/health'
          ];
          const endpoint = endpoints[i % endpoints.length];
          
          const response = await helper.client.get(endpoint, {
            headers: helper.getHeaders(token)
          });
          
          if (response.status === 200) {
            localResults.success++;
          } else {
            localResults.failed++;
          }
        } catch (error) {
          localResults.failed++;
        }
        
        localResults.totalTime += (Date.now() - startTime);
      }
      
      return localResults;
    };
    
    // Execute concurrent requests
    const allResults = await Promise.all(
      tokens.map((_, index) => makeRequests(index))
    );
    
    // Aggregate results
    allResults.forEach(r => {
      results.success += r.success;
      results.failed += r.failed;
      results.totalTime += r.totalTime;
    });
    
    // Calculate statistics
    const totalRequests = tokens.length * requestsPerUser;
    const successRate = results.success / totalRequests;
    const avgResponseTime = results.totalTime / totalRequests;
    
    expect(successRate).toBeGreaterThan(0.95); // 95% success rate
    expect(avgResponseTime).toBeLessThan(1000); // <1s average response
    
    // Calculate percentiles
    const responseTimes = [];
    // In real test, collect individual response times
    // and calculate p95, p99
    
    console.log(`Load Test Results: ${successRate.toFixed(2)}% success rate, ${avgResponseTime.toFixed(0)}ms avg response`);
  }, 300000); // 5 minute timeout
  
  it('should maintain performance over extended period', async () => {
    const testDuration = 5 * 60 * 1000; // 5 minutes
    const requestInterval = 100; // 100ms between requests
    const startTime = Date.now();
    let requestCount = 0;
    let errorCount = 0;
    
    const token = await helper.authenticate(config.testUserEmail, config.testUserPassword);
    
    while (Date.now() - startTime < testDuration) {
      try {
        const response = await helper.client.get('/api/v1/users/profile', {
          headers: helper.getHeaders(token)
        });
        
        if (response.status === 200) {
          requestCount++;
        } else {
          errorCount++;
        }
      } catch (error) {
        errorCount++;
      }
      
      await helper.sleep(requestInterval);
    }
    
    const elapsedTime = Date.now() - startTime;
    const requestsPerSecond = requestCount / (elapsedTime / 1000);
    const errorRate = errorCount / (requestCount + errorCount);
    
    expect(errorRate).toBeLessThan(0.01); // <1% error rate
    expect(requestsPerSecond).toBeGreaterThan(5); // Maintain >5 req/s
    
    console.log(`Sustained Load Test: ${requestsPerSecond.toFixed(2)} req/s over ${elapsedTime/1000}s with ${(errorRate*100).toFixed(2)}% errors`);
  }, 360000); // 6 minute timeout
});

// ====================
// DISASTER RECOVERY TESTS
// ====================

describe('Disaster Recovery Tests', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.waitForSystemReady();
  }, 150000);
  
  it('should recover gracefully from database connection loss', async () => {
    // Step 1: Verify system is healthy
    let healthResponse = await helper.client.get('/health');
    expect(healthResponse.data.status).toBe('healthy');
    
    // Step 2: Simulate database failure
    // In real test, would stop database container or block connections
    
    // Step 3: Verify graceful degradation
    try {
      const response = await helper.client.get('/api/v1/users/profile', {
        headers: helper.getHeaders(await helper.authenticate(config.testUserEmail, config.testUserPassword))
      });
      
      // Should return 503 Service Unavailable, not crash
      expect([503, 500]).toContain(response.status);
    } catch (error) {
      // Expected if service is completely down
      expect(error.response).toBeDefined();
    }
    
    // Step 4: Restore database
    // In real test, would restart database container
    await helper.sleep(5000);
    
    // Step 5: Verify system recovers
    healthResponse = await helper.client.get('/health');
    expect(healthResponse.data.status).toBe('healthy');
    
    // Verify normal operations
    const profileResponse = await helper.client.get('/api/v1/users/profile', {
      headers: helper.getHeaders(await helper.authenticate(config.testUserEmail, config.testUserPassword))
    });
    expect(profileResponse.status).toBe(200);
  });
});

// ====================
// SECURITY TESTS
// ====================

describe('Security Tests', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.waitForSystemReady();
  }, 150000);
  
  it('should protect against SQL injection attempts', async () => {
    const maliciousInputs = [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "admin'--",
      "1' OR 1=1--"
    ];
    
    for (const injection of maliciousInputs) {
      const response = await helper.client.get('/api/v1/search', {
        params: { q: injection },
        validateStatus: () => true // Don't throw on any status
      });
      
      // Should not return 500 (server error)
      expect(response.status).not.toBe(500);
      // Should not return DB error messages
      if (response.data.error) {
        expect(response.data.error).not.toMatch(/SQL|database|table/i);
      }
    }
  });
  
  it('should enforce rate limiting', async () => {
    // Make many rapid requests
    const requests = [];
    for (let i = 0; i < 150; i++) {
      requests.push(
        helper.client.post('/api/v1/auth/login', {
          email: `test${i}@example.com`,
          password: 'wrongpassword'
        }, {
          validateStatus: () => true
        })
      );
    }
    
    const responses = await Promise.all(requests);
    
    // Should eventually get rate limited
    const rateLimitedResponses = responses.filter(r => r.status === 429);
    expect(rateLimitedResponses.length).toBeGreaterThan(0);
    
    // Check for rate limit headers
    const rateLimitedResponse = rateLimitedResponses[0];
    expect(rateLimitedResponse.headers['x-ratelimit-limit']).toBeDefined();
    expect(rateLimitedResponse.headers['retry-after']).toBeDefined();
  });
  
  it('should block common authentication bypass attempts', async () => {
    const bypassAttempts = [
      { email: "admin' --", password: 'password' },
      { email: 'admin@example.com', password: "' OR '1'='1" },
      { email: 'admin@example.com', password: 'admin' --' },
    ];
    
    for (const attempt of bypassAttempts) {
      const response = await helper.client.post('/api/v1/auth/login', attempt, {
        validateStatus: () => true
      });
      
      // Should not authenticate
      expect(response.status).toBe(401);
      expect(response.data.accessToken).toBeUndefined();
    }
  });
  
  it('should validate JWT token properly', async () => {
    // Test with malformed token
    const malformedResponse = await helper.client.get('/api/v1/users/profile', {
      headers: { 'Authorization': 'Bearer malformed.token.here' }
    }).catch(error => error.response);
    
    expect(malformedResponse.status).toBe(401);
    
    // Test with expired token (if possible to generate)
    const expiredResponse = await helper.client.get('/api/v1/users/profile', {
      headers: { 'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.4Adcj3UFYzPUVaVF43FmMab6RlaQD8A9V8wFzzht-KQ' }
    }).catch(error => error.response);
    
    expect(expiredResponse.status).toBe(401);
  });
});

// ====================
// COMPLIANCE TESTS
// ====================

describe('Compliance Tests', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.waitForSystemReady();
  }, 150000);
  
  it('should support GDPR data export', async () => {
    const userToken = await helper.authenticate(config.testUserEmail, config.testUserPassword);
    
    // Create some user data
    await helper.client.put(
      '/api/v1/users/profile',
      { bio: 'Test bio', preferences: { newsletter: true } },
      { headers: helper.getHeaders(userToken) }
    );
    
    // Request data export
    const exportResponse = await helper.client.get(
      '/api/v1/users/export',
      { headers: helper.getHeaders(userToken) }
    );
    
    expect(exportResponse.status).toBe(200);
    
    const exportData = exportResponse.data;
    expect(exportData.personalInfo).toBeDefined();
    expect(exportData.activityLogs).toBeDefined();
    expect(exportData.orders).toBeDefined();
    expect(exportData.preferences).toBeDefined();
    
    // Verify structure matches GDPR requirements
    expect(exportData.format).toBe('machine_readable');
    expect(exportData.exportDate).toBeDefined();
  });
  
  it('should support GDPR data deletion (right to erasure)', async () => {
    // Create a test user
    const tempUser = {
      name: 'GDPR Test User',
      email: 'gdprtest@test.com',
      password: 'TempPass123!'
    };
    
    const registerResponse = await helper.client.post(
      '/api/v1/users/register',
      tempUser,
      { headers: helper.getHeaders() }
    );
    
    const userId = registerResponse.data.id;
    
    // Verify user
    await helper.client.post(
      `/api/v1/admin/verify-user/${userId}`,
      {},
      { headers: helper.getHeaders(await helper.authenticate(config.adminEmail, config.adminPassword)) }
    );
    
    // Login as user
    const token = await helper.authenticate(tempUser.email, tempUser.password);
    
    // Create some activity
    await helper.client.get('/api/v1/users/profile', {
      headers: helper.getHeaders(token)
    });
    
    // Delete account
    const deleteResponse = await helper.client.delete(
      `/api/v1/users/${userId}`,
      { headers: helper.getHeaders(token) }
    );
    
    expect(deleteResponse.status).toBe(204);
    
    // Verify data is anonymized/deleted
    const getResponse = await helper.client.get(
      `/api/v1/users/${userId}`,
      { headers: helper.getHeaders(await helper.authenticate(config.adminEmail, config.adminPassword)) }
    );
    
    expect(getResponse.status).toBe(200);
    expect(getResponse.data.email).toContain('[DELETED]');
    expect(getResponse.data.name).toContain('[DELETED]');
  });
  
  it('should enforce data retention policies', async () => {
    const adminToken = await helper.authenticate(config.adminEmail, config.adminPassword);
    
    // Check audit logs retention
    const auditResponse = await helper.client.get(
      '/api/v1/admin/audit-logs/settings',
      { headers: helper.getHeaders(adminToken) }
    );
    
    expect(auditResponse.status).toBe(200);
    expect(auditResponse.data.retentionPeriod).toBeDefined();
    expect(auditResponse.data.autoDelete).toBe(true);
    
    // Verify old data is automatically purged
    const purgeResponse = await helper.client.post(
      '/api/v1/admin/audit-logs/purge',
      { olderThan: '90 days' },
      { headers: helper.getHeaders(adminToken) }
    );
    
    expect(purgeResponse.status).toBe(200);
    expect(purgeResponse.data.recordsDeleted).toBeGreaterThanOrEqual(0);
  });
});

// ====================
// DATA INTEGRITY TESTS
// ====================

describe('Data Integrity Tests', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.waitForSystemReady();
  }, 150000);
  
  it('should maintain data consistency across multiple operations', async () => {
    const token = await helper.authenticate(config.testUserEmail, config.testUserPassword);
    
    // Create multiple records
    const records = [];
    for (let i = 0; i < 10; i++) {
      const recordResponse = await helper.client.post(
        '/api/v1/notes',
        {
          title: `Note ${i}`,
          content: `Content for note ${i}`
        },
        { headers: helper.getHeaders(token) }
      );
      records.push(recordResponse.data);
    }
    
    // Perform concurrent updates
    const updatePromises = records.map((record, index) =>
      helper.client.put(
        `/api/v1/notes/${record.id}`,
        { title: `Updated Note ${index}` },
        { headers: helper.getHeaders(token) }
      )
    );
    
    await Promise.all(updatePromises);
    
    // Verify all updates applied correctly
    for (let i = 0; i < records.length; i++) {
      const getResponse = await helper.client.get(
        `/api/v1/notes/${records[i].id}`,
        { headers: helper.getHeaders(token) }
      );
      
      expect(getResponse.data.title).toBe(`Updated Note ${i}`);
    }
  });
  
  it('should maintain referential integrity', async () => {
    const token = await helper.authenticate(config.testUserEmail, config.testUserPassword);
    
    // Create a user with related data
    const userResponse = await helper.client.get(
      '/api/v1/users/profile',
      { headers: helper.getHeaders(token) }
    );
    
    const user = userResponse.data;
    
    // Create related records (orders, addresses, etc.)
    const orderResponse = await helper.client.post(
      '/api/v1/orders',
      {
        items: [{ productId: 1, quantity: 1 }],
        shippingAddress: {
          street: '123 Test',
          city: 'Test',
          state: 'TS',
          zip: '12345'
        }
      },
      { headers: helper.getHeaders(token) }
    );
    
    expect(orderResponse.status).toBe(201);
    
    // Verify user cannot be deleted while orders exist
    const deleteResponse = await helper.client.delete(
      `/api/v1/users/${user.id}`,
      { headers: helper.getHeaders(token) }
    ).catch(error => error.response);
    
    // Should succeed (cascades to orders) or fail with constraint error
    expect([204, 409]).toContain(deleteResponse.status);
  });
});

// ====================
// RUN SYSTEM TESTS
// ====================

/*
Commands to run system tests:

# Set environment variables
export SYSTEM_TEST_URL=http://localhost:3000
export ADMIN_EMAIL=admin@example.com
export ADMIN_PASSWORD=admin123
export TEST_USER_EMAIL=test@example.com
export TEST_USER_PASSWORD=test123
export ENVIRONMENT=test

# Run all system tests (requires running application)
npm test -- tests/system/

# Run specific system test
npm test -- tests/system/ecommerce_flow.test.js

# Run with extended timeout
npm test -- tests/system/ --testTimeout=60000

# Run without coverage for speed
npm test -- tests/system/ --coverage=false

# Run in band to avoid port conflicts
npm test -- tests/system/ --runInBand

# Generate HTML report
npm test -- tests/system/ --reporters=default --reporters=jest-html-reporter

# Run with verbose output
npm test -- tests/system/ --verbose

# Debug a specific test
node --inspect-brk node_modules/.bin/jest tests/system/ecommerce_flow.test.js --runInBand

# Run tests in CI mode
npm test -- tests/system/ --ci --maxWorkers=2
*/

module.exports = { SystemTestConfig, SystemTestHelper };
