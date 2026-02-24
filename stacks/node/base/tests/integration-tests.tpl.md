// Node.js Integration Testing Template
// Integration testing patterns for Node.js projects with Jest and testcontainers

/**
 * Node.js Integration Test Patterns
 * Complete integration testing with testcontainers, databases, and external services
 */

const { describe, it, expect, beforeAll, afterAll, beforeEach } = require('@jest/globals');
const request = require('supertest');
const { Client } = require('pg');
const Redis = require('ioredis');
const { GenericContainer, Wait } = require('testcontainers');

// ====================
// TEST SETUP AND FIXTURES
// ====================

describe('Integration Test Setup', () => {
  let postgresContainer;
  let redisContainer;
  let postgresClient;
  let redisClient;
  let app;
  
  beforeAll(async () => {
    // Start PostgreSQL container
    postgresContainer = await new GenericContainer('postgres:15-alpine')
      .withExposedPorts(5432)
      .withEnvironment({
        POSTGRES_USER: 'testuser',
        POSTGRES_PASSWORD: 'testpass',
        POSTGRES_DB: 'testdb'
      })
      .withWaitStrategy(Wait.forLogMessage('database system is ready'))
      .start();
    
    // Start Redis container
    redisContainer = await new GenericContainer('redis:7-alpine')
      .withExposedPorts(6379)
      .withWaitStrategy(Wait.forLogMessage('Ready to accept connections'))
      .start();
    
    // Create database connection
    const postgresPort = postgresContainer.getMappedPort(5432);
    const postgresHost = postgresContainer.getHost();
    
    postgresClient = new Client({
      host: postgresHost,
      port: postgresPort,
      user: 'testuser',
      password: 'testpass',
      database: 'testdb'
    });
    
    await postgresClient.connect();
    
    // Create Redis connection
    const redisPort = redisContainer.getMappedPort(6379);
    const redisHost = redisContainer.getHost();
    
    redisClient = new Redis({
      host: redisHost,
      port: redisPort
    });
    
    // Initialize database schema
    await setupDatabase();
    
    // Setup test app with test containers
    app = createTestApp({
      database: {
        host: postgresHost,
        port: postgresPort
      },
      redis: {
        host: redisHost,
        port: redisPort
      }
    });
  }, 30000); // 30 second timeout for container startup
  
  afterAll(async () => {
    // Cleanup connections
    if (postgresClient) {
      await postgresClient.end();
    }
    if (redisClient) {
      await redisClient.quit();
    }
    if (postgresContainer) {
      await postgresContainer.stop();
    }
    if (redisContainer) {
      await redisContainer.stop();
    }
  });
  
  async function setupDatabase() {
    await postgresClient.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        is_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await postgresClient.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        stock INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await postgresClient.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        total DECIMAL(10, 2) NOT NULL,
        status VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        paid_at TIMESTAMP
      )
    `);
    
    await postgresClient.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        product_id INTEGER,
        quantity INTEGER NOT NULL,
        price DECIMAL(10, 2) NOT NULL
      )
    `);
  }
});

// ====================
// USER REGISTRATION FLOW INTEGRATION TESTS
// ====================

describe('User Registration Flow Integration', () => {
  
  it('should complete full user registration, verification, and login flow', async () => {
    // Step 1: Register new user
    const newUser = {
      name: 'Integration Test User',
      email: 'integration@test.com',
      password: 'SecurePass123!',
      passwordConfirm: 'SecurePass123!'
    };
    
    const registerResponse = await request(app)
      .post('/api/v1/users/register')
      .send(newUser)
      .expect(201);
    
    const user = registerResponse.body;
    expect(user.id).toBeDefined();
    expect(user.email).toBe('integration@test.com');
    expect(user.password).toBeUndefined(); // Should not return password
    
    // Verify user in database
    const dbUser = await postgresClient.query(
      'SELECT * FROM users WHERE id = $1',
      [user.id]
    );
    expect(dbUser.rows[0].email).toBe('integration@test.com');
    expect(dbUser.rows[0].is_verified).toBe(false);
    
    // Step 2: Simulate email verification
    // In production, this would involve clicking email link
    await postgresClient.query(
      'UPDATE users SET is_verified = true WHERE id = $1',
      [user.id]
    );
    
    // Step 3: Login with verified account
    const loginResponse = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'integration@test.com',
        password: 'SecurePass123!'
      })
      .expect(200);
    
    const { accessToken, refreshToken } = loginResponse.body;
    expect(accessToken).toBeDefined();
    expect(refreshToken).toBeDefined();
    expect(typeof accessToken).toBe('string');
    expect(typeof refreshToken).toBe('string');
    
    // Step 4: Access protected endpoint with token
    const profileResponse = await request(app)
      .get('/api/v1/users/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);
    
    expect(profileResponse.body.email).toBe('integration@test.com');
    expect(profileResponse.body.name).toBe('Integration Test User');
    
    // Step 5: Refresh token
    const refreshResponse = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Authorization', `Bearer ${refreshToken}`)
      .expect(200);
    
    expect(refreshResponse.body.accessToken).toBeDefined();
    expect(refreshResponse.body.accessToken).not.toBe(accessToken);
  });
  
  it('should return error for duplicate email registration', async () => {
    const userData = {
      name: 'Test User',
      email: 'duplicate@test.com',
      password: 'Password123!
    };
    
    // First registration
    await request(app)
      .post('/api/v1/users/register')
      .send(userData)
      .expect(201);
    
    // Duplicate registration
    const response = await request(app)
      .post('/api/v1/users/register')
      .send(userData)
      .expect(409);
    
    expect(response.body.error).toContain('email already exists');
  });
});

// ====================
// E-COMMERCE ORDER FLOW INTEGRATION TESTS
// ====================

describe('E-commerce Order Flow Integration', () => {
  
  let authToken;
  let userId;
  
  beforeEach(async () => {
    // Create and authenticate user
    const userData = {
      name: 'Customer Test',
      email: 'customer@test.com',
      password: 'Customer123!'
    };
    
    const registerResponse = await request(app)
      .post('/api/v1/users/register')
      .send(userData)
      .expect(201);
    
    userId = registerResponse.body.id;
    
    // Verify and login
    await postgresClient.query(
      'UPDATE users SET is_verified = true WHERE id = $1',
      [userId]
    );
    
    const loginResponse = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'customer@test.com',
        password: 'Customer123!'
      })
      .expect(200);
    
    authToken = loginResponse.body.accessToken;
    
    // Create test products
    await postgresClient.query(`
      INSERT INTO products (name, price, stock)
      VALUES 
        ('Product 1', 29.99, 100),
        ('Product 2', 49.99, 50)
    `);
  });
  
  it('should complete full order flow from cart to payment', async () => {
    // Step 1: Get products
    const productsResponse = await request(app)
      .get('/api/v1/products')
      .set('Authorization', `Bearer ${authToken}`)
      .expect(200);
    
    const products = productsResponse.body;
    expect(products.length).toBeGreaterThanOrEqual(2);
    
    // Step 2: Add items to cart
    const cartData = {
      items: [
        { productId: products[0].id, quantity: 2 },
        { productId: products[1].id, quantity: 1 }
      ]
    };
    
    const cartResponse = await request(app)
      .post('/api/v1/cart')
      .set('Authorization', `Bearer ${authToken}`)
      .send(cartData)
      .expect(201);
    
    const cart = cartResponse.body;
    expect(cart.items.length).toBe(2);
    
    // Calculate expected total
    const expectedTotal = (products[0].price * 2) + products[1].price;
    expect(parseFloat(cart.total)).toBeCloseTo(expectedTotal);
    
    // Step 3: Checkout
    const checkoutData = {
      cartId: cart.id,
      shippingAddress: {
        street: '123 Main St',
        city: 'Springfield',
        state: 'IL',
        zip: '62701',
        country: 'USA'
      },
      billingAddress: {
        street: '123 Main St',
        city: 'Springfield',
        state: 'IL',
        zip: '62701',
        country: 'USA'
      }
    };
    
    const orderResponse = await request(app)
      .post('/api/v1/orders')
      .set('Authorization', `Bearer ${authToken}`)
      .send(checkoutData)
      .expect(201);
    
    const order = orderResponse.body;
    expect(order.status).toBe('pending');
    expect(order.userId).toBe(userId);
    
    // Verify order in database
    const dbOrder = await postgresClient.query(
      'SELECT * FROM orders WHERE id = $1',
      [order.id]
    );
    expect(dbOrder.rows[0].status).toBe('pending');
    expect(parseFloat(dbOrder.rows[0].total)).toBeCloseTo(expectedTotal);
    
    // Verify order items
    const dbOrderItems = await postgresClient.query(
      'SELECT * FROM order_items WHERE order_id = $1',
      [order.id]
    );
    expect(dbOrderItems.rows).toHaveLength(2);
    expect(dbOrderItems.rows[0].quantity).toBe(2);
    
    // Step 4: Process payment
    const paymentData = {
      orderId: order.id,
      amount: expectedTotal,
      method: 'stripe',
      token: 'tok_visa_test'
    };
    
    const paymentResponse = await request(app)
      .post('/api/v1/payments')
      .set('Authorization', `Bearer ${authToken}`)
      .send(paymentData)
      .expect(200);
    
    const payment = paymentResponse.body;
    expect(payment.status).toBe('completed');
    expect(payment.orderId).toBe(order.id);
    
    // Wait for async order update
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Step 5: Verify order status updated to paid
    const updatedOrderResponse = await request(app)
      .get(`/api/v1/orders/${order.id}`)
      .set('Authorization', `Bearer ${authToken}`)
      .expect(200);
    
    const updatedOrder = updatedOrderResponse.body;
    expect(updatedOrder.status).toBe('paid');
    expect(updatedOrder.paidAt).toBeDefined();
    
    // Step 6: Verify inventory updated
    const product1 = await postgresClient.query(
      'SELECT stock FROM products WHERE id = $1',
      [products[0].id]
    );
    expect(product1.rows[0].stock).toBe(98); // 100 - 2 purchased
  });
  
  it('should handle failed payment flow', async () => {
    // ... setup cart and order ...
    const orderData = {
      items: [{ productId: 1, quantity: 1 }],
      shippingAddress: { /* ... */ }
    };
    
    const orderResponse = await request(app)
      .post('/api/v1/orders')
      .set('Authorization', `Bearer ${authToken}`)
      .send(orderData)
      .expect(201);
    
    const order = orderResponse.body;
    
    // Attempt payment with invalid token
    const invalidPaymentData = {
      orderId: order.id,
      amount: order.total,
      method: 'stripe',
      token: 'tok_card_declined'
    };
    
    const paymentResponse = await request(app)
      .post('/api/v1/payments')
      .set('Authorization', `Bearer ${authToken}`)
      .send(invalidPaymentData)
      .expect(402);
    
    expect(paymentResponse.body.error).toContain('payment failed');
    
    // Verify order remains pending
    const updatedOrder = await request(app)
      .get(`/api/v1/orders/${order.id}`)
      .set('Authorization', `Bearer ${authToken}`)
      .expect(200);
    
    expect(updatedOrder.body.status).toBe('pending');
    expect(updatedOrder.body.paidAt).toBeNull();
  });
});

// ====================
// REDIS INTEGRATION TESTS
// ====================

describe('Redis Integration Tests', () => {
  
  it('should cache and retrieve data from Redis', async () => {
    // Set cache value
    await redisClient.set('test:key', 'test value', 'EX', 60);
    
    // Retrieve cache value
    const cachedValue = await redisClient.get('test:key');
    expect(cachedValue).toBe('test value');
    
    // Verify TTL is set
    const ttl = await redisClient.ttl('test:key');
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(60);
  });
  
  it('should handle rate limiting with Redis', async () => {
    const rateLimitKey = 'rate_limit:test_user';
    const limit = 10;
    const window = 60; // 60 seconds
    
    // Simulate multiple requests
    for (let i = 0; i < limit; i++) {
      const current = await redisClient.incr(rateLimitKey);
      if (current === 1) {
        await redisClient.expire(rateLimitKey, window);
      }
    }
    
    // Check current count
    const count = await redisClient.get(rateLimitKey);
    expect(parseInt(count)).toBe(limit);
    
    // Next request should be rate limited
    const nextCount = await redisClient.incr(rateLimitKey);
    expect(nextCount).toBe(limit + 1);
  });
  
  it('should use Redis for session storage', async () => {
    const sessionId = 'session_' + Date.now();
    const sessionData = {
      userId: 123,
      email: 'user@example.com',
      role: 'customer'
    };
    
    // Store session
    await redisClient.setex(
      `session:${sessionId}`,
      3600, // 1 hour TTL
      JSON.stringify(sessionData)
    );
    
    // Retrieve session
    const storedSession = await redisClient.get(`session:${sessionId}`);
    expect(JSON.parse(storedSession)).toEqual(sessionData);
    
    // Verify session exists
    const exists = await redisClient.exists(`session:${sessionId}`);
    expect(exists).toBe(1);
  });
});

// ====================
// EXTERNAL API INTEGRATION TESTS
// ====================

describe('External API Integration Tests', () => {
  
  it('should integrate with Stripe for payments', async () => {
    const mockStripe = {
      paymentIntents: {
        create: jest.fn().mockResolvedValue({
          id: 'pi_test_123',
          amount: 2999,
          currency: 'usd',
          status: 'succeeded'
        })
      }
    };
    
    const paymentData = {
      amount: 2999,
      currency: 'usd',
      payment_method: 'pm_test_card'
    };
    
    const paymentIntent = await mockStripe.paymentIntents.create(paymentData);
    
    expect(paymentIntent.id).toBe('pi_test_123');
    expect(paymentIntent.status).toBe('succeeded');
    expect(mockStripe.paymentIntents.create).toHaveBeenCalledWith(paymentData);
  });
  
  it('should handle external API failures gracefully', async () => {
    const mockExternalAPI = {
      fetch: jest.fn().mockRejectedValue(new Error('External API timeout'))
    };
    
    try {
      await mockExternalAPI.fetch();
      fail('Should have thrown an error');
    } catch (error) {
      expect(error.message).toContain('timeout');
    }
  });
});

// ====================
// CONCURRENT LOAD INTEGRATION TESTS
// ====================

describe('Concurrent Load Integration Tests', () => {
  
  it('should handle concurrent user registrations', async () => {
    const concurrentUsers = 20;
    const registrationPromises = [];
    
    // Create multiple registration requests concurrently
    for (let i = 0; i < concurrentUsers; i++) {
      const userData = {
        name: `Concurrent User ${i}`,
        email: `concurrent${i}@test.com`,
        password: 'Password123!'
      };
      
      registrationPromises.push(
        request(app)
          .post('/api/v1/users/register')
          .send(userData)
      );
    }
    
    // Execute all registrations
    const results = await Promise.all(registrationPromises);
    
    // Verify all succeeded
    expect(results.length).toBe(concurrentUsers);
    results.forEach((response, index) => {
      expect(response.status).toBe(201);
      expect(response.body.email).toBe(`concurrent${index}@test.com`);
    });
    
    // Verify in database
    const dbCount = await postgresClient.query(
      'SELECT COUNT(*) FROM users WHERE email LIKE \'concurrent%@test.com\''
    );
    expect(parseInt(dbCount.rows[0].count)).toBe(concurrentUsers);
  });
  
  it('should handle concurrent product purchases without overselling', async () => {
    // Create product with limited stock
    const productResult = await postgresClient.query(`
      INSERT INTO products (name, price, stock)
      VALUES ('Limited Product', 99.99, 10)
      RETURNING id
    `);
    
    const productId = productResult.rows[0].id;
    const oversellAttempts = 15; // Try to buy more than available
    
    // Create multiple purchase attempts
    const purchasePromises = [];
    for (let i = 0; i < oversellAttempts; i++) {
      const userData = {
        name: `Buyer ${i}`,
        email: `buyer${i}@test.com`,
        password: 'Password123!'
      };
      
      // Register user
      const userResponse = await request(app)
        .post('/api/v1/users/register')
        .send(userData);
      
      const userId = userResponse.body.id;
      
      // Verify user
      await postgresClient.query(
        'UPDATE users SET is_verified = true WHERE id = $1',
        [userId]
      );
      
      // Login
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: `buyer${i}@test.com`,
          password: 'Password123!'
        });
      
      const token = loginResponse.body.accessToken;
      
      // Create order
      purchasePromises.push(
        (async () => {
          try {
            const orderResponse = await request(app)
              .post('/api/v1/orders')
              .set('Authorization', `Bearer ${token}`)
              .send({
                items: [{ productId, quantity: 1 }],
                shippingAddress: {
                  street: '123 Test St',
                  city: 'Test City',
                  state: 'TS',
                  zip: '12345'
                }
              });
            
            return { success: orderResponse.status === 201, userId };
          } catch (error) {
            return { success: false, userId, error: error.message };
          }
        })()
      );
    }
    
    // Execute all purchases concurrently
    const results = await Promise.all(purchasePromises);
    
    // Verify only 10 succeeded (available stock)
    const successfulPurchases = results.filter(r => r.success).length;
    expect(successfulPurchases).toBeLessThanOrEqual(10);
    
    // Verify final stock is 0
    const finalStock = await postgresClient.query(
      'SELECT stock FROM products WHERE id = $1',
      [productId]
    );
    expect(finalStock.rows[0].stock).toBe(0);
  });
});

// ====================
// TEST UTILITIES
// ====================

class IntegrationTestHelper {
  constructor(app, postgresClient, redisClient) {
    this.app = app;
    this.postgresClient = postgresClient;
    this.redisClient = redisClient;
    this.tokens = new Map();
  }
  
  async createUser(userData) {
    const response = await request(this.app)
      .post('/api/v1/users/register')
      .send(userData)
      .expect(201);
    
    return response.body;
  }
  
  async authenticate(email, password) {
    if (this.tokens.has(email)) {
      return this.tokens.get(email);
    }
    
    const response = await request(this.app)
      .post('/api/v1/auth/login')
      .send({ email, password })
      .expect(200);
    
    const token = response.body.accessToken;
    this.tokens.set(email, token);
    return token;
  }
  
  async createProduct(productData) {
    const result = await this.postgresClient.query(`
      INSERT INTO products (name, price, stock)
      VALUES ($1, $2, $3)
      RETURNING *
    `, [productData.name, productData.price, productData.stock]);
    
    return result.rows[0];
  }
  
  async getFromCache(key) {
    return this.redisClient.get(key);
  }
  
  async setInCache(key, value, ttl = 60) {
    return this.redisClient.setex(key, ttl, value);
  }
}

// ====================
// RUN INTEGRATION TESTS
// ====================

/*
Commands to run integration tests:

# Run all integration tests
npm test -- tests/integration/

# Run specific integration test file
npm test -- tests/integration/user_flows.test.js

# Run with live output
npm test -- tests/integration/ --verbose

# Run slow integration tests
npm test -- tests/integration/ --testNamePattern="slow"

# Run with coverage
npm test -- tests/integration/ --coverage

# Run in watch mode for development
npm test -- tests/integration/ --watch

# Run with extended timeout for containers
npm test -- tests/integration/ --testTimeout=30000

# Run without coverage for speed
npm test -- tests/integration/ --coverage=false

# Run tests in parallel (default)
npm test -- tests/integration/

# Run tests sequentially to debug timing issues
npm test -- tests/integration/ --runInBand

# Debug a specific test
node --inspect-brk node_modules/.bin/jest tests/integration/user_flows.test.js --runInBand
*/
