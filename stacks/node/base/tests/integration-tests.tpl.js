/**
 * Template: integration-tests.tpl.js
 * Purpose: integration-tests template
 * Stack: node
 * Tier: base
 */

# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: node
# Category: testing

// -----------------------------------------------------------------------------
// FILE: integration-tests.tpl.js
// PURPOSE: Integration testing patterns for Node.js projects
// USAGE: Test interactions between multiple components and services
// DEPENDENCIES: jest, supertest, nock, mongodb-memory-server
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * Node.js Integration Tests Template
 * Purpose: Integration testing patterns for Node.js projects
 * Usage: Test interactions between multiple components and services
 */

const request = require('supertest');
const nock = require('nock');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const app = require('../app');
const User = require('../models/User');
const AuthService = require('../services/AuthService');
const UserService = require('../services/UserService');

describe('Integration Tests - API Endpoints', () => {
  let mongoServer;
  let authToken;

  beforeAll(async () => {
    // Start in-memory MongoDB
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    await mongoose.connect(mongoUri);
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    // Clear database before each test
    await User.deleteMany({});
  });

  describe('User Authentication Flow', () => {
    test('should complete user registration and login flow', async () => {
      // Arrange
      const userData = {
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User'
      };

      // Act - Register user
      const registerResponse = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      // Assert - Registration successful
      expect(registerResponse.body.email).toBe(userData.email);
      expect(registerResponse.body.id).toBeDefined();
      expect(registerResponse.body.password).toBeUndefined(); // Password should not be returned

      // Act - Login with registered user
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: userData.email,
          password: userData.password
        })
        .expect(200);

      // Assert - Login successful
      expect(loginResponse.body.token).toBeDefined();
      expect(loginResponse.body.user.email).toBe(userData.email);
      authToken = loginResponse.body.token;
    });

    test('should protect routes with authentication middleware', async () => {
      // Act - Try to access protected route without token
      const response = await request(app)
        .get('/api/users/profile')
        .expect(401);

      // Assert
      expect(response.body.error).toContain('unauthorized');
    });

    test('should allow access to protected routes with valid token', async () => {
      // Arrange - Create and authenticate user
      const userData = {
        email: 'protected@example.com',
        password: 'password123',
        name: 'Protected User'
      };

      await request(app)
        .post('/api/auth/register')
        .send(userData);

      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: userData.email,
          password: userData.password
        });

      const token = loginResponse.body.token;

      // Act - Access protected route with token
      const response = await request(app)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      // Assert
      expect(response.body.email).toBe(userData.email);
    });
  });

  describe('User Management Integration', () => {
    let userToken;

    beforeEach(async () => {
      // Create and authenticate a user for each test
      const userData = {
        email: 'user@example.com',
        password: 'password123',
        name: 'Regular User'
      };

      await request(app)
        .post('/api/auth/register')
        .send(userData);

      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: userData.email,
          password: userData.password
        });

      userToken = loginResponse.body.token;
    });

    test('should update user profile', async () => {
      // Arrange
      const updateData = {
        name: 'Updated Name',
        bio: 'Updated bio'
      };

      // Act
      const response = await request(app)
        .put('/api/users/profile')
        .set('Authorization', `Bearer ${userToken}`)
        .send(updateData)
        .expect(200);

      // Assert
      expect(response.body.name).toBe(updateData.name);
      expect(response.body.bio).toBe(updateData.bio);
    });

    test('should handle file upload for user avatar', async () => {
      // Act
      const response = await request(app)
        .post('/api/users/avatar')
        .set('Authorization', `Bearer ${userToken}`)
        .attach('avatar', 'tests/fixtures/test-avatar.jpg')
        .expect(200);

      // Assert
      expect(response.body.avatarUrl).toBeDefined();
      expect(response.body.avatarUrl).toContain('.jpg');
    });

    test('should delete user account', async () => {
      // Act
      await request(app)
        .delete('/api/users/account')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      // Assert - User should no longer be able to login
      await request(app)
        .post('/api/auth/login')
        .send({
          email: 'user@example.com',
          password: 'password123'
        })
        .expect(401);
    });
  });

  describe('Database Transactions', () => {
    test('should handle complex transactions correctly', async () => {
      // Arrange
      const userService = new UserService();
      const transactionData = {
        user: {
          email: 'transaction@example.com',
          password: 'password123',
          name: 'Transaction User'
        },
        profile: {
          bio: 'User bio',
          preferences: { theme: 'dark', language: 'en' }
        },
        settings: {
          notifications: true,
          privacy: { public: false }
        }
      };

      // Act
      const result = await userService.createUserWithProfile(transactionData);

      // Assert
      expect(result.user.id).toBeDefined();
      expect(result.profile.userId).toBe(result.user.id);
      expect(result.settings.userId).toBe(result.user.id);

      // Verify data consistency
      const user = await User.findById(result.user.id);
      expect(user).toBeTruthy();
    });

    test('should rollback on transaction failure', async () => {
      // Arrange
      const userService = new UserService();
      const invalidData = {
        user: {
          email: 'invalid@example.com',
          password: 'password123',
          name: 'Invalid User'
        },
        profile: null, // This should cause transaction to fail
        settings: {
          notifications: true
        }
      };

      // Act & Assert
      await expect(userService.createUserWithProfile(invalidData))
        .rejects.toThrow();

      // Verify no data was created
      const user = await User.findOne({ email: 'invalid@example.com' });
      expect(user).toBeNull();
    });
  });
});

describe('Integration Tests - External Services', () => {
  describe('Email Service Integration', () => {
    test('should send welcome email after registration', async () => {
      // Arrange - Mock email service
      const emailServiceMock = {
        sendWelcomeEmail: jest.fn().mockResolvedValue({ messageId: 'msg-123' })
      };

      // Mock the email service module
      jest.doMock('../services/EmailService', () => emailServiceMock);

      const userData = {
        email: 'welcome@example.com',
        password: 'password123',
        name: 'Welcome User'
      };

      // Act
      await request(app)
        .post('/api/auth/register')
        .send(userData);

      // Assert
      expect(emailServiceMock.sendWelcomeEmail).toHaveBeenCalledWith(userData.email, userData.name);
    });

    test('should handle email service failures gracefully', async () => {
      // Arrange - Mock email service failure
      const emailServiceMock = {
        sendWelcomeEmail: jest.fn().mockRejectedValue(new Error('Email service down'))
      };

      jest.doMock('../services/EmailService', () => emailServiceMock);

      const userData = {
        email: 'fail@example.com',
        password: 'password123',
        name: 'Fail User'
      };

      // Act
      const response = await request(app)
        .post('/api/auth/register')
        .send(userData)
        .expect(201);

      // Assert - User should still be created even if email fails
      expect(response.body.email).toBe(userData.email);
    });
  });

  describe('Payment Service Integration', () => {
    test('should process payment with external provider', async () => {
      // Arrange - Mock payment provider
      nock('https://api.stripe.com')
        .post('/v1/charges')
        .reply(200, {
          id: 'ch_123',
          status: 'succeeded',
          amount: 2000
        });

      const paymentData = {
        amount: 2000,
        currency: 'usd',
        source: 'tok_visa'
      };

      // Act
      const response = await request(app)
        .post('/api/payments/charge')
        .send(paymentData)
        .expect(200);

      // Assert
      expect(response.body.status).toBe('succeeded');
      expect(response.body.chargeId).toBe('ch_123');
    });

    test('should handle payment failures', async () => {
      // Arrange - Mock payment failure
      nock('https://api.stripe.com')
        .post('/v1/charges')
        .reply(400, {
          error: {
            type: 'card_error',
            message: 'Your card was declined.'
          }
        });

      const paymentData = {
        amount: 2000,
        currency: 'usd',
        source: 'tok_declined'
      };

      // Act
      const response = await request(app)
        .post('/api/payments/charge')
        .send(paymentData)
        .expect(400);

      // Assert
      expect(response.body.error).toContain('declined');
    });
  });
});

describe('Integration Tests - Caching', () => {
  let redisClient;

  beforeAll(async () => {
    // Setup Redis client for testing
    redisClient = require('../config/redis');
  });

  test('should cache and retrieve user data', async () => {
    // Arrange
    const userData = {
      email: 'cache@example.com',
      password: 'password123',
      name: 'Cache User'
    };

    // Act - Create user
    const createResponse = await request(app)
      .post('/api/auth/register')
      .send(userData);

    const userId = createResponse.body.id;

    // Get user data (should cache it)
    const getResponse = await request(app)
      .get(`/api/users/${userId}`)
      .expect(200);

    // Get user data again (should come from cache)
    const cachedResponse = await request(app)
      .get(`/api/users/${userId}`)
      .expect(200);

    // Assert
    expect(getResponse.body.email).toBe(userData.email);
    expect(cachedResponse.body.email).toBe(userData.email);
    
    // Verify cache was used (check for cache headers or timing)
    expect(cachedResponse.headers['x-cache']).toBe('hit');
  });

  test('should invalidate cache on user update', async () => {
    // Arrange
    const userData = {
      email: 'invalidate@example.com',
      password: 'password123',
      name: 'Original Name'
    };

    // Create user and get token
    const createResponse = await request(app)
      .post('/api/auth/register')
      .send(userData);

    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        email: userData.email,
        password: userData.password
      });

    const token = loginResponse.body.token;
    const userId = createResponse.body.id;

    // Get user data (caches it)
    await request(app)
      .get(`/api/users/${userId}`)
      .expect(200);

    // Update user
    await request(app)
      .put('/api/users/profile')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'Updated Name' })
      .expect(200);

    // Get user data again (should not use stale cache)
    const updatedResponse = await request(app)
      .get(`/api/users/${userId}`)
      .expect(200);

    // Assert
    expect(updatedResponse.body.name).toBe('Updated Name');
    expect(updatedResponse.headers['x-cache']).toBe('miss');
  });
});

describe('Integration Tests - File Storage', () => {
  test('should upload and serve files from cloud storage', async () => {
    // Arrange
    const fileContent = Buffer.from('test file content');
    
    // Mock S3 upload
    nock('https://bucket.s3.amazonaws.com')
      .put('/uploads/test.txt')
      .reply(200, {
        Location: 'https://bucket.s3.amazonaws.com/uploads/test.txt',
        ETag: '"etag-123"'
      });

    // Act - Upload file
    const uploadResponse = await request(app)
      .post('/api/files/upload')
      .attach('file', fileContent, 'test.txt')
      .expect(200);

    // Assert
    expect(uploadResponse.body.url).toContain('test.txt');
    expect(uploadResponse.body.etag).toBe('"etag-123"');

    // Mock S3 download
    nock('https://bucket.s3.amazonaws.com')
      .get('/uploads/test.txt')
      .reply(200, fileContent);

    // Act - Download file
    const downloadResponse = await request(app)
      .get('/api/files/download/test.txt')
      .expect(200);

    // Assert
    expect(downloadResponse.body).toEqual(fileContent);
  });
});

describe('Integration Tests - WebSocket', () => {
  let server;
  let client;

  beforeAll(async () => {
    server = require('../server');
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
  });

  test('should handle real-time chat messages', async () => {
    // Arrange
    const WebSocket = require('ws');
    client = new WebSocket('ws://localhost:3000/chat');

    await new Promise((resolve) => {
      client.on('open', resolve);
    });

    // Act
    const message = {
      type: 'message',
      content: 'Hello, World!',
      userId: 'user123'
    };

    client.send(JSON.stringify(message));

    // Assert
    const response = await new Promise((resolve) => {
      client.on('message', (data) => {
        resolve(JSON.parse(data));
      });
    });

    expect(response.type).toBe('message');
    expect(response.content).toBe(message.content);
    expect(response.timestamp).toBeDefined();
  });

  test('should handle user join/leave events', async () => {
    // Arrange
    const WebSocket = require('ws');
    client = new WebSocket('ws://localhost:3000/chat');

    await new Promise((resolve) => {
      client.on('open', resolve);
    });

    // Act
    client.send(JSON.stringify({
      type: 'join',
      userId: 'user456',
      username: 'TestUser'
    }));

    // Assert
    const response = await new Promise((resolve) => {
      client.on('message', (data) => {
        const parsed = JSON.parse(data);
        if (parsed.type === 'user_joined') {
          resolve(parsed);
        }
      });
    });

    expect(response.type).toBe('user_joined');
    expect(response.userId).toBe('user456');
    expect(response.username).toBe('TestUser');
  });
});

describe('Integration Tests - Performance', () => {
  test('should handle concurrent requests efficiently', async () => {
    // Arrange
    const concurrentRequests = 50;
    const requests = [];

    // Act - Make concurrent requests
    for (let i = 0; i < concurrentRequests; i++) {
      requests.push(
        request(app)
          .get('/api/health')
          .expect(200)
      );
    }

    const startTime = Date.now();
    await Promise.all(requests);
    const endTime = Date.now();

    // Assert
    const totalTime = endTime - startTime;
    expect(totalTime).toBeLessThan(5000); // Should complete within 5 seconds
  });

  test('should handle large file uploads', async () => {
    // Arrange
    const largeFile = Buffer.alloc(10 * 1024 * 1024); // 10MB file

    // Act
    const startTime = Date.now();
    const response = await request(app)
      .post('/api/files/upload')
      .attach('file', largeFile, 'large-file.bin')
      .expect(200);
    const endTime = Date.now();

    // Assert
    expect(response.body.size).toBe(10 * 1024 * 1024);
    expect(endTime - startTime).toBeLessThan(10000); // Should upload within 10 seconds
  });
});

describe('Integration Tests - Error Handling', () => {
  test('should handle database connection failures', async () => {
    // Arrange - Disconnect database
    await mongoose.connection.close();

    // Act
    const response = await request(app)
      .get('/api/users/profile')
      .expect(500);

    // Assert
    expect(response.body.error).toContain('database');
  });

  test('should handle external API timeouts', async () => {
    // Arrange - Mock slow external API
    nock('https://api.external.com')
      .get('/data')
      .delayConnection(5000) // 5 second delay
      .reply(200, { data: 'response' });

    // Act
    const response = await request(app)
      .get('/api/external/data')
      .expect(408); // Request timeout

    // Assert
    expect(response.body.error).toContain('timeout');
  });
});

// Mock implementations for testing
class MockEmailService {
  async sendWelcomeEmail(email, name) {
    return { messageId: 'msg-123' };
  }
}

class MockPaymentService {
  async charge(amount, currency, source) {
    return {
      id: 'ch_123',
      status: 'succeeded',
      amount
    };
  }
}

module.exports = {
  MockEmailService,
  MockPaymentService
};
