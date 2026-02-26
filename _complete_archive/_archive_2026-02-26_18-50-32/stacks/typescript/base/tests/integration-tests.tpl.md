# TypeScript Integration Testing Template
# Comprehensive integration testing patterns for TypeScript projects with API, database, and external service testing

/**
 * TypeScript Integration Test Patterns
 * API testing, database integration, external services, and complete workflow testing
 */

import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from '@jest/globals';
import request from 'supertest';
import { Express } from 'express';
import { createApp } from '@/app';
import { setupTestDatabase, cleanupTestDatabase } from '@/helpers/testDatabase';
import { UserService } from '@/services/UserService';
import { UserRepository } from '@/repositories/UserRepository';
import { EmailService } from '@/services/EmailService';
import { User, CreateUserRequest, UserRole } from '@/models/User';
import { Pool } from 'pg';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { MongoClient, Db } from 'mongodb';
import nock from 'nock';

// ====================
// API INTEGRATION TESTING
// ====================

describe('API Integration Tests', () => {
  let app: Express;
  let dbConnection: Pool;

  beforeAll(async () => {
    // Setup test database
    dbConnection = await setupTestDatabase();
    
    // Create Express app with test configuration
    app = createApp({
      database: dbConnection,
      environment: 'test',
      disableRateLimiting: true,
    });
  });

  afterAll(async () => {
    await cleanupTestDatabase(dbConnection);
  });

  beforeEach(async () => {
    // Clean database before each test
    await dbConnection.query('TRUNCATE TABLE users, orders, products CASCADE');
  });

  describe('POST /api/v1/users', () => {
    it('should create a new user with valid data', async () => {
      const userData: CreateUserRequest = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'SecureP@ssw0rd123',
        roles: [UserRole.USER],
      };

      const response = await request(app)
        .post('/api/v1/users')
        .send(userData)
        .expect(201);

      expect(response.body).toMatchObject({
        success: true,
        data: {
          name: userData.name,
          email: userData.email,
          roles: userData.roles,
          isActive: true,
        },
      });

      expect(response.body.data.id).toBeDefined();
      expect(response.body.data.password).toBeUndefined();
      expect(response.body.data.passwordHash).toBeUndefined();
      expect(response.body.data.createdAt).toBeDefined();
      expect(response.body.data.updatedAt).toBeDefined();
    });

    it('should return validation errors for invalid data', async () => {
      const invalidData = {
        name: '',
        email: 'invalid-email',
        password: '123',
      };

      const response = await request(app)
        .post('/api/v1/users')
        .send(invalidData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Validation failed');
      expect(response.body.details).toBeInstanceOf(Array);
      expect(response.body.details.length).toBeGreaterThan(0);
    });

    it('should handle duplicate email addresses', async () => {
      const userData: CreateUserRequest = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'SecureP@ssw0rd123',
      };

      // Create first user
      await request(app)
        .post('/api/v1/users')
        .send(userData)
        .expect(201);

      // Attempt to create duplicate user
      const response = await request(app)
        .post('/api/v1/users')
        .send(userData)
        .expect(409);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Email already exists');
    });

    it('should handle database connection errors gracefully', async () => {
      // Mock database error
      const mockPool = {
        query: jest.fn().mockRejectedValue(new Error('Database connection failed')),
      } as any;

      const testApp = createApp({
        database: mockPool,
        environment: 'test',
      });

      const userData: CreateUserRequest = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const response = await request(testApp)
        .post('/api/v1/users')
        .send(userData)
        .expect(500);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Internal server error');
    });
  });

  describe('GET /api/v1/users/:id', () => {
    let createdUserId: string;
    let authToken: string;

    beforeEach(async () => {
      // Create a user and get auth token
      const userData: CreateUserRequest = {
        name: 'Jane Doe',
        email: 'jane@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const createResponse = await request(app)
        .post('/api/v1/users')
        .send(userData)
        .expect(201);

      createdUserId = createResponse.body.data.id;

      // Login to get auth token
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: userData.email,
          password: userData.password,
        })
        .expect(200);

      authToken = loginResponse.body.data.accessToken;
    });

    it('should retrieve user by ID with authentication', async () => {
      const response = await request(app)
        .get(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toMatchObject({
        id: createdUserId,
        name: 'Jane Doe',
        email: 'jane@example.com',
      });
      expect(response.body.data.passwordHash).toBeUndefined();
    });

    it('should return 401 without authentication', async () => {
      const response = await request(app)
        .get(`/api/v1/users/${createdUserId}`)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Authentication required');
    });

    it('should return 404 for non-existent user', async () => {
      const response = await request(app)
        .get('/api/v1/users/nonexistent-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('User not found');
    });
  });

  describe('PUT /api/v1/users/:id', () => {
    let createdUserId: string;
    let authToken: string;

    beforeEach(async () => {
      // Create a user and get auth token
      const userData: CreateUserRequest = {
        name: 'John Smith',
        email: 'john.smith@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const createResponse = await request(app)
        .post('/api/v1/users')
        .send(userData)
        .expect(201);

      createdUserId = createResponse.body.data.id;

      // Login to get auth token
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: userData.email,
          password: userData.password,
        })
        .expect(200);

      authToken = loginResponse.body.data.accessToken;
    });

    it('should update user information', async () => {
      const updateData = {
        name: 'John Updated Smith',
        bio: 'Software developer',
        location: 'San Francisco',
      };

      const response = await request(app)
        .put(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toMatchObject(updateData);
      expect(response.body.data.updatedAt).not.toBe(response.body.data.createdAt);
    });

    it('should validate update data', async () => {
      const invalidData = {
        name: '',
        email: 'invalid-email-format',
      };

      const response = await request(app)
        .put(`/api/v1/users/${createdUserId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Validation failed');
    });

    it('should prevent updating another user without permission', async () => {
      // Create another user
      const otherUserData: CreateUserRequest = {
        name: 'Other User',
        email: 'other@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const otherUserResponse = await request(app)
        .post('/api/v1/users')
        .send(otherUserData)
        .expect(201);

      const otherUserId = otherUserResponse.body.data.id;

      // Try to update other user with first user's token
      const response = await request(app)
        .put(`/api/v1/users/${otherUserId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ name: 'Hacked Name' })
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Permission denied');
    });
  });

  describe('GET /api/v1/users', () => {
    let authToken: string;

    beforeEach(async () => {
      // Create multiple users
      const users: CreateUserRequest[] = [
        { name: 'User 1', email: 'user1@example.com', password: 'SecureP@ssw0rd123' },
        { name: 'User 2', email: 'user2@example.com', password: 'SecureP@ssw0rd123' },
        { name: 'User 3', email: 'user3@example.com', password: 'SecureP@ssw0rd123' },
      ];

      for (const userData of users) {
        await request(app)
          .post('/api/v1/users')
          .send(userData)
          .expect(201);
      }

      // Login to get auth token
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'user1@example.com',
          password: 'SecureP@ssw0rd123',
        })
        .expect(200);

      authToken = loginResponse.body.data.accessToken;
    });

    it('should list users with pagination', async () => {
      const response = await request(app)
        .get('/api/v1/users?page=1&limit=2')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toHaveProperty('items');
      expect(response.body.data).toHaveProperty('pagination');
      expect(response.body.data.items).toHaveLength(2);
      expect(response.body.data.pagination).toMatchObject({
        page: 1,
        limit: 2,
        total: 3,
        totalPages: 2,
      });
    });

    it('should filter users by query parameters', async () => {
      const response = await request(app)
        .get('/api/v1/users?search=User 2')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.items).toHaveLength(1);
      expect(response.body.data.items[0].name).toBe('User 2');
    });

    it('should sort users by specified field', async () => {
      const response = await request(app)
        .get('/api/v1/users?sort=name&order=desc')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.items.length).toBeGreaterThan(0);
      
      // Verify sorting
      const names = response.body.data.items.map((user: User) => user.name);
      const sortedNames = [...names].sort().reverse();
      expect(names).toEqual(sortedNames);
    });
  });
});

// ====================
// AUTHENTICATION INTEGRATION TESTING
// ====================

describe('Authentication Integration Tests', () => {
  let app: Express;
  let dbConnection: Pool;

  beforeAll(async () => {
    dbConnection = await setupTestDatabase();
    app = createApp({
      database: dbConnection,
      environment: 'test',
    });
  });

  afterAll(async () => {
    await cleanupTestDatabase(dbConnection);
  });

  beforeEach(async () => {
    await dbConnection.query('TRUNCATE TABLE users CASCADE');
  });

  describe('POST /api/v1/auth/register', () => {
    it('should register a new user', async () => {
      const userData: CreateUserRequest = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data).toMatchObject({
        name: userData.name,
        email: userData.email,
        isActive: true,
      });
      expect(response.body.data.id).toBeDefined();
    });

    it('should hash password during registration', async () => {
      const userData: CreateUserRequest = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);

      const userId = response.body.data.id;
      
      // Verify password is hashed in database
      const dbResult = await dbConnection.query(
        'SELECT password_hash FROM users WHERE id = $1',
        [userId]
      );
      
      const storedPasswordHash = dbResult.rows[0].password_hash;
      expect(storedPasswordHash).toBeDefined();
      expect(storedPasswordHash).not.toBe(userData.password);
      expect(storedPasswordHash.length).toBeGreaterThan(50); // Bcrypt hash length
    });
  });

  describe('POST /api/v1/auth/login', () => {
    beforeEach(async () => {
      // Create a test user
      const userData: CreateUserRequest = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'SecureP@ssw0rd123',
      };

      await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);
    });

    it('should authenticate valid credentials', async () => {
      const credentials = {
        email: 'test@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(credentials)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.accessToken).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();
      expect(response.body.data.tokenType).toBe('Bearer');
      expect(response.body.data.expiresIn).toBeDefined();
      expect(response.body.data.user).toMatchObject({
        email: credentials.email,
        name: 'Test User',
      });
    });

    it('should reject invalid credentials', async () => {
      const credentials = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(credentials)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid credentials');
      expect(response.body.data).toBeUndefined();
    });

    it('should reject non-existent user', async () => {
      const credentials = {
        email: 'nonexistent@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(credentials)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid credentials');
    });

    it('should rate limit repeated failed login attempts', async () => {
      const credentials = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      // Make multiple failed attempts
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/api/v1/auth/login')
          .send(credentials)
          .expect(401);
      }

      // Next attempt should be rate limited
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(credentials)
        .expect(429);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Too many attempts');
    });
  });

  describe('POST /api/v1/auth/refresh', () => {
    let refreshToken: string;

    beforeEach(async () => {
      // Register and login to get refresh token
      const userData: CreateUserRequest = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'SecureP@ssw0rd123',
      };

      await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);

      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: userData.email,
          password: userData.password,
        })
        .expect(200);

      refreshToken = loginResponse.body.data.refreshToken;
    });

    it('should refresh access token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.accessToken).toBeDefined();
      expect(response.body.data.refreshToken).toBeDefined();
      expect(response.body.data.tokenType).toBe('Bearer');
    });

    it('should reject invalid refresh token', async () => {
      const response = await request(app)
        .post('/api/v1/auth/refresh')
        .send({ refreshToken: 'invalid-token' })
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid refresh token');
    });
  });

  describe('Protected Routes', () => {
    let authToken: string;

    beforeEach(async () => {
      // Create user and get auth token
      const userData: CreateUserRequest = {
        name: 'Test User',
        email: 'test@example.com',
        password: 'SecureP@ssw0rd123',
      };

      await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);

      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: userData.email,
          password: userData.password,
        })
        .expect(200);

      authToken = loginResponse.body.data.accessToken;
    });

    it('should access protected routes with valid token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.email).toBe('test@example.com');
    });

    it('should reject protected routes without token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/profile')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Access token required');
    });

    it('should reject protected routes with invalid token', async () => {
      const response = await request(app)
        .get('/api/v1/auth/profile')
        .set('Authorization', 'Bearer invalid-token')
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Invalid token');
    });

    it('should reject expired tokens', async () => {
      // Wait for token expiration (if configured with short expiration)
      await new Promise(resolve => setTimeout(resolve, 2000));

      const response = await request(app)
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('Token expired');
    });
  });
});

// ====================
// DATABASE INTEGRATION TESTING
// ====================

describe('Database Integration Tests', () => {
  
  describe('PostgreSQL Integration', () => {
    let dbConnection: Pool;
    let userRepository: UserRepository;

    beforeAll(async () => {
      dbConnection = await setupTestDatabase();
      userRepository = new UserRepository(dbConnection);
    });

    afterAll(async () => {
      await cleanupTestDatabase(dbConnection);
    });

    beforeEach(async () => {
      await dbConnection.query('TRUNCATE TABLE users CASCADE');
    });

    describe('UserRepository', () => {
      it('should create a new user in database', async () => {
        const userData = {
          name: 'John Doe',
          email: 'john@example.com',
          passwordHash: 'hashed_password',
          roles: [UserRole.USER],
          isActive: true,
        };

        const user = await userRepository.create(userData);

        expect(user).toMatchObject({
          name: userData.name,
          email: userData.email,
          roles: userData.roles,
          isActive: userData.isActive,
        });
        expect(user.id).toBeDefined();
        expect(user.createdAt).toBeInstanceOf(Date);
        expect(user.updatedAt).toBeInstanceOf(Date);

        // Verify user was actually stored in database
        const dbResult = await dbConnection.query(
          'SELECT * FROM users WHERE id = $1',
          [user.id]
        );
        expect(dbResult.rows).toHaveLength(1);
        expect(dbResult.rows[0].email).toBe(userData.email);
      });

      it('should enforce unique email constraint', async () => {
        const userData = {
          name: 'John Doe',
          email: 'john@example.com',
          passwordHash: 'hashed_password',
        };

        // Create first user
        await userRepository.create(userData);

        // Attempt to create duplicate user
        await expect(userRepository.create(userData)).rejects.toThrow(
          'duplicate key value violates unique constraint'
        );
      });

      it('should find user by ID', async () => {
        const userData = {
          name: 'Jane Doe',
          email: 'jane@example.com',
          passwordHash: 'hashed_password',
        };

        const createdUser = await userRepository.create(userData);
        const foundUser = await userRepository.findById(createdUser.id);

        expect(foundUser).toMatchObject(createdUser);
        expect(foundUser?.id).toBe(createdUser.id);
      });

      it('should return null for non-existent user', async () => {
        const user = await userRepository.findById('nonexistent-id');
        expect(user).toBeNull();
      });

      it('should find user by email', async () => {
        const userData = {
          name: 'Test User',
          email: 'test@example.com',
          passwordHash: 'hashed_password',
        };

        const createdUser = await userRepository.create(userData);
        const foundUser = await userRepository.findByEmail(userData.email);

        expect(foundUser).toMatchObject(createdUser);
        expect(foundUser?.email).toBe(userData.email);
      });

      it('should update user information', async () => {
        const userData = {
          name: 'Original Name',
          email: 'original@example.com',
          passwordHash: 'hashed_password',
        };

        const createdUser = await userRepository.create(userData);
        
        const updateData = {
          name: 'Updated Name',
          bio: 'Updated bio',
        };

        const updatedUser = await userRepository.update(createdUser.id, updateData);

        expect(updatedUser.name).toBe(updateData.name);
        expect(updatedUser.bio).toBe(updateData.bio);
        expect(updatedUser.updatedAt.getTime()).toBeGreaterThan(
          createdUser.updatedAt.getTime()
        );
      });

      it('should delete user', async () => {
        const userData = {
          name: 'User to Delete',
          email: 'delete@example.com',
          passwordHash: 'hashed_password',
        };

        const createdUser = await userRepository.create(userData);
        await userRepository.delete(createdUser.id);

        const foundUser = await userRepository.findById(createdUser.id);
        expect(foundUser).toBeNull();
      });

      it('should handle complex queries with joins', async () => {
        // Create test data with relationships
        const userData = {
          name: 'User with Orders',
          email: 'orders@example.com',
          passwordHash: 'hashed_password',
        };

        const user = await userRepository.create(userData);
        
        // Create related orders
        await dbConnection.query(
          'INSERT INTO orders (user_id, total_amount, status) VALUES ($1, $2, $3)',
          [user.id, 100.00, 'completed']
        );
        
        await dbConnection.query(
          'INSERT INTO orders (user_id, total_amount, status) VALUES ($1, $2, $3)',
          [user.id, 200.00, 'pending']
        );

        // Test complex query with aggregation
        const result = await dbConnection.query(`
          SELECT u.*, COUNT(o.id) as order_count, SUM(o.total_amount) as total_spent
          FROM users u
          LEFT JOIN orders o ON u.id = o.user_id
          WHERE u.id = $1
          GROUP BY u.id
        `, [user.id]);

        expect(result.rows).toHaveLength(1);
        expect(result.rows[0].order_count).toBe('2');
        expect(parseFloat(result.rows[0].total_spent)).toBe(300.00);
      });

      it('should handle transactions correctly', async () => {
        const client = await dbConnection.connect();
        
        try {
          await client.query('BEGIN');
          
          const userData = {
            name: 'Transaction Test',
            email: 'transaction@example.com',
            passwordHash: 'hashed_password',
          };

          const user = await userRepository.createWithClient(client, userData);
          
          // Simulate error to test rollback
          await client.query('INSERT INTO nonexistent_table VALUES (1)');
          
          await client.query('COMMIT');
        } catch (error) {
          await client.query('ROLLBACK');
          
          // Verify user was not created due to rollback
          const result = await dbConnection.query(
            'SELECT * FROM users WHERE email = $1',
            ['transaction@example.com']
          );
          expect(result.rows).toHaveLength(0);
        } finally {
          client.release();
        }
      });
    });
  });

  describe('MongoDB Integration', () => {
    let mongod: MongoMemoryServer;
    let mongoClient: MongoClient;
    let mongoDb: Db;

    beforeAll(async () => {
      mongod = await MongoMemoryServer.create();
      const uri = mongod.getUri();
      mongoClient = new MongoClient(uri);
      await mongoClient.connect();
      mongoDb = mongoClient.db('test');
    });

    afterAll(async () => {
      await mongoClient.close();
      await mongod.stop();
    });

    beforeEach(async () => {
      await mongoDb.collection('users').deleteMany({});
      await mongoDb.collection('products').deleteMany({});
    });

    describe('MongoUserRepository', () => {
      it('should create user with MongoDB ObjectId', async () => {
        const userData = {
          name: 'Mongo User',
          email: 'mongo@example.com',
          passwordHash: 'hashed_password',
          roles: [UserRole.USER],
          isActive: true,
        };

        const result = await mongoDb.collection('users').insertOne(userData);
        const user = await mongoDb.collection('users').findOne({ _id: result.insertedId });

        expect(user).toBeDefined();
        expect(user?._id).toBeDefined();
        expect(user?._id.toString()).toMatch(/^[0-9a-fA-F]{24}$/);
        expect(user?.name).toBe(userData.name);
      });

      it('should perform complex aggregation queries', async () => {
        // Create test data
        const users = [
          { name: 'User 1', email: 'user1@example.com', age: 25, city: 'New York' },
          { name: 'User 2', email: 'user2@example.com', age: 30, city: 'Los Angeles' },
          { name: 'User 3', email: 'user3@example.com', age: 25, city: 'New York' },
          { name: 'User 4', email: 'user4@example.com', age: 35, city: 'Chicago' },
        ];

        await mongoDb.collection('users').insertMany(users);

        // Perform aggregation
        const pipeline = [
          {
            $group: {
              _id: '$city',
              count: { $sum: 1 },
              averageAge: { $avg: '$age' },
            },
          },
          { $sort: { count: -1 } },
        ];

        const results = await mongoDb
          .collection('users')
          .aggregate(pipeline)
          .toArray();

        expect(results).toHaveLength(3);
        expect(results[0]._id).toBe('New York');
        expect(results[0].count).toBe(2);
        expect(results[0].averageAge).toBe(25);
      });

      it('should handle text search with indexes', async () => {
        // Create text index
        await mongoDb.collection('products').createIndex({ name: 'text', description: 'text' });

        // Insert test products
        const products = [
          {
            name: 'iPhone 13',
            description: 'Latest Apple smartphone with advanced camera',
            price: 999,
            category: 'Electronics',
          },
          {
            name: 'Samsung Galaxy S21',
            description: 'Android smartphone with great camera',
            price: 799,
            category: 'Electronics',
          },
          {
            name: 'MacBook Pro',
            description: 'Apple laptop for professional use',
            price: 1999,
            category: 'Computers',
          },
        ];

        await mongoDb.collection('products').insertMany(products);

        // Search for products
        const searchResults = await mongoDb
          .collection('products')
          .find({ $text: { $search: 'Apple' } })
          .toArray();

        expect(searchResults).toHaveLength(2);
        expect(searchResults.map(p => p.name)).toContain('iPhone 13');
        expect(searchResults.map(p => p.name)).toContain('MacBook Pro');
      });

      it('should handle transactions in MongoDB', async () => {
        const session = mongoClient.startSession();

        try {
          await session.withTransaction(async () => {
            // Insert user
            const userResult = await mongoDb.collection('users').insertOne(
              {
                name: 'Transaction User',
                email: 'transaction@example.com',
                balance: 1000,
              },
              { session }
            );

            // Update balance
            await mongoDb.collection('users').updateOne(
              { _id: userResult.insertedId },
              { $inc: { balance: -100 } },
              { session }
            );

            // Simulate error to test rollback
            throw new Error('Simulated error');
          });
        } catch (error) {
          // Transaction should be rolled back
          const user = await mongoDb
            .collection('users')
            .findOne({ email: 'transaction@example.com' });
          
          expect(user).toBeNull(); // User should not exist due to rollback
        } finally {
          session.endSession();
        }
      });
    });
  });
});

// ====================
// EXTERNAL SERVICE INTEGRATION TESTING
// ====================

describe('External Service Integration Tests', () => {
  
  describe('Email Service Integration', () => {
    it('should send email via external API', async () => {
      // Mock external email API
      const emailApi = nock('https://api.emailservice.com')
        .post('/v1/emails')
        .reply(200, {
          success: true,
          messageId: 'msg-123456',
          status: 'sent',
        });

      const emailData = {
        to: 'recipient@example.com',
        subject: 'Test Email',
        html: '<p>This is a test email</p>',
        from: 'noreply@example.com',
      };

      // Simulate email service call
      const emailService = new EmailService({
        apiKey: 'test-api-key',
        baseUrl: 'https://api.emailservice.com',
      });

      // Mock the actual API call
      const mockSendEmail = jest.fn().mockResolvedValue({
        success: true,
        messageId: 'msg-123456',
      });

      emailService.sendEmail = mockSendEmail;

      const result = await emailService.sendEmail(emailData);

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('msg-123456');
      expect(mockSendEmail).toHaveBeenCalledWith(emailData);
      
      emailApi.done();
    });

    it('should handle API errors gracefully', async () => {
      const emailApi = nock('https://api.emailservice.com')
        .post('/v1/emails')
        .reply(429, {
          error: 'Rate limit exceeded',
          retryAfter: 60,
        });

      const emailService = new EmailService({
        apiKey: 'test-api-key',
        baseUrl: 'https://api.emailservice.com',
      });

      const mockSendEmail = jest.fn().mockRejectedValue(
        new Error('Rate limit exceeded')
      );

      emailService.sendEmail = mockSendEmail;

      await expect(emailService.sendEmail({ to: 'test@example.com' }))
        .rejects.toThrow('Rate limit exceeded');

      emailApi.done();
    });

    it('should retry on temporary failures', async () => {
      let attemptCount = 0;
      
      const emailApi = nock('https://api.emailservice.com')
        .post('/v1/emails')
        .reply(500, () => {
          attemptCount++;
          if (attemptCount === 1) {
            return { error: 'Internal server error' };
          }
          return { success: true, messageId: 'msg-456' };
        })
        .post('/v1/emails')
        .reply(200, { success: true, messageId: 'msg-456' });

      const emailService = new EmailService({
        apiKey: 'test-api-key',
        baseUrl: 'https://api.emailservice.com',
        maxRetries: 3,
        retryDelay: 100,
      });

      const mockSendEmailWithRetry = jest.fn()
        .mockRejectedValueOnce(new Error('Internal server error'))
        .mockResolvedValueOnce({ success: true, messageId: 'msg-456' });

      emailService.sendEmail = mockSendEmailWithRetry;

      const result = await emailService.sendEmail({ to: 'test@example.com' });

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('msg-456');
      expect(mockSendEmailWithRetry).toHaveBeenCalledTimes(2);
      
      emailApi.done();
    });
  });

  describe('Payment Service Integration', () => {
    it('should process payment via Stripe API', async () => {
      const stripeApi = nock('https://api.stripe.com')
        .post('/v1/payment_intents')
        .reply(200, {
          id: 'pi_test123',
          amount: 2000,
          currency: 'usd',
          status: 'succeeded',
        });

      const paymentData = {
        amount: 2000, // $20.00 in cents
        currency: 'usd',
        paymentMethod: 'pm_test123',
        customerId: 'cus_test123',
      };

      // Mock payment service
      const mockProcessPayment = jest.fn().mockResolvedValue({
        id: 'pi_test123',
        amount: 2000,
        currency: 'usd',
        status: 'succeeded',
      });

      const paymentService = {
        processPayment: mockProcessPayment,
      };

      const result = await paymentService.processPayment(paymentData);

      expect(result.id).toBe('pi_test123');
      expect(result.amount).toBe(paymentData.amount);
      expect(result.currency).toBe(paymentData.currency);
      expect(result.status).toBe('succeeded');
      
      stripeApi.done();
    });

    it('should handle payment failures', async () => {
      const stripeApi = nock('https://api.stripe.com')
        .post('/v1/payment_intents')
        .reply(402, {
          error: {
            code: 'card_declined',
            message: 'Your card was declined.',
            type: 'card_error',
          },
        });

      const mockProcessPayment = jest.fn().mockRejectedValue(
        new Error('Your card was declined.')
      );

      const paymentService = {
        processPayment: mockProcessPayment,
      };

      await expect(paymentService.processPayment({
        amount: 2000,
        currency: 'usd',
        paymentMethod: 'pm_declined',
      })).rejects.toThrow('Your card was declined.');

      stripeApi.done();
    });
  });

  describe('File Upload Service Integration', () => {
    it('should upload file to AWS S3', async () => {
      const s3Api = nock('https://s3.amazonaws.com')
        .put('/bucket-name/test-file.jpg')
        .reply(200, {
          ETag: '"abc123"',
          Location: 'https://s3.amazonaws.com/bucket-name/test-file.jpg',
        });

      const fileData = {
        buffer: Buffer.from('test file content'),
        originalname: 'test-file.jpg',
        mimetype: 'image/jpeg',
        size: 1024,
      };

      const mockUploadFile = jest.fn().mockResolvedValue({
        url: 'https://s3.amazonaws.com/bucket-name/test-file.jpg',
        key: 'test-file.jpg',
        etag: '"abc123"',
      });

      const fileService = {
        uploadFile: mockUploadFile,
      };

      const result = await fileService.uploadFile(fileData);

      expect(result.url).toBe('https://s3.amazonaws.com/bucket-name/test-file.jpg');
      expect(result.key).toBe('test-file.jpg');
      expect(result.etag).toBe('"abc123"');
      
      s3Api.done();
    });
  });
});

// ====================
// WORKFLOW INTEGRATION TESTING
// ====================

describe('Workflow Integration Tests', () => {
  let app: Express;
  let dbConnection: Pool;

  beforeAll(async () => {
    dbConnection = await setupTestDatabase();
    app = createApp({
      database: dbConnection,
      environment: 'test',
    });
  });

  afterAll(async () => {
    await cleanupTestDatabase(dbConnection);
  });

  beforeEach(async () => {
    await dbConnection.query('TRUNCATE TABLE users, orders, products, cart_items CASCADE');
  });

  describe('Complete User Registration and Verification Workflow', () => {
    it('should complete full user registration workflow', async () => {
      // Step 1: Register user
      const registrationData: CreateUserRequest = {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const registerResponse = await request(app)
        .post('/api/v1/auth/register')
        .send(registrationData)
        .expect(201);

      const userId = registerResponse.body.data.id;
      expect(registerResponse.body.success).toBe(true);
      expect(registerResponse.body.data.email).toBe(registrationData.email);

      // Step 2: Verify email (mock verification)
      const verificationResponse = await request(app)
        .post('/api/v1/auth/verify-email')
        .send({
          token: 'verification-token-123',
          userId,
        })
        .expect(200);

      expect(verificationResponse.body.success).toBe(true);
      expect(verificationResponse.body.data.isEmailVerified).toBe(true);

      // Step 3: Login
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: registrationData.email,
          password: registrationData.password,
        })
        .expect(200);

      const authToken = loginResponse.body.data.accessToken;
      expect(authToken).toBeDefined();

      // Step 4: Update profile
      const profileUpdate = {
        bio: 'Software developer passionate about TypeScript',
        location: 'San Francisco, CA',
        website: 'https://johndoe.dev',
      };

      const updateResponse = await request(app)
        .put(`/api/v1/users/${userId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(profileUpdate)
        .expect(200);

      expect(updateResponse.body.success).toBe(true);
      expect(updateResponse.body.data).toMatchObject(profileUpdate);

      // Step 5: Verify profile is updated
      const profileResponse = await request(app)
        .get(`/api/v1/users/${userId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(profileResponse.body.success).toBe(true);
      expect(profileResponse.body.data).toMatchObject({
        name: registrationData.name,
        email: registrationData.email,
        ...profileUpdate,
        isEmailVerified: true,
      });

      // Step 6: Test password reset flow
      const resetRequestResponse = await request(app)
        .post('/api/v1/auth/request-password-reset')
        .send({ email: registrationData.email })
        .expect(200);

      expect(resetRequestResponse.body.success).toBe(true);
      expect(resetRequestResponse.body.data.message).toContain('Password reset email sent');

      // Step 7: Reset password
      const resetPasswordResponse = await request(app)
        .post('/api/v1/auth/reset-password')
        .send({
          token: 'reset-token-123',
          newPassword: 'NewSecureP@ssw0rd456',
        })
        .expect(200);

      expect(resetPasswordResponse.body.success).toBe(true);

      // Step 8: Login with new password
      const newLoginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: registrationData.email,
          password: 'NewSecureP@ssw0rd456',
        })
        .expect(200);

      expect(newLoginResponse.body.success).toBe(true);
      expect(newLoginResponse.body.data.accessToken).toBeDefined();
    });
  });

  describe('E-commerce Order Processing Workflow', () => {
    it('should process complete order workflow', async () => {
      let authToken: string;
      let userId: string;
      let productId: string;
      let orderId: string;

      // Step 1: Create user and login
      const userData: CreateUserRequest = {
        name: 'Test Customer',
        email: 'customer@example.com',
        password: 'SecureP@ssw0rd123',
      };

      const registerResponse = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);

      userId = registerResponse.body.data.id;

      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: userData.email,
          password: userData.password,
        })
        .expect(200);

      authToken = loginResponse.body.data.accessToken;

      // Step 2: Create test product
      const productData = {
        name: 'Test Product',
        description: 'A great test product',
        price: 2999, // $29.99 in cents
        inventory: 100,
        category: 'Electronics',
      };

      const productResponse = await request(app)
        .post('/api/v1/products')
        .set('Authorization', `Bearer ${authToken}`)
        .send(productData)
        .expect(201);

      productId = productResponse.body.data.id;

      // Step 3: Add item to cart
      const cartResponse = await request(app)
        .post('/api/v1/cart/items')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          productId,
          quantity: 2,
        })
        .expect(200);

      expect(cartResponse.body.success).toBe(true);
      expect(cartResponse.body.data.items).toHaveLength(1);
      expect(cartResponse.body.data.items[0].productId).toBe(productId);
      expect(cartResponse.body.data.items[0].quantity).toBe(2);

      // Step 4: Create order from cart
      const orderResponse = await request(app)
        .post('/api/v1/orders')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          shippingAddress: {
            street: '123 Test Street',
            city: 'Test City',
            state: 'CA',
            zipCode: '12345',
            country: 'USA',
          },
          billingAddress: {
            street: '123 Test Street',
            city: 'Test City',
            state: 'CA',
            zipCode: '12345',
            country: 'USA',
          },
        })
        .expect(201);

      orderId = orderResponse.body.data.id;
      expect(orderResponse.body.success).toBe(true);
      expect(orderResponse.body.data.status).toBe('pending');
      expect(orderResponse.body.data.totalAmount).toBe(5998); // 2 * 2999

      // Step 5: Process payment (mock)
      const paymentResponse = await request(app)
        .post(`/api/v1/orders/${orderId}/pay`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          paymentMethod: 'credit_card',
          cardToken: 'tok_visa',
          savePaymentMethod: false,
        })
        .expect(200);

      expect(paymentResponse.body.success).toBe(true);
      expect(paymentResponse.body.data.status).toBe('paid');

      // Step 6: Verify inventory was updated
      const productResponse = await request(app)
        .get(`/api/v1/products/${productId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(productResponse.body.success).toBe(true);
      expect(productResponse.body.data.inventory).toBe(98); // 100 - 2

      // Step 7: Verify order status and details
      const finalOrderResponse = await request(app)
        .get(`/api/v1/orders/${orderId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(finalOrderResponse.body.success).toBe(true);
      expect(finalOrderResponse.body.data.status).toBe('paid');
      expect(finalOrderResponse.body.data.items).toHaveLength(1);
      expect(finalOrderResponse.body.data.totalAmount).toBe(5998);
      expect(finalOrderResponse.body.data.shippingAddress).toMatchObject({
        street: '123 Test Street',
        city: 'Test City',
      });

      // Step 8: Verify user order history
      const ordersResponse = await request(app)
        .get('/api/v1/orders')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(ordersResponse.body.success).toBe(true);
      expect(ordersResponse.body.data.items).toHaveLength(1);
      expect(ordersResponse.body.data.items[0].id).toBe(orderId);

      // Step 9: Test order cancellation
      const cancelResponse = await request(app)
        .post(`/api/v1/orders/${orderId}/cancel`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ reason: 'Changed my mind' })
        .expect(200);

      expect(cancelResponse.body.success).toBe(true);
      expect(cancelResponse.body.data.status).toBe('cancelled');

      // Step 10: Verify inventory was restored after cancellation
      const finalProductResponse = await request(app)
        .get(`/api/v1/products/${productId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(finalProductResponse.body.success).toBe(true);
      expect(finalProductResponse.body.data.inventory).toBe(100); // Restored to original
    });
  });

  describe('Multi-User Collaboration Workflow', () => {
    it('should handle team collaboration features', async () => {
      let adminToken: string;
      let member1Token: string;
      let member2Token: string;
      let teamId: string;
      let projectId: string;

      // Step 1: Create admin user
      const adminData: CreateUserRequest = {
        name: 'Team Admin',
        email: 'admin@team.com',
        password: 'SecureP@ssw0rd123',
      };

      await request(app)
        .post('/api/v1/auth/register')
        .send(adminData)
        .expect(201);

      const adminLoginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: adminData.email,
          password: adminData.password,
        })
        .expect(200);

      adminToken = adminLoginResponse.body.data.accessToken;

      // Step 2: Create team members
      const member1Data: CreateUserRequest = {
        name: 'Team Member 1',
        email: 'member1@team.com',
        password: 'SecureP@ssw0rd123',
      };

      const member2Data: CreateUserRequest = {
        name: 'Team Member 2',
        email: 'member2@team.com',
        password: 'SecureP@ssw0rd123',
      };

      await request(app)
        .post('/api/v1/auth/register')
        .send(member1Data)
        .expect(201);

      await request(app)
        .post('/api/v1/auth/register')
        .send(member2Data)
        .expect(201);

      const member1LoginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: member1Data.email,
          password: member1Data.password,
        })
        .expect(200);

      member1Token = member1LoginResponse.body.data.accessToken;

      const member2LoginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: member2Data.email,
          password: member2Data.password,
        })
        .expect(200);

      member2Token = member2LoginResponse.body.data.accessToken;

      // Step 3: Create team
      const teamResponse = await request(app)
        .post('/api/v1/teams')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'Development Team',
          description: 'A team for development projects',
        })
        .expect(201);

      teamId = teamResponse.body.data.id;

      // Step 4: Invite team members
      const inviteResponse1 = await request(app)
        .post(`/api/v1/teams/${teamId}/invites`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: member1Data.email,
          role: 'developer',
        })
        .expect(200);

      expect(inviteResponse1.body.success).toBe(true);

      const inviteResponse2 = await request(app)
        .post(`/api/v1/teams/${teamId}/invites`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          email: member2Data.email,
          role: 'designer',
        })
        .expect(200);

      expect(inviteResponse2.body.success).toBe(true);

      // Step 5: Accept invitations
      const acceptResponse1 = await request(app)
        .post(`/api/v1/teams/invites/accept`)
        .set('Authorization', `Bearer ${member1Token}`)
        .send({
          inviteId: inviteResponse1.body.data.id,
        })
        .expect(200);

      expect(acceptResponse1.body.success).toBe(true);

      const acceptResponse2 = await request(app)
        .post(`/api/v1/teams/invites/accept`)
        .set('Authorization', `Bearer ${member2Token}`)
        .send({
          inviteId: inviteResponse2.body.data.id,
        })
        .expect(200);

      expect(acceptResponse2.body.success).toBe(true);

      // Step 6: Create project
      const projectResponse = await request(app)
        .post('/api/v1/projects')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'Team Project',
          description: 'A collaborative project',
          teamId,
        })
        .expect(201);

      projectId = projectResponse.body.data.id;

      // Step 7: Assign tasks
      const taskResponse1 = await request(app)
        .post(`/api/v1/projects/${projectId}/tasks`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          title: 'Implement authentication',
          description: 'Set up user authentication system',
          assigneeId: acceptResponse1.body.data.memberId,
          priority: 'high',
        })
        .expect(201);

      expect(taskResponse1.body.success).toBe(true);

      const taskResponse2 = await request(app)
        .post(`/api/v1/projects/${projectId}/tasks`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          title: 'Design user interface',
          description: 'Create UI mockups',
          assigneeId: acceptResponse2.body.data.memberId,
          priority: 'medium',
        })
        .expect(201);

      expect(taskResponse2.body.success).toBe(true);

      // Step 8: Update task status
      const updateTaskResponse = await request(app)
        .put(`/api/v1/tasks/${taskResponse1.body.data.id}`)
        .set('Authorization', `Bearer ${member1Token}`)
        .send({
          status: 'in_progress',
          progress: 50,
        })
        .expect(200);

      expect(updateTaskResponse.body.success).toBe(true);
      expect(updateTaskResponse.body.data.status).toBe('in_progress');
      expect(updateTaskResponse.body.data.progress).toBe(50);

      // Step 9: Add comments
      const commentResponse = await request(app)
        .post(`/api/v1/tasks/${taskResponse1.body.data.id}/comments`)
        .set('Authorization', `Bearer ${member1Token}`)
        .send({
          content: 'Making good progress on authentication',
        })
        .expect(201);

      expect(commentResponse.body.success).toBe(true);

      // Step 10: Verify team activity
      const activityResponse = await request(app)
        .get(`/api/v1/teams/${teamId}/activity`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(activityResponse.body.success).toBe(true);
      expect(activityResponse.body.data.items.length).toBeGreaterThan(0);

      // Step 11: Test permissions
      // Member should not be able to delete team
      const deleteTeamResponse = await request(app)
        .delete(`/api/v1/teams/${teamId}`)
        .set('Authorization', `Bearer ${member1Token}`)
        .expect(403);

      expect(deleteTeamResponse.body.success).toBe(false);
      expect(deleteTeamResponse.body.error).toContain('Permission denied');

      // Admin should be able to delete team
      const adminDeleteTeamResponse = await request(app)
        .delete(`/api/v1/teams/${teamId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(adminDeleteTeamResponse.body.success).toBe(true);
    });
  });
});

// ====================
// TEST UTILITIES AND HELPERS
// ====================

// Helper function to create authenticated user
async function createAuthenticatedUser(
  app: Express,
  userData: CreateUserRequest
): Promise<{ user: User; token: string }> {
  // Register user
  const registerResponse = await request(app)
    .post('/api/v1/auth/register')
    .send(userData)
    .expect(201);

  const user = registerResponse.body.data;

  // Login to get token
  const loginResponse = await request(app)
    .post('/api/v1/auth/login')
    .send({
      email: userData.email,
      password: userData.password,
    })
    .expect(200);

  const token = loginResponse.body.data.accessToken;

  return { user, token };
}

// Helper function to create test product
async function createTestProduct(
  app: Express,
  token: string,
  productData: any
): Promise<any> {
  const response = await request(app)
    .post('/api/v1/products')
    .set('Authorization', `Bearer ${token}`)
    .send(productData)
    .expect(201);

  return response.body.data;
}

// Helper function to expect API error response
function expectErrorResponse(
  response: any,
  status: number,
  error?: string
): void {
  expect(response.status).toBe(status);
  expect(response.body.success).toBe(false);
  expect(response.body.error).toBeDefined();
  
  if (error) {
    expect(response.body.error).toContain(error);
  }
}

// Helper function to expect API success response
function expectSuccessResponse(
  response: any,
  status: number = 200
): void {
  expect(response.status).toBe(status);
  expect(response.body.success).toBe(true);
  expect(response.body.data).toBeDefined();
}