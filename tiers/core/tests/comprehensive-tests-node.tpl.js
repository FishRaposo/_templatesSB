/**
 * Template: comprehensive-tests-node.tpl.js
 * Purpose: comprehensive-tests-node template
 * Stack: node
 * Tier: base
 */

# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: core
# Stack: unknown
# Category: testing

# Comprehensive Node.js Testing Template
# Purpose: Core-level testing template with unit, integration, and feature tests for Node.js applications
# Usage: Copy to test/ directory and customize for your Node.js project
# Stack: Node.js (.js)
# Tier: Core (Production Ready)

## Purpose

Core-level Node.js testing template providing comprehensive testing coverage including unit tests, integration tests, and feature tests for production-ready applications. Focuses on testing business logic, API endpoints, data persistence, and complete user features.

## Usage

```bash
# Copy to your Node.js project
cp _templates/tiers/core/tests/comprehensive-tests-node.tpl.js test/comprehensive.test.js

# Install dependencies
npm install --save-dev jest supertest mongodb-memory-server

# Run tests
npm test

# Run with coverage
npm run test:coverage

# Run integration tests
npm run test:integration
```

## Structure

```javascript
// test/comprehensive.test.js
const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/User');
const Product = require('../src/models/Product');
const UserService = require('../src/services/UserService');
const ProductService = require('../src/services/ProductService');
const AuthService = require('../src/services/AuthService');
const { ValidationError, NotFoundError, AuthenticationError } = require('../src/errors');

// Test Setup and Teardown
let mongoServer;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  await mongoose.connect(mongoUri);
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  await User.deleteMany({});
  await Product.deleteMany({});
});

// Test Fixtures
const createMockUser = (overrides = {}) => ({
  name: 'Test User',
  email: 'test@example.com',
  password: 'SecurePass123!',
  age: 25,
  active: true,
  ...overrides
});

const createMockProduct = (overrides = {}) => ({
  name: 'Test Product',
  price: 10.99,
  quantity: 100,
  category: 'electronics',
  ...overrides
});

// Unit Tests - Business Logic
describe('User Model', () => {
  test('should create user with valid data', async () => {
    const userData = createMockUser();
    const user = new User(userData);
    
    await user.save();
    
    expect(user.name).toBe(userData.name);
    expect(user.email).toBe(userData.email);
    expect(user.age).toBe(userData.age);
    expect(user.active).toBe(true);
    expect(user.id).toBeDefined();
  });

  test('should validate user data correctly', async () => {
    const invalidUser = new User({
      name: '', // Invalid empty name
      email: 'invalid-email',
      age: 15, // Underage
      password: 'weak' // Weak password
    });
    
    await expect(invalidUser.save()).rejects.toThrow();
  });

  test('should hash password before saving', async () => {
    const userData = createMockUser();
    const user = new User(userData);
    
    await user.save();
    
    expect(user.password).not.toBe(userData.password);
    expect(user.password.length).toBeGreaterThan(20); // Hashed password
  });

  test('should verify password correctly', async () => {
    const userData = createMockUser();
    const user = new User(userData);
    
    await user.save();
    
    const isValid = await user.verifyPassword(userData.password);
    expect(isValid).toBe(true);
    
    const isInvalid = await user.verifyPassword('wrongpassword');
    expect(isInvalid).toBe(false);
  });

  test('should calculate user display name', async () => {
    const userData = createMockUser({ name: 'John Doe' });
    const user = new User(userData);
    
    await user.save();
    
    expect(user.displayName).toBe('John Doe');
    
    user.name = '';
    expect(user.displayName).toBe(userData.email);
  });

  test('should check if user is adult', async () => {
    const adultUser = new User(createMockUser({ age: 25 }));
    const minorUser = new User(createMockUser({ age: 17 }));
    
    expect(adultUser.isAdult()).toBe(true);
    expect(minorUser.isAdult()).toBe(false);
  });
});

describe('Product Model', () => {
  test('should create product with valid data', async () => {
    const productData = createMockProduct();
    const product = new Product(productData);
    
    await product.save();
    
    expect(product.name).toBe(productData.name);
    expect(product.price).toBe(productData.price);
    expect(product.quantity).toBe(productData.quantity);
    expect(product.category).toBe(productData.category);
    expect(product.id).toBeDefined();
  });

  test('should validate product data correctly', async () => {
    const invalidProduct = new Product({
      name: '', // Invalid empty name
      price: -10, // Negative price
      quantity: -5, // Negative quantity
      category: 'invalid_category'
    });
    
    await expect(invalidProduct.save()).rejects.toThrow();
  });

  test('should calculate total value correctly', async () => {
    const productData = createMockProduct({ price: 10.99, quantity: 5 });
    const product = new Product(productData);
    
    await product.save();
    
    expect(product.totalValue).toBe(54.95); // 10.99 * 5
  });

  test('should check stock availability', async () => {
    const inStockProduct = new Product(createMockProduct({ quantity: 10 }));
    const outOfStockProduct = new Product(createMockProduct({ quantity: 0 }));
    
    await inStockProduct.save();
    await outOfStockProduct.save();
    
    expect(inStockProduct.isInStock).toBe(true);
    expect(outOfStockProduct.isInStock).toBe(false);
  });

  test('should validate price correctly', async () => {
    const validProduct = new Product(createMockProduct({ price: 10.99 }));
    const invalidProduct = new Product(createMockProduct({ price: -10 }));
    
    await validProduct.save();
    
    expect(validProduct.hasValidPrice).toBe(true);
    await expect(invalidProduct.save()).rejects.toThrow();
  });
});

describe('User Service', () => {
  let userService;
  
  beforeEach(() => {
    userService = new UserService();
  });

  test('should create user successfully', async () => {
    const userData = createMockUser();
    
    const result = await userService.createUser(userData);
    
    expect(result).toBeDefined();
    expect(result.name).toBe(userData.name);
    expect(result.email).toBe(userData.email);
    expect(result.password).not.toBe(userData.password); // Should be hashed
  });

  test('should throw validation error for invalid user data', async () => {
    const invalidUserData = createMockUser({
      name: '',
      email: 'invalid-email',
      age: 15,
      password: 'weak'
    });
    
    await expect(userService.createUser(invalidUserData))
      .rejects.toThrow(ValidationError);
  });

  test('should get user by ID successfully', async () => {
    const userData = createMockUser();
    const createdUser = await userService.createUser(userData);
    
    const result = await userService.getUserById(createdUser.id);
    
    expect(result.id).toBe(createdUser.id);
    expect(result.name).toBe(createdUser.name);
  });

  test('should throw not found error for non-existent user', async () => {
    await expect(userService.getUserById('507f1f77bcf86cd799439011'))
      .rejects.toThrow(NotFoundError);
  });

  test('should update user successfully', async () => {
    const userData = createMockUser();
    const createdUser = await userService.createUser(userData);
    
    const updateData = { name: 'Updated Name', age: 26 };
    const result = await userService.updateUser(createdUser.id, updateData);
    
    expect(result.name).toBe('Updated Name');
    expect(result.age).toBe(26);
  });

  test('should delete user successfully', async () => {
    const userData = createMockUser();
    const createdUser = await userService.createUser(userData);
    
    const result = await userService.deleteUser(createdUser.id);
    
    expect(result).toBe(true);
    
    await expect(userService.getUserById(createdUser.id))
      .rejects.toThrow(NotFoundError);
  });

  test('should get users by age range', async () => {
    const users = [
      createMockUser({ name: 'User 1', age: 20 }),
      createMockUser({ name: 'User 2', age: 25 }),
      createMockUser({ name: 'User 3', age: 30 }),
      createMockUser({ name: 'User 4', age: 35 })
    ];
    
    for (const userData of users) {
      await userService.createUser(userData);
    }
    
    const result = await userService.getUsersByAgeRange(25, 30);
    
    expect(result).toHaveLength(2);
    expect(result.map(u => u.name)).toEqual(['User 2', 'User 3']);
  });
});

describe('Product Service', () => {
  let productService;
  
  beforeEach(() => {
    productService = new ProductService();
  });

  test('should create product successfully', async () => {
    const productData = createMockProduct();
    
    const result = await productService.createProduct(productData);
    
    expect(result).toBeDefined();
    expect(result.name).toBe(productData.name);
    expect(result.price).toBe(productData.price);
    expect(result.quantity).toBe(productData.quantity);
  });

  test('should throw validation error for invalid product data', async () => {
    const invalidProductData = createMockProduct({
      name: '',
      price: -10,
      quantity: -5
    });
    
    await expect(productService.createProduct(invalidProductData))
      .rejects.toThrow(ValidationError);
  });

  test('should update product stock successfully', async () => {
    const productData = createMockProduct({ quantity: 50 });
    const createdProduct = await productService.createProduct(productData);
    
    const result = await productService.updateStock(createdProduct.id, 25); // Add 25
    
    expect(result.quantity).toBe(75);
  });

  test('should get products by category', async () => {
    const products = [
      createMockProduct({ name: 'Phone', category: 'electronics' }),
      createMockProduct({ name: 'Laptop', category: 'electronics' }),
      createMockProduct({ name: 'Book', category: 'books' })
    ];
    
    for (const productData of products) {
      await productService.createProduct(productData);
    }
    
    const result = await productService.getProductsByCategory('electronics');
    
    expect(result).toHaveLength(2);
    expect(result.map(p => p.name)).toEqual(['Phone', 'Laptop']);
  });

  test('should search products by name', async () => {
    const products = [
      createMockProduct({ name: 'iPhone 13' }),
      createMockProduct({ name: 'iPhone 14' }),
      createMockProduct({ name: 'Samsung Galaxy' })
    ];
    
    for (const productData of products) {
      await productService.createProduct(productData);
    }
    
    const result = await productService.searchProducts('iPhone');
    
    expect(result).toHaveLength(2);
    expect(result.map(p => p.name)).toEqual(['iPhone 13', 'iPhone 14']);
  });
});

describe('Auth Service', () => {
  let authService;
  let testUser;
  
  beforeEach(async () => {
    authService = new AuthService();
    testUser = await new User(createMockUser()).save();
  });

  test('should authenticate user with valid credentials', async () => {
    const result = await authService.signIn(testUser.email, 'SecurePass123!');
    
    expect(result).toBeDefined();
    expect(result.token).toBeDefined();
    expect(result.user.id).toBe(testUser.id);
  });

  test('should reject authentication with invalid password', async () => {
    await expect(authService.signIn(testUser.email, 'wrongpassword'))
      .rejects.toThrow(AuthenticationError);
  });

  test('should reject authentication with non-existent user', async () => {
    await expect(authService.signIn('nonexistent@example.com', 'password'))
      .rejects.toThrow(AuthenticationError);
  });

  test('should generate valid JWT token', async () => {
    const result = await authService.signIn(testUser.email, 'SecurePass123!');
    
    expect(result.token).toBeDefined();
    expect(typeof result.token).toBe('string');
    expect(result.token.length).toBeGreaterThan(50);
  });

  test('should verify token correctly', async () => {
    const signInResult = await authService.signIn(testUser.email, 'SecurePass123!');
    const decoded = authService.verifyToken(signInResult.token);
    
    expect(decoded.userId).toBe(testUser.id.toString());
    expect(decoded.email).toBe(testUser.email);
  });

  test('should reject invalid token', async () => {
    expect(() => authService.verifyToken('invalid.token.here'))
      .toThrow(AuthenticationError);
  });
});

// Integration Tests - API Endpoints
describe('User API Endpoints', () => {
  test('POST /api/users should create user successfully', async () => {
    const userData = createMockUser();
    
    const response = await request(app)
      .post('/api/users')
      .send(userData)
      .expect(201);
    
    expect(response.body.name).toBe(userData.name);
    expect(response.body.email).toBe(userData.email);
    expect(response.body.password).toBeUndefined(); // Password should not be returned
  });

  test('POST /api/users should validate input data', async () => {
    const invalidUserData = createMockUser({
      name: '',
      email: 'invalid-email',
      age: 15,
      password: 'weak'
    });
    
    const response = await request(app)
      .post('/api/users')
      .send(invalidUserData)
      .expect(400);
    
    expect(response.body.error).toBeDefined();
  });

  test('GET /api/users/:id should return user successfully', async () => {
    const userData = createMockUser();
    const createdUser = await new User(userData).save();
    
    const response = await request(app)
      .get(`/api/users/${createdUser.id}`)
      .expect(200);
    
    expect(response.body.id).toBe(createdUser.id);
    expect(response.body.name).toBe(createdUser.name);
    expect(response.body.email).toBe(createdUser.email);
  });

  test('GET /api/users/:id should return 404 for non-existent user', async () => {
    const response = await request(app)
      .get('/api/users/507f1f77bcf86cd799439011')
      .expect(404);
    
    expect(response.body.error).toContain('not found');
  });

  test('PUT /api/users/:id should update user successfully', async () => {
    const userData = createMockUser();
    const createdUser = await new User(userData).save();
    
    const updateData = { name: 'Updated Name', age: 26 };
    
    const response = await request(app)
      .put(`/api/users/${createdUser.id}`)
      .send(updateData)
      .expect(200);
    
    expect(response.body.name).toBe('Updated Name');
    expect(response.body.age).toBe(26);
  });

  test('DELETE /api/users/:id should delete user successfully', async () => {
    const userData = createMockUser();
    const createdUser = await new User(userData).save();
    
    await request(app)
      .delete(`/api/users/${createdUser.id}`)
      .expect(204);
    
    await request(app)
      .get(`/api/users/${createdUser.id}`)
      .expect(404);
  });

  test('GET /api/users should return paginated user list', async () => {
    // Create test users
    const users = Array.from({ length: 25 }, (_, i) => 
      createMockUser({ name: `User ${i}`, email: `user${i}@example.com` })
    );
    
    for (const userData of users) {
      await new User(userData).save();
    }
    
    const response = await request(app)
      .get('/api/users?page=1&limit=10')
      .expect(200);
    
    expect(response.body.users).toHaveLength(10);
    expect(response.body.total).toBe(25);
    expect(response.body.page).toBe(1);
    expect(response.body.totalPages).toBe(3);
  });
});

describe('Product API Endpoints', () => {
  test('POST /api/products should create product successfully', async () => {
    const productData = createMockProduct();
    
    const response = await request(app)
      .post('/api/products')
      .send(productData)
      .expect(201);
    
    expect(response.body.name).toBe(productData.name);
    expect(response.body.price).toBe(productData.price);
    expect(response.body.quantity).toBe(productData.quantity);
  });

  test('GET /api/products should return product list', async () => {
    const products = [
      createMockProduct({ name: 'Product 1' }),
      createMockProduct({ name: 'Product 2' }),
      createMockProduct({ name: 'Product 3' })
    ];
    
    for (const productData of products) {
      await new Product(productData).save();
    }
    
    const response = await request(app)
      .get('/api/products')
      .expect(200);
    
    expect(response.body).toHaveLength(3);
    expect(response.body.map(p => p.name)).toEqual(['Product 1', 'Product 2', 'Product 3']);
  });

  test('GET /api/products?category=electronics should filter by category', async () => {
    const products = [
      createMockProduct({ name: 'Phone', category: 'electronics' }),
      createMockProduct({ name: 'Laptop', category: 'electronics' }),
      createMockProduct({ name: 'Book', category: 'books' })
    ];
    
    for (const productData of products) {
      await new Product(productData).save();
    }
    
    const response = await request(app)
      .get('/api/products?category=electronics')
      .expect(200);
    
    expect(response.body).toHaveLength(2);
    expect(response.body.map(p => p.name)).toEqual(['Phone', 'Laptop']);
  });

  test('PUT /api/products/:id/stock should update product stock', async () => {
    const productData = createMockProduct({ quantity: 50 });
    const createdProduct = await new Product(productData).save();
    
    const response = await request(app)
      .put(`/api/products/${createdProduct.id}/stock`)
      .send({ quantity: 25 })
      .expect(200);
    
    expect(response.body.quantity).toBe(75);
  });

  test('GET /api/products/search should search products', async () => {
    const products = [
      createMockProduct({ name: 'iPhone 13' }),
      createMockProduct({ name: 'iPhone 14' }),
      createMockProduct({ name: 'Samsung Galaxy' })
    ];
    
    for (const productData of products) {
      await new Product(productData).save();
    }
    
    const response = await request(app)
      .get('/api/products/search?q=iPhone')
      .expect(200);
    
    expect(response.body).toHaveLength(2);
    expect(response.body.map(p => p.name)).toEqual(['iPhone 13', 'iPhone 14']);
  });
});

describe('Authentication API Endpoints', () => {
  let testUser;
  
  beforeEach(async () => {
    testUser = await new User(createMockUser()).save();
  });

  test('POST /api/auth/signin should authenticate user', async () => {
    const response = await request(app)
      .post('/api/auth/signin')
      .send({
        email: testUser.email,
        password: 'SecurePass123!'
      })
      .expect(200);
    
    expect(response.body.token).toBeDefined();
    expect(response.body.user.id).toBe(testUser.id);
    expect(response.body.user.email).toBe(testUser.email);
  });

  test('POST /api/auth/signin should reject invalid credentials', async () => {
    const response = await request(app)
      .post('/api/auth/signin')
      .send({
        email: testUser.email,
        password: 'wrongpassword'
      })
      .expect(401);
    
    expect(response.body.error).toContain('invalid credentials');
  });

  test('GET /api/auth/profile should return user profile with valid token', async () => {
    const authService = new AuthService();
    const signInResult = await authService.signIn(testUser.email, 'SecurePass123!');
    
    const response = await request(app)
      .get('/api/auth/profile')
      .set('Authorization', `Bearer ${signInResult.token}`)
      .expect(200);
    
    expect(response.body.id).toBe(testUser.id);
    expect(response.body.email).toBe(testUser.email);
  });

  test('GET /api/auth/profile should reject request without token', async () => {
    const response = await request(app)
      .get('/api/auth/profile')
      .expect(401);
    
    expect(response.body.error).toContain('token required');
  });

  test('GET /api/auth/profile should reject request with invalid token', async () => {
    const response = await request(app)
      .get('/api/auth/profile')
      .set('Authorization', 'Bearer invalid.token.here')
      .expect(401);
    
    expect(response.body.error).toContain('invalid token');
  });
});

// Feature Tests - Complete User Workflows
describe('User Registration Feature', () => {
  test('should complete user registration workflow', async () => {
    const registrationData = {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'SecurePass123!',
      confirmPassword: 'SecurePass123!',
      age: 25,
      acceptTerms: true
    };
    
    // Register user
    const registerResponse = await request(app)
      .post('/api/auth/register')
      .send(registrationData)
      .expect(201);
    
    expect(registerResponse.body.user.name).toBe('John Doe');
    expect(registerResponse.body.user.email).toBe('john@example.com');
    expect(registerResponse.body.token).toBeDefined();
    
    // Sign in with new user
    const signInResponse = await request(app)
      .post('/api/auth/signin')
      .send({
        email: registrationData.email,
        password: registrationData.password
      })
      .expect(200);
    
    expect(signInResponse.body.user.id).toBe(registerResponse.body.user.id);
    
    // Get user profile
    const profileResponse = await request(app)
      .get('/api/auth/profile')
      .set('Authorization', `Bearer ${signInResponse.body.token}`)
      .expect(200);
    
    expect(profileResponse.body.name).toBe('John Doe');
  });

  test('should reject registration with weak password', async () => {
    const registrationData = {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'weak',
      confirmPassword: 'weak',
      age: 25,
      acceptTerms: true
    };
    
    const response = await request(app)
      .post('/api/auth/register')
      .send(registrationData)
      .expect(400);
    
    expect(response.body.error).toContain('password too weak');
  });

  test('should reject registration with password mismatch', async () => {
    const registrationData = {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'SecurePass123!',
      confirmPassword: 'DifferentPass123!',
      age: 25,
      acceptTerms: true
    };
    
    const response = await request(app)
      .post('/api/auth/register')
      .send(registrationData)
      .expect(400);
    
    expect(response.body.error).toContain('passwords do not match');
  });
});

describe('Product Purchase Feature', () => {
  let testUser, testProduct, authToken;
  
  beforeEach(async () => {
    testUser = await new User(createMockUser()).save();
    testProduct = await new Product(createMockProduct({ quantity: 100 })).save();
    
    const authService = new AuthService();
    const signInResult = await authService.signIn(testUser.email, 'SecurePass123!');
    authToken = signInResult.token;
  });

  test('should complete product purchase workflow', async () => {
    const purchaseData = {
      productId: testProduct.id,
      quantity: 5,
      paymentMethod: 'credit_card'
    };
    
    // Create purchase
    const purchaseResponse = await request(app)
      .post('/api/purchases')
      .set('Authorization', `Bearer ${authToken}`)
      .send(purchaseData)
      .expect(201);
    
    expect(purchaseResponse.body.productId).toBe(testProduct.id);
    expect(purchaseResponse.body.quantity).toBe(5);
    expect(purchaseResponse.body.totalAmount).toBe(54.95); // 5 * 10.99
    expect(purchaseResponse.body.status).toBe('completed');
    
    // Verify product stock was updated
    const productResponse = await request(app)
      .get(`/api/products/${testProduct.id}`)
      .expect(200);
    
    expect(productResponse.body.quantity).toBe(95); // 100 - 5
    
    // Get user's purchase history
    const historyResponse = await request(app)
      .get('/api/purchases/history')
      .set('Authorization', `Bearer ${authToken}`)
      .expect(200);
    
    expect(historyResponse.body).toHaveLength(1);
    expect(historyResponse.body[0].id).toBe(purchaseResponse.body.id);
  });

  test('should reject purchase with insufficient stock', async () => {
    // Update product to have low stock
    await Product.findByIdAndUpdate(testProduct.id, { quantity: 2 });
    
    const purchaseData = {
      productId: testProduct.id,
      quantity: 5,
      paymentMethod: 'credit_card'
    };
    
    const response = await request(app)
      .post('/api/purchases')
      .set('Authorization', `Bearer ${authToken}`)
      .send(purchaseData)
      .expect(400);
    
    expect(response.body.error).toContain('insufficient stock');
  });

  test('should reject purchase without authentication', async () => {
    const purchaseData = {
      productId: testProduct.id,
      quantity: 5,
      paymentMethod: 'credit_card'
    };
    
    const response = await request(app)
      .post('/api/purchases')
      .send(purchaseData)
      .expect(401);
    
    expect(response.body.error).toContain('authentication required');
  });
});

describe('User Dashboard Feature', () => {
  let testUser, testProducts, authToken;
  
  beforeEach(async () => {
    testUser = await new User(createMockUser()).save();
    
    // Create test products
    testProducts = await Promise.all([
      new Product(createMockProduct({ name: 'Product 1', price: 10.99 })).save(),
      new Product(createMockProduct({ name: 'Product 2', price: 20.50 })).save(),
      new Product(createMockProduct({ name: 'Product 3', price: 15.75 })).save()
    ]);
    
    const authService = new AuthService();
    const signInResult = await authService.signIn(testUser.email, 'SecurePass123!');
    authToken = signInResult.token;
  });

  test('should aggregate dashboard data correctly', async () => {
    // Simulate some purchases for the user
    const purchaseData = {
      userId: testUser.id,
      items: [
        { productId: testProducts[0].id, quantity: 2, price: testProducts[0].price },
        { productId: testProducts[1].id, quantity: 1, price: testProducts[1].price }
      ],
      totalAmount: 42.48, // 2*10.99 + 1*20.50
      status: 'completed'
    };
    
    await request(app)
      .post('/api/purchases')
      .set('Authorization', `Bearer ${authToken}`)
      .send(purchaseData);
    
    // Get dashboard data
    const response = await request(app)
      .get('/api/dashboard')
      .set('Authorization', `Bearer ${authToken}`)
      .expect(200);
    
    const dashboard = response.body;
    
    expect(dashboard.user.name).toBe(testUser.name);
    expect(dashboard.user.email).toBe(testUser.email);
    expect(dashboard.stats.totalPurchases).toBe(1);
    expect(dashboard.stats.totalSpent).toBe(42.48);
    expect(dashboard.stats.averageOrderValue).toBe(42.48);
    expect(dashboard.recentPurchases).toHaveLength(1);
    expect(dashboard.recommendedProducts).toBeDefined();
    expect(Array.isArray(dashboard.recommendedProducts)).toBe(true);
  });

  test('should handle empty dashboard for new user', async () => {
    const newUser = await new User(createMockUser({ email: 'newuser@example.com' })).save();
    
    const authService = new AuthService();
    const signInResult = await authService.signIn(newUser.email, 'SecurePass123!');
    const newUserToken = signInResult.token;
    
    const response = await request(app)
      .get('/api/dashboard')
      .set('Authorization', `Bearer ${newUserToken}`)
      .expect(200);
    
    const dashboard = response.body;
    
    expect(dashboard.stats.totalPurchases).toBe(0);
    expect(dashboard.stats.totalSpent).toBe(0);
    expect(dashboard.stats.averageOrderValue).toBe(0);
    expect(dashboard.recentPurchases).toHaveLength(0);
  });
});

// Performance Tests
describe('Performance Tests', () => {
  test('should handle large product list efficiently', async () => {
    // Create 1000 products
    const products = Array.from({ length: 1000 }, (_, i) => 
      createMockProduct({ name: `Product ${i}`, price: 10.99 + i })
    );
    
    const startTime = Date.now();
    
    await Promise.all(products.map(productData => 
      new Product(productData).save()
    ));
    
    const creationTime = Date.now() - startTime;
    expect(creationTime).toBeLessThan(5000); // Should complete within 5 seconds
    
    // Test retrieval performance
    const retrievalStart = Date.now();
    
    const response = await request(app)
      .get('/api/products')
      .expect(200);
    
    const retrievalTime = Date.now() - retrievalStart;
    expect(retrievalTime).toBeLessThan(1000); // Should complete within 1 second
    expect(response.body).toHaveLength(1000);
  });

  test('should handle concurrent user creation', async () => {
    const concurrentRequests = 50;
    const userData = createMockUser();
    
    const startTime = Date.now();
    
    const promises = Array.from({ length: concurrentRequests }, (_, i) => 
      request(app)
        .post('/api/users')
        .send({ ...userData, email: `user${i}@example.com` })
        .expect(201)
    );
    
    await Promise.all(promises);
    
    const totalTime = Date.now() - startTime;
    expect(totalTime).toBeLessThan(3000); // Should complete within 3 seconds
    
    // Verify all users were created
    const users = await User.find({});
    expect(users).toHaveLength(concurrentRequests);
  });
});

// Test Utilities and Helpers
class TestDataFactory {
  static createMockUser(overrides = {}) {
    return {
      name: 'Test User',
      email: 'test@example.com',
      password: 'SecurePass123!',
      age: 25,
      active: true,
      ...overrides
    };
  }

  static createMockProduct(overrides = {}) {
    return {
      name: 'Test Product',
      price: 10.99,
      quantity: 100,
      category: 'electronics',
      ...overrides
    };
  }

  static createMockUserList(count) {
    return Array.from({ length: count }, (_, i) => 
      this.createMockUser({ 
        name: `User ${i}`, 
        email: `user${i}@example.com` 
      })
    );
  }

  static createMockProductList(count) {
    return Array.from({ length: count }, (_, i) => 
      this.createMockProduct({ 
        name: `Product ${i}`, 
        price: 10.99 + i 
      })
    );
  }
}

class CustomAssertions {
  static assertValidUser(user) {
    expect(user.id).toBeDefined();
    expect(user.name).toBeTruthy();
    expect(user.email).toContain('@');
    expect(user.age).toBeGreaterThanOrEqual(18);
    expect(user.age).toBeLessThanOrEqual(120);
  }

  static assertValidProduct(product) {
    expect(product.id).toBeDefined();
    expect(product.name).toBeTruthy();
    expect(product.price).toBeGreaterThan(0);
    expect(product.quantity).toBeGreaterThanOrEqual(0);
  }

  static assertValidApiResponse(response, expectedStatus = 200) {
    expect(response.status).toBe(expectedStatus);
    
    if (expectedStatus < 400) {
      expect(response.body).toBeDefined();
    } else {
      expect(response.body.error || response.body.message).toBeDefined();
    }
  }
}

// Test Configuration
const testConfig = {
  timeout: 30000,
  mongoServer: {
    instance: {
      dbName: 'test_db'
    }
  },
  performance: {
    maxCreationTime: 5000,
    maxRetrievalTime: 1000,
    maxConcurrentTime: 3000
  }
};

module.exports = {
  TestDataFactory,
  CustomAssertions,
  testConfig,
  createMockUser,
  createMockProduct
};
```

## Guidelines

### Test Organization
- **Unit Tests**: Business logic, models, services with comprehensive validation
- **Integration Tests**: API endpoints and database interactions
- **Feature Tests**: Complete user workflows (registration, purchase, dashboard)
- **Performance Tests**: Concurrent operations and large dataset handling

### Test Structure
- Use `describe()` blocks to group related tests
- Use MongoDB Memory Server for isolated database testing
- Use Jest matchers for clear assertions
- Test both success and error paths

### Coverage Requirements
- **Unit Tests**: 85%+ coverage for business logic
- **Integration Tests**: 75%+ coverage for API endpoints
- **Feature Tests**: 70%+ coverage for user workflows
- **Overall**: 80%+ minimum for Core tier

## Required Dependencies

Add to `package.json`:

```json
{
  "devDependencies": {
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "mongodb-memory-server": "^8.15.1"
  },
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:integration": "jest --testPathPattern=integration"
  }
}
```

## What's Included

- **Unit Tests**: Business logic, models, services with comprehensive validation
- **Integration Tests**: Express.js endpoints and MongoDB interactions
- **Feature Tests**: Complete user workflows with authentication
- **Performance Tests**: Concurrent operations and large dataset handling
- **Test Helpers**: Data factories and custom assertions

## What's NOT Included

- Real database integration tests
- Third-party API integration tests
- Load testing with real traffic
- Security penetration tests

---

**Template Version**: 2.0 (Core)  
**Last Updated**: 2025-12-10  
**Stack**: Node.js  
**Tier**: Core  
**Framework**: Jest + Supertest + MongoDB Memory Server
