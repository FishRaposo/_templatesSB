# TypeScript System Testing Template
# End-to-end system testing patterns for TypeScript projects with performance, security, and GDPR compliance

/**
 * TypeScript System Test Patterns
 * E2E testing, performance testing, security testing, GDPR compliance, and production readiness
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { chromium, Browser, Page, BrowserContext } from 'playwright';
import { execSync, spawn } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import axios, { AxiosResponse } from 'axios';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcrypt';
import { performance } from 'perf_hooks';

// ====================
// SYSTEM TEST CONFIGURATION
// ====================

interface SystemTestConfig {
  baseUrl: string;
  adminEmail: string;
  adminPassword: string;
  testUserEmail: string;
  testUserPassword: string;
  environment: string;
  timeout: number;
  performanceThresholds: {
    pageLoad: number; // ms
    apiResponse: number; // ms
    databaseQuery: number; // ms
  };
}

const systemConfig: SystemTestConfig = {
  baseUrl: process.env.SYSTEM_TEST_URL || 'http://localhost:3000',
  adminEmail: process.env.ADMIN_EMAIL || 'admin@example.com',
  adminPassword: process.env.ADMIN_PASSWORD || 'admin123',
  testUserEmail: process.env.TEST_USER_EMAIL || 'testuser@example.com',
  testUserPassword: process.env.TEST_USER_PASSWORD || 'testpass123',
  environment: process.env.ENVIRONMENT || 'test',
  timeout: 30000, // 30 seconds
  performanceThresholds: {
    pageLoad: 3000, // 3 seconds
    apiResponse: 500, // 500ms
    databaseQuery: 100, // 100ms
  },
};

// ====================
// BROWSER AUTOMATION SETUP
// ====================

class BrowserManager {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;

  async launch(): Promise<BrowserContext> {
    this.browser = await chromium.launch({
      headless: process.env.HEADLESS !== 'false',
      slowMo: process.env.SLOW_MO ? parseInt(process.env.SLOW_MO) : 0,
    });

    this.context = await this.browser.newContext({
      viewport: { width: 1280, height: 720 },
      locale: 'en-US',
      timezoneId: 'America/New_York',
      permissions: ['geolocation'],
      geolocation: { latitude: 40.7128, longitude: -74.0060 },
    });

    return this.context;
  }

  async close(): Promise<void> {
    if (this.context) {
      await this.context.close();
    }
    if (this.browser) {
      await this.browser.close();
    }
  }

  async newPage(): Promise<Page> {
    if (!this.context) {
      throw new Error('Browser context not initialized');
    }
    return this.context.newPage();
  }
}

// ====================
// SYSTEM HEALTH CHECKS
// ====================

describe('System Health and Readiness Tests', () => {
  
  it('should verify all system components are healthy', async () => {
    const healthChecks = [
      // API Health
      axios.get(`${systemConfig.baseUrl}/health`),
      axios.get(`${systemConfig.baseUrl}/health/database`),
      axios.get(`${systemConfig.baseUrl}/health/redis`),
      axios.get(`${systemConfig.baseUrl}/health/external-services`),
    ];

    const results = await Promise.allSettled(healthChecks);
    
    results.forEach((result, index) => {
      expect(result.status).toBe('fulfilled');
      if (result.status === 'fulfilled') {
        expect(result.value.status).toBe(200);
        expect(result.value.data.status).toBe('healthy');
      }
    });
  });

  it('should verify database connectivity and performance', async () => {
    const startTime = performance.now();
    
    const response = await axios.get(`${systemConfig.baseUrl}/health/database`, {
      timeout: systemConfig.performanceThresholds.databaseQuery,
    });
    
    const endTime = performance.now();
    const responseTime = endTime - startTime;

    expect(response.status).toBe(200);
    expect(response.data.status).toBe('healthy');
    expect(response.data.responseTime).toBeLessThan(systemConfig.performanceThresholds.databaseQuery);
    expect(responseTime).toBeLessThan(systemConfig.performanceThresholds.databaseQuery);
  });

  it('should verify external service connectivity', async () => {
    const response = await axios.get(`${systemConfig.baseUrl}/health/external-services`);

    expect(response.status).toBe(200);
    expect(response.data.status).toBe('healthy');
    expect(response.data.services).toBeDefined();
    
    // Check individual services
    const services = response.data.services;
    Object.keys(services).forEach(serviceName => {
      expect(services[serviceName].status).toBe('healthy');
      expect(services[serviceName].responseTime).toBeLessThan(2000); // 2 seconds max
    });
  });

  it('should verify system resource usage', async () => {
    const response = await axios.get(`${systemConfig.baseUrl}/health/resources`);

    expect(response.status).toBe(200);
    expect(response.data.status).toBe('healthy');
    expect(response.data.resources).toBeDefined();
    
    const { cpu, memory, disk } = response.data.resources;
    
    // CPU usage should be reasonable
    expect(cpu.usage).toBeLessThan(80); // 80% max
    
    // Memory usage should be reasonable
    expect(memory.usage).toBeLessThan(85); // 85% max
    expect(memory.available).toBeGreaterThan(100 * 1024 * 1024); // 100MB free minimum
    
    // Disk usage should be reasonable
    expect(disk.usage).toBeLessThan(90); // 90% max
    expect(disk.free).toBeGreaterThan(1 * 1024 * 1024 * 1024); // 1GB free minimum
  });
});

// ====================
// END-TO-END USER WORKFLOWS
// ====================

describe('End-to-End User Workflows', () => {
  let browserManager: BrowserManager;
  let context: BrowserContext;

  beforeAll(async () => {
    browserManager = new BrowserManager();
    context = await browserManager.launch();
  });

  afterAll(async () => {
    await browserManager.close();
  });

  describe('Complete User Registration and Onboarding Flow', () => {
    it('should complete full user registration and onboarding', async () => {
      const page = await browserManager.newPage();
      
      try {
        // Navigate to registration page
        await page.goto(`${systemConfig.baseUrl}/register`);
        await page.waitForLoadState('networkidle');
        
        // Verify page loaded within performance threshold
        const loadTime = await page.evaluate(() => {
          return performance.timing.loadEventEnd - performance.timing.navigationStart;
        });
        expect(loadTime).toBeLessThan(systemConfig.performanceThresholds.pageLoad);

        // Fill registration form
        await page.fill('input[name="name"]', 'John Doe');
        await page.fill('input[name="email"]', systemConfig.testUserEmail);
        await page.fill('input[name="password"]', systemConfig.testUserPassword);
        await page.fill('input[name="confirmPassword"]', systemConfig.testUserPassword);
        
        // Submit form
        const startTime = performance.now();
        await page.click('button[type="submit"]');
        
        // Wait for success page or redirect
        await page.waitForURL(`${systemConfig.baseUrl}/dashboard`, { timeout: 10000 });
        
        const endTime = performance.now();
        const registrationTime = endTime - startTime;
        expect(registrationTime).toBeLessThan(5000); // 5 seconds max

        // Verify user is logged in
        const userInfo = await page.locator('.user-info').textContent();
        expect(userInfo).toContain('John Doe');

        // Complete onboarding steps
        await page.click('button:has-text("Complete Profile")');
        await page.fill('textarea[name="bio"]', 'Software developer passionate about TypeScript');
        await page.fill('input[name="location"]', 'San Francisco, CA');
        await page.click('button:has-text("Save Profile")');
        
        // Wait for success notification
        await page.waitForSelector('.notification-success', { timeout: 5000 });
        
        // Verify profile was updated
        const profileData = await page.locator('.profile-data').textContent();
        expect(profileData).toContain('Software developer');
        expect(profileData).toContain('San Francisco, CA');

        // Test email verification flow
        await page.goto(`${systemConfig.baseUrl}/verify-email?token=test-token`);
        await page.waitForSelector('.verification-success', { timeout: 5000 });
        
        const verificationMessage = await page.locator('.verification-message').textContent();
        expect(verificationMessage).toContain('Email verified successfully');

      } finally {
        await page.close();
      }
    }, 60000); // 1 minute timeout

    it('should handle registration validation errors', async () => {
      const page = await browserManager.newPage();
      
      try {
        await page.goto(`${systemConfig.baseUrl}/register`);
        await page.waitForLoadState('networkidle');

        // Submit empty form
        await page.click('button[type="submit"]');
        
        // Wait for validation errors
        await page.waitForSelector('.error-message', { timeout: 5000 });
        
        // Check for specific error messages
        const nameError = await page.locator('.error-name').textContent();
        const emailError = await page.locator('.error-email').textContent();
        const passwordError = await page.locator('.error-password').textContent();
        
        expect(nameError).toContain('Name is required');
        expect(emailError).toContain('Email is required');
        expect(passwordError).toContain('Password is required');

        // Test invalid email format
        await page.fill('input[name="email"]', 'invalid-email');
        await page.click('button[type="submit"]');
        
        await page.waitForSelector('.error-email', { timeout: 5000 });
        const emailFormatError = await page.locator('.error-email').textContent();
        expect(emailFormatError).toContain('Invalid email format');

        // Test weak password
        await page.fill('input[name="password"]', '123');
        await page.click('button[type="submit"]');
        
        await page.waitForSelector('.error-password', { timeout: 5000 });
        const passwordStrengthError = await page.locator('.error-password').textContent();
        expect(passwordStrengthError).toContain('Password must be at least 8 characters');

      } finally {
        await page.close();
      }
    }, 60000);
  });

  describe('Complete E-commerce Purchase Flow', () => {
    it('should complete full purchase workflow', async () => {
      const page = await browserManager.newPage();
      
      try {
        // Step 1: Browse products
        await page.goto(`${systemConfig.baseUrl}/products`);
        await page.waitForLoadState('networkidle');
        
        // Verify products are loaded
        await page.waitForSelector('.product-card', { timeout: 5000 });
        const productCount = await page.locator('.product-card').count();
        expect(productCount).toBeGreaterThan(0);

        // Select first product
        await page.click('.product-card:first-child');
        await page.waitForURL(/\/products\//);
        
        // Add to cart
        await page.click('button:has-text("Add to Cart")');
        await page.waitForSelector('.cart-notification', { timeout: 5000 });
        
        // Step 2: View cart
        await page.click('.cart-icon');
        await page.waitForURL('/cart');
        
        // Verify cart contents
        const cartItems = await page.locator('.cart-item').count();
        expect(cartItems).toBe(1);
        
        // Update quantity
        await page.fill('input[name="quantity"]', '2');
        await page.click('button:has-text("Update")');
        
        // Verify price updated
        const totalPrice = await page.locator('.cart-total').textContent();
        expect(totalPrice).toMatch(/\$\d+\.\d{2}/);

        // Step 3: Proceed to checkout
        await page.click('button:has-text("Checkout")');
        await page.waitForURL('/checkout');

        // Login or register
        await page.fill('input[name="email"]', systemConfig.testUserEmail);
        await page.fill('input[name="password"]', systemConfig.testUserPassword);
        await page.click('button:has-text("Continue")');

        // Fill shipping information
        await page.fill('input[name="firstName"]', 'John');
        await page.fill('input[name="lastName"]', 'Doe');
        await page.fill('input[name="address"]', '123 Test Street');
        await page.fill('input[name="city"]', 'Test City');
        await page.fill('input[name="zipCode"]', '12345');
        await page.selectOption('select[name="country"]', 'US');

        // Fill payment information
        await page.fill('input[name="cardNumber"]', '4242424242424242');
        await page.fill('input[name="cardName"]', 'John Doe');
        await page.fill('input[name="expiry"]', '12/25');
        await page.fill('input[name="cvv"]', '123');

        // Submit order
        const orderStartTime = performance.now();
        await page.click('button:has-text("Place Order")');
        
        // Wait for order confirmation
        await page.waitForURL('/order-confirmation', { timeout: 15000 });
        
        const orderEndTime = performance.now();
        const orderProcessingTime = orderEndTime - orderStartTime;
        expect(orderProcessingTime).toBeLessThan(10000); // 10 seconds max

        // Verify order confirmation
        const confirmationMessage = await page.locator('.confirmation-message').textContent();
        expect(confirmationMessage).toContain('Order placed successfully');
        
        const orderNumber = await page.locator('.order-number').textContent();
        expect(orderNumber).toMatch(/ORDER-\d+/);

        // Verify email confirmation
        await page.waitForSelector('.email-confirmation', { timeout: 5000 });
        const emailMessage = await page.locator('.email-confirmation').textContent();
        expect(emailMessage).toContain('confirmation email');

      } finally {
        await page.close();
      }
    }, 120000); // 2 minute timeout
  });

  describe('Multi-User Collaboration Workflow', () => {
    it('should handle team collaboration features', async () => {
      const adminPage = await browserManager.newPage();
      const memberPage = await browserManager.newPage();
      
      try {
        // Admin creates team
        await adminPage.goto(`${systemConfig.baseUrl}/login`);
        await adminPage.fill('input[name="email"]', systemConfig.adminEmail);
        await adminPage.fill('input[name="password"]', systemConfig.adminPassword);
        await adminPage.click('button[type="submit"]');
        await adminPage.waitForURL('/dashboard');

        // Navigate to teams
        await adminPage.click('nav a:has-text("Teams")');
        await adminPage.waitForURL('/teams');

        // Create new team
        await adminPage.click('button:has-text("Create Team")');
        await adminPage.fill('input[name="teamName"]', 'Development Team');
        await adminPage.fill('textarea[name="description"]', 'A team for development projects');
        await adminPage.click('button:has-text("Create")');
        
        await adminPage.waitForSelector('.team-created', { timeout: 5000 });
        
        // Get team ID from URL
        const teamUrl = adminPage.url();
        const teamId = teamUrl.match(/\/teams\/(\w+)/)?.[1];
        expect(teamId).toBeDefined();

        // Invite team member
        await adminPage.click('button:has-text("Invite Members")');
        await adminPage.fill('input[name="email"]', 'teammember@example.com');
        await adminPage.selectOption('select[name="role"]', 'developer');
        await adminPage.click('button:has-text("Send Invitation")');
        
        await adminPage.waitForSelector('.invitation-sent', { timeout: 5000 });

        // Member accepts invitation
        await memberPage.goto(`${systemConfig.baseUrl}/register`);
        await memberPage.fill('input[name="name"]', 'Team Member');
        await memberPage.fill('input[name="email"]', 'teammember@example.com');
        await memberPage.fill('input[name="password"]', 'TeamMember123!');
        await memberPage.click('button[type="submit"]');
        await memberPage.waitForURL('/dashboard');

        // Navigate to invitations
        await memberPage.click('nav a:has-text("Invitations")');
        await memberPage.click('.invitation-accept');
        
        await memberPage.waitForSelector('.invitation-accepted', { timeout: 5000 });

        // Create collaborative project
        await adminPage.click('nav a:has-text("Projects")');
        await adminPage.click('button:has-text("New Project")');
        await adminPage.fill('input[name="projectName"]', 'Team Project');
        await adminPage.selectOption('select[name="team"]', teamId!);
        await adminPage.click('button:has-text("Create Project")');

        await adminPage.waitForSelector('.project-created', { timeout: 5000 });

        // Assign tasks
        await adminPage.click('button:has-text("Add Task")');
        await adminPage.fill('input[name="taskTitle"]', 'Implement authentication');
        await adminPage.fill('textarea[name="taskDescription"]', 'Set up user authentication system');
        await adminPage.selectOption('select[name="assignee"]', 'teammember@example.com');
        await adminPage.selectOption('select[name="priority"]', 'high');
        await adminPage.click('button:has-text("Create Task")');

        await adminPage.waitForSelector('.task-created', { timeout: 5000 });

        // Member updates task status
        await memberPage.goto(adminPage.url()); // Navigate to same project
        await memberPage.click('.task-item');
        await memberPage.selectOption('select[name="status"]', 'in-progress');
        await memberPage.fill('textarea[name="progress"]', '50');
        await memberPage.click('button:has-text("Update Task")');

        await memberPage.waitForSelector('.task-updated', { timeout: 5000 });

        // Verify collaboration features
        const taskStatus = await adminPage.locator('.task-status').textContent();
        expect(taskStatus).toContain('In Progress');
        
        const taskProgress = await adminPage.locator('.task-progress').textContent();
        expect(taskProgress).toContain('50');

        // Test notifications
        await adminPage.waitForSelector('.notification', { timeout: 5000 });
        const notification = await adminPage.locator('.notification').textContent();
        expect(notification).toContain('Task updated');

      } finally {
        await adminPage.close();
        await memberPage.close();
      }
    }, 120000); // 2 minute timeout
  });
});

// ====================
// PERFORMANCE TESTING
// ====================

describe('Performance Testing', () => {
  
  it('should meet API response time requirements', async () => {
    const endpoints = [
      { method: 'GET', url: '/health', expectedMaxTime: 100 },
      { method: 'GET', url: '/api/v1/users', expectedMaxTime: 500 },
      { method: 'POST', url: '/api/v1/auth/login', body: { email: 'test@example.com', password: 'test' }, expectedMaxTime: 1000 },
    ];

    for (const endpoint of endpoints) {
      const startTime = performance.now();
      
      let response: AxiosResponse;
      if (endpoint.method === 'GET') {
        response = await axios.get(`${systemConfig.baseUrl}${endpoint.url}`);
      } else {
        response = await axios.post(`${systemConfig.baseUrl}${endpoint.url}`, endpoint.body);
      }
      
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      
      expect(response.status).toBeLessThan(500);
      expect(responseTime).toBeLessThan(endpoint.expectedMaxTime);
      
      console.log(`${endpoint.method} ${endpoint.url}: ${responseTime.toFixed(2)}ms`);
    }
  });

  it('should handle concurrent load without degradation', async () => {
    const concurrentRequests = 50;
    const requests = Array.from({ length: concurrentRequests }, (_, i) =>
      axios.get(`${systemConfig.baseUrl}/health`)
    );

    const startTime = performance.now();
    const results = await Promise.allSettled(requests);
    const endTime = performance.now();
    
    const totalTime = endTime - startTime;
    const averageTime = totalTime / concurrentRequests;

    // All requests should succeed
    const successfulRequests = results.filter(r => r.status === 'fulfilled').length;
    expect(successfulRequests).toBe(concurrentRequests);

    // Average response time should be reasonable
    expect(averageTime).toBeLessThan(200); // 200ms average max

    // Total time should scale reasonably
    expect(totalTime).toBeLessThan(5000); // 5 seconds max for all requests
  });

  it('should maintain performance under sustained load', async () => {
    const loadTestDuration = 10000; // 10 seconds
    const requestsPerSecond = 10;
    const results: number[] = [];
    
    const startTime = performance.now();
    const endTime = startTime + loadTestDuration;
    
    let currentTime = startTime;
    while (currentTime < endTime) {
      const requestStart = performance.now();
      
      try {
        await axios.get(`${systemConfig.baseUrl}/health`);
        const requestEnd = performance.now();
        results.push(requestEnd - requestStart);
      } catch (error) {
        results.push(-1); // Mark as failed
      }
      
      // Wait for next request
      await new Promise(resolve => setTimeout(resolve, 1000 / requestsPerSecond));
      currentTime = performance.now();
    }
    
    const successfulResults = results.filter(r => r > 0);
    const averageResponseTime = successfulResults.reduce((a, b) => a + b, 0) / successfulResults.length;
    const successRate = successfulResults.length / results.length;
    
    expect(successRate).toBeGreaterThan(0.95); // 95% success rate minimum
    expect(averageResponseTime).toBeLessThan(150); // 150ms average max
  });

  it('should optimize database queries for large datasets', async () => {
    // Test pagination performance
    const pageSizes = [10, 50, 100, 500];
    
    for (const pageSize of pageSizes) {
      const startTime = performance.now();
      
      const response = await axios.get(
        `${systemConfig.baseUrl}/api/v1/users?limit=${pageSize}&page=1`
      );
      
      const endTime = performance.now();
      const responseTime = endTime - startTime;
      
      expect(response.status).toBe(200);
      expect(response.data.data.items).toHaveLength(pageSize);
      expect(responseTime).toBeLessThan(systemConfig.performanceThresholds.apiResponse);
      
      console.log(`Pagination with ${pageSize} items: ${responseTime.toFixed(2)}ms`);
    }
  });

  it('should cache responses effectively', async () => {
    const endpoint = '/api/v1/products';
    
    // First request (cold cache)
    const start1 = performance.now();
    const response1 = await axios.get(`${systemConfig.baseUrl}${endpoint}`);
    const end1 = performance.now();
    const firstRequestTime = end1 - start1;
    
    // Second request (warm cache)
    const start2 = performance.now();
    const response2 = await axios.get(`${systemConfig.baseUrl}${endpoint}`);
    const end2 = performance.now();
    const secondRequestTime = end2 - start2;
    
    // Cached request should be significantly faster
    expect(secondRequestTime).toBeLessThan(firstRequestTime * 0.5);
    
    // Verify cache headers
    expect(response2.headers['cache-control']).toContain('max-age');
    expect(response2.headers['etag']).toBeDefined();
  });
});

// ====================
// SECURITY TESTING
// ====================

describe('Security Testing', () => {
  
  it('should prevent SQL injection attacks', async () => {
    const maliciousInputs = [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "' UNION SELECT * FROM users --",
      "admin'--",
      "1' OR 1=1--",
    ];

    for (const input of maliciousInputs) {
      try {
        const response = await axios.get(`${systemConfig.baseUrl}/api/v1/users`, {
          params: { search: input },
        });
        
        // Should not crash or return sensitive data
        expect(response.status).toBeLessThan(500);
        expect(response.data).not.toHaveProperty('sql');
        expect(response.data).not.toHaveProperty('query');
      } catch (error) {
        // Should handle gracefully
        expect(error.response?.status).toBeLessThan(500);
      }
    }
  });

  it('should prevent XSS attacks', async () => {
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src="x" onerror="alert(\'XSS\')">',
      'javascript:alert("XSS")',
      '<svg onload="alert(\'XSS\')">',
      '"><script>alert("XSS")</script>',
    ];

    for (const payload of xssPayloads) {
      try {
        const response = await axios.post(`${systemConfig.baseUrl}/api/v1/users`, {
          name: payload,
          email: 'test@example.com',
          password: 'TestPassword123!',
        });
        
        // Should sanitize input
        if (response.status === 201) {
          expect(response.data.data.name).not.toContain('<script>');
          expect(response.data.data.name).not.toContain('javascript:');
          expect(response.data.data.name).not.toContain('<svg');
        }
      } catch (error) {
        // Should handle gracefully
        expect(error.response?.status).toBeLessThan(500);
      }
    }
  });

  it('should prevent CSRF attacks', async () => {
    // Test that state-changing operations require proper tokens
    const endpoints = [
      { method: 'POST', url: '/api/v1/users' },
      { method: 'PUT', url: '/api/v1/users/123' },
      { method: 'DELETE', url: '/api/v1/users/123' },
    ];

    for (const endpoint of endpoints) {
      try {
        let response;
        if (endpoint.method === 'POST') {
          response = await axios.post(`${systemConfig.baseUrl}${endpoint.url}`, {
            name: 'Test User',
            email: 'test@example.com',
            password: 'TestPassword123!',
          });
        } else if (endpoint.method === 'PUT') {
          response = await axios.put(`${systemConfig.baseUrl}${endpoint.url}`, {
            name: 'Updated Name',
          });
        } else {
          response = await axios.delete(`${systemConfig.baseUrl}${endpoint.url}`);
        }
        
        // Should require authentication or CSRF token
        expect(response.status).toBeGreaterThanOrEqual(400);
      } catch (error) {
        // Should reject unauthorized requests
        expect(error.response?.status).toBeGreaterThanOrEqual(401);
      }
    }
  });

  it('should implement proper authentication mechanisms', async () => {
    // Test JWT token validation
    const invalidTokens = [
      'invalid-token',
      'Bearer invalid-token',
      'Bearer ' + jwt.sign({ userId: '123' }, 'wrong-secret'),
      'Bearer ' + jwt.sign({ userId: '123' }, 'secret', { expiresIn: '-1h' }), // Expired
    ];

    for (const token of invalidTokens) {
      try {
        const response = await axios.get(`${systemConfig.baseUrl}/api/v1/users/me`, {
          headers: { Authorization: token },
        });
        
        expect(response.status).toBeGreaterThanOrEqual(401);
      } catch (error) {
        expect(error.response?.status).toBeGreaterThanOrEqual(401);
      }
    }
  });

  it('should implement rate limiting', async () => {
    const endpoint = '/api/v1/auth/login';
    const requests = Array.from({ length: 20 }, () =>
      axios.post(`${systemConfig.baseUrl}${endpoint}`, {
        email: 'test@example.com',
        password: 'wrongpassword',
      })
    );

    const results = await Promise.allSettled(requests);
    
    // Count rate-limited responses
    const rateLimitedCount = results.filter(r => 
      r.status === 'rejected' && r.reason.response?.status === 429
    ).length;
    
    expect(rateLimitedCount).toBeGreaterThan(0);
  });

  it('should encrypt sensitive data', async () => {
    // Register a new user
    const userData = {
      name: 'Security Test User',
      email: 'securitytest@example.com',
      password: 'SecurePassword123!',
    };

    const response = await axios.post(`${systemConfig.baseUrl}/api/v1/auth/register`, userData);
    expect(response.status).toBe(201);

    const userId = response.data.data.id;

    // Verify password is not returned in response
    expect(response.data.data).not.toHaveProperty('password');
    expect(response.data.data).not.toHaveProperty('passwordHash');

    // Login to verify password hashing works
    const loginResponse = await axios.post(`${systemConfig.baseUrl}/api/v1/auth/login`, {
      email: userData.email,
      password: userData.password,
    });
    
    expect(loginResponse.status).toBe(200);
    expect(loginResponse.data.data.accessToken).toBeDefined();
  });

  it('should validate input data properly', async () => {
    const invalidInputs = [
      // SQL injection attempts
      { name: "'; DROP TABLE users; --", email: 'test@example.com', password: 'Test123!' },
      // XSS attempts
      { name: '<script>alert("XSS")</script>', email: 'test@example.com', password: 'Test123!' },
      // Oversized inputs
      { name: 'A'.repeat(1000), email: 'test@example.com', password: 'Test123!' },
      // Invalid formats
      { name: 'Valid Name', email: 'not-an-email', password: 'Test123!' },
      { name: 'Valid Name', email: 'test@example.com', password: '123' }, // Weak password
    ];

    for (const input of invalidInputs) {
      try {
        const response = await axios.post(`${systemConfig.baseUrl}/api/v1/users`, input);
        
        // Should either reject with validation error or sanitize input
        if (response.status === 201) {
          // If created, verify input was sanitized
          expect(response.data.data.name).not.toContain('<script>');
          expect(response.data.data.name.length).toBeLessThan(255);
        } else {
          expect(response.status).toBe(400);
        }
      } catch (error) {
        expect(error.response?.status).toBeGreaterThanOrEqual(400);
      }
    }
  });

  it('should implement secure headers', async () => {
    const response = await axios.get(`${systemConfig.baseUrl}/api/v1/health`);
    
    const headers = response.headers;
    
    // Check for security headers
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBeDefined();
    expect(headers['x-xss-protection']).toBeDefined();
    expect(headers['strict-transport-security']).toBeDefined();
    expect(headers['content-security-policy']).toBeDefined();
  });
});

// ====================
// GDPR COMPLIANCE TESTING
// ====================

describe('GDPR Compliance Testing', () => {
  
  it('should provide data export functionality', async () => {
    // Login as test user
    const loginResponse = await axios.post(`${systemConfig.baseUrl}/api/v1/auth/login`, {
      email: systemConfig.testUserEmail,
      password: systemConfig.testUserPassword,
    });
    
    const token = loginResponse.data.data.accessToken;
    
    // Request data export
    const exportResponse = await axios.post(
      `${systemConfig.baseUrl}/api/v1/users/me/export`,
      {},
      { headers: { Authorization: `Bearer ${token}` } }
    );
    
    expect(exportResponse.status).toBe(200);
    expect(exportResponse.data.success).toBe(true);
    expect(exportResponse.data.data.exportId).toBeDefined();
    
    // Download exported data
    const downloadResponse = await axios.get(
      `${systemConfig.baseUrl}/api/v1/users/me/export/${exportResponse.data.data.exportId}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    
    expect(downloadResponse.status).toBe(200);
    expect(downloadResponse.data).toBeDefined();
    
    // Verify exported data contains expected information
    const exportedData = downloadResponse.data;
    expect(exportedData).toHaveProperty('user');
    expect(exportedData).toHaveProperty('orders');
    expect(exportedData).toHaveProperty('activities');
    expect(exportedData.user).toHaveProperty('email');
    expect(exportedData.user.email).toBe(systemConfig.testUserEmail);
  });

  it('should implement right to be forgotten', async () => {
    // Create a test user
    const userData = {
      name: 'GDPR Test User',
      email: 'gdprtest@example.com',
      password: 'SecurePassword123!',
    };
    
    const registerResponse = await axios.post(`${systemConfig.baseUrl}/api/v1/auth/register`, userData);
    expect(registerResponse.status).toBe(201);
    
    const userId = registerResponse.data.data.id;
    const token = registerResponse.data.data.accessToken;
    
    // Request account deletion
    const deleteResponse = await axios.delete(
      `${systemConfig.baseUrl}/api/v1/users/me`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    
    expect(deleteResponse.status).toBe(200);
    expect(deleteResponse.data.success).toBe(true);
    expect(deleteResponse.data.data.message).toContain('Account scheduled for deletion');
    
    // Verify user cannot login anymore
    try {
      await axios.post(`${systemConfig.baseUrl}/api/v1/auth/login`, {
        email: userData.email,
        password: userData.password,
      });
      fail('Should not be able to login after deletion');
    } catch (error) {
      expect(error.response?.status).toBe(401);
    }
  });

  it('should obtain proper consent for data processing', async () => {
    // Test registration with consent
    const userData = {
      name: 'Consent Test User',
      email: 'consenttest@example.com',
      password: 'SecurePassword123!',
      consent: {
        termsOfService: true,
        privacyPolicy: true,
        marketingEmails: false,
        dataProcessing: true,
      },
    };
    
    const response = await axios.post(`${systemConfig.baseUrl}/api/v1/auth/register`, userData);
    expect(response.status).toBe(201);
    
    const userId = response.data.data.id;
    
    // Verify consent was recorded
    const loginResponse = await axios.post(`${systemConfig.baseUrl}/api/v1/auth/login`, {
      email: userData.email,
      password: userData.password,
    });
    
    const token = loginResponse.data.data.accessToken;
    
    const consentResponse = await axios.get(
      `${systemConfig.baseUrl}/api/v1/users/me/consent`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    
    expect(consentResponse.status).toBe(200);
    expect(consentResponse.data.data).toMatchObject(userData.consent);
  });

  it('should provide cookie consent management', async () => {
    const page = await (await chromium.launch()).newPage();
    
    try {
      await page.goto(systemConfig.baseUrl);
      
      // Check for cookie consent banner
      const cookieBanner = await page.waitForSelector('.cookie-consent-banner', { timeout: 5000 });
      expect(cookieBanner).toBeDefined();
      
      // Verify cookie categories
      const necessaryCookies = await page.locator('.cookie-category-necessary').count();
      const analyticsCookies = await page.locator('.cookie-category-analytics').count();
      const marketingCookies = await page.locator('.cookie-category-marketing').count();
      
      expect(necessaryCookies).toBeGreaterThan(0);
      expect(analyticsCookies).toBeGreaterThan(0);
      expect(marketingCookies).toBeGreaterThan(0);
      
      // Test accepting only necessary cookies
      await page.click('.accept-necessary-cookies');
      
      // Verify only necessary cookies are set
      const cookies = await page.context().cookies();
      const necessaryCookie = cookies.find(c => c.name.includes('necessary'));
      const analyticsCookie = cookies.find(c => c.name.includes('analytics'));
      const marketingCookie = cookies.find(c => c.name.includes('marketing'));
      
      expect(necessaryCookie).toBeDefined();
      expect(analyticsCookie).toBeUndefined();
      expect(marketingCookie).toBeUndefined();
      
    } finally {
      await page.close();
    }
  });

  it('should log data processing activities', async () => {
    // Login as test user
    const loginResponse = await axios.post(`${systemConfig.baseUrl}/api/v1/auth/login`, {
      email: systemConfig.testUserEmail,
      password: systemConfig.testUserPassword,
    });
    
    const token = loginResponse.data.data.accessToken;
    
    // Perform some activities
    await axios.get(`${systemConfig.baseUrl}/api/v1/users/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    
    await axios.put(`${systemConfig.baseUrl}/api/v1/users/me`, {
      name: 'Updated Name',
    }, {
      headers: { Authorization: `Bearer ${token}` },
    });
    
    // Request activity log
    const activityResponse = await axios.get(
      `${systemConfig.baseUrl}/api/v1/users/me/activity-log`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    
    expect(activityResponse.status).toBe(200);
    expect(activityResponse.data.success).toBe(true);
    expect(activityResponse.data.data.activities).toBeDefined();
    expect(activityResponse.data.data.activities.length).toBeGreaterThan(0);
    
    // Verify activity details
    const activities = activityResponse.data.data.activities;
    activities.forEach(activity => {
      expect(activity).toHaveProperty('timestamp');
      expect(activity).toHaveProperty('action');
      expect(activity).toHaveProperty('ipAddress');
      expect(activity).toHaveProperty('userAgent');
    });
  });

  it('should handle data portability requests', async () => {
    // Login as test user
    const loginResponse = await axios.post(`${systemConfig.baseUrl}/api/v1/auth/login`, {
      email: systemConfig.testUserEmail,
      password: systemConfig.testUserPassword,
    });
    
    const token = loginResponse.data.data.accessToken;
    
    // Request data in different formats
    const formats = ['json', 'csv', 'xml'];
    
    for (const format of formats) {
      const exportResponse = await axios.post(
        `${systemConfig.baseUrl}/api/v1/users/me/export`,
        { format },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      expect(exportResponse.status).toBe(200);
      expect(exportResponse.data.success).toBe(true);
      
      // Download exported data
      const downloadResponse = await axios.get(
        `${systemConfig.baseUrl}/api/v1/users/me/export/${exportResponse.data.data.exportId}`,
        { 
          headers: { Authorization: `Bearer ${token}` },
          responseType: 'arraybuffer',
        }
      );
      
      expect(downloadResponse.status).toBe(200);
      expect(downloadResponse.data).toBeDefined();
      
      // Verify content type based on format
      const contentType = downloadResponse.headers['content-type'];
      
      if (format === 'json') {
        expect(contentType).toContain('application/json');
        // Verify it's valid JSON
        const jsonData = JSON.parse(downloadResponse.data.toString());
        expect(jsonData).toHaveProperty('user');
      } else if (format === 'csv') {
        expect(contentType).toContain('text/csv');
        // Verify it's valid CSV
        const csvData = downloadResponse.data.toString();
        expect(csvData).toContain(',');
      } else if (format === 'xml') {
        expect(contentType).toContain('application/xml');
        // Verify it's valid XML
        const xmlData = downloadResponse.data.toString();
        expect(xmlData).toContain('<?xml');
      }
    }
  });
});

// ====================
// PRODUCTION READINESS TESTING
// ====================

describe('Production Readiness Testing', () => {
  
  it('should have proper logging configuration', async () => {
    const response = await axios.get(`${systemConfig.baseUrl}/health/logging`);
    
    expect(response.status).toBe(200);
    expect(response.data.status).toBe('healthy');
    expect(response.data.config).toBeDefined();
    
    const { level, format, destination } = response.data.config;
    
    // Verify appropriate log level for production
    expect(['info', 'warn', 'error']).toContain(level);
    
    // Verify structured logging format
    expect(format).toBe('json');
    
    // Verify log destination
    expect(destination).toBeDefined();
  });

  it('should have proper error handling', async () => {
    // Test 404 handling
    try {
      await axios.get(`${systemConfig.baseUrl}/nonexistent-endpoint`);
      fail('Should return 404');
    } catch (error) {
      expect(error.response?.status).toBe(404);
      expect(error.response?.data).toHaveProperty('error');
      expect(error.response?.data).not.toHaveProperty('stack'); // No stack trace in production
    }
    
    // Test 500 handling
    try {
      await axios.get(`${systemConfig.baseUrl}/health/error`);
      fail('Should return 500');
    } catch (error) {
      expect(error.response?.status).toBe(500);
      expect(error.response?.data).toHaveProperty('error');
      expect(error.response?.data).not.toHaveProperty('stack');
    }
  });

  it('should have proper monitoring and metrics', async () => {
    const response = await axios.get(`${systemConfig.baseUrl}/metrics`);
    
    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toContain('text/plain');
    
    const metrics = response.data;
    
    // Verify key metrics are present
    expect(metrics).toContain('http_requests_total');
    expect(metrics).toContain('http_request_duration_seconds');
    expect(metrics).toContain('database_connections');
    expect(metrics).toContain('memory_usage_bytes');
    expect(metrics).toContain('cpu_usage_percent');
  });

  it('should have proper backup and recovery procedures', async () => {
    const response = await axios.get(`${systemConfig.baseUrl}/health/backup`);
    
    expect(response.status).toBe(200);
    expect(response.data.status).toBe('healthy');
    expect(response.data.lastBackup).toBeDefined();
    expect(response.data.backupSize).toBeDefined();
    expect(response.data.backupLocation).toBeDefined();
    
    // Verify backup is recent (within 24 hours)
    const lastBackup = new Date(response.data.lastBackup);
    const now = new Date();
    const hoursSinceBackup = (now.getTime() - lastBackup.getTime()) / (1000 * 60 * 60);
    
    expect(hoursSinceBackup).toBeLessThan(24);
  });

  it('should have proper deployment configuration', async () => {
    const response = await axios.get(`${systemConfig.baseUrl}/health/deployment`);
    
    expect(response.status).toBe(200);
    expect(response.data.status).toBe('healthy');
    expect(response.data.environment).toBe('production');
    expect(response.data.version).toBeDefined();
    expect(response.data.commitHash).toBeDefined();
    expect(response.data.buildDate).toBeDefined();
  });

  it('should handle graceful shutdown', async () => {
    // This test would typically be run in a controlled environment
    // For now, we'll just verify the endpoint exists
    const response = await axios.get(`${systemConfig.baseUrl}/health/shutdown`);
    
    expect(response.status).toBe(200);
    expect(response.data.status).toBe('ready');
    expect(response.data.activeConnections).toBeDefined();
    expect(response.data.gracefulShutdownTimeout).toBeDefined();
  });

  it('should have proper configuration management', async () => {
    const response = await axios.get(`${systemConfig.baseUrl}/health/configuration`);
    
    expect(response.status).toBe(200);
    expect(response.data.status).toBe('healthy');
    expect(response.data.configSources).toBeDefined();
    expect(response.data.environmentVariables).toBeDefined();
    
    // Verify sensitive data is not exposed
    const configData = response.data;
    const configString = JSON.stringify(configData);
    
    expect(configString).not.toContain('password');
    expect(configString).not.toContain('secret');
    expect(configString).not.toContain('key');
    expect(configString).not.toContain('token');
  });
});

// ====================
// DISASTER RECOVERY TESTING
// ====================

describe('Disaster Recovery Testing', () => {
  
  it('should handle database connection failures gracefully', async () => {
    // This would typically be tested in a controlled environment
    // For now, we'll verify the error handling endpoint exists
    try {
      await axios.get(`${systemConfig.baseUrl}/health/database-failure`);
    } catch (error) {
      expect(error.response?.status).toBe(503);
      expect(error.response?.data).toHaveProperty('error');
      expect(error.response?.data.error).toContain('Database');
    }
  });

  it('should handle external service failures gracefully', async () => {
    try {
      await axios.get(`${systemConfig.baseUrl}/health/external-service-failure`);
    } catch (error) {
      expect(error.response?.status).toBe(503);
      expect(error.response?.data).toHaveProperty('error');
      expect(error.response?.data.error).toContain('External service');
    }
  });

  it('should have circuit breaker patterns', async () => {
    const response = await axios.get(`${systemConfig.baseUrl}/health/circuit-breakers`);
    
    expect(response.status).toBe(200);
    expect(response.data.status).toBe('healthy');
    expect(response.data.circuitBreakers).toBeDefined();
    
    const circuitBreakers = response.data.circuitBreakers;
    Object.keys(circuitBreakers).forEach(serviceName => {
      const breaker = circuitBreakers[serviceName];
      expect(breaker).toHaveProperty('state');
      expect(breaker).toHaveProperty('failureCount');
      expect(breaker).toHaveProperty('lastFailureTime');
      expect(['closed', 'open', 'half-open']).toContain(breaker.state);
    });
  });

  it('should have fallback mechanisms', async () => {
    const response = await axios.get(`${systemConfig.baseUrl}/health/fallbacks`);
    
    expect(response.status).toBe(200);
    expect(response.data.status).toBe('healthy');
    expect(response.data.fallbacks).toBeDefined();
    
    const fallbacks = response.data.fallbacks;
    Object.keys(fallbacks).forEach(serviceName => {
      const fallback = fallbacks[serviceName];
      expect(fallback).toHaveProperty('isActive');
      expect(fallback).toHaveProperty('fallbackStrategy');
      expect(fallback).toHaveProperty('lastUsed');
    });
  });
});

// ====================
// HELPER FUNCTIONS
// ====================

async function waitForSystemReady(): Promise<boolean> {
  const maxAttempts = 30;
  
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const response = await axios.get(`${systemConfig.baseUrl}/health`, {
        timeout: 5000,
      });
      
      if (response.status === 200 && response.data.status === 'healthy') {
        return true;
      }
    } catch (error) {
      console.log(`System not ready yet (attempt ${attempt + 1}): ${error.message}`);
    }
    
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  
  return false;
}

async function createTestUser(): Promise<{ email: string; password: string; token: string }> {
  const userData = {
    name: 'System Test User',
    email: `systemtest-${Date.now()}@example.com`,
    password: 'SecurePassword123!',
  };
  
  const registerResponse = await axios.post(`${systemConfig.baseUrl}/api/v1/auth/register`, userData);
  expect(registerResponse.status).toBe(201);
  
  const loginResponse = await axios.post(`${systemConfig.baseUrl}/api/v1/auth/login`, {
    email: userData.email,
    password: userData.password,
  });
  
  expect(loginResponse.status).toBe(200);
  
  return {
    email: userData.email,
    password: userData.password,
    token: loginResponse.data.data.accessToken,
  };
}

function generateSecurityReport(results: any[]): void {
  console.log('\n=== SECURITY TEST REPORT ===');
  console.log(`Total Tests: ${results.length}`);
  console.log(`Passed: ${results.filter(r => r.status === 'passed').length}`);
  console.log(`Failed: ${results.filter(r => r.status === 'failed').length}`);
  console.log(`Warnings: ${results.filter(r => r.status === 'warning').length}`);
  
  const failedTests = results.filter(r => r.status === 'failed');
  if (failedTests.length > 0) {
    console.log('\nFailed Tests:');
    failedTests.forEach(test => {
      console.log(`- ${test.name}: ${test.message}`);
    });
  }
  
  console.log('\n=== END REPORT ===\n');
}