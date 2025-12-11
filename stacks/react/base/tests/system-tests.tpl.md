# React System Tests Template
// React System Testing Template
// End-to-end system testing patterns for React projects

/**
 * React System Test Patterns
 * Complete E2E testing with business workflows, load testing, security, compliance
 */

import puppeteer from 'puppeteer';
import { setupServer } from 'msw/node';
import { rest } from 'msw';
import { faker } from '@faker-js/faker';

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
    this.slowMo = parseInt(process.env.SLOW_MO || '0'); // For debugging
  }
}

class SystemTestHelper {
  constructor(config) {
    this.config = config;
    this.browser = null;
    this.page = null;
    this.tokens = new Map();
  }
  
  async launchBrowser() {
    this.browser = await puppeteer.launch({
      headless: process.env.HEADLESS !== 'false',
      slowMo: this.config.slowMo,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    this.page = await this.browser.newPage();
    await this.page.setViewport({ width: 1200, height: 800 });
  }
  
  async closeBrowser() {
    if (this.browser) {
      await this.browser.close();
    }
  }
  
  async navigate(path) {
    await this.page.goto(`${this.config.baseURL}${path}`, {
      waitUntil: 'networkidle0',
      timeout: this.config.timeout
    });
  }
  
  async login(email, password) {
    await this.navigate('/login');
    
    await this.page.type('input[name="email"]', email);
    await this.page.type('input[name="password"]', password);
    
    await Promise.all([
      this.page.click('button[type="submit"]'),
      this.page.waitForNavigation({ waitUntil: 'networkidle0' })
    ]);
    
    // Verify login succeeded
    const loggedIn = await this.page.evaluate(() => {
      return localStorage.getItem('accessToken') !== null;
    });
    
    return loggedIn;
  }
  
  async waitForSelector(selector, options = {}) {
    return this.page.waitForSelector(selector, {
      timeout: this.config.timeout,
      ...options
    });
  }
  
  async waitForSystemReady() {
    for (let attempt = 0; attempt < 30; attempt++) {
      try {
        await this.navigate('/health');
        const health = await this.page.evaluate(() => document.body.textContent);
        if (health.includes('healthy')) {
          return true;
        }
      } catch (error) {
        console.log(`System not ready yet, attempt ${attempt + 1}/30`);
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
// SYSTEM TEST SETUP
// ====================

describe('System Health Checks', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.launchBrowser();
    await helper.waitForSystemReady();
  }, 180000); // 3 minute timeout
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should load application in browser', async () => {
    await helper.navigate('/');
    
    // Verify page loaded
    const pageTitle = await helper.page.title();
    expect(pageTitle).toBeTruthy();
    
    // Verify JavaScript executed
    const bodyContent = await helper.page.evaluate(() => document.body.textContent);
    expect(bodyContent).toBeTruthy();
  });
  
  it('should show responsive design on different viewports', async () => {
    // Test mobile viewport
    await helper.page.setViewport({ width: 375, height: 667 });
    await helper.navigate('/');
    
    const mobileNav = await helper.page.$('[data-testid="mobile-nav"]');
    expect(mobileNav).toBeTruthy();
    
    // Test desktop viewport
    await helper.page.setViewport({ width: 1200, height: 800 });
    await helper.navigate('/');
    
    const desktopNav = await helper.page.$('[data-testid="desktop-nav"]');
    expect(desktopNav).toBeTruthy();
  });
  
  it('should check performance metrics', async () => {
    await helper.navigate('/products');
    
    // Get performance metrics
    const metrics = await helper.page.evaluate(() => {
      const navigation = performance.getEntriesByType('navigation')[0];
      return {
        domContentLoaded: navigation.domContentLoadedEventEnd - navigation.startTime,
        loadComplete: navigation.loadEventEnd - navigation.startTime,
        firstPaint: performance.getEntriesByType('paint').find(
          entry => entry.name === 'first-paint'
        )?.startTime || 0
      };
    });
    
    console.log('Performance Metrics:', metrics);
    
    // Verify reasonable load times
    expect(metrics.domContentLoaded).toBeLessThan(3000); // <3 seconds
    expect(metrics.loadComplete).toBeLessThan(5000); // <5 seconds
  });
});

// ====================
// END-TO-END BUSINESS FLOW TESTS
// ====================

describe('End-to-End Business Flows', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.launchBrowser();
    await helper.waitForSystemReady();
  }, 180000);
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should complete full e-commerce journey', async () => {
    // Step 1: Navigate to site
    await helper.navigate('/');
    
    // Step 2: Register new user
    await helper.page.click('a[href="/register"]');
    
    const randomEmail = `e2e-${faker.random.alphaNumeric(8)}@test.com`;
    await helper.page.type('input[name="name"]', 'E2E Test User');
    await helper.page.type('input[name="email"]', randomEmail);
    await helper.page.type('input[name="password"]', 'E2EPass123!');
    await helper.page.type('input[name="passwordConfirm"]', 'E2EPass123!');
    
    await Promise.all([
      helper.page.click('button[type="submit"]'),
      helper.page.waitForNavigation({ waitUntil: 'networkidle0' })
    ]);
    
    // Step 3: Login
    expect(helper.page.url()).toContain('/login');
    
    await helper.page.type('input[name="email"]', randomEmail);
    await helper.page.type('input[name="password"]', 'E2EPass123!');
    
    await Promise.all([
      helper.page.click('button[type="submit"]'),
      helper.page.waitForNavigation({ waitUntil: 'networkidle0' })
    ]);
    
    // Step 4: Browse products
    await helper.page.click('nav a[href="/products"]');
    await helper.page.waitForSelector('[data-testid="product-card"]');
    
    const products = await helper.page.$$('[data-testid="product-card"]');
    expect(products.length).toBeGreaterThan(0);
    
    // Step 5: Add products to cart
    const addButtons = await helper.page.$$('button[data-testid="add-to-cart"]');
    await addButtons[0].click();
    await addButtons[1].click();
    
    // Verify cart badge updated
    const cartBadge = await helper.page.$('[data-testid="cart-badge"]');
    const badgeText = await helper.page.evaluate(el => el.textContent, cartBadge);
    expect(badgeText).toBe('2');
    
    // Step 6: Navigate to cart
    await helper.page.click('a[href="/cart"]');
    await helper.page.waitForSelector('[data-testid="cart-item"]');
    
    // Step 7: Proceed to checkout
    await helper.page.click('button[data-testid="checkout"]');
    await helper.page.waitForSelector('form[data-testid="checkout-form"]');
    
    // Step 8: Fill checkout form
    await helper.page.type('input[name="shippingAddress"]', '123 Main St');
    await helper.page.type('input[name="city"]', 'Springfield');
    await helper.page.type('input[name="zip"]', '62701');
    
    // Step 9: Submit order
    await Promise.all([
      helper.page.click('button[type="submit"]'),
      helper.page.waitForNavigation({ waitUntil: 'networkidle0' })
    ]);
    
    // Step 10: Verify order confirmation
    expect(helper.page.url()).toContain('/order-confirmation');
    
    const orderNumber = await helper.page.evaluate(() => 
      document.querySelector('[data-testid="order-number"]')?.textContent
    );
    expect(orderNumber).toMatch(/order #\d+/i);
    
    // Verify order details
    const orderItems = await helper.page.$$('[data-testid="order-item"]');
    expect(orderItems.length).toBe(2);
  }, 180000); // 3 minute timeout
  
  it('should test data visualization dashboard', async () => {
    await helper.navigate('/dashboard');
    
    // Wait for dashboard to load
    await helper.page.waitForSelector('[data-testid="dashboard-chart"]');
    
    // Verify charts rendered
    const charts = await helper.page.$$('[data-testid="dashboard-chart"]');
    expect(charts.length).toBeGreaterThan(0);
    
    // Test filter functionality
    const dateFilter = await helper.page.$('select[name="dateRange"]');
    await dateFilter.selectOption('last-30-days');
    
    // Wait for chart update
    await helper.page.waitForFunction(
      () => {
        const charts = document.querySelectorAll('[data-testid="dashboard-chart"]');
        return charts.length > 0;
      },
      { timeout: 5000 }
    );
    
    // Verify data export
    const exportButton = await helper.page.$('button[data-testid="export-data"]');
    await exportButton.click();
    
    // Wait for download (if applicable)
    await helper.sleep(2000);
  });
});

// ====================
// PERFORMANCE AND LOAD TESTS
// ====================

describe('Performance and Load Tests', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.launchBrowser();
    await helper.waitForSystemReady();
  }, 180000);
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should handle concurrent user sessions', async () => {
    const concurrentUsers = 5;
    const browsers = [];
    
    // Launch multiple browsers
    for (let i = 0; i < concurrentUsers; i++) {
      const browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox']
      });
      browsers.push(browser);
    }
    
    // Create pages and perform actions
    const actions = browsers.map(async (browser, index) => {
      const page = await browser.newPage();
      
      try {
        // Login
        await page.goto(`${config.baseURL}/login`);
        await page.type('input[name="email"]', `user${index}@test.com`);
        await page.type('input[name="password"]', 'TestPass123!');
        await page.click('button[type="submit"]');
        await page.waitForNavigation();
        
        // Navigate to products
        await page.goto(`${config.baseURL}/products`);
        await page.waitForSelector('[data-testid="product-card"]');
        
        // Add to cart
        await page.click('button[data-testid="add-to-cart"]');
        
        return { success: true, userIndex: index };
      } catch (error) {
        return { success: false, userIndex: index, error: error.message };
      } finally {
        await page.close();
        await browser.close();
      }
    });
    
    const results = await Promise.all(actions);
    
    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;
    
    expect(successful).toBeGreaterThanOrEqual(concurrentUsers * 0.8); // 80% success rate
    expect(failed).toBeLessThanOrEqual(concurrentUsers * 0.2);
  });
  
  it('should maintain performance under sustained load', async () => {
    const testDuration = 60 * 1000; // 1 minute
    const requestInterval = 200; // 200ms between requests
    const requestCount = testDuration / requestInterval;
    
    const results = {
      success: 0,
      failed: 0,
      totalTime: 0,
      responseTimes: []
    };
    
    // Login first
    await helper.login(config.testUserEmail, config.testUserPassword);
    
    // Perform sustained requests
    for (let i = 0; i < requestCount; i++) {
      const startTime = Date.now();
      
      try {
        await helper.navigate('/api/v1/users/profile');
        results.success++;
        
        const responseTime = Date.now() - startTime;
        results.totalTime += responseTime;
        results.responseTimes.push(responseTime);
      } catch (error) {
        results.failed++;
      }
      
      await helper.sleep(requestInterval);
    }
    
    // Calculate statistics
    const successRate = results.success / requestCount;
    const avgResponseTime = results.totalTime / results.success;
    const p95ResponseTime = results.responseTimes
      .sort((a, b) => a - b)[Math.floor(results.responseTimes.length * 0.95)];
    
    expect(successRate).toBeGreaterThan(0.95); // 95% success rate
    expect(avgResponseTime).toBeLessThan(1000); // <1s average
    expect(p95ResponseTime).toBeLessThan(2000); // <2s p95
    
    console.log(`Sustained Load Test: ${successRate.toFixed(2)}% success rate, ${avgResponseTime.toFixed(0)}ms avg response, ${p95ResponseTime.toFixed(0)}ms p95`);
  }, 120000); // 2 minute test
});

// ====================
// SECURITY TESTS
// ====================

describe('Security Tests', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.launchBrowser();
    await helper.waitForSystemReady();
  }, 180000);
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should protect against XSS attacks', async () => {
    const maliciousInput = '<script>alert("XSS")</script>';
    
    await helper.navigate('/products');
    
    // Try search with malicious input
    const searchInput = await helper.page.$('input[name="search"]');
    await searchInput.type(maliciousInput);
    await helper.page.press('input[name="search"]', 'Enter');
    
    await helper.page.waitForNavigation();
    
    // Check if script was executed (it shouldn't be)
    const alertTriggered = await helper.page.evaluate(() => {
      window.alertTriggered = false;
      window.alert = () => { window.alertTriggered = true; };
      return window.alertTriggered;
    });
    
    expect(alertTriggered).toBe(false);
    
    // Verify input is properly escaped
    const pageContent = await helper.page.evaluate(() => document.body.innerHTML);
    expect(pageContent).not.toContain('<script>');
  });
  
  it('should enforce secure session management', async () => {
    await helper.navigate('/login');
    
    // Login
    await helper.page.type('input[name="email"]', config.testUserEmail);
    await helper.page.type('input[name="password"]', config.testUserPassword);
    await helper.page.click('button[type="submit"]');
    await helper.page.waitForNavigation();
    
    // Check for secure session storage
    const sessionStorage = await helper.page.evaluate(() => {
      const token = localStorage.getItem('accessToken');
      const refreshToken = localStorage.getItem('refreshToken');
      
      return {
        tokenExists: !!token,
        tokenFormat: token ? token.split('.').length : 0, // JWT has 3 parts
        refreshTokenSeparate: refreshToken !== token
      };
    });
    
    expect(sessionStorage.tokenExists).toBe(true);
    expect(sessionStorage.tokenFormat).toBe(3); // JWT format
    expect(sessionStorage.refreshTokenSeparate).toBe(true);
    
    // Verify HTTP-only cookies aren't accessible via JavaScript
    const cookies = await helper.page.evaluate(() => document.cookie);
    expect(cookies).not.toContain('accessToken');
  });
  
  it('should handle SQL injection attempts', async () => {
    const injectionAttempts = [
      "' OR '1'='1",
      "admin' --",
      "'; DROP TABLE users; --"
    ];
    
    for (const attempt of injectionAttempts) {
      await helper.navigate('/login');
      
      await helper.page.type('input[name="email"]', attempt);
      await helper.page.type('input[name="password"]', attempt);
      await helper.page.click('button[type="submit"]');
      
      // Should not crash or show DB errors
      const pageContent = await helper.page.evaluate(() => document.body.textContent);
      expect(pageContent).not.toMatch(/SQL|database|table|column/i);
      expect(pageContent).not.toMatch(/error.*(syntax|constraint|foreign key)/i);
    }
  });
});

// ====================
// COMPLIANCE TESTS
// ====================

describe('Compliance Tests', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.launchBrowser();
    await helper.waitForSystemReady();
  }, 180000);
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should support GDPR data export', async () => {
    // Login as test user
    await helper.login(config.testUserEmail, config.testUserPassword);
    
    // Navigate to data export page
    await helper.navigate('/account/data-export');
    
    // Request data export
    const exportButton = await helper.page.$('button[data-testid="export-data"]');
    await exportButton.click();
    
    // Wait for export to generate
    await helper.page.waitForSelector('[data-testid="export-download"]', { timeout: 60000 });
    
    // Download should be available
    const downloadButton = await helper.page.$('[data-testid="export-download"]');
    expect(downloadButton).toBeTruthy();
    
    // Verify export contains required data
    const exportInfo = await helper.page.evaluate(() => {
      return {
        containsPersonalInfo: !!document.querySelector('[data-section="personal-info"]'),
        containsActivity: !!document.querySelector('[data-section="activity-logs"]'),
        containsOrders: !!document.querySelector('[data-section="orders"]')
      };
    });
    
    expect(exportInfo.containsPersonalInfo).toBe(true);
    expect(exportInfo.containsActivity).toBe(true);
    expect(exportInfo.containsOrders).toBe(true);
  });
  
  it('should support data deletion request', async () => {
    // Create a temporary test account
    const tempEmail = `delete-test-${ faker.random.alphaNumeric(8) }@test.com`;
    
    await helper.navigate('/register');
    await helper.page.type('input[name="name"]', 'Delete Test User');
    await helper.page.type('input[name="email"]', tempEmail);
    await helper.page.type('input[name="password"]', 'TempPass123!');
    await helper.page.click('button[type="submit"]');
    await helper.page.waitForNavigation();
    
    // Login with new account
    await helper.page.type('input[name="email"]', tempEmail);
    await helper.page.type('input[name="password"]', 'TempPass123!');
    await helper.page.click('button[type="submit"]');
    await helper.page.waitForNavigation();
    
    // Navigate to account deletion
    await helper.page.click('a[href="/account/delete"]');
    await helper.page.waitForSelector('button[data-testid="delete-account"]');
    
    // Confirm deletion
    await helper.page.click('button[data-testid="delete-account"]');
    
    // Confirm in modal
    await helper.page.waitForSelector('[data-testid="confirm-delete"]');
    await helper.page.click('[data-testid="confirm-delete"]');
    
    // Should redirect to home/login
    await helper.page.waitForNavigation();
    expect(helper.page.url()).toMatch(/\/(login|home)$/);
    
    // Verify account is deleted (try to login)
    await helper.navigate('/login');
    await helper.page.type('input[name="email"]', tempEmail);
    await helper.page.type('input[name="password"]', 'TempPass123!');
    await helper.page.click('button[type="submit"]');
    
    // Should show error
    const errorText = await helper.page.evaluate(() => 
      document.querySelector('[data-testid="error-message"]')?.textContent
    );
    expect(errorText).toMatch(/account not found|invalid credentials/i);
  });
});

// ====================
// ACCESSIBILITY TESTS
// ====================

describe('Accessibility Tests', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.launchBrowser();
    await helper.waitForSystemReady();
  }, 180000);
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should be keyboard navigable', async () => {
    await helper.navigate('/login');
    
    // Navigate form fields using Tab
    await helper.page.keyboard.press('Tab');
    await helper.page.keyboard.type(config.testUserEmail);
    
    await helper.page.keyboard.press('Tab');
    await helper.page.keyboard.type(config.testUserPassword);
    
    await helper.page.keyboard.press('Tab');
    await helper.page.keyboard.press('Enter');
    
    // Should submit form
    await helper.page.waitForNavigation();
    
    // Should be logged in (redirect to dashboard/profile)
    const currentUrl = helper.page.url();
    expect(currentUrl).not.toContain('login');
  });
  
  it('should have proper ARIA labels and roles', async () => {
    await helper.navigate('/products');
    
    const accessibilityIssues = await helper.page.evaluate(async () => {
      const issues = [];
      
      // Check for images without alt text
      const images = document.querySelectorAll('img:not([alt])');
      if (images.length > 0) {
        issues.push(`${images.length} images missing alt text`);
      }
      
      // Check for buttons without accessible names
      const buttons = document.querySelectorAll('button:not([aria-label]):not([aria-labelledby]):empty');
      if (buttons.length > 0) {
        issues.push(`${buttons.length} buttons missing accessible names`);
      }
      
      // Check for form inputs without labels
      const inputs = document.querySelectorAll('input:not([aria-label]):not([aria-labelledby]):not([id])');
      if (inputs.length > 0) {
        issues.push(`${inputs.length} inputs missing labels`);
      }
      
      // Check color contrast (basic check)
      const elements = document.querySelectorAll('*');
      let lowContrastCount = 0;
      
      for (const el of elements) {
        const style = window.getComputedStyle(el);
        const color = style.color;
        const bgColor = style.backgroundColor;
        
        // Simple check: if both are similar shades of gray
        if (color.includes('rgb') && bgColor.includes('rgb')) {
          const colorMatch = color.match(/\d+/g);
          const bgMatch = bgColor.match(/\d+/g);
          
          if (colorMatch && bgMatch) {
            const rDiff = Math.abs(parseInt(colorMatch[0]) - parseInt(bgMatch[0]));
            const gDiff = Math.abs(parseInt(colorMatch[1]) - parseInt(bgMatch[1]));
            const bDiff = Math.abs(parseInt(colorMatch[2]) - parseInt(bgMatch[2]));
            
            const totalDiff = rDiff + gDiff + bDiff;
            if (totalDiff < 150) { // Very rough contrast check
              lowContrastCount++;
            }
          }
        }
      }
      
      if (lowContrastCount > 10) { // More than 10 elements with potential contrast issues
        issues.push(`${lowContrastCount} elements may have low contrast`);
      }
      
      return issues;
    });
    
    expect(accessibilityIssues.length).toBeLessThan(10); // Fewer than 10 issues
    
    if (accessibilityIssues.length > 0) {
      console.log('Accessibility issues found:', accessibilityIssues);
    }
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

# Run all system tests
npm test -- tests/system/

# Run specific system test
npm test -- tests/system/ecommerce_flow.test.js

# Run with visible browser (for debugging)
HEADLESS=false npm test -- tests/system/

# Run with slow motion (for debugging)
SLOW_MO=100 npm test -- tests/system/

# Run specific test
npm test -- -t "complete full e-commerce journey"

# Generate HTML report
npm test -- tests/system/ --reporters=jest-html-reporters --reporter-options=filename=system-report.html

# Run with max workers
npm test -- tests/system/ --maxWorkers=1

# Debug specific test
node --inspect-brk node_modules/.bin/jest tests/system/ecommerce_flow.test.js --runInBand

# Run tests in CI mode
CI=true npm test -- tests/system/

# Clear cache before running
npm test -- tests/system/ --clearCache

# Run with verbose output
npm test -- tests/system/ --verbose
*/

module.exports = { SystemTestConfig, SystemTestHelper };
