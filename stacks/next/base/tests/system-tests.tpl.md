# Next.js System Tests Template
// Next.js System Testing Template
// End-to-end system testing patterns for Next.js projects

/**
 * Next.js System Test Patterns
 * Complete E2E testing with business workflows, SSR/SSG, authentication, security
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
  }
}

class SystemTestHelper {
  constructor(config) {
    this.config = config;
    this.browser = null;
    this.page = null;
  }
  
  async launchBrowser() {
    this.browser = await puppeteer.launch({
      headless: process.env.HEADLESS !== 'false',
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
    
    // Verify login succeeded for Next.js
    const loggedIn = await this.page.evaluate(() => {
      return document.body.textContent.includes('Dashboard') ||
             document.body.textContent.includes('Profile') ||
             !window.location.pathname.includes('login');
    });
    
    return loggedIn;
  }
  
  async waitForSystemReady() {
    for (let attempt = 0; attempt < 30; attempt++) {
      try {
        await this.navigate('/api/health');
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
  }, 180000);
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should load Next.js application in browser', async () => {
    await helper.navigate('/');
    
    // Verify page loaded
    const pageSource = await this.page.content();
    expect(pageSource).toContain('<html');
    expect(pageSource).toContain('</html>');
    
    // Check for Next.js data
    const hasNextJs = await helper.page.evaluate(() => {
      return !!window.__NEXT_DATA__ || document.querySelector('script[data-next-page]');
    });
    
    expect(hasNextJs).toBe(true);
  });
  
  it('should support both SSG and SSR pages', async () => {
    // Navigate to SSG page (e.g., products)
    await helper.navigate('/products');
    
    const ssgSource = await helper.page.content();
    expect(ssgSource).toContain('data-nextjs=""');
    
    // Navigate to SSR page (e.g., dashboard)
    await helper.navigate('/dashboard');
    
    const ssrSource = await helper.page.content();
    expect(ssrSource).toContain('data-nextjs=""');
    
    // Verify both pages work
    const productsVisible = await helper.page.waitForSelector('[data-testid="product-card"]');
    expect(productsVisible).toBeTruthy();
  });
  
  it('should check performance metrics', async () => {
    await helper.navigate('/');
    
    // Get Core Web Vitals
    const cwv = await helper.page.evaluate(() => {
      const navEntries = performance.getEntriesByType('navigation');
      const largestContentfulPaint = performance.getEntriesByType('largest-contentful-paint');
      const firstInputDelay = performance.getEntriesByType('first-input');
      const cumulativeLayoutShift = performance.getEntriesByType('layout-shift');
      
      return {
        ttfb: navEntries[0]?.responseStart - navEntries[0]?.requestStart,
        fcp: navEntries[0]?.domContentLoadedEventStart - navEntries[0]?.responseStart,
        lcp: largestContentfulPaint[0]?.startTime || 0,
        cls: cumulativeLayoutShift.reduce((sum, entry) => sum + entry.value, 0)
      };
    });
    
    console.log('Core Web Vitals:', cwv);
    
    // Verify reasonable metrics
    expect(cwv.ttfb).toBeLessThan(1000); // <1s TTFB
    expect(cwv.fcp).toBeLessThan(3000); // <3s First Contentful Paint
    expect(cwv.lcp).toBeLessThan(4000); // <4s Largest Contentful Paint
  });
});

// ====================
// COMPLETE E-COMMERCE WORKFLOW TESTS
// ====================

describe('Next.js E-commerce Workflow', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.launchBrowser();
    await helper.waitForSystemReady();
  }, 180000);
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should complete next-gen e-commerce journey', async () => {
    // Step 1: Navigate to site and verify SSR content
    await helper.navigate('/');
    
    // Check for SSR-rendered content
    const ssrContent = await helper.page.evaluate(() => 
      document.querySelector('[data-testid="ssr-content"]')
    );
    expect(ssrContent).toBeTruthy();
    
    // Step 2: Dynamic route navigation
    await helper.page.click('a[href="/products"]');
    await helper.page.waitForSelector('[data-testid="product-card"]');
    
    // Verify SSG/ISR
    const firstCard = await helper.page.$('[data-testid="product-card"]');
    expect(firstCard).toBeTruthy();
    
    // Step 3: Navigate to dynamic product route
    const productLink = await helper.page.$('a[href^="/products/"]');
    await productLink.click();
    await helper.page.waitForNavigation();
    
    // Verify dynamic route works
    const productDetail = await helper.page.waitForSelector('[data-testid="product-detail"]');
    expect(productDetail).toBeTruthy();
    
    // Step 4: Add to cart with API route
    await helper.page.click('button[data-testid="add-to-cart"]');
    
    // Wait for API response
    await helper.page.waitForResponse(response => 
      response.url().includes('/api/cart') && response.status() === 201
    );
    
    // Verify cart updated
    const cartBadge = await helper.page.$('[data-testid="cart-badge"]');
    const badgeText = await helper.page.evaluate(el => el.textContent, cartBadge);
    expect(badgeText).toBe('1');
    
    // Step 5: Navigate to cart with SSG
    await helper.page.click('a[href="/cart"]');
    await helper.page.waitForSelector('[data-testid="cart-item"]');
    
    // Step 6: Use middleware for auth check
    await helper.page.click('button[data-testid="checkout"]');
    
    // Should redirect to login if not authenticated
    const currentUrl = helper.page.url();
    if (currentUrl.includes('/login')) {
      // Login
      await helper.page.type('input[name="email"]', 'test@example.com');
      await helper.page.type('input[name="password"]', 'TestPass123!');
      await helper.page.click('button[type="submit"]');
      await helper.page.waitForNavigation();
    }
    
    // Step 7: Complete checkout with API route
    await helper.page.type('input[name="address"]', '123 Main St');
    await helper.page.type('input[name="city"]', 'Springfield');
    await helper.page.type('input[name="zip"]', '62701');
    
    const orderResponse = await Promise.all([
      helper.page.click('button[type="submit"]'),
      helper.page.waitForResponse(response => 
        response.url().includes('/api/orders') && response.status() === 201
      )
    ]);
    
    // Step 8: Verify success page with ISR
    await helper.page.waitForSelector('[data-testid="order-confirmation"]');
    
    const orderNumber = await helper.page.evaluate(() =>
      document.querySelector('[data-testid="order-number"]')?.textContent
    );
    expect(orderNumber).toMatch(/order #\d+/i);
  }, 180000);
  
  it('should test API route error handling', async () => {
    await helper.navigate('/api/fallback-test');
    
    // Test fallback route for 404 errors
    await helper.navigate('/non-existent-page');
    
    await helper.page.waitForSelector('[data-testid="error-page"]');
    
    const errorStatus = await helper.page.evaluate(() =>
      document.querySelector('[data-testid="error-status"]')?.textContent
    );
    expect(errorStatus).toBe('404');
  });
});

// ====================
// AUTHENTICATION WORKFLOW TESTS
// ====================

describe('Next.js Authentication Workflows', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.launchBrowser();
    await helper.waitForSystemReady();
  }, 180000);
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should test complete OAuth flow', async () => {
    await helper.navigate('/login');
    
    // Click Google OAuth button
    const googleButton = await helper.page.$('button[data-auth="google"]');
    await googleButton.click();
    
    // Should redirect to Google (mocked in test environment)
    await helper.page.waitForNavigation();
    
    // Simulate OAuth callback
    await helper.navigate('/api/auth/callback/google?code=test-code');
    
    // Should create session and redirect
    await helper.page.waitForNavigation();
    
    const currentUrl = helper.page.url();
    expect(currentUrl).not.toContain('/login');
  });
  
  it('should test JWT token refresh mechanism', async () => {
    await helper.login(config.testUserEmail, config.testUserPassword);
    
    // Wait for token to be set
    await helper.page.waitForFunction(() => 
      localStorage.getItem('accessToken')
    );
    
    // Simulate token expiration
    await helper.page.evaluate(() => {
      localStorage.setItem('tokenExpired', 'true');
    });
    
    // Navigate to protected page
    await helper.navigate('/dashboard');
    
    // Should auto-refresh token
    const tokenRefreshed = await helper.page.waitForResponse(response =>
      response.url().includes('/api/auth/refresh') && response.status() === 200
    );
    
    expect(tokenRefreshed).toBeTruthy();
  });
  
  it('should test role-based access control (RBAC)', async () => {
    // Login as regular user
    await helper.login('user@example.com', 'user123');
    
    // Try to access admin route
    await helper.navigate('/admin/users');
    
    // Should redirect or show access denied
    const hasAccess = await helper.page.evaluate(() => {
      return !document.body.textContent.includes('Access Denied') &&
             !window.location.pathname.includes('login');
    });
    
    expect(hasAccess).toBe(false);
    
    // Login as admin
    await helper.navigate('/login');
    await helper.page.type('input[name="email"]', config.adminEmail);
    await helper.page.type('input[name="password"]', config.adminPassword);
    await helper.page.click('button[type="submit"]');
    await helper.page.waitForNavigation();
    
    // Try admin route again
    await helper.navigate('/admin/users');
    
    const adminHasAccess = await helper.page.evaluate(() => {
      return document.querySelector('[data-testid="admin-panel"]') !== null;
    });
    
    expect(adminHasAccess).toBe(true);
  });
});

// ====================
// PERFORMANCE AND SEO TESTS
// ====================

describe('Next.js Performance and SEO', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.launchBrowser();
    await helper.waitForSystemReady();
  }, 180000);
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should validate Core Web Vitals', async () => {
    await helper.navigate('/products');
    
    // Measure LCP
    const lcp = await helper.page.evaluate(() => {
      return new Promise(resolve => {
        new PerformanceObserver(entryList => {
          const entries = entryList.getEntries();
          const lcpEntry = entries[entries.length - 1];
          resolve(lcpEntry.startTime);
        }).observe({ entryTypes: ['largest-contentful-paint'] });
      });
    });
    
    console.log('LCP:', lcp);
    expect(lcp).toBeLessThan(4000); // <4s LCP
  });
  
  it('should test ISR (Incremental Static Regeneration)', async () => {
    // Navigate to ISR page
    await helper.navigate('/blog/post-1');
    
    // Get initial build time
    const initialBuildTime = await helper.page.evaluate(() => {
      return document.querySelector('[data-build-time]')?.textContent;
    });
    
    // Wait for revalidation period
    await helper.sleep(5000);
    
    // Refresh page
    await helper.page.reload();
    
    // Get updated build time
    const updatedBuildTime = await helper.page.evaluate(() => {
      return document.querySelector('[data-build-time]')?.textContent;
    });
    
    // Should be different due to ISR
    expect(initialBuildTime).not.toBe(updatedBuildTime);
  });
  
  it('should verify SEO meta tags', async () => {
    await helper.navigate('/products');
    
    const seoTags = await helper.page.evaluate(() => {
      const title = document.querySelector('title')?.textContent;
      const description = document.querySelector('meta[name="description"]')?.content;
      const ogTitle = document.querySelector('meta[property="og:title"]')?.content;
      const ogImage = document.querySelector('meta[property="og:image"]')?.content;
      
      return {
        title,
        description,
        ogTitle,
        ogImage
      };
    });
    
    expect(seoTags.title).toBeTruthy();
    expect(seoTags.description).toBeTruthy();
    expect(seoTags.ogTitle).toBeTruthy();
    expect(seoTags.ogImage).toBeTruthy();
  });
});

// ====================
// MIDDLEWARE AND SECURITY TESTS
// ====================

describe('Next.js Middleware and Security', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.launchBrowser();
    await helper.waitForSystemReady();
  }, 180000);
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should test CSRF protection', async () => {
    await helper.navigate('/login');
    
    // Check for CSRF token
    const hasCSRFToken = await helper.page.evaluate(() => {
      return document.querySelector('input[name="csrfToken"]') !== null ||
             document.querySelector('meta[name="csrf-token"]') !== null;
    });
    
    expect(hasCSRFToken).toBe(true);
  });
  
  it('should test rate limiting via middleware', async () => {
    // Make multiple rapid requests
    const requests = [];
    
    for (let i = 0; i < 20; i++) {
      requests.push(
        fetch(`${config.baseURL}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: 'test@example.com',
            password: 'wrongpassword'
          })
        })
      );
    }
    
    const responses = await Promise.all(requests);
    const rateLimitedResponses = responses.filter(r => r.status === 429);
    
    expect(rateLimitedResponses.length).toBeGreaterThan(0);
  });
  
  it('should test CSP headers via middleware', async () => {
    await helper.navigate('/');
    
    const cspHeader = await helper.page.evaluate(() => {
      return performance.getEntriesByType('navigation')[0]
        .serverTiming?.find(t => t.name === 'csp')?.description;
    });
    
    // Check for CSP meta tag as fallback
    const hasCSPMeta = await helper.page.evaluate(() => {
      return document.querySelector('meta[http-equiv="Content-Security-Policy"]') !== null;
    });
    
    expect(cspHeader || hasCSPMeta).toBeTruthy();
  });
});

// ====================
// INTERNATIONALIZATION TESTS
// ====================

describe('Next.js Internationalization', () => {
  
  const config = new SystemTestConfig();
  const helper = new SystemTestHelper(config);
  
  beforeAll(async () => {
    await helper.launchBrowser();
    await helper.waitForSystemReady();
  }, 180000);
  
  afterAll(async () => {
    await helper.closeBrowser();
  });
  
  it('should switch languages and update content', async () => {
    await helper.navigate('/');
    
    // Get default language
    const defaultLang = await helper.page.evaluate(() =>
      document.documentElement.lang
    );
    
    // Switch language
    const languageSelector = await helper.page.$('select[data-testid="language-selector"]');
    if (languageSelector) {
      await languageSelector.select('fr'); // French
      
      // Verify content updated
      const frenchContent = await helper.page.evaluate(() =>
        document.querySelector('h1')?.textContent
      );
      
      expect(document.documentElement.lang).toBe('fr');
    }
  });
  
  it('should persist language preference', async () => {
    await helper.navigate('/');
    
    // Select language
    await helper.page.select('select[data-testid="language-selector"]', 'es');
    
    // Navigate to another page
    await helper.page.click('a[href="/about"]');
    await helper.page.waitForNavigation();
    
    // Check language persisted
    const currentLang = await helper.page.evaluate(() =>
      document.documentElement.lang
    );
    
    expect(currentLang).toBe('es');
  });
});

// ====================
// RUN SYSTEM TESTS
// ====================

/*
Commands to run Next.js system tests:

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

# Run with visible browser
HEADLESS=false npm test -- tests/system/

# Run with slow motion
SLOW_MO=100 npm test -- tests/system/

# Run specific test
npm test -- -t "complete next-gen e-commerce journey"

# Generate HTML report
npm test -- tests/system/ --reporters=jest-html-reporters --reporter-options=filename=system-report.html

# Run with max workers
npm test -- tests/system/ --maxWorkers=1

# Debug specific test
node --inspect-brk node_modules/.bin/jest tests/system/ecommerce_flow.test.js --runInBand

# Run tests in CI mode
CI=true npm test -- tests/system/
*/
