import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { rest } from 'msw';
import { setupServer } from 'msw/node';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { BrowserRouter } from 'react-router-dom';
import puppeteer from 'puppeteer';
import '@testing-library/jest-dom';

// System test server setup
export const systemServer = setupServer(
  // Mock all critical API endpoints
  rest.get('/api/auth/me', (req, res, ctx) => {
    const authHeader = req.headers.get('authorization');
    if (authHeader === 'Bearer valid-token') {
      return res(ctx.json({ user: { id: 1, name: 'Test User', email: 'test@example.com' } }));
    }
    return res(ctx.status(401), ctx.json({ error: 'Unauthorized' }));
  }),
  
  rest.post('/api/auth/login', (req, res, ctx) => {
    return res(ctx.json({ 
      user: { id: 1, name: 'Test User', email: 'test@example.com' },
      token: 'valid-token'
    }));
  }),
  
  rest.get('/api/posts', (req, res, ctx) => {
    return res(ctx.json([
      { id: 1, title: 'Post 1', content: 'Content 1' },
      { id: 2, title: 'Post 2', content: 'Content 2' },
    ]));
  }),
  
  rest.post('/api/posts', (req, res, ctx) => {
    return res(ctx.status(201), ctx.json({ 
      id: 3, 
      title: 'New Post', 
      content: 'New Content',
      createdAt: new Date().toISOString()
    }));
  })
);

// End-to-end test utilities
export class E2ETestHelper {
  constructor() {
    this.browser = null;
    this.page = null;
  }

  async setup() {
    this.browser = await puppeteer.launch({ 
      headless: process.env.NODE_ENV === 'test',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    this.page = await this.browser.newPage();
    
    // Set viewport and user agent
    await this.page.setViewport({ width: 1280, height: 720 });
    await this.page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
  }

  async goto(url) {
    await this.page.goto(`http://localhost:3000${url}`);
  }

  async login(email = 'test@example.com', password = 'password') {
    await this.page.fill('[data-testid=email-input]', email);
    await this.page.fill('[data-testid=password-input]', password);
    await this.page.click('[data-testid=login-button]');
    await this.page.waitForNavigation();
  }

  async createPost(title, content) {
    await this.page.click('[data-testid=new-post-button]');
    await this.page.fill('[data-testid=post-title]', title);
    await this.page.fill('[data-testid=post-content]', content);
    await this.page.click('[data-testid=save-post-button]');
    await this.page.waitForSelector('[data-testid=post-saved]');
  }

  async teardown() {
    if (this.browser) {
      await this.browser.close();
    }
  }
}

// System test template
describe('{{COMPONENT_NAME}} System Tests', () => {
  let e2eHelper;

  beforeAll(() => {
    systemServer.listen();
  });

  afterAll(() => {
    systemServer.close();
  });

  beforeEach(async () => {
    e2eHelper = new E2ETestHelper();
    await e2eHelper.setup();
  });

  afterEach(async () => {
    await e2eHelper.teardown();
    systemServer.resetHandlers();
  });

  it('performs complete user journey', async () => {
    // Navigate to home page
    await e2eHelper.goto('/');
    
    // Verify page loads
    await expect(e2eHelper.page).toMatch('Welcome to {{APP_NAME}}');
    
    // Login flow
    await e2eHelper.login();
    await expect(e2eHelper.page).toMatch('Welcome, Test User');
    
    // Create content
    await e2eHelper.createPost('Test Post', 'Test Content');
    await expect(e2eHelper.page).toMatch('Post created successfully');
    
    // Navigate to posts
    await e2eHelper.goto('/posts');
    await expect(e2eHelper.page).toMatch('Test Post');
  });

  it('handles authentication across the app', async () => {
    // Try to access protected route without auth
    await e2eHelper.goto('/dashboard');
    await expect(e2eHelper.page).toMatch('Please login to continue');
    
    // Login
    await e2eHelper.goto('/login');
    await e2eHelper.login();
    
    // Access protected route now works
    await e2eHelper.goto('/dashboard');
    await expect(e2eHelper.page).toMatch('Dashboard');
  });

  it('maintains state across page refreshes', async () => {
    // Login
    await e2eHelper.goto('/login');
    await e2eHelper.login();
    
    // Refresh page
    await e2eHelper.page.reload();
    
    // User should still be logged in
    await expect(e2eHelper.page).toMatch('Welcome, Test User');
  });

  it('handles network errors gracefully', async () => {
    // Mock network failure
    systemServer.use(
      rest.get('/api/posts', (req, res, ctx) => {
        return res.networkError('Network error');
      })
    );

    await e2eHelper.goto('/posts');
    await expect(e2eHelper.page).toMatch('Unable to load posts');
  });
});

// Performance system tests
describe('{{APP_NAME}} Performance Tests', () => {
  it('loads within acceptable time limits', async () => {
    const e2eHelper = new E2ETestHelper();
    await e2eHelper.setup();
    
    const startTime = Date.now();
    await e2eHelper.goto('/');
    await e2eHelper.page.waitForSelector('[data-testid=app-loaded]');
    const loadTime = Date.now() - startTime;
    
    expect(loadTime).toBeLessThan(3000); // Should load in under 3 seconds
    
    await e2eHelper.teardown();
  });

  it('handles large datasets efficiently', async () => {
    // Mock large dataset
    systemServer.use(
      rest.get('/api/posts', (req, res, ctx) => {
        const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
          id: i,
          title: `Post ${i}`,
          content: `Content for post ${i}`.repeat(10)
        }));
        return res(ctx.json(largeDataset));
      })
    );

    const e2eHelper = new E2ETestHelper();
    await e2eHelper.setup();
    
    await e2eHelper.goto('/posts');
    
    // Should implement virtual scrolling or pagination
    await expect(e2eHelper.page).toMatch('Showing 1-50 of 1000');
    
    await e2eHelper.teardown();
  });
});

// Accessibility system tests
describe('{{APP_NAME}} Accessibility Tests', () => {
  it('is navigable via keyboard', async () => {
    const e2eHelper = new E2ETestHelper();
    await e2eHelper.setup();
    
    await e2eHelper.goto('/');
    
    // Tab through interactive elements
    await e2eHelper.page.keyboard.press('Tab');
    let focused = await e2eHelper.page.evaluate(() => document.activeElement.tagName);
    expect(focused).toBe('BUTTON');
    
    await e2eHelper.page.keyboard.press('Tab');
    focused = await e2eHelper.page.evaluate(() => document.activeElement.tagName);
    expect(focused).toBe('A');
    
    await e2eHelper.teardown();
  });

  it('provides proper ARIA labels', async () => {
    const e2eHelper = new E2ETestHelper();
    await e2eHelper.setup();
    
    await e2eHelper.goto('/');
    
    // Check for ARIA labels on interactive elements
    const buttons = await e2eHelper.page.$$('[role="button"]');
    for (const button of buttons) {
      const hasLabel = await e2eHelper.page.evaluate(el => {
        return el.hasAttribute('aria-label') || el.hasAttribute('aria-labelledby') || el.textContent.trim();
      }, button);
      expect(hasLabel).toBe(true);
    }
    
    await e2eHelper.teardown();
  });
});

// Cross-browser compatibility tests
describe('{{APP_NAME}} Cross-Browser Tests', () => {
  const browsers = ['chromium', 'firefox', 'webkit'];
  
  browsers.forEach(browserType => {
    it(`works correctly in ${browserType}`, async () => {
      const browser = await puppeteer.launch({ 
        headless: true,
        product: browserType
      });
      const page = await browser.newPage();
      
      await page.goto('http://localhost:3000');
      await page.waitForSelector('[data-testid=app-loaded]');
      
      const title = await page.title();
      expect(title).toBe('{{APP_NAME}}');
      
      await browser.close();
    });
  });
});

// Mobile responsiveness tests
describe('{{APP_NAME}} Mobile Tests', () => {
  it('displays correctly on mobile devices', async () => {
    const e2eHelper = new E2ETestHelper();
    await e2eHelper.setup();
    
    // Set mobile viewport
    await e2eHelper.page.setViewport({ width: 375, height: 667 });
    
    await e2eHelper.goto('/');
    
    // Check for mobile navigation
    await expect(e2eHelper.page).toMatch('[data-testid=mobile-menu]');
    
    // Menu should be collapsed by default
    const isMenuCollapsed = await e2eHelper.page.evaluate(() => {
      const menu = document.querySelector('[data-testid=mobile-menu]');
      return menu && menu.classList.contains('collapsed');
    });
    expect(isMenuCollapsed).toBe(true);
    
    await e2eHelper.teardown();
  });
});
