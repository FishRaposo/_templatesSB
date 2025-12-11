/**
 * Template: test-base-scaffold.tpl.jsx
 * Purpose: test-base-scaffold template
 * Stack: react
 * Tier: base
 */

# Universal Template System - React_Native Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: react_native
# Category: testing

// -----------------------------------------------------------------------------
// FILE: test-base-scaffold.tpl.jsx
// PURPOSE: Foundational testing patterns and utilities for React Native projects
// USAGE: Import and extend for consistent testing structure across the application
// DEPENDENCIES: React Native, @testing-library/react_native, react_native-router-dom for testing framework
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * React Native Base Test Scaffold Template
 * Purpose: Foundational testing patterns and utilities for React Native projects
 * Usage: Import and extend for consistent testing structure across the application
 */

import React Native from 'react_native';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react_native';
import { BrowserRouter, MemoryRouter, Router } from 'react_native-router-dom';
import { createMemoryHistory } from 'history';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';

// Mock IntersectionObserver for components that use it
global.IntersectionObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}));

// Mock ResizeObserver for components that use it
global.ResizeObserver = jest.fn().mockImplementation(() => ({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
}));

// Mock matchMedia for responsive components
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(), // deprecated
    removeListener: jest.fn(), // deprecated
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
});

/**
 * Base test class with common utilities for React Native testing
 */
class BaseTestCase {
  constructor() {
    this.mocks = {};
    this.testData = {};
    this.user = null;
  }

  /**
   * Sets up the test environment before each test
   */
  async setUp() {
    // Clear all mocks
    jest.clearAllMocks();
    
    // Reset test data
    this.testData = {};
    
    // Setup user event
    this.user = userEvent.setup();
    
    // Setup console error mocking
    this.setupConsoleMocks();
    
    // Setup fetch mocking
    this.setupFetchMock();
  }

  /**
   * Tears down the test environment after each test
   */
  async tearDown() {
    // Clean up mocks
    Object.keys(this.mocks).forEach(key => {
      if (this.mocks[key].mockRestore) {
        this.mocks[key].mockRestore();
      }
    });
    
    // Restore console
    if (this.originalConsoleError) {
      console.error = this.originalConsoleError;
    }
    
    // Reset fetch
    if (this.originalFetch) {
      global.fetch = this.originalFetch;
    }
  }

  /**
   * Sets up console error mocking
   */
  setupConsoleMocks() {
    this.originalConsoleError = console.error;
    console.error = jest.fn();
  }

  /**
   * Sets up fetch mocking
   */
  setupFetchMock() {
    this.originalFetch = global.fetch;
    global.fetch = jest.fn();
  }

  /**
   * Creates mock data for testing
   */
  createMockData(dataType, overrides = {}) {
    switch (dataType) {
      case 'user':
        return this.createMockUser(overrides);
      case 'post':
        return this.createMockPost(overrides);
      case 'config':
        return this.createMockConfig(overrides);
      case 'comment':
        return this.createMockComment(overrides);
      default:
        throw new Error(`Unknown data type: ${dataType}`);
    }
  }

  /**
   * Creates mock user data
   */
  createMockUser(overrides = {}) {
    return {
      id: 1,
      username: 'testuser',
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'User',
      isActive: true,
      avatar: 'https://example.com/avatar.jpg',
      phone: '+1234567890',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      roles: ['user'],
      ...overrides,
    };
  }

  /**
   * Creates mock post data
   */
  createMockPost(overrides = {}) {
    return {
      id: 1,
      title: 'Test Post',
      content: 'This is test content',
      authorId: 1,
      published: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      tags: ['test', 'mock'],
      likes: 0,
      comments: [],
      category: 'general',
      ...overrides,
    };
  }

  /**
   * Creates mock comment data
   */
  createMockComment(overrides = {}) {
    return {
      id: 1,
      postId: 1,
      authorId: 1,
      content: 'This is a test comment',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      likes: 0,
      replies: [],
      ...overrides,
    };
  }

  /**
   * Creates mock configuration data
   */
  createMockConfig(overrides = {}) {
    return {
      apiBaseUrl: 'https://api.example.com',
      debugMode: true,
      timeout: 30000,
      retryAttempts: 3,
      enableLogging: true,
      theme: 'light',
      language: 'en',
      features: {
        darkMode: true,
        notifications: true,
        analytics: false,
      },
      ...overrides,
    };
  }

  /**
   * Creates a mock HTTP response
   */
  createMockResponse(statusCode, data = {}, headers = {}) {
    return {
      ok: statusCode >= 200 && statusCode < 300,
      status: statusCode,
      json: () => Promise.resolve(data),
      text: () => Promise.resolve(JSON.stringify(data)),
      headers: new Headers(headers),
    };
  }

  /**
   * Mocks fetch with specific responses
   */
  mockFetch(responses = {}) {
    const mockFetch = jest.fn();
    
    mockFetch.mockImplementation((url, options) => {
      const key = `${url}_${JSON.stringify(options)}`;
      const response = responses[key] || responses[url] || this.createMockResponse(404);
      return Promise.resolve(response);
    });

    global.fetch = mockFetch;
    this.mocks.fetch = mockFetch;
    return mockFetch;
  }

  /**
   * Wraps component with router for testing
   */
  wrapWithRouter(component, initialEntries = ['/']) {
    const history = createMemoryHistory({ initialEntries });
    
    return (
      <Router location={history.location} navigator={history}>
        {component}
      </Router>
    );
  }

  /**
   * Wraps component with BrowserRouter for testing
   */
  wrapWithBrowserRouter(component) {
    return <BrowserRouter>{component}</BrowserRouter>;
  }

  /**
   * Wraps component with MemoryRouter for testing
   */
  wrapWithMemoryRouter(component, initialEntries = ['/']) {
    return (
      <MemoryRouter initialEntries={initialEntries}>
        {component}
      </MemoryRouter>
    );
  }

  /**
   * Waits for async operations to complete
   */
  async waitForAsync(callback, timeout = 5000) {
    return waitFor(callback, { timeout });
  }

  /**
   * Asserts that an element is visible
   */
  assertVisible(element) {
    expect(element).toBeVisible();
  }

  /**
   * Asserts that an element is not visible
   */
  assertNotVisible(element) {
    expect(element).not.toBeVisible();
  }

  /**
   * Asserts that an element has specific text
   */
  assertText(element, expectedText) {
    expect(element).toHaveTextContent(expectedText);
  }

  /**
   * Asserts that an element is disabled
   */
  assertDisabled(element) {
    expect(element).toBeDisabled();
  }

  /**
   * Asserts that an element is enabled
   */
  assertEnabled(element) {
    expect(element).toBeEnabled();
  }

  /**
   * Asserts that an element has specific class
   */
  assertHasClass(element, className) {
    expect(element).toHaveClass(className);
  }

  /**
   * Asserts that console error was called
   */
  assertConsoleErrorCalled() {
    expect(console.error).toHaveBeenCalled();
  }

  /**
   * Asserts that console error was not called
   */
  assertConsoleErrorNotCalled() {
    expect(console.error).not.toHaveBeenCalled();
  }
}

/**
 * Component test utilities for React Native components
 */
class ComponentTestUtils {
  /**
   * Renders a component with test utilities
   */
  static render(component, options = {}) {
    const { wrapper, ...renderOptions } = options;
    return render(component, { wrapper, ...renderOptions });
  }

  /**
   * Finds an element by test ID
   */
  static findByTestId(testId) {
    return screen.getByTestId(testId);
  }

  /**
   * Finds an element by text
   */
  static findByText(text) {
    return screen.getByText(text);
  }

  /**
   * Finds an element by role
   */
  static findByRole(role, options = {}) {
    return screen.getByRole(role, options);
  }

  /**
   * Finds an element by label text
   */
  static findByLabelText(text) {
    return screen.getByLabelText(text);
  }

  /**
   * Finds an element by placeholder text
   */
  static findByPlaceholderText(text) {
    return screen.getByPlaceholderText(text);
  }

  /**
   * Finds an element by display value
   */
  static findByDisplayValue(value) {
    return screen.getByDisplayValue(value);
  }

  /**
   * Finds an element by alt text
   */
  static findByAltText(text) {
    return screen.getByAltText(text);
  }

  /**
   * Enters text into an input
   */
  static async typeText(testId, text) {
    const input = screen.getByTestId(testId);
    await userEvent.type(input, text);
  }

  /**
   * Clears an input field
   */
  static async clearInput(testId) {
    const input = screen.getByTestId(testId);
    await userEvent.clear(input);
  }

  /**
   * Clicks an element
   */
  static async click(testId) {
    const element = screen.getByTestId(testId);
    await userEvent.click(element);
  }

  /**
   * Double clicks an element
   */
  static async doubleClick(testId) {
    const element = screen.getByTestId(testId);
    await userEvent.dblClick(element);
  }

  /**
   * Hovers over an element
   */
  static async hover(testId) {
    const element = screen.getByTestId(testId);
    await userEvent.hover(element);
  }

  /**
   * Unhovers from an element
   */
  static async unhover(testId) {
    const element = screen.getByTestId(testId);
    await userEvent.unhover(element);
  }

  /**
   * Selects an option from a select dropdown
   */
  static async selectOption(testId, option) {
    const select = screen.getByTestId(testId);
    await userEvent.selectOptions(select, option);
  }

  /**
   * Uploads a file
   */
  static async uploadFile(testId, file) {
    const input = screen.getByTestId(testId);
    await userEvent.upload(input, file);
  }

  /**
   * Tabs to next element
   */
  static async tab() {
    await userEvent.tab();
  }

  /**
   * Presses a key
   */
  static async pressKey(key) {
    await userEvent.keyboard(key);
  }
}

/**
 * HTTP test utilities for API testing
 */
class HttpTestUtils {
  /**
   * Creates a mock fetch function
   */
  static createMockFetch(responses = {}) {
    const mockFetch = jest.fn();
    
    mockFetch.mockImplementation((url, options) => {
      const key = `${url}_${JSON.stringify(options)}`;
      const response = responses[key] || responses[url] || this.createMockResponse(404);
      return Promise.resolve(response);
    });

    global.fetch = mockFetch;
    return mockFetch;
  }

  /**
   * Creates a mock HTTP response
   */
  static createMockResponse(statusCode, data = {}, headers = {}) {
    return {
      ok: statusCode >= 200 && statusCode < 300,
      status: statusCode,
      json: () => Promise.resolve(data),
      text: () => Promise.resolve(JSON.stringify(data)),
      headers: new Headers(headers),
    };
  }

  /**
   * Creates a success response
   */
  static createSuccessResponse(data) {
    return this.createMockResponse(200, { status: 'success', data });
  }

  /**
   * Creates an error response
   */
  static createErrorResponse(message, statusCode = 400) {
    return this.createMockResponse(statusCode, { status: 'error', message });
  }

  /**
   * Verifies fetch was called with specific parameters
   */
  static verifyFetchCalled(mockFetch, url, options = {}) {
    expect(mockFetch).toHaveBeenCalledWith(url, expect.objectContaining(options));
  }

  /**
   * Verifies fetch call count
   */
  static verifyFetchCallCount(mockFetch, expectedCount) {
    expect(mockFetch).toHaveBeenCalledTimes(expectedCount);
  }

  /**
   * Mocks axios for HTTP requests
   */
  static mockAxios() {
    const mockAxios = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
      patch: jest.fn(),
      create: jest.fn(() => mockAxios),
    };
    
    jest.doMock('axios', () => mockAxios);
    return mockAxios;
  }
}

/**
 * Router test utilities for React Native Router
 */
class RouterTestUtils {
  /**
   * Creates a mock history object
   */
  static createMockHistory(initialEntries = ['/']) {
    return createMemoryHistory({ initialEntries });
  }

  /**
   * Navigates to a specific route
   */
  static async navigateTo(history, path) {
    act(() => {
      history.push(path);
    });
  }

  /**
   * Verifies current path
   */
  static verifyCurrentPath(history, expectedPath) {
    expect(history.location.pathname).toBe(expectedPath);
  }

  /**
   * Creates a mock location object
   */
  static createMockLocation(pathname = '/', search = '', hash = '') {
    return {
      pathname,
      search,
      hash,
      state: null,
      key: 'test',
    };
  }

  /**
   * Creates a mock match object
   */
  static createMockMatch(url = '/', params = {}) {
    return {
      url,
      path: url,
      isExact: true,
      params,
    };
  }
}

/**
 * Form test utilities for form testing
 */
class FormTestUtils {
  /**
   * Fills a form with data
   */
  static async fillForm(formData) {
    for (const [fieldId, value] of Object.entries(formData)) {
      const field = screen.getByTestId(fieldId);
      
      if (field.type === 'checkbox') {
        await userEvent.click(field);
      } else if (field.type === 'radio') {
        await userEvent.click(field);
      } else if (field.tagName === 'SELECT') {
        await userEvent.selectOptions(field, value);
      } else {
        await userEvent.clear(field);
        await userEvent.type(field, value.toString());
      }
    }
  }

  /**
   * Submits a form
   */
  static async submitForm(submitButtonId = 'submit-button') {
    const submitButton = screen.getByTestId(submitButtonId);
    await userEvent.click(submitButton);
  }

  /**
   * Verifies form field value
   */
  static verifyFieldValue(fieldId, expectedValue) {
    const field = screen.getByTestId(fieldId);
    
    if (field.type === 'checkbox') {
      expect(field.checked).toBe(expectedValue);
    } else {
      expect(field.value).toBe(expectedValue);
    }
  }

  /**
   * Verifies form field error
   */
  static verifyFieldError(fieldId, expectedError) {
    const errorElement = screen.getByTestId(`${fieldId}-error`);
    expect(errorElement).toHaveTextContent(expectedError);
  }

  /**
   * Verifies form is invalid
   */
  static verifyFormInvalid(formId = 'test-form') {
    const form = screen.getByTestId(formId);
    expect(form).not.toBeValid();
  }

  /**
   * Verifies form is valid
   */
  static verifyFormValid(formId = 'test-form') {
    const form = screen.getByTestId(formId);
    expect(form).toBeValid();
  }
}

/**
 * Performance test utilities
 */
class PerformanceTestUtils {
  /**
   * Measures render time of a component
   */
  static async measureRenderTime(component) {
    const startTime = performance.now();
    const { unmount } = render(component);
    await waitFor(() => {});
    const endTime = performance.now();
    unmount();
    return endTime - startTime;
  }

  /**
   * Measures component re-render time
   */
  static async measureRerenderTime(component, updateCallback) {
    const { unmount, rerender } = render(component);
    
    // Initial render
    await waitFor(() => {});
    
    // Measure re-render
    const startTime = performance.now();
    if (updateCallback) {
      await act(async () => {
        updateCallback();
        rerender(component);
      });
    }
    const endTime = performance.now();
    
    unmount();
    return endTime - startTime;
  }

  /**
   * Asserts performance threshold
   */
  static assertPerformanceThreshold(actualTime, thresholdTime, metric) {
    expect(actualTime).toBeLessThan(thresholdTime, 
      `${metric} (${actualTime}ms) exceeds threshold (${thresholdTime}ms)`);
  }
}

/**
 * Accessibility test utilities
 */
class AccessibilityTestUtils {
  /**
   * Verifies accessibility label
   */
  static verifyAccessibilityLabel(testId, expectedLabel) {
    const element = screen.getByTestId(testId);
    expect(element).toHaveAttribute('aria-label', expectedLabel);
  }

  /**
   * Verifies accessibility role
   */
  static verifyAccessibilityRole(testId, expectedRole) {
    const element = screen.getByTestId(testId);
    expect(element).toHaveAttribute('role', expectedRole);
  }

  /**
   * Verifies element is focusable
   */
  static verifyElementFocusable(testId) {
    const element = screen.getByTestId(testId);
    expect(element).toHaveAttribute('tabIndex');
  }

  /**
   * Verifies element has accessible description
   */
  static verifyAccessibleDescription(testId, expectedDescription) {
    const element = screen.getByTestId(testId);
    expect(element).toHaveAttribute('aria-describedby', expectedDescription);
  }

  /**
   * Runs accessibility checks
   */
  static async runAccessibilityChecks(container) {
    // This would integrate with axe-core or similar accessibility testing library
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  }
}

/**
 * Integration test utilities
 */
class IntegrationTestUtils {
  /**
   * Sets up integration test environment
   */
  static async setupIntegrationTest() {
    // Setup mocks and environment
    jest.useFakeTimers();
  }

  /**
   * Cleans up integration test environment
   */
  static async cleanupIntegrationTest() {
    // Cleanup mocks and environment
    jest.useRealTimers();
    jest.clearAllMocks();
  }

  /**
   * Runs integration test with setup and cleanup
   */
  static async runIntegrationTest(testCallback) {
    try {
      await this.setupIntegrationTest();
      await testCallback();
    } finally {
      await this.cleanupIntegrationTest();
    }
  }

  /**
   * Waits for all async operations to complete
   */
  static async waitForAsyncOperations() {
    await act(async () => {
      await new Promise(resolve => setImmediate(resolve));
    });
  }

  /**
   * Advances timers by specified duration
   */
  static async advanceTimers(duration) {
    await act(async () => {
      jest.advanceTimersByTime(duration);
    });
  }
}

/**
 * Mock data factory
 */
class MockDataFactory {
  /**
   * Creates a mock user
   */
  static createUser(overrides = {}) {
    const baseCase = new BaseTestCase();
    return baseCase.createMockData('user', overrides);
  }

  /**
   * Creates multiple mock users
   */
  static createUsers(count, overrides = {}) {
    const users = [];
    for (let i = 0; i < count; i++) {
      users.push(this.createUser({
        ...overrides,
        id: i + 1,
        username: `testuser${i + 1}`,
        email: `test${i + 1}@example.com`,
      }));
    }
    return users;
  }

  /**
   * Creates a mock post
   */
  static createPost(overrides = {}) {
    const baseCase = new BaseTestCase();
    return baseCase.createMockData('post', overrides);
  }

  /**
   * Creates multiple mock posts
   */
  static createPosts(count, overrides = {}) {
    const posts = [];
    for (let i = 0; i < count; i++) {
      posts.push(this.createPost({
        ...overrides,
        id: i + 1,
        title: `Test Post ${i + 1}`,
      }));
    }
    return posts;
  }

  /**
   * Creates a mock comment
   */
  static createComment(overrides = {}) {
    const baseCase = new BaseTestCase();
    return baseCase.createMockData('comment', overrides);
  }

  /**
   * Creates multiple mock comments
   */
  static createComments(count, overrides = {}) {
    const comments = [];
    for (let i = 0; i < count; i++) {
      comments.push(this.createComment({
        ...overrides,
        id: i + 1,
        content: `Test comment ${i + 1}`,
      }));
    }
    return comments;
  }

  /**
   * Creates mock configuration
   */
  static createConfig(overrides = {}) {
    const baseCase = new BaseTestCase();
    return baseCase.createMockData('config', overrides);
  }
}

/**
 * Example test class demonstrating usage
 */
class ExampleComponentTest extends BaseTestCase {
  constructor() {
    super();
    this.baseTestCase = new BaseTestCase();
  }

  /**
   * Example test method
   */
  async testComponentRendering() {
    await this.baseTestCase.setUp();
    
    try {
      // Test implementation
      const user = this.createMockUser({ username: 'example' });
      const component = render(<div>{user.username}</div>);
      
      this.assertVisible(component.getByText('example'));
    } finally {
      await this.baseTestCase.tearDown();
    }
  }
}

/**
 * Example usage demonstration
 */
function exampleUsage() {
  console.log('React Native Test Scaffold Usage:');
  console.log('1. Extend BaseTestCase for common utilities');
  console.log('2. Use ComponentTestUtils for component testing');
  console.log('3. Use HttpTestUtils for API testing');
  console.log('4. Use RouterTestUtils for navigation testing');
  console.log('5. Use FormTestUtils for form testing');
  console.log('6. Use PerformanceTestUtils for performance testing');
  console.log('7. Use AccessibilityTestUtils for accessibility testing');
  console.log('8. Use IntegrationTestUtils for integration testing');
  console.log('9. Use MockDataFactory for creating test data');
}

export {
  BaseTestCase,
  ComponentTestUtils,
  HttpTestUtils,
  RouterTestUtils,
  FormTestUtils,
  PerformanceTestUtils,
  AccessibilityTestUtils,
  IntegrationTestUtils,
  MockDataFactory,
  ExampleComponentTest,
  exampleUsage,
};

// Export for CommonJS environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    BaseTestCase,
    ComponentTestUtils,
    HttpTestUtils,
    RouterTestUtils,
    FormTestUtils,
    PerformanceTestUtils,
    AccessibilityTestUtils,
    IntegrationTestUtils,
    MockDataFactory,
    ExampleComponentTest,
    exampleUsage,
  };
}
