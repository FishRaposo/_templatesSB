/**
 * File: testing-utilities.tpl.jsx
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

// -----------------------------------------------------------------------------
// FILE: testing-utilities.tpl.jsx
// PURPOSE: Comprehensive testing utilities and helpers for Next.js projects
// USAGE: Import and adapt for consistent testing patterns across the application
// DEPENDENCIES: Next.js, @testing-library/next, @testing-library/user-event for testing framework
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * Next.js Testing Utilities Template
 * Purpose: Reusable testing utilities and helpers for Next.js projects
 * Usage: Import and adapt for consistent testing patterns across the application
 */

import Next.js, { createContext, useContext, useState, useCallback, useEffect } from 'next';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/next';
import userEvent from '@testing-library/user-event';

/**
 * Test context for Next.js components
 */
const TestContext = createContext();

/**
 * Test provider component
 */
export const TestProvider = ({ children, testConfig = {} }) => {
  const [testData, setTestData] = useState({});
  const [mocks, setMocks] = useState({});
  const [isTestMode, setIsTestMode] = useState(false);

  const value = {
    testData,
    setTestData,
    mocks,
    setMocks,
    isTestMode,
    setIsTestMode
  };

  return (
    <TestContext.Provider value={value}>
      {children}
    </TestContext.Provider>
  );
};

/**
 * Hook to use test context
 */
export const useTestContext = () => {
  const context = useContext(TestContext);
  if (!context) {
    throw new Error('useTestContext must be used within a TestProvider');
  }
  return context;
};

/**
 * Mock data factory
 */
export class MockDataFactory {
  /**
   * Create mock user
   */
  static createMockUser(overrides = {}) {
    return {
      id: 1,
      username: 'testuser',
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'User',
      isActive: true,
      createdAt: new Date('2023-01-01T00:00:00Z'),
      updatedAt: new Date('2023-01-01T00:00:00Z'),
      ...overrides
    };
  }

  /**
   * Create mock post
   */
  static createMockPost(overrides = {}) {
    return {
      id: 1,
      title: 'Test Post',
      content: 'This is test content',
      authorId: 1,
      published: true,
      createdAt: new Date('2023-01-01T12:00:00Z'),
      updatedAt: new Date('2023-01-01T12:00:00Z'),
      ...overrides
    };
  }

  /**
   * Create mock API response
   */
  static createMockResponse(data, status = 200, headers = {}) {
    return {
      data,
      status,
      headers: {
        'content-type': 'application/json',
        ...headers
      },
      config: {},
      request: {}
    };
  }

  /**
   * Create mock form data
   */
  static createMockFormData(overrides = {}) {
    return {
      username: 'testuser',
      email: 'test@example.com',
      password: 'password123',
      confirmPassword: 'password123',
      ...overrides
    };
  }

  /**
   * Create array of mock items
   */
  static createMockArray(createFunction, count = 3, baseOverrides = {}) {
    return Array.from({ length: count }, (_, index) => 
      createFunction({ ...baseOverrides, id: index + 1 })
    );
  }
}

/**
 * Custom render function with providers
 */
export const renderWithProviders = (
  ui,
  {
    initialState = {},
    initialTestData = {},
    mocks = {},
    ...renderOptions
  } = {}
) => {
  const Wrapper = ({ children }) => (
    <TestProvider testConfig={{ initialTestData, mocks }}>
      {children}
    </TestProvider>
  );

  return {
    ...render(ui, { wrapper: Wrapper, ...renderOptions }),
    // Add additional test utilities
    rerenderWithProviders: (ui, newOptions = {}) => 
      renderWithProviders(ui, { ...renderOptions, ...newOptions })
  };
};

/**
 * Mock component for testing
 */
export const MockComponent = ({ children, ...props }) => {
  return <div data-testid="mock-component" {...props}>{children}</div>;
};

/**
 * Test utilities for common patterns
 */
export const TestUtils = {
  /**
   * Wait for element to appear
   */
  waitForElement: async (testId) => {
    return await screen.findByTestId(testId);
  },

  /**
   * Check if element exists
   */
  elementExists: (testId) => {
    return screen.queryByTestId(testId) !== null;
  },

  /**
   * Fill form by test IDs
   */
  fillFormByTestId: async (formData) => {
    for (const [testId, value] of Object.entries(formData)) {
      const element = screen.getByTestId(testId);
      await userEvent.clear(element);
      await userEvent.type(element, value);
    }
  },

  /**
   * Submit form
   */
  submitForm: async (submitButtonTestId = 'submit-button') => {
    const submitButton = screen.getByTestId(submitButtonTestId);
    await userEvent.click(submitButton);
  },

  /**
   * Click element by test ID
   */
  clickByTestId: async (testId) => {
    const element = screen.getByTestId(testId);
    await userEvent.click(element);
  },

  /**
   * Select dropdown option
   */
  selectDropdownOption: async (dropdownTestId, optionText) => {
    const dropdown = screen.getByTestId(dropdownTestId);
    await userEvent.click(dropdown);
    
    const option = screen.getByText(optionText);
    await userEvent.click(option);
  },

  /**
   * Upload file
   */
  uploadFile: async (inputTestId, file) => {
    const input = screen.getByTestId(inputTestId);
    await userEvent.upload(input, file);
  },

  /**
   * Assert element text content
   */
  assertElementText: (testId, expectedText) => {
    const element = screen.getByTestId(testId);
    expect(element).toHaveTextContent(expectedText);
  },

  /**
   * Assert element is visible
   */
  assertElementVisible: (testId) => {
    const element = screen.getByTestId(testId);
    expect(element).toBeVisible();
  },

  /**
   * Assert element is hidden
   */
  assertElementHidden: (testId) => {
    const element = screen.queryByTestId(testId);
    expect(element).not.toBeInTheDocument();
  },

  /**
   * Assert form values
   */
  assertFormValues: (formData) => {
    for (const [testId, expectedValue] of Object.entries(formData)) {
      const element = screen.getByTestId(testId);
      expect(element).toHaveValue(expectedValue);
    }
  }
};

/**
 * Mock API utilities
 */
export const MockAPIUtils = {
  /**
   * Create mock fetch response
   */
  createMockFetch: (response, delay = 0) => {
    return jest.fn().mockImplementation(() =>
      new Promise(resolve => {
        setTimeout(() => {
          resolve({
            ok: response.status >= 200 && response.status < 300,
            status: response.status,
            json: () => Promise.resolve(response.data),
            text: () => Promise.resolve(JSON.stringify(response.data)),
            headers: new Headers(response.headers)
          });
        }, delay);
      })
    );
  },

  /**
   * Setup mock fetch for multiple calls
   */
  setupMockFetch: (responses) => {
    const mockFetch = jest.fn();
    
    responses.forEach((response, index) => {
      if (index === responses.length - 1) {
        mockFetch.mockReturnValueOnce(
          Promise.resolve({
            ok: response.status >= 200 && response.status < 300,
            status: response.status,
            json: () => Promise.resolve(response.data),
            text: () => Promise.resolve(JSON.stringify(response.data))
          })
        );
      } else {
        mockFetch.mockReturnValueOnce(
          Promise.resolve({
            ok: response.status >= 200 && response.status < 300,
            status: response.status,
            json: () => Promise.resolve(response.data),
            text: () => Promise.resolve(JSON.stringify(response.data))
          })
        );
      }
    });

    global.fetch = mockFetch;
    return mockFetch;
  },

  /**
   * Restore original fetch
   */
  restoreFetch: () => {
    global.fetch = originalFetch;
  }
};

// Store original fetch
const originalFetch = global.fetch;

/**
 * Hook testing utilities
 */
export const HookTestUtils = {
  /**
   * Render hook in test component
   */
  renderHook: (hook, options = {}) => {
    const result = {
      current: null
    };

    const TestComponent = () => {
      result.current = hook();
      return null;
    };

    renderWithProviders(<TestComponent />, options);
    return result;
  },

  /**
   * Wait for hook to update
   */
  waitForHookUpdate: async (hookResult) => {
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 0));
    });
    return hookResult.current;
  },

  /**
   * Trigger hook re-render
   */
  rerenderHook: (hookResult, hook, options = {}) => {
    const TestComponent = () => {
      hookResult.current = hook();
      return null;
    };

    renderWithProviders(<TestComponent />, options);
    return hookResult;
  }
};

/**
 * Performance testing utilities
 */
export const PerformanceTestUtils = {
  /**
   * Measure render time
   */
  measureRenderTime: async (Component, props = {}) => {
    const startTime = performance.now();
    
    renderWithProviders(<Component {...props} />);
    
    const endTime = performance.now();
    return endTime - startTime;
  },

  /**
   * Measure function execution time
   */
  measureExecutionTime: async (fn) => {
    const startTime = performance.now();
    await fn();
    const endTime = performance.now();
    return endTime - startTime;
  },

  /**
   * Benchmark component render
   */
  benchmarkRender: async (Component, props = {}, iterations = 10) => {
    const times = [];
    
    for (let i = 0; i < iterations; i++) {
      const { unmount } = renderWithProviders(<Component {...props} />);
      const time = await PerformanceTestUtils.measureRenderTime(Component, props);
      times.push(time);
      unmount();
    }

    const average = times.reduce((sum, time) => sum + time, 0) / times.length;
    const min = Math.min(...times);
    const max = Math.max(...times);

    return { average, min, max, times };
  }
};

/**
 * Accessibility testing utilities
 */
export const A11yTestUtils = {
  /**
   * Check if element has proper ARIA attributes
   */
  assertAriaLabel: (testId, expectedLabel) => {
    const element = screen.getByTestId(testId);
    expect(element).toHaveAttribute('aria-label', expectedLabel);
  },

  /**
   * Check if element has proper role
   */
  assertRole: (testId, expectedRole) => {
    const element = screen.getByTestId(testId);
    expect(element).toHaveAttribute('role', expectedRole);
  },

  /**
   * Check if element is keyboard accessible
   */
  assertKeyboardAccessible: async (testId) => {
    const element = screen.getByTestId(testId);
    element.focus();
    expect(element).toHaveFocus();
    
    await userEvent.keyboard('{Enter}');
    // Add specific assertions based on expected behavior
  },

  /**
   * Check color contrast (simplified)
   */
  checkColorContrast: (element) => {
    const styles = window.getComputedStyle(element);
    const color = styles.color;
    const backgroundColor = styles.backgroundColor;
    
    // This is a simplified check - in real implementation, you'd use a proper contrast calculation
    console.log(`Color: ${color}, Background: ${backgroundColor}`);
    return { color, backgroundColor };
  }
};

/**
 * Integration testing utilities
 */
export const IntegrationTestUtils = {
  /**
   * Setup integration test environment
   */
  setupIntegrationTest: (mockServices = {}) => {
    // Mock localStorage
    const localStorageMock = {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
      clear: jest.fn()
    };
    Object.defineProperty(window, 'localStorage', {
      value: localStorageMock
    });

    // Mock sessionStorage
    const sessionStorageMock = {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
      clear: jest.fn()
    };
    Object.defineProperty(window, 'sessionStorage', {
      value: sessionStorageMock
    });

    // Mock window.location
    delete window.location;
    window.location = {
      href: 'http://localhost:3000',
      pathname: '/',
      search: '',
      hash: ''
    };

    return {
      localStorageMock,
      sessionStorageMock
    };
  },

  /**
   * Cleanup integration test environment
   */
  cleanupIntegrationTest: () => {
    jest.restoreAllMocks();
  },

  /**
   * Simulate navigation
   */
  simulateNavigation: (path) => {
    window.location.pathname = path;
    window.dispatchEvent(new PopStateEvent('popstate'));
  }
};

/**
 * Test data management
 */
export class TestDataManager {
  constructor() {
    this.data = new Map();
    this.files = [];
  }

  /**
   * Set test data
   */
  setData(key, value) {
    this.data.set(key, value);
  }

  /**
   * Get test data
   */
  getData(key) {
    return this.data.get(key);
  }

  /**
   * Create temporary file for testing
   */
  createTempFile(content = 'test content', type = 'text/plain') {
    const file = new File([content], 'test.txt', { type });
    this.files.push(file);
    return file;
  }

  /**
   * Cleanup test data
   */
  cleanup() {
    this.data.clear();
    this.files = [];
  }
}

/**
 * Custom matchers for Jest
 */
export const customMatchers = {
  /**
   * Check if element has CSS class
   */
  toHaveClass: (received, expectedClass) => {
    const hasClass = received.classList.contains(expectedClass);
    return {
      pass: hasClass,
      message: () => `expected element to have class "${expectedClass}"`
    };
  },

  /**
   * Check if element is disabled
   */
  toBeDisabled: (received) => {
    const isDisabled = received.disabled || received.getAttribute('aria-disabled') === 'true';
    return {
      pass: isDisabled,
      message: () => `expected element to be disabled`
    };
  },

  /**
   * Check if element is loading
   */
  toBeLoading: (received) => {
    const isLoading = received.getAttribute('aria-busy') === 'true' || 
                     received.classList.contains('loading');
    return {
      pass: isLoading,
      message: () => `expected element to be in loading state`
    };
  }
};

/**
 * Example test component
 */
export const ExampleTestComponent = () => {
  const [count, setCount] = useState(0);
  const [inputValue, setInputValue] = useState('');

  const handleIncrement = () => setCount(count + 1);
  const handleInputChange = (e) => setInputValue(e.target.value);

  return (
    <div data-testid="example-component">
      <h1 data-testid="title">Example Component</h1>
      <p data-testid="count">Count: {count}</p>
      <button 
        data-testid="increment-button"
        onClick={handleIncrement}
      >
        Increment
      </button>
      <input
        data-testid="text-input"
        value={inputValue}
        onChange={handleInputChange}
        placeholder="Type something..."
      />
      <p data-testid="input-display">Input: {inputValue}</p>
    </div>
  );
};

/**
 * Example test using the utilities
 */
export const exampleTest = () => {
  test('Example component test', async () => {
    // Render component with providers
    renderWithProviders(<ExampleTestComponent />);

    // Check initial state
    expect(screen.getByTestId('title')).toHaveTextContent('Example Component');
    TestUtils.assertElementText('count', 'Count: 0');

    // Test button click
    await TestUtils.clickByTestId('increment-button');
    TestUtils.assertElementText('count', 'Count: 1');

    // Test input interaction
    await TestUtils.fillFormByTestId({
      'text-input': 'Hello World'
    });
    TestUtils.assertElementText('input-display', 'Input: Hello World');

    // Test accessibility
    A11yTestUtils.assertRole('increment-button', 'button');
  });
};

export default {
  TestProvider,
  useTestContext,
  MockDataFactory,
  renderWithProviders,
  MockComponent,
  TestUtils,
  MockAPIUtils,
  HookTestUtils,
  PerformanceTestUtils,
  A11yTestUtils,
  IntegrationTestUtils,
  TestDataManager,
  customMatchers,
  ExampleTestComponent
};
