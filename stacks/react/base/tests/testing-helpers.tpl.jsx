/**
 * FILE: testing-helpers.tpl.jsx
 * PURPOSE: Testing utilities and helpers for React projects
 * USAGE: Component testing, integration testing, and user interaction testing
 * DEPENDENCIES: @testing-library/react, @testing-library/jest-dom, @testing-library/user-event, jest
 * AUTHOR: [[.Author]]
 * VERSION: [[.Version]]
 * SINCE: [[.Version]]
 */

/**
 * React Testing Helpers Template
 * Purpose: Testing utilities and helpers for React projects
 * Usage: Component testing, integration testing, and user interaction testing
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { renderHook, act } from '@testing-library/react-hooks';
import userEvent from '@testing-library/user-event';
import { BrowserRouter, Router } from 'react-router-dom';
import { ThemeProvider } from 'styled-components';
import { Provider } from 'react-redux';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ConfigProvider } from 'antd';
import { ChakraProvider } from '@chakra-ui/react';
import { MaterialUIControllerProvider } from '../context';

// =============================================================================
// CUSTOM RENDER FUNCTION WITH PROVIDERS
// =============================================================================

const AllTheProviders = ({ children, options = {} }) => {
  const {
    theme = {},
    store = null,
    queryClient = null,
    router = 'browser',
    initialEntries = ['/'],
    antdTheme = {},
    chakraTheme = {}
  } = options;

  let queryClientInstance = queryClient;
  if (!queryClientInstance) {
    queryClientInstance = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
          cacheTime: 0
        },
        mutations: {
          retry: false
        }
      }
    });
  }

  let content = (
    <QueryClientProvider client={queryClientInstance}>
      <ConfigProvider theme={antdTheme}>
        <ChakraProvider theme={chakraTheme}>
          <ThemeProvider theme={theme}>
            <MaterialUIControllerProvider>
              {children}
            </MaterialUIControllerProvider>
          </ThemeProvider>
        </ChakraProvider>
      </ConfigProvider>
    </QueryClientProvider>
  );

  if (store) {
    content = <Provider store={store}>{content}</Provider>;
  }

  if (router === 'memory') {
    content = (
      <Router initialEntries={initialEntries}>
        {content}
      </Router>
    );
  } else {
    content = <BrowserRouter>{content}</BrowserRouter>;
  }

  return content;
};

const customRender = (ui, options = {}) => {
  const renderOptions = {
    wrapper: (props) => <AllTheProviders {...props} options={options} />,
    ...options
  };

  return render(ui, renderOptions);
};

// =============================================================================
// MOCK HELPERS
// =============================================================================

class MockHelper {
  constructor() {
    this.mocks = new Map();
  }

  // Mock API responses
  mockApiResponse(endpoint, response, options = {}) {
    const mock = jest.fn().mockResolvedValue({
      data: response,
      status: options.status || 200,
      headers: options.headers || {},
      ...options
    });

    this.mocks.set(endpoint, mock);
    return mock;
  }

  // Mock API errors
  mockApiError(endpoint, error, options = {}) {
    const mock = jest.fn().mockRejectedValue({
      response: {
        status: options.status || 500,
        data: error
      },
      ...options
    });

    this.mocks.set(endpoint, mock);
    return mock;
  }

  // Mock localStorage
  mockLocalStorage() {
    const store = {};
    
    return {
      getItem: jest.fn((key) => store[key] || null),
      setItem: jest.fn((key, value) => {
        store[key] = value.toString();
      }),
      removeItem: jest.fn((key) => {
        delete store[key];
      }),
      clear: jest.fn(() => {
        Object.keys(store).forEach(key => delete store[key]);
      }),
      get length() {
        return Object.keys(store).length;
      },
      key: jest.fn((index) => Object.keys(store)[index] || null)
    };
  }

  // Mock sessionStorage
  mockSessionStorage() {
    return this.mockLocalStorage();
  }

  // Mock IntersectionObserver
  mockIntersectionObserver() {
    const mockIntersectionObserver = jest.fn();
    mockIntersectionObserver.mockReturnValue({
      observe: jest.fn(),
      unobserve: jest.fn(),
      disconnect: jest.fn()
    });
    global.IntersectionObserver = mockIntersectionObserver;
    return mockIntersectionObserver;
  }

  // Mock ResizeObserver
  mockResizeObserver() {
    const mockResizeObserver = jest.fn();
    mockResizeObserver.mockReturnValue({
      observe: jest.fn(),
      unobserve: jest.fn(),
      disconnect: jest.fn()
    });
    global.ResizeObserver = mockResizeObserver;
    return mockResizeObserver;
  }

  // Mock window.matchMedia
  mockMatchMedia(matches = false) {
    const mockMatchMedia = jest.fn().mockImplementation(query => ({
      matches,
      media: query,
      onchange: null,
      addListener: jest.fn(),
      removeListener: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn()
    }));
    global.matchMedia = mockMatchMedia;
    return mockMatchMedia;
  }

  // Clear all mocks
  clearAllMocks() {
    this.mocks.clear();
    jest.clearAllMocks();
  }
}

// =============================================================================
// TEST DATA GENERATORS
// =============================================================================

class TestDataGenerator {
  constructor() {
    this.faker = require('@faker-js/faker');
  }

  // Generate user data
  generateUser(overrides = {}) {
    return {
      id: this.faker.datatype.uuid(),
      email: this.faker.internet.email(),
      firstName: this.faker.name.firstName(),
      lastName: this.faker.name.lastName(),
      username: this.faker.internet.userName(),
      avatar: this.faker.internet.avatar(),
      bio: this.faker.lorem.paragraph(),
      phone: this.faker.phone.number(),
      isActive: this.faker.datatype.boolean(),
      isVerified: this.faker.datatype.boolean(),
      roles: [this.faker.helpers.arrayElement(['user', 'admin', 'moderator'])],
      preferences: {
        theme: this.faker.helpers.arrayElement(['light', 'dark']),
        language: this.faker.helpers.arrayElement(['en', 'es', 'fr']),
        notifications: this.faker.datatype.boolean()
      },
      createdAt: this.faker.date.past(),
      updatedAt: this.faker.date.recent(),
      ...overrides
    };
  }

  // Generate product data
  generateProduct(overrides = {}) {
    return {
      id: this.faker.datatype.uuid(),
      name: this.faker.commerce.productName(),
      description: this.faker.commerce.productDescription(),
      price: parseFloat(this.faker.commerce.price(10, 1000, 2)),
      category: this.faker.commerce.department(),
      sku: this.faker.datatype.string(8),
      stock: this.faker.datatype.number({ min: 0, max: 1000 }),
      isActive: this.faker.datatype.boolean(),
      tags: this.faker.helpers.arrayElements(['popular', 'new', 'sale', 'featured'], 2),
      images: Array.from({ length: this.faker.datatype.number({ min: 1, max: 5 }) }, () => 
        this.faker.image.imageUrl()
      ),
      attributes: {
        color: this.faker.commerce.color(),
        size: this.faker.helpers.arrayElement(['S', 'M', 'L', 'XL']),
        material: this.faker.helpers.arrayElement(['cotton', 'polyester', 'wool'])
      },
      createdAt: this.faker.date.past(),
      updatedAt: this.faker.date.recent(),
      ...overrides
    };
  }

  // Generate form data
  generateFormData(fields = {}) {
    const defaultFields = {
      firstName: this.faker.name.firstName(),
      lastName: this.faker.name.lastName(),
      email: this.faker.internet.email(),
      phone: this.faker.phone.number(),
      message: this.faker.lorem.paragraph()
    };

    return { ...defaultFields, ...fields };
  }

  // Generate table data
  generateTableData(count = 10, fields = {}) {
    return Array.from({ length: count }, (_, index) => ({
      id: this.faker.datatype.uuid(),
      index: index + 1,
      name: this.faker.name.fullName(),
      email: this.faker.internet.email(),
      status: this.faker.helpers.arrayElement(['active', 'inactive', 'pending']),
      createdAt: this.faker.date.past(),
      ...fields
    }));
  }

  // Generate chart data
  generateChartData(points = 10, type = 'line') {
    const data = Array.from({ length: points }, (_, index) => ({
      x: index,
      y: this.faker.datatype.number({ min: 0, max: 100 }),
      label: this.faker.date.recent()
    }));

    return { type, data };
  }
}

// =============================================================================
// USER INTERACTION HELPERS
// =============================================================================

class UserInteractionHelper {
  constructor() {
    this.user = userEvent.setup();
  }

  // Simulate typing in input
  async typeInInput(selector, text, options = {}) {
    const element = screen.getByRole('textbox', { name: selector }) || 
                  screen.getByLabelText(selector) ||
                  screen.getByPlaceholderText(selector);
    
    await this.user.clear(element);
    await this.user.type(element, text, options);
  }

  // Simulate clicking button
  async clickButton(selector, options = {}) {
    const element = screen.getByRole('button', { name: selector }) ||
                  screen.getByText(selector);
    
    await this.user.click(element, options);
  }

  // Simulate selecting from dropdown
  async selectDropdown(selector, value, options = {}) {
    const element = screen.getByRole('combobox', { name: selector }) ||
                  screen.getByLabelText(selector);
    
    await this.user.click(element);
    
    const option = screen.getByRole('option', { name: value });
    await this.user.click(option, options);
  }

  // Simulate file upload
  async uploadFile(selector, file, options = {}) {
    const element = screen.getByLabelText(selector);
    
    const fileData = new File(['content'], file.name, {
      type: file.type || 'text/plain'
    });

    await this.user.upload(element, fileData, options);
  }

  // Simulate form submission
  async submitForm(selector = 'form', options = {}) {
    const form = screen.getByRole('form', { name: selector }) ||
                 screen.getByTestId(selector);
    
    await this.user.click(
      within(form).getByRole('button', { name: /submit|save|send/i }),
      options
    );
  }

  // Simulate navigation
  async navigateTo(path, options = {}) {
    const link = screen.getByRole('link', { name: path }) ||
                screen.getByText(path);
    
    await this.user.click(link, options);
  }

  // Simulate tab navigation
  async tabNavigation(times = 1) {
    for (let i = 0; i < times; i++) {
      await this.user.tab();
    }
  }

  // Simulate keyboard shortcuts
  async pressKey(key, options = {}) {
    await this.user.keyboard(key, options);
  }

  // Simulate hover
  async hover(selector, options = {}) {
    const element = screen.getByRole('button', { name: selector }) ||
                  screen.getByText(selector);
    
    await this.user.hover(element, options);
  }

  // Simulate drag and drop
  async dragAndDrop(sourceSelector, targetSelector, options = {}) {
    const source = screen.getByTestId(sourceSelector);
    const target = screen.getByTestId(targetSelector);
    
    await this.user.drag(source, target, options);
  }
}

// =============================================================================
// COMPONENT TESTING HELPERS
// =============================================================================

class ComponentTestHelper {
  constructor() {
    this.mockHelper = new MockHelper();
    this.dataGenerator = new TestDataGenerator();
    this.userHelper = new UserInteractionHelper();
  }

  // Test component rendering
  async testComponentRendering(Component, props = {}, options = {}) {
    customRender(<Component {...props} />, options);
    
    return {
      container: screen.getByTestId(options.testId || 'component'),
      component: Component,
      props
    };
  }

  // Test component with loading state
  async testComponentLoadingState(Component, props = {}) {
    customRender(<Component {...props} loading />);
    
    return {
      loadingElement: screen.getByTestId('loading') ||
                     screen.getByRole('progressbar') ||
                     screen.getByText(/loading|loading.../i)
    };
  }

  // Test component with error state
  async testComponentErrorState(Component, props = {}, error = {}) {
    customRender(<Component {...props} error={error} />);
    
    return {
      errorElement: screen.getByTestId('error') ||
                   screen.getByRole('alert') ||
                   screen.getByText(/error|failed|unable to/i)
    };
  }

  // Test component with empty state
  async testComponentEmptyState(Component, props = {}) {
    customRender(<Component {...props} data={[]} />);
    
    return {
      emptyElement: screen.getByTestId('empty') ||
                   screen.getByText(/no data|empty|nothing to show/i)
    };
  }

  // Test form validation
  async testFormValidation(FormComponent, formData, validationRules) {
    const { result } = renderHook(() => FormComponent());
    
    // Test each validation rule
    for (const [field, rules] of Object.entries(validationRules)) {
      const testCases = [
        { value: '', rule: 'required' },
        { value: 'invalid', rule: 'format' },
        { value: 'a'.repeat(rules.maxLength + 1), rule: 'maxLength' }
      ];

      for (const testCase of testCases) {
        if (rules[testCase.rule]) {
          await act(async () => {
            result.current.setValue(field, testCase.value);
            await result.current.validateField(field);
          });

          expect(result.current.errors[field]).toBeDefined();
        }
      }
    }

    return result.current;
  }

  // Test accessibility
  async testAccessibility(Component, props = {}) {
    const { container } = customRender(<Component {...props} />);
    
    // Basic accessibility checks
    const buttons = container.querySelectorAll('button');
    buttons.forEach(button => {
      expect(button).toHaveAttribute('aria-label') ||
                   expect(button).toHaveAttribute('aria-labelledby') ||
                   expect(button).toHaveTextContent(/.+/);
    });

    const inputs = container.querySelectorAll('input');
    inputs.forEach(input => {
      expect(input).toHaveAttribute('aria-label') ||
                   expect(input).toHaveAttribute('aria-labelledby') ||
                   expect(input).toHaveAttribute('placeholder') ||
                   expect(input).toHaveAttribute('title');
    });

    return { container };
  }

  // Test responsive behavior
  async testResponsiveBehavior(Component, props = {}, breakpoints = {}) {
    const defaultBreakpoints = {
      mobile: '375px',
      tablet: '768px',
      desktop: '1024px'
    };

    const testBreakpoints = { ...defaultBreakpoints, ...breakpoints };
    const results = {};

    for (const [name, width] of Object.entries(testBreakpoints)) {
      // Mock window.innerWidth
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: parseInt(width)
      });

      const { container } = customRender(<Component {...props} />);
      results[name] = container;
    }

    return results;
  }
}

// =============================================================================
// HOOK TESTING HELPERS
// =============================================================================

class HookTestHelper {
  constructor() {
    this.mockHelper = new MockHelper();
    this.dataGenerator = new TestDataGenerator();
  }

  // Test custom hook
  testCustomHook(hook, options = {}) {
    const { result, waitForNextUpdate, rerender } = renderHook(hook, options);
    
    return {
      result,
      waitForNextUpdate,
      rerender,
      current: result.current
    };
  }

  // Test async hook
  async testAsyncHook(hook, options = {}) {
    const { result, waitForNextUpdate } = renderHook(hook, options);
    
    return {
      result,
      waitFor: async (condition) => {
        await waitFor(() => {
          expect(condition(result.current)).toBe(true);
        });
      },
      current: result.current
    };
  }

  // Test hook with error handling
  async testHookWithError(hook, errorCondition) {
    const { result } = renderHook(hook);
    
    await act(async () => {
      try {
        await errorCondition(result.current);
      } catch (error) {
        expect(result.current.error).toBeDefined();
      }
    });

    return result.current;
  }

  // Test hook cleanup
  testHookCleanup(hook) {
    const { unmount } = renderHook(hook);
    
    // Test cleanup function
    const cleanup = jest.fn();
    
    // This would need to be implemented based on specific hook
    unmount();
    
    expect(cleanup).toHaveBeenCalled();
  }
}

// =============================================================================
// INTEGRATION TESTING HELPERS
// =============================================================================

class IntegrationTestHelper {
  constructor() {
    this.mockHelper = new MockHelper();
    this.dataGenerator = new TestDataGenerator();
    this.componentHelper = new ComponentTestHelper();
  }

  // Test full user flow
  async testUserFlow(steps, options = {}) {
    const results = [];
    
    for (const step of steps) {
      const result = await this.executeStep(step, options);
      results.push(result);
    }

    return results;
  }

  // Execute individual step in user flow
  async executeStep(step, options = {}) {
    switch (step.type) {
      case 'navigate':
        return await this.navigate(step.to, options);
      case 'fill':
        return await this.fillForm(step.fields, options);
      case 'click':
        return await this.clickElement(step.selector, options);
      case 'wait':
        return await this.waitFor(step.condition, options);
      case 'assert':
        return await this.assert(step.assertion, options);
      default:
        throw new Error(`Unknown step type: ${step.type}`);
    }
  }

  // Navigate to route
  async navigate(to, options = {}) {
    window.history.pushState({}, '', to);
    
    // Wait for route to load
    await waitFor(() => {
      expect(screen.getByTestId('route-content')).toBeInTheDocument();
    });

    return { type: 'navigate', to, success: true };
  }

  // Fill form
  async fillForm(fields, options = {}) {
    for (const [selector, value] of Object.entries(fields)) {
      await this.userHelper.typeInInput(selector, value);
    }

    return { type: 'fill', fields, success: true };
  }

  // Click element
  async clickElement(selector, options = {}) {
    await this.userHelper.clickButton(selector);
    
    return { type: 'click', selector, success: true };
  }

  // Wait for condition
  async waitFor(condition, options = {}) {
    await waitFor(() => {
      expect(condition()).toBe(true);
    });

    return { type: 'wait', condition: condition.toString(), success: true };
  }

  // Assert condition
  async assert(assertion, options = {}) {
    expect(assertion()).toBe(true);
    
    return { type: 'assert', assertion: assertion.toString(), success: true };
  }
}

// =============================================================================
// PERFORMANCE TESTING HELPERS
// =============================================================================

class PerformanceTestHelper {
  constructor() {
    this.measurements = [];
  }

  // Measure render time
  async measureRenderTime(Component, props = {}, iterations = 10) {
    const times = [];

    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      
      const { unmount } = customRender(<Component {...props} />);
      
      const end = performance.now();
      times.push(end - start);
      
      unmount();
    }

    return {
      average: times.reduce((a, b) => a + b, 0) / times.length,
      min: Math.min(...times),
      max: Math.max(...times),
      times
    };
  }

  // Measure re-render performance
  async measureReRenderPerformance(Component, props, updateProps, iterations = 10) {
    const { rerender } = customRender(<Component {...props} />);
    
    const times = [];
    
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      
      rerender(<Component {...updateProps} />);
      
      const end = performance.now();
      times.push(end - start);
    }

    return {
      average: times.reduce((a, b) => a + b, 0) / times.length,
      min: Math.min(...times),
      max: Math.max(...times),
      times
    };
  }

  // Measure memory usage
  measureMemoryUsage() {
    if (performance.memory) {
      return {
        used: performance.memory.usedJSHeapSize,
        total: performance.memory.totalJSHeapSize,
        limit: performance.memory.jsHeapSizeLimit
      };
    }
    
    return null;
  }

  // Profile component
  async profileComponent(Component, props = {}, duration = 5000) {
    const measurements = [];
    const startTime = performance.now();
    
    const { unmount } = customRender(<Component {...props} />);
    
    const interval = setInterval(() => {
      measurements.push({
        timestamp: performance.now() - startTime,
        memory: this.measureMemoryUsage(),
        domNodes: document.querySelectorAll('*').length
      });
    }, 100);

    await new Promise(resolve => setTimeout(resolve, duration));
    
    clearInterval(interval);
    unmount();

    return measurements;
  }
}

// =============================================================================
// EXPORT ALL HELPERS
// =============================================================================

export {
  // Custom render
  customRender,
  AllTheProviders,
  
  // Helper classes
  MockHelper,
  TestDataGenerator,
  UserInteractionHelper,
  ComponentTestHelper,
  HookTestHelper,
  IntegrationTestHelper,
  PerformanceTestHelper,
  
  // Re-export testing library functions
  screen,
  fireEvent,
  waitFor,
  within,
  renderHook,
  act,
  userEvent
};

// Default export for convenience
export default {
  customRender,
  MockHelper,
  TestDataGenerator,
  UserInteractionHelper,
  ComponentTestHelper,
  HookTestHelper,
  IntegrationTestHelper,
  PerformanceTestHelper,
  screen,
  fireEvent,
  waitFor,
  within,
  renderHook,
  act
};