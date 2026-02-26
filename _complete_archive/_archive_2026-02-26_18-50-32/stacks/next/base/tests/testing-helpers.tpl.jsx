import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { rest } from 'msw';
import { setupServer } from 'msw/node';
import '@testing-library/jest-dom';

// Custom render function with providers
export const customRender = (ui, options = {}) => {
  const {
    initialState = {},
    store = createTestStore(initialState),
    router = {},
    ...renderOptions
  } = options;

  const Wrapper = ({ children }) => {
    return (
      <TestStoreProvider store={store}>
        <TestRouterProvider {...router}>
          {children}
        </TestRouterProvider>
      </TestStoreProvider>
    );
  };

  return render(ui, { wrapper: Wrapper, ...renderOptions });
};

// Test store factory
export const createTestStore = (initialState = {}) => {
  return {
    getState: () => initialState,
    dispatch: jest.fn(),
    subscribe: jest.fn(),
  };
};

// Mock providers
export const TestStoreProvider = ({ children, store }) => {
  return React.createElement(
    'div',
    { 'data-testid': 'test-store-provider' },
    children
  );
};

export const TestRouterProvider = ({ children, ...props }) => {
  return React.createElement(
    'div',
    { 'data-testid': 'test-router-provider', ...props },
    children
  );
};

// Form testing helpers
export const fillForm = async (formElement, data) => {
  const user = userEvent.setup();
  
  for (const [fieldName, value] of Object.entries(data)) {
    const field = within(formElement).getByLabelText(fieldName);
    await user.clear(field);
    await user.type(field, value);
  }
};

export const submitForm = async (formElement) => {
  const user = userEvent.setup();
  const submitButton = within(formElement).getByRole('button', { name: /submit/i });
  await user.click(submitButton);
};

// API testing helpers
export const createMockApiHandler = (method, endpoint, response, options = {}) => {
  const { status = 200, delay = 0 } = options;
  
  const handlers = {
    get: rest.get,
    post: rest.post,
    put: rest.put,
    delete: rest.delete,
    patch: rest.patch,
  };
  
  return handlers[method.toLowerCase()](endpoint, (req, res, ctx) => {
    if (delay > 0) {
      return res(ctx.delay(delay), ctx.status(status), ctx.json(response));
    }
    return res(ctx.status(status), ctx.json(response));
  });
};

export const createMockErrorHandler = (method, endpoint, error, status = 500) => {
  const handlers = {
    get: rest.get,
    post: rest.post,
    put: rest.put,
    delete: rest.delete,
    patch: rest.patch,
  };
  
  return handlers[method.toLowerCase()](endpoint, (req, res, ctx) => {
    return res(ctx.status(status), ctx.json({ error }));
  });
};

// Async testing helpers
export const waitForElement = async (testId, options = {}) => {
  const { timeout = 5000 } = options;
  return screen.findByTestId(testId, { timeout });
};

export const waitForText = async (text, options = {}) => {
  const { timeout = 5000 } = options;
  return screen.findByText(text, { timeout });
};

export const waitForElementToDisappear = async (element) => {
  await waitFor(() => {
    expect(element).not.toBeInTheDocument();
  });
};

// Component testing helpers
export const expectElementToBeVisible = (element) => {
  expect(element).toBeInTheDocument();
  expect(element).toBeVisible();
};

export const expectElementToHaveText = (element, text) => {
  expect(element).toBeInTheDocument();
  expect(element).toHaveTextContent(text);
};

export const expectButtonToBeDisabled = (button) => {
  expect(button).toBeInTheDocument();
  expect(button).toBeDisabled();
};

export const expectButtonToBeEnabled = (button) => {
  expect(button).toBeInTheDocument();
  expect(button).toBeEnabled();
};

// Mock data factories
export const createMockUser = (overrides = {}) => {
  return {
    id: 1,
    name: 'Test User',
    email: 'test@example.com',
    avatar: 'https://example.com/avatar.jpg',
    createdAt: new Date().toISOString(),
    ...overrides,
  };
};

export const createMockPost = (overrides = {}) => {
  return {
    id: 1,
    title: 'Test Post',
    content: 'This is a test post content.',
    authorId: 1,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
};

export const createMockComment = (overrides = {}) => {
  return {
    id: 1,
    content: 'Test comment',
    postId: 1,
    authorId: 1,
    createdAt: new Date().toISOString(),
    ...overrides,
  };
};

// Array helpers for testing
export const createMockArray = (factory, count, overrides = {}) => {
  return Array.from({ length: count }, (_, i) => 
    factory({ id: i + 1, ...overrides })
  );
};

// Local storage testing helpers
export const createMockLocalStorage = () => {
  let store = {};
  
  return {
    getItem: jest.fn((key) => store[key]),
    setItem: jest.fn((key, value) => {
      store[key] = value.toString();
    }),
    removeItem: jest.fn((key) => {
      delete store[key];
    }),
    clear: jest.fn(() => {
      store = {};
    }),
  };
};

// Session storage testing helpers
export const createMockSessionStorage = () => {
  return createMockLocalStorage();
};

// Intersection Observer mock
export const createMockIntersectionObserver = () => {
  const observers = [];
  
  const mockObserver = {
    observe: jest.fn((element) => {
      observers.push(element);
    }),
    unobserve: jest.fn((element) => {
      const index = observers.indexOf(element);
      if (index > -1) {
        observers.splice(index, 1);
      }
    }),
    disconnect: jest.fn(() => {
      observers.length = 0;
    }),
  };
  
  global.IntersectionObserver = jest.fn(() => mockObserver);
  
  return mockObserver;
};

// Resize Observer mock
export const createMockResizeObserver = () => {
  const observers = [];
  
  const mockObserver = {
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
  };
  
  global.ResizeObserver = jest.fn(() => mockObserver);
  
  return mockObserver;
};

// File upload testing helpers
export const createMockFile = (name = 'test.txt', type = 'text/plain', content = 'test content') => {
  const file = new File([content], name, { type });
  Object.defineProperty(file, 'size', { value: content.length });
  return file;
};

export const createMockFileList = (files) => {
  const fileList = Object.create(null);
  fileList.item = (index) => files[index];
  fileList.length = files.length;
  Object.setPrototypeOf(fileList, FileList.prototype);
  
  files.forEach((file, index) => {
    fileList[index] = file;
  });
  
  return fileList;
};

// Date testing helpers
export const createMockDate = (dateString) => {
  const mockDate = new Date(dateString);
  jest.spyOn(global, 'Date').mockImplementation(() => mockDate);
  return mockDate;
};

export const restoreMockDate = () => {
  global.Date.mockRestore();
};

// Router testing helpers
export const createMockRouter = (overrides = {}) => {
  return {
    push: jest.fn(),
    replace: jest.fn(),
    back: jest.fn(),
    forward: jest.fn(),
    reload: jest.fn(),
    prefetch: jest.fn(),
    pathname: '/',
    query: {},
    asPath: '/',
    isReady: true,
    ...overrides,
  };
};

// Scroll testing helpers
export const createMockScrollTo = () => {
  const scrollTo = jest.fn();
  global.scrollTo = scrollTo;
  global.scrollBy = jest.fn();
  global.scrollIntoView = jest.fn();
  
  return { scrollTo, scrollBy: global.scrollBy, scrollIntoView: global.scrollIntoView };
};

// Performance testing helpers
export const measureRenderTime = async (Component, props = {}) => {
  const start = performance.now();
  customRender(<Component {...props} />);
  const end = performance.now();
  return end - start;
};

export const measureFunctionTime = async (fn) => {
  const start = performance.now();
  await fn();
  const end = performance.now();
  return end - start;
};

// Accessibility testing helpers
export const testAccessibility = async (container) => {
  // Check for proper heading hierarchy
  const headings = container.querySelectorAll('h1, h2, h3, h4, h5, h6');
  let lastLevel = 0;
  
  headings.forEach(heading => {
    const level = parseInt(heading.tagName.substring(1));
    if (level > lastLevel + 1) {
      console.warn(`Heading level skipped: h${lastLevel} to h${level}`);
    }
    lastLevel = level;
  });
  
  // Check for alt text on images
  const images = container.querySelectorAll('img');
  images.forEach(img => {
    if (!img.alt && img.role !== 'presentation') {
      console.warn('Image missing alt text:', img.src);
    }
  });
  
  // Check for proper ARIA labels
  const interactiveElements = container.querySelectorAll('button, input, select, textarea, a');
  interactiveElements.forEach(element => {
    const hasLabel = element.hasAttribute('aria-label') || 
                    element.hasAttribute('aria-labelledby') ||
                    element.textContent.trim();
    
    if (!hasLabel && element.tagName !== 'A') {
      console.warn('Interactive element missing label:', element);
    }
  });
};

// Cleanup helpers
export const cleanup = () => {
  jest.clearAllMocks();
  jest.restoreAllMocks();
  
  // Reset global mocks
  if (global.IntersectionObserver) {
    delete global.IntersectionObserver;
  }
  if (global.ResizeObserver) {
    delete global.ResizeObserver;
  }
  if (global.scrollTo) {
    delete global.scrollTo;
  }
  if (global.scrollBy) {
    delete global.scrollBy;
  }
  if (global.scrollIntoView) {
    delete global.scrollIntoView;
  }
};

// Re-export commonly used testing utilities
export {
  screen,
  fireEvent,
  waitFor,
  within,
  userEvent,
};
