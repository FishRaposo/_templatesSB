import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { BrowserRouter } from 'react-router-dom';
import '@testing-library/jest-dom';

// Test configuration and utilities
export const createTestStore = (initialState = {}) => {
  return configureStore({
    reducer: {
      // Add your reducers here
    },
    preloadedState: initialState,
  });
};

export const renderWithProviders = (
  ui,
  {
    initialState = {},
    store = createTestStore(initialState),
    ...renderOptions
  } = {}
) => {
  const Wrapper = ({ children }) => {
    return (
      <Provider store={store}>
        <BrowserRouter>
          {children}
        </BrowserRouter>
      </Provider>
    );
  };

  return render(ui, { wrapper: Wrapper, ...renderOptions });
};

// Mock common dependencies
jest.mock('next/router', () => ({
  useRouter() {
    return {
      route: '/',
      pathname: '/',
      query: '',
      asPath: '',
      push: jest.fn(),
      pop: jest.fn(),
      reload: jest.fn(),
      back: jest.fn(),
      prefetch: jest.fn(),
      beforePopState: jest.fn(),
      events: {
        on: jest.fn(),
        off: jest.fn(),
        emit: jest.fn(),
      },
    };
  },
}));

jest.mock('next-auth/react', () => ({
  useSession: jest.fn(() => ({
    data: { user: { name: 'Test User', email: 'test@example.com' } },
    status: 'authenticated',
  })),
  signIn: jest.fn(),
  signOut: jest.fn(),
}));

// Example unit test template
describe('{{COMPONENT_NAME}} Component', () => {
  const defaultProps = {
    // Define default props here
  };

  beforeEach(() => {
    // Setup before each test
  });

  afterEach(() => {
    // Cleanup after each test
    jest.clearAllMocks();
  });

  it('renders without crashing', () => {
    renderWithProviders(<{{COMPONENT_NAME}} {...defaultProps} />);
    expect(screen.getByTestId('{{COMPONENT_ID}}')).toBeInTheDocument();
  });

  it('displays correct initial state', () => {
    renderWithProviders(<{{COMPONENT_NAME}} {...defaultProps} />);
    // Add assertions for initial state
  });

  it('handles user interactions correctly', async () => {
    const handleClick = jest.fn();
    renderWithProviders(<{{COMPONENT_NAME}} {...defaultProps} onClick={handleClick} />);
    
    fireEvent.click(screen.getByRole('button'));
    
    await waitFor(() => {
      expect(handleClick).toHaveBeenCalledTimes(1);
    });
  });

  it('updates state when props change', () => {
    const { rerender } = renderWithProviders(<{{COMPONENT_NAME}} {...defaultProps} />);
    
    rerenderWithProps({ ...defaultProps, someProp: 'new value' });
    
    expect(screen.getByTestId('{{COMPONENT_ID}}')).toHaveTextContent('new value');
  });
});

// Helper function to rerender with new props
export const rerenderWithProps = (props) => {
  const { rerender } = renderWithProviders(<{{COMPONENT_NAME}} {...props} />);
  return rerender;
};

// Performance test utilities
export const measureRenderTime = async (Component, props = {}) => {
  const start = performance.now();
  renderWithProviders(<Component {...props} />);
  const end = performance.now();
  return end - start;
};

// Accessibility test helpers
export const testAccessibility = (Component, props = {}) => {
  const { container } = renderWithProviders(<Component {...props} />);
  
  // Basic accessibility checks
  expect(container).toBeAccessible();
  
  // Check for ARIA labels
  const interactiveElements = container.querySelectorAll('button, input, select, textarea');
  interactiveElements.forEach(element => {
    expect(element).toHaveAttribute('aria-label');
  });
};
