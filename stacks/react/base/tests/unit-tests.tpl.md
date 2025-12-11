// React Unit Testing Template
// Comprehensive unit testing patterns for React projects

/**
 * React Unit Test Patterns
 * Component, hook, and utility testing with React Testing Library
 */

import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { renderHook } from '@testing-library/react-hooks';
import '@testing-library/jest-dom';
import userEvent from '@testing-library/user-event';

// ====================
// BASIC COMPONENT TESTS
// ====================

describe('Basic Component Tests', () => {
  
  test('renders component with props', () => {
    render(<UserCard name="John Doe" email="john@example.com" />);
    
    expect(screen.getByText('John Doe')).toBeInTheDocument();
    expect(screen.getByText('john@example.com')).toBeInTheDocument();
  });
  
  test('component handles click events', async () => {
    const handleClick = jest.fn();
    render(<Button onClick={handleClick}>Click Me</Button>);
    
    const button = screen.getByText('Click Me');
    await userEvent.click(button);
    
    expect(handleClick).toHaveBeenCalledTimes(1);
  });
  
  test('component with conditional rendering', () => {
    const { rerender } = render(<LoadingSpinner isLoading={true} />);
    
    expect(screen.getByTestId('spinner')).toBeInTheDocument();
    
    rerender(<LoadingSpinner isLoading={false} />);
    
    expect(screen.queryByTestId('spinner')).not.toBeInTheDocument();
  });
  
  test('form component with controlled inputs', async () => {
    const handleSubmit = jest.fn();
    render(<LoginForm onSubmit={handleSubmit} />);
    
    const emailInput = screen.getByLabelText('Email');
    const passwordInput = screen.getByLabelText('Password');
    const submitButton = screen.getByRole('button', { name: /submit/i });
    
    await userEvent.type(emailInput, 'test@example.com');
    await userEvent.type(passwordInput, 'password123');
    await userEvent.click(submitButton);
    
    expect(handleSubmit).toHaveBeenCalledWith({
      email: 'test@example.com',
      password: 'password123'
    });
  });
});

// ====================
// TABLE-DRIVEN COMPONENT TESTS
// ====================

describe('Table-Driven Component Tests', () => {
  
  test.each([
    ['primary', 'bg-blue-500'],
    ['secondary', 'bg-gray-500'],
    ['danger', 'bg-red-500'],
    ['success', 'bg-green-500']
  ])('Button with variant %s has class %s', (variant, expectedClass) => {
    render(<Button variant={variant}>Test Button</Button>);
    
    const button = screen.getByText('Test Button');
    expect(button).toHaveClass(expectedClass);
  });
  
  test.each([
    { value: '', expectedError: 'Email is required' },
    { value: 'invalid-email', expectedError: 'Invalid email format' },
    { value: 'a@b', expectedError: 'Email too short' },
    { value: 'valid@email.com', expectedError: null }
  ])('Email input validation: %s', async ({ value, expectedError }) => {
    const mockOnValidate = jest.fn();
    render(<EmailInput onValidate={mockOnValidate} />);
    
    const input = screen.getByLabelText('Email');
    await userEvent.clear(input);
    await userEvent.type(input, value);
    await userEvent.tab(); // Trigger blur
    
    if (expectedError) {
      await waitFor(() => {
        expect(screen.getByText(expectedError)).toBeInTheDocument();
      });
      expect(mockOnValidate).toHaveBeenCalledWith(false);
    } else {
      expect(screen.queryByText(/email/i)).not.toBeInTheDocument();
      expect(mockOnValidate).toHaveBeenCalledWith(true);
    }
  });
});

// ====================
// MOCK TESTING PATTERNS
// ====================

describe('Mock Testing Patterns', () => {
  
  test('component with mocked API call', async () => {
    const mockFetchUser = jest.fn().mockResolvedValue({
      id: 1,
      name: 'John Doe',
      email: 'john@example.com'
    });
    
    render(<UserProfile fetchUser={mockFetchUser} userId={1} />);
    
    // Initially shows loading
    expect(screen.getByText('Loading...')).toBeInTheDocument();
    
    // Wait for data to load
    await waitFor(() => {
      expect(screen.getByText('John Doe')).toBeInTheDocument();
      expect(screen.getByText('john@example.com')).toBeInTheDocument();
    });
    
    expect(mockFetchUser).toHaveBeenCalledWith(1);
  });
  
  test('component with React Router hooks', () => {
    // Mock useNavigate
    const mockNavigate = jest.fn();
    jest.mock('react-router-dom', () => ({
      ...jest.requireActual('react-router-dom'),
      useNavigate: () => mockNavigate
    }));
    
    render(<LoginButton onLogin={() => mockNavigate('/dashboard')} />);
    
    const button = screen.getByText('Login');
    fireEvent.click(button);
    
    expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
  });
  
  test('component with mocked context', () => {
    // Mock context provider
    const mockThemeContext = {
      theme: 'dark',
      toggleTheme: jest.fn()
    };
    
    jest.spyOn(React, 'useContext').mockReturnValue(mockThemeContext);
    
    render(<ThemeToggle />);
    
    const toggle = screen.getByRole('switch');
    fireEvent.click(toggle);
    
    expect(mockThemeContext.toggleTheme).toHaveBeenCalled();
  });
  
  test('component with localStorage mock', () => {
    const localStorageMock = {
      getItem: jest.fn(),
      setItem: jest.fn()
    };
    
    global.localStorage = localStorageMock;
    
    render(<RememberMeCheckbox />);
    
    const checkbox = screen.getByRole('checkbox');
    fireEvent.click(checkbox);
    
    expect(localStorageMock.setItem).toHaveBeenCalledWith('rememberMe', 'true');
  });
});

// ====================
// CUSTOM HOOK TESTS
// ====================

describe('Custom Hook Tests', () => {
  
  test('useCounter hook increments and decrements', () => {
    const { result } = renderHook(() => useCounter(0));
    
    expect(result.current.count).toBe(0);
    
    act(() => {
      result.current.increment();
    });
    
    expect(result.current.count).toBe(1);
    
    act(() => {
      result.current.decrement();
    });
    
    expect(result.current.count).toBe(0);
  });
  
  test('useApi hook handles loading and error states', async () => {
    const mockApiCall = jest.fn().mockResolvedValue({ data: 'test data' });
    
    const { result, waitForNextUpdate } = renderHook(() => 
      useApi(mockApiCall)
    );
    
    // Initially not loading
    expect(result.current.loading).toBe(false);
    expect(result.current.data).toBeNull();
    expect(result.current.error).toBeNull();
    
    // Trigger API call
    act(() => {
      result.current.execute();
    });
    
    // Should be loading
    expect(result.current.loading).toBe(true);
    
    // Wait for completion
    await waitForNextUpdate();
    
    expect(result.current.loading).toBe(false);
    expect(result.current.data).toBe('test data');
    expect(result.current.error).toBeNull();
  });
  
  test('useLocalStorage hook persists to localStorage', () => {
    const localStorageMock = {
      getItem: jest.fn().mockReturnValue(null),
      setItem: jest.fn()
    };
    global.localStorage = localStorageMock;
    
    const { result } = renderHook(() => useLocalStorage('theme', 'light'));
    
    expect(result.current[0]).toBe('light');
    
    act(() => {
      result.current[1]('dark');
    });
    
    expect(localStorageMock.setItem).toHaveBeenCalledWith('theme', '"dark"');
    expect(result.current[0]).toBe('dark');
  });
  
  test('useDebounce hook debounces value changes', async () => {
    jest.useFakeTimers();
    
    const { result, rerender } = renderHook(
      ({ value, delay }) => useDebounce(value, delay),
      {
        initialProps: { value: 'initial', delay: 500 }
      }
    );
    
    expect(result.current).toBe('initial');
    
    // Change value
    rerender({ value: 'changed', delay: 500 });
    expect(result.current).toBe('initial'); // Still initial due to debounce
    
    // Advance time
    jest.advanceTimersByTime(500);
    expect(result.current).toBe('changed'); // Now updated
    
    jest.useRealTimers();
  });
});

// ====================
// CONTEXT PROVIDER TESTS
// ====================

describe('Context Provider Tests', () => {
  
  const UserContext = React.createContext();
  
  const UserProvider = ({ children, initialUser }) => {
    const [user, setUser] = React.useState(initialUser);
    
    const login = (userData) => setUser(userData);
    const logout = () => setUser(null);
    
    return (
      <UserContext.Provider value={{ user, login, logout }}>
        {children}
      </UserContext.Provider>
    );
  };
  
  test('context provider provides values to consumers', () => {
    const TestComponent = () => {
      const { user, login, logout } = React.useContext(UserContext);
      
      return (
        <div>
          <span data-testid="user">{user?.name || 'No user'}</span>
          <button onClick={() => login({ name: 'John' })}>Login</button>
          <button onClick={logout}>Logout</button>
        </div>
      );
    };
    
    render(
      <UserProvider initialUser={null}>
        <TestComponent />
      </UserProvider>
    );
    
    expect(screen.getByTestId('user')).toHaveTextContent('No user');
    
    fireEvent.click(screen.getByText('Login'));
    
    expect(screen.getByTestId('user')).toHaveTextContent('John');
    
    fireEvent.click(screen.getByText('Logout'));
    
    expect(screen.getByTestId('user')).toHaveTextContent('No user');
  });
  
  test('context updates trigger re-renders', () => {
    const TestComponent = () => {
      const { user } = React.useContext(UserContext);
      const renderCount = React.useRef(0);
      renderCount.current++;
      
      return <div data-testid="render-count">{renderCount.current}</div>;
    };
    
    const { rerender } = render(
      <UserProvider initialUser={null}>
        <TestComponent />
      </UserProvider>
    );
    
    expect(screen.getByTestId('render-count')).toHaveTextContent('1');
    
    // Force re-render
    rerender(
      <UserProvider initialUser={null}>
        <TestComponent />
      </UserProvider>
    );
    
    // Should still be 1 (no context change)
    expect(screen.getByTestId('render-count')).toHaveTextContent('1');
  });
});

// ====================
// ASYNC COMPONENT TESTS
// ====================

describe('Async Component Tests', () => {
  
  test('component with data fetching', async () => {
    const mockApi = {
      getUser: jest.fn().mockResolvedValue({
        id: 1,
        name: 'John Doe',
        posts: [{ id: 1, title: 'First Post' }]
      })
    };
    
    render(<UserProfileWithPosts userId={1} api={mockApi} />);
    
    // Shows loading state
    expect(screen.getByText('Loading user data...')).toBeInTheDocument();
    
    // Wait for user data
    await waitFor(() => {
      expect(screen.getByText('John Doe')).toBeInTheDocument();
    });
    
    // Wait for posts
    await waitFor(() => {
      expect(screen.getByText('First Post')).toBeInTheDocument();
    });
    
    expect(mockApi.getUser).toHaveBeenCalledWith(1);
  });
  
  test('component handles API errors gracefully', async () => {
    const mockApi = {
      getUser: jest.fn().mockRejectedValue(new Error('User not found'))
    };
    
    render(<UserProfileWithPosts userId={999} api={mockApi} />);
    
    // Shows loading initially
    expect(screen.getByText('Loading user data...')).toBeInTheDocument();
    
    // Shows error after failed fetch
    await waitFor(() => {
      expect(screen.getByText('Error loading user')).toBeInTheDocument();
      expect(screen.getByText('User not found')).toBeInTheDocument();
    });
  });
  
  test('component with polling for updates', async () => {
    jest.useFakeTimers();
    
    const mockApi = {
      getStatus: jest.fn()
        .mockResolvedValueOnce({ status: 'processing' })
        .mockResolvedValueOnce({ status: 'processing' })
        .mockResolvedValueOnce({ status: 'completed' })
    };
    
    render(<StatusPoller checkInterval={1000} api={mockApi} />);
    
    expect(screen.getByText('Status: processing')).toBeInTheDocument();
    
    // Advance time
    jest.advanceTimersByTime(1000);
    await waitFor(() => {
      expect(screen.getByText('Status: processing')).toBeInTheDocument();
    });
    
    // Advance time again
    jest.advanceTimersByTime(1000);
    await waitFor(() => {
      expect(screen.getByText('Status: completed')).toBeInTheDocument();
    });
    
    expect(mockApi.getStatus).toHaveBeenCalledTimes(3);
    
    jest.useRealTimers();
  });
});

// ====================
// RENDERING OPTIMIZATION TESTS
// ====================

describe('Rendering Optimization Tests', () => {
  
  test('memoized component prevents unnecessary re-renders', async () => {
    let renderCount = 0;
    
    const MemoizedComponent = React.memo(({ value }) => {
      renderCount++;
      return <div data-testid="memoized">{value}</div>;
    });
    
    const ParentComponent = () => {
      const [count, setCount] = React.useState(0);
      const [memoValue] = React.useState('unchanged');
      
      return (
        <div>
          <MemoizedComponent value={memoValue} />
          <button onClick={() => setCount(c => c + 1)}>Increment: {count}</button>
        </div>
      );
    };
    
    const { getByText, getByTestId } = render(<ParentComponent />);
    
    const initialRenderCount = renderCount;
    
    // Click button to trigger parent re-render
    await userEvent.click(getByText(/Increment:/));
    
    // Memoized component should not re-render
    expect(renderCount).toBe(initialRenderCount);
    expect(getByTestId('memoized')).toHaveTextContent('unchanged');
  });
  
  test('useMemo hook caches expensive computations', () => {
    let computationCount = 0;
    
    const ExpensiveComponent = ({ items }) => {
      const expensiveCalculation = React.useMemo(() => {
        computationCount++;
        return items.reduce((sum, item) => sum + item.value, 0);
      }, [items]);
      
      return <div data-testid="result">{expensiveCalculation}</div>;
    };
    
    const items = [{ value: 1 }, { value: 2 }, { value: 3 }];
    
    const { rerender } = render(<ExpensiveComponent items={items} />);
    
    const initialComputations = computationCount;
    expect(screen.getByTestId('result')).toHaveTextContent('6');
    
    // Re-render with same items
    rerender(<ExpensiveComponent items={items} />);
    
    expect(computationCount).toBe(initialComputations); // No recalculation
    expect(screen.getByTestId('result')).toHaveTextContent('6');
  });
});

// ====================
// ACCESSIBILITY TESTS
// ====================

describe('Accessibility Tests', () => {
  
  test('button has correct ARIA attributes', () => {
    render(<Button aria-label="Close dialog" aria-pressed={false} />);
    
    const button = screen.getByLabelText('Close dialog');
    expect(button).toHaveAttribute('aria-pressed', 'false');
  });
  
  test('form inputs have proper labels', () => {
    render(
      <form>
        <label htmlFor="email">Email Address</label>
        <input id="email" type="email" required aria-required="true" />
      </form>
    );
    
    const emailInput = screen.getByLabelText('Email Address');
    expect(emailInput).toHaveAttribute('type', 'email');
    expect(emailInput).toHaveAttribute('required');
    expect(emailInput).toHaveAttribute('aria-required', 'true');
  });
  
  test('modal dialog has proper ARIA attributes', () => {
    render(
      <div role="dialog" aria-modal="true" aria-labelledby="dialog-title">
        <h2 id="dialog-title">Modal Title</h2>
        <p>Modal content</p>
      </div>
    );
    
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAttribute('aria-labelledby', 'dialog-title');
  });
  
  test('skip link is accessible', () => {
    render(<a href="#main" className="skip-link">Skip to main content</a>);
    
    const skipLink = screen.getByText('Skip to main content');
    expect(skipLink).toHaveAttribute('href', '#main');
  });
});

// ====================
// VISUAL REGRESSION TESTS
// ====================

describe('Visual Regression Tests', () => {
  
  test('component matches snapshot', () => {
    const { asFragment } = render(<Card title="Test Card" content="Test content" />);
    
    expect(asFragment()).toMatchSnapshot();
  });
  
  test('responsive component renders correctly at different breakpoints', () => {
    // Mock different viewport sizes
    global.innerWidth = 1200;
    global.dispatchEvent(new Event('resize'));
    
    const { rerender } = render(<ResponsiveComponent />);
    
    expect(screen.getByText('Desktop View')).toBeInTheDocument();
    
    // Change to mobile width
    global.innerWidth = 375;
    global.dispatchEvent(new Event('resize'));
    
    rerender(<ResponsiveComponent />);
    
    expect(screen.getByText('Mobile View')).toBeInTheDocument();
  });
});

// ====================
// TEST UTILITIES
// ====================

// Custom render function with providers
const customRender = (ui, { providerProps, ...options } = {}) => {
  const Wrapper = ({ children }) => (
    <ThemeProvider {...providerProps}>
      <UserProvider>
        {children}
      </UserProvider>
    </ThemeProvider>
  );
  
  return render(ui, { wrapper: Wrapper, ...options });
};

// Helper to create test data
const createTestUser = (overrides = {}) => ({
  id: 1,
  name: 'Test User',
  email: 'test@example.com',
  ...overrides
});

// ====================
// RUN REACT TESTS
// ====================

/*
Commands to run React tests:

# Run all tests
npm test

# Run specific test file
npm test -- UserProfile.test.js

# Run specific test
npm test -- -t "should render component with props"

# Run in watch mode
npm test -- --watch

# Run with coverage
npm test -- --coverage

# Update snapshots
npm test -- -u

# Run in CI mode
npm test -- --ci --coverage --maxWorkers=2

# Debug test
node --inspect-brk node_modules/.bin/jest --runInBand

# Run with verbose output
npm test -- --verbose

# Filter tests
npm test -- --testNamePattern="Component"

# Run tests in parallel (default)
npm test

# Run tests sequentially
npm test -- --runInBand

# Clear Jest cache
npm test -- --clearCache
*/

export { customRender, createTestUser };
