# React Integration Tests Template
// React Integration Testing Template
// Integration testing patterns for React projects

/**
 * React Integration Test Patterns
 * Full component integration, API integration, routing, state management
 */

import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { renderHook, act } from '@testing-library/react-hooks';
import '@testing-library/jest-dom';
import userEvent from '@testing-library/user-event';
import { setupServer } from 'msw/node';
import { rest } from 'msw';
import { BrowserRouter, MemoryRouter, Routes, Route } from 'react-router-dom';

// ====================
// MSW SERVER SETUP
// ====================

const server = setupServer(
  // Authentication endpoints
  rest.post('/api/v1/auth/login', (req, res, ctx) => {
    const { email, password } = req.body;
    
    if (email === 'test@example.com' && password === 'password123') {
      return res(
        ctx.status(200),
        ctx.json({
          accessToken: 'mock-access-token',
          refreshToken: 'mock-refresh-token',
          user: { id: 1, name: 'Test User', email: 'test@example.com' }
        })
      );
    }
    
    return res(
      ctx.status(401),
      ctx.json({ error: 'Invalid credentials' })
    );
  }),
  
  // User endpoints
  rest.get('/api/v1/users/profile', (req, res, ctx) => {
    const token = req.headers.get('authorization')?.replace('Bearer ', '');
    
    if (token === 'mock-access-token') {
      return res(
        ctx.status(200),
        ctx.json({ id: 1, name: 'Test User', email: 'test@example.com' })
      );
    }
    
    return res(ctx.status(401), ctx.json({ error: 'Unauthorized' }));
  }),
  
  // Product endpoints
  rest.get('/api/v1/products', (req, res, ctx) => {
    return res(
      ctx.status(200),
      ctx.json([
        { id: 1, name: 'Product 1', price: 29.99, stock: 100 },
        { id: 2, name: 'Product 2', price: 49.99, stock: 50 },
        { id: 3, name: 'Product 3', price: 19.99, stock: 200 }
      ])
    );
  }),
  
  // Order endpoints
  rest.post('/api/v1/orders', (req, res, ctx) => {
    const token = req.headers.get('authorization')?.replace('Bearer ', '');
    
    if (token === 'mock-access-token') {
      return res(
        ctx.status(201),
        ctx.json({
          id: 1,
          total: 109.97,
          status: 'pending',
          items: [
            { productId: 1, quantity: 2, price: 29.99 },
            { productId: 2, quantity: 1, price: 49.99 }
          ]
        })
      );
    }
    
    return res(ctx.status(401), ctx.json({ error: 'Unauthorized' }));
  })
);

// ====================
// INTEGRATION TEST SETUP
// ====================

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// ====================
// USER AUTHENTICATION FLOW INTEGRATION TESTS
// ====================

describe('User Authentication Flow Integration', () => {
  
  test('complete registration, login, and profile view flow', async () => {
    // Setup: Render app with router
    const { getByLabelText, getByText, findByText } = render(
      <MemoryRouter initialEntries={['/register']}>
        <AuthProvider>
          <Routes>
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/profile" element={<ProfilePage />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    
    // Step 1: Fill registration form
    const nameInput = getByLabelText(/name/i);
    const emailInput = getByLabelText(/email/i);
    const passwordInput = getByLabelText(/^password$/i);
    const confirmPasswordInput = getByLabelText(/confirm password/i);
    
    await userEvent.type(nameInput, 'Integration Test User');
    await userEvent.type(emailInput, 'test@example.com');
    await userEvent.type(passwordInput, 'password123');
    await userEvent.type(confirmPasswordInput, 'password123');
    
    // Submit registration
    const registerButton = getByText(/register/i);
    await userEvent.click(registerButton);
    
    // Should redirect to login
    await waitFor(() => {
      expect(getByText(/login/i)).toBeInTheDocument();
    });
    
    // Step 2: Login
    const loginEmailInput = getByLabelText(/email/i);
    const loginPasswordInput = getByLabelText(/password/i);
    
    await userEvent.type(loginEmailInput, 'test@example.com');
    await userEvent.type(loginPasswordInput, 'password123');
    
    const loginButton = getByText(/login/i);
    await userEvent.click(loginButton);
    
    // Should redirect to profile
    await waitFor(() => {
      expect(getByText(/profile/i)).toBeInTheDocument();
    });
    
    // Step 3: Verify profile shows user data
    await waitFor(() => {
      expect(getByText('Integration Test User')).toBeInTheDocument();
      expect(getByText('test@example.com')).toBeInTheDocument();
    });
  });
  
  test('handles authentication errors gracefully', async () => {
    const { getByLabelText, getByText, findByText } = render(
      <MemoryRouter initialEntries={['/login']}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    
    // Fill login form with invalid credentials
    const emailInput = getByLabelText(/email/i);
    const passwordInput = getByLabelText(/password/i);
    
    await userEvent.type(emailInput, 'wrong@example.com');
    await userEvent.type(passwordInput, 'wrongpassword');
    
    const loginButton = getByText(/login/i);
    await userEvent.click(loginButton);
    
    // Should show error message
    await waitFor(async () => {
      const errorMessage = await findByText(/invalid credentials/i);
      expect(errorMessage).toBeInTheDocument();
    });
    
    // Should stay on login page
    expect(getByText(/login/i)).toBeInTheDocument();
  });
});

// ====================
// E-COMMERCE FLOW INTEGRATION TESTS
// ====================

describe('E-commerce Flow Integration', () => {
  
  test('complete shopping flow from browse to purchase', async () => {
    // Setup: Login user first
    const { getByLabelText, getByText, findByText, getByTestId } = render(
      <MemoryRouter initialEntries={['/products']}>
        <AuthProvider>
          <CartProvider>
            <Routes>
              <Route path="/products" element={<ProductListPage />} />
              <Route path="/cart" element={<CartPage />} />
              <Route path="/checkout" element={<CheckoutPage />} />
              <Route path="/order-confirmation" element={<OrderConfirmationPage />} />
            </Routes>
          </CartProvider>
        </AuthProvider>
      </MemoryRouter>
    );
    
    // Login first
    fireEvent.change(getByLabelText(/email/i), { target: { value: 'test@example.com' } });
    fireEvent.change(getByLabelText(/password/i), { target: { value: 'password123' } });
    fireEvent.click(getByText(/login/i));
    
    // Step 1: Browse products
    await waitFor(() => {
      expect(getByText('Product 1')).toBeInTheDocument();
      expect(getByText('Product 2')).toBeInTheDocument();
      expect(getByText('Product 3')).toBeInTheDocument();
    });
    
    // Step 2: Add products to cart
    const product1Card = getByText('Product 1').closest('[data-testid="product-card"]');
    const addButton1 = within(product1Card).getByText(/add to cart/i);
    await userEvent.click(addButton1);
    
    const product2Card = getByText('Product 2').closest('[data-testid="product-card"]');
    const addButton2 = within(product2Card).getByText(/add to cart/i);
    await userEvent.click(addButton2);
    
    // Verify cart badge shows 2 items
    await waitFor(() => {
      expect(getByTestId('cart-badge')).toHaveTextContent('2');
    });
    
    // Step 3: View cart
    const cartLink = getByText(/cart/i);
    await userEvent.click(cartLink);
    
    await waitFor(() => {
      expect(getByText(/your cart/i)).toBeInTheDocument();
      expect(getByText('Product 1')).toBeInTheDocument();
      expect(getByText('Product 2')).toBeInTheDocument();
    });
    
    // Step 4: Update quantities
    const product1Row = getByText('Product 1').closest('tr');
    const quantityInput1 = within(product1Row).getByLabelText(/quantity/i);
    await userEvent.clear(quantityInput1);
    await userEvent.type(quantityInput1, '2');
    
    await waitFor(() => {
      const updatedTotal = within(product1Row).getByText('$59.98'); // 2 x $29.99
      expect(updatedTotal).toBeInTheDocument();
    });
    
    // Step 5: Proceed to checkout
    const checkoutButton = getByText(/proceed to checkout/i);
    await userEvent.click(checkoutButton);
    
    await waitFor(() => {
      expect(getByText(/checkout/i)).toBeInTheDocument();
    });
    
    // Step 6: Fill checkout form
    const addressInput = getByLabelText(/shipping address/i);
    const cityInput = getByLabelText(/city/i);
    const zipInput = getByLabelText(/zip code/i);
    
    await userEvent.type(addressInput, '123 Main St');
    await userEvent.type(cityInput, 'Springfield');
    await userEvent.type(zipInput, '62701');
    
    // Step 7: Submit order
    const placeOrderButton = getByText(/place order/i);
    await userEvent.click(placeOrderButton);
    
    // Step 8: Verify order confirmation
    await waitFor(async () => {
      const confirmationTitle = await findByText(/order confirmation/i);
      expect(confirmationTitle).toBeInTheDocument();
    });
    
    expect(getByText(/order #\d+/i)).toBeInTheDocument();
    expect(getByText('Product 1')).toBeInTheDocument();
    expect(getByText('Product 2')).toBeInTheDocument();
    
    // Verify total
    const totalElement = getByTestId('order-total');
    expect(totalElement).toHaveTextContent('$159.96'); // (2 x $29.99) + $49.99 + tax
  });
});

// ====================
// STATE MANAGEMENT INTEGRATION TESTS
// ====================

describe('State Management Integration', () => {
  
  test('Redux state persists across component navigation', async () => {
    const { getByText, getByLabelText } = render(
      <Provider store={mockStore}>
        <MemoryRouter initialEntries={['/products']}>
          <Routes>
            <Route path="/products" element={<ProductListWithRedux />} />
            <Route path="/cart" element={<CartPageWithRedux />} />
          </Routes>
        </MemoryRouter>
      </Provider>
    );
    
    // Add product to cart via Redux
    const addButton = getByText(/add to cart/i);
    await userEvent.click(addButton);
    
    // Navigate to cart
    const cartLink = getByText(/cart/i);
    await userEvent.click(cartLink);
    
    // Verify Redux state persisted
    await waitFor(() => {
      expect(getByText('Cart (1 item)')).toBeInTheDocument();
      expect(getByText('Product 1')).toBeInTheDocument();
    });
  });
  
  test('Context state updates propagate to all consumers', async () => {
    const TestComponent = () => {
      const { theme, toggleTheme } = React.useContext(ThemeContext);
      
      return (
        <>
          <div data-testid="theme">{theme}</div>
          <button onClick={toggleTheme}>Toggle Theme</button>
        </>
      );
    };
    
    const AnotherComponent = () => {
      const { theme } = React.useContext(ThemeContext);
      return <div data-testid="another-theme">{theme}</div>;
    };
    
    const { getByText, getByTestId } = render(
      <ThemeProvider initialTheme="light">
        <TestComponent />
        <AnotherComponent />
      </ThemeProvider>
    );
    
    // Initial state
    expect(getByTestId('theme')).toHaveTextContent('light');
    expect(getByTestId('another-theme')).toHaveTextContent('light');
    
    // Toggle theme
    await userEvent.click(getByText('Toggle Theme'));
    
    // Both components should update
    expect(getByTestId('theme')).toHaveTextContent('dark');
    expect(getByTestId('another-theme')).toHaveTextContent('dark');
  });
});

// ====================
// ROUTING INTEGRATION TESTS
// ====================

describe('Routing Integration', () => {
  
  test('route parameters and navigation work correctly', async () => {
    const TestComponent = () => {
      const { id } = useParams();
      const navigate = useNavigate();
      
      return (
        <div>
          <h1>Product {id}</h1>
          <button onClick={() => navigate('/cart')}>Go to Cart</button>
        </div>
      );
    };
    
    const { getByText } = render(
      <MemoryRouter initialEntries={['/products/123']}>
        <Routes>
          <Route path="/products/:id" element={<TestComponent />} />
          <Route path="/cart" element={<div>Cart Page</div>} />
        </Routes>
      </MemoryRouter>
    );
    
    expect(getByText('Product 123')).toBeInTheDocument();
    
    // Navigate to cart
    await userEvent.click(getByText(/go to cart/i));
    
    await waitFor(() => {
      expect(getByText('Cart Page')).toBeInTheDocument();
    });
  });
  
  test('protected routes redirect to login', async () => {
    const ProtectedRoute = ({ children }) => {
      const { user } = React.useContext(AuthContext);
      const location = useLocation();
      
      if (!user) {
        return <Navigate to="/login" state={{ from: location }} replace />;
      }
      
      return children;
    };
    
    const { getByText } = render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route 
              path="/dashboard" 
              element={
                <ProtectedRoute>
                  <div>Dashboard</div>
                </ProtectedRoute>
              } 
            />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );
    
    // Should redirect to login
    await waitFor(() => {
      expect(getByText('Login Page')).toBeInTheDocument();
    });
  });
});

// ====================
// ERROR BOUNDARY INTEGRATION TESTS
// ====================

describe('Error Boundary Integration', () => {
  
  class TestErrorBoundary extends React.Component {
    constructor(props) {
      super(props);
      this.state = { hasError: false };
    }
    
    static getDerivedStateFromError(error) {
      return { hasError: true };
    }
    
    componentDidCatch(error, errorInfo) {
      this.props.onError(error, errorInfo);
    }
    
    render() {
      if (this.state.hasError) {
        return <div data-testid="error-boundary">Something went wrong</div>;
      }
      
      return this.props.children;
    }
  }
  
  const ThrowError = ({ shouldThrow }) => {
    if (shouldThrow) {
      throw new Error('Test error');
    }
    return <div>Component works</div>;
  };
  
  test('error boundary catches and handles component errors', async () => {
    const onError = jest.fn();
    
    const { getByText, getByTestId, rerender } = render(
      <TestErrorBoundary onError={onError}>
        <ThrowError shouldThrow={false} />
      </TestErrorBoundary>
    );
    
    expect(getByText('Component works')).toBeInTheDocument();
    
    // Trigger error
    rerender(
      <TestErrorBoundary onError={onError}>
        <ThrowError shouldThrow={true} />
      </TestErrorBoundary>
    );
    
    expect(getByTestId('error-boundary')).toHaveTextContent('Something went wrong');
    expect(onError).toHaveBeenCalledWith(
      expect.any(Error),
      expect.objectContaining({ componentStack: expect.any(String) })
    );
  });
});

// ====================
// FORM INTEGRATION TESTS
// ====================

describe('Form Integration Tests', () => {
  
  test('complex form with validation and submission', async () => {
    const handleSubmit = jest.fn();
    
    const { getByLabelText, getByText, queryByText } = render(
      <RegistrationForm onSubmit={handleSubmit} />
    );
    
    // Fill form fields
    await userEvent.type(getByLabelText(/name/i), 'John Doe');
    await userEvent.type(getByLabelText(/email/i), 'john@example.com');
    await userEvent.type(getByLabelText(/^password$/i), 'Pass123!');
    await userEvent.type(getByLabelText(/confirm password/i), 'Pass123!');
    
    // Try submit (should succeed)
    const submitButton = getByText(/submit/i);
    await userEvent.click(submitButton);
    
    await waitFor(() => {
      expect(handleSubmit).toHaveBeenCalledWith({
        name: 'John Doe',
        email: 'john@example.com',
        password: 'Pass123!',
        confirmPassword: 'Pass123!'
      });
    });
    
    // Reset and test validation errors
    handleSubmit.mockClear();
    
    // Clear and enter invalid data
    const nameInput = getByLabelText(/name/i);
    await userEvent.clear(nameInput);
    await userEvent.type(nameInput, 'Jo'); // Too short
    
    await userEvent.click(submitButton);
    
    await waitFor(() => {
      expect(queryByText(/name must be at least 3 characters/i)).toBeInTheDocument();
    });
    
    expect(handleSubmit).not.toHaveBeenCalled();
  });
  
  test('multi-step form wizard', async () => {
    const { getByText, queryByText } = render(<MultiStepFormWizard />);
    
    // Step 1: Personal Info
    await userEvent.type(getByLabelText(/first name/i), 'John');
    await userEvent.type(getByLabelText(/last name/i), 'Doe');
    await userEvent.click(getByText(/next/i));
    
    await waitFor(() => {
      expect(queryByText(/contact information/i)).toBeInTheDocument();
    });
    
    // Step 2: Contact Info
    await userEvent.type(getByLabelText(/email/i), 'john@example.com');
    await userEvent.type(getByLabelText(/phone/i), '555-1234');
    await userEvent.click(getByText(/next/i));
    
    await waitFor(() => {
      expect(queryByText(/review/i)).toBeInTheDocument();
    });
    
    // Step 3: Review and submit
    expect(getByText('John Doe')).toBeInTheDocument();
    expect(getByText('john@example.com')).toBeInTheDocument();
    
    await userEvent.click(getByText(/submit/i));
    
    await waitFor(() => {
      expect(queryByText(/success/i)).toBeInTheDocument();
    });
  });
});

// ====================
// WEB SOCKET INTEGRATION TESTS
// ====================

describe('WebSocket Integration Tests', () => {
  
  class MockWebSocket {
    constructor(url) {
      this.url = url;
      this.onopen = null;
      this.onmessage = null;
      this.onerror = null;
      this.onclose = null;
      this.readyState = 0; // CONNECTING
      
      // Simulate connection
      setTimeout(() => {
        this.readyState = 1; // OPEN
        this.onopen && this.onopen();
      }, 100);
    }
    
    send(data) {
      // Simulate receiving response
      setTimeout(() => {
        this.onmessage && this.onmessage({ data: `Echo: ${data}` });
      }, 50);
    }
    
    close() {
      this.readyState = 3; // CLOSED
      this.onclose && this.onclose();
    }
  }
  
  test('real-time chat component with WebSocket', async () => {
    global.WebSocket = MockWebSocket;
    
    const { getByLabelText, getByText, findByText } = render(<ChatRoom roomId="test-room" />);
    
    // Wait for connection
    await waitFor(() => {
      expect(getByText(/connected/i)).toBeInTheDocument();
    });
    
    // Send message
    const input = getByLabelText(/message/i);
    await userEvent.type(input, 'Hello, world!');
    
    fireEvent.keyPress(input, { key: 'Enter', code: 'Enter' });
    
    // Verify message appears
    await waitFor(() => {
      expect(getByText('Hello, world!')).toBeInTheDocument();
    });
    
    // Verify echo received
    await waitFor(() => {
      expect(findByText('Echo: Hello, world!')).resolves.toBeInTheDocument();
    });
  });
});

// ====================
// PERFORMANCE INTEGRATION TESTS
// ====================

describe('Performance Integration Tests', () => {
  
  test('large list renders efficiently', async () => {
    const items = Array.from({ length: 1000 }, (_, i) => ({
      id: i,
      name: `Item ${i}`,
      description: `Description for item ${i}`
    }));
    
    const startTime = performance.now();
    
    const { container } = render(<VirtualizedList items={items} />);
    
    const renderTime = performance.now() - startTime;
    
    // Should render in less than 100ms
    expect(renderTime).toBeLessThan(100);
    
    // Should not render all items at once (virtualization)
    const renderedItems = container.querySelectorAll('[data-testid="list-item"]');
    expect(renderedItems.length).toBeLessThan(20); // Assuming viewport shows ~20 items
  });
  
  test('debounced search doesn't make excessive API calls', async () => {
    jest.useFakeTimers();
    
    const searchApi = jest.fn().mockResolvedValue({ results: [] });
    
    const { getByLabelText } = render(<SearchBar searchApi={searchApi} debounceMs={300} />);
    
    const input = getByLabelText(/search/i);
    
    // Type quickly (should only trigger search once)
    await userEvent.type(input, 'hello world');
    
    // Fast-forward time
    jest.advanceTimersByTime(300);
    
    await waitFor(() => {
      expect(searchApi).toHaveBeenCalledTimes(1);
    });
    
    jest.useRealTimers();
  });
});

// ====================
// RUN INTEGRATION TESTS
// ====================

/*
Commands to run integration tests:

# Run all integration tests
npm test -- tests/integration/

# Run specific integration test file
npm test -- tests/integration/ecommerce_flow.test.js

# Run with coverage
npm test -- tests/integration/ --coverage

# Run in watch mode for development
npm test -- tests/integration/ --watch

# Run with verbose output
npm test -- tests/integration/ --verbose

# Generate HTML report
npm test -- tests/integration/ --reporters=default --reporters=jest-html-reporter

# Debug specific test
node --inspect-brk node_modules/.bin/jest tests/integration/ecommerce_flow.test.js --runInBand

# Run tests sequentially (to debug timing issues)
npm test -- tests/integration/ --runInBand

# Filter tests by name
npm test -- tests/integration/ --testNamePattern="e-commerce"

# Clear cache before running
npm test -- tests/integration/ --clearCache

# Run with max workers
npm test -- tests/integration/ --maxWorkers=50%
*/
