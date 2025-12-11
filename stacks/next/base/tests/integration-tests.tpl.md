# Next.js Integration Tests Template
// Next.js Integration Testing Template
// Integration testing patterns for Next.js projects

/**
 * Next.js Integration Test Patterns
 * Full page integration, API routes, middleware, authentication flows
 */

import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { renderHook, act } from '@testing-library/react-hooks';
import '@testing-library/jest-dom';
import userEvent from '@testing-library/user-event';
import { MemoryRouterProvider } from 'next-router-mock/MemoryRouterProvider';
import mockRouter from 'next-router-mock';
import { setupServer } from 'msw/node';
import { rest } from 'msw';

// ====================
// MSW SERVER SETUP FOR NEXT.JS
// ====================

const server = setupServer(
  // API Routes
  rest.get('/api/products', (req, res, ctx) => {
    return res(
      ctx.status(200),
      ctx.json([
        { id: 1, name: 'Product 1', price: 29.99, stock: 100 },
        { id: 2, name: 'Product 2', price: 49.99, stock: 50 }
      ])
    );
  }),
  
  rest.post('/api/cart', async (req, res, ctx) => {
    const { items } = await req.json();
    
    return res(
      ctx.status(201),
      ctx.json({
        id: 'cart-123',
        items: items,
        total: items.reduce((sum, item) => sum + (item.price * item.quantity), 0)
      })
    );
  }),
  
  rest.get('/api/auth/session', (req, res, ctx) => {
    const token = req.headers.get('authorization')?.replace('Bearer ', '');
    
    if (token === 'valid-token') {
      return res(
        ctx.status(200),
        ctx.json({
          user: { id: 1, name: 'Test User', email: 'test@example.com' }
        })
      );
    }
    
    return res(ctx.status(401), ctx.json({ error: 'Unauthorized' }));
  }),
  
  rest.post('/api/auth/login', async (req, res, ctx) => {
    const { email, password } = await req.json();
    
    if (email === 'test@example.com' && password === 'password123') {
      return res(
        ctx.status(200),
        ctx.json({
          accessToken: 'valid-token',
          user: { id: 1, name: 'Test User', email: 'test@example.com' }
        })
      );
    }
    
    return res(ctx.status(401), ctx.json({ error: 'Invalid credentials' }));
  })
);

// ====================
// INTEGRATION TEST SETUP
// ====================

beforeAll(() => server.listen());
afterEach(() => {
  server.resetHandlers();
  mockRouter.setCurrentUrl('/');
});
afterAll(() => server.close());

// ====================
// FULL PAGE INTEGRATION TESTS
// ====================

describe('Next.js Full Page Integration', () => {
  
  test('complete product listing and detail flow', async () => {
    // Mock authenticated state
    const ProductListPage = () => {
      const [products, setProducts] = React.useState([]);
      const router = mockRouter;
      
      React.useEffect(() => {
        fetch('/api/products')
          .then(res => res.json())
          .then(setProducts);
      }, []);
      
      const viewProduct = (productId) => {
        router.push(`/products/${productId}`);
      };
      
      return (
        <div>
          <h1>Products</h1>
          <div data-testid="product-list">
            {products.map(product => (
              <div key={product.id} data-testid="product-card">
                <h2>{product.name}</h2>
                <p>${product.price}</p>
                <button onClick={() => viewProduct(product.id)}>
                  View Details
                </button>
              </div>
            ))}
          </div>
        </div>
      );
    };
    
    render(<ProductListPage />);
    
    // Wait for products to load
    await waitFor(() => {
      expect(screen.getAllByTestId('product-card')).toHaveLength(2);
    });
    
    expect(screen.getByText('Product 1')).toBeInTheDocument();
    expect(screen.getByText('Product 2')).toBeInTheDocument();
    
    // Click view details
    await userEvent.click(screen.getAllByText('View Details')[0]);
    
    await waitFor(() => {
      expect(mockRouter.asPath).toBe('/products/1');
    });
  });
  
  test('authentication flow with protected routes', async () => {
    const ProtectedRoute = ({ children }) = {
      const [auth, setAuth] = React.useState(null);
      
      React.useEffect(() => {
        // Check authentication
        fetch('/api/auth/session', {
          headers: { Authorization: `Bearer ${localStorage.getItem('token') || ''}` }
        })
        .then(res => res.json())
        .then(data => setAuth(data))
        .catch(() => setAuth(null));
      }, []);
      
      if (!auth) {
        return <div>Please log in</div>;
      }
      
      return <>{children}</>;
    };
    
    const DashboardPage = () => {
      const [user, setUser] = React.useState(null);
      
      React.useEffect(() => {
        fetch('/api/auth/session', {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
        })
        .then(res => res.json())
        .then(data => setUser(data.user));
      }, []);
      
      return (
        <ProtectedRoute>
          <div>
            <h1>Dashboard</h1>
            <p>Welcome, {user?.name}!</p>
          </div>
        </ProtectedRoute>
      );
    };
    
    // Set auth token
    localStorage.setItem('token', 'valid-token');
    
    render(<DashboardPage />);
    
    await waitFor(() => {
      expect(screen.getByText('Welcome, Test User!')).toBeInTheDocument();
    });
    
    // Clear token and test unauthorized
    localStorage.removeItem('token');
    
    const { rerender } = render(<DashboardPage />);
    rerender(<DashboardPage />);
    
    await waitFor(() => {
      expect(screen.getByText('Please log in')).toBeInTheDocument();
    });
  });
});

// ====================
// API ROUTE INTEGRATION TESTS
// ====================

describe('Next.js API Route Integration', () => {
  
  test('complete authentication flow with API routes', async () => {
    const LoginForm = () => {
      const [email, setEmail] = React.useState('');
      const [password, setPassword] = React.useState('');
      const [error, setError] = React.useState('');
      const [success, setSuccess] = React.useState(false);
      
      const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        
        try {
          const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
          });
          
          if (!response.ok) {
            throw new Error('Login failed');
          }
          
          const data = await response.json();
          localStorage.setItem('accessToken', data.accessToken);
          setSuccess(true);
        } catch (err) {
          setError('Invalid credentials');
        }
      };
      
      return (
        <form onSubmit={handleSubmit}>
          {error && <div className="error">{error}</div>}
          {success && <div className="success">Login successful!</div>}
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Email"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
          />
          <button type="submit">Login</button>
        </form>
      );
    };
    
    render(<LoginForm />);
    
    // Fill form with invalid credentials
    await userEvent.type(screen.getByPlaceholderText('Email'), 'wrong@example.com');
    await userEvent.type(screen.getByPlaceholderText('Password'), 'wrongpassword');
    await userEvent.click(screen.getByText('Login'));
    
    await waitFor(() => {
      expect(screen.getByText('Invalid credentials')).toBeInTheDocument();
    });
    
    // Now try with valid credentials
    await userEvent.clear(screen.getByPlaceholderText('Email'));
    await userEvent.clear(screen.getByPlaceholderText('Password'));
    
    await userEvent.type(screen.getByPlaceholderText('Email'), 'test@example.com');
    await userEvent.type(screen.getByPlaceholderText('Password'), 'password123');
    await userEvent.click(screen.getByText('Login'));
    
    await waitFor(() => {
      expect(screen.getByText('Login successful!')).toBeInTheDocument();
    });
    
    // Verify token stored
    const token = localStorage.getItem('accessToken');
    expect(token).toBe('valid-token');
  });
  
  test('cart management with API routes integration', async () => {
    const CartProvider = ({ children }) => {
      const [cart, setCart] = React.useState({ items: [], total: 0 });
      
      const addToCart = async (product) => {
        const response = await fetch('/api/cart', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            items: [...cart.items, { ...product, quantity: 1 }]
          })
        });
        
        const newCart = await response.json();
        setCart(newCart);
      };
      
      const removeFromCart = async (productId) => {
        const newItems = cart.items.filter(item => item.id !== productId);
        
        const response = await fetch('/api/cart', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ items: newItems })
        });
        
        const newCart = await response.json();
        setCart(newCart);
      };
      
      return (
        <CartContext.Provider value={{ cart, addToCart, removeFromCart }}>
          {children}
        </CartContext.Provider>
      );
    };
    
    const CartPage = () => {
      const { cart, addToCart, removeFromCart } = React.useContext(CartContext);
      
      return (
        <div>
          <h1>Shopping Cart</h1>
          <div data-testid="cart-items">
            {cart.items.map(item => (
              <div key={item.id} data-testid="cart-item">
                <span>{item.name}</span>
                <button onClick={() => removeFromCart(item.id)}>
                  Remove
                </button>
              </div>
            ))}
          </div>
          <p data-testid="cart-total">Total: ${cart.total}</p>
        </div>
      );
    };
    
    const CartContext = React.createContext();
    
    render(
      <CartProvider>
        <CartPage />
      </CartProvider>
    );
    
    // Add items via context
    const addButton = screen.getByText(/add to cart/i);
    // Would need to wrap in a component that provides addToCart
  });
});

// ====================
// MIDDLEWARE INTEGRATION TESTS
// ====================

describe('Next.js Middleware Integration', () => {
  
  test('authentication middleware protects routes', async () => {
    const ProtectedPage = () => {
      const [isAuthenticated, setIsAuthenticated] = React.useState(false);
      
      React.useEffect(() => {
        // Simulate checking auth via middleware
        fetch('/api/auth/check', {
          credentials: 'include'
        })
        .then(res => {
          if (!res.ok) {
            mockRouter.push('/login');
          } else {
            setIsAuthenticated(true);
          }
        });
      }, []);
      
      if (!isAuthenticated) {
        return <div>Checking authentication...</div>;
      }
      
      return <div>Protected Content</div>;
    };
    
    render(<ProtectedPage />);
    
    expect(screen.getByText('Checking authentication...')).toBeInTheDocument();
    
    // Simulate successful auth
    server.use(
      rest.get('/api/auth/check', (req, res, ctx) => {
        return res(ctx.status(200), ctx.json({ authenticated: true }));
      })
    );
    
    await waitFor(() => {
      expect(screen.getByText('Protected Content')).toBeInTheDocument();
    });
  });
  
  test('rate limiting middleware prevents abuse', async () => {
    let requestCount = 0;
    
    server.use(
      rest.get('/api/protected', (req, res, ctx) => {
        requestCount++;
        
        if (requestCount > 10) {
          return res(
            ctx.status(429),
            ctx.json({ error: 'Too many requests' })
          );
        }
        
        return res(ctx.status(200), ctx.json({ success: true }));
      })
    );
    
    // Make multiple requests
    const requests = [];
    for (let i = 0; i < 15; i++) {
      requests.push(fetch('/api/protected'));
    }
    
    const responses = await Promise.all(requests);
    const statuses = responses.map(r => r.status);
    
    expect(statuses.filter(s => s === 429).length).toBeGreaterThan(0);
  });
});

// ====================
// STATE MANAGEMENT INTEGRATION
// ====================

describe('State Management Integration', () => {
  
  test('Zustand store integration', async () => {
    const createUserStore = (set) => ({
      user: null,
      setUser: (user) => set({ user }),
      logout: () => set({ user: null }),
      login: async (email, password) => {
        const response = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        
        if (response.ok) {
          const data = await response.json();
          set({ user: data.user });
        }
      }
    });
    
    const useUserStore = create(createUserStore);
    
    const UserProfile = () => {
      const { user, login, logout } = useUserStore();
      
      React.useEffect(() => {
        if (!user) {
          login('test@example.com', 'password123');
        }
      }, [user, login]);
      
      if (!user) return <div>Loading...</div>;
      
      return (
        <div>
          <h1>{user.name}</h1>
          <p>{user.email}</p>
          <button onClick={logout}>Logout</button>
        </div>
      );
    };
    
    render(<UserProfile />);
    
    await waitFor(() => {
      expect(screen.getByText('Test User')).toBeInTheDocument();
      expect(screen.getByText('test@example.com')).toBeInTheDocument();
    });
    
    // Test logout
    fireEvent.click(screen.getByText('Logout'));
    
    await waitFor(() => {
      expect(screen.getByText('Loading...')).toBeInTheDocument();
    });
  });
  
  test('SWR data fetching integration', async () => {
    const DataFetcher = () => {
      const { data, error, isLoading } = useSWR('/api/products', {
        refreshInterval: 5000
      });
      
      if (isLoading) return <div>Loading...</div>;
      if (error) return <div>Error: {error.message}</div>;
      
      return (
        <ul>
          {data?.map(product => (
            <li key={product.id}>{product.name}</li>
          ))}
        </ul>
      );
    };
    
    render(<DataFetcher />);
    
    await waitFor(() => {
      expect(screen.getByText('Loading...')).toBeInTheDocument();
    });
    
    await waitFor(() => {
      expect(screen.getByText('Product 1')).toBeInTheDocument();
    });
  });
});

// ====================
// FILE UPLOAD INTEGRATION TESTS
// ====================

describe('File Upload Integration', () => {
  
  test('complete file upload flow with API route', async () => {
    const FileUploadForm = () => {
      const [selectedFile, setSelectedFile] = React.useState(null);
      const [uploadStatus, setUploadStatus] = React.useState(null);
      
      const handleFileChange = (event) => {
        setSelectedFile(event.target.files[0]);
      };
      
      const handleSubmit = async (event) => {
        event.preventDefault();
        
        const formData = new FormData();
        formData.append('file', selectedFile);
        
        try {
          const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
          });
          
          const result = await response.json();
          setUploadStatus(result);
        } catch (error) {
          setUploadStatus({ error: error.message });
        }
      };
      
      return (
        <form onSubmit={handleSubmit}>
          <input type="file" onChange={handleFileChange} />
          {selectedFile && <p>Selected: {selectedFile.name}</p>}
          <button type="submit">Upload</button>
          {uploadStatus && (
            <div>
              {uploadStatus.error && (
                <p className="error">{uploadStatus.error}</p>
              )}
              {uploadStatus.success && (
                <p className="success">File uploaded successfully!</p>
              )}
            </div>
          )}
        </form>
      );
    };
    
    render(<FileUploadForm />);
    
    // Create a mock file
    const mockFile = new File(['test content'], 'test.txt', { type: 'text/plain' });
    
    const fileInput = screen.getByLabelText('');
    await userEvent.upload(fileInput, mockFile);
    
    expect(screen.getByText('Selected: test.txt')).toBeInTheDocument();
    
    // Mock successful upload
    server.use(
      rest.post('/api/upload', (req, res, ctx) => {
        return res(
          ctx.status(200),
          ctx.json({ success: true, filename: 'test.txt' })
        );
      })
    );
    
    await userEvent.click(screen.getByText('Upload'));
    
    await waitFor(() => {
      expect(screen.getByText('File uploaded successfully!')).toBeInTheDocument();
    });
  });
});

// ====================
// INTERACTIVE COMPONENT TESTS
// ====================

describe('Interactive Next.js Components', () => {
  
  test('Dynamic form with conditional fields', async () => {
    const DynamicForm = () => {
      const [formType, setFormType] = React.useState('personal');
      const [formData, setFormData] = React.useState({});
      
      return (
        <form>
          <select value={formType} onChange={(e) => setFormType(e.target.value)}>
            <option value="personal">Personal</option>
            <option value="business">Business</option>
          </select>
          
          {formType === 'personal' ? (
            <>
              <input placeholder="Full Name" />
              <input type="date" placeholder="Date of Birth" />
            </>
          ) : (
            <>
              <input placeholder="Company Name" />
              <input placeholder="Tax ID" />
            </>
          )}
          
          <button type="submit">Submit</button>
        </form>
      );
    };
    
    render(<DynamicForm />);
    
    expect(screen.getByPlaceholderText('Full Name')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Date of Birth')).toBeInTheDocument();
    
    // Change to business form
    await userEvent.selectOptions(screen.getByRole('combobox'), 'business');
    
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Company Name')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Tax ID')).toBeInTheDocument();
    });
  });
  
  test('infinite scroll implementation', async () => {
    const InfiniteScrollList = () => {
      const [items, setItems] = React.useState([]);
      const [page, setPage] = React.useState(1);
      const [isLoading, setIsLoading] = React.useState(false);
      
      const loadMore = async () => {
        setIsLoading(true);
        
        const response = await fetch(`/api/items?page=${page}`);
        const data = await response.json();
        
        setItems(prev => [...prev, ...data.items]);
        setPage(prev => prev + 1);
        setIsLoading(false);
      };
      
      React.useEffect(() => {
        loadMore();
      }, []);
      
      const handleScroll = async (e) => {
        const { scrollTop, scrollHeight, clientHeight } = e.currentTarget;
        
        if (scrollHeight - scrollTop === clientHeight && !isLoading) {
          await loadMore();
        }
      };
      
      return (
        <div onScroll={handleScroll} style={{ height: '400px', overflow: 'auto' }}>
          {items.map((item, index) => (
            <div key={item.id || index}>{item.name}</div>
          ))}
          {isLoading && <div>Loading more...</div>}
        </div>
      );
    };
    
    render(<InfiniteScrollList />);
    
    await waitFor(() => {
      expect(screen.getByText('Loading more...')).toBeInTheDocument();
    });
  });
});

// ====================
// ERROR HANDLING INTEGRATION TESTS
// ====================

describe('Error Handling Integration', () => {
  
  test('ErrorBoundary catches and displays errors', async () => {
    const ThrowError = ({ shouldThrow }) => {
      if (shouldThrow) {
        throw new Error('Test error');
      }
      return <div>Component works</div>;
    };
    
    const ErrorBoundary = ({ children, fallback }) => {
      const [hasError, setHasError] = React.useState(false);
      const [error, setError] = React.useState(null);
      
      React.useEffect(() => {
        const errorHandler = (error) => {
          setHasError(true);
          setError(error);
        };
        
        window.addEventListener('error', errorHandler);
        return () => window.removeEventListener('error', errorHandler);
      }, []);
      
      if (hasError) {
        return fallback || <div>Something went wrong: {error?.message}</div>;
      }
      
      return children;
    };
    
    const { rerender } = render(
      <ErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ErrorBoundary>
    );
    
    expect(screen.getByText('Component works')).toBeInTheDocument();
    
    // Trigger error
    rerender(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    
    await waitFor(() => {
      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    });
  });
});

// ====================
// TEST UTILITIES
// ====================

// Custom render for Next.js with router
const renderWithNextRouter = (
  ui: React.ReactElement,
  { route = '/', query = {}, asPath = '/', pathname = route, ...routerProps } = {}
) => {
  mockRouter.setCurrentUrl(route);
  mockRouter.query = query;
  mockRouter.pathname = pathname;
  mockRouter.asPath = asPath;
  
  return render(ui, {
    wrapper: ({ children }) => (
      <MemoryRouterProvider>{children}</MemoryRouterProvider>
    )
  });
};

// Mock fetch for API routes
const mockFetch = (data, status = 200) => {
  global.fetch = jest.fn().mockResolvedValue({
    status,
    json: async () => data,
    headers: new Headers()
  });
};

// ====================
// RUN INTEGRATION TESTS
// ====================

/*
Commands to run Next.js integration tests:

# Run all integration tests
npm test -- tests/integration/

# Run specific integration test
npm test -- tests/integration/ecommerce_flow.test.js

# Run with coverage
npm test -- tests/integration/ --coverage

# Run in watch mode
npm test -- tests/integration/ --watch

# Run with verbose output
npm test -- tests/integration/ --verbose

# Generate HTML report
npm test -- tests/integration/ --reporters=jest-html-reporter

# Debug specific test
node --inspect-brk node_modules/.bin/jest tests/integration/ecommerce_flow.test.js --runInBand

# Run tests sequentially
npm test -- tests/integration/ --runInBand

# Filter tests by name
npm test -- tests/integration/ --testNamePattern="authentication"

# Clear cache
npm test -- tests/integration/ --clearCache
*/

export { renderWithNextRouter, mockFetch };
