// Next.js Unit Testing Template
// Comprehensive unit testing patterns for Next.js projects

/**
 * Next.js Unit Test Patterns
 * Page, component, API route, and hook testing with React Testing Library
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { renderHook } from '@testing-library/react-hooks';
import '@testing-library/jest-dom';
import userEvent from '@testing-library/user-event';
import { NextRouter } from 'next/router';

// ====================
// MOCK NEXT.JS MODULES
// ====================

jest.mock('next/router', () => ({
  useRouter: jest.fn(),
  withRouter: (Component) => (props) => <Component {...props} router={mockRouter} />
}));

jest.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }) => <a href={href}>{children}</a>
}));

jest.mock('next/image', () => ({
  __esModule: true,
  default: (props) => <img {...props} />
}));

const mockRouter: NextRouter = {
  pathname: '/',
  route: '/',
  query: {},
  asPath: '/',
  basePath: '',
  isLocaleDomain: false,
  push: jest.fn(),
  replace: jest.fn(),
  reload: jest.fn(),
  back: jest.fn(),
  prefetch: jest.fn(),
  beforePopState: jest.fn(),
  events: {
    on: jest.fn(),
    off: jest.fn(),
    emit: jest.fn()
  },
  isFallback: false,
  isReady: true,
  isPreview: false
};

// ====================
// PAGE COMPONENT TESTS
// ====================

describe('Next.js Page Components', () => {
  
  test('HomePage renders with static props', async () => {
    const mockProps = {
      products: [
        { id: 1, name: 'Product 1', price: 29.99 },
        { id: 2, name: 'Product 2', price: 49.99 }
      ],
      categories: ['Electronics', 'Books', 'Clothing']
    };
    
    const HomePage = ({ products, categories }: typeof mockProps) => {
      return (
        <div>
          <h1>Welcome to Our Store</h1>
          <div data-testid="products">
            {products.map(product => (
              <div key={product.id} data-testid="product-card">
                <h2>{product.name}</h2>
                <p>${product.price}</p>
              </div>
            ))}
          </div>
          <nav>
            {categories.map(cat => (
              <a key={cat} href={`/category/${cat.toLowerCase()}`}>
                {cat}
              </a>
            ))}
          </nav>
        </div>
      );
    };
    
    render(<HomePage {...mockProps} />);
    
    expect(screen.getByText('Welcome to Our Store')).toBeInTheDocument();
    expect(screen.getAllByTestId('product-card')).toHaveLength(2);
    expect(screen.getByText('Electronics')).toBeInTheDocument();
  });
  
  test('DynamicPage renders with dynamic route params', () => {
    const DynamicProductPage = ({ product }) => {
      return (
        <div>
          <h1>{product.name}</h1>
          <p data-testid="price">${product.price}</p>
          <p>{product.description}</p>
        </div>
      );
    };
    
    const mockProduct = {
      id: 1,
      name: 'Test Product',
      price: 99.99,
      description: 'A test product description'
    };
    
    render(<DynamicProductPage product={mockProduct} />);
    
    expect(screen.getByText('Test Product')).toBeInTheDocument();
    expect(screen.getByTestId('price')).toHaveTextContent('$99.99');
  });
  
  test('ErrorPage renders error message', () => {
    const ErrorPage = ({ statusCode, message }) => {
      return (
        <div>
          <h1>Error {statusCode}</h1>
          <p data-testid="error-message">{message}</p>
          <a href="/">Go back home</a>
        </div>
      );
    };
    
    render(<ErrorPage statusCode={404} message="Page not found" />);
    
    expect(screen.getByText('Error 404')).toBeInTheDocument();
    expect(screen.getByTestId('error-message')).toHaveTextContent('Page not found');
    expect(screen.getByText('Go back home')).toHaveAttribute('href', '/');
  });
});

// ====================
// API ROUTES TESTS
// ====================

describe('Next.js API Routes', () => {
  
  test('GET /api/products returns product list', async () => {
    const mockHandler = async (req, res) => {
      const products = [
        { id: 1, name: 'Product 1', price: 29.99 },
        { id: 2, name: 'Product 2', price: 49.99 }
      ];
      res.status(200).json(products);
    };
    
    const mockReq = { method: 'GET', query: {} };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    
    await mockHandler(mockReq, mockRes);
    
    expect(mockRes.status).toHaveBeenCalledWith(200);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ id: 1, name: 'Product 1' })
      ])
    );
  });
  
  test('POST /api/users creates new user', async () => {
    const mockHandler = async (req, res) => {
      const { name, email, password } = req.body;
      
      if (!name || !email || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
      }
      
      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
      }
      
      const newUser = {
        id: Date.now(),
        name,
        email,
        createdAt: new Date().toISOString()
      };
      
      res.status(201).json(newUser);
    };
    
    // Test successful creation
    const mockReq = {
      method: 'POST',
      body: {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'password123'
      }
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    
    await mockHandler(mockReq, mockRes);
    
    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        name: 'John Doe',
        email: 'john@example.com',
        id: expect.any(Number)
      })
    );
    
    // Test validation error
    const invalidReq = {
      method: 'POST',
      body: {
        name: 'John Doe',
        email: 'john@example.com',
        password: 'short' // Too short
      }
    };
    const invalidRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    
    await mockHandler(invalidReq, invalidRes);
    
    expect(invalidRes.status).toHaveBeenCalledWith(400);
    expect(invalidRes.json).toHaveBeenCalledWith({
      error: 'Password must be at least 8 characters'
    });
  });
  
  test('PUT /api/users/[id] handles dynamic route parameter', async () => {
    const mockHandler = async (req, res) => {
      const { id } = req.query;
      const updates = req.body;
      
      if (!id) {
        return res.status(400).json({ error: 'User ID is required' });
      }
      
      const updatedUser = {
        id: parseInt(id),
        ...updates,
        updatedAt: new Date().toISOString()
      };
      
      res.status(200).json(updatedUser);
    };
    
    const mockReq = {
      method: 'PUT',
      query: { id: '123' },
      body: { name: 'Updated Name' }
    };
    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    
    await mockHandler(mockReq, mockRes);
    
    expect(mockRes.status).toHaveBeenCalledWith(200);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 123,
        name: 'Updated Name'
      })
    );
  });
});

// ====================
// HOOKS AND UTILITIES TESTS
// ====================

describe('Next.js Hooks and Utilities', () => {
  
  test('useRouter hook provides navigation functions', () => {
    const TestComponent = () => {
      const router = useRouter();
      
      return (
      <div>
          <span data-testid="pathname">{router.pathname}</span>
          <button onClick={() => router.push('/about')}>Go to About</button>
          <button onClick={() => router.back()}>Go Back</button>
        </div>
      );
    };
    
    (useRouter as jest.Mock).mockReturnValue(mockRouter);
    
    render(<TestComponent />);
    
    expect(screen.getByTestId('pathname')).toHaveTextContent('/');
    
    fireEvent.click(screen.getByText('Go to About'));
    expect(mockRouter.push).toHaveBeenCalledWith('/about');
    
    fireEvent.click(screen.getByText('Go Back'));
    expect(mockRouter.back).toHaveBeenCalled();
  });
  
  test('useSearchParams hook handles URL parameters', () => {
    const TestComponent = () => {
      const [searchParams, setSearchParams] = useSearchParams();
      
      const page = searchParams.get('page') || '1';
      const category = searchParams.get('category') || 'all';
      
      return (
        <div>
          <div data-testid="page">Page: {page}</div>
          <div data-testid="category">Category: {category}</div>
          <button 
            onClick={() => setSearchParams({ page: '2', category: 'electronics' })}
          >
            Set Electronics Page 2
          </button>
        </div>
      );
    };
    
    const mockSearchParams = new URLSearchParams('page=1&category=all');
    jest.spyOn(require('next/navigation'), 'useSearchParams')
      .mockReturnValue(mockSearchParams);
    
    render(<TestComponent />);
    
    expect(screen.getByTestId('page')).toHaveTextContent('Page: 1');
    expect(screen.getByTestId('category')).toHaveTextContent('Category: all');
  });
  
  test('useOptimistic hook provides optimistic updates', async () => {
    const TestComponent = () => {
      const [messages, setMessages] = React.useState([
        { id: 1, text: 'Hello' }
      ]);
      
      const [optimisticMessages, addOptimisticMessage] = useOptimistic(
        messages,
        (state, newMessage) => [...state, { id: Date.now(), text: newMessage }]
      );
      
      const handleSendMessage = async (message) => {
        addOptimisticMessage(message);
        // Simulate API call
        await new Promise(resolve => setTimeout(resolve, 100));
        setMessages(prev => [...prev, { id: Date.now(), text: message }]);
      };
      
      return (
        <div>
          <div data-testid="messages">
            {optimisticMessages.map(msg => (
              <div key={msg.id}>{msg.text}</div>
            ))}
          </div>
          <button onClick={() => handleSendMessage('New message')}>
            Send Message
          </button>
        </div>
      );
    };
    
    render(<TestComponent />);
    
    expect(screen.getByTestId('messages')).toHaveTextContent('Hello');
    
    fireEvent.click(screen.getByText('Send Message'));
    
    // Should show optimistic update immediately
    await waitFor(() => {
      expect(screen.getByTestId('messages')).toHaveTextContent('New message');
    });
  });
  
  test('NextResponse and NextRequest utilities', () => {
    const mockHandler = async (request) => {
      const url = new URL(request.url);
      const searchParams = Object.fromEntries(url.searchParams.entries());
      
      const response = NextResponse.json({
        success: true,
        searchParams,
        timestamp: Date.now()
      }, {
        status: 200,
        headers: {
          'Cache-Control': 'no-cache',
          'X-Custom-Header': 'test'
        }
      });
      
      return response;
    };
    
    const mockRequest = new Request('https://example.com/api/test?foo=bar&baz=qux');
    
    return mockHandler(mockRequest).then(response => {
      expect(response.status).toBe(200);
      expect(response.headers.get('X-Custom-Header')).toBe('test');
    });
  });
});

// ====================
// SERVER COMPONENTS TESTS
// ====================

describe('React Server Components', () => {
  
  test('server component renders with async data', async () => {
    const async function ProductList({ products }) {
      // Simulating server-side data fetch
      await new Promise(resolve => setTimeout(resolve, 100));
      
      return (
        <ul>
          {products.map(product => (
            <li key={product.id}>
              {product.name} - ${product.price}
            </li>
          ))}
        </ul>
      );
    };
    
    render(<ProductList products={[
      { id: 1, name: 'Product 1', price: 29.99 },
      { id: 2, name: 'Product 2', price: 49.99 }
    ]} />);
    
    await waitFor(() => {
      expect(screen.getByText('Product 1 - $29.99')).toBeInTheDocument();
      expect(screen.getByText('Product 2 - $49.99')).toBeInTheDocument();
    });
  });
  
  test('server component with metadata', () => {
    const ServerComponentWithMeta = ({ title, description, image }) => {
      return (
        <>
          <head>
            <title>{title}</title>
            <meta name="description" content={description} />
            <meta property="og:image" content={image} />
          </head>
          <main>
            <h1>{title}</h1>
            <p>{description}</p>
          </main>
        </>
      );
    };
    
    render(
      <ServerComponentWithMeta
        title="My Page"
        description="Page description"
        image="/og-image.jpg"
      />
    );
    
    expect(screen.getByText('My Page')).toBeInTheDocument();
    expect(document.querySelector('title')).toHaveTextContent('My Page');
    expect(document.querySelector('meta[name="description"]'))
      .toHaveAttribute('content', 'Page description');
  });
});

// ====================
// CLIENT COMPONENTS TESTS
// ====================

describe('Client Components', () => {
  
  test('client component with interactive features', () => {
    const InteractiveButton = ({ onClick }) => {
      const [count, setCount] = React.useState(0);
      
      const handleClick = () => {
        setCount(prev => prev + 1);
        onClick?.();
      };
      
      return (
        <button onClick={handleClick}>
          Clicked {count} times
        </button>
      );
    };
    
    const handleClick = jest.fn();
    render(<InteractiveButton onClick={handleClick} />);
    
    const button = screen.getByRole('button');
    expect(button).toHaveTextContent('Clicked 0 times');
    
    fireEvent.click(button);
    expect(button).toHaveTextContent('Clicked 1 times');
    expect(handleClick).toHaveBeenCalled();
    
    fireEvent.click(button);
    expect(button).toHaveTextContent('Clicked 2 times');
    expect(handleClick).toHaveBeenCalledTimes(2);
  });
  
  test('client component with local storage', () => {
    const localStorageMock = {
      getItem: jest.fn().mockReturnValue(null),
      setItem: jest.fn()
    };
    global.localStorage = localStorageMock;
    
    const ThemeToggle = () => {
      const [theme, setTheme] = React.useState(() => {
        return localStorage.getItem('theme') || 'light';
      });
      
      const toggleTheme = () => {
        const newTheme = theme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
        localStorage.setItem('theme', newTheme);
      };
      
      return (
        <div>
          <div data-testid="theme">{theme}</div>
          <button onClick={toggleTheme}>Toggle Theme</button>
        </div>
      );
    };
    
    render(<ThemeToggle />);
    
    expect(screen.getByTestId('theme')).toHaveTextContent('light');
    expect(localStorageMock.getItem).toHaveBeenCalledWith('theme');
    
    fireEvent.click(screen.getByText('Toggle Theme'));
    
    expect(screen.getByTestId('theme')).toHaveTextContent('dark');
    expect(localStorageMock.setItem).toHaveBeenCalledWith('theme', 'dark');
  });
});

// ====================
// METADATA AND SEO TESTS
// ====================

describe('Metadata and SEO', () => {
  
  test('Metadata component renders proper meta tags', () => {
    const Metadata = ({ title, description, keywords }) => {
      return (
        <>
          <title>{title}</title>
          <meta name="description" content={description} />
          <meta name="keywords" content={keywords} />
          <meta property="og:title" content={title} />
          <meta property="og:description" content={description} />
          <meta name="twitter:card" content="summary_large_image" />
        </>
      );
    };
    
    render(
      <Metadata
        title="My Next.js App"
        description="A test application"
        keywords="nextjs,react,testing"
      />
    );
    
    expect(document.title).toBe('My Next.js App');
    expect(document.querySelector('meta[name="description"]'))
      .toHaveAttribute('content', 'A test application');
    expect(document.querySelector('meta[property="og:title"]'))
      .toHaveAttribute('content', 'My Next.js App');
  });
  
  test('Open Graph image meta tags', () => {
    const OpenGraphImage = ({ url, width, height, alt }) => {
      return (
        <>
          <meta property="og:image" content={url} />
          <meta property="og:image:width" content={width.toString()} />
          <meta property="og:image:height" content={height.toString()} />
          <meta property="og:image:alt" content={alt} />
        </>
      );
    };
    
    render(
      <OpenGraphImage
        url="/images/hero.jpg"
        width={1200}
        height={630}
        alt="Hero image"
      />
    );
    
    expect(document.querySelector('meta[property="og:image"]'))
      .toHaveAttribute('content', '/images/hero.jpg');
    expect(document.querySelector('meta[property="og:image:width"]'))
      .toHaveAttribute('content', '1200');
    expect(document.querySelector('meta[property="og:image:height"]'))
      .toHaveAttribute('content', '630');
  });
});

// ====================
// PERFORMANCE TESTS
// ====================

describe('Performance Tests', () => {
  
  test('large list renders efficiently', () => {
    const LargeList = ({ items }) => {
      return (
        <ul>
          {items.map(item => (
            <li key={item.id}>
              {item.name} - ${item.price}
            </li>
          ))}
        </ul>
      );
    };
    
    const items = Array.from({ length: 1000 }, (_, i) => ({
      id: i,
      name: `Item ${i}`,
      price: Math.random() * 100
    }));
    
    const { container } = render(<LargeList items={items} />);
    
    const listItems = container.querySelectorAll('li');
    expect(listItems.length).toBe(1000);
  });
  
  test('memoized component prevents unnecessary re-renders', () => {
    let renderCount = 0;
    
    const ExpensiveComponent = React.memo(({ value }) => {
      renderCount++;
      return <div data-testid="expensive">{value}</div>;
    });
    
    const ParentComponent = () => {
      const [count, setCount] = React.useState(0);
      const [memoValue] = React.useState('unchanged');
      
      return (
        <div>
          <ExpensiveComponent value={memoValue} />
          <button onClick={() => setCount(c => c + 1)}>Count: {count}</button>
        </div>
      );
    };
    
    render(<ParentComponent />);
    
    const initialRenderCount = renderCount;
    expect(screen.getByTestId('expensive')).toHaveTextContent('unchanged');
    
    fireEvent.click(screen.getByText(/count:/i));
    
    // Should not re-render memoized component
    expect(renderCount).toBe(initialRenderCount);
  });
});

// ====================
// TEST UTILITIES
// ====================

const createMockRouter = (router: Partial<NextRouter> = {}): NextRouter => {
  return {
    pathname: '/',
    route: '/',
    query: {},
    asPath: '/',
    basePath: '',
    isLocaleDomain: false,
    push: jest.fn(() => Promise.resolve(true)),
    replace: jest.fn(() => Promise.resolve(true)),
    reload: jest.fn(() => Promise.resolve()),
    back: jest.fn(() => Promise.resolve()),
    prefetch: jest.fn(() => Promise.resolve()),
    beforePopState: jest.fn(() => Promise.resolve()),
    events: {
      on: jest.fn(),
      off: jest.fn(),
      emit: jest.fn()
    },
    isFallback: false,
    isReady: true,
    isPreview: false,
    ...router
  };
};

const renderWithRouter = (
  ui: React.ReactElement,
  { router = {} }: { router?: Partial<NextRouter> } = {}
) => {
  (useRouter as jest.Mock).mockReturnValue(createMockRouter(router));
  return render(ui);
};

// ====================
// RUN NEXT.JS TESTS
// ====================

/*
Commands to run Next.js tests:

# Run all tests
npm test

# Run specific test file
npm test -- unit-tests.test.js

# Run tests in watch mode
npm test -- --watch

# Run with coverage
npm test -- --coverage

# Update snapshots
npm test -- -u

# Run in CI mode
npm test -- --ci --coverage --maxWorkers=2

# Debug test
node --inspect-brk node_modules/.bin/jest --runInBand

# Run tests matching pattern
npm test -- --testNamePattern="API Routes"

# Clear Jest cache
npm test -- --clearCache

# Generate coverage report
npm test -- --coverage --coverageReporters=html

# Run in parallel (default)
npm test

# Run sequentially
npm test -- --runInBand
*/

export { createMockRouter, renderWithRouter };
