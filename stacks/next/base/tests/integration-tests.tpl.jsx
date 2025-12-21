import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { rest } from 'msw';
import { setupServer } from 'msw/node';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import { BrowserRouter } from 'react-router-dom';
import '@testing-library/jest-dom';

// Mock server setup
export const server = setupServer(
  // API endpoints to mock
  rest.get('/api/test', (req, res, ctx) => {
    return res(ctx.json({ message: 'Test successful' }));
  }),
  rest.post('/api/test', (req, res, ctx) => {
    return res(ctx.status(200), ctx.json({ success: true }));
  }),
  rest.get('/api/test/error', (req, res, ctx) => {
    return res(ctx.status(500), ctx.json({ error: 'Server error' }));
  })
);

// Integration test utilities
export const createMockStore = (initialState = {}) => {
  return configureStore({
    reducer: {
      auth: (state = { user: null, token: null }, action) => {
        switch (action.type) {
          case 'auth/loginSuccess':
            return { ...state, user: action.payload.user, token: action.payload.token };
          case 'auth/logout':
            return { user: null, token: null };
          default:
            return state;
        }
      },
      api: (state = { loading: false, data: null, error: null }, action) => {
        switch (action.type) {
          case 'api/pending':
            return { ...state, loading: true };
          case 'api/fulfilled':
            return { ...state, loading: false, data: action.payload };
          case 'api/rejected':
            return { ...state, loading: false, error: action.payload };
          default:
            return state;
        }
      },
    },
    preloadedState: initialState,
  });
};

export const renderWithProviders = (
  ui,
  {
    initialState = {},
    store = createMockStore(initialState),
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

// Database mocking utilities
export const mockDatabase = {
  users: [
    { id: 1, name: 'Test User', email: 'test@example.com' },
    { id: 2, name: 'Another User', email: 'another@example.com' },
  ],
  posts: [
    { id: 1, title: 'Test Post', content: 'Test content', userId: 1 },
  ],
  
  async findUser(id) {
    return this.users.find(u => u.id === id);
  },
  
  async createPost(post) {
    const newPost = { id: this.posts.length + 1, ...post };
    this.posts.push(newPost);
    return newPost;
  },
};

// Example integration test template
describe('{{COMPONENT_NAME}} Integration Tests', () => {
  beforeAll(() => server.listen());
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  const defaultProps = {
    // Define default props here
  };

  it('integrates with API correctly', async () => {
    renderWithProviders(<{{COMPONENT_NAME}} {...defaultProps} />);
    
    // Trigger API call
    fireEvent.click(screen.getByText('Load Data'));
    
    // Wait for API response
    await waitFor(() => {
      expect(screen.getByText('Test successful')).toBeInTheDocument();
    });
  });

  it('handles API errors gracefully', async () => {
    server.use(
      rest.get('/api/test', (req, res, ctx) => {
        return res(ctx.status(500), ctx.json({ error: 'Server error' }));
      })
    );

    renderWithProviders(<{{COMPONENT_NAME}} {...defaultProps} />);
    
    fireEvent.click(screen.getByText('Load Data'));
    
    await waitFor(() => {
      expect(screen.getByText('Error: Server error')).toBeInTheDocument();
    });
  });

  it('integrates with Redux store', async () => {
    const initialState = {
      auth: { user: { name: 'Test User', email: 'test@example.com' }, token: 'fake-token' },
    };

    renderWithProviders(<{{COMPONENT_NAME}} {...defaultProps} />, {
      initialState,
    });

    expect(screen.getByText('Welcome, Test User')).toBeInTheDocument();
  });

  it('works with database operations', async () => {
    const testUser = await mockDatabase.findUser(1);
    expect(testUser).toBeDefined();
    expect(testUser.name).toBe('Test User');
  });

  it('handles form submission with validation', async () => {
    renderWithProviders(<{{COMPONENT_NAME}} {...defaultProps} />);
    
    // Fill form
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Test Name' } });
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'test@example.com' } });
    
    // Submit form
    fireEvent.click(screen.getByText('Submit'));
    
    await waitFor(() => {
      expect(screen.getByText('Form submitted successfully')).toBeInTheDocument();
    });
  });
});

// Authentication integration helpers
export const mockAuth = {
  authenticated: {
    user: { id: 1, name: 'Test User', email: 'test@example.com' },
    token: 'fake-jwt-token',
  },
  unauthenticated: {
    user: null,
    token: null,
  },
};

export const renderWithAuth = (Component, authState = 'authenticated') => {
  const initialState = {
    auth: mockAuth[authState],
  };
  
  return renderWithProviders(Component, { initialState });
};

// API testing utilities
export const createApiMock = (endpoint, response, status = 200) => {
  return rest.get(endpoint, (req, res, ctx) => {
    return res(ctx.status(status), ctx.json(response));
  });
};

export const createPostApiMock = (endpoint, response, status = 200) => {
  return rest.post(endpoint, (req, res, ctx) => {
    return res(ctx.status(status), ctx.json(response));
  });
};

// Performance testing for integration
export const measureApiCallTime = async (apiCall) => {
  const start = performance.now();
  await apiCall();
  const end = performance.now();
  return end - start;
};
