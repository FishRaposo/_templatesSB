<!--
File: ERROR-HANDLING.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Error Handling Guide - React

This guide covers comprehensive error handling strategies, exception management, and error recovery patterns for React applications.

## 🚨 React Error Handling Overview

React provides robust error handling through Error Boundaries, error states, and proper exception management. Proper error handling ensures application stability and good user experience.

## 📊 Error Categories

### Common Error Types
- **Error**: Base JavaScript error class
- **TypeError**: Invalid type or operation
- **ReferenceError**: Reference to undefined variable
- **NetworkError**: HTTP and connectivity issues
- **ValidationError**: Form and data validation errors
- **AsyncError**: Promise and async operation failures
- **RenderError**: Component rendering errors

### Custom Error Classes
```javascript
class BaseAppError extends Error {
  constructor(message, code = null, context = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.context = context;
    this.timestamp = new Date().toISOString();
    this.isOperational = true;
    
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
  
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      context: this.context,
      timestamp: this.timestamp,
      stack: this.stack
    };
  }
}

class ValidationError extends BaseAppError {
  constructor(message, field = null, context = {}) {
    super(message, 'VALIDATION_ERROR', { field, ...context });
  }
}

class NetworkError extends BaseAppError {
  constructor(message, statusCode = null, context = {}) {
    super(message, 'NETWORK_ERROR', { statusCode, ...context });
  }
}

class BusinessError extends BaseAppError {
  constructor(message, code = 'BUSINESS_ERROR', context = {}) {
    super(message, code, context);
  }
}

class AsyncError extends BaseAppError {
  constructor(message, originalError = null, context = {}) {
    super(message, 'ASYNC_ERROR', { originalError: originalError?.message, ...context });
  }
}
```

## 🔍 Error Boundaries

### React Error Boundary Implementation

#### Before: No Error Boundary
```javascript
// BAD: No error boundary - app crashes on component errors
function App() {
  return (
    <div>
      <Header />
      <UserProfile userId="invalid" />
      <Footer />
    </div>
  );
}

// UserProfile component throws error - entire app crashes
function UserProfile({ userId }) {
  const [user, setUser] = useState(null);
  
  useEffect(() => {
    if (userId === 'invalid') {
      throw new Error('Invalid user ID');
    }
    fetchUser(userId).then(setUser);
  }, [userId]);
  
  return <div>{user?.name}</div>;
}
```

#### After: Comprehensive Error Boundary
```javascript
// GOOD: Comprehensive error boundary with recovery options
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null
    };
  }
  
  static getDerivedStateFromError(error) {
    return {
      hasError: true,
      error,
      errorId: this.generateErrorId()
    };
  }
  
  componentDidCatch(error, errorInfo) {
    this.setState({
      error,
      errorInfo,
      errorId: this.generateErrorId()
    });
    
    this.logError(error, errorInfo);
  }
  
  generateErrorId() {
    return `err_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  logError(error, errorInfo) {
    const errorData = {
      errorId: this.state.errorId,
      message: error.message,
      stack: error.stack,
      componentStack: errorInfo.componentStack,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href
    };
    
    // Log to monitoring service
    if (window.errorLogger) {
      window.errorLogger.logError(error, errorData);
    }
    
    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error('Error caught by boundary:', errorData);
    }
  }
  
  handleRetry = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null
    });
  };
  
  render() {
    if (this.state.hasError) {
      return this.props.fallback ? (
        this.props.fallback({
          error: this.state.error,
          errorInfo: this.state.errorInfo,
          errorId: this.state.errorId,
          retry: this.handleRetry
        })
      ) : (
        <DefaultErrorFallback
          error={this.state.error}
          errorInfo={this.state.errorInfo}
          errorId={this.state.errorId}
          onRetry={this.handleRetry}
        />
      );
    }
    
    return this.props.children;
  }
}

// Default error fallback component
const DefaultErrorFallback = ({ error, errorId, onRetry }) => (
  <div className="error-boundary-fallback">
    <div className="error-icon">
      <svg width="64" height="64" viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="12" r="10" stroke="#ff6b6b" strokeWidth="2"/>
        <line x1="15" y1="9" x2="9" y2="15" stroke="#ff6b6b" strokeWidth="2"/>
        <line x1="9" y1="9" x2="15" y2="15" stroke="#ff6b6b" strokeWidth="2"/>
      </svg>
    </div>
    
    <h2>Something went wrong</h2>
    <p>We apologize for the inconvenience. The error has been reported to our team.</p>
    
    <div className="error-actions">
      <button onClick={onRetry} className="retry-button">
        Try Again
      </button>
      <button onClick={() => window.location.reload()} className="refresh-button">
        Refresh Page
      </button>
    </div>
    
    {process.env.NODE_ENV === 'development' && (
      <details className="error-details">
        <summary>Error Details</summary>
        <pre>
          <code>
            {errorId}: {error?.message}
            {error?.stack}
          </code>
        </pre>
      </details>
    )}
  </div>
);

// Usage
function App() {
  return (
    <ErrorBoundary>
      <div className="app">
        <ErrorBoundary>
          <Header />
        </ErrorBoundary>
        
        <ErrorBoundary>
          <UserProfile userId="123" />
        </ErrorBoundary>
        
        <ErrorBoundary>
          <Footer />
        </ErrorBoundary>
      </div>
    </ErrorBoundary>
  );
}
```

### Functional Error Boundary Hook
```javascript
// GOOD: Error boundary hook for functional components
function useErrorHandler() {
  const [error, setError] = useState(null);
  
  const resetError = useCallback(() => {
    setError(null);
  }, []);
  
  const handleError = useCallback((error) => {
    setError(error);
    
    // Log error
    if (window.errorLogger) {
      window.errorLogger.logError(error, {
        timestamp: new Date().toISOString(),
        component: 'useErrorHandler'
      });
    }
  }, []);
  
  // Throw error to be caught by error boundary
  if (error) {
    throw error;
  }
  
  return { handleError, resetError };
}

// Usage in functional component
function UserProfile({ userId }) {
  const { handleError } = useErrorHandler();
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    const fetchUserData = async () => {
      try {
        setLoading(true);
        
        if (!userId) {
          throw new ValidationError('User ID is required');
        }
        
        const userData = await userService.getUser(userId);
        setUser(userData);
        
      } catch (error) {
        handleError(error);
      } finally {
        setLoading(false);
      }
    };
    
    fetchUserData();
  }, [userId, handleError]);
  
  if (loading) {
    return <div>Loading...</div>;
  }
  
  return (
    <div className="user-profile">
      <h2>{user?.name}</h2>
      <p>{user?.email}</p>
    </div>
  );
}
```

## ⚡ Async Error Handling

### Promise Error Handling

#### Before: Poor Async Error Handling
```javascript
// BAD: Not handling async errors properly
function DataComponent() {
  const [data, setData] = useState(null);
  
  useEffect(() => {
    fetchData().then(setData); // No error handling
  }, []);
  
  return <div>{data}</div>;
}

async function fetchData() {
  const response = await fetch('/api/data');
  const data = await response.json(); // Might fail
  return data;
}
```

#### After: Comprehensive Async Error Handling
```javascript
// GOOD: Comprehensive async error handling
function DataComponent() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        setError(null);
        
        const result = await dataService.fetchData();
        setData(result);
        
      } catch (err) {
        const error = handleAsyncError(err);
        setError(error);
        
        // Log error
        if (window.errorLogger) {
          window.errorLogger.logError(error, {
            component: 'DataComponent',
            operation: 'fetchData'
          });
        }
      } finally {
        setLoading(false);
      }
    };
    
    loadData();
  }, []);
  
  const handleRetry = () => {
    // Trigger refetch
    const loadData = async () => {
      try {
        setLoading(true);
        setError(null);
        
        const result = await dataService.fetchData();
        setData(result);
        
      } catch (err) {
        const error = handleAsyncError(err);
        setError(error);
      } finally {
        setLoading(false);
      }
    };
    
    loadData();
  };
  
  if (loading) {
    return <LoadingSpinner />;
  }
  
  if (error) {
    return (
      <ErrorDisplay
        error={error}
        onRetry={handleRetry}
        onDismiss={() => setError(null)}
      />
    );
  }
  
  return <DataDisplay data={data} />;
}

// Error handling utility
function handleAsyncError(error) {
  if (error instanceof NetworkError) {
    return error;
  }
  
  if (error.name === 'TypeError' && error.message.includes('fetch')) {
    return new NetworkError('Network connection failed', null, {
      originalError: error.message
    });
  }
  
  if (error.message.includes('JSON')) {
    return new ValidationError('Invalid response format', null, {
      originalError: error.message
    });
  }
  
  return new AsyncError('Failed to load data', error);
}

// Data service with error handling
class DataService {
  async fetchData() {
    try {
      const response = await fetch('/api/data', {
        timeout: 10000,
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      if (!response.ok) {
        throw new NetworkError(
          `HTTP ${response.status}: ${response.statusText}`,
          response.status,
          { url: '/api/data' }
        );
      }
      
      const data = await response.json();
      
      if (!data || typeof data !== 'object') {
        throw new ValidationError('Invalid response data');
      }
      
      return data;
      
    } catch (error) {
      if (error instanceof BaseAppError) {
        throw error;
      }
      
      if (error.name === 'AbortError') {
        throw new NetworkError('Request timeout', null, {
          originalError: error.message
        });
      }
      
      throw new AsyncError('Failed to fetch data', error);
    }
  }
  
  async submitData(formData) {
    try {
      // Validate form data
      this.validateFormData(formData);
      
      const response = await fetch('/api/submit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        
        throw new NetworkError(
          errorData.message || `HTTP ${response.status}`,
          response.status,
          { formData: sanitizeFormData(formData) }
        );
      }
      
      return await response.json();
      
    } catch (error) {
      if (error instanceof BaseAppError) {
        throw error;
      }
      
      throw new AsyncError('Failed to submit data', error);
    }
  }
  
  validateFormData(data) {
    if (!data.name || data.name.trim().length === 0) {
      throw new ValidationError('Name is required', 'name');
    }
    
    if (!data.email || !isValidEmail(data.email)) {
      throw new ValidationError('Valid email is required', 'email');
    }
  }
}

function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function sanitizeFormData(data) {
  const { name, email } = data || {};
  return { name, email };
}
```

### Custom Hook for Async Operations
```javascript
// GOOD: Custom hook for async operations with error handling
function useAsyncOperation(asyncFn, dependencies = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  const execute = useCallback(async (...args) => {
    try {
      setLoading(true);
      setError(null);
      
      const result = await asyncFn(...args);
      setData(result);
      return result;
      
    } catch (err) {
      const error = handleAsyncError(err);
      setError(error);
      
      // Log error
      if (window.errorLogger) {
        window.errorLogger.logError(error, {
          operation: asyncFn.name,
          args: sanitizeArgs(args)
        });
      }
      
      throw error;
    } finally {
      setLoading(false);
    }
  }, [asyncFn]);
  
  useEffect(() => {
    if (dependencies.length > 0) {
      execute();
    }
  }, dependencies);
  
  const reset = useCallback(() => {
    setData(null);
    setError(null);
    setLoading(false);
  }, []);
  
  return {
    data,
    loading,
    error,
    execute,
    reset
  };
}

// Usage
function UserComponent({ userId }) {
  const { data: user, loading, error, execute: loadUser } = useAsyncOperation(
    () => userService.getUser(userId),
    [userId]
  );
  
  if (loading) return <LoadingSpinner />;
  if (error) return <ErrorDisplay error={error} onRetry={loadUser} />;
  
  return <UserProfile user={user} />;
}

function sanitizeArgs(args) {
  return args.map(arg => {
    if (typeof arg === 'object' && arg !== null) {
      // Remove sensitive data
      const { password, token, ...sanitized } = arg;
      return sanitized;
    }
    return arg;
  });
}
```

## 🛡️ Form Error Handling

### Comprehensive Form Validation

#### Before: Basic Form Validation
```javascript
// BAD: Basic form validation without proper error handling
function ContactForm() {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    message: ''
  });
  
  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (!formData.name || !formData.email) {
      alert('Please fill in all fields');
      return;
    }
    
    // Submit form without error handling
    submitForm(formData);
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input
        value={formData.name}
        onChange={(e) => setFormData({...formData, name: e.target.value})}
        placeholder="Name"
      />
      <input
        value={formData.email}
        onChange={(e) => setFormData({...formData, email: e.target.value})}
        placeholder="Email"
      />
      <textarea
        value={formData.message}
        onChange={(e) => setFormData({...formData, message: e.target.value})}
        placeholder="Message"
      />
      <button type="submit">Submit</button>
    </form>
  );
}
```

#### After: Comprehensive Form Error Handling
```javascript
// GOOD: Comprehensive form validation with error handling
function ContactForm() {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    message: ''
  });
  
  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState(null);
  const [isSubmitted, setIsSubmitted] = useState(false);
  
  const validateField = (name, value) => {
    const fieldErrors = {};
    
    switch (name) {
      case 'name':
        if (!value || value.trim().length === 0) {
          fieldErrors[name] = 'Name is required';
        } else if (value.trim().length < 2) {
          fieldErrors[name] = 'Name must be at least 2 characters';
        } else if (value.trim().length > 50) {
          fieldErrors[name] = 'Name must be less than 50 characters';
        }
        break;
        
      case 'email':
        if (!value || value.trim().length === 0) {
          fieldErrors[name] = 'Email is required';
        } else if (!isValidEmail(value)) {
          fieldErrors[name] = 'Please enter a valid email address';
        }
        break;
        
      case 'message':
        if (!value || value.trim().length === 0) {
          fieldErrors[name] = 'Message is required';
        } else if (value.trim().length < 10) {
          fieldErrors[name] = 'Message must be at least 10 characters';
        } else if (value.trim().length > 500) {
          fieldErrors[name] = 'Message must be less than 500 characters';
        }
        break;
        
      default:
        break;
    }
    
    return fieldErrors;
  };
  
  const validateForm = (data) => {
    const formErrors = {};
    
    Object.keys(data).forEach(field => {
      const fieldErrors = validateField(field, data[field]);
      Object.assign(formErrors, fieldErrors);
    });
    
    return formErrors;
  };
  
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    
    // Clear field error when user starts typing
    if (errors[name]) {
      setErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[name];
        return newErrors;
      });
    }
    
    // Clear submit error when user makes changes
    if (submitError) {
      setSubmitError(null);
    }
    
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };
  
  const handleBlur = (e) => {
    const { name, value } = e.target;
    const fieldErrors = validateField(name, value);
    
    setErrors(prev => ({
      ...prev,
      ...fieldErrors
    }));
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Validate all fields
    const formErrors = validateForm(formData);
    
    if (Object.keys(formErrors).length > 0) {
      setErrors(formErrors);
      return;
    }
    
    try {
      setIsSubmitting(true);
      setSubmitError(null);
      
      await formService.submitContactForm(formData);
      
      setIsSubmitted(true);
      setFormData({ name: '', email: '', message: '' });
      
    } catch (error) {
      const handledError = handleFormError(error);
      setSubmitError(handledError);
      
      // Log error
      if (window.errorLogger) {
        window.errorLogger.logError(handledError, {
          component: 'ContactForm',
          formData: sanitizeFormData(formData)
        });
      }
    } finally {
      setIsSubmitting(false);
    }
  };
  
  const handleReset = () => {
    setFormData({ name: '', email: '', message: '' });
    setErrors({});
    setSubmitError(null);
    setIsSubmitted(false);
  };
  
  if (isSubmitted) {
    return (
      <div className="form-success">
        <h3>Thank you for your message!</h3>
        <p>We'll get back to you soon.</p>
        <button onClick={handleReset}>Send another message</button>
      </div>
    );
  }
  
  return (
    <form onSubmit={handleSubmit} className="contact-form">
      <h2>Contact Us</h2>
      
      <FormField
        label="Name"
        name="name"
        type="text"
        value={formData.name}
        onChange={handleInputChange}
        onBlur={handleBlur}
        error={errors.name}
        required
      />
      
      <FormField
        label="Email"
        name="email"
        type="email"
        value={formData.email}
        onChange={handleInputChange}
        onBlur={handleBlur}
        error={errors.email}
        required
      />
      
      <FormField
        label="Message"
        name="message"
        type="textarea"
        value={formData.message}
        onChange={handleInputChange}
        onBlur={handleBlur}
        error={errors.message}
        required
        rows={5}
      />
      
      {submitError && (
        <div className="form-error">
          <span className="error-icon">⚠️</span>
          {submitError.message}
        </div>
      )}
      
      <div className="form-actions">
        <button
          type="submit"
          disabled={isSubmitting}
          className="submit-button"
        >
          {isSubmitting ? 'Sending...' : 'Send Message'}
        </button>
        
        <button
          type="button"
          onClick={handleReset}
          disabled={isSubmitting}
          className="reset-button"
        >
          Reset
        </button>
      </div>
    </form>
  );
}

// Reusable form field component
function FormField({
  label,
  name,
  type,
  value,
  onChange,
  onBlur,
  error,
  required,
  ...props
}) {
  const fieldId = `field-${name}`;
  const hasError = !!error;
  
  return (
    <div className={`form-field ${hasError ? 'has-error' : ''}`}>
      <label htmlFor={fieldId}>
        {label}
        {required && <span className="required">*</span>}
      </label>
      
      {type === 'textarea' ? (
        <textarea
          id={fieldId}
          name={name}
          value={value}
          onChange={onChange}
          onBlur={onBlur}
          className={hasError ? 'error' : ''}
          aria-describedby={hasError ? `${fieldId}-error` : undefined}
          {...props}
        />
      ) : (
        <input
          id={fieldId}
          name={name}
          type={type}
          value={value}
          onChange={onChange}
          onBlur={onBlur}
          className={hasError ? 'error' : ''}
          aria-describedby={hasError ? `${fieldId}-error` : undefined}
          {...props}
        />
      )}
      
      {hasError && (
        <div id={`${fieldId}-error`} className="field-error">
          {error}
        </div>
      )}
    </div>
  );
}

// Form error handling utility
function handleFormError(error) {
  if (error instanceof ValidationError) {
    return error;
  }
  
  if (error instanceof NetworkError) {
    if (error.context?.statusCode === 429) {
      return new BusinessError(
        'Too many requests. Please try again later.',
        'RATE_LIMIT_EXCEEDED'
      );
    }
    
    if (error.context?.statusCode >= 500) {
      return new BusinessError(
        'Server error. Please try again later.',
        'SERVER_ERROR'
      );
    }
    
    return error;
  }
  
  return new AsyncError('Failed to submit form', error);
}
```

## 🔄 Error Recovery & Retry

### Retry Component with Exponential Backoff
```javascript
// GOOD: Retry component with exponential backoff
function RetryWrapper({
  children,
  maxAttempts = 3,
  delay = 1000,
  backoffFactor = 2,
  onRetry,
  fallback
}) {
  const [attempt, setAttempt] = useState(0);
  const [error, setError] = useState(null);
  const [isRetrying, setIsRetrying] = useState(false);
  
  const handleRetry = useCallback(async () => {
    if (attempt >= maxAttempts) {
      return;
    }
    
    setIsRetrying(true);
    setError(null);
    
    try {
      const retryDelay = delay * Math.pow(backoffFactor, attempt);
      await new Promise(resolve => setTimeout(resolve, retryDelay));
      
      setAttempt(prev => prev + 1);
      onRetry?.(attempt + 1);
      
    } catch (retryError) {
      setError(retryError);
    } finally {
      setIsRetrying(false);
    }
  }, [attempt, maxAttempts, delay, backoffFactor, onRetry]);
  
  const handleError = useCallback((error) => {
    setError(error);
    
    // Log error
    if (window.errorLogger) {
      window.errorLogger.logError(error, {
        component: 'RetryWrapper',
        attempt: attempt + 1,
        maxAttempts
      });
    }
  }, [attempt, maxAttempts]);
  
  if (error) {
    if (attempt >= maxAttempts) {
      return fallback ? (
        fallback({ error, attempt, maxAttempts })
      ) : (
        <div className="retry-failed">
          <h3>Failed after {maxAttempts} attempts</h3>
          <p>{error.message}</p>
          <button onClick={() => setAttempt(0)}>
            Try Again
          </button>
        </div>
      );
    }
    
    return (
      <div className="retry-prompt">
        <h3>Something went wrong</h3>
        <p>{error.message}</p>
        <button 
          onClick={handleRetry}
          disabled={isRetrying}
        >
          {isRetrying ? 'Retrying...' : `Retry (${attempt + 1}/${maxAttempts})`}
        </button>
      </div>
    );
  }
  
  return (
    <ErrorBoundary onError={handleError}>
      {React.cloneElement(children, { 
        key: attempt, // Force re-render on retry
        onError: handleError 
      })}
    </ErrorBoundary>
  );
}

// Usage
function DataComponent() {
  return (
    <RetryWrapper
      maxAttempts={3}
      delay={1000}
      fallback={({ error, attempt }) => (
        <div className="data-error">
          <h3>Unable to load data</h3>
          <p>Error: {error.message}</p>
          <p>Attempts: {attempt}/3</p>
        </div>
      )}
    >
      <DataContent />
    </RetryWrapper>
  );
}
```

## 📝 Error Logging & Monitoring

### Error Logging System
```javascript
// GOOD: Comprehensive error logging system
class ErrorLogger {
  constructor(options = {}) {
    this.serviceName = options.serviceName || 'react-app';
    this.environment = options.environment || process.env.NODE_ENV;
    this.version = options.version || '1.0.0';
    this.userId = null;
    this.sessionId = this.generateSessionId();
  }
  
  generateSessionId() {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  setUserId(userId) {
    this.userId = userId;
  }
  
  logError(error, context = {}) {
    const errorData = {
      timestamp: new Date().toISOString(),
      service: this.serviceName,
      environment: this.environment,
      version: this.version,
      sessionId: this.sessionId,
      userId: this.userId,
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
        code: error.code,
        context: error.context || {}
      },
      context: {
        url: window.location.href,
        userAgent: navigator.userAgent,
        ...context
      }
    };
    
    // Log to console in development
    if (this.environment === 'development') {
      console.error('Error logged:', errorData);
    }
    
    // Send to monitoring service
    this.sendToMonitoringService(errorData);
    
    // Store in local storage for debugging
    this.storeErrorLocally(errorData);
  }
  
  sendToMonitoringService(errorData) {
    // Send to external monitoring service
    fetch('/api/errors', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(errorData)
    }).catch(err => {
      console.warn('Failed to send error to monitoring service:', err);
    });
  }
  
  storeErrorLocally(errorData) {
    try {
      const storedErrors = JSON.parse(localStorage.getItem('errorLogs') || '[]');
      storedErrors.push(errorData);
      
      // Keep only last 50 errors
      if (storedErrors.length > 50) {
        storedErrors.splice(0, storedErrors.length - 50);
      }
      
      localStorage.setItem('errorLogs', JSON.stringify(storedErrors));
    } catch (err) {
      console.warn('Failed to store error locally:', err);
    }
  }
  
  logUserAction(action, context = {}) {
    const actionData = {
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId,
      userId: this.userId,
      action,
      context: {
        url: window.location.href,
        ...context
      }
    };
    
    // Send to analytics service
    this.sendToAnalyticsService(actionData);
  }
  
  sendToAnalyticsService(actionData) {
    fetch('/api/analytics', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(actionData)
    }).catch(err => {
      console.warn('Failed to send analytics data:', err);
    });
  }
}

// Initialize error logger
const errorLogger = new ErrorLogger({
  serviceName: 'my-react-app',
  environment: process.env.NODE_ENV,
  version: '1.0.0'
});

// Make available globally
window.errorLogger = errorLogger;

// Error context provider
const ErrorContext = React.createContext();

function ErrorProvider({ children }) {
  const [errors, setErrors] = useState([]);
  
  const addError = useCallback((error, context = {}) => {
    errorLogger.logError(error, context);
    
    setErrors(prev => [
      ...prev,
      {
        id: Date.now(),
        error,
        context,
        timestamp: new Date()
      }
    ]);
  }, []);
  
  const clearErrors = useCallback(() => {
    setErrors([]);
  }, []);
  
  const removeError = useCallback((id) => {
    setErrors(prev => prev.filter(err => err.id !== id));
  }, []);
  
  return (
    <ErrorContext.Provider value={{
      errors,
      addError,
      clearErrors,
      removeError
    }}>
      {children}
    </ErrorContext.Provider>
  );
}

function useErrorContext() {
  const context = useContext(ErrorContext);
  if (!context) {
    throw new Error('useErrorContext must be used within ErrorProvider');
  }
  return context;
}

// Usage in app
function App() {
  return (
    <ErrorProvider>
      <ErrorBoundary>
        <Router>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/contact" element={<ContactPage />} />
          </Routes>
        </Router>
      </ErrorBoundary>
    </ErrorProvider>
  );
}
```

## 🧪 Error Testing

### Testing Error Boundaries
```javascript
// GOOD: Testing error boundaries
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';

describe('ErrorBoundary', () => {
  let consoleSpy;
  
  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });
  
  afterEach(() => {
    consoleSpy.mockRestore();
  });
  
  it('should render fallback UI when child component throws error', () => {
    const ThrowError = () => {
      throw new Error('Test error');
    };
    
    render(
      <ErrorBoundary>
        <ThrowError />
      </ErrorBoundary>
    );
    
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    expect(screen.getByText('Try Again')).toBeInTheDocument();
  });
  
  it('should render custom fallback when provided', () => {
    const CustomFallback = ({ error, retry }) => (
      <div>
        <span>Custom error: {error.message}</span>
        <button onClick={retry}>Custom Retry</button>
      </div>
    );
    
    const ThrowError = () => {
      throw new Error('Custom test error');
    };
    
    render(
      <ErrorBoundary fallback={CustomFallback}>
        <ThrowError />
      </ErrorBoundary>
    );
    
    expect(screen.getByText('Custom error: Custom test error')).toBeInTheDocument();
    expect(screen.getByText('Custom Retry')).toBeInTheDocument();
  });
  
  it('should reset error state when retry is clicked', () => {
    const ThrowError = () => {
      throw new Error('Test error');
    };
    
    const { rerender } = render(
      <ErrorBoundary>
        <ThrowError />
      </ErrorBoundary>
    );
    
    // Should show error fallback
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    
    // Click retry
    fireEvent.click(screen.getByText('Try Again'));
    
    // Rerender with working component
    rerender(
      <ErrorBoundary>
        <div>Working component</div>
      </ErrorBoundary>
    );
    
    expect(screen.getByText('Working component')).toBeInTheDocument();
  });
});

describe('useErrorHandler', () => {
  it('should handle errors and throw them to error boundary', () => {
    const TestComponent = () => {
      const { handleError } = useErrorHandler();
      
      useEffect(() => {
        handleError(new Error('Test error'));
      }, [handleError]);
      
      return <div>Test component</div>;
    };
    
    render(
      <ErrorBoundary>
        <TestComponent />
      </ErrorBoundary>
    );
    
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
  });
});

describe('ContactForm', () => {
  it('should display validation errors for empty fields', async () => {
    render(<ContactForm />);
    
    const submitButton = screen.getByRole('button', { name: 'Send Message' });
    fireEvent.click(submitButton);
    
    expect(screen.getByText('Name is required')).toBeInTheDocument();
    expect(screen.getByText('Email is required')).toBeInTheDocument();
    expect(screen.getByText('Message is required')).toBeInTheDocument();
  });
  
  it('should display error for invalid email', async () => {
    render(<ContactForm />);
    
    const emailInput = screen.getByLabelText(/email/i);
    fireEvent.change(emailInput, { target: { value: 'invalid-email' } });
    fireEvent.blur(emailInput);
    
    expect(screen.getByText('Please enter a valid email address')).toBeInTheDocument();
  });
  
  it('should handle form submission errors', async () => {
    const mockSubmit = jest.fn().mockRejectedValue(new Error('Submission failed'));
    jest.mock('../services/formService', () => ({
      submitContactForm: mockSubmit
    }));
    
    render(<ContactForm />);
    
    // Fill form with valid data
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: 'John Doe' } });
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'john@example.com' } });
    fireEvent.change(screen.getByLabelText(/message/i), { target: { value: 'Test message with sufficient length' } });
    
    // Submit form
    fireEvent.click(screen.getByRole('button', { name: 'Send Message' }));
    
    // Should show submission error
    await waitFor(() => {
      expect(screen.getByText(/Failed to submit form/)).toBeInTheDocument();
    });
  });
});
```

## 🚀 Best Practices Checklist

### Error Boundaries
- [ ] Implement error boundaries at component level
- [ ] Provide meaningful fallback UI
- [ ] Include retry mechanisms in error boundaries
- [ ] Log errors with context information
- [ ] Show error details only in development
- [ ] Use error boundaries for async rendering errors

### Async Error Handling
- [ ] Use try-catch blocks for async operations
- [ ] Implement proper error states in components
- [ ] Use custom hooks for async error handling
- [ ] Handle promise rejections appropriately
- [ ] Implement retry mechanisms with exponential backoff
- [ ] Provide loading states during async operations

### Form Error Handling
- [ ] Validate form fields on blur and change
- [ ] Show field-specific error messages
- [ ] Implement form-level validation
- [ ] Handle submission errors gracefully
- [ ] Provide clear error recovery options
- [ ] Use accessible error messages

### Error Logging & Monitoring
- [ ] Implement structured error logging
- [ ] Include context information in error logs
- [ ] Use error monitoring services
- [ ] Track user actions leading to errors
- [ ] Implement error rate monitoring
- [ ] Store errors locally for debugging

### User Experience
- [ ] Provide user-friendly error messages
- [ ] Include error recovery options
- [ ] Use appropriate error severity levels
- [ ] Implement graceful degradation
- [ ] Show loading states during error recovery
- [ ] Maintain application state during errors

### Testing & Validation
- [ ] Test error boundary functionality
- [ ] Test async error handling scenarios
- [ ] Validate form error handling
- [ ] Test error logging and monitoring
- [ ] Include error scenarios in unit tests
- [ ] Test error recovery mechanisms

---

**React Version**: [REACT_VERSION]  
**Error Handling Framework**: Error boundaries, Custom hooks, Form validation  
**Last Updated**: [DATE]  
**Template Version**: 1.0
