/**
 * Template: error-handling.tpl.jsx
 * Purpose: error-handling template
 * Stack: react
 * Tier: base
 */

# Universal Template System - React_Native Stack
# Generated: 2025-12-10
# Purpose: Error handling utilities
# Tier: base
# Stack: react_native
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: error-handling.tpl.jsx
// PURPOSE: Comprehensive error handling patterns and utilities for React Native projects
// USAGE: Import and adapt for consistent error handling across the application
// DEPENDENCIES: React Native (createContext, useContext, useState, useCallback, useEffect)
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * React Native Error Handling Template
 * Purpose: Reusable error handling patterns and utilities for React Native projects
 * Usage: Import and adapt for consistent error handling across the application
 */

import React Native, { createContext, useContext, useState, useCallback, useEffect } from 'react_native';

/**
 * Error severity levels
 */
export const ErrorSeverity = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

/**
 * Error categories
 */
export const ErrorCategory = {
  VALIDATION: 'validation',
  BUSINESS_LOGIC: 'business_logic',
  EXTERNAL_API: 'external_api',
  NETWORK: 'network',
  AUTHENTICATION: 'authentication',
  AUTHORIZATION: 'authorization',
  SYSTEM: 'system',
  USER_INPUT: 'user_input'
};

/**
 * Base application error class
 */
export class BaseApplicationError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = this.constructor.name;
    this.message = message;
    this.category = options.category || ErrorCategory.SYSTEM;
    this.severity = options.severity || ErrorSeverity.MEDIUM;
    this.errorCode = options.errorCode || this.constructor.name;
    this.context = options.context || {};
    this.timestamp = new Date().toISOString();
    this.userMessage = options.userMessage || this.getDefaultUserMessage();
  }

  getDefaultUserMessage() {
    if (this.severity === ErrorSeverity.LOW) {
      return this.message;
    }
    return 'An error occurred. Please try again or contact support.';
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      category: this.category,
      severity: this.severity,
      errorCode: this.errorCode,
      context: this.context,
      timestamp: this.timestamp,
      userMessage: this.userMessage,
      stack: this.stack
    };
  }
}

/**
 * Validation error for form inputs
 */
export class ValidationError extends BaseApplicationError {
  constructor(message, field = null, value = null, options = {}) {
    super(message, {
      category: ErrorCategory.VALIDATION,
      severity: ErrorSeverity.LOW,
      ...options
    });
    this.field = field;
    this.value = value;
  }
}

/**
 * Business logic error for application rules
 */
export class BusinessLogicError extends BaseApplicationError {
  constructor(message, options = {}) {
    super(message, {
      category: ErrorCategory.BUSINESS_LOGIC,
      severity: ErrorSeverity.MEDIUM,
      ...options
    });
  }
}

/**
 * External API error for third-party service failures
 */
export class ExternalAPIError extends BaseApplicationError {
  constructor(message, options = {}) {
    super(message, {
      category: ErrorCategory.EXTERNAL_API,
      severity: ErrorSeverity.HIGH,
      ...options
    });
    this.serviceName = options.serviceName || null;
    this.statusCode = options.statusCode || null;
    this.responseData = options.responseData || null;
  }
}

/**
 * Network error for connectivity issues
 */
export class NetworkError extends BaseApplicationError {
  constructor(message, options = {}) {
    super(message, {
      category: ErrorCategory.NETWORK,
      severity: ErrorSeverity.HIGH,
      ...options
    });
    this.isOnline = navigator.onLine;
  }
}

/**
 * Authentication error for identity verification failures
 */
export class AuthenticationError extends BaseApplicationError {
  constructor(message = 'Authentication failed', options = {}) {
    super(message, {
      category: ErrorCategory.AUTHENTICATION,
      severity: ErrorSeverity.MEDIUM,
      ...options
    });
  }
}

/**
 * Authorization error for permission failures
 */
export class AuthorizationError extends BaseApplicationError {
  constructor(message = 'Access denied', options = {}) {
    super(message, {
      category: ErrorCategory.AUTHORIZATION,
      severity: ErrorSeverity.MEDIUM,
      ...options
    });
    this.resource = options.resource || null;
    this.action = options.action || null;
  }
}

/**
 * Error context for React Native components
 */
const ErrorContext = createContext();

/**
 * Error provider component
 */
export const ErrorProvider = ({ children }) => {
  const [errors, setErrors] = useState([]);
  const [isOnline, setIsOnline] = useState(navigator.onLine);

  /**
   * Add error to the error list
   */
  const addError = useCallback((error, context = {}) => {
    let errorData;

    if (error instanceof BaseApplicationError) {
      errorData = error.toJSON();
      errorData.context = { ...errorData.context, ...context };
    } else {
      // Handle unexpected errors
      errorData = {
        name: error.constructor.name,
        message: error.message,
        category: ErrorCategory.SYSTEM,
        severity: ErrorSeverity.CRITICAL,
        errorCode: 'UNEXPECTED_ERROR',
        context: {
          ...context,
          stack: error.stack
        },
        timestamp: new Date().toISOString(),
        userMessage: 'An unexpected error occurred'
      };
    }

    setErrors(prev => {
      const newErrors = [...prev, errorData];
      // Keep only last 50 errors
      return newErrors.slice(-50);
    });

    // Log to console
    console.error('Application error:', errorData);

    // Send to error reporting service
    if (errorData.severity === ErrorSeverity.CRITICAL) {
      sendErrorReport(errorData);
    }

    return errorData;
  }, []);

  /**
   * Remove error from the error list
   */
  const removeError = useCallback((errorId) => {
    setErrors(prev => prev.filter(error => error.id !== errorId));
  }, []);

  /**
   * Clear all errors
   */
  const clearErrors = useCallback(() => {
    setErrors([]);
  }, []);

  /**
   * Handle API errors
   */
  const handleAPIError = useCallback((response, error) => {
    let appError;

    if (response) {
      if (response.status === 401) {
        appError = new AuthenticationError('Session expired', {
          context: { url: response.url, status: response.status }
        });
      } else if (response.status === 403) {
        appError = new AuthorizationError('Access denied', {
          context: { url: response.url, status: response.status }
        });
      } else if (response.status === 404) {
        appError = new BusinessLogicError('Resource not found', {
          context: { url: response.url, status: response.status }
        });
      } else if (response.status >= 500) {
        appError = new ExternalAPIError('Server error', {
          statusCode: response.status,
          context: { url: response.url, status: response.status }
        });
      } else {
        appError = new ExternalAPIError(`API error: ${response.statusText}`, {
          statusCode: response.status,
          context: { url: response.url, status: response.status }
        });
      }
    } else if (error) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        appError = new NetworkError('Network connection failed', {
          context: { originalError: error.message }
        });
      } else {
        appError = new ExternalAPIError(error.message, {
          context: { originalError: error.message }
        });
      }
    }

    return addError(appError);
  }, [addError]);

  // Monitor online/offline status
  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => {
      setIsOnline(false);
      addError(new NetworkError('Network connection lost'));
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [addError]);

  const value = {
    errors,
    addError,
    removeError,
    clearErrors,
    handleAPIError,
    isOnline
  };

  return (
    <ErrorContext.Provider value={value}>
      {children}
    </ErrorContext.Provider>
  );
};

/**
 * Hook to use error handling in components
 */
export const useErrorHandler = () => {
  const context = useContext(ErrorContext);
  if (!context) {
    throw new Error('useErrorHandler must be used within an ErrorProvider');
  }
  return context;
};

/**
 * Send error to reporting service
 */
async function sendErrorReport(errorData) {
  try {
    // Replace with your error reporting service
    await fetch('/api/errors', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(errorData)
    });
  } catch (error) {
    console.warn('Failed to send error report:', error);
  }
}

/**
 * Error boundary component with error reporting
 */
export class ErrorBoundary extends React Native.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ error, errorInfo });
    
    const errorData = {
      name: error.constructor.name,
      message: error.message,
      category: ErrorCategory.SYSTEM,
      severity: ErrorSeverity.CRITICAL,
      errorCode: 'REACT_ERROR_BOUNDARY',
      context: {
        stack: error.stack,
        componentStack: errorInfo.componentStack,
        url: window.location.href,
        userAgent: navigator.userAgent
      },
      timestamp: new Date().toISOString(),
      userMessage: 'A critical error occurred'
    };

    sendErrorReport(errorData);
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback || (
        <div className="error-boundary">
          <h2>Something went wrong</h2>
          <p>We apologize for the inconvenience. The error has been reported.</p>
          <button onClick={() => window.location.reload()}>
            Reload Page
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

/**
 * Hook for async error handling
 */
export const useAsyncError = () => {
  const { addError } = useErrorHandler();

  return useCallback((error) => {
    if (error instanceof BaseApplicationError) {
      addError(error);
    } else {
      addError(new BaseApplicationError(error.message, {
        context: { originalError: error.message, stack: error.stack }
      }));
    }
  }, [addError]);
};

/**
 * Hook for form validation errors
 */
export const useFormValidation = (initialValues = {}) => {
  const [values, setValues] = useState(initialValues);
  const [errors, setErrors] = useState({});
  const [touched, setTouched] = useState({});

  const { addError } = useErrorHandler();

  const validateField = useCallback((name, value, rules) => {
    const fieldErrors = [];

    for (const rule of rules) {
      if (rule.required && (!value || value.toString().trim() === '')) {
        fieldErrors.push(`${name} is required`);
      }

      if (rule.minLength && value && value.length < rule.minLength) {
        fieldErrors.push(`${name} must be at least ${rule.minLength} characters`);
      }

      if (rule.maxLength && value && value.length > rule.maxLength) {
        fieldErrors.push(`${name} must be at most ${rule.maxLength} characters`);
      }

      if (rule.pattern && value && !rule.pattern.test(value)) {
        fieldErrors.push(rule.message || `${name} is not valid`);
      }

      if (rule.custom && !rule.custom(value)) {
        fieldErrors.push(rule.message || `${name} is not valid`);
      }
    }

    return fieldErrors;
  }, []);

  const setValue = useCallback((name, value, rules = []) => {
    setValues(prev => ({ ...prev, [name]: value }));
    
    if (touched[name]) {
      const fieldErrors = validateField(name, value, rules);
      setErrors(prev => ({ ...prev, [name]: fieldErrors }));
    }
  }, [touched, validateField]);

  const setTouchedField = useCallback((name) => {
    setTouched(prev => ({ ...prev, [name]: true }));
  }, []);

  const validateForm = useCallback((validationRules) => {
    const newErrors = {};
    let isValid = true;

    Object.entries(validationRules).forEach(([fieldName, rules]) => {
      const fieldErrors = validateField(fieldName, values[fieldName], rules);
      if (fieldErrors.length > 0) {
        newErrors[fieldName] = fieldErrors;
        isValid = false;
      }
    });

    setErrors(newErrors);
    
    if (!isValid) {
      addError(new ValidationError('Form validation failed', null, values, {
        context: { errors: newErrors }
      }));
    }

    return isValid;
  }, [values, validateField, addError]);

  const resetForm = useCallback(() => {
    setValues(initialValues);
    setErrors({});
    setTouched({});
  }, [initialValues]);

  return {
    values,
    errors,
    touched,
    setValue,
    setTouchedField,
    validateForm,
    resetForm,
    hasErrors: Object.keys(errors).some(key => errors[key].length > 0)
  };
};

/**
 * Error toast notification component
 */
export const ErrorToast = ({ error, onClose }) => {
  const getSeverityColor = (severity) => {
    switch (severity) {
      case ErrorSeverity.LOW: return '#3178c6';
      case ErrorSeverity.MEDIUM: return '#f59e0b';
      case ErrorSeverity.HIGH: return '#ef4444';
      case ErrorSeverity.CRITICAL: return '#dc2626';
      default: return '#6b7280';
    }
  };

  return (
    <div className="error-toast" style={{ borderLeftColor: getSeverityColor(error.severity) }}>
      <div className="error-header">
        <span className="error-category">{error.category}</span>
        <button onClick={onClose} className="error-close">×</button>
      </div>
      <div className="error-message">{error.userMessage}</div>
      {error.severity === ErrorSeverity.CRITICAL && (
        <div className="error-actions">
          <button onClick={() => window.location.reload()}>Reload Page</button>
        </div>
      )}
    </div>
  );
};

/**
 * Error notification container
 */
export const ErrorNotifications = () => {
  const { errors, removeError } = useErrorHandler();

  return (
    <div className="error-notifications">
      {errors.map(error => (
        <ErrorToast
          key={error.timestamp}
          error={error}
          onClose={() => removeError(error.timestamp)}
        />
      ))}
    </div>
  );
};

/**
 * Higher-order component for error handling
 */
export const withErrorHandling = (WrappedComponent) => {
  return function ErrorHandledComponent(props) {
    const { addError } = useErrorHandler();

    const handleError = useCallback((error, context = {}) => {
      addError(error, context);
    }, [addError]);

    return (
      <WrappedComponent
        {...props}
        onError={handleError}
      />
    );
  };
};

/**
 * Custom hook for API calls with error handling
 */
export const useAPI = () => {
  const { handleAPIError } = useErrorHandler();

  const callAPI = useCallback(async (url, options = {}) => {
    try {
      const response = await fetch(url, options);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      handleAPIError(null, error);
      throw error;
    }
  }, [handleAPIError]);

  return { callAPI };
};

// Example usage component
export const ExampleComponent = () => {
  const { addError, clearErrors, errors } = useErrorHandler();
  const { values, errors: formErrors, setValue, validateForm } = useFormValidation({
    email: '',
    password: ''
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    
    const validationRules = {
      email: [
        { required: true },
        { pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, message: 'Invalid email address' }
      ],
      password: [
        { required: true },
        { minLength: 8 }
      ]
    };

    if (validateForm(validationRules)) {
      // Form is valid, submit it
      console.log('Form submitted:', values);
    }
  };

  const triggerTestError = () => {
    addError(new ValidationError('This is a test validation error', 'testField', 'testValue'));
  };

  return (
    <div className="example-error-handling">
      <h2>Error Handling Example</h2>
      
      <form onSubmit={handleSubmit}>
        <div>
          <input
            type="email"
            placeholder="Email"
            value={values.email}
            onChange={(e) => setValue('email', e.target.value)}
          />
          {formErrors.email && (
            <span className="field-error">{formErrors.email[0]}</span>
          )}
        </div>
        
        <div>
          <input
            type="password"
            placeholder="Password"
            value={values.password}
            onChange={(e) => setValue('password', e.target.value)}
          />
          {formErrors.password && (
            <span className="field-error">{formErrors.password[0]}</span>
          )}
        </div>
        
        <button type="submit">Submit</button>
      </form>
      
      <button onClick={triggerTestError}>Trigger Test Error</button>
      <button onClick={clearErrors}>Clear Errors</button>
      
      <ErrorNotifications />
    </div>
  );
};

export default {
  ErrorProvider,
  useErrorHandler,
  ErrorBoundary,
  useAsyncError,
  useFormValidation,
  ErrorNotifications,
  withErrorHandling,
  useAPI,
  
  // Error classes
  BaseApplicationError,
  ValidationError,
  BusinessLogicError,
  ExternalAPIError,
  NetworkError,
  AuthenticationError,
  AuthorizationError,
  
  // Constants
  ErrorSeverity,
  ErrorCategory
};
