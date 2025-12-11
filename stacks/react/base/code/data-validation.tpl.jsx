/**
 * Template: data-validation.tpl.jsx
 * Purpose: data-validation template
 * Stack: react
 * Tier: base
 */

# Universal Template System - React Stack
# Generated: 2025-12-10
# Purpose: Data validation utilities
# Tier: base
# Stack: react
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: data-validation.tpl.jsx
// PURPOSE: Comprehensive data validation utilities for React projects
// USAGE: Import and adapt for consistent data validation across the application
// DEPENDENCIES: React (createContext, useContext, useCallback, useState, useEffect)
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * React Data Validation Template
 * Purpose: Reusable data validation utilities for React projects
 * Usage: Import and adapt for consistent data validation across the application
 */

import React, { createContext, useContext, useCallback, useState, useEffect } from 'react';

/**
 * Validation types
 */
export const ValidationType = {
  REQUIRED: 'required',
  STRING: 'string',
  EMAIL: 'email',
  PHONE: 'phone',
  URL: 'url',
  MIN_LENGTH: 'min_length',
  MAX_LENGTH: 'max_length',
  MIN_VALUE: 'min_value',
  MAX_VALUE: 'max_value',
  PATTERN: 'pattern',
  CUSTOM: 'custom',
  IN_CHOICES: 'in_choices'
};

/**
 * Validation rule class
 */
export class ValidationRule {
  constructor(type, options = {}) {
    this.type = type;
    this.params = options.params || {};
    this.message = options.message || null;
    this.required = options.required || false;
  }
}

/**
 * Validation result class
 */
export class ValidationResult {
  constructor(field, value) {
    this.field = field;
    this.value = value;
    this.isValid = true;
    this.errors = [];
  }

  addError(message) {
    this.errors.push(message);
    this.isValid = false;
  }

  getFirstError() {
    return this.errors.length > 0 ? this.errors[0] : null;
  }

  toJSON() {
    return {
      field: this.field,
      value: this.value,
      isValid: this.isValid,
      errors: this.errors
    };
  }
}

/**
 * Validation context
 */
const ValidationContext = createContext();

/**
 * Validation provider
 */
export const ValidationProvider = ({ children }) => {
  const [validators] = useState(() => new Map());
  const [globalRules] = useState(() => new Map());

  /**
   * Setup built-in validators
   */
  useEffect(() => {
    // Email validator
    validators.set('email', (value) => {
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      return emailRegex.test(value);
    });

    // Phone validator
    validators.set('phone', (value) => {
      const cleanPhone = value.replace(/[\s\-\(\)]+/g, '');
      const phoneRegex = /^\+?[1-9]\d{9,14}$/;
      return phoneRegex.test(cleanPhone);
    });

    // URL validator
    validators.set('url', (value) => {
      try {
        new URL(value);
        return true;
      } catch {
        return false;
      }
    });

    // Date validator
    validators.set('date', (value) => {
      const date = new Date(value);
      return !isNaN(date.getTime()) && value.match(/^\d{4}-\d{2}-\d{2}$/);
    });

    // Number validator
    validators.set('number', (value) => {
      return !isNaN(Number(value)) && value.trim() !== '';
    });
  }, [validators]);

  /**
   * Add custom validator
   */
  const addValidator = useCallback((name, validatorFunc, errorMessage = null) => {
    validators.set(name, {
      func: validatorFunc,
      message: errorMessage || `Custom validation '${name}' failed`
    });
  }, [validators]);

  /**
   * Validate a single field
   */
  const validateField = useCallback((fieldName, value, rules) => {
    const result = new ValidationResult(fieldName, value);

    for (const rule of rules) {
      const error = validateRule(fieldName, value, rule);
      if (error) {
        result.addError(error);
      }
    }

    return result;
  }, []);

  /**
   * Validate a single rule
   */
  const validateRule = useCallback((fieldName, value, rule) => {
    const params = rule.params;

    try {
      switch (rule.type) {
        case ValidationType.REQUIRED:
          if (value === null || value === undefined || value.toString().trim() === '') {
            return rule.message || `${fieldName} is required`;
          }
          break;

        case ValidationType.STRING:
          if (value !== null && value !== undefined && typeof value !== 'string') {
            return rule.message || `${fieldName} must be a string`;
          }
          break;

        case ValidationType.EMAIL:
          if (value && !validators.get('email')(value)) {
            return rule.message || `${fieldName} must be a valid email`;
          }
          break;

        case ValidationType.PHONE:
          if (value && !validators.get('phone')(value)) {
            return rule.message || `${fieldName} must be a valid phone number`;
          }
          break;

        case ValidationType.URL:
          if (value && !validators.get('url')(value)) {
            return rule.message || `${fieldName} must be a valid URL`;
          }
          break;

        case ValidationType.MIN_LENGTH:
          if (value && value.toString().length < params.length) {
            return rule.message || `${fieldName} must be at least ${params.length} characters`;
          }
          break;

        case ValidationType.MAX_LENGTH:
          if (value && value.toString().length > params.length) {
            return rule.message || `${fieldName} must be at most ${params.length} characters`;
          }
          break;

        case ValidationType.MIN_VALUE:
          if (value !== null && value !== undefined) {
            const numValue = Number(value);
            if (isNaN(numValue) || numValue < params.value) {
              return rule.message || `${fieldName} must be at least ${params.value}`;
            }
          }
          break;

        case ValidationType.MAX_VALUE:
          if (value !== null && value !== undefined) {
            const numValue = Number(value);
            if (isNaN(numValue) || numValue > params.value) {
              return rule.message || `${fieldName} must be at most ${params.value}`;
            }
          }
          break;

        case ValidationType.PATTERN:
          if (value && params.pattern) {
            const regex = new RegExp(params.pattern);
            if (!regex.test(value.toString())) {
              return rule.message || `${fieldName} does not match required pattern`;
            }
          }
          break;

        case ValidationType.IN_CHOICES:
          if (value && params.choices && !params.choices.includes(value)) {
            return rule.message || `${fieldName} must be one of: ${params.choices.join(', ')}`;
          }
          break;

        case ValidationType.CUSTOM:
          if (params.validator && validators.has(params.validator)) {
            const validator = validators.get(params.validator);
            const validatorFunc = typeof validator === 'function' ? validator : validator.func;
            if (!validatorFunc(value)) {
              return rule.message || validator.message || `${fieldName} is not valid`;
            }
          }
          break;

        default:
          return `Unknown validation type: ${rule.type}`;
      }
    } catch (error) {
      return `Validation failed for ${fieldName}: ${error.message}`;
    }

    return null;
  }, [validators]);

  /**
   * Validate entire form
   */
  const validateForm = useCallback((data, schema) => {
    const results = {};
    let hasErrors = false;

    for (const [fieldName, rules] of Object.entries(schema)) {
      const value = data[fieldName];
      results[fieldName] = validateField(fieldName, value, rules);
      
      if (!results[fieldName].isValid) {
        hasErrors = true;
      }
    }

    return {
      isValid: !hasErrors,
      results,
      errors: Object.values(results).flatMap(result => result.errors)
    };
  }, [validateField]);

  const value = {
    validateField,
    validateForm,
    validateRule,
    addValidator
  };

  return (
    <ValidationContext.Provider value={value}>
      {children}
    </ValidationContext.Provider>
  );
};

/**
 * Hook to use validation
 */
export const useValidation = () => {
  const context = useContext(ValidationContext);
  if (!context) {
    throw new Error('useValidation must be used within a ValidationProvider');
  }
  return context;
};

/**
 * Hook for form validation
 */
export const useFormValidation = (initialValues = {}, validationSchema = {}) => {
  const { validateForm } = useValidation();
  const [values, setValues] = useState(initialValues);
  const [errors, setErrors] = useState({});
  const [touched, setTouched] = useState({});
  const [isValid, setIsValid] = useState(true);

  /**
   * Set field value and validate if touched
   */
  const setValue = useCallback((fieldName, value) => {
    setValues(prev => ({ ...prev, [fieldName]: value }));
    
    if (touched[fieldName] && validationSchema[fieldName]) {
      const { validateField } = useValidation();
      const result = validateField(fieldName, value, validationSchema[fieldName]);
      setErrors(prev => ({ ...prev, [fieldName]: result.errors }));
    }
  }, [touched, validationSchema]);

  /**
   * Mark field as touched and validate
   */
  const setTouchedField = useCallback((fieldName) => {
    setTouched(prev => ({ ...prev, [fieldName]: true }));
    
    if (validationSchema[fieldName]) {
      const { validateField } = useValidation();
      const result = validateField(fieldName, values[fieldName], validationSchema[fieldName]);
      setErrors(prev => ({ ...prev, [fieldName]: result.errors }));
    }
  }, [validationSchema, values]);

  /**
   * Validate entire form
   */
  const validate = useCallback(() => {
    const validation = validateForm(values, validationSchema);
    setErrors(validation.results);
    setIsValid(validation.isValid);
    return validation;
  }, [values, validationSchema, validateForm]);

  /**
   * Reset form
   */
  const reset = useCallback(() => {
    setValues(initialValues);
    setErrors({});
    setTouched({});
    setIsValid(true);
  }, [initialValues]);

  /**
   * Check if form has errors
   */
  const hasErrors = Object.values(errors).some(fieldErrors => fieldErrors.length > 0);

  return {
    values,
    errors,
    touched,
    isValid,
    hasErrors,
    setValue,
    setTouchedField,
    validate,
    reset
  };
};

/**
 * Validation rule builder
 */
export class ValidationRuleBuilder {
  constructor() {
    this.rules = [];
  }

  required(message = null) {
    this.rules.push(new ValidationRule(ValidationType.REQUIRED, { message }));
    return this;
  }

  string(message = null) {
    this.rules.push(new ValidationRule(ValidationType.STRING, { message }));
    return this;
  }

  email(message = null) {
    this.rules.push(new ValidationRule(ValidationType.EMAIL, { message }));
    return this;
  }

  phone(message = null) {
    this.rules.push(new ValidationRule(ValidationType.PHONE, { message }));
    return this;
  }

  url(message = null) {
    this.rules.push(new ValidationRule(ValidationType.URL, { message }));
    return this;
  }

  minLength(length, message = null) {
    this.rules.push(new ValidationRule(ValidationType.MIN_LENGTH, { 
      params: { length }, 
      message 
    }));
    return this;
  }

  maxLength(length, message = null) {
    this.rules.push(new ValidationRule(ValidationType.MAX_LENGTH, { 
      params: { length }, 
      message 
    }));
    return this;
  }

  min(value, message = null) {
    this.rules.push(new ValidationRule(ValidationType.MIN_VALUE, { 
      params: { value }, 
      message 
    }));
    return this;
  }

  max(value, message = null) {
    this.rules.push(new ValidationRule(ValidationType.MAX_VALUE, { 
      params: { value }, 
      message 
    }));
    return this;
  }

  pattern(regex, message = null) {
    this.rules.push(new ValidationRule(ValidationType.PATTERN, { 
      params: { pattern: regex }, 
      message 
    }));
    return this;
  }

  choices(choices, message = null) {
    this.rules.push(new ValidationRule(ValidationType.IN_CHOICES, { 
      params: { choices }, 
      message 
    }));
    return this;
  }

  custom(validatorName, message = null) {
    this.rules.push(new ValidationRule(ValidationType.CUSTOM, { 
      params: { validator: validatorName }, 
      message 
    }));
    return this;
  }

  build() {
    return [...this.rules];
  }
}

/**
 * Form field component with validation
 */
export const ValidatedField = ({ 
  name, 
  label, 
  type = 'text', 
  value, 
  onChange, 
  onBlur, 
  errors, 
  touched, 
  required = false,
  ...props 
}) => {
  const hasError = touched[name] && errors[name] && errors[name].length > 0;

  return (
    <div className="validated-field">
      {label && (
        <label htmlFor={name}>
          {label}
          {required && <span className="required">*</span>}
        </label>
      )}
      <input
        id={name}
        name={name}
        type={type}
        value={value || ''}
        onChange={onChange}
        onBlur={onBlur}
        className={hasError ? 'error' : ''}
        {...props}
      />
      {hasError && (
        <div className="error-message">
          {errors[name][0]}
        </div>
      )}
    </div>
  );
};

/**
 * Validation summary component
 */
export const ValidationSummary = ({ errors, touched }) => {
  const visibleErrors = Object.entries(errors)
    .filter(([fieldName]) => touched[fieldName])
    .flatMap(([fieldName, fieldErrors]) => fieldErrors);

  if (visibleErrors.length === 0) {
    return null;
  }

  return (
    <div className="validation-summary">
      <h4>Please fix the following errors:</h4>
      <ul>
        {visibleErrors.map((error, index) => (
          <li key={index}>{error}</li>
        ))}
      </ul>
    </div>
  );
};

/**
 * Predefined validation schemas
 */
export const createValidationSchemas = () => {
  const userSchema = {
    username: new ValidationRuleBuilder()
      .required('Username is required')
      .string()
      .minLength(3, 'Username must be at least 3 characters')
      .maxLength(50, 'Username must be at most 50 characters')
      .pattern(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')
      .build(),
    
    email: new ValidationRuleBuilder()
      .required('Email is required')
      .email('Please enter a valid email address')
      .build(),
    
    age: new ValidationRuleBuilder()
      .min(0, 'Age must be at least 0')
      .max(150, 'Age must be at most 150')
      .build(),
    
    password: new ValidationRuleBuilder()
      .required('Password is required')
      .minLength(8, 'Password must be at least 8 characters')
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain at least one lowercase letter, one uppercase letter, and one number')
      .build()
  };

  const contactSchema = {
    name: new ValidationRuleBuilder()
      .required('Name is required')
      .string()
      .minLength(2, 'Name must be at least 2 characters')
      .build(),
    
    email: new ValidationRuleBuilder()
      .required('Email is required')
      .email('Please enter a valid email address')
      .build(),
    
    phone: new ValidationRuleBuilder()
      .phone('Please enter a valid phone number')
      .build(),
    
    message: new ValidationRuleBuilder()
      .required('Message is required')
      .minLength(10, 'Message must be at least 10 characters')
      .maxLength(1000, 'Message must be at most 1000 characters')
      .build()
  };

  return {
    userSchema,
    contactSchema
  };
};

/**
 * Utility functions
 */
export const ValidationUtils = {
  /**
   * Validate email list
   */
  validateEmailList: (emails) => {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emails.filter(email => !emailRegex.test(email));
  },

  /**
   * Sanitize string input
   */
  sanitizeString: (value, options = {}) => {
    const {
      allowSpaces = true,
      allowSpecial = false,
      maxLength = null
    } = options;

    let pattern;
    if (allowSpaces && allowSpecial) {
      pattern = /[^a-zA-Z0-9\s\-\._@+]/g;
    } else if (allowSpaces) {
      pattern = /[^a-zA-Z0-9\s]/g;
    } else if (allowSpecial) {
      pattern = /[^a-zA-Z0-9\-\._@+]/g;
    } else {
      pattern = /[^a-zA-Z0-9]/g;
    }

    let sanitized = value.replace(pattern, '');
    
    if (maxLength && sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }

    return sanitized;
  },

  /**
   * Validate password strength
   */
  validatePasswordStrength: (password) => {
    const result = {
      isValid: true,
      score: 0,
      issues: [],
      suggestions: []
    };

    if (password.length < 8) {
      result.isValid = false;
      result.issues.push('Password must be at least 8 characters');
    } else {
      result.score += 1;
    }

    if (!/[a-z]/.test(password)) {
      result.isValid = false;
      result.issues.push('Password must contain lowercase letters');
    } else {
      result.score += 1;
    }

    if (!/[A-Z]/.test(password)) {
      result.isValid = false;
      result.issues.push('Password must contain uppercase letters');
    } else {
      result.score += 1;
    }

    if (!/\d/.test(password)) {
      result.isValid = false;
      result.issues.push('Password must contain numbers');
    } else {
      result.score += 1;
    }

    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      result.suggestions.push('Consider adding special characters for stronger security');
    } else {
      result.score += 1;
    }

    return result;
  }
};

// Example usage component
export const ExampleForm = () => {
  const { userSchema } = createValidationSchemas();
  const {
    values,
    errors,
    touched,
    isValid,
    hasErrors,
    setValue,
    setTouchedField,
    validate,
    reset
  } = useFormValidation({
    username: '',
    email: '',
    age: '',
    password: ''
  }, userSchema);

  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (validate().isValid) {
      console.log('Form submitted:', values);
      alert('Form submitted successfully!');
    } else {
      console.log('Form has errors:', errors);
    }
  };

  const handleInputChange = (fieldName) => (e) => {
    setValue(fieldName, e.target.value);
  };

  const handleInputBlur = (fieldName) => () => {
    setTouchedField(fieldName);
  };

  return (
    <div className="example-validation-form">
      <h2>Validation Example</h2>
      
      <form onSubmit={handleSubmit}>
        <ValidatedField
          name="username"
          label="Username"
          value={values.username}
          onChange={handleInputChange('username')}
          onBlur={handleInputBlur('username')}
          errors={errors}
          touched={touched}
          required
        />

        <ValidatedField
          name="email"
          label="Email"
          type="email"
          value={values.email}
          onChange={handleInputChange('email')}
          onBlur={handleInputBlur('email')}
          errors={errors}
          touched={touched}
          required
        />

        <ValidatedField
          name="age"
          label="Age"
          type="number"
          value={values.age}
          onChange={handleInputChange('age')}
          onBlur={handleInputBlur('age')}
          errors={errors}
          touched={touched}
        />

        <ValidatedField
          name="password"
          label="Password"
          type="password"
          value={values.password}
          onChange={handleInputChange('password')}
          onBlur={handleInputBlur('password')}
          errors={errors}
          touched={touched}
          required
        />

        <ValidationSummary errors={errors} touched={touched} />

        <div className="form-actions">
          <button type="submit" disabled={!isValid}>
            Submit
          </button>
          <button type="button" onClick={reset}>
            Reset
          </button>
        </div>
      </form>

      <div className="debug-info">
        <h4>Debug Info</h4>
        <p>Form Valid: {isValid ? 'Yes' : 'No'}</p>
        <p>Has Errors: {hasErrors ? 'Yes' : 'No'}</p>
        <pre>{JSON.stringify(values, null, 2)}</pre>
      </div>
    </div>
  );
};

export default {
  ValidationProvider,
  useValidation,
  useFormValidation,
  ValidationRuleBuilder,
  ValidatedField,
  ValidationSummary,
  createValidationSchemas,
  ValidationUtils,
  
  // Classes
  ValidationRule,
  ValidationResult,
  
  // Constants
  ValidationType
};
