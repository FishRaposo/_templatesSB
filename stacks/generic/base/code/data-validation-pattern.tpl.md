# Universal Template System - Generic Stack
# Generated: 2025-12-10
# Purpose: Data validation utilities
# Tier: base
# Stack: generic
# Category: utilities

# ----------------------------------------------------------------------------- 
# FILE: data-validation-pattern.tpl.md
# PURPOSE: Generic data validation design pattern
# USAGE: Adapt this pattern for your specific technology stack
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Data Validation Pattern

## Overview
Data validation is essential for ensuring data integrity, security, and user experience. This pattern provides a comprehensive approach to validating input data, business rules, and data transformations across different technology stacks.

## Core Design Pattern

### 1. Validation Architecture

#### Validation Types
- **Input Validation**: Validate incoming user data
- **Business Rule Validation**: Enforce domain-specific constraints
- **Data Type Validation**: Ensure correct data types and formats
- **Cross-Field Validation**: Validate relationships between fields
- **Conditional Validation**: Apply rules based on other field values

#### Core Components
- **Validator**: Main validation engine with rule registration
- **Validation Rules**: Individual validation constraints
- **Validation Context**: Data and metadata for validation
- **Error Collector**: Collect and format validation errors
- **Schema Builder**: Define validation schemas declaratively
- **Transformers**: Data sanitization and normalization

### 2. Pseudocode Implementation

```pseudocode
class ValidationResult:
    function __init__(is_valid, errors=None, data=None):
        self.is_valid = is_valid
        self.errors = errors or []
        self.data = data or {}
    
    function add_error(field, message, code=None):
        self.errors.append({
            "field": field,
            "message": message,
            "code": code or "VALIDATION_ERROR"
        })
        self.is_valid = False
    
    function get_field_errors(field):
        return [error for error in self.errors if error.field == field]
    
    function get_all_errors():
        return self.errors

class ValidationRule:
    function __init__(name, validator, message=None, code=None):
        self.name = name
        self.validator = validator
        self.message = message
        self.code = code
    
    function validate(value, context=None):
        try:
            return self.validator(value, context)
        except ValidationError as e:
            raise ValidationError(self.message or str(e), self.code or "VALIDATION_ERROR")

class Validator:
    function __init__():
        self.rules = {}
        self.global_rules = []
        self.transformers = {}
    
    function add_field_rule(field, rule):
        if field not in self.rules:
            self.rules[field] = []
        self.rules[field].append(rule)
    
    function add_global_rule(rule):
        self.global_rules.append(rule)
    
    function add_transformer(field, transformer):
        self.transformers[field] = transformer
    
    function validate(data, context=None):
        result = ValidationResult(True)
        transformed_data = {}
        
        # Transform data first
        for field, transformer in self.transformers.items():
            if field in data:
                try:
                    transformed_data[field] = transformer(data[field])
                except TransformError as e:
                    result.add_error(field, str(e), "TRANSFORM_ERROR")
        
        # Validate individual fields
        for field, value in transformed_data.items():
            if field in self.rules:
                for rule in self.rules[field]:
                    try:
                        rule.validate(value, context)
                    except ValidationError as e:
                        result.add_error(field, str(e), e.code)
        
        # Apply global validation rules
        for rule in self.global_rules:
            try:
                rule.validate(transformed_data, context)
            except ValidationError as e:
                result.add_error("_global", str(e), e.code)
        
        result.data = transformed_data if result.is_valid else data
        return result
    
    function validate_field(field, value, context=None):
        if field not in self.rules:
            return ValidationResult(True)
        
        result = ValidationResult(True)
        for rule in self.rules[field]:
            try:
                rule.validate(value, context)
            except ValidationError as e:
                result.add_error(field, str(e), e.code)
        
        return result

class SchemaBuilder:
    function __init__():
        self.validator = Validator()
    
    function string(field, required=False, min_length=None, max_length=None, pattern=None):
        rules = []
        
        if required:
            rules.append(ValidationRule("required", lambda v: v is not None and v != "", "Field is required", "REQUIRED"))
        
        if min_length:
            rules.append(ValidationRule("min_length", lambda v: len(v) >= min_length, f"Must be at least {min_length} characters", "MIN_LENGTH"))
        
        if max_length:
            rules.append(ValidationRule("max_length", lambda v: len(v) <= max_length, f"Must be at most {max_length} characters", "MAX_LENGTH"))
        
        if pattern:
            rules.append(ValidationRule("pattern", lambda v: regex_match(pattern, v), "Invalid format", "INVALID_FORMAT"))
        
        for rule in rules:
            self.validator.add_field_rule(field, rule)
        
        return self
    
    function number(field, required=False, min_value=None, max_value=None, integer_only=False):
        rules = []
        
        if required:
            rules.append(ValidationRule("required", lambda v: v is not None, "Field is required", "REQUIRED"))
        
        if integer_only:
            rules.append(ValidationRule("integer", lambda v: is_integer(v), "Must be an integer", "INTEGER_ONLY"))
        
        if min_value is not None:
            rules.append(ValidationRule("min_value", lambda v: v >= min_value, f"Must be at least {min_value}", "MIN_VALUE"))
        
        if max_value is not None:
            rules.append(ValidationRule("max_value", lambda v: v <= max_value, f"Must be at most {max_value}", "MAX_VALUE"))
        
        for rule in rules:
            self.validator.add_field_rule(field, rule)
        
        return self
    
    function email(field, required=False):
        rules = []
        
        if required:
            rules.append(ValidationRule("required", lambda v: v is not None and v != "", "Email is required", "REQUIRED"))
        
        rules.append(ValidationRule("email", lambda v: is_valid_email(v), "Invalid email format", "INVALID_EMAIL"))
        
        for rule in rules:
            self.validator.add_field_rule(field, rule)
        
        return self
    
    function in_choices(field, choices, required=False):
        rules = []
        
        if required:
            rules.append(ValidationRule("required", lambda v: v is not None, "Field is required", "REQUIRED"))
        
        rules.append(ValidationRule("in_choices", lambda v: v in choices, f"Must be one of: {choices}", "INVALID_CHOICE"))
        
        for rule in rules:
            self.validator.add_field_rule(field, rule)
        
        return self
    
    function custom(field, validator, message=None, code=None):
        rule = ValidationRule("custom", validator, message, code)
        self.validator.add_field_rule(field, rule)
        return self
    
    function global_rule(validator, message=None, code=None):
        rule = ValidationRule("global", validator, message, code)
        self.validator.add_global_rule(rule)
        return self
    
    function transform(field, transformer):
        self.validator.add_transformer(field, transformer)
        return self
    
    function build():
        return self.validator

// Built-in Validation Functions
function is_valid_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return regex_match(pattern, email)

function is_integer(value):
    return isinstance(value, int) or (isinstance(value, str) and value.isdigit())

function is_phone_number(phone):
    pattern = r"^\+?[\d\s\-\(\)]{10,}$"
    return regex_match(pattern, phone)

function is_strong_password(password):
    # At least 8 characters, 1 uppercase, 1 lowercase, 1 digit, 1 special
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return regex_match(pattern, password)

function is_url(url):
    pattern = r"^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$"
    return regex_match(pattern, url)

// Built-in Transformers
function trim_string(value):
    return value.strip() if isinstance(value, str) else value

function to_lowercase(value):
    return value.lower() if isinstance(value, str) else value

function to_integer(value):
    if isinstance(value, int):
        return value
    elif isinstance(value, str) and value.isdigit():
        return int(value)
    else:
        raise TransformError("Cannot convert to integer")

function normalize_email(value):
    if isinstance(value, str):
        return value.strip().lower()
    return value

// Usage Examples
function create_user_schema():
    return (SchemaBuilder()
        .string("username", required=True, min_length=3, max_length=50)
        .string("email", required=True)
        .string("password", required=True)
        .custom("password", is_strong_password, "Password must be at least 8 characters with uppercase, lowercase, digit, and special character", "WEAK_PASSWORD")
        .string("first_name", required=True, max_length=100)
        .string("last_name", required=True, max_length=100)
        .number("age", min_value=18, max_value=120)
        .in_choices("role", ["user", "admin", "moderator"], required=True)
        .transform("email", normalize_email)
        .transform("username", trim_string)
        .transform("username", to_lowercase)
        .global_rule(lambda data: data["password"] != data["username"], "Password cannot be the same as username", "PASSWORD_SAME_AS_USERNAME")
        .build())

function example_validation():
    schema = create_user_schema()
    
    user_data = {
        "username": "  JohnDoe  ",
        "email": "JOHN.DOE@EXAMPLE.COM",
        "password": "StrongPass123!",
        "first_name": "John",
        "last_name": "Doe",
        "age": 25,
        "role": "user"
    }
    
    result = schema.validate(user_data)
    
    if result.is_valid:
        print("Validation successful!")
        print("Transformed data:", result.data)
    else:
        print("Validation failed:")
        for error in result.errors:
            print(f"  {error.field}: {error.message}")

class APIValidator:
    function __init__(schema_builder):
        self.schema_builder = schema_builder
    
    function validate_request(request_data, required_fields=None):
        # Validate required fields presence
        if required_fields:
            for field in required_fields:
                if field not in request_data:
                    raise ValidationError(f"Missing required field: {field}", "MISSING_FIELD")
        
        # Validate against schema
        schema = self.schema_builder.build()
        return schema.validate(request_data)
    
    function validate_query_params(params, allowed_params=None):
        if allowed_params:
            for param in params:
                if param not in allowed_params:
                    raise ValidationError(f"Invalid query parameter: {param}", "INVALID_PARAM")
        
        # Additional query param validation
        return self.validate_request(params)

// Middleware for web frameworks
function validation_middleware(validator):
    def middleware(request, response, next_handler):
        try:
            # Validate request body
            if request.body:
                validation_result = validator.validate_request(request.body)
                if not validation_result.is_valid:
                    return response.json({
                        "success": False,
                        "errors": validation_result.errors
                    }, status_code=400)
                
                # Replace request data with validated data
                request.body = validation_result.data
            
            # Validate query parameters
            if request.query_params:
                query_result = validator.validate_query_params(request.query_params)
                if not query_result.is_valid:
                    return response.json({
                        "success": False,
                        "errors": query_result.errors
                    }, status_code=400)
                
                request.query_params = query_result.data
            
            return next_handler(request, response)
            
        except ValidationError as e:
            return response.json({
                "success": False,
                "error": str(e)
            }, status_code=400)
    
    return middleware
```

## Technology-Specific Implementations

### Node.js (JavaScript/TypeScript)
```typescript
interface ValidationError {
  field: string;
  message: string;
  code: string;
}

interface ValidationResult<T = any> {
  isValid: boolean;
  errors: ValidationError[];
  data?: T;
}

interface ValidationRule {
  name: string;
  validator: (value: any, context?: any) => boolean | void;
  message?: string;
  code?: string;
}

class Validator {
  private fieldRules: Map<string, ValidationRule[]> = new Map();
  private globalRules: ValidationRule[] = [];
  private transformers: Map<string, (value: any) => any> = new Map();

  addFieldRule(field: string, rule: ValidationRule): this {
    if (!this.fieldRules.has(field)) {
      this.fieldRules.set(field, []);
    }
    this.fieldRules.get(field)!.push(rule);
    return this;
  }

  addGlobalRule(rule: ValidationRule): this {
    this.globalRules.push(rule);
    return this;
  }

  addTransformer(field: string, transformer: (value: any) => any): this {
    this.transformers.set(field, transformer);
    return this;
  }

  validate<T = any>(data: any, context?: any): ValidationResult<T> {
    const errors: ValidationError[] = [];
    const transformedData: any = {};

    // Apply transformers
    for (const [field, transformer] of this.transformers) {
      if (field in data) {
        try {
          transformedData[field] = transformer(data[field]);
        } catch (error) {
          errors.push({
            field,
            message: error.message,
            code: 'TRANSFORM_ERROR'
          });
        }
      }
    }

    // Validate individual fields
    for (const [field, value] of Object.entries(transformedData)) {
      const rules = this.fieldRules.get(field);
      if (rules) {
        for (const rule of rules) {
          try {
            rule.validator(value, context);
          } catch (error) {
            errors.push({
              field,
              message: rule.message || error.message,
              code: rule.code || 'VALIDATION_ERROR'
            });
          }
        }
      }
    }

    // Apply global rules
    for (const rule of this.globalRules) {
      try {
        rule.validator(transformedData, context);
      } catch (error) {
        errors.push({
          field: '_global',
          message: rule.message || error.message,
          code: rule.code || 'VALIDATION_ERROR'
        });
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      data: errors.length === 0 ? transformedData : data
    };
  }
}

// Schema builder
class SchemaBuilder {
  private validator = new Validator();

  string(field: string, options: {
    required?: boolean;
    minLength?: number;
    maxLength?: number;
    pattern?: RegExp;
  } = {}): this {
    const { required, minLength, maxLength, pattern } = options;

    if (required) {
      this.validator.addFieldRule(field, {
        name: 'required',
        validator: (value) => {
          if (value === null || value === undefined || value === '') {
            throw new Error('Field is required');
          }
        },
        message: 'Field is required',
        code: 'REQUIRED'
      });
    }

    if (minLength) {
      this.validator.addFieldRule(field, {
        name: 'minLength',
        validator: (value) => {
          if (value && value.length < minLength) {
            throw new Error(`Must be at least ${minLength} characters`);
          }
        },
        message: `Must be at least ${minLength} characters`,
        code: 'MIN_LENGTH'
      });
    }

    if (maxLength) {
      this.validator.addFieldRule(field, {
        name: 'maxLength',
        validator: (value) => {
          if (value && value.length > maxLength) {
            throw new Error(`Must be at most ${maxLength} characters`);
          }
        },
        message: `Must be at most ${maxLength} characters`,
        code: 'MAX_LENGTH'
      });
    }

    if (pattern) {
      this.validator.addFieldRule(field, {
        name: 'pattern',
        validator: (value) => {
          if (value && !pattern.test(value)) {
            throw new Error('Invalid format');
          }
        },
        message: 'Invalid format',
        code: 'INVALID_FORMAT'
      });
    }

    return this;
  }

  email(field: string, required: boolean = false): this {
    if (required) {
      this.validator.addFieldRule(field, {
        name: 'required',
        validator: (value) => {
          if (!value) {
            throw new Error('Email is required');
          }
        },
        message: 'Email is required',
        code: 'REQUIRED'
      });
    }

    this.validator.addFieldRule(field, {
      name: 'email',
      validator: (value) => {
        if (value) {
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          if (!emailRegex.test(value)) {
            throw new Error('Invalid email format');
          }
        }
      },
      message: 'Invalid email format',
      code: 'INVALID_EMAIL'
    });

    return this;
  }

  number(field: string, options: {
    required?: boolean;
    min?: number;
    max?: number;
    integer?: boolean;
  } = {}): this {
    const { required, min, max, integer } = options;

    if (required) {
      this.validator.addFieldRule(field, {
        name: 'required',
        validator: (value) => {
          if (value === null || value === undefined) {
            throw new Error('Field is required');
          }
        },
        message: 'Field is required',
        code: 'REQUIRED'
      });
    }

    if (integer) {
      this.validator.addFieldRule(field, {
        name: 'integer',
        validator: (value) => {
          if (value !== null && value !== undefined && !Number.isInteger(value)) {
            throw new Error('Must be an integer');
          }
        },
        message: 'Must be an integer',
        code: 'INTEGER_ONLY'
      });
    }

    if (min !== undefined) {
      this.validator.addFieldRule(field, {
        name: 'min',
        validator: (value) => {
          if (value !== null && value !== undefined && value < min) {
            throw new Error(`Must be at least ${min}`);
          }
        },
        message: `Must be at least ${min}`,
        code: 'MIN_VALUE'
      });
    }

    if (max !== undefined) {
      this.validator.addFieldRule(field, {
        name: 'max',
        validator: (value) => {
          if (value !== null && value !== undefined && value > max) {
            throw new Error(`Must be at most ${max}`);
          }
        },
        message: `Must be at most ${max}`,
        code: 'MAX_VALUE'
      });
    }

    return this;
  }

  transform(field: string, transformer: (value: any) => any): this {
    this.validator.addTransformer(field, transformer);
    return this;
  }

  custom(field: string, validator: (value: any) => void, message?: string, code?: string): this {
    this.validator.addFieldRule(field, {
      name: 'custom',
      validator,
      message,
      code
    });
    return this;
  }

  build(): Validator {
    return this.validator;
  }
}

// Express middleware
export const validateRequest = (schema: Validator) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      if (req.body) {
        const result = schema.validate(req.body);
        if (!result.isValid) {
          return res.status(400).json({
            success: false,
            errors: result.errors
          });
        }
        req.body = result.data;
      }
      next();
    } catch (error) {
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  };
};

// Usage
const userSchema = new SchemaBuilder()
  .string('username', { required: true, minLength: 3, maxLength: 50 })
  .email('email', true)
  .string('password', { required: true, minLength: 8 })
  .custom('password', (value) => {
    const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!strongPasswordRegex.test(value)) {
      throw new Error('Password must contain uppercase, lowercase, digit, and special character');
    }
  }, 'Password must be strong', 'WEAK_PASSWORD')
  .transform('email', (value) => value?.toLowerCase().trim())
  .build();

app.post('/users', validateRequest(userSchema), (req, res) => {
  // req.body is now validated and transformed
  res.json({ success: true, data: req.body });
});
```

### Python
```python
import re
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass

@dataclass
class ValidationError:
    field: str
    message: str
    code: str = "VALIDATION_ERROR"

@dataclass
class ValidationResult:
    is_valid: bool
    errors: List[ValidationError]
    data: Optional[Dict[str, Any]] = None
    
    def add_error(self, field: str, message: str, code: str = "VALIDATION_ERROR"):
        self.errors.append(ValidationError(field, message, code))
        self.is_valid = False

class ValidationRule:
    def __init__(self, name: str, validator: Callable, message: str = None, code: str = None):
        self.name = name
        self.validator = validator
        self.message = message
        self.code = code or "VALIDATION_ERROR"
    
    def validate(self, value: Any, context: Dict[str, Any] = None):
        try:
            result = self.validator(value, context)
            if result is False:
                raise ValidationError(self.field, self.message or "Validation failed", self.code)
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(self.field, self.message or str(e), self.code)

class Validator:
    def __init__(self):
        self.field_rules: Dict[str, List[ValidationRule]] = {}
        self.global_rules: List[ValidationRule] = []
        self.transformers: Dict[str, Callable] = {}
    
    def add_field_rule(self, field: str, rule: ValidationRule):
        if field not in self.field_rules:
            self.field_rules[field] = []
        self.field_rules[field].append(rule)
        rule.field = field
    
    def add_global_rule(self, rule: ValidationRule):
        self.global_rules.append(rule)
    
    def add_transformer(self, field: str, transformer: Callable):
        self.transformers[field] = transformer
    
    def validate(self, data: Dict[str, Any], context: Dict[str, Any] = None) -> ValidationResult:
        result = ValidationResult(True, [])
        transformed_data = {}
        
        # Apply transformers
        for field, transformer in self.transformers.items():
            if field in data:
                try:
                    transformed_data[field] = transformer(data[field])
                except Exception as e:
                    result.add_error(field, str(e), "TRANSFORM_ERROR")
        
        # Validate individual fields
        for field, value in transformed_data.items():
            if field in self.field_rules:
                for rule in self.field_rules[field]:
                    try:
                        rule.validate(value, context)
                    except ValidationError as e:
                        result.add_error(e.field, e.message, e.code)
        
        # Apply global rules
        for rule in self.global_rules:
            try:
                rule.validate(transformed_data, context)
            except ValidationError as e:
                result.add_error(e.field, e.message, e.code)
        
        result.data = transformed_data if result.is_valid else data
        return result

class SchemaBuilder:
    def __init__(self):
        self.validator = Validator()
    
    def string(self, field: str, required: bool = False, min_length: int = None, 
               max_length: int = None, pattern: str = None):
        if required:
            self.validator.add_field_rule(field, ValidationRule(
                "required",
                lambda v, ctx: v is not None and v != "",
                "Field is required",
                "REQUIRED"
            ))
        
        if min_length:
            self.validator.add_field_rule(field, ValidationRule(
                "min_length",
                lambda v, ctx: len(v) >= min_length if v else True,
                f"Must be at least {min_length} characters",
                "MIN_LENGTH"
            ))
        
        if max_length:
            self.validator.add_field_rule(field, ValidationRule(
                "max_length",
                lambda v, ctx: len(v) <= max_length if v else True,
                f"Must be at most {max_length} characters",
                "MAX_LENGTH"
            ))
        
        if pattern:
            self.validator.add_field_rule(field, ValidationRule(
                "pattern",
                lambda v, ctx: bool(re.match(pattern, v)) if v else True,
                "Invalid format",
                "INVALID_FORMAT"
            ))
        
        return self
    
    def email(self, field: str, required: bool = False):
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        
        if required:
            self.validator.add_field_rule(field, ValidationRule(
                "required",
                lambda v, ctx: v is not None and v != "",
                "Email is required",
                "REQUIRED"
            ))
        
        self.validator.add_field_rule(field, ValidationRule(
            "email",
            lambda v, ctx: bool(re.match(email_pattern, v)) if v else True,
            "Invalid email format",
            "INVALID_EMAIL"
        ))
        
        return self
    
    def number(self, field: str, required: bool = False, min_value: float = None, 
               max_value: float = None, integer_only: bool = False):
        if required:
            self.validator.add_field_rule(field, ValidationRule(
                "required",
                lambda v, ctx: v is not None,
                "Field is required",
                "REQUIRED"
            ))
        
        if integer_only:
            self.validator.add_field_rule(field, ValidationRule(
                "integer",
                lambda v, ctx: isinstance(v, int) if v is not None else True,
                "Must be an integer",
                "INTEGER_ONLY"
            ))
        
        if min_value is not None:
            self.validator.add_field_rule(field, ValidationRule(
                "min_value",
                lambda v, ctx: v >= min_value if v is not None else True,
                f"Must be at least {min_value}",
                "MIN_VALUE"
            ))
        
        if max_value is not None:
            self.validator.add_field_rule(field, ValidationRule(
                "max_value",
                lambda v, ctx: v <= max_value if v is not None else True,
                f"Must be at most {max_value}",
                "MAX_VALUE"
            ))
        
        return self
    
    def in_choices(self, field: str, choices: List[Any], required: bool = False):
        if required:
            self.validator.add_field_rule(field, ValidationRule(
                "required",
                lambda v, ctx: v is not None,
                "Field is required",
                "REQUIRED"
            ))
        
        self.validator.add_field_rule(field, ValidationRule(
            "in_choices",
            lambda v, ctx: v in choices if v is not None else True,
            f"Must be one of: {choices}",
            "INVALID_CHOICE"
        ))
        
        return self
    
    def custom(self, field: str, validator: Callable, message: str = None, code: str = None):
        self.validator.add_field_rule(field, ValidationRule(
            "custom", validator, message, code
        ))
        return self
    
    def transform(self, field: str, transformer: Callable):
        self.validator.add_transformer(field, transformer)
        return self
    
    def global_rule(self, validator: Callable, message: str = None, code: str = None):
        rule = ValidationRule("global", validator, message, code)
        self.validator.add_global_rule(rule)
        return self
    
    def build(self) -> Validator:
        return self.validator

# Flask decorator
def validate_json(schema: Validator):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                data = request.get_json()
                if not data:
                    return jsonify({"success": False, "error": "No JSON data provided"}), 400
                
                result = schema.validate(data)
                if not result.is_valid:
                    return jsonify({
                        "success": False,
                        "errors": [{"field": e.field, "message": e.message, "code": e.code} for e in result.errors]
                    }), 400
                
                # Store validated data in request context
                g.validated_data = result.data
                return func(*args, **kwargs)
                
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 400
        return wrapper
    return decorator

# Usage
def create_user_schema():
    return (SchemaBuilder()
        .string("username", required=True, min_length=3, max_length=50)
        .email("email", required=True)
        .string("password", required=True, min_length=8)
        .custom("password", 
                lambda v, ctx: bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', v)),
                "Password must contain uppercase, lowercase, digit, and special character",
                "WEAK_PASSWORD")
        .transform("email", lambda v: v.lower().strip() if v else v)
        .transform("username", lambda v: v.strip().lower() if v else v)
        .global_rule(lambda data, ctx: data.get("password") != data.get("username"),
                    "Password cannot be the same as username",
                    "PASSWORD_SAME_AS_USERNAME")
        .build())

@app.route('/users', methods=['POST'])
@validate_json(create_user_schema())
def create_user():
    user_data = g.validated_data
    # Process validated user data
    return jsonify({"success": True, "data": user_data})
```

### Go
```go
package validation

import (
    "fmt"
    "reflect"
    "regexp"
    "strconv"
    "strings"
)

type ValidationError struct {
    Field   string `json:"field"`
    Message string `json:"message"`
    Code    string `json:"code"`
}

type ValidationResult struct {
    IsValid bool              `json:"is_valid"`
    Errors  []ValidationError `json:"errors"`
    Data    map[string]interface{} `json:"data,omitempty"`
}

func (r *ValidationResult) AddError(field, message, code string) {
    r.Errors = append(r.Errors, ValidationError{
        Field:   field,
        Message: message,
        Code:    code,
    })
    r.IsValid = false
}

type ValidationRule struct {
    Name      string
    Validator func(interface{}, map[string]interface{}) error
    Message   string
    Code      string
}

type Validator struct {
    fieldRules   map[string][]ValidationRule
    globalRules  []ValidationRule
    transformers map[string]func(interface{}) (interface{}, error)
}

func NewValidator() *Validator {
    return &Validator{
        fieldRules:   make(map[string][]ValidationRule),
        globalRules:  make([]ValidationRule, 0),
        transformers: make(map[string]func(interface{}) (interface{}, error)),
    }
}

func (v *Validator) AddFieldRule(field string, rule ValidationRule) {
    if v.fieldRules[field] == nil {
        v.fieldRules[field] = make([]ValidationRule, 0)
    }
    v.fieldRules[field] = append(v.fieldRules[field], rule)
}

func (v *Validator) AddGlobalRule(rule ValidationRule) {
    v.globalRules = append(v.globalRules, rule)
}

func (v *Validator) AddTransformer(field string, transformer func(interface{}) (interface{}, error)) {
    v.transformers[field] = transformer
}

func (v *Validator) Validate(data map[string]interface{}, context map[string]interface{}) *ValidationResult {
    result := &ValidationResult{
        IsValid: true,
        Errors:  make([]ValidationError, 0),
        Data:    make(map[string]interface{}),
    }
    
    // Apply transformers
    for field, value := range data {
        if transformer, exists := v.transformers[field]; exists {
            transformed, err := transformer(value)
            if err != nil {
                result.AddError(field, err.Error(), "TRANSFORM_ERROR")
            } else {
                result.Data[field] = transformed
            }
        } else {
            result.Data[field] = value
        }
    }
    
    // Validate individual fields
    for field, value := range result.Data {
        if rules, exists := v.fieldRules[field]; exists {
            for _, rule := range rules {
                if err := rule.Validator(value, context); err != nil {
                    result.AddError(field, rule.Message, rule.Code)
                }
            }
        }
    }
    
    // Apply global rules
    for _, rule := range v.globalRules {
        if err := rule.Validator(result.Data, context); err != nil {
            result.AddError("_global", rule.Message, rule.Code)
        }
    }
    
    if !result.IsValid {
        result.Data = data // Return original data on validation failure
    }
    
    return result
}

// Built-in validators
func ValidateRequired(value interface{}, context map[string]interface{}) error {
    if value == nil || value == "" {
        return fmt.Errorf("field is required")
    }
    return nil
}

func ValidateEmail(value interface{}, context map[string]interface{}) error {
    if value == nil || value == "" {
        return nil // Skip validation if empty (use with Required rule)
    }
    
    str, ok := value.(string)
    if !ok {
        return fmt.Errorf("must be a string")
    }
    
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    if !emailRegex.MatchString(str) {
        return fmt.Errorf("invalid email format")
    }
    
    return nil
}

func ValidateMinLength(minLength int) func(interface{}, map[string]interface{}) error {
    return func(value interface{}, context map[string]interface{}) error {
        if value == nil || value == "" {
            return nil
        }
        
        str, ok := value.(string)
        if !ok {
            return fmt.Errorf("must be a string")
        }
        
        if len(str) < minLength {
            return fmt.Errorf("must be at least %d characters", minLength)
        }
        
        return nil
    }
}

func ValidateMaxLength(maxLength int) func(interface{}, map[string]interface{}) error {
    return func(value interface{}, context map[string]interface{}) error {
        if value == nil || value == "" {
            return nil
        }
        
        str, ok := value.(string)
        if !ok {
            return fmt.Errorf("must be a string")
        }
        
        if len(str) > maxLength {
            return fmt.Errorf("must be at most %d characters", maxLength)
        }
        
        return nil
    }
}

func ValidateMinValue(minValue float64) func(interface{}, map[string]interface{}) error {
    return func(value interface{}, context map[string]interface{}) error {
        if value == nil {
            return nil
        }
        
        var num float64
        switch v := value.(type) {
        case int:
            num = float64(v)
        case float64:
            num = v
        case string:
            parsed, err := strconv.ParseFloat(v, 64)
            if err != nil {
                return fmt.Errorf("must be a number")
            }
            num = parsed
        default:
            return fmt.Errorf("must be a number")
        }
        
        if num < minValue {
            return fmt.Errorf("must be at least %g", minValue)
        }
        
        return nil
    }
}

// HTTP middleware for Go
func ValidationMiddleware(validator *Validator) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
                var data map[string]interface{}
                if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
                    http.Error(w, "Invalid JSON", http.StatusBadRequest)
                    return
                }
                
                result := validator.Validate(data, nil)
                if !result.IsValid {
                    w.WriteHeader(http.StatusBadRequest)
                    json.NewEncoder(w).Encode(map[string]interface{}{
                        "success": false,
                        "errors":  result.Errors,
                    })
                    return
                }
                
                // Add validated data to context
                ctx := context.WithValue(r.Context(), "validatedData", result.Data)
                r = r.WithContext(ctx)
            }
            
            next.ServeHTTP(w, r)
        })
    }
}

// Usage example
func CreateUserValidator() *Validator {
    validator := NewValidator()
    
    // Username validation
    validator.AddFieldRule("username", ValidationRule{
        Name:      "required",
        Validator: ValidateRequired,
        Message:   "Username is required",
        Code:      "REQUIRED",
    })
    
    validator.AddFieldRule("username", ValidationRule{
        Name:      "min_length",
        Validator: ValidateMinLength(3),
        Message:   "Username must be at least 3 characters",
        Code:      "MIN_LENGTH",
    })
    
    // Email validation
    validator.AddFieldRule("email", ValidationRule{
        Name:      "required",
        Validator: ValidateRequired,
        Message:   "Email is required",
        Code:      "REQUIRED",
    })
    
    validator.AddFieldRule("email", ValidationRule{
        Name:      "email",
        Validator: ValidateEmail,
        Message:   "Invalid email format",
        Code:      "INVALID_EMAIL",
    })
    
    // Add transformers
    validator.AddTransformer("email", func(value interface{}) (interface{}, error) {
        if str, ok := value.(string); ok {
            return strings.ToLower(strings.TrimSpace(str)), nil
        }
        return value, nil
    })
    
    return validator
}
```

## Best Practices

### 1. Validation Design
- Validate on the server side (never trust client validation)
- Use specific error messages for different validation failures
- Implement both field-level and cross-field validation
- Provide clear error codes for programmatic handling

### 2. User Experience
- Validate input in real-time when possible
- Provide helpful error messages with suggestions
- Highlight invalid fields in the UI
- Preserve user input when validation fails

### 3. Security
- Sanitize input to prevent XSS and injection attacks
- Validate file uploads (type, size, content)
- Implement rate limiting for validation requests
- Log validation failures for security monitoring

### 4. Performance
- Use efficient validation algorithms
- Cache validation results when appropriate
- Implement early termination for failed validations
- Consider async validation for complex checks

## Adaptation Checklist

- [ ] Choose validation library for your technology stack
- [ ] Implement field-level validation rules
- [ ] Add cross-field and business rule validation
- [ ] Create data transformation and sanitization
- [ ] Set up validation middleware for your framework
- [ ] Implement comprehensive error handling
- [ ] Add security-focused validation (XSS, injection)
- [ ] Create validation schemas for common data types

## Common Pitfalls

1. **Client-only validation** - Always validate on the server side
2. **Generic error messages** - Provide specific, helpful error messages
3. **Missing sanitization** - Clean input to prevent security issues
4. **Complex validation logic** - Keep validation rules simple and testable
5. **Performance issues** - Optimize validation for high-throughput scenarios

---

*Generic Data Validation Pattern - Adapt to your technology stack*
