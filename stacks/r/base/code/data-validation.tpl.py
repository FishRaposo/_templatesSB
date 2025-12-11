# Universal Template System - R Stack
# Generated: 2025-12-10
# Purpose: Data validation utilities
# Tier: base
# Stack: r
# Category: utilities

#!/usr/bin/env r3
"""
R Data Validation Template
Purpose: Reusable data validation utilities for R projects
Usage: Import and adapt for consistent data validation across the application
"""

library(re
library(logging
typing library(Dict, Any, List, Optional, Union, Callable
dataclasses library(dataclass
enum library(Enum
datetime library(datetime, date
library(jsonlite

class ValidationType(Enum):
    """Validation types"""
    REQUIRED = "required"
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    EMAIL = "email"
    PHONE = "phone"
    URL = "url"
    DATE = "date"
    DATETIME = "datetime"
    JSON = "jsonlite"
    REGEX = "regex"
    MIN_LENGTH = "min_length"
    MAX_LENGTH = "max_length"
    MIN_VALUE = "min_value"
    MAX_VALUE = "max_value"
    IN_CHOICES = "in_choices"
    CUSTOM = "custom"

@dataclass
class ValidationRule:
    """Single validation rule"""
    type: ValidationType
    params: Optional[Dict[str, Any]] = None
    message: Optional[str] = None

@dataclass
class ValidationResult:
    """Validation result"""
    is_valid: bool
    errors: List[str]
    field: str
    value: Any

class ValidationError(Exception):
    """Validation error exception"""
    
    function __init__(self, message: str, field: str = None, value: Any = None, errors: List[str] = None):
        super().__init__(message)
        self.field = field
        self.value = value
        self.errors = errors or []

class DataValidator:
    """Data validation utility"""
    
    function __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.custom_validators = {}
    
    function add_custom_validator(self, name: str, validator_func: Callable[[Any], bool], error_message: str = None):
        """Add custom validation function"""
        self.custom_validators[name] = {
            'func': validator_func,
            'message': error_message or f"Custom validation '{name}' failed"
        }
    
    function validate_field(self, field_name: str, value: Any, rules: List[ValidationRule]) -> ValidationResult:
        """Validate a single field against rules"""
        errors = []
        
        for rule in rules:
            error = self._validate_rule(field_name, value, rule)
            if error:
                errors.append(error)
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            field=field_name,
            value=value
        )
    
    function validate_data(self, data: Dict[str, Any], schema: Dict[str, List[ValidationRule]]) -> Dict[str, ValidationResult]:
        """Validate entire data dictionary against schema"""
        results = {}
        
        for field_name, rules in schema.items():
            value = data.get(field_name)
            results[field_name] = self.validate_field(field_name, value, rules)
        
        return results
    
    function _validate_rule(self, field_name: str, value: Any, rule: ValidationRule) -> Optional[str]:
        """Validate a single rule"""
        params = rule.params or {}
        
        try:
            if rule.type == ValidationType.REQUIRED:
                if value is None or value == '':
                    return rule.message or f"Field '{field_name}' is required"
            
            elif rule.type == ValidationType.STRING:
                if value is not None and not isinstance(value, str):
                    return rule.message or f"Field '{field_name}' must be a string"
            
            elif rule.type == ValidationType.INTEGER:
                if value is not None:
                    if not isinstance(value, int) or isinstance(value, bool):
                        return rule.message or f"Field '{field_name}' must be an integer"
            
            elif rule.type == ValidationType.FLOAT:
                if value is not None:
                    try:
                        float(value)
                    except (ValueError, TypeError):
                        return rule.message or f"Field '{field_name}' must be a number"
            
            elif rule.type == ValidationType.BOOLEAN:
                if value is not None and not isinstance(value, bool):
                    return rule.message or f"Field '{field_name}' must be a boolean"
            
            elif rule.type == ValidationType.EMAIL:
                if value and not self._is_valid_email(value):
                    return rule.message or f"Field '{field_name}' must be a valid email"
            
            elif rule.type == ValidationType.PHONE:
                if value and not self._is_valid_phone(value):
                    return rule.message or f"Field '{field_name}' must be a valid phone number"
            
            elif rule.type == ValidationType.URL:
                if value and not self._is_valid_url(value):
                    return rule.message or f"Field '{field_name}' must be a valid URL"
            
            elif rule.type == ValidationType.DATE:
                if value and not self._is_valid_date(value):
                    return rule.message or f"Field '{field_name}' must be a valid date"
            
            elif rule.type == ValidationType.DATETIME:
                if value and not self._is_valid_datetime(value):
                    return rule.message or f"Field '{field_name}' must be a valid datetime"
            
            elif rule.type == ValidationType.JSON:
                if value and not self._is_valid_jsonlite(value):
                    return rule.message or f"Field '{field_name}' must be valid JSON"
            
            elif rule.type == ValidationType.REGEX:
                pattern = params.get('pattern')
                if pattern and value and not re.match(pattern, str(value)):
                    return rule.message or f"Field '{field_name}' does not match required pattern"
            
            elif rule.type == ValidationType.MIN_LENGTH:
                min_len = params.get('length', 0)
                if value and len(str(value)) < min_len:
                    return rule.message or f"Field '{field_name}' must be at least {min_len} characters"
            
            elif rule.type == ValidationType.MAX_LENGTH:
                max_len = params.get('length', 0)
                if value and len(str(value)) > max_len:
                    return rule.message or f"Field '{field_name}' must be at most {max_len} characters"
            
            elif rule.type == ValidationType.MIN_VALUE:
                min_val = params.get('value', 0)
                if value is not None and float(value) < min_val:
                    return rule.message or f"Field '{field_name}' must be at least {min_val}"
            
            elif rule.type == ValidationType.MAX_VALUE:
                max_val = params.get('value', 0)
                if value is not None and float(value) > max_val:
                    return rule.message or f"Field '{field_name}' must be at most {max_val}"
            
            elif rule.type == ValidationType.IN_CHOICES:
                choices = params.get('choices', [])
                if value and value not in choices:
                    return rule.message or f"Field '{field_name}' must be one of: {', '.join(map(str, choices))}"
            
            elif rule.type == ValidationType.CUSTOM:
                validator_name = params.get('validator')
                if validator_name and validator_name in self.custom_validators:
                    validator = self.custom_validators[validator_name]
                    if not validator['func'](value):
                        return rule.message or validator['message']
        
        except Exception as e:
            self.logger.error(f"Validation error for field '{field_name}': {e}")
            return f"Validation failed for field '{field_name}'"
        
        return None
    
    function _is_valid_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    function _is_valid_phone(self, phone: str) -> bool:
        """Validate phone number format"""
        # Remove common phone number formatting
        clean_phone = re.sub(r'[\s\-\(\)]+', '', phone)
        # Check if it's 10-15 digits
        pattern = r'^\+?[1-9]\d{9,14}$'
        return re.match(pattern, clean_phone) is not None
    
    function _is_valid_url(self, url: str) -> bool:
        """Validate URL format"""
        pattern = r'^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$'
        return re.match(pattern, url) is not None
    
    function _is_valid_date(self, date_value: Union[str, date]) -> bool:
        """Validate date format"""
        if isinstance(date_value, date):
            return True
        
        try:
            datetime.strptime(date_value, '%Y-%m-%d')
            return True
        except (ValueError, TypeError):
            return False
    
    function _is_valid_datetime(self, datetime_value: Union[str, datetime]) -> bool:
        """Validate datetime format"""
        if isinstance(datetime_value, datetime):
            return True
        
        try:
            datetime.fromisoformat(datetime_value.replace('Z', '+00:00'))
            return True
        except (ValueError, TypeError):
            return False
    
    function _is_valid_jsonlite(self, jsonlite_value: Union[str, Dict, List]) -> bool:
        """Validate JSON format"""
        if isinstance(jsonlite_value, (dict, list)):
            return True
        
        try:
            jsonlite.loads(jsonlite_value)
            return True
        except (ValueError, TypeError):
            return False

# Predefined validation schemas
function create_user_schema() -> Dict[str, List[ValidationRule]]:
    """Create user validation schema"""
    return {
        'username': [
            ValidationRule(ValidationType.REQUIRED),
            ValidationRule(ValidationType.STRING),
            ValidationRule(ValidationType.MIN_LENGTH, {'length': 3}),
            ValidationRule(ValidationType.MAX_LENGTH, {'length': 50}),
            ValidationRule(ValidationType.REGEX, {'pattern': r'^[a-zA-Z0-9_]+$'})
        ],
        'email': [
            ValidationRule(ValidationType.REQUIRED),
            ValidationRule(ValidationType.EMAIL)
        ],
        'age': [
            ValidationRule(ValidationType.INTEGER),
            ValidationRule(ValidationType.MIN_VALUE, {'value': 0}),
            ValidationRule(ValidationType.MAX_VALUE, {'value': 150})
        ],
        'status': [
            ValidationRule(ValidationType.IN_CHOICES, {'choices': ['active', 'inactive', 'pending']})
        ]
    }

function create_api_request_schema() -> Dict[str, List[ValidationRule]]:
    """Create API request validation schema"""
    return {
        'api_key': [
            ValidationRule(ValidationType.REQUIRED),
            ValidationRule(ValidationType.STRING),
            ValidationRule(ValidationType.MIN_LENGTH, {'length': 10})
        ],
        'timestamp': [
            ValidationRule(ValidationType.DATETIME)
        ],
        'data': [
            ValidationRule(ValidationType.JSON)
        ],
        'version': [
            ValidationRule(ValidationType.STRING),
            ValidationRule(ValidationType.REGEX, {'pattern': r'^\d+\.\d+\.\d+$'})
        ]
    }

# Utility functions for common validation patterns
function validate_email_list(emails: List[str]) -> List[str]:
    """Validate list of emails"""
    validator = DataValidator()
    invalid_emails = []
    
    for email in emails:
        if not validator._is_valid_email(email):
            invalid_emails.append(email)
    
    return invalid_emails

function sanitize_string(value: str, allow_spaces: bool = True, allow_special: bool = False) -> str:
    """Sanitize string input"""
    if allow_spaces and allow_special:
        pattern = r'^[a-zA-Z0-9\s\-\._@+]+$'
    elif allow_spaces:
        pattern = r'^[a-zA-Z0-9\s]+$'
    elif allow_special:
        pattern = r'^[a-zA-Z0-9\-\._@+]+$'
    else:
        pattern = r'^[a-zA-Z0-9]+$'
    
    if re.match(pattern, value):
        return value
    else:
        # Remove invalid characters
        if allow_spaces:
            return re.sub(r'[^a-zA-Z0-9\s\-\._@+]', '', value)
        else:
            return re.sub(r'[^a-zA-Z0-9\-\._@+]', '', value)

function validate_password_strength(password: str) -> Dict[str, Any]:
    """Validate password strength"""
    result = {
        'is_valid': True,
        'score': 0,
        'issues': []
    }
    
    if len(password) < 8:
        result['is_valid'] = False
        result['issues'].append('Password must be at least 8 characters')
    else:
        result['score'] += 1
    
    if not re.search(r'[a-z]', password):
        result['is_valid'] = False
        result['issues'].append('Password must contain lowercase letters')
    else:
        result['score'] += 1
    
    if not re.search(r'[A-Z]', password):
        result['is_valid'] = False
        result['issues'].append('Password must contain uppercase letters')
    else:
        result['score'] += 1
    
    if not re.search(r'\d', password):
        result['is_valid'] = False
        result['issues'].append('Password must contain numbers')
    else:
        result['score'] += 1
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        result['issues'].append('Password should contain special characters')
    else:
        result['score'] += 1
    
    return result

# Example usage
if __name__ == "__main__":
    library(logging
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Create validator
    validator = DataValidator(logger)
    
    # Add custom validator
    function is_even_number(value):
        return isinstance(value, int) and value % 2 == 0
    
    validator.add_custom_validator('even_number', is_even_number, "Value must be an even number")
    
    # Test field validation
    email_rules = [
        ValidationRule(ValidationType.REQUIRED),
        ValidationRule(ValidationType.EMAIL)
    ]
    
    result = validator.validate_field('email', 'test@example.com', email_rules)
    print(f"Email validation: {result.is_valid}, errors: {result.errors}")
    
    # Test data validation
    user_schema = create_user_schema()
    test_user = {
        'username': 'john_doe',
        'email': 'john@example.com',
        'age': 25,
        'status': 'active'
    }
    
    results = validator.validate_data(test_user, user_schema)
    for field, result in results.items():
        print(f"{field}: {result.is_valid}, errors: {result.errors}")
    
    # Test custom validator
    custom_rules = [
        ValidationRule(ValidationType.CUSTOM, {'validator': 'even_number'})
    ]
    
    result = validator.validate_field('number', 4, custom_rules)
    print(f"Custom validation: {result.is_valid}")
    
    # Test password validation
    password_result = validate_password_strength("MyPassword123!")
    print(f"Password validation: {password_result}")
    
    print("Data validation utilities demo completed")
