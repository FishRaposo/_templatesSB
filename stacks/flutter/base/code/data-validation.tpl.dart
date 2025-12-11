///
/// File: data-validation.tpl.dart
/// Purpose: Template for unknown implementation
/// Generated for: {{PROJECT_NAME}}
///

/// Template: data-validation.tpl.dart
/// Purpose: data-validation template
/// Stack: flutter
/// Tier: base

# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: Data validation utilities
# Tier: base
# Stack: flutter
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: data-validation.tpl.dart
// PURPOSE: Comprehensive data validation utilities for Flutter projects
// USAGE: Import and adapt for consistent data validation across the application
// DEPENDENCIES: dart:convert, flutter/foundation.dart for validation and error handling
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * Flutter Data Validation Template
 * Purpose: Reusable data validation utilities for Flutter projects
 * Usage: Import and adapt for consistent data validation across the application
 */

import 'dart:convert';
import 'package:flutter/foundation.dart';

/// Validation types
enum ValidationType {
  required,
  string,
  email,
  phone,
  url,
  number,
  integer,
  min,
  max,
  minLength,
  maxLength,
  pattern,
  custom,
  choices,
  date,
  datetime,
}

/// Validation rule class
class ValidationRule {
  final ValidationType type;
  final Map<String, dynamic> params;
  final String? errorMessage;
  final bool isRequired;

  const ValidationRule({
    required this.type,
    this.params = const {},
    this.errorMessage,
    this.isRequired = false,
  });

  /// Create required rule
  factory ValidationRule.required([String? message]) {
    return ValidationRule(
      type: ValidationType.required,
      errorMessage: message ?? 'This field is required',
      isRequired: true,
    );
  }

  /// Create email rule
  factory ValidationRule.email([String? message]) {
    return ValidationRule(
      type: ValidationType.email,
      errorMessage: message ?? 'Please enter a valid email address',
    );
  }

  /// Create phone rule
  factory ValidationRule.phone([String? message]) {
    return ValidationRule(
      type: ValidationType.phone,
      errorMessage: message ?? 'Please enter a valid phone number',
    );
  }

  /// Create URL rule
  factory ValidationRule.url([String? message]) {
    return ValidationRule(
      type: ValidationType.url,
      errorMessage: message ?? 'Please enter a valid URL',
    );
  }

  /// Create number rule
  factory ValidationRule.number([String? message]) {
    return ValidationRule(
      type: ValidationType.number,
      errorMessage: message ?? 'Please enter a valid number',
    );
  }

  /// Create integer rule
  factory ValidationRule.integer([String? message]) {
    return ValidationRule(
      type: ValidationType.integer,
      errorMessage: message ?? 'Please enter a valid integer',
    );
  }

  /// Create minimum value rule
  factory ValidationRule.min(dynamic value, [String? message]) {
    return ValidationRule(
      type: ValidationType.min,
      params: {'value': value},
      errorMessage: message ?? 'Value must be at least $value',
    );
  }

  /// Create maximum value rule
  factory ValidationRule.max(dynamic value, [String? message]) {
    return ValidationRule(
      type: ValidationType.max,
      params: {'value': value},
      errorMessage: message ?? 'Value must be at most $value',
    );
  }

  /// Create minimum length rule
  factory ValidationRule.minLength(int length, [String? message]) {
    return ValidationRule(
      type: ValidationType.minLength,
      params: {'length': length},
      errorMessage: message ?? 'Must be at least $length characters',
    );
  }

  /// Create maximum length rule
  factory ValidationRule.maxLength(int length, [String? message]) {
    return ValidationRule(
      type: ValidationType.maxLength,
      params: {'length': length},
      errorMessage: message ?? 'Must be at most $length characters',
    );
  }

  /// Create pattern rule
  factory ValidationRule.pattern(String pattern, [String? message]) {
    return ValidationRule(
      type: ValidationType.pattern,
      params: {'pattern': pattern},
      errorMessage: message ?? 'Invalid format',
    );
  }

  /// Create choices rule
  factory ValidationRule.choices(List<dynamic> choices, [String? message]) {
    return ValidationRule(
      type: ValidationType.choices,
      params: {'choices': choices},
      errorMessage: message ?? 'Must be one of: ${choices.join(', ')}',
    );
  }

  /// Create custom rule
  factory ValidationRule.custom(
    bool Function(dynamic) validator,
    String message,
  ) {
    return ValidationRule(
      type: ValidationType.custom,
      params: {'validator': validator},
      errorMessage: message,
    );
  }
}

/// Validation result class
class ValidationResult {
  final String field;
  final dynamic value;
  final bool isValid;
  final List<String> errors;

  const ValidationResult({
    required this.field,
    required this.value,
    required this.isValid,
    required this.errors,
  });

  /// Create valid result
  factory ValidationResult.valid(String field, dynamic value) {
    return ValidationResult(
      field: field,
      value: value,
      isValid: true,
      errors: [],
    );
  }

  /// Create invalid result
  factory ValidationResult.invalid(String field, dynamic value, List<String> errors) {
    return ValidationResult(
      field: field,
      value: value,
      isValid: false,
      errors: errors,
    );
  }

  /// Get first error message
  String? get firstError => errors.isNotEmpty ? errors.first : null;

  @override
  String toString() {
    return 'ValidationResult(field: $field, isValid: $isValid, errors: $errors)';
  }
}

/// Form validation result
class FormValidationResult {
  final Map<String, ValidationResult> fieldResults;
  final bool isValid;

  const FormValidationResult({
    required this.fieldResults,
    required this.isValid,
  });

  /// Get all errors
  List<String> get allErrors {
    return fieldResults.values
        .expand((result) => result.errors)
        .toList();
  }

  /// Get errors for specific field
  List<String> getFieldErrors(String fieldName) {
    return fieldResults[fieldName]?.errors ?? [];
  }

  /// Check if field is valid
  bool isFieldValid(String fieldName) {
    return fieldResults[fieldName]?.isValid ?? true;
  }

  @override
  String toString() {
    return 'FormValidationResult(isValid: $isValid, fieldCount: ${fieldResults.length})';
  }
}

/// Validator class
class Validator {
  final Map<String, List<ValidationRule>> _rules;
  final Map<String, bool Function(dynamic)> _customValidators = {};

  Validator([Map<String, List<ValidationRule>>? rules])
      : _rules = rules ?? {};

  /// Add validation rule for field
  void addRule(String fieldName, ValidationRule rule) {
    _rules.putIfAbsent(fieldName, () => []).add(rule);
  }

  /// Add multiple validation rules for field
  void addRules(String fieldName, List<ValidationRule> rules) {
    _rules.putIfAbsent(fieldName, () => []).addAll(rules);
  }

  /// Add custom validator
  void addCustomValidator(String name, bool Function(dynamic) validator) {
    _customValidators[name] = validator;
  }

  /// Validate single field
  ValidationResult validateField(String fieldName, dynamic value) {
    final rules = _rules[fieldName] ?? [];
    final errors = <String>[];

    for (final rule in rules) {
      final error = _validateRule(rule, value);
      if (error != null) {
        errors.add(error);
      }
    }

    return errors.isEmpty
        ? ValidationResult.valid(fieldName, value)
        : ValidationResult.invalid(fieldName, value, errors);
  }

  /// Validate entire form
  FormValidationResult validate(Map<String, dynamic> data) {
    final fieldResults = <String, ValidationResult>{};
    bool isValid = true;

    for (final fieldName in _rules.keys) {
      final value = data[fieldName];
      final result = validateField(fieldName, value);
      fieldResults[fieldName] = result;
      
      if (!result.isValid) {
        isValid = false;
      }
    }

    return FormValidationResult(
      fieldResults: fieldResults,
      isValid: isValid,
    );
  }

  /// Validate single rule
  String? _validateRule(ValidationRule rule, dynamic value) {
    try {
      switch (rule.type) {
        case ValidationType.required:
          if (value == null || value.toString().trim().isEmpty) {
            return rule.errorMessage;
          }
          break;

        case ValidationType.string:
          if (value != null && value is! String) {
            return rule.errorMessage ?? 'Must be a string';
          }
          break;

        case ValidationType.email:
          if (value != null && value.toString().isNotEmpty) {
            if (!_isValidEmail(value.toString())) {
              return rule.errorMessage;
            }
          }
          break;

        case ValidationType.phone:
          if (value != null && value.toString().isNotEmpty) {
            if (!_isValidPhone(value.toString())) {
              return rule.errorMessage;
            }
          }
          break;

        case ValidationType.url:
          if (value != null && value.toString().isNotEmpty) {
            if (!_isValidUrl(value.toString())) {
              return rule.errorMessage;
            }
          }
          break;

        case ValidationType.number:
          if (value != null && value.toString().isNotEmpty) {
            if (!_isValidNumber(value.toString())) {
              return rule.errorMessage;
            }
          }
          break;

        case ValidationType.integer:
          if (value != null && value.toString().isNotEmpty) {
            if (!_isValidInteger(value.toString())) {
              return rule.errorMessage;
            }
          }
          break;

        case ValidationType.min:
          if (value != null && value.toString().isNotEmpty) {
            final numValue = num.tryParse(value.toString());
            if (numValue == null || numValue < (rule.params['value'] as num)) {
              return rule.errorMessage;
            }
          }
          break;

        case ValidationType.max:
          if (value != null && value.toString().isNotEmpty) {
            final numValue = num.tryParse(value.toString());
            if (numValue == null || numValue > (rule.params['value'] as num)) {
              return rule.errorMessage;
            }
          }
          break;

        case ValidationType.minLength:
          if (value != null) {
            final length = value.toString().length;
            if (length < (rule.params['length'] as int)) {
              return rule.errorMessage;
            }
          }
          break;

        case ValidationType.maxLength:
          if (value != null) {
            final length = value.toString().length;
            if (length > (rule.params['length'] as int)) {
              return rule.errorMessage;
            }
          }
          break;

        case ValidationType.pattern:
          if (value != null && value.toString().isNotEmpty) {
            final pattern = RegExp(rule.params['pattern'] as String);
            if (!pattern.hasMatch(value.toString())) {
              return rule.errorMessage;
            }
          }
          break;

        case ValidationType.choices:
          if (value != null) {
            final choices = rule.params['choices'] as List;
            if (!choices.contains(value)) {
              return rule.errorMessage;
            }
          }
          break;

        case ValidationType.custom:
          final validator = rule.params['validator'] as bool Function(dynamic);
          if (!validator(value)) {
            return rule.errorMessage;
          }
          break;

        case ValidationType.date:
          if (value != null && value.toString().isNotEmpty) {
            if (!_isValidDate(value.toString())) {
              return rule.errorMessage ?? 'Invalid date format';
            }
          }
          break;

        case ValidationType.datetime:
          if (value != null && value.toString().isNotEmpty) {
            if (!_isValidDateTime(value.toString())) {
              return rule.errorMessage ?? 'Invalid datetime format';
            }
          }
          break;
      }
    } catch (e) {
      if (kDebugMode) {
        print('Validation error: $e');
      }
      return 'Validation failed';
    }

    return null;
  }

  /// Email validation
  bool _isValidEmail(String email) {
    final emailRegex = RegExp(
      r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    );
    return emailRegex.hasMatch(email);
  }

  /// Phone validation
  bool _isValidPhone(String phone) {
    final cleanPhone = phone.replaceAll(RegExp(r'[\s\-\(\)]+'), '');
    final phoneRegex = RegExp(r'^\+?[1-9]\d{9,14}$');
    return phoneRegex.hasMatch(cleanPhone);
  }

  /// URL validation
  bool _isValidUrl(String url) {
    try {
      final uri = Uri.parse(url);
      return uri.hasScheme && (uri.scheme == 'http' || uri.scheme == 'https');
    } catch (e) {
      return false;
    }
  }

  /// Number validation
  bool _isValidNumber(String value) {
    return num.tryParse(value) != null;
  }

  /// Integer validation
  bool _isValidInteger(String value) {
    final number = num.tryParse(value);
    return number != null && number % 1 == 0;
  }

  /// Date validation (YYYY-MM-DD)
  bool _isValidDate(String date) {
    final dateRegex = RegExp(r'^\d{4}-\d{2}-\d{2}$');
    if (!dateRegex.hasMatch(date)) return false;
    
    try {
      DateTime.parse(date);
      return true;
    } catch (e) {
      return false;
    }
  }

  /// DateTime validation (ISO 8601)
  bool _isValidDateTime(String dateTime) {
    try {
      DateTime.parse(dateTime);
      return true;
    } catch (e) {
      return false;
    }
  }
}

/// Validation rule builder
class ValidationRuleBuilder {
  final List<ValidationRule> _rules = [];

  /// Add required rule
  ValidationRuleBuilder required([String? message]) {
    _rules.add(ValidationRule.required(message));
    return this;
  }

  /// Add email rule
  ValidationRuleBuilder email([String? message]) {
    _rules.add(ValidationRule.email(message));
    return this;
  }

  /// Add phone rule
  ValidationRuleBuilder phone([String? message]) {
    _rules.add(ValidationRule.phone(message));
    return this;
  }

  /// Add URL rule
  ValidationRuleBuilder url([String? message]) {
    _rules.add(ValidationRule.url(message));
    return this;
  }

  /// Add number rule
  ValidationRuleBuilder number([String? message]) {
    _rules.add(ValidationRule.number(message));
    return this;
  }

  /// Add integer rule
  ValidationRuleBuilder integer([String? message]) {
    _rules.add(ValidationRule.integer(message));
    return this;
  }

  /// Add minimum value rule
  ValidationRuleBuilder min(dynamic value, [String? message]) {
    _rules.add(ValidationRule.min(value, message));
    return this;
  }

  /// Add maximum value rule
  ValidationRuleBuilder max(dynamic value, [String? message]) {
    _rules.add(ValidationRule.max(value, message));
    return this;
  }

  /// Add minimum length rule
  ValidationRuleBuilder minLength(int length, [String? message]) {
    _rules.add(ValidationRule.minLength(length, message));
    return this;
  }

  /// Add maximum length rule
  ValidationRuleBuilder maxLength(int length, [String? message]) {
    _rules.add(ValidationRule.maxLength(length, message));
    return this;
  }

  /// Add pattern rule
  ValidationRuleBuilder pattern(String pattern, [String? message]) {
    _rules.add(ValidationRule.pattern(pattern, message));
    return this;
  }

  /// Add choices rule
  ValidationRuleBuilder choices(List<dynamic> choices, [String? message]) {
    _rules.add(ValidationRule.choices(choices, message));
    return this;
  }

  /// Add custom rule
  ValidationRuleBuilder custom(bool Function(dynamic) validator, String message) {
    _rules.add(ValidationRule.custom(validator, message));
    return this;
  }

  /// Build rules list
  List<ValidationRule> build() {
    return List.unmodifiable(_rules);
  }
}

/// Form validator with common schemas
class FormValidator {
  static Validator createEmailValidator() {
    return Validator()
      ..addRule('email', ValidationRule.required())
      ..addRule('email', ValidationRule.email());
  }

  static Validator createPasswordValidator() {
    return Validator()
      ..addRule('password', ValidationRule.required())
      ..addRule('password', ValidationRule.minLength(8))
      ..addRule('password', ValidationRule.pattern(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)',
        'Password must contain at least one lowercase letter, one uppercase letter, and one number',
      ));
  }

  static Validator createUserValidator() {
    return Validator()
      ..addRule('username', ValidationRule.required())
      ..addRule('username', ValidationRule.minLength(3))
      ..addRule('username', ValidationRule.maxLength(50))
      ..addRule('username', ValidationRule.pattern(
        r'^[a-zA-Z0-9_]+$',
        'Username can only contain letters, numbers, and underscores',
      ))
      ..addRule('email', ValidationRule.required())
      ..addRule('email', ValidationRule.email())
      ..addRule('age', ValidationRule.min(0))
      ..addRule('age', ValidationRule.max(150));
  }

  static Validator createContactValidator() {
    return Validator()
      ..addRule('name', ValidationRule.required())
      ..addRule('name', ValidationRule.minLength(2))
      ..addRule('email', ValidationRule.required())
      ..addRule('email', ValidationRule.email())
      ..addRule('phone', ValidationRule.phone())
      ..addRule('message', ValidationRule.required())
      ..addRule('message', ValidationRule.minLength(10))
      ..addRule('message', ValidationRule.maxLength(1000));
  }
}

/// Validation utilities
class ValidationUtils {
  /// Validate email list
  static List<String> validateEmailList(List<String> emails) {
    final validator = Validator();
    final invalidEmails = <String>[];

    for (final email in emails) {
      if (!validator._isValidEmail(email)) {
        invalidEmails.add(email);
      }
    }

    return invalidEmails;
  }

  /// Sanitize string input
  static String sanitizeString(String value, {
    bool allowSpaces = true,
    bool allowSpecial = false,
    int? maxLength,
  }) {
    String pattern;
    if (allowSpaces && allowSpecial) {
      pattern = r'[^a-zA-Z0-9\s\-\._@+]';
    } else if (allowSpaces) {
      pattern = r'[^a-zA-Z0-9\s]';
    } else if (allowSpecial) {
      pattern = r'[^a-zA-Z0-9\-\._@+]';
    } else {
      pattern = r'[^a-zA-Z0-9]';
    }

    String sanitized = value.replaceAll(RegExp(pattern), '');
    
    if (maxLength != null && sanitized.length > maxLength) {
      sanitized = sanitized.substring(0, maxLength);
    }

    return sanitized;
  }

  /// Validate password strength
  static PasswordStrengthResult validatePasswordStrength(String password) {
    final result = PasswordStrengthResult();

    if (password.length < 8) {
      result.isValid = false;
      result.issues.add('Password must be at least 8 characters');
    } else {
      result.score += 1;
    }

    if (!RegExp(r'[a-z]').hasMatch(password)) {
      result.isValid = false;
      result.issues.add('Password must contain lowercase letters');
    } else {
      result.score += 1;
    }

    if (!RegExp(r'[A-Z]').hasMatch(password)) {
      result.isValid = false;
      result.issues.add('Password must contain uppercase letters');
    } else {
      result.score += 1;
    }

    if (!RegExp(r'\d').hasMatch(password)) {
      result.isValid = false;
      result.issues.add('Password must contain numbers');
    } else {
      result.score += 1;
    }

    if (!RegExp(r'[!@#$%^&*(),.?":{}|<>]').hasMatch(password)) {
      result.suggestions.add('Consider adding special characters for stronger security');
    } else {
      result.score += 1;
    }

    // Check for common patterns
    if (RegExp(r'^(.)\1+$').hasMatch(password)) {
      result.issues.add('Password cannot be repeated characters');
      result.isValid = false;
    }

    if (RegExp(r'password|123456|qwerty', caseSensitive: false).hasMatch(password)) {
      result.issues.add('Password is too common');
      result.isValid = false;
    }

    return result;
  }

  /// Generate validation schema from data model
  static Map<String, List<ValidationRule>> generateSchemaFromModel(
    Map<String, dynamic> model,
    Map<String, dynamic> fieldConfigs,
  ) {
    final schema = <String, List<ValidationRule>>{};

    for (final fieldName in fieldConfigs.keys) {
      final config = fieldConfigs[fieldName] as Map<String, dynamic>;
      final rules = <ValidationRule>[];

      // Add required rule if specified
      if (config['required'] == true) {
        rules.add(ValidationRule.required());
      }

      // Add type-specific rules
      final type = config['type'] as String?;
      switch (type) {
        case 'email':
          rules.add(ValidationRule.email());
          break;
        case 'phone':
          rules.add(ValidationRule.phone());
          break;
        case 'url':
          rules.add(ValidationRule.url());
          break;
        case 'number':
          rules.add(ValidationRule.number());
          break;
        case 'integer':
          rules.add(ValidationRule.integer());
          break;
      }

      // Add length constraints
      final minLength = config['minLength'] as int?;
      if (minLength != null) {
        rules.add(ValidationRule.minLength(minLength));
      }

      final maxLength = config['maxLength'] as int?;
      if (maxLength != null) {
        rules.add(ValidationRule.maxLength(maxLength));
      }

      // Add value constraints
      final min = config['min'];
      if (min != null) {
        rules.add(ValidationRule.min(min));
      }

      final max = config['max'];
      if (max != null) {
        rules.add(ValidationRule.max(max));
      }

      // Add pattern
      final pattern = config['pattern'] as String?;
      if (pattern != null) {
        rules.add(ValidationRule.pattern(pattern));
      }

      // Add choices
      final choices = config['choices'] as List?;
      if (choices != null) {
        rules.add(ValidationRule.choices(choices));
      }

      if (rules.isNotEmpty) {
        schema[fieldName] = rules;
      }
    }

    return schema;
  }
}

/// Password strength result
class PasswordStrengthResult {
  bool isValid = true;
  int score = 0;
  final List<String> issues = [];
  final List<String> suggestions = [];

  String get strength {
    if (score <= 2) return 'Weak';
    if (score <= 3) return 'Medium';
    if (score <= 4) return 'Strong';
    return 'Very Strong';
  }
}

/// Example usage
void main() {
  // Create validator
  final validator = Validator()
    ..addRule('email', ValidationRule.required())
    ..addRule('email', ValidationRule.email())
    ..addRule('password', ValidationRule.required())
    ..addRule('password', ValidationRule.minLength(8))
    ..addRule('age', ValidationRule.min(18))
    ..addRule('age', ValidationRule.max(100));

  // Test field validation
  final emailResult = validator.validateField('email', 'test@example.com');
  print('Email validation: ${emailResult.isValid}');

  // Test form validation
  final formData = {
    'email': 'invalid-email',
    'password': 'weak',
    'age': 25,
  };

  final formResult = validator.validate(formData);
  print('Form validation: ${formResult.isValid}');
  print('Errors: ${formResult.allErrors}');

  // Test password strength
  final passwordStrength = ValidationUtils.validatePasswordStrength('MyPassword123!');
  print('Password strength: ${passwordStrength.strength}');
  print('Password valid: ${passwordStrength.isValid}');

  // Test sanitization
  final sanitized = ValidationUtils.sanitizeString(
    'Hello World! @#$',
    allowSpaces: true,
    allowSpecial: true,
  );
  print('Sanitized string: $sanitized');
}

export {
  // Enums
  ValidationType,

  // Classes
  ValidationRule,
  ValidationResult,
  FormValidationResult,
  Validator,
  ValidationRuleBuilder,
  FormValidator,
  ValidationUtils,
  PasswordStrengthResult,
};
