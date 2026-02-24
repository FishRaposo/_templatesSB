name: [[.ProjectName]]
description: [[.ProjectDescription]]
version: 1.0.0+1

environment:
  sdk: '>=3.0.0 <4.0.0'
  flutter: ">=3.10.0"

dependencies:
  flutter:
    sdk: flutter
  
  # Core dependencies for foundational templates
  http: ^1.1.0              # Used in http-client.tpl.dart
  path_provider: ^2.1.0     # Used in config-management.tpl.dart and logging-utilities.tpl.dart
  shared_preferences: ^2.2.0 # Used in config-management.tpl.dart for persistence
  meta: ^1.9.0              # Used in error-handling.tpl.dart for annotations

dev_dependencies:
  flutter_test:
    sdk: flutter
  
  # Testing dependencies for testing-utilities.tpl.dart
  test: ^1.24.0             # Core testing framework
  mockito: ^5.4.0           # Mocking utilities
  build_runner: ^2.4.0      # Code generation for mocks
  golden_toolkit: ^0.15.0   # Golden testing utilities
  integration_test:
    sdk: flutter

  # Development tools (optional)
  flutter_lints: ^3.0.0     # Linting rules
  very_good_analysis: ^5.1.0 # Additional linting rules

flutter:
  uses-material-design: true

# Template Dependency Notes:
# - http: HTTP client library used in http-client.tpl.dart
# - path_provider: File system access for config and logging templates
# - shared_preferences: Simple key-value storage for config-management.tpl.dart
# - meta: Annotations used in error-handling.tpl.dart
# - flutter_test: Core testing framework for testing-utilities.tpl.dart
# - mockito: Mock objects for unit testing in testing-utilities.tpl.dart
# - golden_toolkit: Golden (snapshot) testing utilities
# - integration_test: Integration testing framework
#
# Note: All Flutter foundational templates are designed to work primarily with
# Flutter's built-in capabilities. External dependencies provide enhanced
# functionality but can be replaced with standard library alternatives.
