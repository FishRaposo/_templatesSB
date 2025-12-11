# Flutter Stack Dependencies Template
# Complete package management and tooling configurations for Flutter projects

# ====================
# FLUTTER SDK REQUIREMENTS
# ====================

flutter: ">=3.13.0 <4.0.0"
dart: ">=3.1.0 <4.0.0"

# Environment Configuration
environment:
  sdk: ">=3.1.0 <4.0.0"
  flutter: ">=3.13.0"

# ====================
# CORE FLUTTER DEPENDENCIES
# ====================

dependencies:
  # Flutter SDK
  flutter:
    sdk: flutter
  flutter_localizations:
    sdk: flutter
  
  # State Management
  flutter_bloc: ^8.1.4
  bloc: ^8.1.2
  provider: ^6.1.1
  get: ^4.6.6
  riverpod: ^2.4.6
  
  # Navigation
  go_router: ^12.1.1
  auto_route: ^7.8.4
  
  # Dependency Injection
  get_it: ^7.6.4
  injectable: ^2.3.5
  
  # HTTP & API
  dio: ^5.3.3
  http: ^1.1.2
  retrofit: ^4.0.3
  
  # JSON Serialization
  json_annotation: ^4.8.1
  freezed_annotation: ^2.4.1
  
  # Local Storage
  shared_preferences: ^2.2.2
  flutter_secure_storage: ^9.0.0
  hive: ^2.2.3
  hive_flutter: ^1.1.0
  
  # Database
  sqflite: ^2.3.0
  drift: ^2.14.1
  
  # Remote Configuration
  firebase_core: ^2.24.2
  firebase_remote_config: ^4.3.8
  
  # Analytics & Crashlytics
  firebase_analytics: ^10.7.4
  firebase_crashlytics: ^3.4.8
  
  # Push Notifications
  firebase_messaging: ^14.7.4
  flutter_local_notifications: ^16.2.0
  
  # Deep Linking
  uni_links: ^0.5.1
  app_links: ^3.5.0
  
  # Social Authentication
  google_sign_in: ^6.2.1
  sign_in_with_apple: ^5.0.0
  flutter_facebook_auth: ^6.0.3
  
  # Maps & Location
  google_maps_flutter: ^2.5.3
  flutter_map: ^6.0.2
  geolocator: ^10.1.0
  geocoding: ^2.1.1
  
  # Camera & Media
  camera: ^0.10.5+9
  image_picker: ^1.0.7
  video_player: ^2.8.2
  chewie: ^1.7.4
  
  # File Management
  file_picker: ^6.1.1
  path_provider: ^2.1.2
  
  # UI Components
  fl_chart: ^0.66.2
  syncfusion_flutter_charts: ^24.2.7
  table_calendar: ^3.0.9
  flutter_staggered_grid_view: ^0.7.0
  
  # Animation
  lottie: ^2.7.0
  flutter_animate: ^4.3.0
  
  # Internationalization
  intl: ^0.18.1
  
  # Logging
  logger: ^2.0.2
  talker: ^4.0.4
  talker_dio_logger: ^4.0.4
  
  # Error Handling
  sentry_flutter: ^7.14.0
  catcher: ^0.8.0
  
  # Utilities
  equatable: ^2.0.5
  meta: ^1.10.0
  collection: ^1.18.0
  async: ^2.11.0
  path: ^1.8.3
  mime: ^1.0.4
  
  # Platform Specific
  universal_platform: ^1.0.0+1
  
  # Web Support (if targeting web)
  flutter_web_plugins:
    sdk: flutter
  
  # Desktop Support (if targeting desktop)
  # window_manager: ^0.3.7
  # system_tray: ^2.0.3

# ====================
# DEV DEPENDENCIES
# ====================

dev_dependencies:
  # Testing
  flutter_test:
    sdk: flutter
  bloc_test: ^9.1.5
  mockito: ^5.4.4
  build_runner: ^2.4.7
  
  # Code Generation
  json_serializable: ^6.7.1
  freezed: ^2.4.6
  injectable_generator: ^2.4.1
  
  # Linting
  flutter_lints: ^3.0.1
  very_good_analysis: ^5.1.0
  dart_code_metrics: ^5.7.6
  
  # Documentation
  dartdoc: ^6.3.0
  
  # Icons Generation
  flutter_launcher_icons: ^0.13.1
  
  # Native Splash Screen
  flutter_native_splash: ^2.3.7
  
  # App Version Management
  cider: ^0.2.4
  
  # Golden Tests
  alchemist: ^0.7.0

# ====================
# FLUTTER CONFIGURATION
# ====================

flutter:
  uses-material-design: true
  generate: true
  
  # Assets
  assets:
    - assets/images/
    - assets/icons/
    - assets/lottie/
    - assets/translations/
  
  # Fonts
  fonts:
    - family: CustomIcon
      fonts:
        - asset: fonts/CustomIcon.ttf
    - family: Roboto
      fonts:
        - asset: fonts/Roboto-Regular.ttf
          weight: 400
        - asset: fonts/Roboto-Medium.ttf
          weight: 500
        - asset: fonts/Roboto-Bold.ttf
          weight: 700
  
  # Translations
  flutter_intl:
    enabled: true
    class_name: S
    main_locale: en
    arb_dir: lib/l10n/arb
    output_dir: lib/l10n/generated

# ====================
# BUILD CONFIGURATION
# ====================

# Create analysis_options.yaml with:
/*
analyzer:
  exclude:
    - lib/**/*.g.dart
    - lib/**/*.freezed.dart
    - lib/generated/**
  errors:
    invalid_annotation_target: ignore
  strong-mode:
    implicit-casts: false
    implicit-dynamic: false

linter:
  rules:
    - always_declare_return_types
    - always_require_non_null_named_parameters
    - annotate_overrides
    - avoid_empty_else
    - avoid_init_to_null
    - avoid_null_checks_in_equality_operators
    - avoid_relative_lib_imports
    - avoid_return_types_on_setters
    - avoid_shadowing_type_parameters
    - avoid_types_as_parameter_names
    - await_only_futures
    - camel_case_extensions
    - camel_case_types
    - cancel_subscriptions
    - cascade_invocations
    - comment_references
    - constant_identifier_names
    - control_flow_in_finally
    - curly_braces_in_flow_control_structures
    - directives_ordering
    - empty_catches
    - empty_constructor_bodies
    - empty_statements
    - file_names
    - hash_and_equals
    - implementation_imports
    - invariant_booleans
    - iterable_contains_unrelated_type
    - library_names
    - library_prefixes
    - list_remove_unrelated_type
    - no_adjacent_strings_in_list
    - no_duplicate_case_values
    - non_constant_identifier_names
    - null_closures
    - only_throw_errors
    - overridden_fields
    - package_api_docs
    - package_names
    - package_prefixed_library_names
    - prefer_adjacent_string_concatenation
    - prefer_collection_literals
    - prefer_conditional_assignment
    - prefer_contains
    - prefer_equal_for_default_values
    - prefer_final_fields
    - prefer_for_elements_to_map_fromIterable
    - prefer_generic_function_type_aliases
    - prefer_if_elements_to_conditional_expressions
    - prefer_if_null_operators
    - prefer_inlined_adds
    - prefer_is_empty
    - prefer_is_not_empty
    - prefer_iterable_whereType
    - prefer_mixin
    - prefer_null_aware_operators
    - prefer_single_quotes
    - prefer_spread_collections
    - prefer_void_to_null
    - recursive_getters
    - slash_for_doc_comments
    - sort_pub_dependencies
    - test_types_in_equals
    - throw_in_finally
    - type_init_formals
    - unnecessary_brace_in_string_interps
    - unnecessary_const
    - unnecessary_getters_setters
    - unnecessary_lambdas
    - unnecessary_new
    - unnecessary_null_aware_assignments
    - unnecessary_null_in_if_null_operators
    - unnecessary_nullable_for_final_variable_declarations
    - unnecessary_overrides
    - unnecessary_parenthesis
    - unnecessary_statements
    - unnecessary_this
    - unrelated_type_equality_checks
    - use_function_type_syntax_for_parameters
    - use_rethrow_when_possible
    - use_string_buffers
    - use_to_and_as_if_applicable
    - valid_regexps
    - void_checks
*/

// ====================
# FLAVOR CONFIGURATION
// ====================

# For multiple flavors (dev, staging, prod)
# Create flavors.dart and configure in main_*.dart

// ====================
# FASTLANE CONFIGURATION (CI/CD)
// ====================

# fastlane/Fastfile configuration for automated builds

# ====================
# PUBLISHING CONFIGURATION
// ====================

# Android Keystore Configuration
# Store in: android/key.properties
/*
storePassword=STORE_PASSWORD
keyPassword=KEY_PASSWORD
keyAlias=KEY_ALIAS
storeFile=KEYSTORE_FILE_PATH
*/

# iOS Code Signing
# Configure in Xcode or use fastlane match

// ====================
# DEVELOPMENT WORKFLOW
// ====================

/*
# Initial Setup:
flutter pub get
flutter packages pub run build_runner build --delete-conflicting-outputs

# Generate code (after model changes):
flutter packages pub run build_runner build --delete-conflicting-outputs
flutter packages pub run build_runner watch --delete-conflicting-outputs

# Run app:
flutter run

# Run tests:
flutter test
flutter test --coverage

# Generate coverage report:
genhtml coverage/lcov.info -o coverage/html
open coverage/html/index.html

# Build for different platforms:
flutter build apk --release                # Android APK
flutter build appbundle --release          # Android App Bundle
flutter build ios --release                # iOS
flutter build web --release                # Web
flutter build macos --release              # macOS
flutter build windows --release            # Windows
flutter build linux --release              # Linux

# Analyze code:
flutter analyze
flutter analyze --watch

# Format code:
flutter format lib/

# Check outdated packages:
flutter pub outdated
flutter pub upgrade

# Clean build:
flutter clean
flutter pub get

# Icons generation:
flutter pub run flutter_launcher_icons:main

# Splash screen generation:
flutter pub run flutter_native_splash:create
*/

// ====================
# TESTING STRATEGY
// ====================

/*
# Unit Tests:
- Test business logic (BLoC, providers)
- Test models and utilities
- Test repositories

# Widget Tests:
- Test UI components
- Test user interactions
- Test navigation

# Integration Tests:
- Test complete user flows
- Test API integration
- Test database operations

# Golden Tests:
- Screenshot testing with alchemist
- Visual regression testing

# Example test commands:
flutter test test/unit/
flutter test test/widget/
flutter test test/integration/
flutter test test/golden/
*/

// ====================
# CI/CD INTEGRATION
// ====================

/*
# GitHub Actions workflow for Flutter

name: Flutter CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-java@v2
      with:
        java-version: '11'
        distribution: 'adopt'
    - uses: subosito/flutter-action@v2
      with:
        flutter-version: '3.13.0'
    - run: flutter pub get
    - run: flutter analyze
    - run: flutter test --coverage
    - run: flutter build apk --release
*/

// ====================
# DEPLOYMENT PLATFORMS
// ====================

/*
# Google Play Store:
- Build appbundle: flutter build appbundle --release
- Upload to Play Console
- Use fastlane for automation

# Apple App Store:
- Build: flutter build ios --release
- Archive in Xcode
- Upload to App Store Connect
- Use fastlane match and deliver

# Web Hosting:
- Build: flutter build web --release
- Deploy to Firebase Hosting, Vercel, or Netlify

# Desktop Distribution:
- Use platform-specific installers
- Sign executables for Windows/macOS
*/

// ====================
# MONITORING & ANALYTICS
// ====================

/*
# Firebase Analytics:
- Track user events
- Monitor app usage
- A/B testing

# Sentry Error Tracking:
- Real-time error monitoring
- Crash reporting
- Performance monitoring

# Custom Analytics:
- Implement custom event tracking
- Backend analytics integration
*/

// ====================
# SECURITY BEST PRACTICES
// ====================

/*
- Store API keys in environment variables
- Use flutter_secure_storage for sensitive data
- Implement certificate pinning for API calls
- Validate all user inputs
- Use HTTPS for all API calls
- Keep dependencies updated
- Review code with security focus
- Use ProGuard/R8 for Android obfuscation
- Enable iOS app transport security
*/

// ====================
# PERFORMANCE OPTIMIZATION
// ====================

/*
# Image Optimization:
- Use appropriate image formats (WebP)
- Implement image caching
- Use fade_in_image for network images

# State Management:
- Use const constructors where possible
- Implement proper state lifting
- Avoid unnecessary rebuilds

# Build Optimization:
- Use --release flag for production
- Enable code shrinking and obfuscation
- Use app bundles for Android

# Profiling:
flutter run --profile
- Use Flutter DevTools
- Monitor widget rebuilds
- Track memory usage
*/

// ====================
# ACCESSIBILITY
// ====================

/*
- Use Semantics widget
- Provide accessible labels
- Test with screen readers
- Ensure proper contrast ratios
- Support large text scaling
- Implement keyboard navigation
*/

// ====================
# INTERNATIONALIZATION
// ====================

/*
# Setup:
flutter pub get
flutter gen-l10n

# Add new languages:
# 1. Create arb files: lib/l10n/arb/app_{locale}.arb
# 2. Add translations
# 3. Run flutter gen-l10n

# Supported in code:
import 'package:flutter_gen/gen_l10n/app_localizations.dart';

Text(AppLocalizations.of(context)!.helloWorld);
*/

echo "Flutter dependencies and configuration setup complete!"
echo "Run 'flutter pub get' to install packages"
echo "Run 'flutter packages pub run build_runner build' to generate code"
