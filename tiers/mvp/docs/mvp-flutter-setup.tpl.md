<!--
File: mvp-flutter-setup.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# MVP Flutter Setup Guide

## Overview

This guide extends the foundational Flutter templates with MVP-specific configurations and minimal feature set for rapid development and deployment.

## Prerequisites

- Flutter SDK 3.0+
- Dart 2.17+
- Android Studio / VS Code
- Android SDK (for Android development)
- Xcode (for iOS development)

## Quick Start

### 1. Project Setup

```bash
# Copy MVP Flutter boilerplate
cp tiers/mvp/code/minimal-boilerplate-flutter.tpl.dart [project-name]/lib/main.dart

# Copy foundational templates
cp -r stacks/flutter/base/code/* [project-name]/lib/
cp -r stacks/flutter/base/tests/* [project-name]/test/

# Setup dependencies
cp stacks/flutter/pubspec.yaml.tpl [project-name]/pubspec.yaml
cd [project-name]
flutter pub get
```

### 2. Configuration

```dart
// lib/config/app_config.dart - extends foundational config
class AppConfig extends BaseConfig {
  @override
  Future<void> load() async {
    await super.load();
    
    // MVP-specific settings
    enableAnalytics = false;
    enableCrashlytics = false;
    enableRemoteConfig = false;
    
    // Minimal feature set
    maxRetries = 2;
    timeout = Duration(seconds: 15);
  }
}
```

## MVP Architecture

### Core Components

1. **Minimal State Management**
   - Basic Provider pattern
   - Simple state classes
   - No complex state persistence

2. **Essential UI Components**
   - Material Design basics
   - Common form widgets
   - Simple navigation

3. **Basic Data Layer**
   - Local storage only
   - Simple HTTP client
   - Basic caching

4. **Core Features**
   - Authentication (local)
   - Basic CRUD operations
   - Simple settings

## File Structure

```
lib/
├── main.dart                 # MVP boilerplate
├── config/
│   ├── app_config.dart       # MVP-specific config
│   └── env_config.dart       # Environment settings
├── core/
│   ├── constants.dart        # App constants
│   ├── themes.dart          # Basic themes
│   └── routes.dart          # Route definitions
├── data/
│   ├── models/              # Data models
│   ├── services/            # Basic services
│   └── repositories/        # Simple repositories
├── presentation/
│   ├── pages/               # Main pages
│   ├── widgets/             # Common widgets
│   └── providers/           # State management
└── utils/
    ├── helpers.dart         # Utility functions
    └── validators.dart      # Input validation
```

## MVP Features

### 1. Authentication

```dart
// lib/services/auth_service.dart
class AuthService extends BaseService {
  // Local authentication only
  Future<bool> login(String email, String password) async {
    // Basic validation
    // Local storage
    // No OAuth integration
  }
  
  Future<void> logout() async {
    // Clear local data
    // Reset state
  }
}
```

### 2. Data Management

```dart
// lib/services/data_service.dart
class DataService extends BaseService {
  // Simple HTTP calls
  // Basic error handling
  // Local caching
  
  Future<List<Model>> getItems() async {
    try {
      final response = await httpClient.get('/items');
      return Model.fromJsonList(response.data);
    } catch (e) {
      return _getCachedItems();
    }
  }
}
```

### 3. Navigation

```dart
// lib/core/routes.dart
class AppRoutes {
  static const String home = '/';
  static const String login = '/login';
  static const String settings = '/settings';
  
  // Simple route definitions
  static Map<String, WidgetBuilder> routes = {
    home: (context) => HomePage(),
    login: (context) => LoginPage(),
    settings: (context) => SettingsPage(),
  };
}
```

## Configuration Options

### Environment Variables

```dart
// lib/config/env_config.dart
class EnvConfig {
  static const String appName = '[[.ProjectName]]';
  static const String apiBaseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'https://api.example.com',
  );
  
  // MVP-specific flags
  static const bool enableDebugMode = bool.fromEnvironment(
    'DEBUG_MODE',
    defaultValue: true,
  );
  
  static const bool enableLogging = bool.fromEnvironment(
    'ENABLE_LOGGING',
    defaultValue: true,
  );
}
```

### Feature Flags

```dart
// lib/config/feature_flags.dart
class FeatureFlags {
  // MVP features - minimal set
  static const bool enableOfflineMode = true;
  static const bool enableDarkMode = true;
  static const bool enableNotifications = false;
  static const bool enableAnalytics = false;
  static const bool enableCrashlytics = false;
}
```

## Development Workflow

### 1. Local Development

```bash
# Run in debug mode
flutter run --debug

# Run with specific flavor
flutter run --flavor development

# Hot reload enabled by default
```

### 2. Testing

```bash
# Run all tests
flutter test

# Run specific test file
flutter test test/services/auth_service_test.dart

# Run with coverage
flutter test --coverage
```

### 3. Building

```bash
# Build for development
flutter build apk --debug

# Build for release
flutter build apk --release

# Build for iOS
flutter build ios --release
```

## Deployment

### 1. Android

```bash
# Build release APK
flutter build apk --release

# Build app bundle (recommended)
flutter build appbundle --release
```

### 2. iOS

```bash
# Build for iOS
flutter build ios --release

# Archive in Xcode
open ios/Runner.xcworkspace
```

## MVP Limitations

### What's NOT Included

- No advanced state management (BLoC, Riverpod advanced features)
- No offline data synchronization
- No push notifications
- No analytics or crash reporting
- No advanced caching strategies
- No OAuth authentication
- No real-time features

### Upgrade Path

When ready to move to Core tier:

1. **State Management**: Upgrade to advanced Provider or BLoC
2. **Data Layer**: Add offline sync and advanced caching
3. **Authentication**: Add OAuth providers
4. **Features**: Enable analytics, notifications, crashlytics
5. **Performance**: Add performance monitoring and optimization

## Best Practices

### 1. Code Organization

- Keep features separate and focused
- Use consistent naming conventions
- Follow Flutter/Dart style guidelines
- Document public APIs

### 2. Performance

- Use const constructors where possible
- Implement proper widget lifecycle management
- Optimize image loading and caching
- Use proper state management patterns

### 3. Testing

- Write unit tests for business logic
- Write widget tests for UI components
- Test error scenarios
- Maintain good test coverage

## Troubleshooting

### Common Issues

1. **Build Errors**: Check Flutter version and dependencies
2. **Import Errors**: Verify file paths and exports
3. **State Issues**: Review Provider setup and widget rebuilds
4. **Navigation Problems**: Check route definitions and context

### Debug Tips

- Use Flutter DevTools for debugging
- Enable verbose logging for troubleshooting
- Use print statements for quick debugging
- Check console for error messages

## Resources

- [Flutter Documentation](https://flutter.dev/docs)
- [Dart Language Guide](https://dart.dev/guides)
- [Flutter Testing](https://flutter.dev/docs/testing)
- [Flutter Deployment](https://flutter.dev/docs/deployment)

## Next Steps

1. Review the foundational templates for detailed implementation
2. Customize the MVP boilerplate for your specific needs
3. Implement your business logic using the provided structure
4. Add tests for your custom code
5. Prepare for deployment

---

**Note**: This MVP setup provides a solid foundation for rapid development. When your application grows, consider upgrading to the Core tier for additional features and capabilities.
