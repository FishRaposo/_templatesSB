<!--
File: PACKAGE-MANAGEMENT.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Package Management Guide - Flutter

This guide covers package management strategies, dependency management, and best practices for Flutter applications.

## 📦 Flutter Package Management

### pub.dev Repository
Flutter packages are hosted on [pub.dev](https://pub.dev), the official package repository for Dart and Flutter.

### pubspec.yaml Configuration
```yaml
name: [PROJECT_NAME]
description: [PROJECT_DESCRIPTION]
version: [VERSION]

environment:
  sdk: '>=[MIN_SDK_VERSION] <[MAX_SDK_VERSION]'
  flutter: ">=[MIN_FLUTTER_VERSION]"

dependencies:
  flutter:
    sdk: flutter
  
  # Core dependencies
  cupertino_icons: ^[VERSION]
  
  # State management
  flutter_bloc: ^[VERSION]
  provider: ^[VERSION]
  
  # Networking
  dio: ^[VERSION]
  http: ^[VERSION]
  
  # Storage
  shared_preferences: ^[VERSION]
  sqflite: ^[VERSION]
  
  # Utilities
  get_it: ^[VERSION]
  injectable: ^[VERSION]
  equatable: ^[VERSION]

dev_dependencies:
  flutter_test:
    sdk: flutter
  
  # Code generation
  build_runner: ^[VERSION]
  freezed: ^[VERSION]
  json_annotation: ^[VERSION]
  
  # Testing
  mockito: ^[VERSION]
  integration_test:
    sdk: flutter
  
  # Linting
  flutter_lints: ^[VERSION]

flutter:
  uses-material-design: true
  
  # Assets
  assets:
    - assets/images/
    - assets/icons/
  
  # Fonts
  fonts:
    - family: CustomFont
      fonts:
        - asset: fonts/CustomFont-Regular.ttf
        - asset: fonts/CustomFont-Bold.ttf
          weight: 700
```

## 🚀 Package Installation Commands

### Adding Dependencies
```bash
# Add latest version
flutter pub add [PACKAGE_NAME]

# Add specific version
flutter pub add [PACKAGE_NAME]:^[VERSION]

# Add dev dependency
flutter pub add --dev [PACKAGE_NAME]

# Add multiple packages
flutter pub add [PACKAGE1] [PACKAGE2] [PACKAGE3]
```

### Removing Dependencies
```bash
# Remove package
flutter pub remove [PACKAGE_NAME]

# Remove multiple packages
flutter pub remove [PACKAGE1] [PACKAGE2]
```

### Updating Dependencies
```bash
# Get all dependencies
flutter pub get

# Upgrade dependencies
flutter pub upgrade

# Upgrade specific dependency
flutter pub upgrade [PACKAGE_NAME]

# Upgrade to latest compatible versions
flutter pub upgrade --major-versions
```

## 📋 Dependency Categories

### Core Flutter Packages
- `flutter` - Flutter framework
- `flutter_test` - Testing framework
- `integration_test` - Integration testing

### UI & Design
- `cupertino_icons` - iOS-style icons
- `material_design_icons_flutter` - Material Design icons
- `flutter_svg` - SVG rendering
- `cached_network_image` - Cached network images

### State Management
- `flutter_bloc` - BLoC state management
- `provider` - Provider state management
- `riverpod` - Riverpod state management
- `get` - GetX state management

### Networking
- `dio` - HTTP client with interceptors
- `http` - Simple HTTP client
- `retrofit` - Type-safe HTTP client
- `graphql_flutter` - GraphQL client

### Storage & Database
- `shared_preferences` - Simple key-value storage
- `sqflite` - SQLite database
- `hive` - Lightweight key-value database
- `sembast` - NoSQL embedded database

### Utilities
- `get_it` - Service locator
- `injectable` - Dependency injection
- `equatable` - Value equality
- `freezed` - Code generation
- `json_annotation` - JSON serialization

### Development Tools
- `build_runner` - Code generation runner
- `mockito` - Mocking framework
- `flutter_lints` - Linting rules
- `very_good_analysis` - Additional linting rules

## 🔧 Package Management Best Practices

### Version Constraints
```yaml
# Caret (^) - allows compatible version updates
dependencies:
  dio: ^5.3.0

# Exact version - prevents any updates
dependencies:
  dio: 5.3.0

# Range - allows updates within range
dependencies:
  dio: ">=5.0.0 <6.0.0"

# Any version - not recommended
dependencies:
  dio: any
```

### Dependency Optimization
```yaml
# Use path dependencies for local packages
dependencies:
  local_package:
    path: ../local_package

# Use git dependencies for bleeding-edge
dependencies:
  git_package:
    git:
      url: https://github.com/user/repo.git
      ref: main

# Use overridden dependencies for conflicts
dependency_overrides:
  some_package: 1.2.3
```

### Platform-Specific Dependencies
```yaml
dependencies:
  # iOS only
  ios_platform:
    sdk: flutter
    platform: ios
  
  # Android only
  android_platform:
    sdk: flutter
    platform: android
  
  # Web only
  web_platform:
    sdk: flutter
    platform: web
```

## 📊 Package Analysis

### Dependency Tree
```bash
# Show dependency tree
flutter pub deps

# Show dependency tree for specific package
flutter pub deps [PACKAGE_NAME]

# Show dependency graph
flutter pub deps --style=tree
```

### Outdated Packages
```bash
# Check for outdated packages
flutter pub outdated

# Check for outdated packages with major versions
flutter pub outdated --show-all
```

### Package Security
```bash
# Check for security vulnerabilities (requires external tool)
dart pub security
```

## 🗂️ Package Organization

### Feature-Based Organization
```
lib/
├── features/
│   ├── authentication/
│   │   ├── data/
│   │   │   ├── datasources/
│   │   │   ├── models/
│   │   │   └── repositories/
│   │   ├── domain/
│   │   │   ├── entities/
│   │   │   ├── repositories/
│   │   │   └── usecases/
│   │   └── presentation/
│   │       ├── pages/
│   │       ├── widgets/
│   │       └── bloc/
│   └── profile/
│       └── ...
├── core/
│   ├── constants/
│   ├── errors/
│   ├── network/
│   └── utils/
└── main.dart
```

### Layer-Based Organization
```
lib/
├── data/
│   ├── datasources/
│   ├── models/
│   └── repositories/
├── domain/
│   ├── entities/
│   ├── repositories/
│   └── usecases/
├── presentation/
│   ├── pages/
│   ├── widgets/
│   └── providers/
├── core/
│   ├── constants/
│   ├── errors/
│   ├── network/
│   └── utils/
└── main.dart
```

## 🔍 Package Selection Guidelines

### Choosing the Right Package
1. **Check Popularity**: Look at pub scores and likes
2. **Review Maintenance**: Check last update date
3. **Read Documentation**: Ensure good documentation
4. **Check Dependencies**: Avoid packages with many transitive dependencies
5. **Test Compatibility**: Verify compatibility with your Flutter version

### Package Evaluation Checklist
- [ ] Active maintenance (updated within last 6 months)
- [ ] Good pub score (>90)
- [ ] Comprehensive documentation
- [ ] Compatible with Flutter version
- [ ] Reasonable dependency count
- [ ] Good community support
- [ ] License compatibility
- [ ] No security vulnerabilities

## 🚨 Common Issues & Solutions

### Version Conflicts
```bash
# Error: Two packages depend on different versions
Solution: Use dependency_overrides in pubspec.yaml

dependency_overrides:
  conflicting_package: 1.2.3
```

### Flutter Version Incompatibility
```bash
# Error: Package requires newer Flutter version
Solution: Update Flutter SDK or use compatible package version

flutter upgrade
flutter pub upgrade
```

### Platform-Specific Issues
```bash
# Error: Package not available for target platform
Solution: Check package platform support or find alternative

# Check platform support
flutter pub deps --style=tree | grep [PACKAGE_NAME]
```

## 📈 Performance Optimization

### Reducing Package Size
- Remove unused dependencies
- Use tree shaking for web builds
- Optimize assets and images
- Use lazy loading for heavy packages

### Bundle Analysis
```bash
# Analyze bundle size
flutter build apk --analyze-size
flutter build web --analyze-size

# Use flutter_tools to analyze dependencies
flutter build apk --split-debug-info=build/debug-info/
```

## 🔄 Continuous Integration

### CI/CD Integration
```yaml
# .github/workflows/flutter.yml
name: Flutter CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '[FLUTTER_VERSION]'
      - run: flutter pub get
      - run: flutter analyze
      - run: flutter test
      - run: flutter pub outdated
```

### Dependency Updates
```yaml
# Automated dependency updates
name: Update Dependencies
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: subosito/flutter-action@v2
      - run: flutter pub upgrade
      - run: flutter test
      # Create PR if tests pass
```

---

**Flutter Version**: [FLUTTER_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
