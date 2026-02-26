<!--
File: PROJECT-STRUCTURE.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# {{PROJECT_NAME}} - Flutter Project Structure

**Tier**: {{TIER}} | **Stack**: Flutter

## 🐦 Canonical Flutter Project Structure

### **MVP Tier (Single Module)**
```
{{PROJECT_NAME}}/
├── lib/
│   ├── main.dart
│   ├── app.dart
│   ├── core/
│   │   ├── constants/
│   │   ├── themes/
│   │   └── utils/
│   ├── features/
│   │   └── feature_name/
│   │       ├── data/
│   │       ├── domain/
│   │       └── presentation/
│   └── shared/
│       └── widgets/
├── test/
├── pubspec.yaml
└── README.md
```

### **CORE Tier (Modularized)**
```
{{PROJECT_NAME}}/
├── lib/
│   ├── main.dart
│   ├── app.dart
│   ├── core/
│   │   ├── constants/
│   │   ├── errors/
│   │   ├── network/
│   │   ├── themes/
│   │   ├── utils/
│   │   └── services/
│   ├── features/
│   │   ├── authentication/
│   │   ├── profile/
│   │   └── [business_features]/
│   │   └── Each feature follows:
│   │       ├── data/
│   │       │   ├── datasources/
│   │       │   ├── models/
│   │       │   └── repositories/
│   │       ├── domain/
│   │       │   ├── entities/
│   │       │   ├── repositories/
│   │       │   └── usecases/
│   │       └── presentation/
│   │           ├── pages/
│   │           ├── widgets/
│   │           └── providers/
│   └── shared/
│       ├── widgets/
│       └── extensions/
├── test/
│   ├── unit/
│   ├── widget/
│   └── integration/
├── test_driver/
├── assets/
├── pubspec.yaml
└── README.md
```

### **FULL Tier (Enterprise)**
```
{{PROJECT_NAME}}/
├── lib/
│   ├── [CORE tier structure]
│   ├── features/
│   │   ├── [CORE features]
│   │   ├── analytics/
│   │   ├── monitoring/
│   │   ├── localization/
│   │   └── advanced_features/
│   ├── infrastructure/
│   │   ├── monitoring/
│   │   ├── analytics/
│   │   ├── crashlytics/
│   │   └── remote_config/
│   └── shared/
│       ├── components/
│       ├── extensions/
│       └── utilities/
├── test/
│   ├── [CORE test structure]
│   ├── e2e/
│   └── performance/
├── tools/
│   ├── build_runner/
│   ├── code_generation/
│   └── deployment/
├── assets/
│   ├── images/
│   ├── fonts/
│   └── localization/
├── android/
├── ios/
├── web/
├── pubspec.yaml
├── analysis_options.yaml
└── README.md
```

## 📁 Feature Structure Pattern

Each feature follows clean architecture:

```
feature_name/
├── data/
│   ├── datasources/
│   │   ├── local_datasource.dart
│   │   └── remote_datasource.dart
│   ├── models/
│   │   └── feature_model.dart
│   └── repositories/
│       └── feature_repository_impl.dart
├── domain/
│   ├── entities/
│   │   └── feature_entity.dart
│   ├── repositories/
│   │   └── feature_repository.dart
│   └── usecases/
│       └── feature_usecase.dart
└── presentation/
    ├── pages/
    │   └── feature_page.dart
    ├── widgets/
    │   └── feature_widget.dart
    └── providers/
        └── feature_provider.dart
```

## 🎯 Tier Mapping

| Tier | Features | Complexity | Testing |
|------|----------|------------|---------|
| **MVP** | Single feature module | Basic structure | Widget tests only |
| **CORE** | Multiple features, clean architecture | Modular, scalable | Unit + Widget + Integration |
| **FULL** | Enterprise features + monitoring | Complete ecosystem | All tests + Performance |

## 📦 Package Organization

**Core Dependencies** (all tiers):
- `flutter_riverpod` - State management
- `go_router` - Navigation
- `dio` - HTTP client
- `json_annotation` - Serialization

**CORE Tier Additions**:
- `flutter_secure_storage` - Security
- `equatable` - Value equality
- `intl` - Internationalization

**FULL Tier Additions**:
- `firebase_analytics` - Analytics
- `firebase_crashlytics` - Crash reporting
- `package_info_plus` - App information

---

**Flutter Version**: [FLUTTER_VERSION]  
**Dart Version**: [DART_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
