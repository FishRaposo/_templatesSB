# Flutter project structure and CLI commands

Reference for the flutter-setup skill. Use for full folder tree and essential CLI.

## Recommended folder tree

```
project_root/
├── lib/
│   ├── app/                    # App root, router, theme, DI
│   │   ├── app.dart
│   │   ├── router.dart
│   │   └── theme.dart
│   ├── features/
│   │   └── <feature_name>/
│   │       ├── data/           # Repositories, data sources, DTOs
│   │       ├── domain/         # Entities, use cases
│   │       └── presentation/   # Widgets, state, pages
│   └── shared/                 # UI kit, utils, services
│       ├── widgets/
│       ├── services/
│       └── utils/
├── assets/
│   ├── images/
│   └── fonts/
├── test/                       # Unit and widget tests (*_test.dart)
├── integration_test/
├── pubspec.yaml
├── analysis_options.yaml
├── android/
├── ios/
└── web/
```

## Essential Flutter CLI commands

| Command | Purpose |
|---------|--------|
| `flutter create --org com.example <name>` | Create new project |
| `flutter create --platforms=ios,android,web <name>` | Create with specific platforms |
| `flutter pub get` | Fetch dependencies |
| `flutter pub add <package>` | Add dependency |
| `flutter pub add --dev <package>` | Add dev dependency |
| `flutter analyze` | Run static analysis |
| `dart fix --apply` | Apply automated fixes |
| `flutter test` | Run unit/widget tests |
| `flutter test integration_test` | Run integration tests |
| `flutter run` | Run on default device |
| `flutter run -d chrome` | Run web in Chrome |
| `flutter devices` | List available devices |
| `flutter build web` | Build web release |
| `flutter build apk` | Build Android APK |
| `flutter build ipa` | Build iOS IPA |
| `flutter clean` | Remove build artifacts |
| `flutter pub global activate devtools` | Install DevTools |
| `devtools` | Launch DevTools (after activate) |
| `flutter doctor` | Diagnose environment issues |
| `flutter pub outdated` | Check for outdated dependencies |
| `flutter pub upgrade --major-versions` | Upgrade across major versions |
| `flutter pub cache clean` | Clear pub cache |
| `flutter build apk --flavor staging` | Build with flavor |

## analysis_options.yaml (minimal with flutter_lints)

```yaml
include: package:flutter_lints/flutter.yaml
```

Only one `include` is allowed. Add custom rules under `linter: rules:` if needed.

## pubspec.yaml (minimal structure)

```yaml
name: my_app
description: My Flutter app.
version: 1.0.0+1
publish_to: 'none'

environment:
  sdk: ">=3.0.0 <4.0.0"

dependencies:
  flutter:
    sdk: flutter

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^5.0.0

flutter:
  uses-material-design: true
  assets:
    - assets/images/
```

Adjust SDK range and package versions per project; use `flutter pub add` to add dependencies.
