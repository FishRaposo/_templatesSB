# flutter-setup

Use this skill when creating, configuring, or maintaining Flutter/Dart projects.

**When to invoke**: Flutter project creation, pubspec or analysis_options edits, state management (Provider/Bloc/Riverpod/GetX), testing (unit/widget/integration), run/build/DevTools.

**Quick commands**:
- `flutter create --org com.example my_app`
- `flutter pub add --dev flutter_lints` + `include: package:flutter_lints/flutter.yaml` in analysis_options.yaml
- `flutter analyze` · `dart fix --apply` · `flutter test` · `flutter run` · `flutter build web|apk|ipa`

**Structure**: lib/app, lib/features/<name>/data|domain|presentation, lib/shared, test, integration_test.

See **SKILL.md** for full steps; **_examples/project-structure-and-commands.md** for folder tree and CLI reference.
