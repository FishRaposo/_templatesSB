---
name: flutter-setup
description: Use this skill when creating or configuring Flutter/Dart projects, editing pubspec or analysis_options, choosing state management, writing or running tests, or building/releasing Flutter apps. This includes project structure, Dart 3 and null safety, flutter_lints, Provider/Bloc/Riverpod, unit/widget/integration tests, and Flutter CLI.
---

# Flutter Setup

Guides agents when setting up or maintaining Flutter/Dart projects: project creation, structure, pubspec, static analysis, state management, testing, and build/run. Action-oriented; no curriculum.

## Core Approach

Single-language focus (Dart/Flutter). Emphasize: project layout, `pubspec.yaml` and `analysis_options.yaml`, state management choice, testing pyramid, and Flutter CLI. Use forward slashes for all paths.

## Step-by-Step Instructions

### 1. Project creation

From the directory where the project should live:

```bash
flutter create --org com.example my_app
```

Optional: restrict platforms with `--platforms=ios,android,web` (or omit for all). Generated layout: `lib/`, `test/`, `pubspec.yaml`, platform folders (`android/`, `ios/`, `web/`, etc.).

### 2. Project structure

Use a scalable layout. Recommended:

- `lib/app/` — app root, router, theme, dependency injection
- `lib/features/<feature>/` — per feature: `data/` (repositories, data sources), `domain/` (entities, use cases), `presentation/` (widgets, state)
- `lib/shared/` — UI kit, utilities, shared services (logging, HTTP, storage)
- `assets/` — images, fonts, etc. (declare in `pubspec.yaml` under `flutter:`)
- `test/` — unit and widget tests (`*_test.dart`)
- `integration_test/` — end-to-end tests

See `./_examples/project-structure-and-commands.md` for a full folder tree and CLI reference.

### 3. pubspec.yaml

- **name**: lowercase, underscores (e.g. `my_app`).
- **environment**: `sdk: ">=3.0.0 <4.0.0"` (or current stable; Dart 3 with null safety).
- **dependencies**: `flutter`, app packages (e.g. `flutter_localizations`, state, networking).
- **dev_dependencies**: `flutter_test`, `flutter_lints` (see step 4).
- **flutter:** — `assets:` (paths to asset dirs), `fonts:` if using custom fonts.

Use two spaces for indentation; invalid YAML breaks builds.

### 4. Static analysis (flutter_lints)

Add official lint rules and wire the analyzer:

```bash
flutter pub add --dev flutter_lints
```

Create or update `analysis_options.yaml` at project root (only one `include` allowed):

```yaml
include: package:flutter_lints/flutter.yaml
```

Then:

```bash
flutter analyze
dart fix --apply   # when applicable, then fix remaining manually
```

### 5. State management

Choose by complexity:

- **Provider** — simple to medium apps.
- **Bloc** — predictable state transitions, event-driven.
- **Riverpod** — complex apps, heavy business logic, testability.
- **GetX** — rapid prototyping; use with care for long-term structure.

Keep UI widgets "dumb"; put logic in ViewModels/repositories (MVVM/repository pattern).

### 6. Testing

- **Unit and widget tests**: under `test/`, files named `*_test.dart`. Use `test()` and `expect()` from `flutter_test`.
- **Integration tests**: under `integration_test/`. Run with `flutter test integration_test` or on a device/emulator.

```bash
flutter test
flutter test integration_test
```

### 7. Run and build

- **Run**: `flutter run` (or `flutter run -d chrome` for web). List devices: `flutter devices`.
- **Build**: `flutter build web`, `flutter build apk`, `flutter build ipa`. Outputs go to `build/`.
- **Clean**: `flutter clean` then `flutter pub get` if builds or dependencies are inconsistent.
- **Env config**: use `--dart-define-from-file=path/to/config.json` for non-secret config (e.g. API base URLs) when building.

### 8. DevTools

- Activate: `flutter pub global activate devtools` then run `devtools` (or open from IDE).
- Use Widget Inspector for layout and widget tree; use performance tools for profiling. Launch from VS Code/IntelliJ with the Flutter plugin when available.

## Best Practices

- Keep widgets dumb; put logic in ViewModels/repositories (MVVM + repository pattern).
- Minimize rebuilds: use `const` where possible and scope state appropriately.
- Impeller is the default renderer (iOS/Android); no extra config needed.
- Performance targets (aim for): startup < 3s on mid-range devices, navigation < 300ms, memory under ~100MB for typical usage.
- Adaptive design: solve for touch first; then optimize for other inputs and screen sizes.
- Use forward slashes in paths in all instructions and examples.
- Run `flutter doctor` before starting to diagnose environment issues.
- Use `flutter pub upgrade --major-versions` to update dependencies across major versions.
- iOS builds require macOS with Xcode; Android builds work on all platforms.
- Use `--flavor` flag for environment-specific builds (e.g., `flutter build apk --flavor staging`).
- Clear pub cache with `flutter pub cache clean` if dependency resolution fails persistently.

## Validation Checklist

- [ ] `flutter analyze` passes
- [ ] `flutter test` passes (and `flutter test integration_test` if applicable)
- [ ] App runs on target platform(s) (`flutter run` or device-specific)
- [ ] `pubspec.yaml` has valid name, SDK constraint, and dependencies
- [ ] `analysis_options.yaml` includes `package:flutter_lints/flutter.yaml` (or equivalent)

## Troubleshooting

**Templates or paths not found** — Use project-relative paths and forward slashes (e.g. `lib/features/auth/presentation/login_screen.dart`).

**Many analyzer/lint errors after adding flutter_lints** — Run `dart fix --apply`, then fix remaining issues manually. Temporarily disable specific rules in `analysis_options.yaml` only if necessary, with a comment.

**Build or dependency failures** — Run `flutter clean`, then `flutter pub get`, then rebuild. Ensure SDK constraint in `pubspec.yaml` matches the Flutter/Dart version in use.

**Pub cache or dependency resolution failures** — Run `flutter pub cache clean`, then `flutter pub get`. If version conflicts persist, check `flutter pub outdated` and update constraints.

**iOS build fails on non-macOS** — iOS builds require macOS with Xcode. Use CI/CD or remote Mac for iOS artifacts.

**Hot reload not applying changes** — Restart the app with `R` (full restart) or stop and run `flutter run` again. Some changes (e.g., main method, global state) require full restart.

## Related Skills

- **skill-setup** — When creating or editing any skill (including this one).
- **blueprints-setup** — When a Blueprint specifies Flutter as a stack (e.g. tier and overlays).

## Supporting Files

- **Project structure and CLI reference**: `./_examples/project-structure-and-commands.md` — full folder tree and essential commands
- **Minimal templates**: `./_examples/minimal-templates.md` — main.dart, feature scaffold, test boilerplate
- **State management guide**: `./_examples/state-management-choices.md` — when to use Provider/Bloc/Riverpod/GetX
- **Official docs**: https://docs.flutter.dev, https://dart.dev — reference for latest APIs and tooling
