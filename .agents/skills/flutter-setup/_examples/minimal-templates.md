# Flutter minimal templates

Reference templates for common Flutter scaffolding tasks.

## Minimal main.dart

```dart
import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'My App',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatelessWidget {
  const HomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Home')),
      body: const Center(child: Text('Hello, Flutter!')),
    );
  }
}
```

## Feature scaffold (lib/features/<name>/)

```
auth/
├── data/
│   ├── auth_repository.dart
│   └── auth_data_source.dart
├── domain/
│   ├── user.dart
│   └── auth_use_case.dart
└── presentation/
    ├── login_page.dart
    ├── login_controller.dart  # or cubit/bloc
    └── widgets/
        └── login_form.dart
```

## Test boilerplate

```dart
// test/features/auth/presentation/login_page_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
// import 'package:my_app/features/auth/presentation/login_page.dart';

void main() {
  group('LoginPage', () {
    testWidgets('renders email and password fields', (tester) async {
      // await tester.pumpWidget(const MaterialApp(home: LoginPage()));
      // expect(find.byType(TextField), findsNWidgets(2));
    });
  });
}
```

## analysis_options.yaml (recommended)

```yaml
include: package:flutter_lints/flutter.yaml

linter:
  rules:
    - prefer_const_constructors
    - prefer_const_declarations
    - avoid_print
```