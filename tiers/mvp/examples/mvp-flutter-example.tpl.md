# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: unknown template utilities
# Tier: mvp
# Stack: unknown
# Category: template

# MVP Flutter Example Project

## Overview

This example demonstrates a complete MVP Flutter application using the minimal boilerplate template with local authentication, basic CRUD operations, and simple navigation.

## Project Structure

```
mvp_flutter_example/
├── lib/
│   ├── main.dart                    # MVP boilerplate entry point
│   ├── config/
│   │   ├── app_config.dart          # MVP configuration
│   │   └── env_config.dart          # Environment settings
│   ├── core/
│   │   ├── constants.dart           # App constants
│   │   ├── themes.dart             # Basic themes
│   │   └── routes.dart             # Route definitions
│   ├── data/
│   │   ├── models/
│   │   │   ├── user.dart            # User model
│   │   │   └── task.dart            # Task model
│   │   ├── services/
│   │   │   ├── auth_service.dart    # Authentication service
│   │   │   └── task_service.dart    # Task management service
│   │   └── repositories/
│   │       └── task_repository.dart # Task data repository
│   ├── presentation/
│   │   ├── pages/
│   │   │   ├── home_page.dart       # Main dashboard
│   │   │   ├── login_page.dart      # Authentication screen
│   │   │   ├── tasks_page.dart      # Task management
│   │   │   └── settings_page.dart   # App settings
│   │   ├── widgets/
│   │   │   ├── task_card.dart       # Task display widget
│   │   │   ├── task_form.dart       # Task creation/editing form
│   │   │   └── loading_widget.dart  # Loading indicator
│   │   └── providers/
│   │       ├── auth_provider.dart   # Authentication state
│   │       └── task_provider.dart   # Task management state
│   └── utils/
│       ├── helpers.dart             # Utility functions
│       └── validators.dart          # Input validation
├── test/
│   ├── unit/
│   │   ├── services/
│   │   │   ├── auth_service_test.dart
│   │   │   └── task_service_test.dart
│   │   └── providers/
│   │       ├── auth_provider_test.dart
│   │       └── task_provider_test.dart
│   └── widget/
│       ├── login_page_test.dart
│       ├── tasks_page_test.dart
│       └── task_card_test.dart
├── pubspec.yaml                     # Dependencies
└── README.md                        # Project documentation
```

## Key Features Demonstrated

### 1. Local Authentication
```dart
// lib/presentation/providers/auth_provider.dart
class AuthProvider extends ChangeNotifier {
  bool _isAuthenticated = false;
  User? _currentUser;
  
  bool get isAuthenticated => _isAuthenticated;
  User? get currentUser => _currentUser;
  
  Future<bool> login(String email, String password) async {
    final authService = AuthService();
    
    // Basic validation
    if (!_validateEmail(email)) {
      _setError('Invalid email format');
      return false;
    }
    
    // Local authentication (no backend)
    if (email == 'test@example.com' && password == 'password') {
      _currentUser = User(email: email);
      _isAuthenticated = true;
      await _saveAuthState();
      notifyListeners();
      return true;
    }
    
    _setError('Invalid credentials');
    return false;
  }
  
  Future<void> logout() async {
    _currentUser = null;
    _isAuthenticated = false;
    await _clearAuthState();
    notifyListeners();
  }
}
```

### 2. Task CRUD Operations
```dart
// lib/data/services/task_service.dart
class TaskService extends BaseService {
  Future<List<Task>> getTasks() async {
    try {
      // Simulate API call with local storage
      await Future.delayed(Duration(milliseconds: 500));
      return _getLocalTasks();
    } catch (e) {
      return [];
    }
  }
  
  Future<Task?> createTask(Task task) async {
    try {
      final tasks = await getTasks();
      final newTask = task.copyWith(
        id: tasks.length + 1,
        createdAt: DateTime.now(),
      );
      tasks.add(newTask);
      await _saveLocalTasks(tasks);
      return newTask;
    } catch (e) {
      return null;
    }
  }
  
  Future<bool> updateTask(Task task) async {
    try {
      final tasks = await getTasks();
      final index = tasks.indexWhere((t) => t.id == task.id);
      if (index != -1) {
        tasks[index] = task.copyWith(updatedAt: DateTime.now());
        await _saveLocalTasks(tasks);
        return true;
      }
      return false;
    } catch (e) {
      return false;
    }
  }
  
  Future<bool> deleteTask(int taskId) async {
    try {
      final tasks = await getTasks();
      tasks.removeWhere((t) => t.id == taskId);
      await _saveLocalTasks(tasks);
      return true;
    } catch (e) {
      return false;
    }
  }
}
```

### 3. Simple Navigation
```dart
// lib/core/routes.dart
class AppRoutes {
  static const String home = '/';
  static const String login = '/login';
  static const String tasks = '/tasks';
  static const String settings = '/settings';
  
  static Route<dynamic> generateRoute(RouteSettings settings) {
    switch (settings.name) {
      case home:
        return MaterialPageRoute(builder: (_) => HomePage());
      case login:
        return MaterialPageRoute(builder: (_) => LoginPage());
      case tasks:
        return MaterialPageRoute(builder: (_) => TasksPage());
      case settings:
        return MaterialPageRoute(builder: (_) => SettingsPage());
      default:
        return MaterialPageRoute(
          builder: (_) => Scaffold(
            body: Center(child: Text('Route not found')),
          ),
        );
    }
  }
}
```

### 4. State Management with Provider
```dart
// lib/presentation/providers/task_provider.dart
class TaskProvider extends ChangeNotifier {
  List<Task> _tasks = [];
  bool _isLoading = false;
  String? _error;
  
  List<Task> get tasks => _tasks;
  bool get isLoading => _isLoading;
  String? get error => _error;
  
  Future<void> loadTasks() async {
    _setLoading(true);
    try {
      final taskService = TaskService();
      _tasks = await taskService.getTasks();
      _error = null;
    } catch (e) {
      _error = e.toString();
    } finally {
      _setLoading(false);
    }
  }
  
  Future<void> addTask(Task task) async {
    try {
      final taskService = TaskService();
      final newTask = await taskService.createTask(task);
      if (newTask != null) {
        _tasks.add(newTask);
        notifyListeners();
      }
    } catch (e) {
      _error = e.toString();
      notifyListeners();
    }
  }
  
  Future<void> updateTask(Task task) async {
    try {
      final taskService = TaskService();
      final success = await taskService.updateTask(task);
      if (success) {
        final index = _tasks.indexWhere((t) => t.id == task.id);
        if (index != -1) {
          _tasks[index] = task;
          notifyListeners();
        }
      }
    } catch (e) {
      _error = e.toString();
      notifyListeners();
    }
  }
  
  Future<void> deleteTask(int taskId) async {
    try {
      final taskService = TaskService();
      final success = await taskService.deleteTask(taskId);
      if (success) {
        _tasks.removeWhere((t) => t.id == taskId);
        notifyListeners();
      }
    } catch (e) {
      _error = e.toString();
      notifyListeners();
    }
  }
}
```

## Usage Instructions

### 1. Setup Project
```bash
# Create new Flutter project
flutter create mvp_flutter_example
cd mvp_flutter_example

# Copy MVP boilerplate and templates
cp tiers/mvp/code/minimal-boilerplate-flutter.tpl.dart lib/main.dart
cp -r stacks/flutter/base/code/* lib/
cp -r stacks/flutter/base/tests/* test/

# Install dependencies
flutter pub get
```

### 2. Run the Application
```bash
# Run in debug mode
flutter run

# Run on specific device
flutter run -d chrome
flutter run -d ios
flutter run -d android
```

### 3. Test the Application
```bash
# Run all tests
flutter test

# Run specific test file
flutter test test/unit/services/auth_service_test.dart

# Run widget tests
flutter test test/widget/
```

## Example Screens

### Login Screen
```dart
// lib/presentation/pages/login_page.dart
class LoginPage extends StatefulWidget {
  @override
  _LoginPageState createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final _formKey = GlobalKey<FormState>();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  bool _obscurePassword = true;
  
  @override
  Widget build(BuildContext context) {
    final authProvider = Provider.of<AuthProvider>(context);
    
    return Scaffold(
      appBar: AppBar(title: Text('Login')),
      body: Padding(
        padding: EdgeInsets.all(16.0),
        child: Form(
          key: _formKey,
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              TextFormField(
                controller: _emailController,
                decoration: InputDecoration(
                  labelText: 'Email',
                  border: OutlineInputBorder(),
                ),
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return 'Please enter your email';
                  }
                  if (!EmailValidator.validate(value)) {
                    return 'Please enter a valid email';
                  }
                  return null;
                },
              ),
              SizedBox(height: 16),
              TextFormField(
                controller: _passwordController,
                obscureText: _obscurePassword,
                decoration: InputDecoration(
                  labelText: 'Password',
                  border: OutlineInputBorder(),
                  suffixIcon: IconButton(
                    icon: Icon(_obscurePassword ? Icons.visibility : Icons.visibility_off),
                    onPressed: () {
                      setState(() {
                        _obscurePassword = !_obscurePassword;
                      });
                    },
                  ),
                ),
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return 'Please enter your password';
                  }
                  if (value.length < 6) {
                    return 'Password must be at least 6 characters';
                  }
                  return null;
                },
              ),
              SizedBox(height: 24),
              if (authProvider.error != null)
                Text(
                  authProvider.error!,
                  style: TextStyle(color: Colors.red),
                ),
              SizedBox(height: 16),
              ElevatedButton(
                onPressed: authProvider.isLoading ? null : () async {
                  if (_formKey.currentState!.validate()) {
                    final success = await authProvider.login(
                      _emailController.text,
                      _passwordController.text,
                    );
                    if (success) {
                      Navigator.of(context).pushReplacementNamed(AppRoutes.home);
                    }
                  }
                },
                child: authProvider.isLoading
                    ? CircularProgressIndicator()
                    : Text('Login'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
```

### Tasks Management Screen
```dart
// lib/presentation/pages/tasks_page.dart
class TasksPage extends StatefulWidget {
  @override
  _TasksPageState createState() => _TasksPageState();
}

class _TasksPageState extends State<TasksPage> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance!.addPostFrameCallback((_) {
      Provider.of<TaskProvider>(context, listen: false).loadTasks();
    });
  }
  
  @override
  Widget build(BuildContext context) {
    final taskProvider = Provider.of<TaskProvider>(context);
    
    return Scaffold(
      appBar: AppBar(
        title: Text('Tasks'),
        actions: [
          IconButton(
            icon: Icon(Icons.add),
            onPressed: () => _showAddTaskDialog(),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: () => taskProvider.loadTasks(),
        child: taskProvider.isLoading
            ? Center(child: CircularProgressIndicator())
            : taskProvider.tasks.isEmpty
                ? Center(child: Text('No tasks found'))
                : ListView.builder(
                    itemCount: taskProvider.tasks.length,
                    itemBuilder: (context, index) {
                      final task = taskProvider.tasks[index];
                      return TaskCard(
                        task: task,
                        onToggle: () => taskProvider.updateTask(
                          task.copyWith(isCompleted: !task.isCompleted),
                        ),
                        onDelete: () => taskProvider.deleteTask(task.id),
                        onEdit: () => _showEditTaskDialog(task),
                      );
                    },
                  ),
      ),
    );
  }
  
  void _showAddTaskDialog() {
    showDialog(
      context: context,
      builder: (context) => TaskForm(
        onSubmit: (title, description) {
          final task = Task(
            title: title,
            description: description,
            isCompleted: false,
          );
          Provider.of<TaskProvider>(context, listen: false).addTask(task);
          Navigator.of(context).pop();
        },
      ),
    );
  }
  
  void _showEditTaskDialog(Task task) {
    showDialog(
      context: context,
      builder: (context) => TaskForm(
        task: task,
        onSubmit: (title, description) {
          final updatedTask = task.copyWith(
            title: title,
            description: description,
          );
          Provider.of<TaskProvider>(context, listen: false).updateTask(updatedTask);
          Navigator.of(context).pop();
        },
      ),
    );
  }
}
```

## Testing Examples

### Unit Test for Auth Service
```dart
// test/unit/services/auth_service_test.dart
void main() {
  group('AuthService', () {
    late AuthService authService;
    
    setUp(() {
      authService = AuthService();
    });
    
    test('should login with valid credentials', () async {
      final result = await authService.login('test@example.com', 'password');
      
      expect(result.success, isTrue);
      expect(result.user?.email, equals('test@example.com'));
    });
    
    test('should fail login with invalid email', () async {
      final result = await authService.login('invalid-email', 'password');
      
      expect(result.success, isFalse);
      expect(result.error, contains('Invalid email'));
    });
    
    test('should fail login with invalid credentials', () async {
      final result = await authService.login('test@example.com', 'wrong-password');
      
      expect(result.success, isFalse);
      expect(result.error, contains('Invalid credentials'));
    });
    
    test('should logout successfully', () async {
      // First login
      await authService.login('test@example.com', 'password');
      
      // Then logout
      final result = await authService.logout();
      
      expect(result.success, isTrue);
    });
  });
}
```

### Widget Test for Login Page
```dart
// test/widget/login_page_test.dart
void main() {
  group('LoginPage Widget Tests', () {
    testWidgets('should display login form', (WidgetTester tester) async {
      await tester.pumpWidget(
        ChangeNotifierProvider(
          create: (_) => AuthProvider(),
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );
      
      // Verify email field exists
      expect(find.byType(TextFormField), findsWidgets);
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Password'), findsOneWidget);
      expect(find.text('Login'), findsOneWidget);
    });
    
    testWidgets('should validate email input', (WidgetTester tester) async {
      await tester.pumpWidget(
        ChangeNotifierProvider(
          create: (_) => AuthProvider(),
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );
      
      // Find email field and enter invalid email
      final emailField = find.byKey(Key('email_field'));
      await tester.enterText(emailField, 'invalid-email');
      
      // Find and tap login button
      final loginButton = find.text('Login');
      await tester.tap(loginButton);
      await tester.pump();
      
      // Verify error message
      expect(find.text('Please enter a valid email'), findsOneWidget);
    });
    
    testWidgets('should login with valid credentials', (WidgetTester tester) async {
      await tester.pumpWidget(
        ChangeNotifierProvider(
          create: (_) => AuthProvider(),
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );
      
      // Enter valid credentials
      await tester.enterText(find.byKey(Key('email_field')), 'test@example.com');
      await tester.enterText(find.byKey(Key('password_field')), 'password');
      
      // Tap login button
      await tester.tap(find.text('Login'));
      await tester.pumpAndSettle();
      
      // Verify navigation to home page (mocked)
      expect(find.byType(HomePage), findsOneWidget);
    });
  });
}
```

## Key MVP Patterns Demonstrated

1. **Simple State Management**: Using Provider for basic state management
2. **Local Authentication**: No backend required, uses local validation
3. **File-based Storage**: Tasks stored in local memory/files
4. **Basic Navigation**: Simple route management without deep linking
5. **Minimal Dependencies**: Only essential Flutter packages
6. **Error Handling**: Basic error display and logging
7. **Testing Coverage**: Unit tests for services, widget tests for UI

## Deployment Instructions

### 1. Build for Release
```bash
# Android APK
flutter build apk --release

# Android App Bundle
flutter build appbundle --release

# iOS
flutter build ios --release

# Web
flutter build web --release
```

### 2. Distribution
```bash
# Upload to app stores
# Use Firebase App Distribution for testing
# Deploy web version to hosting service
```

## Next Steps

This example provides a complete MVP foundation that can be extended with:
- Backend API integration
- Advanced state management
- Offline synchronization
- Push notifications
- Analytics and crash reporting
- Advanced authentication (OAuth)

---

**Note**: This example demonstrates the MVP tier capabilities with minimal complexity while maintaining a functional, testable application structure.
