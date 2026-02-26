<!--
File: FRAMEWORK-PATTERNS-flutter.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Flutter Framework Patterns - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Flutter

## 🎯 Flutter's Role in Your Ecosystem

Flutter serves as the **primary client layer** - your "ship beautiful cross-platform things fast" weapon. It handles mobile apps, desktop apps, and web frontends with a single codebase.

### **Core Responsibilities**
- **Cross-platform UI**: iOS, Android, Web, Desktop from one codebase
- **High-performance rendering**: 60fps+ animations and transitions
- **Rapid development**: Hot reload, expressive UI, fast iteration
- **Native integration**: Platform channels for native APIs
- **State management**: Complex application state handling

## 🏗️ Three Pillars Integration

### **1. Universal Principles Applied to Flutter**
- **Clean Architecture**: Feature-based modules with clear boundaries
- **Dependency Injection**: Service locator pattern with Riverpod
- **Testing Pyramid**: Unit, Widget, Integration tests
- **Configuration Management**: Environment-based settings

### **2. Tier-Specific Flutter Patterns**

#### **MVP Tier - Prototyping Mode**
**Purpose**: Validate ideas quickly with minimal complexity
**Characteristics**:
- Single feature module structure
- Simple state management (StateNotifier)
- Basic navigation (go_router with static routes)
- Minimal UI components (Material Design defaults)
- Widget tests only

**When to Use**:
- Proof of concept validation
- MVP for investor demos
- Internal tools and prototypes
- Learning new domains

**MVP Flutter Pattern**:
```dart
// Simple feature state
class CounterNotifier extends StateNotifier<CounterState> {
  CounterNotifier() : super(CounterState());
  
  void increment() => state = state.copyWith(count: state.count + 1);
}

// Basic routing
final appRouter = GoRouter(
  routes: [
    GoRoute(path: '/', builder: (_, __) => const HomePage()),
    GoRoute(path: '/profile', builder: (_, __) => const ProfilePage()),
  ],
);
```

#### **CORE Tier - Production Baseline**
**Purpose**: Real-world applications with proper architecture
**Characteristics**:
- Modular feature architecture
- Advanced state management (Riverpod + AsyncNotifier)
- Complete navigation with guards and deep links
- Custom theming and design system
- Comprehensive testing (Unit + Widget + Integration)

**When to Use**:
- Production mobile applications
- SaaS mobile clients
- Enterprise internal apps
- Consumer-facing products

**CORE Flutter Pattern**:
```dart
// Feature-based state with repository
class AuthNotifier extends StateNotifier<AuthState> {
  final AuthRepository _repository;
  
  AuthNotifier(this._repository) : super(AuthState());
  
  Future<void> signIn(String email, String password) async {
    state = state.copyWith(isLoading: true);
    try {
      final user = await _repository.signIn(email, password);
      state = state.copyWith(user: user, isLoading: false);
    } catch (e) {
      state = state.copyWith(isLoading: false, error: e.toString());
    }
  }
}

// Advanced routing with guards
final appRouter = GoRouter(
  redirect: (context, state) {
    final isAuthenticated = context.read(authProvider).user != null;
    if (!isAuthenticated && !state.location.startsWith('/login')) {
      return '/login';
    }
    return null;
  },
  routes: [
    // Nested routes with shell
    ShellRoute(
      builder: (context, state, child) => MainShell(child: child),
      routes: [
        GoRoute(path: '/home', builder: (_, __) => const HomePage()),
        GoRoute(path: '/profile/:id', builder: (_, state) => 
          ProfilePage(userId: state.pathParameters['id']!)),
      ],
    ),
  ],
);
```

#### **FULL Tier - Enterprise Excellence**
**Purpose**: Large-scale applications with enterprise requirements
**Characteristics**:
- Micro-frontend architecture
- Advanced state management (caching, optimistic updates)
- Enterprise navigation (feature flags, A/B testing)
- Design system with component library
- Complete testing (all types + performance + accessibility)
- Analytics and monitoring integration

**When to Use**:
- Fortune 500 mobile applications
- Multi-team enterprise projects
- Apps with complex compliance requirements
- High-traffic consumer applications

**FULL Flutter Pattern**:
```dart
// Enterprise state with caching and analytics
@riverpod
class ProfileNotifier extends _$ProfileNotifier {
  @override
  Future<Profile?> build() async {
    ref.watch(analyticsServiceProvider).trackScreenView('profile');
    return await _loadProfile();
  }
  
  Future<void> updateProfile(Profile profile) async {
    state = const AsyncValue.loading();
    ref.watch(analyticsServiceProvider).trackEvent('profile_update_started');
    
    try {
      final updatedProfile = await ref.read(profileRepositoryProvider).updateProfile(profile);
      state = AsyncValue.data(updatedProfile);
      ref.watch(analyticsServiceProvider).trackEvent('profile_update_completed');
    } catch (e, stackTrace) {
      state = AsyncValue.error(e, stackTrace);
      ref.watch(analyticsServiceProvider).trackError('profile_update_failed', e);
    }
  }
}

// Enterprise navigation with feature flags
class AppRouter {
  static GoRouter createRouter({required FeatureFlagService featureFlags}) {
    return GoRouter(
      routes: [
        GoRoute(
          path: '/experimental-feature',
          builder: (_, __) => const ExperimentalFeaturePage(),
          redirect: (_, __) {
            return featureFlags.isEnabled('experimental_feature') 
              ? null : '/home';
          },
        ),
      ],
    );
  }
}
```

## 📱 Blessed Patterns (Never Deviate)

### **State Management: Riverpod**
**Why Riverpod**:
- Compile-safe dependency injection
- Excellent testing support
- Flexible and scalable
- Works well with clean architecture

**Riverpod Patterns**:
```dart
// 1. Simple state (MVP)
final counterProvider = StateNotifierProvider<CounterNotifier, CounterState>((ref) {
  return CounterNotifier();
});

// 2. Async state with repository (CORE)
final authProvider = StateNotifierProvider<AuthNotifier, AuthState>((ref) {
  return AuthNotifier(ref.watch(authRepositoryProvider));
});

// 3. Advanced state with caching (FULL)
@riverpod
class ProfileNotifier extends _$ProfileNotifier {
  // Auto-generated code with caching and error handling
}
```

### **Navigation: go_router**
**Why go_router**:
- Declarative routing
- Deep linking support
- URL-based navigation
- Type safety

**go_router Patterns**:
```dart
// MVP: Simple routing
GoRouter(routes: [GoRoute(path: '/', builder: (_, __) => HomePage())]);

// CORE: Nested routing with guards
ShellRoute(builder: (_, __, child) => MainShell(child: child), routes: [
  GoRoute(path: '/profile/:id', builder: (_, state) => ProfilePage(...))
]);

// FULL: Feature flags and analytics
GoRouter(
  observers: [GoRouterObserver(analytics: analytics)],
  redirect: (context, state) => featureFlagRedirect(state),
);
```

### **Networking: dio**
**Why dio**:
- Powerful interceptors
- Request/response transformation
- Timeout and retry support
- Excellent error handling

**dio Patterns**:
```dart
// MVP: Simple client
class ApiClient {
  Future<Map<String, dynamic>> get(String path) async {
    final response = await _dio.get(path);
    return response.data;
  }
}

// CORE: Repository pattern with auth
class DioClient {
  // Auto-refresh tokens, logging, error handling
}

// FULL: Advanced caching and monitoring
class AdvancedDioClient {
  // Retry logic, caching, performance monitoring
}
```

## 🎨 Design System Integration

### **Theming Strategy**
```dart
// MVP: Material defaults
ThemeData(primarySwatch: Colors.blue)

// CORE: Custom theme with dark/light
class AppTheme {
  static ThemeData light = ThemeData(/* custom light theme */);
  static ThemeData dark = ThemeData(/* custom dark theme */);
}

// FULL: Enterprise design system
class DesignSystem {
  static ColorPalette colors = ColorPalette();
  static TextStyles typography = TextStyles();
  static Spacing spacing = Spacing();
  // Component variants, animation curves, etc.
}
```

### **Component Library**
- **MVP**: Use Material components directly
- **CORE**: Wrap Material components in branded widgets
- **FULL**: Complete component library with design tokens

## 🧪 Testing Strategy by Tier

### **MVP Testing**
- Widget tests for critical UI components
- Simple state testing
- No integration tests

### **CORE Testing**
- Unit tests for business logic
- Widget tests for all components
- Integration tests for critical flows
- Golden tests for UI consistency

### **FULL Testing**
- All CORE tests plus:
- Performance tests
- Accessibility tests
- Memory leak tests
- End-to-end tests

## 📊 Analytics and Monitoring

### **MVP**: Basic crash reporting
### **CORE**: User analytics + error tracking
### **FULL**: Complete observability stack
- Custom events
- Performance monitoring
- User session recording
- A/B testing integration

## 🔗 Integration Patterns

### **Backend Integration**
- **REST APIs**: dio + repository pattern
- **GraphQL**: flutter_graphql + code generation
- **WebSocket**: stream-based state management

### **Native Integration**
- **Platform Channels**: For native APIs
- **Method Channels**: Simple native calls
- **Event Channels**: Native-to-Flutter streams

### **Third-party Services**
- **Firebase**: Analytics, Crashlytics, Remote Config
- **AWS**: S3, Cognito, Lambda integration
- **Custom APIs**: Standardized client patterns

## 🚀 Performance Guidelines

### **MVP**: Focus on functionality
### **CORE**: Optimize critical paths
- Image optimization
- Lazy loading
- Efficient state updates

### **FULL**: Performance excellence
- Advanced caching strategies
- Background processing
- Memory optimization
- Network optimization

---
*Flutter Framework Patterns - Use this as your canonical reference for all Flutter development*
