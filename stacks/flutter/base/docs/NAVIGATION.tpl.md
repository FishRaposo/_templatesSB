# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: flutter template utilities
# Tier: base
# Stack: flutter
# Category: template

# {{PROJECT_NAME}} - Flutter Navigation

**Tier**: {{TIER}} | **Stack**: Flutter

## 🧭 Blessed Navigation: go_router

### **Why go_router**
- Declarative routing
- Deep linking support
- URL-based navigation
- Type safety
- Excellent state restoration

## 📱 MVP Tier - Simple Navigation

### **Basic Router Setup**
```dart
// lib/core/router/app_router.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../features/home/presentation/pages/home_page.dart';
import '../features/profile/presentation/pages/profile_page.dart';

final appRouter = GoRouter(
  initialLocation: '/home',
  routes: [
    GoRoute(
      path: '/home',
      builder: (context, state) => const HomePage(),
    ),
    GoRoute(
      path: '/profile',
      builder: (context, state) => const ProfilePage(),
    ),
  ],
);
```

### **Navigation Usage**
```dart
// In any widget
context.go('/profile');  // Navigate to profile
context.push('/settings');  // Push to stack
context.pop();  // Go back
```

## 🏗️ CORE Tier - Feature Navigation

### **Router with Guards and Nested Routes**
```dart
// lib/core/router/app_router.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../features/authentication/presentation/providers/auth_provider.dart';
import '../features/authentication/presentation/pages/login_page.dart';
import '../features/home/presentation/pages/home_page.dart';
import '../features/profile/presentation/pages/profile_page.dart';

class AppRouter {
  static GoRouter createRouter() {
    return GoRouter(
      initialLocation: '/home',
      redirect: (context, state) {
        final authState = context.read(authProvider);
        final isAuthenticated = authState.user != null;
        
        // Protect routes
        if (!isAuthenticated && !state.location.startsWith('/login')) {
          return '/login';
        }
        
        if (isAuthenticated && state.location.startsWith('/login')) {
          return '/home';
        }
        
        return null;
      },
      routes: [
        // Authentication
        GoRoute(
          path: '/login',
          builder: (context, state) => const LoginPage(),
        ),
        
        // Main app with shell
        ShellRoute(
          builder: (context, state, child) => MainShell(child: child),
          routes: [
            GoRoute(
              path: '/home',
              builder: (context, state) => const HomePage(),
            ),
            GoRoute(
              path: '/profile',
              builder: (context, state) => const ProfilePage(),
            ),
            GoRoute(
              path: '/profile/:userId',
              builder: (context, state) {
                final userId = state.pathParameters['userId']!;
                return ProfilePage(userId: userId);
              },
            ),
          ],
        ),
      ],
    );
  }
}
```

### **Main Shell Component**
```dart
// lib/shared/widgets/main_shell.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class MainShell extends ConsumerWidget {
  final Widget child;
  
  const MainShell({super.key, required this.child});
  
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final router = GoRouter.of(context);
    final currentIndex = _getCurrentIndex(router.routeInformationProvider.value.uri.path);
    
    return Scaffold(
      body: child,
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: currentIndex,
        onTap: (index) {
          switch (index) {
            case 0:
              context.go('/home');
              break;
            case 1:
              context.go('/profile');
              break;
          }
        },
        items: const [
          BottomNavigationBarItem(
            icon: Icon(Icons.home),
            label: 'Home',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.person),
            label: 'Profile',
          ),
        ],
      ),
    );
  }
  
  int _getCurrentIndex(String path) {
    if (path.startsWith('/home')) return 0;
    if (path.startsWith('/profile')) return 1;
    return 0;
  }
}
```

## 🚀 FULL Tier - Advanced Navigation

### **Enterprise Router with Deep Links and Analytics**
```dart
// lib/core/router/app_router.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../features/authentication/presentation/providers/auth_provider.dart';
import '../infrastructure/analytics/analytics_service.dart';
import '../infrastructure/monitoring/error_handler.dart';

class AppRouter {
  static GoRouter createRouter({
    required AnalyticsService analytics,
    required ErrorHandler errorHandler,
  }) {
    return GoRouter(
      initialLocation: '/home',
      errorBuilder: (context, state) => ErrorPage(error: state.error),
      observers: [
        GoRouterObserver(analytics: analytics),
      ],
      redirect: (context, state) {
        return _handleRedirect(context, state);
      },
      routes: [
        // Authentication flows
        GoRoute(
          path: '/login',
          builder: (context, state) => const LoginPage(),
        ),
        GoRoute(
          path: '/register',
          builder: (context, state) => const RegisterPage(),
        ),
        GoRoute(
          path: '/forgot-password',
          builder: (context, state) => const ForgotPasswordPage(),
        ),
        
        // Main application
        ShellRoute(
          builder: (context, state, child) => MainShell(child: child),
          routes: [
            // Home section
            GoRoute(
              path: '/home',
              builder: (context, state) => const HomePage(),
            ),
            
            // Profile section with nested routes
            GoRoute(
              path: '/profile',
              builder: (context, state) => const ProfilePage(),
              routes: [
                GoRoute(
                  path: '/edit',
                  builder: (context, state) => const EditProfilePage(),
                ),
                GoRoute(
                  path: '/:userId',
                  builder: (context, state) {
                    final userId = state.pathParameters['userId']!;
                    return ProfilePage(userId: userId);
                  },
                ),
              ],
            ),
            
            // Settings section
            GoRoute(
              path: '/settings',
              builder: (context, state) => const SettingsPage(),
              routes: [
                GoRoute(
                  path: '/notifications',
                  builder: (context, state) => const NotificationSettingsPage(),
                ),
                GoRoute(
                  path: '/privacy',
                  builder: (context, state) => const PrivacySettingsPage(),
                ),
              ],
            ),
          ],
        ),
        
        // Deep link routes
        GoRoute(
          path: '/invite/:token',
          builder: (context, state) {
            final token = state.pathParameters['token']!;
            return InvitePage(token: token);
          },
        ),
      ],
    );
  }
  
  static String? _handleRedirect(BuildContext context, GoRouterState state) {
    final authState = context.read(authProvider);
    final isAuthenticated = authState.user != null;
    final path = state.location;
    
    // Public routes
    final publicRoutes = ['/login', '/register', '/forgot-password'];
    
    if (!isAuthenticated && !publicRoutes.any(route => path.startsWith(route))) {
      return '/login';
    }
    
    if (isAuthenticated && publicRoutes.any(route => path.startsWith(route))) {
      return '/home';
    }
    
    return null;
  }
}
```

### **Router Observer for Analytics**
```dart
// lib/core/router/router_observer.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../infrastructure/analytics/analytics_service.dart';

class GoRouterObserver extends NavigatorObserver {
  final AnalyticsService analytics;
  
  GoRouterObserver({required this.analytics});
  
  @override
  void didPush(Route<dynamic> route, Route<dynamic>? previousRoute) {
    super.didPush(route, previousRoute);
    _trackRoute(route);
  }
  
  @override
  void didReplace({Route<dynamic>? newRoute, Route<dynamic>? oldRoute}) {
    super.didReplace(newRoute: newRoute, oldRoute: oldRoute);
    if (newRoute != null) {
      _trackRoute(newRoute);
    }
  }
  
  void _trackRoute(Route<dynamic> route) {
    final name = route.settings.name;
    if (name != null) {
      analytics.trackScreenView(name);
    }
  }
}
```

## 🔗 Deep Linking Template

### **Deep Link Configuration**
```dart
// lib/core/services/deep_link_service.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:uni_links/uni_links.dart';

class DeepLinkService {
  final GoRouter router;
  
  DeepLinkService({required this.router}) {
    _initDeepLinks();
  }
  
  Future<void> _initDeepLinks() async {
    // App links
    uriLinkStream.listen((Uri? uri) {
      if (uri != null) {
        _handleDeepLink(uri);
      }
    });
    
    // Initial link
    final initialUri = await getInitialUri();
    if (initialUri != null) {
      _handleDeepLink(initialUri);
    }
  }
  
  void _handleDeepLink(Uri uri) {
    switch (uri.path) {
      case '/invite':
        final token = uri.queryParameters['token'];
        if (token != null) {
          router.go('/invite/$token');
        }
        break;
      case '/profile':
        final userId = uri.queryParameters['userId'];
        if (userId != null) {
          router.go('/profile/$userId');
        }
        break;
      default:
        router.go('/home');
    }
  }
}
```

## 🧪 Navigation Testing Template

### **Router Testing**
```dart
// test/unit/router/app_router_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:mockito/mockito.dart';

void main() {
  group('AppRouter', () {
    late ProviderContainer container;
    late MockAuthRepository mockAuthRepository;
    
    setUp(() {
      mockAuthRepository = MockAuthRepository();
      container = ProviderContainer(overrides: [
        authRepositoryProvider.overrideWithValue(mockAuthRepository),
      ]);
    });
    
    testWidgets('should redirect to login when not authenticated', (tester) async {
      // Arrange
      final router = AppRouter.createRouter();
      
      // Act
      await tester.pumpWidget(
        ProviderScope(
          parent: container,
          child: MaterialApp.router(
            routerConfig: router,
          ),
        ),
      );
      
      // Assert
      expect(find.text('Login Page'), findsOneWidget);
    });
    
    testWidgets('should navigate to profile when authenticated', (tester) async {
      // Arrange
      when(mockAuthRepository.getCurrentUser())
          .thenReturn(AuthUser(id: '1', email: 'test@example.com'));
      
      final router = AppRouter.createRouter();
      
      // Act
      await tester.pumpWidget(
        ProviderScope(
          parent: container,
          child: MaterialApp.router(
            routerConfig: router,
          ),
        ),
      );
      
      // Assert
      expect(find.text('Home Page'), findsOneWidget);
      
      // Navigate to profile
      router.go('/profile');
      await tester.pumpAndSettle();
      
      expect(find.text('Profile Page'), findsOneWidget);
    });
  });
}
```

## 📱 Navigation Best Practices

### **1. Use Type-Safe Routing**
- Define routes as constants
- Use path parameters for dynamic data
- Validate parameters in builders

### **2. Implement Proper Guards**
- Authentication checks
- Authorization checks
- Role-based access

### **3. Handle Deep Links**
- Register URL schemes
- Parse parameters safely
- Handle invalid links gracefully

### **4. Track Navigation**
- Analytics integration
- Error reporting
- Performance monitoring

### **5. Test Navigation Scenarios**
- Authentication flows
- Deep link handling
- Error states
- Route transitions

---

**Flutter Version**: [FLUTTER_VERSION]  
**Dart Version**: [DART_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
