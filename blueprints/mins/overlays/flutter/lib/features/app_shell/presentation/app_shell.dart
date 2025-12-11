/// App Shell - Main application container with navigation
/// 
/// Provides:
/// - Bottom navigation bar
/// - Ad banner slot (hidden for premium users)
/// - Page routing
/// 
/// CONFIDENTIAL - INTERNAL USE ONLY
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../services/purchase/purchase_service.dart';
import '../../../widgets/ad_banner_slot.dart';
import '../../home/presentation/home_page.dart';
import '../../settings/presentation/settings_page.dart';

/// App router provider
final appRouterProvider = Provider<GoRouter>((ref) {
  return GoRouter(
    initialLocation: '/',
    routes: [
      ShellRoute(
        builder: (context, state, child) => AppShell(child: child),
        routes: [
          GoRoute(
            path: '/',
            name: 'home',
            pageBuilder: (context, state) => const NoTransitionPage(
              child: HomePage(),
            ),
          ),
          GoRoute(
            path: '/settings',
            name: 'settings',
            pageBuilder: (context, state) => const NoTransitionPage(
              child: SettingsPage(),
            ),
          ),
        ],
      ),
    ],
  );
});

/// Navigation state provider
final navigationIndexProvider = StateProvider<int>((ref) => 0);

/// Main app shell widget
class AppShell extends ConsumerWidget {
  
  const AppShell({
    required this.child, super.key,
  });
  final Widget child;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final navigationIndex = ref.watch(navigationIndexProvider);
    final purchaseState = ref.watch(purchaseServiceProvider);
    
    return Scaffold(
      body: Column(
        children: [
          // Main content
          Expanded(child: child),
          
          // Ad banner (hidden for premium users) - KEY MINS PATTERN
          if (!purchaseState.isPremium)
            const AdBannerSlot(),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: navigationIndex,
        onDestinationSelected: (index) {
          ref.read(navigationIndexProvider.notifier).state = index;
          
          switch (index) {
            case 0:
              context.goNamed('home');
            case 1:
              context.goNamed('settings');
          }
        },
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.home_outlined),
            selectedIcon: Icon(Icons.home),
            label: 'Home',
          ),
          NavigationDestination(
            icon: Icon(Icons.settings_outlined),
            selectedIcon: Icon(Icons.settings),
            label: 'Settings',
          ),
        ],
      ),
    );
  }
}
