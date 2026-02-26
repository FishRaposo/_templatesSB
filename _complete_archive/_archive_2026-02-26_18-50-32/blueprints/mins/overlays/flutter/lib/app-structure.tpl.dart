// -----------------------------------------------------------------------------
// FILE: app-structure.tpl.dart
// PURPOSE: MINS blueprint Flutter app structure for single-purpose micro-SaaS applications
// USAGE: Copy and adapt for MINS blueprint Flutter projects
// AUTHOR: {{AUTHOR}}
// VERSION: {{VERSION}}
// SINCE: {{VERSION}}
// -----------------------------------------------------------------------------

// MINS Blueprint Flutter App Structure
// Single-purpose micro-SaaS application template

import 'package:flutter/material.dart';

// Core MINS app structure with minimal navigation
class {{PROJECT_NAME}}App extends StatelessWidget {
  const {{PROJECT_NAME}}App({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '{{PROJECT_NAME}}',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        // Minimal, clean design for single-purpose app
        visualDensity: VisualDensity.compact,
      ),
      home: const {{PROJECT_NAME}}HomePage(),
      routes: _buildRoutes(),
    );
  }

  Map<String, WidgetBuilder> _buildRoutes() {
    return {
      '/': (context) => const {{PROJECT_NAME}}HomePage(),
      '/feature': (context) => const {{PROJECT_NAME}}FeaturePage(),
      '/settings': (context) => const {{PROJECT_NAME}}SettingsPage(),
      '/premium': (context) => const {{PROJECT_NAME}}PremiumPage(),
    };
  }
}

// Minimal home screen focused on single feature
class {{PROJECT_NAME}}HomePage extends StatelessWidget {
  const {{PROJECT_NAME}}HomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('{{PROJECT_NAME}}'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () => Navigator.pushNamed(context, '/settings'),
          ),
        ],
      ),
      body: const {{PROJECT_NAME}}MainFeature(),
      bottomNavigationBar: const {{PROJECT_NAME}}BottomNav(),
    );
  }
}

// Core feature widget - this is where the main functionality goes
class {{PROJECT_NAME}}MainFeature extends StatefulWidget {
  const {{PROJECT_NAME}}MainFeature({super.key});

  @override
  State<{{PROJECT_NAME}}MainFeature> createState() => _{{PROJECT_NAME}}MainFeatureState();
}

class _{{PROJECT_NAME}}MainFeatureState extends State<{{PROJECT_NAME}}MainFeature> {
  // TODO: Implement your single primary feature here
  // Remember: Keep it simple, focused, and valuable
  
  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.star,
            size: 100,
            color: Colors.blue,
          ),
          SizedBox(height: 20),
          Text(
            '{{CORE_FEATURE_NAME}}',
            style: TextStyle(
              fontSize: 24,
              fontWeight: FontWeight.bold,
            ),
          ),
          SizedBox(height: 10),
          Text(
            '{{CORE_FEATURE_DESCRIPTION}}',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 16),
          ),
        ],
      ),
    );
  }
}

// Minimal bottom navigation for MINS pattern
class {{PROJECT_NAME}}BottomNav extends StatelessWidget {
  const {{PROJECT_NAME}}BottomNav({super.key});

  @override
  Widget build(BuildContext context) {
    return BottomNavigationBar(
      items: const [
        BottomNavigationBarItem(
          icon: Icon(Icons.home),
          label: 'Home',
        ),
        BottomNavigationBarItem(
          icon: Icon(Icons.featured_play_list),
          label: 'Feature',
        ),
        BottomNavigationBarItem(
          icon: Icon(Icons.diamond),
          label: 'Premium',
        ),
      ],
      onTap: (index) {
        switch (index) {
          case 0:
            Navigator.pushReplacementNamed(context, '/');
            break;
          case 1:
            Navigator.pushReplacementNamed(context, '/feature');
            break;
          case 2:
            Navigator.pushReplacementNamed(context, '/premium');
            break;
        }
      },
    );
  }
}

// Feature page - extends core functionality
class {{PROJECT_NAME}}FeaturePage extends StatelessWidget {
  const {{PROJECT_NAME}}FeaturePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('{{FEATURE_PAGE_TITLE}}'),
      ),
      body: const Center(
        child: Text('Extended feature functionality'),
      ),
    );
  }
}

// Settings page - minimal configuration
class {{PROJECT_NAME}}SettingsPage extends StatelessWidget {
  const {{PROJECT_NAME}}SettingsPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
      ),
      body: ListView(
        children: [
          ListTile(
            title: const Text('About'),
            subtitle: const Text('{{PROJECT_NAME}} v1.0'),
            onTap: () {
              // Show about dialog
            },
          ),
          ListTile(
            title: const Text('Privacy Policy'),
            onTap: () {
              // Show privacy policy
            },
          ),
          ListTile(
            title: const Text('Restore Purchases'),
            onTap: () {
              // Restore premium purchases
            },
          ),
        ],
      ),
    );
  }
}

// Premium page - paywall for extended features
class {{PROJECT_NAME}}PremiumPage extends StatelessWidget {
  const {{PROJECT_NAME}}PremiumPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Go Premium'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(
              Icons.diamond,
              size: 100,
              color: Colors.amber,
            ),
            const SizedBox(height: 20),
            const Text(
              'Unlock Premium Features',
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 10),
            const Text(
              'Get {{PREMIUM_FEATURE_COUNT}} premium features for a one-time payment of $9.99',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 16),
            ),
            const SizedBox(height: 30),
            ElevatedButton(
              onPressed: () {
                // Handle premium purchase
              },
              child: const Text('Buy Premium - $9.99'),
            ),
            const SizedBox(height: 10),
            TextButton(
              onPressed: () {
                // Restore purchases
              },
              child: const Text('Restore Purchases'),
            ),
          ],
        ),
      ),
    );
  }
}