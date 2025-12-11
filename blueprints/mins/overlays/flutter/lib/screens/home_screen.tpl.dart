// Universal Template System - Mins Blueprint - Flutter Home Screen Template
// Stack: Flutter
// Purpose: Main home screen for MINS micro-SaaS apps

import 'package:flutter/material.dart';

/// Home screen for {{PROJECT_NAME}}
/// 
/// MINS Pattern: Single-purpose, minimal UI with clear CTA
class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('{{PROJECT_NAME}}'),
        actions: [
          // Minimal settings access
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () => _openSettings(context),
          ),
        ],
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // Core feature area
            const Expanded(
              child: _CoreFeatureWidget(),
            ),
            // CTA for premium/upgrade
            _PremiumCTA(),
          ],
        ),
      ),
    );
  }

  void _openSettings(BuildContext context) {
    // Navigate to settings
    Navigator.pushNamed(context, '/settings');
  }
}

class _CoreFeatureWidget extends StatelessWidget {
  const _CoreFeatureWidget();

  @override
  Widget build(BuildContext context) {
    // TODO: Implement core feature UI
    return const Center(
      child: Text('Core Feature Here'),
    );
  }
}

class _PremiumCTA extends StatelessWidget {
  const _PremiumCTA();

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      child: ElevatedButton(
        onPressed: () => _showUpgrade(context),
        child: const Text('Upgrade to Pro'),
      ),
    );
  }

  void _showUpgrade(BuildContext context) {
    // Show upgrade/paywall dialog
    showDialog(
      context: context,
      builder: (context) => const _UpgradeDialog(),
    );
  }
}

class _UpgradeDialog extends StatelessWidget {
  const _UpgradeDialog();

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Upgrade to Pro'),
      content: const Text('Unlock all features with a one-time purchase.'),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: () {
            // TODO: Implement purchase flow
            Navigator.pop(context);
          },
          child: const Text('Purchase'),
        ),
      ],
    );
  }
}
