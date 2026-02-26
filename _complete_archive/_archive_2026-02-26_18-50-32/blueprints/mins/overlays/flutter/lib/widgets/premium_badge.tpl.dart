// Universal Template System - Mins Blueprint - Flutter Premium Badge Template
// Stack: Flutter
// Purpose: Visual indicator for premium features
// Project: {{PROJECT_NAME}}

import 'package:flutter/material.dart';

/// Premium badge widget for MINS apps
/// 
/// Used to indicate premium-only features in the UI
class PremiumBadge extends StatelessWidget {
  final String? text;
  
  const PremiumBadge({super.key, this.text});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [Colors.amber.shade600, Colors.orange.shade600],
        ),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.star, size: 16, color: Colors.white),
          const SizedBox(width: 4),
          Text(
            text ?? 'PRO',
            style: const TextStyle(
              color: Colors.white,
              fontWeight: FontWeight.bold,
              fontSize: 12,
            ),
          ),
        ],
      ),
    );
  }
}
