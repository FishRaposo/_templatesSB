#!/usr/bin/env python3
"""
Shared stack configuration for all utility scripts
Standardizes the list of supported stacks across the template system
"""

# Standard stack list - matches SYSTEM-MAP and generate_reference_projects.py
STACKS = ['flutter', 'react_native', 'react', 'next', 'node', 'go', 'python', 'r', 'sql', 'generic', 'typescript', 'rust']

# Stack display names for user interfaces
STACK_DISPLAY_NAMES = {
    'flutter': 'Flutter',
    'react_native': 'React Native',
    'react': 'React',
    'next': 'Next.js',
    'node': 'Node.js',
    'go': 'Go',
    'python': 'Python',
    'r': 'R',
    'sql': 'SQL',
    'generic': 'Generic',
    'typescript': 'TypeScript',
    'rust': 'Rust'
}

# Stack categories for organization
STACK_CATEGORIES = {
    'mobile': ['flutter', 'react_native'],
    'web_frontend': ['react', 'next'],
    'web_backend': ['node', 'go', 'python', 'typescript', 'rust'],
    'data': ['r', 'sql'],
    'universal': ['generic']
}

# Tier list
TIERS = ['mvp', 'core', 'enterprise']

# Tier display names
TIER_DISPLAY_NAMES = {
    'mvp': 'MVP',
    'core': 'Core',
    'enterprise': 'Enterprise'
}

def get_all_stacks():
    """Get the complete list of supported stacks"""
    return STACKS.copy()

def get_stack_display_name(stack_key):
    """Get display name for a stack"""
    return STACK_DISPLAY_NAMES.get(stack_key, stack_key.title())

def get_stacks_by_category(category):
    """Get stacks belonging to a specific category"""
    return STACK_CATEGORIES.get(category, [])

def validate_stack(stack_key):
    """Check if a stack is valid"""
    return stack_key in STACKS

def validate_tier(tier_key):
    """Check if a tier is valid"""
    return tier_key in TIERS

def get_all_tiers():
    """Get the complete list of supported tiers"""
    return TIERS.copy()

def get_tier_display_name(tier_key):
    """Get display name for a tier"""
    return TIER_DISPLAY_NAMES.get(tier_key, tier_key.title())
