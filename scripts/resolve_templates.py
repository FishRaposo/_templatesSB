#!/usr/bin/env python3
"""
Template Resolution Engine

Purpose: Resolve templates from universal/tiers/stacks hierarchy into project files.
Usage: python scripts/resolve_templates.py --tier core --stack python,flutter --output /tmp/my-project

Resolution Logic:
effective_templates = universal + tier + all(stack_overlays)
Precedence: stack/{tier}/ > stack/base/ > tiers/{tier}/ > universal/
"""

import os
import sys
import argparse
import shutil
from pathlib import Path
from typing import List, Dict, Set

def list_templates(directory: str) -> List[str]:
    """List all template files in a directory."""
    templates = []
    if os.path.exists(directory):
        for root, dirs, files in os.walk(directory):
            for file in files:
                if '.tpl.' in file:  # Look for .tpl. in filename (e.g., README.tpl.md)
                    rel_path = os.path.relpath(os.path.join(root, file), directory)
                    templates.append(rel_path)
    return templates

def collect_templates(tier: str, stacks: List[str], base_dir: str = ".") -> Dict[str, str]:
    """
    Collect templates following the resolution algorithm.
    
    Args:
        tier: Target tier (mvp, core, enterprise)
        stacks: List of target stacks
        base_dir: Base directory containing templates
    
    Returns:
        Dict mapping template paths to their source files
    """
    templates = {}
    
    # 1) universal templates (lowest precedence)
    for category in ['docs', 'code', 'tests', 'scripts']:
        universal_dir = os.path.join(base_dir, 'universal', category)
        if os.path.exists(universal_dir):
            for template in list_templates(universal_dir):
                rel_path = os.path.join(category, template)
                templates[rel_path] = os.path.join(universal_dir, template)
    
    # 2) tier-specific templates (override universal)
    for category in ['docs', 'code', 'tests', 'scripts']:
        tier_dir = os.path.join(base_dir, 'tiers', tier, category)
        if os.path.exists(tier_dir):
            for template in list_templates(tier_dir):
                rel_path = os.path.join(category, template)
                templates[rel_path] = os.path.join(tier_dir, template)
    
    # 3) stack-specific templates (highest precedence)
    for stack in stacks:
        # base stack templates
        for category in ['docs', 'code', 'tests', 'scripts']:
            stack_base_dir = os.path.join(base_dir, 'stacks', stack, 'base', category)
            if os.path.exists(stack_base_dir):
                for template in list_templates(stack_base_dir):
                    rel_path = os.path.join(category, template)
                    templates[rel_path] = os.path.join(stack_base_dir, template)
        
        # tier-specific stack templates
        for category in ['docs', 'code', 'tests', 'scripts']:
            stack_tier_dir = os.path.join(base_dir, 'stacks', stack, tier, category)
            if os.path.exists(stack_tier_dir):
                for template in list_templates(stack_tier_dir):
                    rel_path = os.path.join(category, template)
                    templates[rel_path] = os.path.join(stack_tier_dir, template)
    
    return templates

def interpolate_variables(content: str, variables: Dict[str, str]) -> str:
    """Replace template variables with actual values."""
    for key, value in variables.items():
        content = content.replace(f"{{{{{key}}}}}", value)
    return content

def resolve_template_filename(template_file: str) -> str:
    """Convert .tpl.* filename to final filename."""
    if '.tpl.' in template_file:
        return template_file.replace('.tpl.', '.')
    return template_file

def resolve_templates(tier: str, stacks: List[str], output_dir: str, 
                     variables: Dict[str, str] = None, base_dir: str = "."):
    """
    Resolve and materialize templates into output directory.
    
    Args:
        tier: Target tier
        stacks: List of target stacks
        output_dir: Output directory for resolved files
        variables: Template variables for interpolation
        base_dir: Base directory containing templates
    """
    if variables is None:
        variables = {}
    
    # Ensure variables have defaults
    variables.setdefault('TIER', tier.upper())
    variables.setdefault('STACKS', ','.join(stacks))
    variables.setdefault('PROJECT_NAME', 'my-project')
    
    # Collect templates with proper precedence
    templates = collect_templates(tier, stacks, base_dir)
    
    print(f"Resolving {len(templates)} templates for tier={tier}, stacks={stacks}")
    print(f"Output directory: {output_dir}")
    print()
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Materialize templates
    for rel_path, source_file in templates.items():
        # Read template content
        with open(source_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Interpolate variables
        content = interpolate_variables(content, variables)
        
        # Resolve final filename
        final_filename = resolve_template_filename(rel_path)
        output_path = os.path.join(output_dir, final_filename)
        
        # Create output subdirectory if needed
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Write resolved file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"  {rel_path} -> {final_filename}")
    
    print()
    print(f"✅ Successfully resolved {len(templates)} templates to {output_dir}")
    
    # Generate resolution report
    report_path = os.path.join(output_dir, '.template-resolution-report.txt')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(f"Template Resolution Report\n")
        f.write(f"========================\n\n")
        f.write(f"Tier: {tier}\n")
        f.write(f"Stacks: {', '.join(stacks)}\n")
        f.write(f"Variables: {variables}\n\n")
        f.write(f"Resolved Templates:\n")
        for rel_path, source_file in sorted(templates.items()):
            f.write(f"  {rel_path} <- {source_file}\n")
    
    print(f"📄 Resolution report written to: {report_path}")

def main():
    parser = argparse.ArgumentParser(description='Resolve templates from hierarchical structure')
    parser.add_argument('--tier', required=True, choices=['mvp', 'core', 'enterprise'],
                       help='Target tier for template resolution')
    parser.add_argument('--stack', required=True,
                       help='Comma-separated list of target stacks')
    parser.add_argument('--output', required=True,
                       help='Output directory for resolved templates')
    parser.add_argument('--project-name', default='my-project',
                       help='Project name for template variables')
    parser.add_argument('--base-dir', default='.',
                       help='Base directory containing templates')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be resolved without writing files')
    
    args = parser.parse_args()
    
    stacks = [s.strip() for s in args.stack.split(',')]
    variables = {
        'PROJECT_NAME': args.project_name,
        'TIER': args.tier.upper(),
        'STACKS': ','.join(stacks)
    }
    
    if args.dry_run:
        templates = collect_templates(args.tier, stacks, args.base_dir)
        print(f"DRY RUN: Would resolve {len(templates)} templates")
        print(f"Tier: {args.tier}")
        print(f"Stacks: {stacks}")
        print(f"Output: {args.output}")
        print("\nTemplates to be resolved:")
        for rel_path, source_file in sorted(templates.items()):
            print(f"  {rel_path} <- {source_file}")
    else:
        resolve_templates(
            tier=args.tier,
            stacks=stacks,
            output_dir=args.output,
            variables=variables,
            base_dir=args.base_dir
        )

if __name__ == '__main__':
    main()
