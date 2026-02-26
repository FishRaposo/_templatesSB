#!/usr/bin/env python3
"""
Blueprint Listing Script

Lists all available blueprints with their metadata and capabilities.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys

class BlueprintLister:
    def __init__(self, templates_root: Path):
        self.templates_root = templates_root
        self.blueprints_dir = templates_root / "blueprints"
        self.stacks_dir = templates_root / "stacks"

    def list_all(self, detailed: bool = False) -> Dict[str, Any]:
        """List all blueprints with their metadata."""
        print("📋 Available Blueprints")
        print("=" * 50)
        
        if not self.blueprints_dir.exists():
            print("❌ Blueprints directory not found")
            return {}
        
        # Discover blueprints
        blueprint_dirs = [d for d in self.blueprints_dir.iterdir() 
                         if d.is_dir() and not d.name.startswith('.')]
        
        blueprints = {}
        
        for blueprint_dir in sorted(blueprint_dirs):
            blueprint_name = blueprint_dir.name
            metadata = self.load_blueprint_metadata(blueprint_dir)
            
            if metadata:
                blueprints[blueprint_name] = metadata
                self.print_blueprint_summary(blueprint_name, metadata, detailed)
        
        # Print summary
        print(f"\n📊 Summary: {len(blueprints)} blueprints found")
        
        # Print stack coverage
        self.print_stack_coverage(blueprints)
        
        return blueprints

    def load_blueprint_metadata(self, blueprint_dir: Path) -> Optional[Dict[str, Any]]:
        """Load blueprint metadata from YAML file."""
        meta_path = blueprint_dir / "blueprint.meta.yaml"
        
        if not meta_path.exists():
            print(f"⚠️  {blueprint_dir.name}: Missing metadata file")
            return None
        
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"⚠️  {blueprint_dir.name}: Error loading metadata: {e}")
            return None

    def print_blueprint_summary(self, blueprint_name: str, metadata: Dict[str, Any], detailed: bool = False):
        """Print a summary of a blueprint."""
        print(f"\n🏗️  {metadata.get('name', blueprint_name)}")
        print(f"   ID: {blueprint_name}")
        print(f"   Category: {metadata.get('category', 'Unknown')}")
        print(f"   Type: {metadata.get('type', 'Unknown')}")
        
        # Print description (truncated)
        description = metadata.get('description', '').strip()
        if description:
            # Split description into lines and take first 2
            desc_lines = description.split('\n')
            short_desc = desc_lines[0][:100] + ('...' if len(desc_lines[0]) > 100 else '')
            print(f"   Description: {short_desc}")
        
        # Print stack support
        stacks = metadata.get('stacks', {})
        required = stacks.get('required', [])
        recommended = stacks.get('recommended', [])
        supported = stacks.get('supported', [])
        
        print(f"   Stacks: Required={required}, Recommended={recommended}, Supported={supported}")
        
        if detailed:
            # Print detailed information
            print(f"   Version: {metadata.get('version', 'Unknown')}")
            
            # Print tasks
            tasks = metadata.get('tasks', {})
            if tasks:
                print(f"   Tasks:")
                for task_type in ['required', 'recommended', 'optional']:
                    if task_type in tasks and tasks[task_type]:
                        print(f"     {task_type.title()}: {', '.join(tasks[task_type])}")
            
            # Print constraints
            constraints = metadata.get('constraints', {})
            if constraints:
                print(f"   Constraints:")
                for key, value in constraints.items():
                    print(f"     {key}: {value}")
            
            # Print overlays
            overlays_dir = self.blueprints_dir / blueprint_name / "overlays"
            if overlays_dir.exists():
                overlay_stacks = [d.name for d in overlays_dir.iterdir() if d.is_dir()]
                if overlay_stacks:
                    print(f"   Overlays: {', '.join(overlay_stacks)}")

    def print_stack_coverage(self, blueprints: Dict[str, Any]):
        """Print stack coverage statistics."""
        print("\n📊 Stack Coverage")
        print("-" * 30)
        
        # Count blueprint support for each stack
        stack_counts = {}
        available_stacks = []
        
        if self.stacks_dir.exists():
            available_stacks = [d.name for d in self.stacks_dir.iterdir() 
                               if d.is_dir() and not d.name.startswith('.')]
        
        for stack_name in available_stacks:
            stack_counts[stack_name] = 0
        
        for blueprint_name, metadata in blueprints.items():
            stacks = metadata.get('stacks', {})
            for stack_type in ['required', 'recommended', 'supported']:
                for stack_name in stacks.get(stack_type, []):
                    if stack_name in stack_counts:
                        stack_counts[stack_name] += 1
        
        # Print coverage
        for stack_name in sorted(available_stacks):
            count = stack_counts.get(stack_name, 0)
            percentage = (count / len(blueprints)) * 100 if blueprints else 0
            print(f"  {stack_name:15}: {count:2}/{len(blueprints):2} blueprints ({percentage:.0f}%)")

    def list_by_category(self, category: str = None):
        """List blueprints by category."""
        blueprints = self.list_all()
        
        if category:
            filtered = {name: meta for name, meta in blueprints.items() 
                       if meta.get('category') == category}
            print(f"\n🏷️  Category: {category}")
            print("=" * 50)
            for name, meta in filtered.items():
                print(f"  • {meta.get('name', name)} ({name})")
        else:
            # Group by category
            categories = {}
            for name, meta in blueprints.items():
                cat = meta.get('category', 'Unknown')
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append((name, meta))
            
            print("\n🏷️  Blueprints by Category")
            print("=" * 50)
            for cat, items in sorted(categories.items()):
                print(f"\n{cat.title()} ({len(items)}):")
                for name, meta in items:
                    print(f"  • {meta.get('name', name)} ({name})")

    def list_by_stack(self, stack_name: str):
        """List blueprints that support a specific stack."""
        blueprints = self.list_all()
        
        print(f"\n🔧 Blueprints supporting '{stack_name}'")
        print("=" * 50)
        
        supported = []
        for name, meta in blueprints.items():
            stacks = meta.get('stacks', {})
            for stack_type in ['required', 'recommended', 'supported']:
                if stack_name in stacks.get(stack_type, []):
                    supported.append((name, meta, stack_type))
                    break
        
        if supported:
            for name, meta, support_type in supported:
                print(f"  • {meta.get('name', name)} ({name}) - {support_type}")
        else:
            print(f"  No blueprints found supporting '{stack_name}'")

def main():
    """Main listing script."""
    templates_root = Path(__file__).parent.parent
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "--help":
            print("Usage: python list_blueprints.py [command] [options]")
            print("Commands:")
            print("  (no args)    List all blueprints")
            print("  --detailed   Show detailed information")
            print("  --category   List by category")
            print("  --stack      List blueprints supporting a stack")
            return
        
        lister = BlueprintLister(templates_root)
        
        if command == "--detailed":
            lister.list_all(detailed=True)
        elif command == "--category":
            if len(sys.argv) > 2:
                lister.list_by_category(sys.argv[2])
            else:
                lister.list_by_category()
        elif command == "--stack":
            if len(sys.argv) > 2:
                lister.list_by_stack(sys.argv[2])
            else:
                print("Error: Stack name required")
                print("Usage: python list_blueprints.py --stack <stack_name>")
        else:
            print(f"Unknown command: {command}")
            print("Use --help for usage information")
    else:
        # Default: list all blueprints
        lister = BlueprintLister(templates_root)
        lister.list_all()

if __name__ == "__main__":
    main()
