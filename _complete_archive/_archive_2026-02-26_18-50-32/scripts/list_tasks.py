#!/usr/bin/env python3
"""
Task Listing Script

Lists all available tasks with their metadata, categories, and stack support.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import sys

class TaskLister:
    def __init__(self, templates_root: Path):
        self.templates_root = templates_root
        self.tasks_dir = templates_root / "tasks"
        self.stacks_dir = templates_root / "stacks"

    def list_all(self, detailed: bool = False) -> Dict[str, Any]:
        """List all tasks with their metadata."""
        print("📋 Available Tasks")
        print("=" * 50)
        
        if not self.tasks_dir.exists():
            print("❌ Tasks directory not found")
            return {}
        
        # Load task index
        task_index = self.load_task_index()
        if not task_index:
            return {}
        
        # Discover tasks
        task_dirs = [d for d in self.tasks_dir.iterdir() 
                    if d.is_dir() and not d.name.startswith('.')]
        
        tasks = {}
        
        for task_dir in sorted(task_dirs):
            task_name = task_dir.name
            metadata = self.get_task_metadata(task_name, task_index, task_dir)
            
            if metadata:
                tasks[task_name] = metadata
                self.print_task_summary(task_name, metadata, detailed)
        
        # Print summary
        print(f"\n📊 Summary: {len(tasks)} tasks found")
        
        # Print category summary
        self.print_category_summary(tasks)
        
        # Print stack coverage
        self.print_stack_coverage(tasks)
        
        return tasks

    def load_task_index(self) -> Optional[Dict[str, Any]]:
        """Load the task index YAML file."""
        index_path = self.tasks_dir / "task-index.yaml"
        
        if not index_path.exists():
            print("❌ task-index.yaml not found")
            return None
        
        try:
            with open(index_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"❌ Error loading task-index.yaml: {e}")
            return None

    def get_task_metadata(self, task_name: str, task_index: Dict[str, Any], task_dir: Path) -> Optional[Dict[str, Any]]:
        """Get comprehensive metadata for a task."""
        # Start with index data
        metadata = {}
        
        if "tasks" in task_index and task_name in task_index["tasks"]:
            metadata = task_index["tasks"][task_name].copy()
        
        # Add directory structure info
        metadata["has_universal"] = (task_dir / "universal").exists()
        metadata["has_stacks"] = (task_dir / "stacks").exists()
        
        # Count templates
        universal_templates = list((task_dir / "universal").rglob("*.tpl.*")) if (task_dir / "universal").exists() else []
        stack_templates = list((task_dir / "stacks").rglob("*.tpl.*")) if (task_dir / "stacks").exists() else []
        
        metadata["template_count"] = {
            "universal": len(universal_templates),
            "stacks": len(stack_templates),
            "total": len(universal_templates) + len(stack_templates)
        }
        
        # Get supported stacks
        supported_stacks = []
        if (task_dir / "stacks").exists():
            supported_stacks = [d.name for d in (task_dir / "stacks").iterdir() 
                               if d.is_dir() and not d.name.startswith('.')]
        metadata["supported_stacks"] = supported_stacks
        
        # Load meta.yaml if exists
        meta_path = task_dir / "meta.yaml"
        if meta_path.exists():
            try:
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta_data = yaml.safe_load(f)
                    if meta_data:
                        metadata.update(meta_data)
            except Exception:
                pass  # Ignore meta.yaml errors
        
        return metadata

    def print_task_summary(self, task_name: str, metadata: Dict[str, Any], detailed: bool = False):
        """Print a summary of a task."""
        display_name = metadata.get('display_name', task_name.replace('-', ' ').title())
        print(f"\n🔧 {display_name}")
        print(f"   ID: {task_name}")
        
        if 'category' in metadata:
            print(f"   Category: {metadata['category']}")
        
        if 'description' in metadata:
            description = metadata['description'].strip()
            if description:
                # Truncate long descriptions
                short_desc = description[:100] + ('...' if len(description) > 100 else '')
                print(f"   Description: {short_desc}")
        
        # Print template info
        template_count = metadata.get('template_count', {})
        print(f"   Templates: {template_count.get('universal', 0)} universal, {template_count.get('stacks', 0)} stack-specific")
        
        # Print stack support
        supported_stacks = metadata.get('supported_stacks', [])
        if supported_stacks:
            print(f"   Stacks: {', '.join(supported_stacks)}")
        
        if detailed:
            # Print detailed information
            if 'complexity' in metadata:
                print(f"   Complexity: {metadata['complexity']}")
            
            if 'dependencies' in metadata:
                deps = metadata['dependencies']
                if deps:
                    print(f"   Dependencies: {', '.join(deps)}")
            
            if 'optional_dependencies' in metadata:
                opt_deps = metadata['optional_dependencies']
                if opt_deps:
                    print(f"   Optional Dependencies: {', '.join(opt_deps)}")
            
            # Print file mappings
            if 'file_mappings' in metadata:
                mappings = metadata['file_mappings']
                print(f"   File Mappings:")
                if 'universal' in mappings:
                    print(f"     Universal: {len(mappings['universal'])} files")
                if 'stacks' in mappings:
                    for stack, files in mappings['stacks'].items():
                        print(f"     {stack}: {len(files)} files")

    def print_category_summary(self, tasks: Dict[str, Any]):
        """Print task category summary."""
        print("\n📂 Tasks by Category")
        print("-" * 30)
        
        categories = {}
        for task_name, metadata in tasks.items():
            category = metadata.get('category', 'Unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append(task_name)
        
        for category, task_list in sorted(categories.items()):
            print(f"  {category.title():20}: {len(task_list):2} tasks")

    def print_stack_coverage(self, tasks: Dict[str, Any]):
        """Print stack coverage statistics."""
        print("\n🔧 Stack Coverage")
        print("-" * 30)
        
        # Count task support for each stack
        stack_counts = {}
        available_stacks = []
        
        if self.stacks_dir.exists():
            available_stacks = [d.name for d in self.stacks_dir.iterdir() 
                               if d.is_dir() and not d.name.startswith('.')]
        
        for stack_name in available_stacks:
            stack_counts[stack_name] = 0
        
        for task_name, metadata in tasks.items():
            supported_stacks = metadata.get('supported_stacks', [])
            for stack_name in supported_stacks:
                if stack_name in stack_counts:
                    stack_counts[stack_name] += 1
        
        # Print coverage
        for stack_name in sorted(available_stacks):
            count = stack_counts.get(stack_name, 0)
            percentage = (count / len(tasks)) * 100 if tasks else 0
            print(f"  {stack_name:15}: {count:2}/{len(tasks):2} tasks ({percentage:.0f}%)")

    def list_by_category(self, category: str = None):
        """List tasks by category."""
        tasks = self.list_all()
        
        if category:
            filtered = {name: meta for name, meta in tasks.items() 
                       if meta.get('category') == category}
            print(f"\n📂 Category: {category}")
            print("=" * 50)
            for name, meta in filtered.items():
                display_name = meta.get('display_name', name.replace('-', ' ').title())
                print(f"  • {display_name} ({name})")
        else:
            # Group by category (already done in list_all)
            pass

    def list_by_stack(self, stack_name: str):
        """List tasks that support a specific stack."""
        tasks = self.list_all()
        
        print(f"\n🔧 Tasks supporting '{stack_name}'")
        print("=" * 50)
        
        supported = []
        for name, meta in tasks.items():
            if stack_name in meta.get('supported_stacks', []):
                supported.append((name, meta))
        
        if supported:
            for name, meta in supported:
                display_name = meta.get('display_name', name.replace('-', ' ').title())
                print(f"  • {display_name} ({name})")
        else:
            print(f"  No tasks found supporting '{stack_name}'")

    def list_dependencies(self):
        """List task dependencies."""
        tasks = self.list_all()
        
        print("\n🔗 Task Dependencies")
        print("=" * 50)
        
        # Build dependency graph
        dependency_graph = {}
        for name, meta in tasks.items():
            deps = meta.get('dependencies', [])
            if deps:
                dependency_graph[name] = deps
        
        if dependency_graph:
            for task, deps in sorted(dependency_graph.items()):
                print(f"  {task}:")
                for dep in deps:
                    print(f"    -> {dep}")
        else:
            print("  No task dependencies found")

    def find_orphans(self):
        """Find tasks with no dependencies or dependents."""
        tasks = self.list_all()
        
        print("\n🏝️ Orphaned Tasks")
        print("=" * 50)
        
        # Build dependency sets
        all_tasks = set(tasks.keys())
        with_deps = set()
        as_dep = set()
        
        for name, meta in tasks.items():
            deps = meta.get('dependencies', [])
            if deps:
                with_deps.add(name)
                as_dep.update(deps)
        
        # Find orphans
        no_deps = all_tasks - with_deps
        never_used = all_tasks - as_dep
        
        print(f"  Tasks with no dependencies ({len(no_deps)}):")
        for task in sorted(no_deps):
            print(f"    • {task}")
        
        print(f"\n  Tasks never used as dependencies ({len(never_used)}):")
        for task in sorted(never_used):
            print(f"    • {task}")

def main():
    """Main listing script."""
    templates_root = Path(__file__).parent.parent
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "--help":
            print("Usage: python list_tasks.py [command] [options]")
            print("Commands:")
            print("  (no args)    List all tasks")
            print("  --detailed   Show detailed information")
            print("  --category   List by category")
            print("  --stack      List tasks supporting a stack")
            print("  --deps       Show task dependencies")
            print("  --orphans    Find orphaned tasks")
            return
        
        lister = TaskLister(templates_root)
        
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
                print("Usage: python list_tasks.py --stack <stack_name>")
        elif command == "--deps":
            lister.list_dependencies()
        elif command == "--orphans":
            lister.find_orphans()
        else:
            print(f"Unknown command: {command}")
            print("Use --help for usage information")
    else:
        # Default: list all tasks
        lister = TaskLister(templates_root)
        lister.list_all()

if __name__ == "__main__":
    main()
