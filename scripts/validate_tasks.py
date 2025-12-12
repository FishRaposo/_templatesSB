#!/usr/bin/env python3
"""
Task Validation Script

Validates task definitions, metadata, templates, and implementations for the Universal Template System.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import sys

from stack_config import get_all_stacks, get_all_tiers

STACK_ALIASES = {
    'nextjs': 'next',
    'agnostic': 'generic'
}

TIER_ALIASES = {
    'full': 'enterprise',
    'all': 'enterprise'
}

class TaskValidator:
    def __init__(self, templates_root: Path):
        self.templates_root = templates_root
        self.tasks_dir = templates_root / "tasks"
        self.stacks_dir = templates_root / "stacks"
        self.errors = []
        self.warnings = []
        self.stats = {
            "total_tasks": 0,
            "valid_tasks": 0,
            "invalid_tasks": 0,
            "total_templates": 0,
            "valid_templates": 0,
            "invalid_templates": 0,
            "categories": {},
            "stack_coverage": {}
        }

    def _canonical_stack(self, stack: str) -> str:
        return STACK_ALIASES.get(stack, stack)

    def _canonical_tier(self, tier: str) -> str:
        return TIER_ALIASES.get(tier, tier)

    def validate_all(self) -> Dict[str, Any]:
        """Validate all tasks in the system."""
        print("🔍 Validating Tasks...")
        print("=" * 50)
        
        if not self.tasks_dir.exists():
            self.log_error("Tasks directory not found", str(self.tasks_dir))
            return self.get_results()
        
        # Load task index
        task_index = self.load_task_index()
        if not task_index:
            return self.get_results()
        
        # Discover tasks
        task_dirs = [d for d in self.tasks_dir.iterdir() 
                    if d.is_dir() and not d.name.startswith('.')]
        
        self.stats["total_tasks"] = len(task_dirs)
        
        for task_dir in task_dirs:
            self.validate_task(task_dir, task_index)
        
        # Validate task index consistency
        self.validate_task_index_consistency(task_index, task_dirs)
        
        # Validate system integration
        self.validate_system_integration()
        
        return self.get_results()

    def load_task_index(self) -> Optional[Dict[str, Any]]:
        """Load the task index YAML file."""
        index_path = self.tasks_dir / "task-index.yaml"
        
        if not index_path.exists():
            self.log_error("task-index.yaml not found", str(index_path))
            return None
        
        try:
            with open(index_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.log_error(f"Invalid YAML in task-index.yaml: {e}", str(index_path))
            return None
        except Exception as e:
            self.log_error(f"Error reading task-index.yaml: {e}", str(index_path))
            return None

    def validate_task(self, task_dir: Path, task_index: Dict[str, Any]) -> None:
        """Validate a single task."""
        task_name = task_dir.name
        print(f"\n📋 Validating Task: {task_name}")
        
        task_valid = True
        
        # Check required directories
        required_dirs = ["universal", "stacks"]
        for dir_name in required_dirs:
            dir_path = task_dir / dir_name
            if not dir_path.exists():
                self.log_error(f"Missing required directory: {dir_name}", str(task_dir))
                task_valid = False
            else:
                # Validate subdirectories
                if dir_name == "universal":
                    self.validate_universal_templates(dir_path, task_name)
                elif dir_name == "stacks":
                    self.validate_stack_implementations(dir_path, task_name)
        
        # Check for meta.yaml (optional)
        meta_path = task_dir / "meta.yaml"
        if meta_path.exists():
            self.validate_task_metadata(meta_path, task_name)
        
        # Check task index entry
        if "tasks" in task_index and task_name in task_index["tasks"]:
            task_data = task_index["tasks"][task_name]
            self.validate_task_index_entry(task_name, task_data, task_dir)
        else:
            self.log_warning(f"Task not found in task-index.yaml", str(task_dir))
        
        if task_valid:
            self.stats["valid_tasks"] += 1
        else:
            self.stats["invalid_tasks"] += 1

    def validate_universal_templates(self, universal_dir: Path, task_name: str) -> None:
        """Validate universal templates."""
        # Check required subdirectories
        required_subdirs = ["code", "docs", "tests"]
        for subdir in required_subdirs:
            subdir_path = universal_dir / subdir
            if not subdir_path.exists():
                self.log_warning(f"Missing universal subdirectory: {subdir}", str(universal_dir))
            else:
                # Validate templates
                templates = list(subdir_path.rglob("*.tpl.*"))
                for template_path in templates:
                    self.stats["total_templates"] += 1
                    if self.validate_template_file(template_path, task_name, "universal"):
                        self.stats["valid_templates"] += 1
                    else:
                        self.stats["invalid_templates"] += 1

    def validate_stack_implementations(self, stacks_dir: Path, task_name: str) -> None:
        """Validate stack-specific implementations."""
        stack_dirs = [d for d in stacks_dir.iterdir() 
                     if d.is_dir() and not d.name.startswith('.')]
        
        for stack_dir in stack_dirs:
            stack_name = stack_dir.name
            canonical_stack = self._canonical_stack(stack_name)
            
            # Check if stack exists
            stack_path = self.stacks_dir / canonical_stack
            if not stack_path.exists():
                self.log_warning(f"Implementation for unsupported stack: {stack_name}", str(stacks_dir))
                continue
            
            # Update stack coverage
            if canonical_stack not in self.stats["stack_coverage"]:
                self.stats["stack_coverage"][canonical_stack] = 0
            self.stats["stack_coverage"][canonical_stack] += 1
            
            # Validate stack templates
            templates = list(stack_dir.rglob("*.tpl.*"))
            for template_path in templates:
                self.stats["total_templates"] += 1
                if self.validate_template_file(template_path, task_name, canonical_stack):
                    self.stats["valid_templates"] += 1
                else:
                    self.stats["invalid_templates"] += 1

    def validate_template_file(self, template_path: Path, task_name: str, stack_name: str) -> bool:
        """Validate a template file."""
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for required header
            if not self.validate_template_header(content, task_name, stack_name):
                return False
            
            # Check for placeholders
            if not self.validate_template_placeholders(content):
                self.log_warning(f"No placeholders found in template: {template_path.name}", str(template_path))
            
            return True
            
        except Exception as e:
            self.log_error(f"Error reading template {template_path.name}: {e}", str(template_path))
            return False

    def validate_template_header(self, content: str, task_name: str, stack_name: str) -> bool:
        """Validate template file header."""
        head = "\n".join(content.split('\n')[:12])
        if "File:" in head:
            return True

        stripped = content.lstrip()
        if stripped.startswith(("<!--", "#", "//", "/**", '"""', "'''")):
            return True

        return stripped.startswith((
            "import ",
            "const ",
            "export ",
            "package ",
            "func ",
            "fn ",
            "use ",
            "pub ",
            "#[",
            "describe(",
            "test_that(",
        ))

    def validate_template_placeholders(self, content: str) -> bool:
        """Check if template contains placeholders."""
        return ("{{" in content) or ("[[" in content) or ("{%" in content)

    def validate_task_metadata(self, meta_path: Path, task_name: str) -> None:
        """Validate task metadata YAML."""
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                metadata = yaml.safe_load(f)
            
            # Validate required fields
            if metadata and "category" in metadata:
                category = metadata["category"]
                if category not in self.stats["categories"]:
                    self.stats["categories"][category] = 0
                self.stats["categories"][category] += 1
            
        except Exception as e:
            self.log_error(f"Error reading metadata: {e}", str(meta_path))

    def validate_task_index_entry(self, task_name: str, task_data: Dict[str, Any], task_dir: Path) -> None:
        """Validate task entry in task index."""
        # Check description
        if "description" not in task_data:
            self.log_warning(f"Missing description in task index", f"task-index.yaml:{task_name}")
        
        # Check categories
        categories = task_data.get("categories")
        if not categories or not isinstance(categories, list):
            self.log_warning("Missing categories in task index", f"task-index.yaml:{task_name}")

        supported_stacks = set(get_all_stacks())
        for field in ("default_stacks", "allowed_stacks"):
            for stack in task_data.get(field, []) or []:
                canonical_stack = self._canonical_stack(stack)
                if canonical_stack not in supported_stacks:
                    self.log_warning(f"Unknown stack in task index: {stack}", f"task-index.yaml:{task_name}")

        supported_tiers = set(get_all_tiers())
        recommended_tier = task_data.get("recommended_tier") or {}
        if isinstance(recommended_tier, dict):
            for _, tier in recommended_tier.items():
                canonical_tier = self._canonical_tier(tier)
                if canonical_tier not in supported_tiers:
                    self.log_warning(f"Unknown tier in task index: {tier}", f"task-index.yaml:{task_name}")

        for file_config in task_data.get("files", []) or []:
            file_id = file_config.get("id")
            if not file_id:
                self.log_error("File mapping missing id", f"task-index.yaml:{task_name}")

            target_path = file_config.get("target_path")
            if not target_path:
                self.log_error("File mapping missing target_path", f"task-index.yaml:{task_name}:{file_id or 'unknown'}")

            universal_template = file_config.get("universal_template")
            if universal_template:
                if isinstance(universal_template, str):
                    full_path = self.templates_root / universal_template
                    if not full_path.exists():
                        self.log_error(f"Universal template not found: {universal_template}", f"task-index.yaml:{task_name}:{file_id or 'unknown'}")
                else:
                    self.log_error("Universal template mapping has unexpected type", f"task-index.yaml:{task_name}:{file_id or 'unknown'}")

            stack_overrides = file_config.get("stack_overrides") or {}
            if isinstance(stack_overrides, dict):
                for override_stack, template_path in stack_overrides.items():
                    canonical_stack = self._canonical_stack(override_stack)
                    if canonical_stack not in supported_stacks:
                        self.log_warning(f"Unknown stack override in task index: {override_stack}", f"task-index.yaml:{task_name}:{file_id or 'unknown'}")

                    if isinstance(template_path, str):
                        full_path = self.templates_root / template_path
                        if not full_path.exists():
                            self.log_error(f"Stack override template not found: {template_path}", f"task-index.yaml:{task_name}:{file_id or 'unknown'}")
                    else:
                        self.log_error("Stack override mapping has unexpected type", f"task-index.yaml:{task_name}:{file_id or 'unknown'}")

    def validate_task_index_consistency(self, task_index: Dict[str, Any], task_dirs: List[Path]) -> None:
        """Validate task index consistency with actual tasks."""
        print("\n🔍 Validating Task Index Consistency")
        
        if "tasks" not in task_index:
            self.log_error("No 'tasks' section in task-index.yaml", "task-index.yaml")
            return
        
        indexed_tasks = set(task_index["tasks"].keys())
        actual_tasks = {d.name for d in task_dirs}
        
        # Check for missing tasks
        missing_tasks = actual_tasks - indexed_tasks
        for task in missing_tasks:
            self.log_warning(f"Task exists but not in index: {task}", "task-index.yaml")
        
        # Check for orphaned entries
        orphaned_tasks = indexed_tasks - actual_tasks
        for task in orphaned_tasks:
            self.log_error(f"Task in index but doesn't exist: {task}", "task-index.yaml")
        
        print(f"  ✅ Found {len(actual_tasks)} actual tasks, {len(indexed_tasks)} indexed tasks")

    def validate_system_integration(self) -> None:
        """Validate task system integration."""
        print("\n🔗 Validating System Integration")
        
        # Check task detection script
        detection_path = self.templates_root / "scripts" / "detect_project_tasks.py"
        if not detection_path.exists():
            self.log_error("Task detection script not found", str(detection_path))
        
        # Check task resolution
        try:
            from detect_project_tasks import TaskDetectionSystem

            tasks = TaskDetectionSystem().tasks
            print(f"  ✅ Task discovery working: {len(tasks)} tasks found")
        except Exception as e:
            self.log_warning(f"Task discovery issue: {e}", "system integration")

    def log_error(self, message: str, location: str = ""):
        """Log an error."""
        self.errors.append(f"ERROR: {message} ({location})")

    def log_warning(self, message: str, location: str = ""):
        """Log a warning."""
        self.warnings.append(f"WARNING: {message} ({location})")

    def get_results(self) -> Dict[str, Any]:
        """Get validation results."""
        return {
            "stats": self.stats,
            "errors": self.errors,
            "warnings": self.warnings,
            "success": len(self.errors) == 0
        }

def main():
    """Main validation script."""
    templates_root = Path(__file__).parent.parent
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help":
            print("Usage: python validate_tasks.py [--detailed]")
            print("Validates all task definitions and templates")
            return
        
        if sys.argv[1] == "--detailed":
            detailed = True
        else:
            detailed = False
    else:
        detailed = False
    
    validator = TaskValidator(templates_root)
    results = validator.validate_all()
    
    # Print results
    print("\n" + "=" * 50)
    print("📊 Task Validation Results")
    print("=" * 50)
    
    stats = results["stats"]
    print(f"Total Tasks: {stats['total_tasks']}")
    print(f"Valid Tasks: {stats['valid_tasks']}")
    print(f"Invalid Tasks: {stats['invalid_tasks']}")
    print(f"Total Templates: {stats['total_templates']}")
    print(f"Valid Templates: {stats['valid_templates']}")
    print(f"Invalid Templates: {stats['invalid_templates']}")
    
    if stats["categories"]:
        print(f"\n📂 Categories:")
        for category, count in sorted(stats["categories"].items()):
            print(f"  {category}: {count} tasks")
    
    if stats["stack_coverage"]:
        print(f"\n🔧 Stack Coverage:")
        for stack, count in sorted(stats["stack_coverage"].items()):
            print(f"  {stack}: {count} tasks")
    
    if results["errors"]:
        print(f"\n❌ Errors ({len(results['errors'])}):")
        if detailed:
            for error in results["errors"]:
                print(f"  • {error}")
        else:
            print(f"  Run with --detailed to see all errors")
    
    if results["warnings"]:
        print(f"\n⚠️  Warnings ({len(results['warnings'])}):")
        if detailed:
            for warning in results["warnings"]:
                print(f"  • {warning}")
        else:
            print(f"  Run with --detailed to see all warnings")
    
    if results["success"]:
        print("\n✅ All tasks validated successfully!")
        return 0
    else:
        print("\n❌ Task validation failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
