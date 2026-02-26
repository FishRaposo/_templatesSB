#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Task File Mapping Generator for {{PROJECT_NAME}} Template System
Scans task directories and auto-generates file mappings for resolver integration.

Usage: python scripts/generate_task_mappings.py [--task TASK_NAME] [--merge]
"""

import os
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse

# Add templates directory to path
SCRIPT_DIR = Path(__file__).parent
TEMPLATES_DIR = SCRIPT_DIR.parent
TASKS_DIR = TEMPLATES_DIR / "tasks"

def load_expanded_task_index() -> Dict[str, Any]:
    """Load the expanded task index with metadata."""
    index_file = TASKS_DIR / "expanded-task-index.yaml"
    if not index_file.exists():
        raise FileNotFoundError(f"Expanded task index not found: {index_file}")
    
    with open(index_file, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def scan_task_templates(task_name: str) -> List[Dict[str, Any]]:
    """Scan a task directory for template files and generate mappings."""
    task_dir = TASKS_DIR / task_name
    mappings = []
    
    if not task_dir.exists():
        print(f"Warning: Task directory not found: {task_dir}")
        return mappings
    
    # Scan universal templates
    universal_dir = task_dir / "universal"
    if universal_dir.exists():
        for template_file in find_template_files(universal_dir):
            relative_path = template_file.relative_to(universal_dir)
            mapping = create_file_mapping(task_name, relative_path, "universal")
            mappings.append(mapping)
    
    # Scan stack-specific templates
    stacks_dir = task_dir / "stacks"
    if stacks_dir.exists():
        for stack_dir in stacks_dir.iterdir():
            if stack_dir.is_dir():
                base_dir = stack_dir / "base"
                if base_dir.exists():
                    for template_file in find_template_files(base_dir):
                        relative_path = template_file.relative_to(base_dir)
                        mapping = create_file_mapping(task_name, relative_path, "stack", stack_dir.name)
                        mappings.append(mapping)
    
    return mappings

def find_template_files(directory: Path) -> List[Path]:
    """Find all template files in a directory."""
    template_files = []
    
    for file_path in directory.rglob("*"):
        if file_path.is_file() and file_path.suffix in ['.md', '.yaml', '.yml', '.py', '.js', '.jsx', '.ts', '.tsx', '.go', '.dart', '.R', '.sql']:
            template_files.append(file_path)
    
    return template_files

def create_file_mapping(task_name: str, relative_path: Path, template_type: str, stack: Optional[str] = None) -> Dict[str, Any]:
    """Create a file mapping entry for the task index."""
    
    # Generate mapping ID based on file type and location
    file_name = relative_path.stem
    file_ext = relative_path.suffix
    
    if template_type == "universal":
        if "skeleton" in file_name.lower():
            mapping_id = f"{task_name.upper()}_SERVICE"
            target_path = f"src/{task_name}/service.{{ext}}"
        elif "config" in file_name.lower():
            mapping_id = f"{task_name.upper()}_CONFIG"
            target_path = f"config/{task_name}.{{ext}}"
        elif "test" in file_name.lower():
            mapping_id = f"{task_name.upper()}_TESTS"
            target_path = f"tests/{task_name}/test_{task_name}.{{ext}}"
        elif "overview" in file_name.lower():
            mapping_id = f"{task_name.upper()}_DOCS"
            target_path = f"docs/{task_name.upper()}.md"
        else:
            mapping_id = f"{task_name.upper()}_{file_name.upper()}"
            target_path = f"src/{task_name}/{file_name}.{{ext}}"
        
        universal_template = f"tasks/{task_name}/universal/{relative_path.as_posix()}"
        
        mapping = {
            "id": mapping_id,
            "target_path": target_path,
            "universal_template": universal_template,
            "merge_behavior": "create"
        }
        
        # Add stack overrides if they exist
        stack_overrides = {}
        stacks_dir = TASKS_DIR / task_name / "stacks"
        if stacks_dir.exists():
            for stack_name in stacks_dir.iterdir():
                if stack_name.is_dir():
                    override_file = stacks_dir / stack_name / "base" / relative_path
                    if override_file.exists():
                        stack_overrides[stack_name] = f"tasks/{task_name}/stacks/{stack_name}/base/{relative_path.as_posix()}"
        
        if stack_overrides:
            mapping["stack_overrides"] = stack_overrides
    
    else:  # stack-specific
        if "service" in file_name.lower():
            mapping_id = f"{task_name.upper()}_SERVICE"
            target_path = f"src/{task_name}/service.{file_ext.lstrip('.')}"
        elif "config" in file_name.lower():
            mapping_id = f"{task_name.upper()}_CONFIG"
            target_path = f"config/{task_name}.{file_ext.lstrip('.')}"
        elif "test" in file_name.lower():
            mapping_id = f"{task_name.upper()}_TESTS"
            target_path = f"tests/{task_name}/test_{task_name}.{file_ext.lstrip('.')}"
        elif "component" in file_name.lower():
            mapping_id = f"{task_name.upper()}_COMPONENT"
            target_path = f"src/{task_name}/component.{file_ext.lstrip('.')}"
        else:
            mapping_id = f"{task_name.upper()}_{file_name.upper()}"
            target_path = f"src/{task_name}/{file_name}"
        
        # Always include universal_template as fallback (required by resolver)
        universal_template = f"tasks/{task_name}/universal/code/{task_name.upper()}-SKELETON.tpl.md"
        
        mapping = {
            "id": mapping_id,
            "target_path": target_path,
            "universal_template": universal_template,
            "stack_overrides": {
                stack: f"tasks/{task_name}/stacks/{stack}/base/{relative_path.as_posix()}"
            },
            "merge_behavior": "create"
        }
    
    return mapping

def generate_complete_task_index(task_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate complete task index with file mappings."""
    complete_index = {
        "tasks": {},
        "task_config": task_data.get("task_config", {}),
        "task_dependencies": task_data.get("task_dependencies", {})
    }
    
    for task_name, task_meta in task_data.get("tasks", {}).items():
        print(f"Generating mappings for task: {task_name}")
        
        # Start with metadata
        task_entry = {
            "description": task_meta.get("description", ""),
            "categories": task_meta.get("categories", []),
            "default_stacks": task_meta.get("default_stacks", []),
            "allowed_stacks": task_meta.get("allowed_stacks", []),
            "recommended_tier": task_meta.get("recommended_tier", {}),
            "files": []
        }
        
        # Generate file mappings
        try:
            file_mappings = scan_task_templates(task_name)
            print(f"  Generated {len(file_mappings)} file mappings")
            
            # Debug: Check each mapping for required fields
            for i, mapping in enumerate(file_mappings):
                if "universal_template" not in mapping:
                    print(f"  ERROR: Missing universal_template in mapping {i}: {mapping}")
                if mapping.get("universal_template") is None:
                    print(f"  ERROR: universal_template is None in mapping {i}: {mapping}")
            
            task_entry["files"] = file_mappings
        except Exception as e:
            print(f"  ERROR generating mappings: {e}")
            task_entry["files"] = []
        
        complete_index["tasks"][task_name] = task_entry
    
    # Debug: Print summary before returning
    print(f"\nDEBUG: Generated complete_index with {len(complete_index['tasks'])} tasks")
    for task_name, task_data in complete_index["tasks"].items():
        files = task_data.get("files", [])
        print(f"  {task_name}: {len(files)} files")
        for i, file_map in enumerate(files[:2]):  # Show first 2 files
            print(f"    File {i}: {file_map.get('id', 'NO_ID')} -> {file_map.get('universal_template', 'NO_TEMPLATE')}")
    
    return complete_index

def merge_with_existing_index(new_index: Dict[str, Any]) -> Dict[str, Any]:
    """Merge new task index with existing one while preserving structure."""
    existing_index_file = TASKS_DIR / "task-index.yaml"
    
    if existing_index_file.exists():
        with open(existing_index_file, 'r', encoding='utf-8') as f:
            existing_index = yaml.safe_load(f)
        
        # Create merged index with correct order: tasks first, then task_config, then task_dependencies
        merged_index = {
            "tasks": existing_index.get("tasks", {})
        }
        
        # Merge tasks (new tasks override existing ones)
        merged_index["tasks"].update(new_index["tasks"])
        
        # Add task_config from existing index (preserve working structure)
        if "task_config" in existing_index:
            merged_index["task_config"] = existing_index["task_config"]
        elif "task_config" in new_index:
            merged_index["task_config"] = new_index["task_config"]
        
        # Add task_dependencies if they exist
        if "task_dependencies" in existing_index:
            merged_index["task_dependencies"] = existing_index["task_dependencies"]
        elif "task_dependencies" in new_index:
            merged_index["task_dependencies"] = new_index["task_dependencies"]
        
        return merged_index
    else:
        return new_index

def write_yaml_with_proper_formatting(data: Dict[str, Any], output_file: Path):
    """Write YAML with proper formatting to match resolver expectations."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Task Index for {{PROJECT_NAME}} Template System\n")
        f.write("# Defines available tasks, their metadata, and file mappings\n\n")
        
        # Write tasks section
        f.write("tasks:\n")
        for task_name, task_data in data.get("tasks", {}).items():
            f.write(f"  {task_name}:\n")
            f.write(f'    description: "{task_data.get("description", "")}"\n')
            
            # Write categories
            categories = task_data.get("categories", [])
            if categories:
                f.write("    categories: [")
                f.write(", ".join([f'"{cat}"' for cat in categories]))
                f.write("]\n")
            
            # Write stacks
            default_stacks = task_data.get("default_stacks", [])
            if default_stacks:
                f.write("    default_stacks: [")
                f.write(", ".join([f'"{stack}"' for stack in default_stacks]))
                f.write("]\n")
            
            allowed_stacks = task_data.get("allowed_stacks", [])
            if allowed_stacks:
                f.write("    allowed_stacks: [")
                f.write(", ".join([f'"{stack}"' for stack in allowed_stacks]))
                f.write("]\n")
            
            # Write recommended tiers
            recommended_tier = task_data.get("recommended_tier", {})
            if recommended_tier:
                f.write("    recommended_tier:\n")
                for tier, desc in recommended_tier.items():
                    f.write(f'      {tier}: "{desc}"\n')
            
            # Write files
            files = task_data.get("files", [])
            if files:
                f.write("    files:\n")
                for file_mapping in files:
                    f.write(f'      - id: "{file_mapping["id"]}"\n')
                    f.write(f'        target_path: "{file_mapping["target_path"]}"\n')
                    f.write(f'        universal_template: "{file_mapping["universal_template"]}"\n')
                    
                    # Write stack overrides if they exist
                    if "stack_overrides" in file_mapping:
                        f.write("        stack_overrides:\n")
                        for stack, template in file_mapping["stack_overrides"].items():
                            f.write(f'          {stack}: "{template}"\n')
                    
                    f.write(f'        merge_behavior: "{file_mapping["merge_behavior"]}"\n')
                    f.write("\n")
        
        # Write task_config section
        if "task_config" in data:
            f.write("\n# Global task configuration\ntask_config:\n")
            task_config = data["task_config"]
            
            if "merge_strategies" in task_config:
                f.write("  merge_strategies:\n")
                for strategy, desc in task_config["merge_strategies"].items():
                    f.write(f'    {strategy}: "{desc}"\n')
            
            if "precedence_order" in task_config:
                f.write("  precedence_order:\n")
                for item in task_config["precedence_order"]:
                    f.write(f'    - "{item}"\n')
            
            if "conflict_resolution" in task_config:
                f.write("  conflict_resolution:\n")
                conflict_res = task_config["conflict_resolution"]
                if "strategy" in conflict_res:
                    f.write(f'    strategy: "{conflict_res["strategy"]}"\n')
                if "markers" in conflict_res:
                    f.write("    markers:\n")
                    for key, value in conflict_res["markers"].items():
                        f.write(f'      {key}: "{value}"\n')
        
        # Write task_dependencies section
        if "task_dependencies" in data:
            f.write("\ntask_dependencies:\n")
            for task, deps in data["task_dependencies"].items():
                if deps is not None and deps:  # Handle None values and empty lists
                    f.write(f"  {task}:\n")
                    for dep in deps:
                        f.write(f"    - {dep}\n")

def main():
    parser = argparse.ArgumentParser(description='Generate file mappings for tasks')
    parser.add_argument('--task', help='Generate mappings for specific task only')
    parser.add_argument('--merge', action='store_true', help='Merge with existing task-index.yaml')
    parser.add_argument('--output', help='Output file path', default='generated-task-index.yaml')
    
    args = parser.parse_args()
    
    try:
        # Load expanded task index
        expanded_index = load_expanded_task_index()
        
        if args.task:
            # Generate mappings for specific task
            if args.task not in expanded_index.get("tasks", {}):
                print(f"Task '{args.task}' not found in expanded index")
                return
            
            task_data = {args.task: expanded_index["tasks"][args.task]}
            complete_index = generate_complete_task_index({"tasks": task_data})
        else:
            # Generate mappings for all tasks
            complete_index = generate_complete_task_index(expanded_index)
        
        # Write the complete index with proper formatting
        if args.merge:
            complete_index = merge_with_existing_index(complete_index)
            output_file = TASKS_DIR / "task-index.yaml"
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.safe_dump(complete_index, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            print(f"Merged with existing task-index.yaml")
        else:
            output_file = TEMPLATES_DIR / args.output
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.safe_dump(complete_index, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            print(f"Writing to: {output_file}")
        
        print(f"Generated complete task index with {len(complete_index['tasks'])} tasks")
        
        # Summary
        total_mappings = sum(len(task.get("files", [])) for task in complete_index["tasks"].values())
        print(f"Total file mappings: {total_mappings}")
        
        # Test with a few tasks
        print("\nSample mappings for rest-api-service:")
        if "rest-api-service" in complete_index["tasks"]:
            for mapping in complete_index["tasks"]["rest-api-service"]["files"][:3]:
                print(f"  - {mapping['id']}: {mapping['target_path']}")
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
