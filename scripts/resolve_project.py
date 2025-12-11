#!/usr/bin/env python3
"""
{{PROJECT_NAME}} Project Resolver
Resolves stack × tier × task specifications into concrete project structures.

This script implements the core logic for combining universal templates,
tier-specific overlays, stack-specific implementations, and task-specific
additions to generate a complete project structure.

Author: {{AUTHOR}}
Created: {{DATE}}
"""

import os
import sys
import yaml
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from copy import deepcopy
import argparse
import logging

# Add templates directory to path
TEMPLATES_DIR = Path(__file__).parent.parent / "_templates"
if not TEMPLATES_DIR.exists():
    # Fallback to current directory structure
    TEMPLATES_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(TEMPLATES_DIR))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ProjectSpec:
    """Project specification defining stack, tier, and tasks."""
    name: str
    stack: str
    tier: str
    tasks: List[str]
    output_dir: Path
    config: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.config is None:
            self.config = {}

@dataclass
class TemplateInfo:
    """Information about a template to be applied."""
    source_path: Path
    target_path: Path
    template_type: str  # universal, tier, stack, task_universal, etc.
    priority: int
    merge_behavior: str  # create, append, prepend, insert_marker
    task_name: Optional[str] = None

class ProjectResolver:
    """Resolves project specifications into concrete file structures."""
    
    def __init__(self, templates_dir: Path, dry_run: bool = False):
        self.templates_dir = templates_dir
        self.dry_run = dry_run
        self.task_index = self._load_task_index()
        self.tier_index = self._load_tier_index()
        
        # Define precedence order (higher number = higher priority)
        self.precedence_order = {
            'universal': 1,
            'universal_tier': 2,
            'stack_base': 3,
            'stack_tier': 4,
            'task_universal': 5,
            'task_stack': 6,
            'task_stack_tier': 7
        }
    
    def _load_task_index(self) -> Dict[str, Any]:
        """Load the task index configuration."""
        task_index_path = self.templates_dir / "tasks" / "task-index.yaml"
        if not task_index_path.exists():
            raise FileNotFoundError(f"Task index not found: {task_index_path}")
        
        with open(task_index_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _load_tier_index(self) -> Dict[str, Any]:
        """Load the tier index configuration."""
        tier_index_path = self.templates_dir / "tiers" / "tier-index.yaml"
        if not tier_index_path.exists():
            # Create minimal tier index if it doesn't exist
            return {
                'tiers': {
                    'mvp': {'description': 'Minimum viable product'},
                    'core': {'description': 'Production-ready'},
                    'full': {'description': 'Full-featured enterprise'}
                }
            }
        
        with open(tier_index_path, 'r') as f:
            return yaml.safe_load(f)
    
    def resolve_project(self, spec: ProjectSpec) -> List[TemplateInfo]:
        """Resolve a project specification into a list of templates to apply."""
        logger.info(f"Resolving project: {spec.name} ({spec.stack} + {spec.tier} + {spec.tasks})")
        
        templates = []
        
        # 1. Load universal base templates
        templates.extend(self._load_universal_templates())
        
        # 2. Load universal tier templates
        templates.extend(self._load_universal_tier_templates(spec.tier))
        
        # 3. Load stack base templates
        templates.extend(self._load_stack_templates(spec.stack, tier=None))
        
        # 4. Load stack tier templates
        templates.extend(self._load_stack_templates(spec.stack, tier=spec.tier))
        
        # 5. Load task templates for each task
        for task_name in spec.tasks:
            task_templates = self._load_task_templates(task_name, spec.stack, spec.tier)
            templates.extend(task_templates)
        
        # Sort templates by precedence
        templates.sort(key=lambda t: t.priority)
        
        logger.info(f"Resolved {len(templates)} templates for project")
        return templates
    
    def _load_universal_templates(self) -> List[TemplateInfo]:
        """Load universal base templates."""
        templates = []
        universal_dir = self.templates_dir / "universal"
        
        if not universal_dir.exists():
            logger.warning("Universal templates directory not found")
            return templates
        
        # Load all universal templates
        for template_file in self._find_template_files(universal_dir):
            relative_path = template_file.relative_to(universal_dir)
            target_path = self._resolve_target_path(relative_path, {})
            
            templates.append(TemplateInfo(
                source_path=template_file,
                target_path=target_path,
                template_type='universal',
                priority=self.precedence_order['universal'],
                merge_behavior='create'
            ))
        
        logger.debug(f"Loaded {len(templates)} universal templates")
        return templates
    
    def _load_universal_tier_templates(self, tier: str) -> List[TemplateInfo]:
        """Load universal tier-specific templates."""
        templates = []
        tier_dir = self.templates_dir / "tiers" / tier / "universal"
        
        if not tier_dir.exists():
            logger.debug(f"No universal tier templates found for tier: {tier}")
            return templates
        
        for template_file in self._find_template_files(tier_dir):
            relative_path = template_file.relative_to(tier_dir)
            target_path = self._resolve_target_path(relative_path, {})
            
            templates.append(TemplateInfo(
                source_path=template_file,
                target_path=target_path,
                template_type='universal_tier',
                priority=self.precedence_order['universal_tier'],
                merge_behavior='create'
            ))
        
        logger.debug(f"Loaded {len(templates)} universal tier templates for {tier}")
        return templates
    
    def _load_stack_templates(self, stack: str, tier: Optional[str] = None) -> List[TemplateInfo]:
        """Load stack-specific templates."""
        templates = []
        
        if tier:
            stack_dir = self.templates_dir / "stacks" / stack / "tiers" / tier
            template_type = 'stack_tier'
            priority = self.precedence_order['stack_tier']
        else:
            stack_dir = self.templates_dir / "stacks" / stack / "base"
            template_type = 'stack_base'
            priority = self.precedence_order['stack_base']
        
        if not stack_dir.exists():
            logger.debug(f"No stack templates found for {stack}/{tier or 'base'}")
            return templates
        
        for template_file in self._find_template_files(stack_dir):
            relative_path = template_file.relative_to(stack_dir)
            target_path = self._resolve_target_path(relative_path, {'stack': stack})
            
            templates.append(TemplateInfo(
                source_path=template_file,
                target_path=target_path,
                template_type=template_type,
                priority=priority,
                merge_behavior='create'
            ))
        
        logger.debug(f"Loaded {len(templates)} stack templates for {stack}/{tier or 'base'}")
        return templates
    
    def _load_task_templates(self, task_name: str, stack: str, tier: str) -> List[TemplateInfo]:
        """Load task-specific templates."""
        templates = []
        
        # Validate task exists
        if task_name not in self.task_index['tasks']:
            logger.error(f"Task not found in index: {task_name}")
            return templates
        
        task_config = self.task_index['tasks'][task_name]
        
        # Check if stack is allowed for this task
        allowed_stacks = task_config.get('allowed_stacks', [])
        if allowed_stacks and stack not in allowed_stacks:
            logger.warning(f"Task {task_name} not officially supported on stack {stack}")
        
        # Load task universal templates
        task_universal_dir = self.templates_dir / "tasks" / task_name / "universal"
        if task_universal_dir.exists():
            for template_file in self._find_template_files(task_universal_dir):
                relative_path = template_file.relative_to(task_universal_dir)
                target_path = self._resolve_target_path(relative_path, {'task': task_name})
                
                templates.append(TemplateInfo(
                    source_path=template_file,
                    target_path=target_path,
                    template_type='task_universal',
                    priority=self.precedence_order['task_universal'],
                    merge_behavior='create',
                    task_name=task_name
                ))
        
        # Load task stack-specific templates
        task_stack_dir = self.templates_dir / "tasks" / task_name / "stacks" / stack / "base"
        if task_stack_dir.exists():
            for template_file in self._find_template_files(task_stack_dir):
                relative_path = template_file.relative_to(task_stack_dir)
                target_path = self._resolve_target_path(relative_path, {'task': task_name, 'stack': stack})
                
                templates.append(TemplateInfo(
                    source_path=template_file,
                    target_path=target_path,
                    template_type='task_stack',
                    priority=self.precedence_order['task_stack'],
                    merge_behavior='create',
                    task_name=task_name
                ))
        
        # Load task stack tier templates
        task_stack_tier_dir = self.templates_dir / "tasks" / task_name / "stacks" / stack / "tiers" / tier
        if task_stack_tier_dir.exists():
            for template_file in self._find_template_files(task_stack_tier_dir):
                relative_path = template_file.relative_to(task_stack_tier_dir)
                target_path = self._resolve_target_path(relative_path, {'task': task_name, 'stack': stack, 'tier': tier})
                
                templates.append(TemplateInfo(
                    source_path=template_file,
                    target_path=target_path,
                    template_type='task_stack_tier',
                    priority=self.precedence_order['task_stack_tier'],
                    merge_behavior='create',
                    task_name=task_name
                ))
        
        # Load task-specific file mappings from task-index.yaml
        for file_config in task_config.get('files', []):
            template_info = self._resolve_task_file_mapping(file_config, task_name, stack, tier)
            if template_info:
                templates.append(template_info)
        
        logger.debug(f"Loaded {len(templates)} task templates for {task_name} on {stack}/{tier}")
        return templates
    
    def _resolve_task_file_mapping(self, file_config: Dict[str, Any], task_name: str, stack: str, tier: str) -> Optional[TemplateInfo]:
        """Resolve a task file mapping from task-index.yaml."""
        file_id = file_config['id']
        target_path_template = file_config['target_path']
        
        # Determine which template to use
        stack_overrides = file_config.get('stack_overrides', {})
        template_path = None
        template_type = None
        
        if stack in stack_overrides:
            # Use stack-specific template
            template_path = self.templates_dir / stack_overrides[stack]
            template_type = 'task_stack'
        else:
            # Use universal template
            template_path = self.templates_dir / file_config['universal_template']
            template_type = 'task_universal'
        
        # Check if template exists
        if not template_path.exists():
            logger.warning(f"Task template not found: {template_path}")
            return None
        
        # Resolve target path with proper extension
        ext = self._get_file_extension(stack)
        target_path = target_path_template.format(ext=ext)
        
        return TemplateInfo(
            source_path=template_path,
            target_path=Path(target_path),
            template_type=template_type,
            priority=self.precedence_order[template_type],
            merge_behavior=file_config.get('merge_behavior', 'create'),
            task_name=task_name
        )
    
    def _find_template_files(self, directory: Path) -> List[Path]:
        """Find all template files in a directory."""
        template_files = []
        
        for file_path in directory.rglob("*"):
            if file_path.is_file() and self._is_template_file(file_path):
                template_files.append(file_path)
        
        return sorted(template_files)
    
    def _is_template_file(self, file_path: Path) -> bool:
        """Check if a file is a template file."""
        # Skip certain files and directories
        if any(part.startswith('.') for part in file_path.parts):
            return False
        
        # Include template files
        return (
            file_path.suffix in ['.tpl', '.md', '.yaml', '.yml', '.json'] or
            'tpl.' in file_path.name or
            file_path.name.startswith('tpl.')
        )
    
    def _resolve_target_path(self, relative_path: Path, context: Dict[str, str]) -> Path:
        """Resolve a relative template path to a target project path."""
        # Remove template extensions and markers
        path_parts = list(relative_path.parts)
        
        for i, part in enumerate(path_parts):
            # Remove .tpl extensions
            if part.endswith('.tpl'):
                path_parts[i] = part[:-4]
            # Replace tpl. prefixes
            elif part.startswith('tpl.'):
                path_parts[i] = part[4:]
            # Replace template markers
            elif '.tpl.' in part:
                path_parts[i] = part.replace('.tpl.', '.')
        
        return Path(*path_parts)
    
    def _get_file_extension(self, stack: str) -> str:
        """Get the appropriate file extension for a stack."""
        extensions = {
            'python': 'py',
            'go': 'go',
            'node': 'js',
            'flutter': 'dart',
            'react': 'jsx',
            'react_native': 'tsx',
            'sql': 'sql',
            'r': 'R'
        }
        return extensions.get(stack, 'txt')
    
    def materialize_project(self, spec: ProjectSpec, templates: List[TemplateInfo]) -> None:
        """Materialize templates into a concrete project structure."""
        if self.dry_run:
            self._dry_run_materialize(spec, templates)
            return
        
        logger.info(f"Materializing project: {spec.name}")
        
        # Create output directory
        spec.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Process templates in precedence order
        processed_files = {}
        
        for template in templates:
            self._process_template(template, spec, processed_files)
        
        # Write processed files to disk
        for target_path, file_data in processed_files.items():
            target_file = spec.output_dir / target_path
            target_file.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                with open(target_file, 'w', encoding='utf-8') as f:
                    f.write(file_data['content'])
                logger.debug(f"Created file: {target_file}")
            except Exception as e:
                logger.error(f"Failed to write file {target_file}: {e}")
        
        logger.info(f"Project materialized with {len(processed_files)} files")
    
    def _dry_run_materialize(self, spec: ProjectSpec, templates: List[TemplateInfo]) -> None:
        """Perform a dry run of project materialization."""
        print(f"\n=== DRY RUN: Project {spec.name} ===")
        print(f"Stack: {spec.stack}")
        print(f"Tier: {spec.tier}")
        print(f"Tasks: {', '.join(spec.tasks)}")
        print(f"Output directory: {spec.output_dir}")
        print(f"\n=== Template Resolution Order ===")
        
        for i, template in enumerate(templates, 1):
            print(f"{i:2d}. [{template.template_type:15s}] {template.source_path.name} -> {template.target_path}")
        
        print(f"\n=== File Conflicts ===")
        
        # Check for conflicts
        target_files = {}
        conflicts = []
        
        for template in templates:
            target = str(template.target_path)
            if target in target_files:
                conflicts.append((target_files[target], template))
            else:
                target_files[target] = template
        
        if conflicts:
            print("WARNING: Template conflicts detected:")
            for existing_template, new_template in conflicts:
                print(f"  {new_template.target_path}")
                print(f"    Existing: [{existing_template.template_type}] {existing_template.source_path.name}")
                print(f"    New:      [{new_template.template_type}] {new_template.source_path.name}")
                print(f"    Winner:   [{new_template.template_type}] (higher priority)")
        else:
            print("No template conflicts detected.")
        
        print(f"\n=== Summary ===")
        print(f"Total templates: {len(templates)}")
        print(f"Unique target files: {len(target_files)}")
        print(f"Conflicts: {len(conflicts)}")
    
    def _process_template(self, template: TemplateInfo, spec: ProjectSpec, processed_files: Dict[str, Any]) -> None:
        """Process a single template and write it to the target."""
        target_path = spec.output_dir / template.target_path
        target_key = str(template.target_path)
        
        # Read template content
        try:
            with open(template.source_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Failed to read template {template.source_path}: {e}")
            return
        
        # Process template content (substitute variables)
        processed_content = self._process_template_content(content, spec, template)
        
        # Handle merge behavior
        if target_key in processed_files:
            # File already exists, handle merge
            existing_content = processed_files[target_key]['content']
            merged_content = self._merge_content(
                existing_content, 
                processed_content, 
                template.merge_behavior,
                template.task_name
            )
            processed_files[target_key]['content'] = merged_content
            processed_files[target_key]['last_template'] = template
        else:
            # New file
            processed_files[target_key] = {
                'content': processed_content,
                'template': template,
                'last_template': template
            }
        
        logger.debug(f"Processed template: {template.template_type} -> {template.target_path}")
    
    def _process_template_content(self, content: str, spec: ProjectSpec, template: TemplateInfo) -> str:
        """Process template content with variable substitution."""
        # Basic variable substitution
        substitutions = {
            '{{PROJECT_NAME}}': spec.name,
            '{{STACK}}': spec.stack,
            '{{TIER}}': spec.tier,
            '{{TASK_NAME}}': template.task_name or '',
            '{{DATE}}': "{{DATE}}",  # Keep as template for now
            '{{AUTHOR}}': "{{AUTHOR}}",  # Keep as template for now
        }
        
        processed = content
        for placeholder, value in substitutions.items():
            processed = processed.replace(placeholder, value)
        
        return processed
    
    def validate_tasks(self, spec: ProjectSpec) -> List[str]:
        """Validate task configurations and check for missing templates."""
        errors = []
        
        for task_name in spec.tasks:
            if task_name not in self.task_index['tasks']:
                errors.append(f"Task '{task_name}' not found in task-index.yaml")
                continue
            
            task_config = self.task_index['tasks'][task_name]
            
            # Check if stack is allowed
            allowed_stacks = task_config.get('allowed_stacks', [])
            if allowed_stacks and spec.stack not in allowed_stacks:
                errors.append(f"Task '{task_name}' not officially supported on stack '{spec.stack}'")
            
            # Validate file mappings
            for file_config in task_config.get('files', []):
                file_id = file_config['id']
                
                # Check universal template
                universal_template = file_config.get('universal_template')
                if universal_template:
                    universal_path = self.templates_dir / universal_template
                    if not universal_path.exists():
                        errors.append(f"Universal template missing for task '{task_name}', file '{file_id}': {universal_template}")
                
                # Check stack-specific templates
                stack_overrides = file_config.get('stack_overrides', {})
                for stack, template_path in stack_overrides.items():
                    full_path = self.templates_dir / template_path
                    if not full_path.exists():
                        errors.append(f"Stack template missing for task '{task_name}', stack '{stack}', file '{file_id}': {template_path}")
        
        return errors
    
    def _merge_content(self, existing: str, new: str, behavior: str, task_name: Optional[str] = None) -> str:
        if behavior == 'create':
            return new  # Higher priority template wins
        elif behavior == 'append':
            return existing + '\n' + new
        elif behavior == 'prepend':
            return new + '\n' + existing
        elif behavior == 'insert_marker' and task_name:
            marker_begin = f"<!-- @TASK:{task_name}:BEGIN -->"
            marker_end = f"<!-- @TASK:{task_name}:END -->"
            
            # Remove existing task section if present
            if marker_begin in existing and marker_end in existing:
                start_idx = existing.find(marker_begin)
                end_idx = existing.find(marker_end) + len(marker_end)
                existing = existing[:start_idx] + existing[end_idx:]
            
            # Insert new task section
            return f"{existing}\n{marker_begin}\n{new}\n{marker_end}\n"
        else:
            return new  # Default to create

def load_project_spec(spec_file: Path) -> ProjectSpec:
    """Load project specification from YAML file."""
    with open(spec_file, 'r') as f:
        spec_data = yaml.safe_load(f)
    
    return ProjectSpec(
        name=spec_data['name'],
        stack=spec_data['stack'],
        tier=spec_data['tier'],
        tasks=spec_data.get('tasks', []),
        output_dir=Path(spec_data.get('output_dir', spec_data['name'])),
        config=spec_data.get('config', {})
    )

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Resolve {{PROJECT_NAME}} project specifications")
    parser.add_argument('spec_file', type=Path, help='Project specification YAML file')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without creating files')
    parser.add_argument('--templates-dir', type=Path, default=TEMPLATES_DIR, help='Templates directory path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--validate-tasks', action='store_true', help='Validate task configurations without materializing')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Load project specification
        spec = load_project_spec(args.spec_file)
        
        # Create resolver
        resolver = ProjectResolver(args.templates_dir, dry_run=args.dry_run)
        
        # Validate task configurations if requested
        if args.validate_tasks:
            validation_errors = resolver.validate_tasks(spec)
            if validation_errors:
                print("Task validation failed:")
                for error in validation_errors:
                    print(f"  ❌ {error}")
                sys.exit(1)
            else:
                print("✓ All task configurations are valid")
                return
        
        # Resolve project
        templates = resolver.resolve_project(spec)
        
        # Materialize project
        resolver.materialize_project(spec, templates)
        
        if not args.dry_run:
            print(f"✓ Project '{spec.name}' resolved successfully")
            print(f"  Output directory: {spec.output_dir}")
            print(f"  Templates applied: {len(templates)}")
        
    except Exception as e:
        logger.error(f"Failed to resolve project: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
