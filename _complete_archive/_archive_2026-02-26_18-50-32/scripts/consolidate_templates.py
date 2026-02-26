#!/usr/bin/env python3
"""
Template System Consolidation Script

Consolidates the template system by:
1. Merging expanded-task-index.yaml into task-index.yaml
2. Removing redundant meta.yaml files
3. Fixing duplicate IDs and inconsistent paths
4. Creating a unified task index with complete metadata and file mappings

Usage:
    python scripts/consolidate_templates.py --validate
    python scripts/consolidate_templates.py --merge
    python scripts/consolidate_templates.py --cleanup
"""

import argparse
import yaml
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any
from collections import defaultdict
import shutil

class TemplateConsolidator:
    """Main template consolidation system"""
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent
        self.tasks_dir = self.templates_dir / "tasks"
        self.task_index_path = self.tasks_dir / "task-index.yaml"
        self.expanded_task_index_path = self.tasks_dir / "expanded-task-index.yaml"
        self.backup_dir = self.templates_dir / "backups"
        
        # Ensure backup directory exists
        self.backup_dir.mkdir(exist_ok=True)
        
    def validate_current_structure(self) -> Dict[str, Any]:
        """Validate the current template structure and identify issues"""
        print("🔍 Validating current template structure...")
        
        issues = {
            "duplicate_ids": [],
            "inconsistent_paths": [],
            "missing_universal_templates": [],
            "orphaned_meta_files": [],
            "metadata_mismatches": []
        }
        
        # Load task index
        try:
            with open(self.task_index_path, 'r', encoding='utf-8') as f:
                task_index = yaml.safe_load(f)
        except Exception as e:
            print(f"❌ Error loading task-index.yaml: {e}")
            return issues
        
        # Load expanded task index
        try:
            with open(self.expanded_task_index_path, 'r', encoding='utf-8') as f:
                expanded_task_index = yaml.safe_load(f)
        except Exception as e:
            print(f"❌ Error loading expanded-task-index.yaml: {e}")
            return issues
        
        tasks = task_index.get('tasks', {})
        expanded_tasks = expanded_task_index.get('tasks', {})
        
        # Check for duplicate file IDs within each task
        for task_id, task_data in tasks.items():
            files = task_data.get('files', [])
            id_counts = defaultdict(int)
            
            for file_mapping in files:
                file_id = file_mapping.get('id', '')
                id_counts[file_id] += 1
            
            for file_id, count in id_counts.items():
                if count > 1:
                    issues["duplicate_ids"].append(f"{task_id}: {file_id} (appears {count} times)")
        
        # Check for inconsistent paths (backslashes vs forward slashes)
        for task_id, task_data in tasks.items():
            files = task_data.get('files', [])
            
            for file_mapping in files:
                target_path = file_mapping.get('target_path', '')
                universal_template = file_mapping.get('universal_template', '')
                
                if '\\' in target_path:
                    issues["inconsistent_paths"].append(f"{task_id}: target_path uses backslashes: {target_path}")
                
                if '\\' in universal_template:
                    issues["inconsistent_paths"].append(f"{task_id}: universal_template uses backslashes: {universal_template}")
        
        # Check for missing universal templates
        for task_id, task_data in tasks.items():
            files = task_data.get('files', [])
            
            for file_mapping in files:
                universal_template = file_mapping.get('universal_template', '')
                if universal_template:
                    # Fix path resolution - universal_template is relative to templates_dir, not tasks_dir
                    template_path = self.templates_dir / universal_template
                    if not template_path.exists():
                        issues["missing_universal_templates"].append(f"{task_id}: {universal_template}")
        
        # Check for orphaned meta files
        meta_files = list(self.tasks_dir.glob("*/meta.yaml"))
        for meta_file in meta_files:
            task_id = meta_file.parent.name
            if task_id not in tasks:
                issues["orphaned_meta_files"].append(str(meta_file))
        
        # Check for metadata mismatches between task-index and expanded-task-index
        for task_id in tasks:
            if task_id in expanded_tasks:
                task_data = tasks[task_id]
                expanded_data = expanded_tasks[task_id]
                
                # Compare descriptions
                desc1 = task_data.get('description', '').strip()
                desc2 = expanded_data.get('description', '').strip()
                if desc1 != desc2 and desc1 and desc2:
                    issues["metadata_mismatches"].append(f"{task_id}: description differs")
                
                # Compare categories
                cats1 = sorted(task_data.get('categories', []))
                cats2 = sorted(expanded_data.get('categories', []))
                if cats1 != cats2:
                    issues["metadata_mismatches"].append(f"{task_id}: categories differ")
        
        return issues
    
    def create_backup(self) -> None:
        """Create backup of current files before consolidation"""
        print("💾 Creating backup...")
        
        timestamp = str(int(Path(__file__).stat().st_mtime))
        backup_folder = self.backup_dir / f"consolidation_backup_{timestamp}"
        backup_folder.mkdir(exist_ok=True)
        
        # Backup main files
        shutil.copy2(self.task_index_path, backup_folder / "task-index.yaml")
        shutil.copy2(self.expanded_task_index_path, backup_folder / "expanded-task-index.yaml")
        
        # Backup meta files
        meta_files = list(self.tasks_dir.glob("*/meta.yaml"))
        for meta_file in meta_files:
            relative_path = meta_file.relative_to(self.tasks_dir)
            backup_path = backup_folder / relative_path
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(meta_file, backup_path)
        
        print(f"✅ Backup created: {backup_folder}")
    
    def merge_task_indices(self) -> Dict[str, Any]:
        """Merge expanded-task-index.yaml into task-index.yaml"""
        print("🔗 Merging task indices...")
        
        # Load both files
        with open(self.task_index_path, 'r', encoding='utf-8') as f:
            task_index = yaml.safe_load(f)
        
        with open(self.expanded_task_index_path, 'r', encoding='utf-8') as f:
            expanded_task_index = yaml.safe_load(f)
        
        merged_index = {
            "tasks": {},
            "task_config": task_index.get("task_config", {}),
            "task_dependencies": expanded_task_index.get("task_dependencies", {})
        }
        
        tasks = task_index.get('tasks', {})
        expanded_tasks = expanded_task_index.get('tasks', {})
        
        # Merge task data
        for task_id in expanded_tasks:
            if task_id in tasks:
                # Task exists in both - merge data
                task_data = tasks[task_id]
                expanded_data = expanded_tasks[task_id]
                
                merged_task = {
                    # Use expanded metadata (better organized)
                    "description": expanded_data.get("description", ""),
                    "categories": expanded_data.get("categories", []),
                    "default_stacks": expanded_data.get("default_stacks", []),
                    "allowed_stacks": expanded_data.get("allowed_stacks", []),
                    "recommended_tier": expanded_data.get("recommended_tier", {}),
                    
                    # Keep file mappings from task-index
                    "files": task_data.get("files", [])
                }
                
                merged_index["tasks"][task_id] = merged_task
            else:
                # Task only in expanded - add without file mappings
                print(f"⚠️  Task {task_id} found only in expanded index, no file mappings available")
                merged_index["tasks"][task_id] = expanded_tasks[task_id]
        
        # Add any tasks that are only in task-index (shouldn't happen, but just in case)
        for task_id in tasks:
            if task_id not in merged_index["tasks"]:
                merged_index["tasks"][task_id] = tasks[task_id]
        
        return merged_index
    
    def fix_file_mappings(self, merged_index: Dict[str, Any]) -> Dict[str, Any]:
        """Fix issues in file mappings (duplicate IDs, inconsistent paths)"""
        print("🔧 Fixing file mappings...")
        
        tasks = merged_index.get('tasks', {})
        
        for task_id, task_data in tasks.items():
            files = task_data.get('files', [])
            
            # Remove duplicate file IDs, keeping the last occurrence
            seen_ids = set()
            fixed_files = []
            
            for file_mapping in files:
                file_id = file_mapping.get('id', '')
                
                # Fix path separators
                if 'target_path' in file_mapping:
                    file_mapping['target_path'] = file_mapping['target_path'].replace('\\', '/')
                
                if 'universal_template' in file_mapping:
                    file_mapping['universal_template'] = file_mapping['universal_template'].replace('\\', '/')
                
                # Handle stack overrides
                if 'stack_overrides' in file_mapping:
                    for stack, template_path in file_mapping['stack_overrides'].items():
                        file_mapping['stack_overrides'][stack] = template_path.replace('\\', '/')
                
                # Remove duplicates (keep last)
                if file_id not in seen_ids:
                    seen_ids.add(file_id)
                    fixed_files.append(file_mapping)
                else:
                    print(f"  🗑️  Removing duplicate {file_id} in {task_id}")
            
            task_data['files'] = fixed_files
        
        return merged_index
    
    def write_unified_task_index(self, unified_index: Dict[str, Any]) -> None:
        """Write the unified task index"""
        print("📝 Writing unified task index...")
        
        # Write to temporary file first
        temp_path = self.task_index_path.with_suffix('.tmp.yaml')
        
        with open(temp_path, 'w', encoding='utf-8') as f:
            yaml.dump(unified_index, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        # Verify the file is valid YAML
        try:
            with open(temp_path, 'r', encoding='utf-8') as f:
                yaml.safe_load(f)
        except Exception as e:
            print(f"❌ Generated invalid YAML: {e}")
            temp_path.unlink()
            return
        
        # Replace original
        shutil.move(temp_path, self.task_index_path)
        print(f"✅ Unified task index written: {self.task_index_path}")
    
    def cleanup_redundant_files(self) -> None:
        """Remove redundant files after consolidation"""
        print("🧹 Cleaning up redundant files...")
        
        # Remove expanded-task-index.yaml
        if self.expanded_task_index_path.exists():
            backup_path = self.backup_dir / "expanded-task-index.yaml.backup"
            shutil.move(self.expanded_task_index_path, backup_path)
            print(f"  🗑️  Moved expanded-task-index.yaml to backup")
        
        # Remove individual meta.yaml files (they're now in the unified index)
        meta_files = list(self.tasks_dir.glob("*/meta.yaml"))
        removed_count = 0
        
        for meta_file in meta_files:
            backup_path = self.backup_dir / meta_file.name
            # Ensure unique backup name
            counter = 1
            while backup_path.exists():
                stem = meta_file.stem
                backup_path = self.backup_dir / f"{stem}_{counter}.yaml"
                counter += 1
            
            shutil.move(meta_file, backup_path)
            removed_count += 1
        
        print(f"  🗑️  Moved {removed_count} meta.yaml files to backup")
        
        # Remove generated-task-index.yaml if it exists
        generated_path = self.tasks_dir / "generated-task-index.yaml"
        if generated_path.exists():
            backup_path = self.backup_dir / "generated-task-index.yaml.backup"
            shutil.move(generated_path, backup_path)
            print(f"  🗑️  Moved generated-task-index.yaml to backup")
    
    def generate_meta_files_from_index(self) -> None:
        """Generate individual meta.yaml files from unified index (optional)"""
        print("📄 Generating meta.yaml files from unified index...")
        
        with open(self.task_index_path, 'r', encoding='utf-8') as f:
            unified_index = yaml.safe_load(f)
        
        tasks = unified_index.get('tasks', {})
        
        for task_id, task_data in tasks.items():
            meta_path = self.tasks_dir / task_id / "meta.yaml"
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            
            meta_data = {
                "name": task_id.replace('-', ' ').title(),
                "description": task_data.get("description", ""),
                "version": "1.0.0",
                "categories": task_data.get("categories", []),
                "compatibility": {
                    "default_stacks": task_data.get("default_stacks", []),
                    "allowed_stacks": task_data.get("allowed_stacks", [])
                },
                "tier_recommendations": task_data.get("recommended_tier", {}),
                "files_count": len(task_data.get("files", []))
            }
            
            with open(meta_path, 'w', encoding='utf-8') as f:
                yaml.dump(meta_data, f, default_flow_style=False, allow_unicode=True)
        
        print(f"✅ Generated {len(tasks)} meta.yaml files")
    
    def validate_consolidated_system(self) -> bool:
        """Validate the consolidated system"""
        print("✅ Validating consolidated system...")
        
        try:
            # Test resolver compatibility
            resolve_script = self.templates_dir / "scripts" / "resolve_project.py"
            if resolve_script.exists():
                import subprocess
                result = subprocess.run([
                    sys.executable, str(resolve_script), 
                    "--help"
                ], capture_output=True, text=True, cwd=self.templates_dir)
                
                if result.returncode == 0:
                    print("  ✅ Resolver script is accessible")
                else:
                    print("  ⚠️  Resolver script may have issues")
            
            # Validate YAML structure
            with open(self.task_index_path, 'r', encoding='utf-8') as f:
                unified_index = yaml.safe_load(f)
            
            required_sections = ['tasks', 'task_config', 'task_dependencies']
            for section in required_sections:
                if section not in unified_index:
                    print(f"  ❌ Missing required section: {section}")
                    return False
            
            tasks = unified_index.get('tasks', {})
            print(f"  ✅ Unified index contains {len(tasks)} tasks")
            
            # Check for basic structure in each task
            for task_id, task_data in tasks.items():
                required_fields = ['description', 'categories', 'allowed_stacks']
                for field in required_fields:
                    if field not in task_data:
                        print(f"  ⚠️  Task {task_id} missing field: {field}")
            
            print("  ✅ Consolidated system validation complete")
            return True
            
        except Exception as e:
            print(f"  ❌ Validation failed: {e}")
            return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Template System Consolidation")
    parser.add_argument("--validate", action="store_true", help="Validate current structure")
    parser.add_argument("--merge", action="store_true", help="Merge task indices")
    parser.add_argument("--cleanup", action="store_true", help="Clean up redundant files")
    parser.add_argument("--generate-meta", action="store_true", help="Generate meta files from index")
    parser.add_argument("--full", action="store_true", help="Run full consolidation")
    
    args = parser.parse_args()
    
    consolidator = TemplateConsolidator()
    
    if args.validate or args.full:
        print("=== Template Structure Validation ===")
        issues = consolidator.validate_current_structure()
        
        total_issues = sum(len(issue_list) for issue_list in issues.values())
        if total_issues == 0:
            print("✅ No structural issues found")
        else:
            print(f"⚠️  Found {total_issues} issues:")
            for issue_type, issue_list in issues.items():
                if issue_list:
                    print(f"  {issue_type}: {len(issue_list)} items")
                    for issue in issue_list[:3]:  # Show first 3
                        print(f"    - {issue}")
                    if len(issue_list) > 3:
                        print(f"    ... and {len(issue_list) - 3} more")
    
    if args.merge or args.full:
        print("\n=== Task Index Merge ===")
        consolidator.create_backup()
        
        merged_index = consolidator.merge_task_indices()
        fixed_index = consolidator.fix_file_mappings(merged_index)
        consolidator.write_unified_task_index(fixed_index)
    
    if args.cleanup or args.full:
        print("\n=== Cleanup Redundant Files ===")
        consolidator.cleanup_redundant_files()
    
    if args.generate_meta:
        print("\n=== Generate Meta Files ===")
        consolidator.generate_meta_files_from_index()
    
    if args.merge or args.full:
        print("\n=== Post-Consolidation Validation ===")
        if consolidator.validate_consolidated_system():
            print("🎉 Template consolidation completed successfully!")
        else:
            print("❌ Consolidation validation failed - check backup files")
    
    if not any([args.validate, args.merge, args.cleanup, args.generate_meta, args.full]):
        parser.print_help()

if __name__ == "__main__":
    main()
