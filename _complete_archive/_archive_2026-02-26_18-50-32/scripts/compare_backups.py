#!/usr/bin/env python3
"""
Compare backup files with current implementation to identify missing components
"""

import yaml
from pathlib import Path

def compare_task_index_files():
    """Compare backup and current task-index.yaml files"""
    
    # Load current task-index.yaml
    current_file = Path(__file__).parent.parent / 'tasks' / 'task-index.yaml'
    backup_file = Path(__file__).parent.parent / 'backups' / 'consolidation_backup_1765363095' / 'task-index.yaml'
    
    print("🔍 Comparing Task Index Files")
    print("=" * 50)
    
    try:
        with open(current_file, 'r', encoding='utf-8') as f:
            current_data = yaml.safe_load(f)
        
        with open(backup_file, 'r', encoding='utf-8') as f:
            backup_data = yaml.safe_load(f)
        
        # Compare virtual categories
        current_categories = current_data.get('virtual_categories', {})
        backup_categories = backup_data.get('virtual_categories', {})
        
        print(f"Current virtual categories: {len(current_categories)}")
        print(f"Backup virtual categories: {len(backup_categories)}")
        
        # Compare tasks
        current_tasks = current_data.get('tasks', {})
        backup_tasks = backup_data.get('tasks', {})
        
        print(f"Current tasks: {len(current_tasks)}")
        print(f"Backup tasks: {len(backup_tasks)}")
        
        # Find missing tasks
        current_task_names = set(current_tasks.keys())
        backup_task_names = set(backup_tasks.keys())
        
        missing_in_current = backup_task_names - current_task_names
        extra_in_current = current_task_names - backup_task_names
        
        if missing_in_current:
            print(f"\n❌ Tasks missing from current implementation:")
            for task in sorted(missing_in_current):
                print(f"  - {task}")
        
        if extra_in_current:
            print(f"\n✅ Tasks added to current implementation:")
            for task in sorted(extra_in_current):
                print(f"  - {task}")
        
        # Compare task configurations for common tasks
        common_tasks = current_task_names & backup_task_names
        config_differences = []
        
        for task_name in common_tasks:
            current_task = current_tasks[task_name]
            backup_task = backup_tasks[task_name]
            
            # Compare allowed_stacks
            current_stacks = set(current_task.get('allowed_stacks', []))
            backup_stacks = set(backup_task.get('allowed_stacks', []))
            
            if current_stacks != backup_stacks:
                config_differences.append({
                    'task': task_name,
                    'current_stacks': sorted(current_stacks),
                    'backup_stacks': sorted(backup_stacks)
                })
        
        if config_differences:
            print(f"\n📊 Stack configuration differences:")
            for diff in config_differences:
                print(f"  Task: {diff['task']}")
                print(f"    Current: {diff['current_stacks']}")
                print(f"    Backup:  {diff['backup_stacks']}")
        
        return {
            'missing_tasks': list(missing_in_current),
            'extra_tasks': list(extra_in_current),
            'config_differences': config_differences,
            'current_task_count': len(current_tasks),
            'backup_task_count': len(backup_tasks)
        }
        
    except Exception as e:
        print(f"Error comparing files: {e}")
        return None

def check_meta_yaml_files():
    """Check meta.yaml files for missing metadata"""
    
    backups_dir = Path(__file__).parent.parent / 'backups'
    meta_files = list(backups_dir.glob('meta*.yaml'))
    
    print(f"\n📋 Checking Meta YAML Files")
    print("=" * 50)
    print(f"Found {len(meta_files)} meta.yaml files")
    
    # Sample a few meta files to understand their structure
    sample_data = {}
    for i, meta_file in enumerate(meta_files[:5]):
        try:
            with open(meta_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                sample_data[meta_file.name] = data
                print(f"  {meta_file.name}: {list(data.keys()) if data else 'empty'}")
        except Exception as e:
            print(f"  Error reading {meta_file.name}: {e}")
    
    return sample_data

def check_system_map_backup():
    """Check SYSTEM-MAP backup for missing documentation"""
    
    backup_system_map = Path(__file__).parent.parent / 'backups' / 'SYSTEM-MAP-v2-tier-based.md'
    current_system_map = Path(__file__).parent.parent / 'SYSTEM-MAP.md'
    
    print(f"\n📚 Checking System Map Documentation")
    print("=" * 50)
    
    backup_content = backup_system_map.read_text(encoding='utf-8') if backup_system_map.exists() else ""
    current_content = current_system_map.read_text(encoding='utf-8') if current_system_map.exists() else ""
    
    print(f"Backup SYSTEM-MAP: {len(backup_content)} characters")
    print(f"Current SYSTEM-MAP: {len(current_content)} characters")
    
    # Look for unique sections in backup
    backup_lines = set(backup_content.split('\n'))
    current_lines = set(current_content.split('\n'))
    
    unique_in_backup = backup_lines - current_lines
    unique_in_current = current_lines - backup_lines
    
    if len(unique_in_backup) > 10:
        print(f"Backup has {len(unique_in_backup)} unique lines (may contain valuable content)")
    else:
        print("Backup and current SYSTEM-MAP are very similar")
    
    return {
        'backup_size': len(backup_content),
        'current_size': len(current_content),
        'unique_backup_lines': len(unique_in_backup)
    }

def main():
    """Run complete backup comparison"""
    print("🔍 COMPREHENSIVE BACKUP COMPARISON")
    print("=" * 80)
    
    # Compare task-index files
    task_comparison = compare_task_index_files()
    
    # Check meta.yaml files
    meta_data = check_meta_yaml_files()
    
    # Check system map
    system_map_comparison = check_system_map_backup()
    
    # Generate integration recommendations
    print(f"\n🎯 INTEGRATION RECOMMENDATIONS")
    print("=" * 80)
    
    if task_comparison and task_comparison['missing_tasks']:
        print("❌ CRITICAL: Missing tasks from current implementation")
        print("   Consider integrating these tasks before clearing backups")
    
    if task_comparison and task_comparison['config_differences']:
        print("⚠️  WARNING: Stack configuration differences found")
        print("   Review if backup configurations are better")
    
    if system_map_comparison and system_map_comparison['unique_backup_lines'] > 10:
        print("📚 INFO: Backup SYSTEM-MAP may have additional content")
        print("   Consider reviewing before clearing backups")
    
    if not task_comparison or not task_comparison['missing_tasks']:
        print("✅ Current implementation appears complete")
        print("   Ready to clear backups after final verification")
    
    return task_comparison, meta_data, system_map_comparison

if __name__ == "__main__":
    main()
