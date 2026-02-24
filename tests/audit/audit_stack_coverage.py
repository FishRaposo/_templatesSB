#!/usr/bin/env python3
"""
Audit stack coverage across all tasks
Identifies which stacks have templates for each task
"""

import os
import yaml
from pathlib import Path
from typing import Dict, List, Set

# Resolve project root for path consistency
PROJECT_ROOT = Path(__file__).parent.parent.parent

def load_task_index():
    """Load task index configuration"""
    with open(PROJECT_ROOT / 'tasks' / 'task-index.yaml', 'r') as f:
        return yaml.safe_load(f)

def audit_stack_templates():
    """Audit which stacks have templates for each task"""
    tasks_dir = PROJECT_ROOT / 'tasks'
    results = {}
    
    for task_dir in tasks_dir.iterdir():
        if not task_dir.is_dir() or task_dir.name.startswith('.'):
            continue
            
        task_name = task_dir.name
        stacks_dir = task_dir / 'stacks'
        
        if not stacks_dir.exists():
            continue
            
        # Check which stack directories exist and have content
        available_stacks = {}
        for stack_dir in stacks_dir.iterdir():
            if not stack_dir.is_dir():
                continue
                
            stack_name = stack_dir.name
            has_templates = len(list(stack_dir.glob('*.tpl.*'))) > 0 or len(list(stack_dir.rglob('*'))) > 1
            available_stacks[stack_name] = has_templates
        
        results[task_name] = available_stacks
    
    return results

def audit_allowed_stacks():
    """Get allowed stacks from task-index.yaml"""
    task_index = load_task_index()
    allowed_stacks = {}
    
    for task_name, task_config in task_index.get('tasks', {}).items():
        allowed = task_config.get('allowed_stacks', [])
        allowed_stacks[task_name] = set(allowed)
    
    return allowed_stacks

def generate_audit_report():
    """Generate comprehensive audit report"""
    print("🔍 Auditing Stack Coverage Across All Tasks")
    print("=" * 60)
    
    # Get current template coverage
    template_coverage = audit_stack_templates()
    allowed_stacks = audit_allowed_stacks()
    
    # All stacks we care about
    all_stacks = ['flutter', 'react_native', 'react', 'node', 'go', 'python', 'r', 'sql', 'generic', 'typescript']
    
    print(f"\n📊 Coverage Summary:")
    print(f"Total tasks: {len(template_coverage)}")
    print(f"Stacks to audit: {len(all_stacks)}")
    
    # Find missing templates
    missing_templates = {}
    for task_name, allowed in allowed_stacks.items():
        current_templates = set(template_coverage.get(task_name, {}).keys())
        missing = allowed - current_templates
        if missing:
            missing_templates[task_name] = missing
    
    print(f"\n❌ Tasks with Missing Templates: {len(missing_templates)}")
    
    # Generate detailed report
    print(f"\n📋 Detailed Stack Coverage:")
    for stack in all_stacks:
        tasks_with_stack = sum(1 for coverage in template_coverage.values() 
                             if stack in coverage and coverage[stack])
        tasks_allowed_stack = sum(1 for allowed in allowed_stacks.values() 
                                if stack in allowed)
        print(f"  {stack:12} | {tasks_with_stack:3}/{tasks_allowed_stack:3} tasks covered")
    
    print(f"\n🔧 Missing Template Details:")
    for task_name, missing in sorted(missing_templates.items()):
        if missing & {'r', 'sql'}:  # Focus on R/SQL for now
            print(f"  {task_name:25} | Missing: {', '.join(sorted(missing))}")
    
    # Generate reference project requirements
    main_stacks = ['flutter', 'react_native', 'react', 'node', 'go', 'python']
    print(f"\n🏗️  Reference Projects Needed:")
    print(f"  Main stacks: {len(main_stacks)}")
    print(f"  Tiers: 3 (mvp, core, enterprise)")
    print(f"  Total reference projects: {len(main_stacks) * 3}")
    
    return {
        'template_coverage': template_coverage,
        'allowed_stacks': allowed_stacks,
        'missing_templates': missing_templates,
        'main_stacks': main_stacks
    }

if __name__ == '__main__':
    os.chdir(Path(__file__).parent.parent)
    generate_audit_report()
