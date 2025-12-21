#!/usr/bin/env python3
"""
Update task-index.yaml with accurate stack support levels
This script distinguishes between stacks with full task-specific implementations
and those that only have base templates.
"""

import yaml
from pathlib import Path
from typing import Dict, Set, List

# Stacks that have task-specific implementations (based on our analysis)
FULL_SUPPORT_STACKS = {
    'python',    # Has implementations in all tasks
    'node',      # Has implementations in all tasks
    'go',        # Has some implementations
    'nextjs'     # Has some implementations
}

# Stacks that only have base templates
BASE_TEMPLATE_STACKS = {
    'rust',
    'typescript', 
    'flutter',
    'react',
    'react_native',
    'r',
    'sql',
    'generic'
}

def check_task_stack_implementations(task_name: str, tasks_dir: Path) -> Set[str]:
    """Check which stacks have implementations for a specific task"""
    task_dir = tasks_dir / task_name
    stacks_dir = task_dir / 'stacks'
    
    if not stacks_dir.exists():
        return set()
    
    implemented_stacks = set()
    for stack_dir in stacks_dir.iterdir():
        if stack_dir.is_dir():
            implemented_stacks.add(stack_dir.name)
    
    return implemented_stacks

def update_task_index():
    """Update task-index.yaml with support_level information"""
    templates_root = Path(__file__).parent.parent
    tasks_dir = templates_root / 'tasks'
    task_index_path = tasks_dir / 'task-index.yaml'
    
    # Load existing task-index.yaml
    with open(task_index_path, 'r') as f:
        task_index = yaml.safe_load(f)
    
    # Update each task with support_level information
    for task_name, task_config in task_index.get('tasks', {}).items():
        implemented_stacks = check_task_stack_implementations(task_name, tasks_dir)
        
        # Update allowed_stacks to reflect actual implementation
        allowed = task_config.get('allowed_stacks', [])
        if allowed:
            # Add support_level field
            stack_support = {}
            for stack in allowed:
                if stack in implemented_stacks:
                    stack_support[stack] = 'full'
                else:
                    stack_support[stack] = 'base-fallback'
            
            task_config['stack_support'] = stack_support
            
            # Log the update
            print(f"Updated {task_name}:")
            for stack, level in stack_support.items():
                print(f"  {stack}: {level}")
    
    # Save updated task-index.yaml
    with open(task_index_path, 'w') as f:
        yaml.dump(task_index, f, default_flow_style=False, sort_keys=False)
    
    print(f"\n✅ Updated task-index.yaml with stack support levels")

if __name__ == '__main__':
    update_task_index()
