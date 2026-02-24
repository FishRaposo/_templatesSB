#!/usr/bin/env python3
"""
Compare task lists between task-index.yaml and expanded-task-index.yaml
"""

import yaml
from pathlib import Path

def main():
    templates_dir = Path(__file__).parent.parent
    task_index_path = templates_dir / "tasks" / "task-index.yaml"
    expanded_task_index_path = templates_dir / "tasks" / "expanded-task-index.yaml"
    
    # Load task index
    with open(task_index_path, 'r', encoding='utf-8') as f:
        task_index = yaml.safe_load(f)
    
    # Load expanded task index
    with open(expanded_task_index_path, 'r', encoding='utf-8') as f:
        expanded_task_index = yaml.safe_load(f)
    
    task_index_tasks = set(task_index.get('tasks', {}).keys())
    expanded_tasks = set(expanded_task_index.get('tasks', {}).keys())
    
    print(f"Task index tasks: {len(task_index_tasks)}")
    print(f"Expanded tasks: {len(expanded_tasks)}")
    
    # Find differences
    only_in_task_index = task_index_tasks - expanded_tasks
    only_in_expanded = expanded_tasks - task_index_tasks
    
    print(f"\nTasks only in task-index.yaml ({len(only_in_task_index)}):")
    for task in sorted(only_in_task_index):
        print(f"  - {task}")
    
    print(f"\nTasks only in expanded-task-index.yaml ({len(only_in_expanded)}):")
    for task in sorted(only_in_expanded):
        print(f"  - {task}")
    
    print(f"\nCommon tasks ({len(task_index_tasks & expanded_tasks)}):")
    for task in sorted(task_index_tasks & expanded_tasks):
        print(f"  - {task}")

if __name__ == "__main__":
    main()
