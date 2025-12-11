#!/usr/bin/env python3
"""
Task Browser - List tasks by virtual category
Provides organized view of tasks while maintaining flat physical structure
"""

import yaml
import sys
from pathlib import Path
from typing import Dict, List, Any

def load_task_index() -> Dict[str, Any]:
    """Load the task index file"""
    task_index_path = Path(__file__).parent.parent / "tasks" / "task-index.yaml"
    
    if not task_index_path.exists():
        print(f"❌ Error: task-index.yaml not found at {task_index_path}")
        sys.exit(1)
    
    with open(task_index_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def list_tasks_by_category(task_index: Dict[str, Any], show_details: bool = False) -> None:
    """Display tasks organized by virtual category"""
    
    virtual_categories = task_index.get('virtual_categories', {})
    tasks = task_index.get('tasks', {})
    
    print("🗂️  Tasks by Virtual Category")
    print("=" * 50)
    print()
    
    # Display each category
    for category_id, category_info in virtual_categories.items():
        display_name = category_info.get('display_name', category_id)
        description = category_info.get('description', '')
        category_tasks = category_info.get('tasks', [])
        
        print(f"📁 {display_name}")
        if description:
            print(f"   {description}")
        print()
        
        for task_id in category_tasks:
            if task_id in tasks:
                task_info = tasks[task_id]
                task_desc = task_info.get('description', 'No description')
                task_categories = task_info.get('categories', [])
                stacks = task_info.get('allowed_stacks', [])
                
                print(f"   📋 {task_id}")
                if show_details:
                    print(f"      📝 {task_desc}")
                    print(f"      🏷️  Categories: {', '.join(task_categories)}")
                    print(f"      🔧 Stacks: {', '.join(stacks)}")
                else:
                    print(f"      {task_desc}")
                print()
        
        print("-" * 40)
        print()

def list_category_summary(task_index: Dict[str, Any]) -> None:
    """Show summary of tasks per category"""
    
    virtual_categories = task_index.get('virtual_categories', {})
    
    print("📊 Category Summary")
    print("=" * 30)
    print()
    
    total_tasks = 0
    for category_id, category_info in virtual_categories.items():
        display_name = category_info.get('display_name', category_id)
        task_count = len(category_info.get('tasks', []))
        total_tasks += task_count
        
        print(f"📁 {display_name}: {task_count} tasks")
    
    print()
    print(f"📈 Total Tasks: {total_tasks}")

def search_tasks(task_index: Dict[str, Any], query: str) -> None:
    """Search tasks by name, description, or category"""
    
    tasks = task_index.get('tasks', {})
    virtual_categories = task_index.get('virtual_categories', {})
    
    # Create reverse mapping from task to category
    task_to_category = {}
    for cat_id, cat_info in virtual_categories.items():
        for task_id in cat_info.get('tasks', []):
            task_to_category[task_id] = cat_info.get('display_name', cat_id)
    
    query_lower = query.lower()
    matches = []
    
    for task_id, task_info in tasks.items():
        # Search in task ID, description, and categories
        if (query_lower in task_id.lower() or 
            query_lower in task_info.get('description', '').lower() or
            any(query_lower in cat.lower() for cat in task_info.get('categories', []))):
            
            matches.append((task_id, task_info, task_to_category.get(task_id, 'Unknown')))
    
    if matches:
        print(f"🔍 Search Results for '{query}':")
        print("=" * 40)
        print()
        
        for task_id, task_info, category in matches:
            print(f"📋 {task_id} ({category})")
            print(f"   📝 {task_info.get('description', 'No description')}")
            print()
    else:
        print(f"❌ No tasks found matching '{query}'")

def main():
    """Main CLI interface"""
    
    import argparse
    
    # Import prompt validation
    try:
        from prompt_validator import PromptValidator, ValidationLevel
    except ImportError:
        print("⚠️  Warning: Prompt validation not available, proceeding without validation")
    
    parser = argparse.ArgumentParser(description='Browse tasks by virtual category')
    parser.add_argument('--details', '-d', action='store_true', 
                       help='Show detailed task information')
    parser.add_argument('--summary', '-s', action='store_true',
                       help='Show category summary only')
    parser.add_argument('--search', nargs='?', metavar='QUERY',
                       help='Search tasks by name, description, or category')
    parser.add_argument('--category', nargs='?', metavar='CATEGORY_ID',
                       help='Show tasks from specific category only')
    
    args = parser.parse_args()
    
    # Validate inputs before processing
    try:
        validator = PromptValidator(ValidationLevel.STANDARD)
        
        # Validate search query if present (treat as project description)
        if args.search:
            search_result = validator.validate_project_description(args.search)
            if not search_result.is_valid:
                print("❌ Search query validation failed:")
                for error in search_result.errors:
                    print(f"   - {error}")
                sys.exit(1)
            
            # Show warnings for search
            if search_result.warnings:
                print("⚠️  Search query warnings:")
                for warning in search_result.warnings:
                    print(f"   - {warning}")
                print()
        
        # Validate category if present
        if args.category:
            args_dict = {'category': args.category}
            validation_result = validator.validate_cli_arguments(args_dict)
            
            if not validation_result.is_valid:
                print("❌ Input validation failed:")
                for error in validation_result.errors:
                    print(f"   - {error}")
                sys.exit(1)
            
            # Show warnings if any
            if validation_result.warnings:
                print("⚠️  Validation warnings:")
                for warning in validation_result.warnings:
                    print(f"   - {warning}")
                print()
                
    except Exception as e:
        print(f"⚠️  Validation error: {e}")
        print("Proceeding without validation...")
    
    # Load task index
    task_index = load_task_index()
    
    if args.search:
        search_tasks(task_index, args.search)
    elif args.summary:
        list_category_summary(task_index)
    elif args.category:
        virtual_categories = task_index.get('virtual_categories', {})
        if args.category in virtual_categories:
            category_info = virtual_categories[args.category]
            display_name = category_info.get('display_name', args.category)
            tasks = task_index.get('tasks', {})
            
            print(f"📁 {display_name}")
            print(f"   {category_info.get('description', '')}")
            print()
            
            for task_id in category_info.get('tasks', []):
                if task_id in tasks:
                    task_info = tasks[task_id]
                    print(f"   📋 {task_id}")
                    if args.details:
                        print(f"      📝 {task_info.get('description', 'No description')}")
                        print(f"      🏷️  Categories: {', '.join(task_info.get('categories', []))}")
                        print(f"      🔧 Stacks: {', '.join(task_info.get('allowed_stacks', []))}")
                    else:
                        print(f"      {task_info.get('description', 'No description')}")
                    print()
        else:
            print(f"❌ Category '{args.category}' not found")
            print("Available categories:")
            for cat_id in virtual_categories.keys():
                print(f"   - {cat_id}")
    else:
        list_tasks_by_category(task_index, args.details)

if __name__ == "__main__":
    main()
