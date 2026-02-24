#!/usr/bin/env python3
"""
Documentation Synchronization Script
Automatically updates documentation to match task-index.yaml content
Prevents drift between source data and documentation
"""

import yaml
import re
import sys
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

class DocumentationSynchronizer:
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent
        self.task_index_path = self.templates_dir / "tasks" / "task-index.yaml"
        self.docs_to_update = [
            "README.md",
            "docs/TASKS-GUIDE.md", 
            "SYSTEM-MAP.md"
        ]
        
    def load_task_index(self) -> Dict[str, Any]:
        """Load the task index file"""
        if not self.task_index_path.exists():
            print(f"❌ Error: task-index.yaml not found at {self.task_index_path}")
            sys.exit(1)
            
        with open(self.task_index_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def extract_category_data(self, task_index: Dict[str, Any]) -> Dict[str, Any]:
        """Extract category statistics and information"""
        virtual_categories = task_index.get('virtual_categories', {})
        
        category_data = {}
        total_tasks = 0
        total_templates = 0
        
        # Count actual template files on disk (same method as validate_templates.py)
        tasks_dir = self.templates_dir / "tasks"
        
        for cat_id, cat_info in virtual_categories.items():
            display_name = cat_info.get('display_name', cat_id)
            description = cat_info.get('description', '')
            category_tasks = cat_info.get('tasks', [])
            
            # Count actual .tpl.* files for this category
            category_template_count = 0
            for task_id in category_tasks:
                task_dir = tasks_dir / task_id
                if task_dir.exists():
                    universal_dir = task_dir / "universal" / "code"
                    if universal_dir.exists():
                        template_files = list(universal_dir.glob("*.tpl.*"))
                        category_template_count += len(template_files)
            
            category_data[cat_id] = {
                'display_name': display_name,
                'description': description,
                'task_count': len(category_tasks),
                'template_count': category_template_count,
                'tasks': category_tasks
            }
            
            total_tasks += len(category_tasks)
            total_templates += category_template_count
        
        return {
            'categories': category_data,
            'total_tasks': total_tasks,
            'total_templates': total_templates,
            'total_categories': len(virtual_categories)
        }
    
    def generate_category_table(self, category_data: Dict[str, Any]) -> str:
        """Generate markdown table for categories"""
        lines = [
            "| Category | Tasks | Description |",
            "|----------|-------|-------------|"
        ]
        
        for cat_id, cat_info in category_data['categories'].items():
            display_name = cat_info['display_name']
            task_count = cat_info['task_count']
            description = cat_info['description']
            
            # Truncate long descriptions for table
            if len(description) > 50:
                description = description[:47] + "..."
            
            lines.append(f"| **{display_name}** | {task_count} | {description} |")
        
        return "\n".join(lines)
    
    def generate_browse_commands(self) -> str:
        """Generate standardized browse commands section"""
        return """```bash
# Show category summary
python scripts/list_tasks_by_category.py --summary

# List all tasks by category
python scripts/list_tasks_by_category.py

# Show detailed task information
python scripts/list_tasks_by_category.py --details

# Search tasks
python scripts/list_tasks_by_category.py --search "scraping"

# Show specific category
python scripts/list_tasks_by_category.py --category web-api --details
```"""
    
    def update_readme(self, category_data: Dict[str, Any]) -> bool:
        """Update README.md with current category data"""
        readme_path = self.templates_dir / "README.md"
        
        if not readme_path.exists():
            print(f"❌ README.md not found")
            return False
        
        with open(readme_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Update task count in header
        content = re.sub(
            r'\*\*46 Production Tasks\*\*',
            f'**{category_data["total_tasks"]} Production Tasks**',
            content
        )
        
        # Update template count in header  
        content = re.sub(
            r'\*\*93 Template Files\*\*',
            f'**{category_data["total_templates"]} Template Files**',
            content
        )
        
        # Update category table
        new_table = self.generate_category_table(category_data)
        table_pattern = r'\| Category \| Tasks \| Description \|\|.*?\| \*\*Meta / Tooling\*\* \| \d+ \| Project scaffolding, documentation \|'
        
        if re.search(table_pattern, content, re.DOTALL):
            content = re.sub(table_pattern, new_table, content, flags=re.DOTALL)
            print(f"✅ Updated README.md category table")
        else:
            print(f"⚠️  Could not find category table pattern in README.md")
        
        # Write back
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return True
    
    def update_tasks_guide(self, category_data: Dict[str, Any]) -> bool:
        """Update TASKS-GUIDE.md with current category data"""
        tasks_guide_path = self.templates_dir / "docs" / "TASKS-GUIDE.md"
        
        if not tasks_guide_path.exists():
            print(f"❌ docs/TASKS-GUIDE.md not found")
            return False
        
        with open(tasks_guide_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Update task count
        content = re.sub(
            r'\*\*46 production tasks\*\*',
            f'**{category_data["total_tasks"]} production tasks**',
            content
        )
        
        content = re.sub(
            r'\*\*93 template files\*\*',
            f'**{category_data["total_templates"]} template files**',
            content
        )
        
        # Update category table
        new_table = self.generate_category_table(category_data)
        table_pattern = r'\| Category \| Tasks \| Description \|\|.*?\| \*\*Meta / Tooling Tasks\*\* \| \d+ \| Project scaffolding, documentation, test data generation \|'
        
        if re.search(table_pattern, content, re.DOTALL):
            content = re.sub(table_pattern, new_table, content, flags=re.DOTALL)
            print(f"✅ Updated TASKS-GUIDE.md category table")
        else:
            print(f"⚠️  Could not find category table pattern in TASKS-GUIDE.md")
        
        # Write back
        with open(tasks_guide_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return True
    
    def update_system_map(self, category_data: Dict[str, Any]) -> bool:
        """Update SYSTEM-MAP.md with current category data"""
        system_map_path = self.templates_dir / "SYSTEM-MAP.md"
        
        if not system_map_path.exists():
            print(f"❌ SYSTEM-MAP.md not found")
            return False
        
        with open(system_map_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Update header statistics
        content = re.sub(
            r'\*\*Total Tasks\**: 46 production tasks across 9 development categories',
            f'**Total Tasks**: {category_data["total_tasks"]} production tasks across {category_data["total_categories"]} development categories',
            content
        )
        
        content = re.sub(
            r'\*\*Total Templates\**: 93 template files',
            f'**Total Templates**: {category_data["total_templates"]} template files',
            content
        )
        
        # Update category overview table
        overview_lines = [
            "| Category | Tasks | Description | Key Examples |",
            "|----------|-------|-------------|--------------|"
        ]
        
        for cat_id, cat_info in category_data['categories'].items():
            display_name = cat_info['display_name']
            task_count = cat_info['task_count']
            description = cat_info['description']
            
            # Get first 3 tasks as examples
            tasks = cat_info['tasks'][:3]
            examples = ", ".join(tasks)
            if len(cat_info['tasks']) > 3:
                examples += "..."
            
            # Truncate description
            if len(description) > 40:
                description = description[:37] + "..."
            
            overview_lines.append(f"| **{display_name}** | {task_count} | {description} | {examples} |")
        
        new_overview = "\n".join(overview_lines)
        
        overview_pattern = r'\| Category \| Tasks \| Description \| Key Examples \|\|.*?\| \*\*Meta / Tooling Tasks\*\* \| \d+ \| Project scaffolding, documentation, development tools \| project-bootstrap, docs-site, sample-data-generator \|'
        
        if re.search(overview_pattern, content, re.DOTALL):
            content = re.sub(overview_pattern, new_overview, content, flags=re.DOTALL)
            print(f"✅ Updated SYSTEM-MAP.md category overview")
        else:
            print(f"⚠️  Could not find category overview pattern in SYSTEM-MAP.md")
        
        # Write back
        with open(system_map_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return True
    
    def validate_sync(self, category_data: Dict[str, Any]) -> bool:
        """Check if documentation is in sync with task-index.yaml"""
        issues = []
        
        # Check README.md
        readme_path = self.templates_dir / "README.md"
        if readme_path.exists():
            with open(readme_path, 'r', encoding='utf-8') as f:
                readme_content = f.read()
            
            if f"{category_data['total_tasks']} Production Tasks" not in readme_content:
                issues.append("README.md task count mismatch")
            
            if f"{category_data['total_templates']} Template Files" not in readme_content:
                issues.append("README.md template count mismatch")
        
        # Check other docs similarly...
        return len(issues) == 0
    
    def sync_all(self, validate_only: bool = False) -> bool:
        """Synchronize all documentation"""
        print("🔄 Starting documentation synchronization...")
        print("=" * 50)
        
        # Load current data
        task_index = self.load_task_index()
        category_data = self.extract_category_data(task_index)
        
        print(f"📊 Current Statistics:")
        print(f"   Total Tasks: {category_data['total_tasks']}")
        print(f"   Total Templates: {category_data['total_templates']}")
        print(f"   Total Categories: {category_data['total_categories']}")
        print()
        
        if validate_only:
            is_valid = self.validate_sync(category_data)
            if is_valid:
                print("✅ Documentation is already in sync!")
                return True
            else:
                print("❌ Documentation needs synchronization")
                return False
        
        # Update all documentation files
        success = True
        success &= self.update_readme(category_data)
        success &= self.update_tasks_guide(category_data)
        success &= self.update_system_map(category_data)
        
        if success:
            print("✅ All documentation synchronized successfully!")
            print(f"📅 Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print("❌ Some documentation updates failed")
        
        return success

def main():
    """Main CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Synchronize documentation with task-index.yaml')
    parser.add_argument('--validate-only', '-v', action='store_true',
                       help='Check if docs are in sync without updating')
    parser.add_argument('--auto', '-a', action='store_true',
                       help='Run automatically without prompts')
    
    args = parser.parse_args()
    
    synchronizer = DocumentationSynchronizer()
    
    if not args.auto:
        print("📝 Documentation Synchronization Tool")
        print("This tool updates README.md, TASKS-GUIDE.md, and SYSTEM-MAP.md")
        print("to match the current task-index.yaml content.")
        print()
        
        if not args.validate_only:
            response = input("Continue with synchronization? (y/N): ")
            if response.lower() not in ['y', 'yes']:
                print("❌ Synchronization cancelled")
                return
    
    success = synchronizer.sync_all(validate_only=args.validate_only)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
