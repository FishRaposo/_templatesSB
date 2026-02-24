#!/usr/bin/env python3
"""
Documentation Link Fixer

Fixes broken documentation links across the Universal Template System.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple
import sys

class DocumentationFixer:
    def __init__(self, templates_root: Path):
        self.templates_root = templates_root
        self.fixes_applied = 0
        self.errors = []

    def fix_all_stack_readmes(self) -> None:
        """Fix broken universal/docs links in all stack READMEs."""
        print("🔧 Fixing Stack README Links...")
        print("=" * 50)
        
        stacks_dir = self.templates_root / "stacks"
        if not stacks_dir.exists():
            print("❌ Stacks directory not found")
            return
        
        # Find all README.md files in stacks
        readme_files = list(stacks_dir.rglob("README.md"))
        
        for readme_path in readme_files:
            self.fix_stack_readme(readme_path)
        
        print(f"\n✅ Fixed {self.fixes_applied} broken links across {len(readme_files)} README files")

    def fix_stack_readme(self, readme_path: Path) -> None:
        """Fix broken links in a specific stack README."""
        try:
            with open(readme_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            stack_name = readme_path.parent.name
            
            # Remove the entire Universal Development Patterns section
            universal_section_pattern = r'### \*\*Universal Development Patterns\*\*.*?(?=\n###|\n---|\n##|$)'
            content = re.sub(universal_section_pattern, '', content, flags=re.DOTALL)
            
            # Fix any remaining universal/docs references
            content = re.sub(r'\.\.\/\.\.\/\.\.\/universal\/docs\/[^)\s]+', '#', content)
            
            # Remove the "Located in ../../../universal/docs/" note
            content = re.sub(r'> 📖 Located in `../../../universal/docs/` - These apply to ALL technology stacks\n', '', content)
            
            # Clean up extra blank lines
            content = re.sub(r'\n{3,}', '\n\n', content)
            
            if content != original_content:
                with open(readme_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"  ✅ Fixed: {stack_name}/README.md")
                self.fixes_applied += 1
            else:
                print(f"  ✓ No fixes needed: {stack_name}/README.md")
                
        except Exception as e:
            self.errors.append(f"Error fixing {readme_path}: {e}")
            print(f"  ❌ Error: {stack_name}/README.md - {e}")

    def check_system_map_references(self) -> None:
        """Check and fix SYSTEM-MAP.md references."""
        print("\n🗺️ Checking SYSTEM-MAP.md References...")
        print("=" * 50)
        
        system_map_path = self.templates_root / "SYSTEM-MAP.md"
        if not system_map_path.exists():
            print("❌ SYSTEM-MAP.md not found")
            return
        
        # Find all references to SYSTEM-MAP.md
        all_files = list(self.templates_root.rglob("*.md"))
        
        for file_path in all_files:
            if file_path.name == "SYSTEM-MAP.md":
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for broken SYSTEM-MAP references
                if "../../SYSTEM-MAP.md" in content:
                    # Calculate correct relative path
                    relative_path = os.path.relpath(system_map_path, file_path.parent)
                    relative_path = relative_path.replace('\\', '/')  # Normalize for cross-platform
                    
                    content = content.replace("../../SYSTEM-MAP.md", relative_path)
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    print(f"  ✅ Fixed SYSTEM-MAP reference in: {file_path.relative_to(self.templates_root)}")
                    self.fixes_applied += 1
                    
            except Exception as e:
                self.errors.append(f"Error checking {file_path}: {e}")

    def validate_main_readme(self) -> None:
        """Validate main README.md references."""
        print("\n📋 Validating Main README.md...")
        print("=" * 50)
        
        readme_path = self.templates_root / "README.md"
        if not readme_path.exists():
            print("❌ README.md not found")
            return
        
        try:
            with open(readme_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check blueprint script references
            scripts_to_check = [
                "blueprint_config.py",
                "blueprint_resolver.py"
            ]
            
            scripts_dir = self.templates_root / "scripts"
            
            for script in scripts_to_check:
                script_path = scripts_dir / script
                if script_path.exists():
                    print(f"  ✓ {script} exists")
                else:
                    print(f"  ❌ {script} missing - referenced in README.md")
                    self.errors.append(f"Missing script: {script}")
            
            # Check task-index.yaml reference
            task_index_path = self.templates_root / "tasks" / "task-index.yaml"
            if task_index_path.exists():
                print(f"  ✓ task-index.yaml exists")
            else:
                print(f"  ❌ task-index.yaml missing - referenced in README.md")
                self.errors.append("Missing task-index.yaml")
                
        except Exception as e:
            self.errors.append(f"Error validating README.md: {e}")

    def report_results(self) -> None:
        """Report the results of all fixes."""
        print("\n" + "=" * 50)
        print("📊 Documentation Fix Results")
        print("=" * 50)
        
        print(f"Total fixes applied: {self.fixes_applied}")
        
        if self.errors:
            print(f"\n❌ Errors ({len(self.errors)}):")
            for error in self.errors:
                print(f"  • {error}")
        else:
            print("\n✅ All documentation links fixed successfully!")

def main():
    """Main fix script."""
    templates_root = Path(__file__).parent.parent
    
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: python fix_documentation_links.py")
        print("Fixes broken documentation links across the template system")
        return
    
    fixer = DocumentationFixer(templates_root)
    
    # Apply all fixes
    fixer.fix_all_stack_readmes()
    fixer.check_system_map_references()
    fixer.validate_main_readme()
    
    # Report results
    fixer.report_results()
    
    return 0 if not fixer.errors else 1

if __name__ == "__main__":
    sys.exit(main())
