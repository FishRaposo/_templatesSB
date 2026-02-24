#!/usr/bin/env python3
"""
Fix path resolution in all moved test scripts to use project root
"""

import re
from pathlib import Path

def fix_script_paths():
    """Add project root resolution to all moved test scripts"""
    
    base_dir = Path(__file__).parent.parent
    
    # All moved script directories
    script_dirs = [
        base_dir / 'tests' / 'validation',
        base_dir / 'tests' / 'audit', 
        base_dir / 'tests' / 'generation'
    ]
    
    # Path resolution code to insert
    path_resolution = """# Resolve project root for path consistency
PROJECT_ROOT = Path(__file__).parent.parent.parent
"""
    
    for script_dir in script_dirs:
        for script_file in script_dir.glob('*.py'):
            if script_file.name == '__init__.py':
                continue
                
            print(f"Fixing paths in {script_file.name}")
            
            content = script_file.read_text(encoding='utf-8')
            original_content = content
            
            # Add Path import if not present
            if 'from pathlib import Path' not in content:
                # Find first import line and add after it
                lines = content.split('\n')
                import_idx = -1
                for i, line in enumerate(lines):
                    if line.startswith('import ') or line.startswith('from '):
                        import_idx = i
                    elif line.strip() == '' and import_idx >= 0:
                        # Found blank line after imports
                        break
                    elif not line.startswith('import ') and not line.startswith('from ') and import_idx >= 0:
                        # End of import section
                        break
                
                if import_idx >= 0:
                    lines.insert(import_idx + 1, 'from pathlib import Path')
                    content = '\n'.join(lines)
            
            # Add project root resolution after imports
            if 'PROJECT_ROOT' not in content:
                # Find where to insert (after imports, before main code)
                lines = content.split('\n')
                insert_idx = -1
                
                for i, line in enumerate(lines):
                    if line.startswith('def ') or line.startswith('class ') or line.startswith('if __name__'):
                        insert_idx = i
                        break
                
                if insert_idx == -1:
                    # Insert before last line if no functions found
                    insert_idx = len(lines) - 1
                
                lines.insert(insert_idx, path_resolution)
                content = '\n'.join(lines)
            
            # Replace relative paths with PROJECT_ROOT
            replacements = [
                ("Path('tasks')", "PROJECT_ROOT / 'tasks'"),
                ("Path('stacks')", "PROJECT_ROOT / 'stacks'"),
                ("Path('tiers')", "PROJECT_ROOT / 'tiers'"),
                ("Path('universal')", "PROJECT_ROOT / 'universal'"),
                ("Path('docs')", "PROJECT_ROOT / 'docs'"),
                ("Path('examples')", "PROJECT_ROOT / 'examples'"),
                ("Path('reference-projects')", "PROJECT_ROOT / 'reference-projects'"),
                ("Path('scripts')", "PROJECT_ROOT / 'scripts'"),
                ("Path('reports')", "PROJECT_ROOT / 'reports'"),
                ("'tasks'", "PROJECT_ROOT / 'tasks'"),
                ("'stacks'", "PROJECT_ROOT / 'stacks'"),
                ("'tiers'", "PROJECT_ROOT / 'tiers'"),
                ("'reference-projects'", "PROJECT_ROOT / 'reference-projects'"),
            ]
            
            for old_path, new_path in replacements:
                # Only replace if it's not already using PROJECT_ROOT
                if old_path in content and 'PROJECT_ROOT' not in old_path:
                    content = content.replace(old_path, new_path)
            
            # Write back if changed
            if content != original_content:
                script_file.write_text(content, encoding='utf-8')
                print(f"  ✅ Updated {script_file.name}")
            else:
                print(f"  ℹ️  No changes needed for {script_file.name}")

def main():
    """Execute path fixes"""
    print("🔧 FIXING SCRIPT PATH RESOLUTION")
    print("=" * 60)
    
    fix_script_paths()
    
    print("\n✅ Path fixes completed!")
    print("All moved scripts now use PROJECT_ROOT for consistent path resolution")

if __name__ == "__main__":
    main()
