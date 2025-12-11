#!/usr/bin/env python3
"""
Comprehensive path fix for all moved test scripts using regex patterns
"""

import re
from pathlib import Path

def fix_remaining_scripts():
    """Fix path issues in remaining moved scripts using comprehensive regex patterns"""
    
    base_dir = Path(__file__).parent.parent
    
    # All moved script directories
    script_dirs = [
        base_dir / 'tests' / 'validation',
        base_dir / 'tests' / 'generation'  # audit is already fixed
    ]
    
    for script_dir in script_dirs:
        for script_file in script_dir.glob('*.py'):
            if script_file.name == '__init__.py':
                continue
                
            print(f"Comprehensive path fix for {script_file.name}")
            
            content = script_file.read_text(encoding='utf-8')
            original_content = content
            
            # Ensure PROJECT_ROOT is defined
            if 'PROJECT_ROOT' not in content:
                # Add after imports
                lines = content.split('\n')
                insert_idx = -1
                
                for i, line in enumerate(lines):
                    if line.startswith('def ') or line.startswith('class ') or line.startswith('if __name__'):
                        insert_idx = i
                        break
                
                if insert_idx == -1:
                    insert_idx = len(lines) - 1
                
                # Add Path import if needed
                if 'from pathlib import Path' not in content:
                    lines.insert(insert_idx, 'from pathlib import Path')
                    insert_idx += 1
                
                lines.insert(insert_idx, '# Resolve project root for path consistency')
                lines.insert(insert_idx + 1, 'PROJECT_ROOT = Path(__file__).parent.parent.parent')
                lines.insert(insert_idx + 2, '')
                
                content = '\n'.join(lines)
            
            # Regex patterns to fix various path usages
            patterns = [
                # open('tasks/file.yaml') -> open(PROJECT_ROOT / 'tasks' / 'file.yaml')
                (r"open\('([^']+)'\)", lambda m: f"open(PROJECT_ROOT / '{m.group(1)}'.replace('/', ' / '))"),
                
                # 'tasks/file.yaml' -> PROJECT_ROOT / 'tasks' / 'file.yaml'
                (r"'([^'/]+/[^'/]+)'", lambda m: f"PROJECT_ROOT / '{m.group(1).replace('/', ' / ')}'"),
                
                # Path('tasks') -> PROJECT_ROOT / 'tasks'
                (r"Path\('([^']+)'\)", lambda m: f"PROJECT_ROOT / '{m.group(1)}'"),
                
                # Fix duplicate PROJECT_ROOT that my previous script created
                (r"PROJECT_ROOT / PROJECT_ROOT /", lambda m: "PROJECT_ROOT / "),
                
                # Fix file operations with string paths
                (r"with open\('([^']+)'", lambda m: f"with open(PROJECT_ROOT / '{m.group(1)}'.replace('/', ' / '))"),
                
                # Fix Path operations
                (r"Path\('([^']+)'\)", lambda m: f"PROJECT_ROOT / '{m.group(1)}'"),
            ]
            
            # Apply patterns more carefully
            for pattern, replacement in patterns:
                try:
                    content = re.sub(pattern, replacement, content)
                except:
                    # Skip if regex fails
                    continue
            
            # Manual fixes for common patterns
            manual_fixes = [
                ("'tasks/task-index.yaml'", "PROJECT_ROOT / 'tasks' / 'task-index.yaml'"),
                ("'stacks/'", "PROJECT_ROOT / 'stacks' / "),
                ("'tiers/'", "PROJECT_ROOT / 'tiers' / "),
                ("'universal/'", "PROJECT_ROOT / 'universal' / "),
                ("'reference-projects/'", "PROJECT_ROOT / 'reference-projects' / "),
                ("'docs/'", "PROJECT_ROOT / 'docs' / "),
                ("'examples/'", "PROJECT_ROOT / 'examples' / "),
                ("'scripts/'", "PROJECT_ROOT / 'scripts' / "),
            ]
            
            for old, new in manual_fixes:
                content = content.replace(old, new)
            
            # Write back if changed
            if content != original_content:
                script_file.write_text(content, encoding='utf-8')
                print(f"  ✅ Updated {script_file.name}")
            else:
                print(f"  ℹ️  No changes needed for {script_file.name}")

def test_a_script():
    """Test one script to verify fixes work"""
    base_dir = Path(__file__).parent.parent
    
    # Test a validation script
    test_script = base_dir / 'tests' / 'validation' / 'validate_templates.py'
    if test_script.exists():
        print(f"\n🧪 Testing {test_script.name}...")
        try:
            import subprocess
            result = subprocess.run(['python', str(test_script), '--help'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("  ✅ Script runs successfully")
            else:
                print(f"  ❌ Script failed: {result.stderr}")
        except Exception as e:
            print(f"  ❌ Test failed: {e}")

def main():
    """Execute comprehensive path fixes"""
    print("🔧 COMPREHENSIVE PATH FIX FOR REMAINING SCRIPTS")
    print("=" * 70)
    
    fix_remaining_scripts()
    test_a_script()
    
    print("\n✅ Comprehensive path fixes completed!")
    print("All moved scripts should now work with proper path resolution")

if __name__ == "__main__":
    main()
