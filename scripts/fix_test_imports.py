#!/usr/bin/env python3
"""
Fix import statements in unit tests after moving test scripts to tests/ subdirectories
"""

import re
from pathlib import Path

def fix_unit_test_imports():
    """Update import statements in unit test files"""
    
    base_dir = Path(__file__).parent.parent
    unit_tests_dir = base_dir / 'tests' / 'unit'
    
    # Find all Python files in unit tests
    test_files = list(unit_tests_dir.glob('*.py'))
    
    # Define import mappings
    import_mappings = {
        'import validate_templates': 'import sys\nsys.path.insert(0, str(Path(__file__).parent.parent.parent / "tests" / "validation"))\nimport validate_templates',
        'import audit_stack_coverage': 'import sys\nsys.path.insert(0, str(Path(__file__).parent.parent.parent / "tests" / "audit"))\nimport audit_stack_coverage',
        'import generate_smoke_tests': 'import sys\nsys.path.insert(0, str(Path(__file__).parent.parent.parent / "tests" / "generation"))\nimport generate_smoke_tests',
        'import generate_tests': 'import sys\nsys.path.insert(0, str(Path(__file__).parent.parent.parent / "tests" / "generation"))\nimport generate_tests',
    }
    
    for test_file in test_files:
        print(f"Fixing imports in {test_file.name}")
        
        content = test_file.read_text(encoding='utf-8')
        original_content = content
        
        # Add Path import at the top if not present
        if 'from pathlib import Path' not in content and 'import sys' not in content:
            content = 'from pathlib import Path\n' + content
        
        # Replace imports
        for old_import, new_import in import_mappings.items():
            if old_import in content and new_import not in content:
                content = content.replace(old_import, new_import)
                print(f"  ✅ Updated {old_import}")
        
        # Write back if changed
        if content != original_content:
            test_file.write_text(content, encoding='utf-8')
            print(f"  ✅ Updated {test_file.name}")
        else:
            print(f"  ℹ️  No changes needed for {test_file.name}")

def fix_script_internal_imports():
    """Fix imports within the moved scripts themselves"""
    
    base_dir = Path(__file__).parent.parent
    
    # Check for internal imports in moved scripts
    script_dirs = [
        base_dir / 'tests' / 'validation',
        base_dir / 'tests' / 'audit',
        base_dir / 'tests' / 'generation'
    ]
    
    for script_dir in script_dirs:
        for script_file in script_dir.glob('*.py'):
            if script_file.name == '__init__.py':
                continue
                
            content = script_file.read_text(encoding='utf-8')
            
            # Check for imports from scripts/ that need updating
            if 'import ' in content and 'scripts.' in content:
                print(f"Checking internal imports in {script_file.name}")
                # This would need specific handling based on actual imports found
                # For now, just report the files that might need attention
                print(f"  ⚠️  May need import fixes in {script_file}")

def main():
    """Execute import fixes"""
    print("🔧 FIXING UNIT TEST IMPORTS")
    print("=" * 50)
    
    fix_unit_test_imports()
    fix_script_internal_imports()
    
    print("\n✅ Import fixes completed!")
    print("Unit tests should now work with the new test infrastructure structure")

if __name__ == "__main__":
    main()
