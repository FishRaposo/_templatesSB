#!/usr/bin/env python3
"""
Test Template Validation Script
Validates syntax and basic structure of all test templates
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Template validation rules
VALIDATION_RULES = {
    'dart': {
        'extension': '.dart',
        'command': ['dart', 'analyze'],
        'required_imports': ['flutter_test', 'test'],
    },
    'py': {
        'extension': '.py',
        'command': ['python', '-m', 'py_compile'],
        'required_imports': ['pytest'],
    },
    'js': {
        'extension': '.js',
        'command': ['node', '-c'],
        'required_imports': ['jest'],
    },
    'jsx': {
        'extension': '.jsx',
        'command': ['node', '-c'],
        'required_imports': ['react'],
    }
}

def validate_template_syntax(file_path: Path, file_type: str) -> Tuple[bool, List[str]]:
    """Validate template syntax using appropriate tool"""
    errors = []
    rule = VALIDATION_RULES.get(file_type)
    
    if not rule:
        return False, [f"Unsupported file type: {file_type}"]
    
    try:
        # Check syntax
        result = subprocess.run(
            rule['command'] + [str(file_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            errors.append(f"Syntax error: {result.stderr.strip()}")
        
        # Check required imports
        content = file_path.read_text(encoding='utf-8')
        for required_import in rule['required_imports']:
            if required_import not in content:
                errors.append(f"Missing required import: {required_import}")
        
        # Check template placeholders
        if '[[.Author]]' not in content:
            errors.append("Missing template placeholder: [[.Author]]")
        if '[[.Version]]' not in content:
            errors.append("Missing template placeholder: [[.Version]]")
        
        return len(errors) == 0, errors
        
    except subprocess.TimeoutExpired:
        return False, ["Validation timed out"]
    except Exception as e:
        return False, [f"Validation error: {str(e)}"]

def find_test_templates() -> Dict[str, List[Path]]:
    """Find all test template files"""
    templates = {
        'dart': [],
        'py': [],
        'js': [],
        'jsx': []
    }
    
    stacks_dir = Path('stacks')
    if not stacks_dir.exists():
        print("❌ stacks directory not found")
        return templates
    
    for stack_dir in stacks_dir.iterdir():
        if not stack_dir.is_dir():
            continue
            
        tests_dir = stack_dir / 'base' / 'tests'
        if not tests_dir.exists():
            continue
        
        for file_path in tests_dir.glob('*.tpl.*'):
            if file_path.suffix in ['.dart', '.py', '.js', '.jsx']:
                templates[file_path.suffix[1:]].append(file_path)
    
    return templates

def main():
    """Main validation function"""
    print("🧪 Validating Test Templates")
    print("=" * 40)
    
    templates = find_test_templates()
    total_files = sum(len(files) for files in templates.values())
    
    if total_files == 0:
        print("❌ No test template files found")
        return False
    
    print(f"📁 Found {total_files} test template files")
    
    all_valid = True
    
    for file_type, files in templates.items():
        if not files:
            continue
            
        print(f"\n🔍 Validating {file_type.upper()} files...")
        
        for file_path in files:
            print(f"  📄 {file_path.name}")
            
            is_valid, errors = validate_template_syntax(file_path, file_type)
            
            if is_valid:
                print("    ✅ Valid")
            else:
                print("    ❌ Invalid:")
                for error in errors:
                    print(f"       - {error}")
                all_valid = False
    
    print("\n" + "=" * 40)
    if all_valid:
        print("🎉 All test templates are valid!")
        return True
    else:
        print("❌ Some test templates have issues")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
