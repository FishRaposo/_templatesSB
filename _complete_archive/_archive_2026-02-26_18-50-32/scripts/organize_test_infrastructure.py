#!/usr/bin/env python3
"""
Organize test infrastructure by moving test-related code from scripts/ to tests/
"""

import shutil
from pathlib import Path

def create_test_structure():
    """Create organized test directory structure"""
    
    base_dir = Path(__file__).parent.parent
    
    # Create test subdirectories
    test_dirs = [
        base_dir / 'tests' / 'validation',
        base_dir / 'tests' / 'audit', 
        base_dir / 'tests' / 'generation'
    ]
    
    for test_dir in test_dirs:
        test_dir.mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {test_dir}")
    
    return test_dirs

def move_test_scripts():
    """Move test-related scripts to appropriate test directories"""
    
    base_dir = Path(__file__).parent.parent
    scripts_dir = base_dir / 'scripts'
    
    # Define which scripts go where
    validation_scripts = [
        'validate_templates.py',
        'validate-foundational-templates.py',
        'validate-tier-compliance.py',
        'validate_docs.py',
        'validate_feature_documentation.py',
        'validate_template_versions.py',
        'validation_protocol_v2.py',
        'verify_templates.py'
    ]
    
    audit_scripts = [
        'audit_stack_coverage.py',
        'audit_template_consistency.py'
    ]
    
    generation_scripts = [
        'generate_smoke_tests.py',
        'generate_tests.py'
    ]
    
    # Move validation scripts
    for script in validation_scripts:
        src = scripts_dir / script
        dst = base_dir / 'tests' / 'validation' / script
        if src.exists():
            shutil.move(str(src), str(dst))
            print(f"✅ Moved {script} to tests/validation/")
    
    # Move audit scripts
    for script in audit_scripts:
        src = scripts_dir / script
        dst = base_dir / 'tests' / 'audit' / script
        if src.exists():
            shutil.move(str(src), str(dst))
            print(f"✅ Moved {script} to tests/audit/")
    
    # Move generation scripts
    for script in generation_scripts:
        src = scripts_dir / script
        dst = base_dir / 'tests' / 'generation' / script
        if src.exists():
            shutil.move(str(src), str(dst))
            print(f"✅ Moved {script} to tests/generation/")

def update_documentation_references():
    """Update documentation to reference new script locations"""
    
    base_dir = Path(__file__).parent.parent
    
    # Files that need updates
    files_to_update = [
        base_dir / 'QUICKSTART.md',
        base_dir / 'README.md',
        base_dir / 'SYSTEM-MAP.md',
        base_dir / 'reference-projects' / 'REFERENCE-PROJECTS-INDEX.md'
    ]
    
    # Define replacements
    replacements = [
        ('python scripts/audit_stack_coverage.py', 'python tests/audit/audit_stack_coverage.py'),
        ('python scripts/audit_template_consistency.py', 'python tests/audit/audit_template_consistency.py'),
        ('python scripts/validate_templates.py', 'python tests/validation/validate_templates.py'),
        ('python scripts/validate-foundational-templates.py', 'python tests/validation/validate-foundational-templates.py'),
        ('python scripts/validate-tier-compliance.py', 'python tests/validation/validate-tier-compliance.py'),
        ('python scripts/validate_docs.py', 'python tests/validation/validate_docs.py'),
        ('python scripts/verify_templates.py', 'python tests/validation/verify_templates.py'),
        ('python scripts/generate_smoke_tests.py', 'python tests/generation/generate_smoke_tests.py'),
        ('python scripts/generate_tests.py', 'python tests/generation/generate_tests.py'),
        ('../scripts/validate_templates.py', '../tests/validation/validate_templates.py'),
        ('scripts/validate_templates.py', 'tests/validation/validate_templates.py'),
        ('scripts/audit_stack_coverage.py', 'tests/audit/audit_stack_coverage.py')
    ]
    
    for file_path in files_to_update:
        if file_path.exists():
            content = file_path.read_text(encoding='utf-8')
            original_content = content
            
            for old_path, new_path in replacements:
                content = content.replace(old_path, new_path)
            
            if content != original_content:
                file_path.write_text(content, encoding='utf-8')
                print(f"✅ Updated references in {file_path.name}")

def create_test_infrastructure_readme():
    """Create README for test infrastructure"""
    
    base_dir = Path(__file__).parent.parent
    tests_dir = base_dir / 'tests'
    
    readme_content = """# Test Infrastructure

This directory contains all testing infrastructure for the universal template system.

## Directory Structure

```
tests/
├── validation/          # Template validation and verification
├── audit/              # System auditing and consistency checks
├── generation/         # Test generation utilities
├── unit/               # Unit tests for core functionality
└── integration/        # Integration tests
```

## Validation Scripts

### Core Validation
- `validate_templates.py` - Comprehensive template validation
- `validate-foundational-templates.py` - Foundational template validation
- `validate-tier-compliance.py` - Tier compliance checking

### Documentation Validation
- `validate_docs.py` - Documentation validation
- `validate_feature_documentation.py` - Feature documentation validation
- `validate_template_versions.py` - Version validation

### Verification
- `verify_templates.py` - Template verification
- `validation_protocol_v2.py` - Validation framework

## Audit Scripts

- `audit_stack_coverage.py` - Stack coverage auditing
- `audit_template_consistency.py` - Template consistency auditing

## Generation Scripts

- `generate_smoke_tests.py` - Smoke test generation
- `generate_tests.py` - Test generation utilities

## Usage

```bash
# Run comprehensive validation
python tests/validation/validate_templates.py --full

# Audit stack coverage
python tests/audit/audit_stack_coverage.py

# Generate smoke tests
python tests/generation/generate_smoke_tests.py
```
"""
    
    readme_path = tests_dir / 'README.md'
    readme_path.write_text(readme_content, encoding='utf-8')
    print(f"✅ Created tests/README.md")

def main():
    """Execute the complete reorganization"""
    print("🔧 ORGANIZING TEST INFRASTRUCTURE")
    print("=" * 60)
    
    # Create directory structure
    create_test_structure()
    
    # Move test scripts
    move_test_scripts()
    
    # Update documentation references
    update_documentation_references()
    
    # Create test infrastructure README
    create_test_infrastructure_readme()
    
    print("\n✅ Test infrastructure organization completed!")
    print("All test-related code moved to tests/ directory")
    print("Documentation references updated")

if __name__ == "__main__":
    main()
