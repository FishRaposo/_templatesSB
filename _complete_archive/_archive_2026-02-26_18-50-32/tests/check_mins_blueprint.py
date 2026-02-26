#!/usr/bin/env python3
"""
Comprehensive MINS Blueprint Check
"""

import sys
from pathlib import Path

# Add scripts to path
sys.path.append(str(Path(__file__).parent / "scripts"))

def check_mins_blueprint():
    """Perform comprehensive check of MINS blueprint"""
    print('🔍 MINS Blueprint Comprehensive Check')
    print('=' * 50)
    
    try:
        from blueprint_config import (
            validate_blueprint, 
            get_blueprint_summary, 
            get_supported_stacks, 
            get_task_configuration, 
            get_blueprint_constraints
        )
        
        # Check 1: Blueprint validation
        print('\n1. Schema Validation:')
        errors = validate_blueprint('mins')
        if errors:
            print('❌ Validation errors found:')
            for error in errors:
                print(f'   - {error}')
        else:
            print('✅ Schema validation passed')
        
        # Check 2: Blueprint summary and consistency
        print('\n2. Blueprint Summary:')
        summary = get_blueprint_summary('mins')
        print(f'   Name: {summary.get("name")}')
        print(f'   Category: {summary.get("category")}')
        print(f'   Type: {summary.get("type")}')
        print(f'   Description: {summary.get("description")[:100]}...')
        
        # Check 3: Stack configuration
        print('\n3. Stack Configuration:')
        stacks = get_supported_stacks('mins')
        print(f'   Required: {stacks["required"]}')
        print(f'   Recommended: {stacks["recommended"]}')
        print(f'   Supported: {stacks["supported"]}')
        
        # Check 4: Task configuration
        print('\n4. Task Configuration:')
        tasks = get_task_configuration('mins')
        print(f'   Required: {tasks["required"]}')
        print(f'   Recommended: {tasks["recommended"]}')
        print(f'   Optional: {tasks["optional"]}')
        
        # Check 5: Constraints
        print('\n5. Blueprint Constraints:')
        constraints = get_blueprint_constraints('mins')
        for key, value in constraints.items():
            print(f'   {key}: {value}')
        
        # Check 6: File structure
        print('\n6. File Structure Check:')
        blueprint_dir = Path(__file__).parent / "blueprints" / "mins"
        required_files = ["BLUEPRINT.md", "blueprint.meta.yaml"]
        
        for file_name in required_files:
            file_path = blueprint_dir / file_name
            if file_path.exists():
                print(f'   ✅ {file_name} exists')
            else:
                print(f'   ❌ {file_name} missing')
        
        # Check overlay structure
        overlay_dir = blueprint_dir / "overlays" / "flutter"
        if overlay_dir.exists():
            print('   ✅ Flutter overlay directory exists')
            overlay_files = list(overlay_dir.rglob("*.tpl.dart"))
            print(f'   ✅ Found {len(overlay_files)} overlay template files')
            for file in overlay_files:
                print(f'      - {file.name}')
        else:
            print('   ❌ Flutter overlay directory missing')
        
        # Check 7: Blueprint resolution test
        print('\n7. Blueprint Resolution Test:')
        from blueprint_resolver import BlueprintResolver, ProjectSpecification
        
        resolver = BlueprintResolver()
        project_spec = ProjectSpecification(
            name='TestMINSProject',
            blueprint='mins',
            stacks={'frontend': 'flutter', 'backend': 'python'},
            description='Test project for MINS blueprint'
        )
        
        try:
            ir = resolver.resolve(project_spec)
            print(f'   ✅ Resolution successful (confidence: {ir.metadata["resolution_confidence"]:.2f})')
            print(f'   ✅ Stacks resolved: {ir.stacks}')
            print(f'   ✅ Tiers resolved: {ir.tiers}')
            print(f'   ✅ Tasks resolved: {len(ir.tasks["all"])} total tasks')
            
            # Validate resolution
            validation_errors = resolver.validate_resolution(ir)
            if validation_errors:
                print(f'   ⚠️  Resolution warnings: {validation_errors}')
            else:
                print('   ✅ Resolution validation passed')
                
        except Exception as e:
            print(f'   ❌ Resolution failed: {e}')
        
        print('\n🎉 MINS Blueprint Check Complete!')
        return True
        
    except Exception as e:
        print(f'\n❌ Blueprint check failed: {e}')
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = check_mins_blueprint()
    sys.exit(0 if success else 1)
