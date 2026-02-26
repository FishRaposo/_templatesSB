#!/usr/bin/env python3
"""
Test script for blueprint system integration
"""

import sys
from pathlib import Path

# Add scripts to path
sys.path.append(str(Path(__file__).parent / "scripts"))

from setup_project import ProjectSetup
from blueprint_resolver import ProjectSpecification

def test_blueprint_integration():
    """Test the blueprint resolution integration"""
    print("🧪 Testing Blueprint System Integration")
    print("=" * 50)
    
    try:
        # Test 1: Basic blueprint resolution
        print("\n1. Testing basic blueprint resolution...")
        setup = ProjectSetup()
        project_spec = ProjectSpecification(
            name='TestProject',
            blueprint='mins',
            stacks={'frontend': 'flutter', 'backend': 'python'},
            description='Test project for blueprint integration'
        )
        
        ir = setup.blueprint_resolver.resolve(project_spec)
        print(f"✅ Blueprint: {ir.blueprint}")
        print(f"✅ Name: {ir.name}")
        print(f"✅ Stacks: {ir.stacks}")
        print(f"✅ Tiers: {ir.tiers}")
        print(f"✅ Tasks: {len(ir.tasks['all'])} tasks configured")
        print(f"✅ Confidence: {ir.metadata['resolution_confidence']:.2f}")
        
        # Test 2: Blueprint validation
        print("\n2. Testing blueprint validation...")
        errors = setup.blueprint_resolver.validate_resolution(ir)
        if errors:
            print(f"⚠️  Validation warnings: {errors}")
        else:
            print("✅ Blueprint validation passed")
        
        # Test 3: Blueprint configuration loading
        print("\n3. Testing blueprint configuration...")
        from blueprint_config import get_available_blueprints, get_blueprint_summary
        
        blueprints = get_available_blueprints()
        print(f"✅ Available blueprints: {blueprints}")
        
        if 'mins' in blueprints:
            summary = get_blueprint_summary('mins')
            print(f"✅ MINS blueprint loaded: {summary.get('name')}")
        
        print("\n🎉 All blueprint integration tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Blueprint integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_blueprint_integration()
    sys.exit(0 if success else 1)
