#!/usr/bin/env python3
"""
Test script for blueprint validation integration
"""

import sys
from pathlib import Path

# Add scripts to path
sys.path.append(str(Path(__file__).parent / "scripts"))

def test_blueprint_validation():
    """Test blueprint validation system"""
    print("🧪 Testing Blueprint Validation System")
    print("=" * 50)
    
    try:
        # Test blueprint validation directly
        from blueprint_config import get_available_blueprints, validate_blueprint, get_blueprint_summary
        
        print("\n1. Testing blueprint configuration loading...")
        blueprints = get_available_blueprints()
        print(f"✅ Available blueprints: {blueprints}")
        
        print("\n2. Testing blueprint validation...")
        for blueprint_id in blueprints:
            errors = validate_blueprint(blueprint_id)
            if errors:
                print(f"⚠️  Blueprint {blueprint_id} has validation errors:")
                for error in errors:
                    print(f"    - {error}")
            else:
                print(f"✅ Blueprint {blueprint_id} validation passed")
        
        print("\n3. Testing blueprint summary...")
        for blueprint_id in blueprints:
            summary = get_blueprint_summary(blueprint_id)
            print(f"✅ {blueprint_id}: {summary.get('name', 'Unknown')}")
        
        print("\n4. Testing blueprint file structure...")
        blueprints_dir = Path(__file__).parent / "blueprints"
        for blueprint_id in blueprints:
            blueprint_path = blueprints_dir / blueprint_id
            required_files = ["BLUEPRINT.md", "blueprint.meta.yaml"]
            
            for file_name in required_files:
                file_path = blueprint_path / file_name
                if file_path.exists():
                    print(f"✅ {blueprint_id}/{file_name} exists")
                else:
                    print(f"❌ {blueprint_id}/{file_name} missing")
        
        print("\n🎉 Blueprint validation system working correctly!")
        return True
        
    except Exception as e:
        print(f"\n❌ Blueprint validation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_blueprint_validation()
    sys.exit(0 if success else 1)
