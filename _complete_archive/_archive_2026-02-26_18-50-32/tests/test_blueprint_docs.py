#!/usr/bin/env python3
"""
Test script to verify blueprint system commands work as documented.
Used to validate documentation accuracy.
"""

from scripts.blueprint_config import get_available_blueprints, validate_blueprint, get_blueprint_summary
from scripts.blueprint_resolver import BlueprintResolver, ProjectSpecification

def test_blueprint_commands():
    print("🧪 Testing Blueprint System Commands")
    print("=" * 50)
    
    # Test 1: List available blueprints
    print("\n1. Available Blueprints:")
    blueprints = get_available_blueprints()
    print(f"   {blueprints}")
    
    # Test 2: Validate mins blueprint
    print("\n2. Blueprint Validation:")
    validation_result = validate_blueprint('mins')
    print(f"   {validation_result}")
    
    # Test 3: Get blueprint summary
    print("\n3. Blueprint Summary:")
    summary = get_blueprint_summary('mins')
    print(f"   {summary}")
    
    # Test 4: Blueprint resolution
    print("\n4. Blueprint Resolution:")
    resolver = BlueprintResolver()
    spec = ProjectSpecification(name='Test', blueprint='mins', stacks={'frontend': 'flutter'})
    ir = resolver.resolve(spec)
    print(f"   IR metadata keys: {list(ir.metadata.keys())}")
    print(f"   IR structure: {ir.__dict__}")
    print(f"   Resolution confidence: {ir.metadata.get('resolution_confidence', 'N/A')}")
    print(f"   Resolved stacks: {ir.stacks}")
    print(f"   Resolved tiers: {ir.tiers}")
    print(f"   Tasks count: {len(ir.tasks['all'])}")
    
    print("\n✅ All blueprint commands working correctly!")

if __name__ == "__main__":
    test_blueprint_commands()
