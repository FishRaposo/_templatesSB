#!/usr/bin/env python3
"""
Blueprint Validation Script

Validates blueprint definitions, metadata, and overlays for the Universal Template System.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys

class BlueprintValidator:
    def __init__(self, templates_root: Path):
        self.templates_root = templates_root
        self.blueprints_dir = templates_root / "blueprints"
        self.stacks_dir = templates_root / "stacks"
        self.errors = []
        self.warnings = []
        self.stats = {
            "total_blueprints": 0,
            "valid_blueprints": 0,
            "invalid_blueprints": 0,
            "total_overlays": 0,
            "valid_overlays": 0,
            "invalid_overlays": 0
        }

    def validate_all(self) -> Dict[str, Any]:
        """Validate all blueprints in the system."""
        print("🔍 Validating Blueprints...")
        print("=" * 50)
        
        if not self.blueprints_dir.exists():
            self.log_error("Blueprints directory not found", str(self.blueprints_dir))
            return self.get_results()
        
        # Discover blueprints
        blueprint_dirs = [d for d in self.blueprints_dir.iterdir() 
                         if d.is_dir() and not d.name.startswith('.')]
        
        self.stats["total_blueprints"] = len(blueprint_dirs)
        
        for blueprint_dir in blueprint_dirs:
            self.validate_blueprint(blueprint_dir)
        
        # Validate blueprint system integration
        self.validate_system_integration()
        
        return self.get_results()

    def validate_blueprint(self, blueprint_dir: Path) -> None:
        """Validate a single blueprint."""
        blueprint_name = blueprint_dir.name
        print(f"\n📋 Validating Blueprint: {blueprint_name}")
        
        # Check required files
        required_files = [
            "BLUEPRINT.md",
            "blueprint.meta.yaml"
        ]
        
        blueprint_valid = True
        
        for file_name in required_files:
            file_path = blueprint_dir / file_name
            if not file_path.exists():
                self.log_error(f"Missing required file: {file_name}", str(blueprint_dir))
                blueprint_valid = False
        
        if blueprint_valid:
            # Validate metadata
            meta_path = blueprint_dir / "blueprint.meta.yaml"
            if self.validate_blueprint_metadata(meta_path, blueprint_name):
                # Validate overlays
                overlays_dir = blueprint_dir / "overlays"
                if overlays_dir.exists():
                    self.validate_overlays(overlays_dir, blueprint_name)
                
                self.stats["valid_blueprints"] += 1
            else:
                self.stats["invalid_blueprints"] += 1
        else:
            self.stats["invalid_blueprints"] += 1

    def validate_blueprint_metadata(self, meta_path: Path, blueprint_name: str) -> bool:
        """Validate blueprint metadata YAML."""
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                metadata = yaml.safe_load(f)
            
            # Check required fields
            required_fields = ["id", "version", "name", "category", "description", "type"]
            for field in required_fields:
                if field not in metadata:
                    self.log_error(f"Missing required field in metadata: {field}", str(meta_path))
                    return False
            
            # Validate ID matches directory name
            if metadata["id"] != blueprint_name:
                self.log_error(f"Blueprint ID '{metadata['id']}' doesn't match directory name '{blueprint_name}'", str(meta_path))
                return False
            
            # Validate stacks configuration
            if "stacks" not in metadata:
                self.log_error("Missing stacks configuration", str(meta_path))
                return False
            
            stacks_config = metadata["stacks"]
            if not isinstance(stacks_config, dict):
                self.log_error("Stacks configuration must be a dictionary", str(meta_path))
                return False
            
            # Validate stack requirements
            for stack_type in ["required", "recommended", "supported"]:
                if stack_type in stacks_config:
                    if not isinstance(stacks_config[stack_type], list):
                        self.log_error(f"Stacks.{stack_type} must be a list", str(meta_path))
                        return False
                    
                    # Check if stacks exist
                    for stack_name in stacks_config[stack_type]:
                        stack_dir = self.stacks_dir / stack_name
                        if not stack_dir.exists():
                            self.log_warning(f"Referenced stack doesn't exist: {stack_name}", str(meta_path))
            
            # Validate tasks configuration
            if "tasks" in metadata:
                tasks_config = metadata["tasks"]
                if not isinstance(tasks_config, dict):
                    self.log_error("Tasks configuration must be a dictionary", str(meta_path))
                    return False
                
                for task_type in ["required", "recommended", "optional"]:
                    if task_type in tasks_config:
                        if not isinstance(tasks_config[task_type], list):
                            self.log_error(f"Tasks.{task_type} must be a list", str(meta_path))
                            return False
            
            print(f"  ✅ Metadata valid for {blueprint_name}")
            return True
            
        except yaml.YAMLError as e:
            self.log_error(f"Invalid YAML in metadata: {e}", str(meta_path))
            return False
        except Exception as e:
            self.log_error(f"Error reading metadata: {e}", str(meta_path))
            return False

    def validate_overlays(self, overlays_dir: Path, blueprint_name: str) -> None:
        """Validate blueprint overlays."""
        print(f"  🔍 Validating overlays for {blueprint_name}")
        
        overlay_dirs = [d for d in overlays_dir.iterdir() 
                       if d.is_dir() and not d.name.startswith('.')]
        
        for stack_dir in overlay_dirs:
            stack_name = stack_dir.name
            self.stats["total_overlays"] += 1
            
            # Check if stack is supported
            stack_path = self.stacks_dir / stack_name
            if not stack_path.exists():
                self.log_warning(f"Overlay for unsupported stack: {stack_name}", str(overlays_dir))
                continue
            
            # Validate overlay structure
            if self.validate_stack_overlay(stack_dir, stack_name, blueprint_name):
                self.stats["valid_overlays"] += 1
            else:
                self.stats["invalid_overlays"] += 1

    def validate_stack_overlay(self, overlay_dir: Path, stack_name: str, blueprint_name: str) -> bool:
        """Validate a specific stack overlay."""
        overlay_valid = True
        
        # Check for overlay files
        overlay_files = list(overlay_dir.rglob("*.tpl.*"))
        
        if not overlay_files:
            self.log_warning(f"No overlay templates found for {stack_name}", str(overlay_dir))
            return False
        
        # Validate overlay file headers
        for file_path in overlay_files:
            if not self.validate_template_header(file_path, blueprint_name, stack_name):
                overlay_valid = False
        
        if overlay_valid:
            print(f"    ✅ {stack_name} overlay valid")
        
        return overlay_valid

    def validate_template_header(self, file_path: Path, blueprint_name: str, stack_name: str) -> bool:
        """Validate template file header."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                first_lines = [f.readline().strip() for _ in range(5)]
            
            # Check for required header comments
            header_found = False
            for line in first_lines:
                if "Universal Template System" in line and blueprint_name.title() in line:
                    header_found = True
                    break
            
            if not header_found:
                self.log_warning(f"Missing or invalid header in template: {file_path.name}", str(file_path))
                return False
            
            return True
            
        except Exception as e:
            self.log_error(f"Error reading template {file_path.name}: {e}", str(file_path))
            return False

    def validate_system_integration(self) -> None:
        """Validate blueprint system integration."""
        print("\n🔗 Validating System Integration")
        
        # Check blueprint resolver
        resolver_path = self.templates_root / "scripts" / "blueprint_resolver.py"
        if not resolver_path.exists():
            self.log_error("Blueprint resolver script not found", str(resolver_path))
        
        # Check blueprint config
        config_path = self.templates_root / "scripts" / "blueprint_config.py"
        if not config_path.exists():
            self.log_error("Blueprint config script not found", str(config_path))
        
        # Validate blueprint discovery
        try:
            from scripts.blueprint_config import get_available_blueprints
            blueprints = get_available_blueprints()
            print(f"  ✅ Blueprint discovery working: {len(blueprints)} blueprints found")
        except Exception as e:
            self.log_error(f"Blueprint discovery failed: {e}", "system integration")

    def log_error(self, message: str, location: str = ""):
        """Log an error."""
        self.errors.append(f"ERROR: {message} ({location})")

    def log_warning(self, message: str, location: str = ""):
        """Log a warning."""
        self.warnings.append(f"WARNING: {message} ({location})")

    def get_results(self) -> Dict[str, Any]:
        """Get validation results."""
        return {
            "stats": self.stats,
            "errors": self.errors,
            "warnings": self.warnings,
            "success": len(self.errors) == 0
        }

def main():
    """Main validation script."""
    templates_root = Path(__file__).parent.parent
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help":
            print("Usage: python validate_blueprints.py [--detailed]")
            print("Validates all blueprint definitions and overlays")
            return
        
        if sys.argv[1] == "--detailed":
            detailed = True
        else:
            detailed = False
    else:
        detailed = False
    
    validator = BlueprintValidator(templates_root)
    results = validator.validate_all()
    
    # Print results
    print("\n" + "=" * 50)
    print("📊 Blueprint Validation Results")
    print("=" * 50)
    
    stats = results["stats"]
    print(f"Total Blueprints: {stats['total_blueprints']}")
    print(f"Valid Blueprints: {stats['valid_blueprints']}")
    print(f"Invalid Blueprints: {stats['invalid_blueprints']}")
    print(f"Total Overlays: {stats['total_overlays']}")
    print(f"Valid Overlays: {stats['valid_overlays']}")
    print(f"Invalid Overlays: {stats['invalid_overlays']}")
    
    if results["errors"]:
        print(f"\n❌ Errors ({len(results['errors'])}):")
        if detailed:
            for error in results["errors"]:
                print(f"  • {error}")
        else:
            print(f"  Run with --detailed to see all errors")
    
    if results["warnings"]:
        print(f"\n⚠️  Warnings ({len(results['warnings'])}):")
        if detailed:
            for warning in results["warnings"]:
                print(f"  • {warning}")
        else:
            print(f"  Run with --detailed to see all warnings")
    
    if results["success"]:
        print("\n✅ All blueprints validated successfully!")
        return 0
    else:
        print("\n❌ Blueprint validation failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
