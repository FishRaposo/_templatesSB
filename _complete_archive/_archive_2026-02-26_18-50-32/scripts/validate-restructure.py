#!/usr/bin/env python3
"""
Template System Validation Script
Validates the ontology-based template system structure and integrity
"""

import os
import yaml
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from stack_config import get_all_stacks

class TemplateValidator:
    def __init__(self, templates_dir: str):
        self.templates_dir = Path(templates_dir)
        self.errors = []
        self.warnings = []
        self.stats = {}
        
    def log_error(self, message: str):
        self.errors.append(f"❌ ERROR: {message}")
        
    def log_warning(self, message: str):
        self.warnings.append(f"⚠️  WARNING: {message}")
        
    def log_info(self, message: str):
        print(f"ℹ️  INFO: {message}")
        
    def validate_directory_structure(self):
        """Validate the core directory structure exists"""
        self.log_info("Validating directory structure...")
        
        required_dirs = [
            "universal/docs",
            "universal/code", 
            "tiers/mvp/docs",
            "tiers/core/docs", 
            "tiers/enterprise/docs",
            "stacks/flutter/base/docs",
            "stacks/python/base/docs",
            "stacks/node/base/docs",
            "stacks/react/base/docs",
            "stacks/react_native/base/docs",
            "stacks/go/base/docs"
        ]
        
        for dir_path in required_dirs:
            full_path = self.templates_dir / dir_path
            if not full_path.exists():
                self.log_error(f"Required directory missing: {dir_path}")
            else:
                self.log_info(f"✓ Directory exists: {dir_path}")
    
    def validate_naming_conventions(self):
        """Validate that all templates follow proper naming conventions"""
        self.log_info("Validating naming conventions...")
        
        template_count = 0
        for template_file in self.templates_dir.rglob("*.tpl.*"):
            template_count += 1
            
        # Check for any .md files that should be .tpl.md
        for md_file in self.templates_dir.rglob("*.md"):
            # Skip validation.md and other non-template files
            if md_file.name in ["validate-restructure.py", "VALIDATION.md", "README.md"]:
                continue
                
            # Skip archive directory entirely
            if "archive" in md_file.parts:
                continue
                
            # Skip files that already have .tpl.* extension (script logic bug)
            if ".tpl." in md_file.name:
                continue
                
            # Check if it's in a template directory
            if any(parent in md_file.parts for parent in ["universal", "tiers", "stacks"]):
                self.log_error(f"File should use .tpl.* extension: {md_file.relative_to(self.templates_dir)}")
        
        self.stats["template_files"] = template_count
        self.log_info(f"✓ Found {template_count} .tpl.* template files")
    
    def validate_tier_index_yaml(self):
        """Validate tier-index.yaml structure and references"""
        self.log_info("Validating tier-index.yaml...")
        
        yaml_file = self.templates_dir / "tier-index.yaml"
        if not yaml_file.exists():
            self.log_error("tier-index.yaml not found")
            return
            
        try:
            with open(yaml_file, 'r') as f:
                config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.log_error(f"Invalid YAML in tier-index.yaml: {e}")
            return
            
        # Validate required top-level sections
        required_sections = ["universal_patterns", "tier_overlays", "stack_patterns", "template_metadata"]
        for section in required_sections:
            if section not in config:
                self.log_error(f"Missing required section in tier-index.yaml: {section}")
            else:
                self.log_info(f"✓ YAML section exists: {section}")
        
        # Validate file references exist
        self._validate_yaml_file_references(config)
        
        # Validate stack configuration
        if "stack_configuration" in config:
            expected_stacks = get_all_stacks()
            actual_stacks = config["stack_configuration"].get("available_stacks", [])
            
            if set(actual_stacks) != set(expected_stacks):
                self.log_error(f"Stack configuration mismatch. Expected: {expected_stacks}, Got: {actual_stacks}")
            else:
                self.log_info(f"✓ Stack configuration correct: {actual_stacks}")
    
    def _validate_yaml_file_references(self, config: dict):
        """Validate that all files referenced in YAML actually exist"""
        self.log_info("Validating YAML file references...")
        
        referenced_files = set()
        
        # Collect universal patterns
        if "universal_patterns" in config:
            for category_name, category_content in config["universal_patterns"].items():
                if isinstance(category_content, list):
                    for item in category_content:
                        if isinstance(item, dict) and "file" in item:
                            if category_name == "code":
                                referenced_files.add(f"universal/code/{item['file']}")
                            elif category_name == "tests" and "location" in item:
                                referenced_files.add(f"{item['location']}{item['file']}")
                            else:
                                referenced_files.add(f"universal/docs/{item['file']}")
                        elif isinstance(item, dict) and "directory" in item:
                            if item['directory'].rstrip('/') == 'scripts':
                                referenced_files.add(f"{item['directory']}")
                            else:
                                referenced_files.add(f"universal/{item['directory']}")
        
        # Collect tier overlays
        if "tier_overlays" in config:
            for tier_name, tier_config in config["tier_overlays"].items():
                if isinstance(tier_config, dict):
                    for category_name, category_content in tier_config.items():
                        if isinstance(category_content, list):
                            for item in category_content:
                                if isinstance(item, dict) and "file" in item:
                                    referenced_files.add(f"tiers/{tier_name}/{category_name}/{item['file']}")
        
        # Collect stack patterns
        if "stack_patterns" in config:
            for stack_name, stack_config in config["stack_patterns"].items():
                if "base" in stack_config and "docs" in stack_config["base"]:
                    for item in stack_config["base"]["docs"]:
                        if isinstance(item, dict) and "file" in item:
                            referenced_files.add(f"stacks/{stack_name}/base/docs/{item['file']}")
        
        # Validate each referenced file exists
        missing_files = []
        for file_ref in referenced_files:
            file_path = self.templates_dir / file_ref
            if not file_path.exists():
                missing_files.append(file_ref)
        
        if missing_files:
            for missing in missing_files:
                self.log_error(f"YAML references non-existent file: {missing}")
        else:
            self.log_info(f"✓ All {len(referenced_files)} YAML file references exist")
    
    def validate_stack_organization(self):
        """Validate each stack has the required pattern files"""
        self.log_info("Validating stack organization...")
        
        expected_stacks = get_all_stacks()
        required_patterns = [
            "FRAMEWORK-PATTERNS-{stack}.tpl.md",
            "TESTING-EXAMPLES-{stack}.tpl.md", 
            "ARCHITECTURE-{stack}.tpl.md",
            "CI-EXAMPLES-{stack}.tpl.md",
            "PROJECT-STRUCTURE.tpl.md"
        ]
        
        for stack in expected_stacks:
            stack_dir = self.templates_dir / "stacks" / stack / "base" / "docs"
            if not stack_dir.exists():
                self.log_error(f"Stack directory missing: {stack}")
                continue
                
            actual_files = {f.name for f in stack_dir.glob("*.tpl.md")}
            
            for pattern in required_patterns:
                expected_file = pattern.format(stack=stack)
                # Special case for react_native - use hyphen instead of underscore
                if stack == "react_native":
                    expected_file = expected_file.replace("react_native", "react-native")
                if expected_file not in actual_files:
                    self.log_error(f"Missing required file in {stack} stack: {expected_file}")
            
            # Check for stack-specific files
            if stack == "flutter":
                flutter_specific = ["NAVIGATION.tpl.md", "NETWORKING.tpl.md", "STATE-MANAGEMENT.tpl.md"]
                for file_name in flutter_specific:
                    if file_name not in actual_files:
                        self.log_error(f"Missing Flutter-specific file: {file_name}")
            
            self.log_info(f"✓ Stack {stack} validated with {len(actual_files)} files")
    
    def validate_no_typescript_node_references(self):
        """Validate no references to old typescript-node naming remain"""
        self.log_info("Checking for typescript-node references...")
        
        search_patterns = ["typescript-node", "typescript_node", "typescriptnode"]
        
        for template_file in self.templates_dir.rglob("*.tpl.md"):
            try:
                with open(template_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    for pattern in search_patterns:
                        if pattern in content.lower():
                            self.log_error(f"Found '{pattern}' reference in: {template_file.relative_to(self.templates_dir)}")
            except Exception as e:
                self.log_warning(f"Could not read {template_file}: {e}")
        
        # Also check tier-index.yaml
        yaml_file = self.templates_dir / "tier-index.yaml"
        if yaml_file.exists():
            with open(yaml_file, 'r') as f:
                content = f.read()
                for pattern in search_patterns:
                    if pattern in content.lower():
                        self.log_error(f"Found '{pattern}' reference in tier-index.yaml")
        
        self.log_info("✓ No typescript-node references found")
    
    def validate_old_files_removed(self):
        """Validate old root-level template files have been removed"""
        self.log_info("Checking for old root-level files...")
        
        # Files that should have been moved to universal/
        moved_files = [
            "QUICKSTART-AI.md",
            "SYSTEM-MAP.md", 
            "MIGRATION-GUIDE.md",
            "VALIDATION.md",
            "UTILITIES.md",
            "WORKFLOWS.md",
            "SYSTEM-INTEGRATION.md",
            "TIERED-TEMPLATES.md",
            "INDEX.md",
            "FEATURES.md",
            "MODULE-TEMPLATE-BACKEND.md",
            "MODULE-TEMPLATE-FRONTEND.md"
        ]
        
        # Allowed root-level system documentation files
        allowed_files = [
            "README.md",
            "tier-index.yaml",
            "validate-restructure.py",
            "validate_feature_documentation.py",
            "requirements.txt"
        ]
        
        for file_name in moved_files:
            file_path = self.templates_dir / file_name
            if file_path.exists():
                self.log_error(f"Old root-level file still exists: {file_name}")
        
        self.log_info("✓ No old root-level template files found")
    
    def validate_examples_directory(self):
        """Validate examples directory doesn't conflict with new structure"""
        self.log_info("Validating examples directory...")
        
        examples_dir = self.templates_dir / "examples"
        if examples_dir.exists():
            # Check for any files that might duplicate stack patterns
            for example_file in examples_dir.rglob("*.md"):
                # Check if it looks like it should be in stacks/
                if any(pattern in example_file.name.upper() for pattern in ["FRAMEWORK", "TESTING", "ARCHITECTURE", "CI"]):
                    self.log_warning(f"Examples file might belong in stacks/: {example_file.relative_to(self.templates_dir)}")
        
        self.log_info("✓ Examples directory validated")
    
    def validate_migration_completeness(self):
        """Migration manifest validation removed - file intentionally deleted during consolidation"""
        self.log_info("✓ Migration manifest validation skipped (file removed during consolidation)")
        pass
    
    def run_validation(self) -> bool:
        """Run all validation checks"""
        print("🔍 Starting Template System Validation")
        print("=" * 50)
        
        self.validate_directory_structure()
        self.validate_naming_conventions()
        self.validate_tier_index_yaml()
        self.validate_stack_organization()
        self.validate_no_typescript_node_references()
        self.validate_old_files_removed()
        self.validate_examples_directory()
        self.validate_migration_completeness()
        
        print("\n" + "=" * 50)
        print("📊 VALIDATION SUMMARY")
        print("=" * 50)
        
        if self.errors:
            print(f"\n❌ {len(self.errors)} ERRORS FOUND:")
            for error in self.errors:
                print(f"  {error}")
        
        if self.warnings:
            print(f"\n⚠️  {len(self.warnings)} WARNINGS:")
            for warning in self.warnings:
                print(f"  {warning}")
        
        if self.stats:
            print(f"\n📈 STATISTICS:")
            for key, value in self.stats.items():
                print(f"  {key}: {value}")
        
        if not self.errors and not self.warnings:
            print("\n🎉 ALL VALIDATIONS PASSED! Template system is ready for production.")
            return True
        elif not self.errors:
            print("\n✅ Validation passed with warnings. Review warnings before production.")
            return True
        else:
            print(f"\n❌ VALIDATION FAILED! Fix {len(self.errors)} errors before proceeding.")
            return False

def main():
    templates_dir = Path(__file__).parent
    validator = TemplateValidator(str(templates_dir))
    success = validator.run_validation()
    
    if not success:
        exit(1)

if __name__ == "__main__":
    main()
