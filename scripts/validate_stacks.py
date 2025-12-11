#!/usr/bin/env python3
"""
Stack Validation Script

Validates stack definitions, templates, reference projects, and integration for the Universal Template System.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import sys
import re

class StackValidator:
    def __init__(self, templates_root: Path):
        self.templates_root = templates_root
        self.stacks_dir = templates_root / "stacks"
        self.reference_projects_dir = templates_root / "reference-projects"
        self.tiers_dir = templates_root / "tiers"
        self.errors = []
        self.warnings = []
        self.stats = {
            "total_stacks": 0,
            "valid_stacks": 0,
            "invalid_stacks": 0,
            "total_templates": 0,
            "valid_templates": 0,
            "invalid_templates": 0,
            "reference_projects": {
                "mvp": 0,
                "core": 0,
                "enterprise": 0
            }
        }

    def validate_all(self) -> Dict[str, Any]:
        """Validate all stacks in the system."""
        print("🔍 Validating Stacks...")
        print("=" * 50)
        
        if not self.stacks_dir.exists():
            self.log_error("Stacks directory not found", str(self.stacks_dir))
            return self.get_results()
        
        # Discover stacks
        stack_dirs = [d for d in self.stacks_dir.iterdir() 
                     if d.is_dir() and not d.name.startswith('.')]
        
        self.stats["total_stacks"] = len(stack_dirs)
        
        for stack_dir in stack_dirs:
            self.validate_stack(stack_dir)
        
        # Validate reference projects consistency
        self.validate_reference_projects()
        
        # Validate system integration
        self.validate_system_integration()
        
        return self.get_results()

    def validate_stack(self, stack_dir: Path) -> None:
        """Validate a single stack."""
        stack_name = stack_dir.name
        print(f"\n🔧 Validating Stack: {stack_name}")
        
        stack_valid = True
        
        # Check required files
        required_files = ["README.md"]
        for file_name in required_files:
            file_path = stack_dir / file_name
            if not file_path.exists():
                self.log_error(f"Missing required file: {file_name}", str(stack_dir))
                stack_valid = False
            else:
                if file_name == "README.md":
                    self.validate_stack_readme(file_path, stack_name)
        
        # Check base directory structure
        base_dir = stack_dir / "base"
        if not base_dir.exists():
            self.log_error("Missing base directory", str(stack_dir))
            stack_valid = False
        else:
            self.validate_base_templates(base_dir, stack_name)
        
        # Check for stack-specific files
        self.validate_stack_specific_files(stack_dir, stack_name)
        
        # Check reference projects
        self.validate_stack_reference_projects(stack_name)
        
        if stack_valid:
            self.stats["valid_stacks"] += 1
        else:
            self.stats["invalid_stacks"] += 1

    def validate_base_templates(self, base_dir: Path, stack_name: str) -> None:
        """Validate base template structure."""
        # Check required subdirectories
        required_subdirs = ["code", "docs", "tests"]
        for subdir in required_subdirs:
            subdir_path = base_dir / subdir
            if not subdir_path.exists():
                self.log_error(f"Missing base subdirectory: {subdir}", str(base_dir))
                continue
            
            # Validate templates in each subdirectory
            templates = list(subdir_path.rglob("*.tpl.*"))
            for template_path in templates:
                self.stats["total_templates"] += 1
                if self.validate_template_file(template_path, stack_name):
                    self.stats["valid_templates"] += 1
                else:
                    self.stats["invalid_templates"] += 1
        
        # Check for required code templates
        code_dir = base_dir / "code"
        if code_dir.exists():
            required_code_templates = [
                "config-management.tpl",
                "data-validation.tpl",
                "error-handling.tpl",
                "http-client.tpl",
                "logging-utilities.tpl",
                "testing-utilities.tpl"
            ]
            
            # Adjust extension based on stack
            ext = self.get_stack_extension(stack_name)
            
            for template_name in required_code_templates:
                template_path = code_dir / f"{template_name}{ext}"
                if not template_path.exists():
                    self.log_warning(f"Missing recommended template: {template_name}{ext}", str(code_dir))
        
        # Check for required documentation templates
        docs_dir = base_dir / "docs"
        if docs_dir.exists():
            required_doc_templates = [
                f"ARCHITECTURE-{stack_name}.tpl.md",
                f"CI-EXAMPLES-{stack_name}.tpl.md",
                f"FRAMEWORK-PATTERNS-{stack_name}.tpl.md",
                f"TESTING-EXAMPLES-{stack_name}.tpl.md"
            ]
            
            for template_name in required_doc_templates:
                template_path = docs_dir / template_name
                if not template_path.exists():
                    self.log_warning(f"Missing recommended documentation: {template_name}", str(docs_dir))

    def get_stack_extension(self, stack_name: str) -> str:
        """Get the typical file extension for a stack."""
        extensions = {
            "flutter": ".dart",
            "python": ".py",
            "node": ".js",
            "go": ".go",
            "react": ".jsx",
            "react_native": ".jsx",
            "next": ".jsx",
            "r": ".R",
            "sql": ".sql",
            "typescript": ".ts",
            "generic": ".md"
        }
        return extensions.get(stack_name, ".tpl")

    def validate_template_file(self, template_path: Path, stack_name: str) -> bool:
        """Validate a template file."""
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for required header
            if not self.validate_template_header(content, stack_name):
                return False
            
            # Check for placeholders
            if template_path.suffix not in [".md", ".yaml", ".yml"]:
                if not self.validate_template_placeholders(content):
                    self.log_warning(f"No placeholders found in template: {template_path.name}", str(template_path))
            
            return True
            
        except Exception as e:
            self.log_error(f"Error reading template {template_path.name}: {e}", str(template_path))
            return False

    def validate_template_header(self, content: str, stack_name: str) -> bool:
        """Validate template file header."""
        lines = content.split('\n')[:5]
        
        # Look for Universal Template System header
        for line in lines:
            if "Universal Template System" in line and stack_name.title() in line:
                return True
        
        return False

    def validate_template_placeholders(self, content: str) -> bool:
        """Check if template contains placeholders."""
        # Look for {{PLACEHOLDER}} or {{PLACEHOLDER}} patterns
        placeholders = re.findall(r'\{\{[^}]+\}\}', content)
        return len(placeholders) > 0

    def validate_stack_readme(self, readme_path: Path, stack_name: str) -> None:
        """Validate stack README.md file."""
        try:
            with open(readme_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for required sections
            required_sections = [
                "# {Stack Name} Templates",
                "## 🚀 Quick Start",
                "## 📁 File Structure",
                "## 🎯 Supported Tiers"
            ]
            
            for section in required_sections:
                # Replace placeholder
                section_pattern = section.replace("{Stack Name}", stack_name.title())
                if section_pattern not in content:
                    self.log_warning(f"Missing section in README: {section_pattern}", str(readme_path))
            
            # Check for broken links
            self.validate_readme_links(readme_path, content)
            
        except Exception as e:
            self.log_error(f"Error reading README: {e}", str(readme_path))

    def validate_readme_links(self, readme_path: Path, content: str) -> None:
        """Validate internal links in README."""
        # Find markdown links
        links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content)
        
        for link_text, link_url in links:
            if link_url.startswith('./') or not link_url.startswith(('http://', 'https://', '#')):
                # Internal link - check if target exists
                target_path = (readme_path.parent / link_url).resolve()
                
                # Handle anchor links
                if '#' in link_url:
                    link_url = link_url.split('#')[0]
                    target_path = (readme_path.parent / link_url).resolve()
                
                if not target_path.exists():
                    self.log_error(f"Broken internal link: {link_url}", str(readme_path))
                
                # Check for SYSTEM-MAP.tpl.md references (should be SYSTEM-MAP.md)
                if "SYSTEM-MAP.tpl.md" in link_url:
                    self.log_error(f"Outdated SYSTEM-MAP.tpl.md reference: {link_url}", str(readme_path))

    def validate_stack_specific_files(self, stack_dir: Path, stack_name: str) -> None:
        """Validate stack-specific files."""
        # Check for requirements.txt, pubspec.yaml, package.json, etc.
        stack_files = {
            "python": ["requirements.txt.tpl"],
            "flutter": ["pubspec.yaml.tpl"],
            "node": ["package.json.tpl"],
            "go": ["go.mod.tpl"],
            "typescript": ["package.json.tpl", "tsconfig.json.tpl"]
        }
        
        if stack_name in stack_files:
            for file_name in stack_files[stack_name]:
                file_path = stack_dir / file_name
                if not file_path.exists():
                    self.log_warning(f"Missing stack-specific file: {file_name}", str(stack_dir))

    def validate_stack_reference_projects(self, stack_name: str) -> None:
        """Validate reference projects for a stack."""
        tiers = ["mvp", "core", "enterprise"]
        
        for tier in tiers:
            project_dir = self.reference_projects_dir / tier / f"{tier}-{stack_name}-reference"
            if project_dir.exists():
                self.stats["reference_projects"][tier] += 1
                self.validate_reference_project(project_dir, stack_name, tier)
            else:
                self.log_warning(f"Missing {tier} reference project", f"reference-projects/{tier}")

    def validate_reference_project(self, project_dir: Path, stack_name: str, tier: str) -> None:
        """Validate a specific reference project."""
        # Check for README.md
        readme_path = project_dir / "README.md"
        if not readme_path.exists():
            self.log_warning(f"Reference project missing README: {tier}-{stack_name}", str(project_dir))
        
        # Check for main entry point
        main_files = {
            "python": ["main.py", "app.py"],
            "flutter": ["lib/main.dart"],
            "node": ["index.js", "app.js", "main.js"],
            "go": ["main.go"],
            "react": ["src/App.jsx", "src/index.js"],
            "react_native": ["App.jsx", "index.js"],
            "next": ["pages/index.jsx", "pages/index.js"],
            "r": ["main.R"],
            "sql": ["schema.sql"]
        }
        
        if stack_name in main_files:
            found_main = False
            for main_file in main_files[stack_name]:
                main_path = project_dir / main_file
                if main_path.exists():
                    found_main = True
                    break
            
            if not found_main:
                self.log_warning(f"No main entry point found in reference project", str(project_dir))

    def validate_reference_projects(self) -> None:
        """Validate reference projects consistency."""
        print("\n🏗️ Validating Reference Projects")
        
        if not self.reference_projects_dir.exists():
            self.log_error("Reference projects directory not found", str(self.reference_projects_dir))
            return
        
        tiers = ["mvp", "core", "enterprise"]
        for tier in tiers:
            tier_dir = self.reference_projects_dir / tier
            if tier_dir.exists():
                projects = [d for d in tier_dir.iterdir() 
                           if d.is_dir() and not d.name.startswith('.')]
                print(f"  {tier.title()}: {len(projects)} reference projects")

    def validate_system_integration(self) -> None:
        """Validate stack system integration."""
        print("\n🔗 Validating System Integration")
        
        # Check tier index
        tier_index_path = self.templates_root / "tier-index.yaml"
        if not tier_index_path.exists():
            self.log_error("tier-index.yaml not found", str(tier_index_path))
        
        # Validate stack integration with tasks
        tasks_dir = self.templates_root / "tasks"
        if tasks_dir.exists():
            task_dirs = [d for d in tasks_dir.iterdir() 
                        if d.is_dir() and not d.name.startswith('.')]
            
            stack_support = {}
            for task_dir in task_dirs:
                stacks_dir = task_dir / "stacks"
                if stacks_dir.exists():
                    for stack_dir in stacks_dir.iterdir():
                        if stack_dir.is_dir():
                            stack_name = stack_dir.name
                            if stack_name not in stack_support:
                                stack_support[stack_name] = 0
                            stack_support[stack_name] += 1
            
            print(f"  Stack-task integration verified")
            for stack, count in sorted(stack_support.items()):
                print(f"    {stack}: {count} tasks")

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
            print("Usage: python validate_stacks.py [--detailed]")
            print("Validates all stack definitions and templates")
            return
        
        if sys.argv[1] == "--detailed":
            detailed = True
        else:
            detailed = False
    else:
        detailed = False
    
    validator = StackValidator(templates_root)
    results = validator.validate_all()
    
    # Print results
    print("\n" + "=" * 50)
    print("📊 Stack Validation Results")
    print("=" * 50)
    
    stats = results["stats"]
    print(f"Total Stacks: {stats['total_stacks']}")
    print(f"Valid Stacks: {stats['valid_stacks']}")
    print(f"Invalid Stacks: {stats['invalid_stacks']}")
    print(f"Total Templates: {stats['total_templates']}")
    print(f"Valid Templates: {stats['valid_templates']}")
    print(f"Invalid Templates: {stats['invalid_templates']}")
    
    ref_projects = stats["reference_projects"]
    print(f"\nReference Projects:")
    print(f"  MVP: {ref_projects['mvp']}")
    print(f"  Core: {ref_projects['core']}")
    print(f"  Enterprise: {ref_projects['enterprise']}")
    
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
        print("\n✅ All stacks validated successfully!")
        return 0
    else:
        print("\n❌ Stack validation failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
