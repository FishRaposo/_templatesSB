#!/usr/bin/env python3
"""
Foundational Templates Validation Script
Purpose: Validate the quality and consistency of foundational code templates
Usage: python scripts/validate-foundational-templates.py
"""

import os
import re
import ast
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Resolve project root for path consistency
PROJECT_ROOT = Path(__file__).parent.parent.parent

class FoundationalTemplateValidator:
    def __init__(self, templates_dir: str):
        self.templates_dir = Path(templates_dir)
        self.stacks = ["flutter", "react_native", "react", "node", "python", "go", "generic", "typescript"]
        self.required_templates = [
            "config-management",
            "logging-utilities", 
            "error-handling",
            "http-client",
            "data-validation",
            "testing-utilities"
        ]
        self.errors = []
        self.warnings = []
        self.stats = {
            "total_templates": 0,
            "validated_templates": 0,
            "templates_with_examples": 0,
            "templates_with_exports": 0,
            "templates_with_docs": 0
        }
        
    def validate_all(self) -> bool:
        """Run all validation checks for foundational templates"""
        print("🔍 Validating Foundational Templates...")
        print("=" * 50)
        
        print("\n📁 Checking template existence...")
        self.validate_template_existence()
        
        print("\n📝 Validating code structure...")
        self.validate_code_structure()
        
        print("\n📚 Checking documentation and examples...")
        self.validate_documentation_and_examples()
        
        print("\n🔗 Validating exports and interfaces...")
        self.validate_exports_and_interfaces()
        
        print("\n📊 Checking dependency manifests...")
        self.validate_dependency_manifests()
        
        self.print_summary()
        return len(self.errors) == 0
    
    def validate_template_existence(self):
        """Check all required templates exist for each stack"""
        for stack in self.stacks:
            stack_path = self.templates_dir / "stacks" / stack / "base" / "code"
            if not stack_path.exists():
                self.errors.append(f"Missing stack directory: {stack_path}")
                continue
                
            for template in self.required_templates:
                ext = self.get_file_extension(stack)
                template_file = stack_path / f"{template}.tpl.{ext}"
                
                if not template_file.exists():
                    self.errors.append(f"Missing template: {template_file}")
                else:
                    self.stats["total_templates"] += 1
                    print(f"✅ {stack}/{template}")
    
    def validate_code_structure(self):
        """Validate code structure within templates"""
        for stack in self.stacks:
            stack_path = self.templates_dir / "stacks" / stack / "base" / "code"
            if not stack_path.exists():
                continue
                
            for template in self.required_templates:
                ext = self.get_file_extension(stack)
                template_file = stack_path / f"{template}.tpl.{ext}"
                
                if template_file.exists():
                    if self.validate_single_template(template_file, stack, template):
                        self.stats["validated_templates"] += 1
    
    def validate_single_template(self, file_path: Path, stack: str, template: str) -> bool:
        """Validate a single template file"""
        try:
            content = file_path.read_text(encoding='utf-8')
            
            # Check file size (should be substantial for foundational templates)
            if len(content) < 2000:
                self.warnings.append(f"Template seems too small: {file_path} ({len(content)} chars)")
            
            # Stack-specific validations
            if stack == "go":
                return self.validate_go_template(file_path, content)
            elif stack == "python":
                return self.validate_python_template(file_path, content)
            elif stack in ["react_native", "node", "react"]:
                return self.validate_js_template(file_path, content)
            elif stack == "flutter":
                return self.validate_flutter_template(file_path, content)
            
            return True
            
        except Exception as e:
            self.errors.append(f"Error reading {file_path}: {e}")
            return False
    
    def validate_go_template(self, file_path: Path, content: str) -> bool:
        """Validate Go template specific requirements"""
        valid = True
        
        # Check for package declaration
        if not re.search(r'^package\s+\w+', content, re.MULTILINE):
            self.errors.append(f"Missing package declaration in: {file_path}")
            valid = False
        
        # Check for proper imports
        if not re.search(r'import\s*\(', content) and not re.search(r'import\s+"', content):
            self.warnings.append(f"No imports found in: {file_path}")
        
        # Check for function definitions
        if not re.search(r'func\s+\w+', content):
            self.errors.append(f"No function definitions found in: {file_path}")
            valid = False
        
        # Check for ExampleUsage function
        if not re.search(r'func\s+ExampleUsage', content):
            self.warnings.append(f"Missing ExampleUsage function in: {file_path}")
        
        # Check for dependency comments
        if "logging-utilities" in file_path.name:
            if "logrus" not in content and "github.com/sirupsen/logrus" not in content:
                self.warnings.append(f"Consider documenting logrus dependency in: {file_path}")
        
        return valid
    
    def validate_python_template(self, file_path: Path, content: str) -> bool:
        """Validate Python template specific requirements"""
        valid = True
        
        try:
            ast.parse(content)
        except SyntaxError as e:
            self.errors.append(f"Syntax error in {file_path}: {e}")
            valid = False
        
        # Check for docstring
        if not content.strip().startswith('"""') and not content.strip().startswith("PROJECT_ROOT / '"):
            self.warnings.append(f"Missing module docstring in: {file_path}")
        
        # Check for function / class definitions
        if not re.search(r'def\s+\w+|class\s+\w+', content):
            self.errors.append(f"No function or class definitions found in: {file_path}")
            valid = False
        
        # Check for example_usage function
        if not re.search(r'def\s+example_usage', content, re.IGNORECASE):
            self.warnings.append(f"Missing example_usage function in: {file_path}")
        
        # Check for imports
        if not re.search(r'import\s+\w+|from\s+\w+\s+import', content):
            self.warnings.append(f"No imports found in: {file_path}")
        
        return valid
    
    def validate_js_template(self, file_path: Path, content: str) -> bool:
        """Validate JavaScript/TypeScript template specific requirements"""
        valid = True
        
        # Check for proper imports/exports
        if "import" not in content and "require" not in content:
            self.warnings.append(f"No imports found in: {file_path}")
        
        if "export" not in content and "module.exports" not in content:
            self.warnings.append(f"No exports found in: {file_path}")
        
        # Check for function/class definitions
        if not re.search(r'function\s+\w+|class\s+\w+|const\s+\w+\s*=|let\s+\w+\s*=', content):
            self.errors.append(f"No function, class, or variable definitions found in: {file_path}")
            valid = False
        
        # Check for example usage
        if "exampleUsage" not in content and "ExampleUsage" not in content:
            self.warnings.append(f"Missing example usage in: {file_path}")
        
        # Basic syntax checks
        if content.count("{") != content.count("}"):
            self.errors.append(f"Mismatched braces in: {file_path}")
            valid = False
        
        if content.count("(") != content.count(")"):
            self.errors.append(f"Mismatched parentheses in: {file_path}")
            valid = False
        
        return valid
    
    def validate_flutter_template(self, file_path: Path, content: str) -> bool:
        """Validate Flutter/Dart template specific requirements"""
        valid = True
        
        # Check for library/import statements
        if not re.search(r"import\s+'|library\s+", content):
            self.warnings.append(f"No import statements found in: {file_path}")
        
        # Check for class definitions
        if not re.search(r'class\s+\w+', content):
            self.errors.append(f"No class definitions found in: {file_path}")
            valid = False
        
        # Check for example usage documentation
        if "/// Example usage" not in content and "// Example usage" not in content:
            self.warnings.append(f"Missing example usage documentation in: {file_path}")
        
        # Check for proper Dart structure
        if not re.search(r'void\s+\w+\(|\w+\s+\w+\([^)]*\)\s*{', content):
            self.warnings.append(f"No method definitions found in: {file_path}")
        
        return valid
    
    def validate_documentation_and_examples(self):
        """Check documentation and example usage"""
        for stack in self.stacks:
            stack_path = self.templates_dir / "stacks" / stack / "base" / "code"
            if not stack_path.exists():
                continue
                
            for template in self.required_templates:
                ext = self.get_file_extension(stack)
                template_file = stack_path / f"{template}.tpl.{ext}"
                
                if template_file.exists():
                    content = template_file.read_text(encoding='utf-8')
                    
                    # Check for header documentation
                    if self.has_header_documentation(content):
                        self.stats["templates_with_docs"] += 1
                    
                    # Check for example usage
                    if self.has_example_usage(content, stack):
                        self.stats["templates_with_examples"] += 1
    
    def has_header_documentation(self, content: str) -> bool:
        """Check if template has header documentation"""
        return (content.startswith('"""') or 
                content.startswith("'''") or 
                content.startswith("/*") or
                content.startswith("//") or
                content.startswith("///"))
    
    def has_example_usage(self, content: str, stack: str) -> bool:
        """Check if template has example usage"""
        example_patterns = [
            r"exampleUsage",
            r"ExampleUsage", 
            r"example_usage",
            r"Example usage",
            r"example usage"
        ]
        
        for pattern in example_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def validate_exports_and_interfaces(self):
        """Validate proper exports and interfaces"""
        for stack in self.stacks:
            stack_path = self.templates_dir / "stacks" / stack / "base" / "code"
            if not stack_path.exists():
                continue
                
            for template in self.required_templates:
                ext = self.get_file_extension(stack)
                template_file = stack_path / f"{template}.tpl.{ext}"
                
                if template_file.exists():
                    content = template_file.read_text(encoding='utf-8')
                    
                    if self.has_proper_exports(content, stack):
                        self.stats["templates_with_exports"] += 1
    
    def has_proper_exports(self, content: str, stack: str) -> bool:
        """Check if template has proper exports"""
        if stack in ["react_native", "node", "react"]:
            return "export" in content or "module.exports" in content
        elif stack == "python":
            return re.search(r'__all__\s*=|def\s+\w+', content) is not None
        elif stack == "go":
            return re.search(r'func\s+\w+', content) is not None
        elif stack == "flutter":
            return re.search(r'class\s+\w+', content) is not None
        return False
    
    def validate_dependency_manifests(self):
        """Check dependency manifest files exist"""
        manifests = {
            "go": "go.mod.tpl",
            "python": "requirements.txt.tpl", 
            "flutter": "pubspec.yaml.tpl",
            "react_native": "package.json.tpl",
            "react": "package.json.tpl",
            "node": "package.json.tpl"
        }
        
        for stack, manifest_file in manifests.items():
            manifest_path = self.templates_dir / "stacks" / stack / manifest_file
            if manifest_path.exists():
                print(f"✅ {stack}/{manifest_file}")
            else:
                self.warnings.append(f"Missing dependency manifest: {manifest_path}")
    
    def get_file_extension(self, stack: str) -> str:
        """Get the appropriate file extension for a stack"""
        extensions = {
            "flutter": "dart",
            "react_native": "js", 
            "react": "jsx",
            "node": "js",
            "python": "py",
            "go": "go"
        }
        return extensions.get(stack, "txt")
    
    def print_summary(self):
        """Print validation summary"""
        print("\n" + "=" * 60)
        print("📊 FOUNDATIONAL TEMPLATES VALIDATION SUMMARY")
        print("=" * 60)
        
        print(f"📁 Total Templates: {self.stats['total_templates']}")
        print(f"✅ Validated Templates: {self.stats['validated_templates']}")
        print(f"📚 Templates with Documentation: {self.stats['templates_with_docs']}")
        print(f"💡 Templates with Examples: {self.stats['templates_with_examples']}")
        print(f"📤 Templates with Exports: {self.stats['templates_with_exports']}")
        print(f"🚨 Errors: {len(self.errors)}")
        print(f"⚠️  Warnings: {len(self.warnings)}")
        
        # Calculate quality score
        if self.stats['total_templates'] > 0:
            quality_score = (self.stats['validated_templatesPROJECT_ROOT / ']  /  self.stats['total_templates']) * 100
            print(f"📈 Quality Score: {quality_score:.1f}%")
        
        if self.errors:
            print(f"\n❌ Errors:")
            for error in self.errors[:10]:  # Limit output
                print(f"   • {error}")
            if len(self.errors) > 10:
                print(f"   ... and {len(self.errors) - 10} more errors")
        
        if self.warnings:
            print(f"\n⚠️  Warnings:")
            for warning in self.warnings[:10]:  # Limit output
                print(f"   • {warning}")
            if len(self.warnings) > 10:
                print(f"   ... and {len(self.warnings) - 10} more warnings")
        
        if len(self.errors) == 0:
            print(f"\n🎉 ALL FOUNDATIONAL TEMPLATES VALIDATED SUCCESSFULLY!")
            if len(self.warnings) == 0:
                print("✨ Perfect quality - no issues found!")
            else:
                print(f"✅ Great quality with {len(self.warnings)} minor improvements suggested")
        else:
            print(f"\n❌ {len(self.errors)} critical issues found - review required")

def main():
    """Main validation function"""
    templates_dir = Path(__file__).parent.parent
    validator = FoundationalTemplateValidator(templates_dir)
    
    success = validator.validate_all()
    
    if not success:
        print(f"\n❌ Foundational template validation failed!")
        exit(1)
    else:
        print(f"\n✅ Foundational template validation completed successfully!")
        exit(0)

if __name__ == "__main__":
    main()
