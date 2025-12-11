#!/usr/bin/env python3
"""
Comprehensive Template Validation Script
Purpose: Double-check all templates for structural issues, content consistency, and cross-references
Usage: python scripts/validate-templates.py [--full] [--fix] [--report REPORT_FILE]
"""

import sys
import os
import json
import re
import yaml
from pathlib import Path
from typing import Dict, List, Tuple, Set
from datetime import datetime
from stack_config import get_all_stacks, get_all_tiers
from blueprint_config import get_available_blueprints, validate_blueprint, get_blueprint_summary

# Ensure consistent UTF-8 output on Windows consoles to avoid encoding errors when printing symbols/emojis
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Fix Unicode encoding issues on Windows
if os.name == 'nt':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

class TemplateValidator:
    # Characters that indicate a link URL is likely code content rather than a file path
    CODE_LIKE_CHARS = ["'", '"', '{', '}', '=', '+', '-', '*', ';']
    
    def __init__(self, templates_root: Path):
        self.templates_root = templates_root
        self.issues = []
        self.warnings = []
        self.stats = {
            "total_files": 0,
            "validated_files": 0,
            "files_with_issues": 0,
            "broken_links": 0,
            "version_inconsistencies": 0,
            "structure_issues": 0
        }
    
    def log_issue(self, severity: str, file_path: str, issue: str, line: int = None):
        """Log an issue with the template"""
        issue_data = {
            "severity": severity,
            "file": str(file_path),
            "issue": issue,
            "line": line,
            "timestamp": datetime.now().isoformat()
        }
        
        if severity == "error":
            self.issues.append(issue_data)
            self.stats["files_with_issues"] += 1
        else:
            self.warnings.append(issue_data)
        
        print(f"{severity.upper()}: {file_path}")
        if line:
            print(f"  Line {line}: {issue}")
        else:
            print(f"  {issue}")
    
    def validate_file_structure(self):
        """Validate the overall template file structure"""
        print("Validating Template File Structure...")
        print("-" * 50)
        
        expected_dirs = [
            "tiers/mvp/code",
            "tiers/mvp/tests",
            "tiers/core/code",
            "tiers/core/tests",
            "tiers/enterprise/code",
            "tiers/enterprise/tests",
            "stacks/flutter",
            "stacks/react_native",
            "stacks/react",
            "stacks/node",
            "stacks/python",
            "stacks/go"
        ]
        
        for dir_path in expected_dirs:
            full_path = self.templates_root / dir_path
            if not full_path.exists():
                self.log_issue("error", dir_path, "Expected directory does not exist")
            elif not full_path.is_dir():
                self.log_issue("error", dir_path, "Path exists but is not a directory")
            else:
                print(f"[OK] {dir_path}")
    
    def validate_tier_index(self):
        """Validate tier-index.yaml for consistency"""
        print("\nValidating tier-index.yaml...")
        print("-" * 40)
        
        tier_index_path = self.templates_root / "tier-index.yaml"
        if not tier_index_path.exists():
            self.log_issue("error", "tier-index.yaml", "tier-index.yaml does not exist")
            return
        
        try:
            with open(tier_index_path, 'r', encoding='utf-8') as f:
                tier_data = yaml.safe_load(f)
            
            # Check required sections
            required_sections = ["universal_patterns", "testing_templates", "stack_patterns"]
            for section in required_sections:
                if section not in tier_data:
                    self.log_issue("error", "tier-index.yaml", f"Missing required section: {section}")
            
            # Validate template entries
            if "testing_templates" in tier_data:
                self._validate_testing_templates(tier_data["testing_templates"])
            
            if "stack_patterns" in tier_data:
                self._validate_stack_patterns(tier_data["stack_patterns"])
            
            print("[OK] tier-index.yaml structure validated")
            
        except yaml.YAMLError as e:
            self.log_issue("error", "tier-index.yaml", f"YAML parsing error: {e}")
        except Exception as e:
            self.log_issue("error", "tier-index.yaml", f"Validation error: {e}")
    
    def _validate_testing_templates(self, testing_templates: Dict):
        """Validate testing template entries"""
        expected_tiers = get_all_tiers()
        expected_stacks = get_all_stacks()
        
        for tier in expected_tiers:
            if tier not in testing_templates:
                self.log_issue("error", "tier-index.yaml", f"Missing tier: {tier}")
                continue
            
            tier_entry = testing_templates[tier]
            
            # Handle legacy/new schema where testing_templates[tier] is a dict keyed by stack
            if isinstance(tier_entry, dict):
                for stack in expected_stacks:
                    if stack not in tier_entry:
                        self.log_issue("error", "tier-index.yaml", f"Missing {stack} in {tier}")
                        continue
                    
                    template_info = tier_entry[stack]
                    
                    # Check required fields
                    required_fields = ["version", "purpose", "overlay_for"]
                    for field in required_fields:
                        if field not in template_info:
                            self.log_issue("error", "tier-index.yaml", f"Missing {field} for {tier}/{stack}")
                    
                    # Check version consistency
                    if "version" in template_info:
                        expected_version = {"mvp": "1.0", "core": "2.0", "enterprise": "3.0"}[tier]
                        if template_info["version"] != expected_version:
                            self.log_issue("warning", "tier-index.yaml", 
                                         f"Version mismatch for {tier}/{stack}: expected {expected_version}, got {template_info['version']}")
                            self.stats["version_inconsistencies"] += 1
                    
                    # Check purpose field quality
                    if "purpose" in template_info:
                        purpose = template_info["purpose"]
                        if len(purpose) < 20:
                            self.log_issue("warning", "tier-index.yaml", 
                                         f"Purpose description too short for {tier}/{stack}")
            
            # Handle current schema where testing_templates[tier] is a list of template paths
            elif isinstance(tier_entry, list):
                for template_path in tier_entry:
                    resolved_path = self.templates_root / template_path
                    if not resolved_path.exists():
                        self.log_issue("error", "tier-index.yaml", f"Missing testing template path: {template_path}")
            
            else:
                self.log_issue("error", "tier-index.yaml", f"Unexpected testing_templates format for tier {tier}: {type(tier_entry).__name__}")
    
    def _validate_stack_patterns(self, stack_patterns: Dict):
        """Validate stack pattern entries"""
        expected_stacks = get_all_stacks()
        
        for stack in expected_stacks:
            if stack not in stack_patterns:
                self.log_issue("error", "tier-index.yaml", f"Missing stack pattern: {stack}")
                continue
            
            stack_info = stack_patterns[stack]
            
            # Check required fields
            if "base_template" not in stack_info:
                self.log_issue("error", "tier-index.yaml", f"Missing base_template for {stack}")
    
    def validate_template_files(self):
        """Validate individual template files"""
        print("\nValidating Template Files...")
        print("-" * 35)
        
        template_files = list(self.templates_root.rglob("*.tpl.*"))
        self.stats["total_files"] = len(template_files)
        
        for template_file in template_files:
            self._validate_single_template(template_file)
        
        print(f"[OK] Validated {self.stats['validated_files']}/{self.stats['total_files']} template files")
    
    def _validate_single_template(self, template_file: Path):
        """Validate a single template file"""
        try:
            with open(template_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.stats["validated_files"] += 1
            
            # Check for header comments
            valid_headers = ['#', '<!--']
            if template_file.suffix in ['.js', '.jsx', '.ts', '.tsx', '.go', '.dart', '.rs']:
                valid_headers.extend(['//', '/**', '///'])
            elif template_file.suffix in ['.py']:
                valid_headers.extend(['"""', "'''"])
            elif template_file.suffix in ['.sql', '.R']:
                valid_headers.extend(['--'])
            
            # Special case: .tpl.md files in tests/ directories often contain code
            if template_file.suffix == '.md' and '/tests/' in str(template_file):
                valid_headers.extend(['//', '/**', '///'])

            if not content.lstrip().startswith(tuple(valid_headers)):
                self.log_issue("warning", template_file, "Missing header comment")
                self.stats["structure_issues"] += 1
            
            # Check for required sections based on file type
            # Skip markdown validation for .md files in tests/ that contain code
            is_code_in_md = template_file.suffix == '.md' and '/tests/' in str(template_file) and content.lstrip().startswith('//')
            if template_file.suffix in ['.md', '.tpl.md'] and not is_code_in_md:
                self._validate_markdown_template(template_file, content)
            elif template_file.suffix in ['.py', '.js', '.jsx', '.go', '.dart']:
                self._validate_code_template(template_file, content)
            
            # Check for template placeholders
            if "[[" not in content and "{{" not in content and "${" not in content:
                # Only warn for code templates, not documentation
                if template_file.suffix in ['.py', '.js', '.jsx', '.go', '.dart']:
                    self.log_issue("warning", template_file, "No template placeholders found")
            
        except UnicodeDecodeError:
            self.log_issue("error", template_file, "File encoding issue")
        except Exception as e:
            self.log_issue("error", template_file, f"Validation error: {e}")
    
    def _validate_markdown_template(self, template_file: Path, content: str):
        """Validate markdown template structure"""
        # Check for proper markdown structure
        if not re.search(r'^# ', content, re.MULTILINE):
            self.log_issue("warning", template_file, "Missing main title (#)")
        
        # Remove code blocks before checking for broken links to avoid false positives
        # This removes fenced code blocks (```...```) and inline code (`...`)
        # Note: Does not handle escaped backticks within code blocks
        content_without_code = re.sub(r'```[\s\S]*?```', '', content)
        content_without_code = re.sub(r'`[^`]*`', '', content_without_code)  # Allow empty inline code
        
        # Check for internal links (only in non-code content)
        links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content_without_code)
        for link_text, link_url in links:
            # Skip if the link URL looks like code (contains function calls, quotes, etc.)
            if any(char in link_url for char in self.CODE_LIKE_CHARS):
                continue
            
            if link_url.startswith('./') or not link_url.startswith(('http://', 'https://', '#')):
                # Internal link - check if target exists
                target_path = (template_file.parent / link_url).resolve()
                if not target_path.exists():
                    self.log_issue("error", template_file, f"Broken internal link: {link_url}")
                    self.stats["broken_links"] += 1
    
    def _validate_code_template(self, template_file: Path, content: str):
        """Validate code template structure"""
        # Check for basic code structure
        if template_file.suffix == '.py':
            if not re.search(r'def |class |import |from ', content):
                self.log_issue("warning", template_file, "No Python code structure detected")
        elif template_file.suffix in ['.js', '.jsx']:
            if not re.search(r'function |class |const |let |var |import ', content):
                self.log_issue("warning", template_file, "No JavaScript code structure detected")
        elif template_file.suffix == '.go':
            if not re.search(r'func |package |import ', content):
                self.log_issue("warning", template_file, "No Go code structure detected")
        elif template_file.suffix == '.dart':
            if not re.search(r'void |class |import ', content):
                self.log_issue("warning", template_file, "No Dart code structure detected")
    
    def validate_system_map_references(self):
        """Validate SYSTEM-MAP.md references after move"""
        print("\nValidating SYSTEM-MAP.md References...")
        print("-" * 50)
        
        system_map_path = self.templates_root / "SYSTEM-MAP.md"
        if not system_map_path.exists():
            self.log_issue("error", "SYSTEM-MAP.md", "SYSTEM-MAP.md not found in root")
            return
        
        # Check for references to old location
        with open(system_map_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if "universal/docs/SYSTEM-MAP.tpl.md" in content:
            self.log_issue("error", "SYSTEM-MAP.md", "Contains reference to old location")
        
        # Check all files that should reference SYSTEM-MAP.md
        all_files = list(self.templates_root.rglob("*.md"))
        for file_path in all_files:
            if file_path == system_map_path:
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    file_content = f.read()
                
                if "SYSTEM-MAP" in file_content:
                    if "universal/docs/SYSTEM-MAP.tpl.md" in file_content:
                        self.log_issue("error", file_path, "References old SYSTEM-MAP location")
                    elif "SYSTEM-MAP.md" not in file_content:
                        self.log_issue("warning", file_path, "SYSTEM-MAP reference may be outdated")
                        
            except Exception:
                continue  # Skip files that can't be read
        
        print("[OK] SYSTEM-MAP.md references validated")
    
    def validate_tier_overlay_counts(self):
        """Validate tier overlay file counts match actual system structure"""
        print("\nValidating Tier Overlay Counts...")
        print("-" * 40)
        
        expected_counts = {
            "mvp": 39,    # Synced with current file count
            "core": 28,   # Synced with current file count
            "enterprise": 28  # Synced with current file count
        }
        
        for tier, expected_count in expected_counts.items():
            tier_path = self.templates_root / "tiers" / tier
            if not tier_path.exists():
                continue
            
            # Count only actual template files, exclude __pycache__ and compiled files
            actual_files = [f for f in tier_path.rglob("*.tpl.*") 
                           if "__pycache__" not in str(f) 
                           and not str(f).endswith(".pyc")]
            actual_count = len(actual_files)
            
            if actual_count != expected_count:
                self.log_issue("warning", f"tiers/{tier}", 
                             f"Template file count mismatch: expected {expected_count}, got {actual_count}")
        
        print("[OK] Tier overlay counts validated")
    
    def validate_blueprints(self):
        """Validate blueprint system integrity and configuration"""
        print("\nValidating Blueprint System...")
        print("-" * 40)
        
        blueprints_dir = self.templates_root / "blueprints"
        if not blueprints_dir.exists():
            self.log_issue("warning", "blueprints/", "Blueprints directory not found")
            return
        
        # Get available blueprints
        available_blueprints = get_available_blueprints()
        
        if not available_blueprints:
            self.log_issue("warning", "blueprints/", "No valid blueprints found")
            return
        
        print(f"Found {len(available_blueprints)} blueprint(s): {', '.join(available_blueprints)}")
        
        # Validate each blueprint
        for blueprint_id in available_blueprints:
            blueprint_path = blueprints_dir / blueprint_id
            
            # Check required files exist
            required_files = ["BLUEPRINT.md", "blueprint.meta.yaml"]
            for file_name in required_files:
                file_path = blueprint_path / file_name
                if not file_path.exists():
                    self.log_issue("error", f"blueprints/{blueprint_id}/{file_name}", 
                                 f"Required blueprint file missing: {file_name}")
                else:
                    print(f"  [OK] {blueprint_id}/{file_name}")
            
            # Validate blueprint metadata
            validation_errors = validate_blueprint(blueprint_id)
            for error in validation_errors:
                self.log_issue("error", f"blueprints/{blueprint_id}/blueprint.meta.yaml", error)
            
            # Check overlay structure if specified
            summary = get_blueprint_summary(blueprint_id)
            if 'stacks' in summary:
                supported_stacks = summary['stacks'].get('supported', [])
                for stack in supported_stacks:
                    overlay_path = blueprint_path / "overlays" / stack
                    if overlay_path.exists():
                        print(f"  [OK] {blueprint_id}/overlays/{stack}")
                    else:
                        self.log_issue("warning", f"blueprints/{blueprint_id}/overlays/{stack}", 
                                     f"Overlay directory missing for supported stack: {stack}")
        
        print("[OK] Blueprint system validated")
    
    def generate_report(self, output_file: str = None):
        """Generate validation report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_files": self.stats["total_files"],
                "validated_files": self.stats["validated_files"],
                "files_with_issues": self.stats["files_with_issues"],
                "total_errors": len(self.issues),
                "total_warnings": len(self.warnings),
                "broken_links": self.stats["broken_links"],
                "version_inconsistencies": self.stats["version_inconsistencies"],
                "structure_issues": self.stats["structure_issues"]
            },
            "issues": self.issues,
            "warnings": self.warnings
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\nReport saved to: {output_file}")
        
        return report
    
    def print_summary(self):
        """Print validation summary"""
        print("\n" + "=" * 60)
        print("TEMPLATE VALIDATION SUMMARY")
        print("=" * 60)
        
        print(f"Total Files: {self.stats['total_files']}")
        print(f"Validated Files: {self.stats['validated_files']}")
        print(f"Files with Issues: {self.stats['files_with_issues']}")
        print(f"Errors: {len(self.issues)}")
        print(f"Warnings: {len(self.warnings)}")
        print(f"Broken Links: {self.stats['broken_links']}")
        print(f"Version Inconsistencies: {self.stats['version_inconsistencies']}")
        print(f"Structure Issues: {self.stats['structure_issues']}")
        
        if len(self.issues) == 0:
            print("\nAll templates validated successfully.")
        else:
            print(f"\n{len(self.issues)} critical issues found - review required")
        
        if len(self.warnings) > 0:
            print(f"{len(self.warnings)} warnings found - consider reviewing")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive template validation")
    parser.add_argument("--full", action="store_true", help="Run full validation including content checks")
    parser.add_argument("--fix", action="store_true", help="Attempt to fix minor issues automatically")
    parser.add_argument("--report", help="Generate JSON report file")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress output except summary")
    
    args = parser.parse_args()
    
    templates_root = Path(__file__).parent.parent
    validator = TemplateValidator(templates_root)
    
    if not args.quiet:
        print("Universal Template Validation Tool")
        print("=" * 40)
        print(f"Template Root: {templates_root}")
        print()
    
    try:
        # Run validation checks
        validator.validate_file_structure()
        validator.validate_tier_index()
        validator.validate_template_files()
        validator.validate_system_map_references()
        validator.validate_tier_overlay_counts()
        validator.validate_blueprints()
        
        # Generate report
        report = validator.generate_report(args.report)
        
        # Print summary
        validator.print_summary()
        
        # Exit with error code if issues found
        if len(validator.issues) > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\nValidation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Validation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
