#!/usr/bin/env python3
"""
Self-Healing Documentation System
Automatically detects and fixes common template system issues
Part of the 10/10 Template System - integrates with validate_docs.py
Usage: python3 scripts/self_heal.py [--dry-run] [--fix-level basic|advanced]
"""

import yaml
import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any
from validate_docs import DocumentationValidator

class SelfHealingSystem:
    def __init__(self, templates_dir="_templates", fix_level="basic"):
        self.templates_dir = Path(templates_dir)
        self.fix_level = fix_level
        self.validator = DocumentationValidator("tier-index.yaml", templates_dir)
        self.fixes_applied = []
        self.fixes_failed = []
        
    def detect_issues(self) -> Dict[str, Any]:
        """Detect issues that can be automatically fixed."""
        issues = {
            "missing_gitignore": [],
            "outdated_references": [],
            "missing_placeholders": [],
            "format_inconsistencies": [],
            "template_sync_issues": []
        }
        
        # Check for missing .gitignore in projects
        if not (self.templates_dir / ".gitignore").exists():
            issues["missing_gitignore"].append("templates/.gitignore")
        
        # Check tier-index.yaml sync issues
        sync_report = self.validator.check_template_sync()
        if not sync_report["tier_index_valid"]:
            issues["template_sync_issues"] = sync_report["missing_templates"]
        
        # Check for outdated file references
        issues["outdated_references"] = self.detect_outdated_references()
        
        # Check for missing placeholders in key templates
        issues["missing_placeholders"] = self.detect_missing_placeholders()
        
        return issues
    
    def detect_outdated_references(self) -> List[str]:
        """Detect outdated file references in documentation."""
        outdated = []
        
        # Check for common outdated reference patterns
        key_files = [
            "README.md", "QUICKSTART-AI.md", "SYSTEM-INTEGRATION.md",
            "docs/README.md", "universal/README.md"
        ]
        
        for file_pattern in key_files:
            file_path = self.templates_dir / file_pattern
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding='utf-8')
                    
                    # Check for outdated docs/QUICKSTART-AI.md references
                    if "docs/QUICKSTART-AI.md" in content:
                        outdated.append(f"{file_pattern}: Contains outdated docs/QUICKSTART-AI.md reference")
                    
                    # Check for other common outdated patterns
                    if "TODO:" in content and "dynamic parsing" in content.lower():
                        outdated.append(f"{file_pattern}: Contains TODO about dynamic parsing (now implemented)")
                        
                except Exception as e:
                    print(f"Warning: Could not read {file_path}: {e}")
        
        return outdated
    
    def detect_missing_placeholders(self) -> List[str]:
        """Detect missing or inconsistent placeholders in templates."""
        missing = []
        
        # Check key templates for required placeholders
        key_templates = [
            "universal/README.md",
            "universal/AGENTS.md", 
            "universal/INTEGRATION-GUIDE.md"
        ]
        
        required_placeholders = {
            "README.md": ["{PROJECT_NAME}", "{DESCRIPTION}"],
            "AGENTS.md": ["{PROJECT_NAME}", "{FRAMEWORK}", "{TIER}"],
            "INTEGRATION-GUIDE.md": ["{PROJECT_NAME}", "{TIER}"]
        }
        
        for template_path in key_templates:
            file_path = self.templates_dir / template_path
            if file_path.exists():
                try:
                    content = file_path.read_text(encoding='utf-8')
                    template_name = Path(template_path).name
                    
                    if template_name in required_placeholders:
                        for placeholder in required_placeholders[template_name]:
                            if placeholder not in content:
                                missing.append(f"{template_path}: Missing {placeholder}")
                                
                except Exception as e:
                    print(f"Warning: Could not read {template_path}: {e}")
        
        return missing
    
    def apply_fixes(self, issues: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
        """Apply automatic fixes for detected issues."""
        results = {
            "fixes_applied": [],
            "fixes_failed": [],
            "fixes_skipped": []
        }
        
        # Fix missing .gitignore
        if issues["missing_gitignore"] and self.fix_level in ["basic", "advanced"]:
            for gitignore_path in issues["missing_gitignore"]:
                if not dry_run:
                    if self.create_gitignore(gitignore_path):
                        results["fixes_applied"].append(f"Created {gitignore_path}")
                    else:
                        results["fixes_failed"].append(f"Failed to create {gitignore_path}")
                else:
                    results["fixes_skipped"].append(f"Would create {gitignore_path}")
        
        # Fix outdated references
        if issues["outdated_references"] and self.fix_level == "advanced":
            for reference in issues["outdated_references"]:
                file_path = reference.split(":")[0]
                if not dry_run:
                    if self.fix_outdated_reference(file_path, reference):
                        results["fixes_applied"].append(f"Fixed reference in {file_path}")
                    else:
                        results["fixes_failed"].append(f"Failed to fix reference in {file_path}")
                else:
                    results["fixes_skipped"].append(f"Would fix reference in {file_path}")
        
        # Fix missing placeholders (advanced only)
        if issues["missing_placeholders"] and self.fix_level == "advanced":
            for placeholder_issue in issues["missing_placeholders"]:
                template_path = placeholder_issue.split(":")[0]
                placeholder = placeholder_issue.split(": ")[1]
                if not dry_run:
                    if self.add_missing_placeholder(template_path, placeholder):
                        results["fixes_applied"].append(f"Added {placeholder} to {template_path}")
                    else:
                        results["fixes_failed"].append(f"Failed to add {placeholder} to {template_path}")
                else:
                    results["fixes_skipped"].append(f"Would add {placeholder} to {template_path}")
        
        return results
    
    def create_gitignore(self, target_path: str) -> bool:
        """Create a comprehensive .gitignore file."""
        try:
            gitignore_content = """# Template System .gitignore
# Generated by self-healing system

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Node.js
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Build outputs
build/
dist/
out/

# Logs
logs
*.log

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/
*.lcov

# Temporary folders
tmp/
temp/

# Documentation build
docs/_build/
docs/build/
"""
            
            full_path = self.templates_dir / target_path
            full_path.write_text(gitignore_content, encoding='utf-8')
            return True
            
        except Exception as e:
            print(f"Error creating .gitignore: {e}")
            return False
    
    def fix_outdated_reference(self, file_path: str, issue_description: str) -> bool:
        """Fix outdated file references."""
        try:
            full_path = self.templates_dir / file_path
            content = full_path.read_text(encoding='utf-8')
            
            # Fix docs/QUICKSTART-AI.md references
            if "docs/QUICKSTART-AI.md" in content:
                content = content.replace("docs/QUICKSTART-AI.md", "QUICKSTART-AI.md")
                full_path.write_text(content, encoding='utf-8')
                return True
            
            # Remove TODO comments about dynamic parsing
            if "dynamic parsing" in issue_description.lower():
                lines = content.split('\n')
                filtered_lines = [line for line in lines 
                                if not (line.strip().startswith('# TODO:') and 
                                       'dynamic parsing' in line.lower())]
                full_path.write_text('\n'.join(filtered_lines), encoding='utf-8')
                return True
            
            return False
            
        except Exception as e:
            print(f"Error fixing reference in {file_path}: {e}")
            return False
    
    def add_missing_placeholder(self, template_path: str, placeholder: str) -> bool:
        """Add missing placeholder to template."""
        # This is a simplified implementation
        # In practice, you'd need more sophisticated logic to determine
        # where to place the placeholder in the template
        try:
            full_path = self.templates_dir / template_path
            content = full_path.read_text(encoding='utf-8')
            
            # Add placeholder at the end of file as a simple approach
            if placeholder not in content:
                content += f"\n<!-- Auto-added placeholder: {placeholder} -->\n"
                full_path.write_text(content, encoding='utf-8')
                return True
            
            return False
            
        except Exception as e:
            print(f"Error adding placeholder to {template_path}: {e}")
            return False
    
    def generate_healing_report(self, issues: Dict[str, Any], results: Dict[str, Any]) -> str:
        """Generate a comprehensive healing report."""
        report = f"""
# Self-Healing Documentation Report
Generated: {sys.argv[0]} on {_get_timestamp()}

## Issues Detected
- Missing .gitignore: {len(issues['missing_gitignore'])}
- Outdated References: {len(issues['outdated_references'])}
- Missing Placeholders: {len(issues['missing_placeholders'])}
- Template Sync Issues: {len(issues['template_sync_issues'])}

## Fixes Applied
- Successfully Applied: {len(results['fixes_applied'])}
- Failed: {len(results['fixes_failed'])}
- Skipped (dry run): {len(results['fixes_skipped'])}

## Details
"""
        
        if results['fixes_applied']:
            report += "\n### ✅ Fixes Applied\n"
            for fix in results['fixes_applied']:
                report += f"- {fix}\n"
        
        if results['fixes_failed']:
            report += "\n### ❌ Fixes Failed\n"
            for fix in results['fixes_failed']:
                report += f"- {fix}\n"
        
        if results['fixes_skipped']:
            report += "\n### ⏭️ Fixes Skipped (Dry Run)\n"
            for fix in results['fixes_skipped']:
                report += f"- {fix}\n"
        
        return report

def _get_timestamp() -> str:
    """Get current timestamp."""
    import time
    return time.strftime("%Y-%m-%d %H:%M:%S")

def main():
    parser = argparse.ArgumentParser(description="Self-healing documentation system")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be fixed without making changes")
    parser.add_argument("--fix-level", choices=["basic", "advanced"], default="basic", 
                       help="Level of fixes to apply (basic=safe fixes, advanced=invasive changes)")
    parser.add_argument("--templates-dir", default="_templates", help="Templates directory path")
    parser.add_argument("--report", action="store_true", help="Generate detailed report")
    
    args = parser.parse_args()
    
    try:
        healer = SelfHealingSystem(args.templates_dir, args.fix_level)
        
        print("🔍 Detecting issues...")
        issues = healer.detect_issues()
        
        total_issues = sum(len(issues[key]) for key in issues)
        print(f"📊 Found {total_issues} issues to address")
        
        if total_issues == 0:
            print("✅ No issues detected - template system is healthy!")
            return
        
        print("🔧 Applying fixes...")
        results = healer.apply_fixes(issues, args.dry_run)
        
        print(f"\n📈 Results:")
        print(f"  ✅ Applied: {len(results['fixes_applied'])}")
        print(f"  ❌ Failed: {len(results['fixes_failed'])}")
        print(f"  ⏭️ Skipped: {len(results['fixes_skipped'])}")
        
        if args.report:
            report = healer.generate_healing_report(issues, results)
            report_path = Path(args.templates_dir) / "self-heal-report.md"
            report_path.write_text(report, encoding='utf-8')
            print(f"📄 Detailed report saved to: {report_path}")
        
        # Exit with error code if fixes failed
        if len(results['fixes_failed']) > 0:
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Self-healing failed: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
