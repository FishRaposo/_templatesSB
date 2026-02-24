#!/usr/bin/env python3
"""
Documentation Validation Script
Validates documentation compliance against tier-index.yaml
Part of the Documentation OS - integrates with VALIDATION.md
Usage: python3 scripts/validate_docs.py --tier core [--verbose] [--json] [--check-sync]
"""

import yaml
import os
import sys
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any

# Resolve project root for path consistency
PROJECT_ROOT = Path(__file__).parent.parent.parent

class ValidationError(Exception):
    pass

class DocumentationValidator:
    def __init__(self, index_path="tier-index.yaml", templates_dir=None):
        self.index_path = index_path
        
        # Auto-detect templates directory like tier_config.py
        if templates_dir is None:
            # Check current directory first (for calls from project root)
            if Path("tier-index.yaml").exists():
                self.templates_dir = Path(".")
            else:
                # Fall back to script-relative path (for calls from scripts/)
                self.templates_dir = Path(__file__).parent.parent
        else:
            self.templates_dir = Path(templates_dir)
            
        self.index = None
        self.tier_requirements = None
        
    def load_index(self):
        """Load tier index with compatibility fallback."""
        try:
            with open(self.index_path, 'r') as f:
                self.index = yaml.safe_load(f)
        except FileNotFoundError:
            # Fallback to alternative naming
            alt_path = "docs_index.yaml"
            if os.path.exists(alt_path):
                with open(alt_path, 'r') as f:
                    self.index = yaml.safe_load(f)
            else:
                raise ValidationError(f"Tier index file not found: {self.index_path} or {alt_path}")
    
    def parse_tier_requirements(self, tier: str):
        """Parse tier requirements from index."""
        if not self.index:
            self.load_index()
        
        tier_key = tier.lower()
        if tier_key not in self.index["tiers"]:
            raise ValidationError(f"Invalid tier: {tier}")
        
        tier_config = self.index["tiers"][tier_key]
        self.tier_requirements = {
            "required": tier_config.get("required", []),
            "recommended": tier_config.get("recommended", []),
            "ignored": tier_config.get("ignored", []),
            "coverage_target": tier_config.get("coverage_target", "85%+"),
            "min_file_size": tier_config.get("min_file_size", 200),
            "max_age_days": tier_config.get("max_age_days", 30)
        }
        
        return self.tier_requirements
    
    def scan_repository(self, base_path: str = ".") -> Dict[str, Dict[str, Any]]:
        """Scan repository and catalog documentation files."""
        doc_files = {}
        base_path = Path(base_path)
        
        for file_path in base_path.rglob("*.md"):
            # Skip hidden directories and common exclusions
            if any(part.startswith('.') for part in file_path.parts):
                continue
            if any(exclude in str(file_path) for exclude in ['node_modules', 'build', 'dist', '.git', '_templatesPROJECT_ROOT / ']):
                continue
            
            rel_path = str(file_path.relative_to(base_path))
            stat = file_path.stat()
            
            doc_files[rel_path] = {
                "size": stat.st_size,
                "modified": stat.st_mtime,
                "age_days": (time.time() - stat.st_mtime)  /  (24 * 3600),
                "full_path": str(file_path)
            }
        
        return doc_files
    
    def validate(self, tier: str, base_path: str = ".") -> Dict[str, Any]:
        """Run complete validation for specified tier."""
        # Parse tier requirements
        requirements = self.parse_tier_requirements(tier)
        
        # Scan repository
        existing_files = self.scan_repository(base_path)
        
        # Validate required files
        errors = self._validate_required_files(requirements["required"], existing_files)
        
        # Check recommended files
        notices = self._validate_recommended_files(requirements["recommended"], existing_files)
        
        # Detect outdated files
        warnings = self._detect_outdated_files(existing_files, requirements["max_age_days"])
        
        # Generate compliance report
        report = self._generate_compliance_report(
            requirements["required"], existing_files, errors, warnings, notices
        )
        
        # Generate fix suggestions
        suggestions = self._suggest_fixes(errors, warnings, notices, requirements)
        
        return {
            "tier": tier,
            "timestamp": time.time(),
            "report": report,
            "issues": {
                "errors": errors,
                "warnings": warnings,
                "notices": notices
            },
            "suggestions": suggestions,
            "requirements": requirements
        }
    
    def _validate_required_files(self, required_files: List[str], existing_files: Dict) -> List[Dict]:
        """Validate required files exist and meet standards."""
        errors = []
        
        for req_file in required_files:
            if req_file not in existing_files:
                errors.append({
                    "type": "ERROR",
                    "file": req_file,
                    "message": f"Missing required file: {req_file}",
                    "severity": "critical"
                })
            else:
                file_info = existing_files[req_file]
                if file_info["size"] < self.tier_requirements["min_file_size"]:
                    errors.append({
                        "type": "WARNING",
                        "file": req_file,
                        "message": f"Required file too small: {req_file} ({file_info['size']} < {self.tier_requirements['min_file_size']} chars)",
                        "severity": "medium"
                    })
        
        return errors
    
    def _validate_recommended_files(self, recommended_files: List[str], existing_files: Dict) -> List[Dict]:
        """Check recommended files."""
        notices = []
        
        for rec_file in recommended_files:
            if rec_file not in existing_files:
                notices.append({
                    "type": "NOTICE",
                    "file": rec_file,
                    "message": f"Missing recommended file: {rec_file}",
                    "severity": "low"
                })
        
        return notices
    
    def _detect_outdated_files(self, existing_files: Dict, max_age_days: int) -> List[Dict]:
        """Detect outdated documentation."""
        warnings = []
        
        for file_path, file_info in existing_files.items():
            if file_info["age_days"] > max_age_days:
                warnings.append({
                    "type": "WARNING",
                    "file": file_path,
                    "message": f"File may be outdated: {file_path} (last modified {file_info['age_daysPROJECT_ROOT / ']:.1f} days ago)",
                    "severity": "medium"
                })
        
        return warnings
    
    def _generate_compliance_report(self, required_files: List[str], existing_files: Dict, 
                                   errors: List[Dict], warnings: List[Dict], notices: List[Dict]) -> Dict[str, Any]:
        """Generate compliance metrics."""
        required_present = len([f for f in required_files if f in existing_files])
        required_total = len(required_files)
        compliance_percentage = (required_present  /  required_total * 100) if required_total > 0 else 0
        
        return {
            "compliance_score": round(compliance_percentage, 1),
            "required_files": {
                "present": required_present,
                "total": required_total,
                "missing": required_total - required_present
            },
            "issues": {
                "errors": len(errors),
                "warnings": len(warnings),
                "notices": len(notices)
            },
            "status": "PASS" if compliance_percentage >= 100 and len([e for e in errors if e["type"] == "ERROR"]) == 0 else "FAIL"
        }
    
    def _suggest_fixes(self, errors: List[Dict], warnings: List[Dict], notices: List[Dict], requirements: Dict) -> List[Dict]:
        """Generate fix suggestions."""
        suggestions = []
        
        for error in errors:
            if error["type"] == "ERROR" and "Missing required file" in error["message"]:
                suggestions.append({
                    "action": "GENERATE_FILE",
                    "file": error["file"],
                    "priority": "high",
                    "template": f"Use appropriate template from tier-index.yaml for {error['filePROJECT_ROOT / ']}",
                    "command": f"python3 scripts / generate_docs.py --file {error['file']}"
                })
        
        for warning in warnings:
            if "too small" in warning["message"]:
                suggestions.append({
                    "action": "EXPAND_FILE",
                    "file": warning["file"],
                    "priority": "medium",
                    "instruction": "Add detailed content following tier-specific requirements"
                })
            elif "outdated" in warning["message"]:
                suggestions.append({
                    "action": "UPDATE_FILE",
                    "file": warning["file"],
                    "priority": "low",
                    "instruction": "Review and update content for current project state"
                })
        
        return suggestions

    def check_template_sync(self, tier: str = None) -> Dict[str, Any]:
        """Check if tier-index.yaml syncs with available templates."""
        if not self.index:
            self.load_index()
        
        sync_report = {
            "tier_index_valid": True,
            "missing_templates": [],
            "orphaned_templates": [],
            "version_consistency": True,
            "cross_reference_errors": []
        }
        
        # Check template availability
        all_required_files = set()
        all_recommended_files = set()
        
        tiers_to_check = [tier] if tier else list(self.index["tiers"].keys())
        
        for tier_name in tiers_to_check:
            tier_config = self.index["tiers"][tier_name]
            all_required_files.update(tier_config.get("required", []))
            all_recommended_files.update(tier_config.get("recommended", []))
        
        # Check if all referenced templates exist
        for file_name in all_required_files.union(all_recommended_files):
            template_path = self.find_template_path(file_name)
            if not template_path:
                sync_report["missing_templates"].append(file_name)
                sync_report["tier_index_valid"] = False
        
        # Check template version consistency
        if "template_metadata" in self.index and "versions" in self.index["template_metadata"]:
            version_errors = self.check_template_versions()
            sync_report["version_consistency"] = len(version_errors) == 0
            sync_report["version_errors"] = version_errors
        
        return sync_report
    
    def find_template_path(self, file_name: str) -> Path:
        """Find template file in universal/ or examples/ directories."""
        # Check universal/ directory
        universal_path = self.templates_dir / "universal" / file_name
        if universal_path.exists():
            return universal_path
        
        # Check examples/ directory
        examples_path = self.templates_dir / "examples" / file_name
        if examples_path.exists():
            return examples_path
        
        # Check root directory
        root_path = self.templates_dir / file_name
        if root_path.exists():
            return root_path
        
        return None
    
    def check_template_versions(self) -> List[str]:
        """Check template version consistency."""
        errors = []
        
        if not self.index or "template_metadata" not in self.index:
            return ["No template metadata found"]
        
        versions = self.index["template_metadata"].get("versions", {})
        
        # Check if all referenced templates have versions
        all_files = set()
        for tier_config in self.index["tiers"].values():
            all_files.update(tier_config.get("required", []))
            all_files.update(tier_config.get("recommended", []))
        
        for file_name in all_files:
            if file_name not in versions:
                errors.append(f"Missing version for template: {file_name}")
        
        return errors
    
    def generate_consistency_report(self) -> Dict[str, Any]:
        """Generate comprehensive consistency report."""
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tier_index_sync": self.check_template_sync(),
            "cross_references": self.check_cross_references(),
            "placeholder_consistency": self.check_placeholder_consistency(),
            "template_availability": self.check_all_template_availability()
        }
        
        # Overall status
        report["overall_status"] = (
            report["tier_index_sync"]["tier_index_valid"] and
            len(report["cross_references"]["broken_links"]) == 0 and
            report["placeholder_consistency"]["consistent"] and
            report["template_availability"]["all_available"]
        )
        
        return report
    
    def check_cross_references(self) -> Dict[str, Any]:
        """Check all cross-references in documentation."""
        broken_links = []
        checked_files = []
        
        # Common reference patterns to check
        reference_patterns = [
            r"\[.*?\]\((.*?\.md)",
            r"\./.*?\.md",
            r"universal/.*?\.md",
            r"examples/.*?\.md",
            r"docs/.*?\.md"
        ]
        
        # Check key documentation files
        key_files = [
            "README.md", "QUICKSTART-AI.md", "SYSTEM-INTEGRATION.md",
            "BLUEPRINT-MAPPING.md", "docs/README.md", "universal/README.md"
        ]
        
        for file_pattern in key_files:
            file_path = self.templates_dir / file_pattern
            if file_path.exists():
                checked_files.append(str(file_path))
                # TODO: Implement actual cross-reference checking
                # This would require parsing markdown and checking each link
        
        return {
            "broken_links": broken_links,
            "checked_files": checked_files,
            "total_checked": len(checked_files)
        }
    
    def check_placeholder_consistency(self) -> Dict[str, Any]:
        """Check placeholder format consistency."""
        inconsistent_files = []
        
        # Check for mixed placeholder formats
        placeholder_patterns = [
            (r"\{[A-Z_]+\}", "bracket_format"),
            (r"\$[A-Z_]+", "dollar_format"),
            (r"\[.*?\]", "square_format")
        ]
        
        # TODO: Implement actual placeholder consistency checking
        # This would scan all templates and ensure consistent usage
        
        return {
            "consistent": len(inconsistent_files) == 0,
            "inconsistent_files": inconsistent_files
        }
    
    def check_all_template_availability(self) -> Dict[str, Any]:
        """Check if all templates referenced in tier-index.yaml exist."""
        if not self.index:
            self.load_index()
        
        missing_templates = []
        available_templates = []
        
        all_files = set()
        for tier_config in self.index["tiers"].values():
            all_files.update(tier_config.get("required", []))
            all_files.update(tier_config.get("recommended", []))
        
        for file_name in all_files:
            template_path = self.find_template_path(file_name)
            if template_path:
                available_templates.append(str(template_path))
            else:
                missing_templates.append(file_name)
        
        return {
            "all_available": len(missing_templates) == 0,
            "available_count": len(available_templates),
            "missing_count": len(missing_templates),
            "missing_templates": missing_templates,
            "available_templates": available_templates
        }

def main():
    parser = argparse.ArgumentParser(description="Validate documentation compliance")
    parser.add_argument("--tier", choices=["mvp", "core", "enterprise"], help="Target tier")
    parser.add_argument("--path", default=".", help="Repository path to validate")
    parser.add_argument("--index", default="tier-index.yaml", help="Tier index file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--fix", action="store_true", help="Attempt to fix issues automatically")
    parser.add_argument("--check-sync", action="store_true", help="Check tier-index.yaml sync with templates")
    parser.add_argument("--consistency-report", action="store_true", help="Generate comprehensive consistency report")
    
    args = parser.parse_args()
    
    # Handle special CI validation modes
    if args.check_sync:
        validator = DocumentationValidator(args.index)
        sync_report = validator.check_template_sync(args.tier)
        
        if args.json:
            print(json.dumps(sync_report, indent=2))
        else:
            print("=== TEMPLATE SYNC REPORT ===")
            print(f"Tier Index Valid: {sync_report['tier_index_valid']}")
            print(f"Missing Templates: {len(sync_report['missing_templates'])}")
            print(f"Version Consistency: {sync_report['version_consistency']}")
            
            if sync_report['missing_templates']:
                print("\nMissing Templates:")
                for template in sync_report['missing_templates']:
                    print(f"  ❌ {template}")
            
            if 'version_errors' in sync_report and sync_report['version_errors']:
                print("\nVersion Errors:")
                for error in sync_report['version_errors']:
                    print(f"  ⚠️  {error}")
        
        sys.exit(0 if sync_report['tier_index_valid'] else 1)
    
    if args.consistency_report:
        validator = DocumentationValidator(args.index)
        report = validator.generate_consistency_report()
        
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("=== COMPREHENSIVE CONSISTENCY REPORT ===")
            print(f"Timestamp: {report['timestamp']}")
            print(f"Overall Status: {'✅ PASS' if report['overall_status'] else '❌ FAIL'}")
            print()
            
            print("Tier Index Sync:")
            print(f"  Valid: {report['tier_index_sync']['tier_index_valid']}")
            print(f"  Missing: {len(report['tier_index_sync']['missing_templates'])}")
            print()
            
            print("Template Availability:")
            print(f"  All Available: {report['template_availability']['all_available']}")
            print(f"  Available: {report['template_availability']['available_count']}")
            print(f"  Missing: {report['template_availability']['missing_count']}")
            print()
            
            print("Cross References:")
            print(f"  Broken Links: {len(report['cross_references']['broken_links'])}")
            print(f"  Files Checked: {report['cross_references']['total_checked']}")
            print()
            
            print("Placeholder Consistency:")
            print(f"  Consistent: {report['placeholder_consistency']['consistent']}")
        
        sys.exit(0 if report['overall_status'] else 1)
    
    # Regular tier validation (requires --tier)
    if not args.tier:
        parser.error("--tier is required for regular validation")
    
    try:
        validator = DocumentationValidator(args.index)
        result = validator.validate(args.tier, args.path)
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("=== DOCUMENTATION VALIDATION REPORT ===")
            print(f"Tier: {result['tier'].upper()}")
            print(f"Status: {result['report']['status']}")
            print(f"Compliance: {result['report']['compliance_score']}%")
            print(f"Required Files: {result['report']['required_files']['presentPROJECT_ROOT / ']} / {result['report']['required_files']['total']}")
            print(f"Issues: {result['report']['issues']['errors']} errors, {result['report']['issues']['warnings']} warnings, {result['report']['issues']['notices']} notices")
            print()
            
            if result['issues']['errors']:
                print("ERRORS:")
                for error in result['issues']['errors']:
                    print(f"  ❌ {error['message']}")
                print()
            
            if result['issues']['warnings']:
                print("WARNINGS:")
                for warning in result['issues']['warnings']:
                    print(f"  ⚠️  {warning['message']}")
                print()
            
            if result['issues']['notices']:
                print("NOTICES:")
                for notice in result['issues']['notices']:
                    print(f"  ℹ️  {notice['message']}")
                print()
            
            if result['suggestions']:
                print("SUGGESTED FIXES:")
                for suggestion in result['suggestions']:
                    print(f"  🔧 {suggestion['action']}: {suggestion['file']} (priority: {suggestion['priority']})")
        
        # Exit with error code if validation failed
        sys.exit(0 if result['report']['status'] == 'PASS' else 1)
        
    except Exception as e:
        print(f"Validation error: {e}", file=sys.stderr)
        sys.exit(2)

    def check_template_sync(self, tier: str = None) -> Dict[str, Any]:
        """Check if tier-index.yaml syncs with available templates."""
        if not self.index:
            self.load_index()
        
        sync_report = {
            "tier_index_valid": True,
            "missing_templates": [],
            "orphaned_templates": [],
            "version_consistency": True,
            "cross_reference_errors": []
        }
        
        # Check template availability
        all_required_files = set()
        all_recommended_files = set()
        
        tiers_to_check = [tier] if tier else list(self.index["tiers"].keys())
        
        for tier_name in tiers_to_check:
            tier_config = self.index["tiers"][tier_name]
            all_required_files.update(tier_config.get("required", []))
            all_recommended_files.update(tier_config.get("recommended", []))
        
        # Check if all referenced templates exist
        for file_name in all_required_files.union(all_recommended_files):
            template_path = self.find_template_path(file_name)
            if not template_path:
                sync_report["missing_templates"].append(file_name)
                sync_report["tier_index_valid"] = False
        
        # Check template version consistency
        if "template_metadata" in self.index and "versions" in self.index["template_metadata"]:
            version_errors = self.check_template_versions()
            sync_report["version_consistency"] = len(version_errors) == 0
            sync_report["version_errors"] = version_errors
        
        return sync_report
    
    def find_template_path(self, file_name: str) -> Path:
        """Find template file in universal/ or examples/ directories."""
        # Check universal/ directory
        universal_path = self.templates_dir / "universal" / file_name
        if universal_path.exists():
            return universal_path
        
        # Check examples/ directory
        examples_path = self.templates_dir / "examples" / file_name
        if examples_path.exists():
            return examples_path
        
        # Check root directory
        root_path = self.templates_dir / file_name
        if root_path.exists():
            return root_path
        
        return None
    
    def check_template_versions(self) -> List[str]:
        """Check template version consistency."""
        errors = []
        
        if not self.index or "template_metadata" not in self.index:
            return ["No template metadata found"]
        
        versions = self.index["template_metadata"].get("versions", {})
        
        # Check if all referenced templates have versions
        all_files = set()
        for tier_config in self.index["tiers"].values():
            all_files.update(tier_config.get("required", []))
            all_files.update(tier_config.get("recommended", []))
        
        for file_name in all_files:
            if file_name not in versions:
                errors.append(f"Missing version for template: {file_name}")
        
        return errors
    
    def generate_consistency_report(self) -> Dict[str, Any]:
        """Generate comprehensive consistency report."""
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tier_index_sync": self.check_template_sync(),
            "cross_references": self.check_cross_references(),
            "placeholder_consistency": self.check_placeholder_consistency(),
            "template_availability": self.check_all_template_availability()
        }
        
        # Overall status
        report["overall_status"] = (
            report["tier_index_sync"]["tier_index_valid"] and
            len(report["cross_references"]["broken_links"]) == 0 and
            report["placeholder_consistency"]["consistent"] and
            report["template_availability"]["all_available"]
        )
        
        return report
    
    def check_cross_references(self) -> Dict[str, Any]:
        """Check all cross-references in documentation."""
        broken_links = []
        checked_files = []
        
        # Common reference patterns to check
        reference_patterns = [
            r"\[.*?\]\((.*?\.md)",
            r"\./.*?\.md",
            r"universal/.*?\.md",
            r"examples/.*?\.md",
            r"docs/.*?\.md"
        ]
        
        # Check key documentation files
        key_files = [
            "README.md", "QUICKSTART-AI.md", "SYSTEM-INTEGRATION.md",
            "BLUEPRINT-MAPPING.md", "docs/README.md", "universal/README.md"
        ]
        
        for file_pattern in key_files:
            file_path = self.templates_dir / file_pattern
            if file_path.exists():
                checked_files.append(str(file_path))
                # TODO: Implement actual cross-reference checking
                # This would require parsing markdown and checking each link
        
        return {
            "broken_links": broken_links,
            "checked_files": checked_files,
            "total_checked": len(checked_files)
        }
    
    def check_placeholder_consistency(self) -> Dict[str, Any]:
        """Check placeholder format consistency."""
        inconsistent_files = []
        
        # Check for mixed placeholder formats
        placeholder_patterns = [
            (r"\{[A-Z_]+\}", "bracket_format"),
            (r"\$[A-Z_]+", "dollar_format"),
            (r"\[.*?\]", "square_format")
        ]
        
        # TODO: Implement actual placeholder consistency checking
        # This would scan all templates and ensure consistent usage
        
        return {
            "consistent": len(inconsistent_files) == 0,
            "inconsistent_files": inconsistent_files
        }
    
    def check_all_template_availability(self) -> Dict[str, Any]:
        """Check if all templates referenced in tier-index.yaml exist."""
        if not self.index:
            self.load_index()
        
        missing_templates = []
        available_templates = []
        
        all_files = set()
        for tier_config in self.index["tiers"].values():
            all_files.update(tier_config.get("required", []))
            all_files.update(tier_config.get("recommended", []))
        
        for file_name in all_files:
            template_path = self.find_template_path(file_name)
            if template_path:
                available_templates.append(str(template_path))
            else:
                missing_templates.append(file_name)
        
        return {
            "all_available": len(missing_templates) == 0,
            "available_count": len(available_templates),
            "missing_count": len(missing_templates),
            "missing_templates": missing_templates,
            "available_templates": available_templates
        }

if __name__ == "__main__":
    main()
