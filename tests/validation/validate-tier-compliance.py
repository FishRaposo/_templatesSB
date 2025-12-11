#!/usr/bin/env python3
"""
Tier Compliance Validation Script
Purpose: Validate projects against their tier requirements (MVP/Core/Enterprise)
Usage: python scripts/validate-tier-compliance.py --tier [mvp|core|enterprise] --project-path [path]
"""

import sys
import os
import re
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Set
from datetime import datetime

# Resolve project root for path consistency
PROJECT_ROOT = Path(__file__).parent.parent.parent

class TierValidator:
    def __init__(self, project_path: Path, target_tier: str):
        self.project_path = project_path
        self.target_tier = target_tier.lower()
        self.issues = []
        self.warnings = []
        self.stats = {
            "total_files": 0,
            "test_files": 0,
            "coverage_percentage": 0,
            "required_patterns_found": [],
            "forbidden_patterns_found": [],
            "tier_compliance": False
        }
        
        # Language-specific refined patterns with context anchors
        self.language_patterns = {
            "go": {
                "mocking": [
                    r"mock\.|Mock\(|mockgen\s+",
                    r"type\s+\w+\s+interface",
                    r"//go:generate\s+mock"
                ],
                "enterprise": [
                    r"import.*enterprise",
                    r"enterprise\.|Enterprise\(",
                    r"observability|circuit.*breaker",
                    r"jwt.*middleware|audit.*log"
                ],
                "security": [
                    r"crypto/jwt|bcrypt\.|crypto/aes",
                    r"middleware.*auth|security\.|validator\."
                ]
            },
            "python": {
                "mocking": [
                    r"import.*unittest\.mock|from.*unittest.*mock",
                    r"@mock\.patch|mock\.Mock\(|MagicMock\(",
                    r"pytest\.mock|unittest\.mock"
                ],
                "enterprise": [
                    r"import.*enterprise|from.*enterprise",
                    r"circuit_breaker|observability|prometheus",
                    r"audit.*log|logging\.audit"
                ],
                "security": [
                    r"import.*jwt|import.*bcrypt|import.*cryptography",
                    r"hashlib\.|secrets\.|ssl\."
                ]
            },
            "javascript": {
                "mocking": [
                    r"jest\.fn\(|jest\.mock\(|vi\.fn\(|vi\.mock\(",
                    r"sinon\.|mockito\.",
                    r"require.*jest|import.*jest"
                ],
                "enterprise": [
                    r"import.*enterprise|require.*enterprise",
                    r"circuit.*breaker|opentelemetry|prometheus",
                    r"audit.*log|winston\.audit"
                ],
                "security": [
                    r"import.*jsonwebtoken|require.*jsonwebtoken",
                    r"import.*bcrypt|require.*bcrypt",
                    r"crypto\.|helmet\(|cors\("
                ]
            },
            "typescript": {
                "mocking": [
                    r"jest\.fn\(|jest\.mock\(|vi\.fn\(|vi\.mock\(",
                    r"sinon\.|mockito\.",
                    r"import.*jest|from.*jest"
                ],
                "enterprise": [
                    r"import.*enterprise|from.*enterprise",
                    r"circuit.*breaker|opentelemetry|prometheus",
                    r"audit.*log|winston\.audit"
                ],
                "security": [
                    r"import.*jsonwebtoken|from.*jsonwebtoken",
                    r"import.*bcrypt|from.*bcrypt",
                    r"crypto\.|helmet\(|cors\("
                ]
            },
            "dart": {
                "mocking": [
                    r"import.*mockito|from.*mockito",
                    r"Mock\(|Fake\(|when\(|verify\(",
                    r"t\.mock\(|testApi\.mock"
                ],
                "enterprise": [
                    r"import.*enterprise|package:enterprise",
                    r"circuit.*breaker|observability|opentelemetry",
                    r"audit.*log|logging.*audit"
                ],
                "security": [
                    r"import.*dart:crypto|package:crypto",
                    r"import.*jwt|package:jwt",
                    r"Hash\.|Encrypter|Signer"
                ]
            }
        }
        
        # Tier requirements with refined patterns
        self.tier_requirements = {
            "mvp": {
                "coverage_threshold": 70,
                "required_patterns": [
                    r"func Test|def test_|test\(|describe\(",
                    r"package.*test|import.*testing",
                    r"testing\.T|unittest\.TestCase|it\("
                ],
                "forbidden_patterns": [
                    r"enterprise|Enterprise",
                    r"observability|Observability",
                    r"circuit.*breaker|CircuitBreaker",
                    r"jwt.*middleware|JWT.*Middleware",
                    r"audit.*log|AuditLog"
                ],
                "required_test_types": ["unit"],
                "forbidden_test_types": ["security", "compliance", "resilience"]
            },
            "core": {
                "coverage_threshold": 85,
                "required_patterns": [
                    r"func Test|def test_|test\(|describe\(",
                    r"func TestIntegration|def test_integration|integration.*test",
                    r"func TestFeature|def test_feature|feature.*test",
                    r"package.*test|import.*testing",
                    r"testing\.T|unittest\.TestCase|it\("
                ],
                "forbidden_patterns": [
                    r"enterprise.*only|EnterpriseOnly",
                    r"hipaa|gdpr|soc2|HIPAA|GDPR|SOC2",
                    r"penetration.*test|pen.*test"
                ],
                "required_test_types": ["unit", "integration", "feature"],
                "forbidden_test_types": ["compliance", "penetration"]
            },
            "enterprise": {
                "coverage_threshold": 90,
                "required_patterns": [
                    r"func Test|def test_|test\(|describe\(",
                    r"func TestIntegration|def test_integration|integration.*test",
                    r"func TestFeature|def test_feature|feature.*test",
                    r"func TestSecurity|def test_security|security.*test",
                    r"func TestCompliance|def test_compliance|compliance.*test",
                    r"func TestResilience|def test_resilience|resilience.*test",
                    r"package.*test|import.*testing",
                    r"testing\.T|unittest\.TestCase|it\("
                ],
                "forbidden_patterns": [
                    r"TODO.*test|FIXME.*test|todo.*test|fixme.*test",
                    r"skip.*test|Skip.*test|\.Skip\("
                ],
                "required_test_types": ["unit", "integration", "feature", "security", "compliance", "resilience"],
                "forbidden_test_types": []
            }
        }
    
    def log_issue(self, severity: str, message: str, file_path: str = None):
        """Log an issue with the validation"""
        issue_data = {
            "severity": severity,
            "message": message,
            "file": str(file_path) if file_path else None,
            "timestamp": datetime.now().isoformat()
        }
        
        if severity == "error":
            self.issues.append(issue_data)
        else:
            self.warnings.append(issue_data)
        
        print(f"{severity.upper()}: {message}")
        if file_path:
            print(f"  File: {file_path}")
    
    def detect_project_tier(self) -> str:
        """Detect project tier from configuration file (mandatory)"""
        config_files = [
            self.project_path / "tier-config.yaml",
            self.project_path / ".tier",
            self.project_path / "tier.json"
        ]
        
        for config_file in config_files:
            if config_file.exists():
                try:
                    if config_file.suffix in ['.yaml', '.yml']:
                        with open(config_file, 'r', encoding='utf-8') as f:
                            import yaml
                            config = yaml.safe_load(f)
                            return config.get('project', {}).get('tier', '').lower()
                    elif config_file.suffix == '.json':
                        with open(config_file, 'r', encoding='utf-8') as f:
                            import json
                            config = json.load(f)
                            return config.get('tier', '').lower()
                    else:  # .tier file
                        with open(config_file, 'r', encoding='utf-8') as f:
                            return f.read().strip().lower()
                except Exception as e:
                    self.log_issue("error", f"Failed to read tier config {config_file}: {e}")
        
        self.log_issue("error", "No tier configuration found. Please create tier-config.yaml, .tier, or tier.json file")
        return "unknown"
        """Detect the primary programming language of the project"""
        language_counts = {
            "go": 0,
            "python": 0,
            "javascript": 0,
            "typescript": 0,
            "dart": 0,
            "java": 0
        }
        
        for file_path in self.project_path.rglob("*"):
            if file_path.is_file():
                if file_path.suffix == ".go":
                    language_counts["go"] += 1
                elif file_path.suffix == ".py":
                    language_counts["python"] += 1
                elif file_path.suffix == ".js":
                    language_counts["javascript"] += 1
                elif file_path.suffix == ".ts":
                    language_counts["typescript"] += 1
                elif file_path.suffix == ".dart":
                    language_counts["dart"] += 1
                elif file_path.suffix == ".java":
                    language_counts["java"] += 1
        
        # Return the language with the most files
        if not language_counts or max(language_counts.values()) == 0:
            return "unknown"
        
        return max(language_counts, key=language_counts.get)
    
    def get_test_coverage(self) -> float:
        """Get test coverage percentage for the project"""
        language = self.detect_project_language()
        
        try:
            if language == "go":
                # Go coverage
                result = subprocess.run(
                    ["go", "test", "-cover", "./..."],
                    cwd=self.project_path,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                # Parse coverage from output
                coverage_match = re.search(r"coverage:\s+(\d+\.\d+)%", result.stdout)
                if coverage_match:
                    return float(coverage_match.group(1))
            
            elif language == "python":
                # Python coverage with pytest-cov
                result = subprocess.run(
                    ["python", "-m", "pytest", "--cov", "--cov-report=term-missing"],
                    cwd=self.project_path,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                # Parse coverage from output
                coverage_match = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", result.stdout)
                if coverage_match:
                    return float(coverage_match.group(1))
            
            elif language in ["javascript", "typescript"]:
                # Node.js coverage with jest
                result = subprocess.run(
                    ["npm", "test", "--", "--coverage"],
                    cwd=self.project_path,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                # Parse coverage from output
                coverage_match = re.search(r"All files\s+\|\s+(\d+)", result.stdout)
                if coverage_match:
                    return float(coverage_match.group(1))
            
            elif language == "dart":
                # Flutter/Dart coverage
                result = subprocess.run(
                    ["flutter", "test", "--coverage"],
                    cwd=self.project_path,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                # Parse coverage from lcov file
                lcov_file = self.project_path / "coverage" / "lcov.info"
                if lcov_file.exists():
                    # Simple coverage calculation from lcov
                    with open(lcov_file, 'rPROJECT_ROOT / ') as f:
                        content = f.read()
                        lines_found = len(re.findall(r"LF:\d+", content))
                        lines_hit = len(re.findall(r"LH:\d+", content))
                        if lines_found > 0:
                            return (lines_hit  /  lines_found) * 100
            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        return 0.0
    
    def validate_patterns(self) -> bool:
        """Validate required and forbidden patterns for the tier"""
        requirements = self.tier_requirements.get(self.target_tier, {})
        test_files = list(self.project_path.rglob("*test*"))
        
        if not test_files:
            self.log_issue("error", f"No test files found for {self.target_tier} tier")
            return False
        
        all_test_content = ""
        for test_file in test_files:
            if test_file.is_file() and test_file.suffix in ['.go', '.py', '.js', '.ts', '.dart']:
                try:
                    with open(test_file, 'r', encoding='utf-8') as f:
                        all_test_content += f.read() + "\n"
                except Exception:
                    continue
        
        # Check required patterns
        required_patterns = requirements.get("required_patterns", [])
        for pattern in required_patterns:
            if re.search(pattern, all_test_content, re.IGNORECASE):
                self.stats["required_patterns_found"].append(pattern)
            else:
                self.log_issue("error", f"Required pattern missing: {pattern}")
        
        # Check forbidden patterns
        forbidden_patterns = requirements.get("forbidden_patterns", [])
        for pattern in forbidden_patterns:
            if re.search(pattern, all_test_content, re.IGNORECASE):
                self.stats["forbidden_patterns_found"].append(pattern)
                self.log_issue("error", f"Forbidden pattern found: {pattern}")
        
        return len(self.stats["forbidden_patterns_found"]) == 0
    
    def validate_test_types(self) -> bool:
        """Validate required test types for the tier"""
        requirements = self.tier_requirements.get(self.target_tier, {})
        test_files = list(self.project_path.rglob("*test*"))
        
        found_test_types = set()
        
        for test_file in test_files:
            if test_file.is_file():
                try:
                    with open(test_file, 'r', encoding='utf-8') as f:
                        content = f.read().lower()
                    
                    # Detect test types based on patterns
                    if "unit" in content or "test" in content:
                        found_test_types.add("unit")
                    if "integration" in content:
                        found_test_types.add("integration")
                    if "feature" in content:
                        found_test_types.add("feature")
                    if "security" in content:
                        found_test_types.add("security")
                    if "compliance" in content:
                        found_test_types.add("compliance")
                    if "resilience" in content:
                        found_test_types.add("resilience")
                
                except Exception:
                    continue
        
        required_test_types = set(requirements.get("required_test_types", []))
        missing_test_types = required_test_types - found_test_types
        
        for test_type in missing_test_types:
            self.log_issue("error", f"Required test type missing: {test_type}")
        
        forbidden_test_types = set(requirements.get("forbidden_test_types", []))
        found_forbidden = found_test_types & forbidden_test_types
        
        for test_type in found_forbidden:
            self.log_issue("error", f"Forbidden test type found: {test_type}")
        
        return len(missing_test_types) == 0 and len(found_forbidden) == 0
    
    def validate_coverage(self) -> bool:
        """Validate test coverage meets tier threshold"""
        coverage = self.get_test_coverage()
        self.stats["coverage_percentage"] = coverage
        
        threshold = self.tier_requirements.get(self.target_tier, {}).get("coverage_threshold", 0)
        
        if coverage < threshold:
            self.log_issue("error", f"Coverage {coverage:.1f}% below {self.target_tier} tier threshold of {threshold}%")
            return False
        
        print(f"✅ Coverage {coverage:.1f}% meets {self.target_tier} tier threshold of {threshold}%")
        return True
    
    def validate_tier_compliance(self) -> bool:
        """Main validation function"""
        print(f"🔍 Validating {self.target_tier.upper()} tier compliance...")
        print(f"📁 Project path: {self.project_path}")
        print("-" * 50)
        
        if self.target_tier not in self.tier_requirements:
            self.log_issue("error", f"Unknown tier: {self.target_tier}. Valid tiers: mvp, core, enterprise")
            return False
        
        # Run all validations
        coverage_valid = self.validate_coverage()
        patterns_valid = self.validate_patterns()
        test_types_valid = self.validate_test_types()
        
        # Overall compliance
        self.stats["tier_compliance"] = coverage_valid and patterns_valid and test_types_valid
        
        return self.stats["tier_compliance"]
    
    def generate_report(self) -> Dict:
        """Generate compliance report"""
        return {
            "tier": self.target_tier,
            "project_path": str(self.project_path),
            "timestamp": datetime.now().isoformat(),
            "compliance": self.stats["tier_compliance"],
            "coverage": self.stats["coverage_percentage"],
            "required_patterns_found": self.stats["required_patterns_found"],
            "forbidden_patterns_found": self.stats["forbidden_patterns_found"],
            "issues": self.issues,
            "warnings": self.warnings,
            "stats": self.stats
        }

def main():
    if len(sys.argv) < 3:
        print("Usage: python scripts / validate-tier-compliance.py --tier [mvp|core|enterprise] --project-path [path] [--dry-run]")
        sys.exit(1)
    
    tier = None
    project_path = None
    dry_run = False
    
    for i, arg in enumerate(sys.argv):
        if arg == "--tier" and i + 1 < len(sys.argv):
            tier = sys.argv[i + 1]
        elif arg == "--project-path" and i + 1 < len(sys.argv):
            project_path = sys.argv[i + 1]
        elif arg == "--dry-run":
            dry_run = True
    
    if not tier or not project_path:
        print("Error: Both --tier and --project-path are required")
        sys.exit(1)
    
    validator = TierValidator(Path(project_path), tier)
    
    if dry_run:
        print("🔍 DRY RUN MODE - Reporting pattern matches without failing validation")
        print("=" * 60)
    
    compliance = validator.validate_tier_compliance()
    
    print("\n" + "=" * 50)
    print("📊 TIER COMPLIANCE SUMMARY")
    print("=" * 50)
    print(f"Tier: {tier.upper()}")
    print(f"Project: {project_path}")
    print(f"Coverage: {validator.stats['coverage_percentage']:.1f}%")
    print(f"Mode: {'DRY RUN (no failures)' if dry_run else 'VALIDATION'}")
    print(f"Compliance: {'✅ PASS' if compliance else '❌ FAIL'}")
    print(f"Issues: {len(validator.issues)}")
    print(f"Warnings: {len(validator.warnings)}")
    
    if dry_run:
        print("\n📋 Pattern Detection Results:")
        print(f"Required patterns found: {len(validator.stats['required_patterns_found'])}")
        for pattern in validator.stats['required_patterns_found']:
            print(f"  ✅ {pattern}")
        
        print(f"Forbidden patterns found: {len(validator.stats['forbidden_patterns_found'])}")
        for pattern in validator.stats['forbidden_patterns_foundPROJECT_ROOT / ']:
            print(f"  ❌ {pattern}")
        
        print("\n💡 Dry run completed - Review pattern matches above before enabling validation")
    
    # Save report
    report = validator.generate_report()
    report_file = Path(project_path)  /  f"tier-compliance-report-{tier}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Report saved to: {report_file}")
    
    # Always succeed in dry-run mode
    sys.exit(0 if dry_run or compliance else 1)

if __name__ == "__main__":
    main()
