# VALIDATION.md - Documentation Compliance Validation System

**Purpose**: Ensures documentation matches tier-index.yaml requirements across LLM reasoning, CLI, and CI/CD contexts.  
**Version**: 1.0  
**Last Updated**: 2025-12-09  
**Design**: LLM-native + CLI-ready + CI-integrated, deterministic, generalizable  

---

## 🧠 Validation Script (LLM Reasoning Version)

### VALIDATION PASS v1.0 - Agent Protocol

**Input**:
- `tier-index.yaml` (or `docs_index.yaml` for compatibility)
- Repository file tree
- Current tier (MVP/Core/Full)
- Optional: Explicit validation rules

**Validation Steps**:

#### Step 1: Load Tier Index
```python
def load_tier_index(index_path="tier-index.yaml"):
    """
    Load and parse tier index with compatibility fallback.
    
    Returns: Dict with tier definitions and requirements
    """
    try:
        with open(index_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        # Fallback to alternative naming
        try:
            with open("docs_index.yaml", 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            raise ValidationError("Tier index file not found")
```

#### Step 2: Parse Tier Requirements
```python
def parse_tier_requirements(index, selected_tier):
    """
    Extract required, recommended, and ignored files for tier.
    
    Returns: Dict with file lists and validation rules
    """
    tier_config = index["tiers"][selected_tier.lower()]
    
    return {
        "required": tier_config.get("required", []),
        "recommended": tier_config.get("recommended", []),
        "ignored": tier_config.get("ignored", []),
        "coverage_target": tier_config.get("coverage_target", "85%+"),
        "min_file_size": tier_config.get("min_file_size", 200),
        "max_age_days": tier_config.get("max_age_days", 30)
    }
```

#### Step 3: Scan Repository
```python
def scan_repository(base_path="."):
    """
    Scan repository and catalog all documentation files.
    
    Returns: Dict with file metadata (size, age, type)
    """
    doc_files = {}
    
    for root, dirs, files in os.walk(base_path):
        # Skip hidden directories and common exclusions
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'build', 'dist']]
        
        for file in files:
            if file.endswith('.md'):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, base_path)
                
                stat = os.stat(full_path)
                doc_files[rel_path] = {
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "age_days": (time.time() - stat.st_mtime) / (24 * 3600)
                }
    
    return doc_files
```

#### Step 4: Compare Required Files
```python
def validate_required_files(required_files, existing_files, min_size=200):
    """
    Validate all required files exist and meet minimum standards.
    
    Returns: List of validation errors
    """
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
            if file_info["size"] < min_size:
                errors.append({
                    "type": "WARNING",
                    "file": req_file,
                    "message": f"Required file too small: {req_file} ({file_info['size']} < {min_size} chars)",
                    "severity": "medium"
                })
    
    return errors
```

#### Step 5: Check Recommended Files
```python
def validate_recommended_files(recommended_files, existing_files):
    """
    Check recommended files and generate notices for missing ones.
    
    Returns: List of validation notices
    """
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
```

#### Step 6: Detect Outdated Documentation
```python
def detect_outdated_files(existing_files, max_age_days=30):
    """
    Detect potentially outdated documentation based on age.
    
    Returns: List of outdated file warnings
    """
    warnings = []
    
    for file_path, file_info in existing_files.items():
        if file_info["age_days"] > max_age_days:
            warnings.append({
                "type": "WARNING",
                "file": file_path,
                "message": f"File may be outdated: {file_path} (last modified {file_info['age_days']:.1f} days ago)",
                "severity": "medium"
            })
    
    return warnings
```

#### Step 7: Generate Compliance Report
```python
def generate_compliance_report(required_files, existing_files, errors, warnings, notices):
    """
    Generate comprehensive compliance report.
    
    Returns: Dict with compliance metrics and summary
    """
    required_present = len([f for f in required_files if f in existing_files])
    required_total = len(required_files)
    compliance_percentage = (required_present / required_total * 100) if required_total > 0 else 0
    
    return {
        "compliance_score": compliance_percentage,
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
        "status": "PASS" if compliance_percentage >= 100 and len(errors) == 0 else "FAIL"
    }
```

#### Step 8: Suggest Automatic Fixes
```python
def suggest_fixes(errors, warnings, notices, tier_requirements):
    """
    Generate actionable fix suggestions for each issue.
    
    Returns: List of fix suggestions with implementation hints
    """
    suggestions = []
    
    for error in errors:
        if error["type"] == "ERROR" and "Missing required file" in error["message"]:
            suggestions.append({
                "action": "GENERATE_FILE",
                "file": error["file"],
                "priority": "high",
                "template": f"Use appropriate template from tier-index.yaml for {error['file']}",
                "command": f"python3 scripts/generate_docs.py --file {error['file']} --tier {{tier}}"
            })
    
    for warning in warnings:
        if "too small" in warning["message"]:
            suggestions.append({
                "action": "EXPAND_FILE",
                "file": warning["file"],
                "priority": "medium",
                "instruction": "Add detailed content following tier-specific requirements",
                "command": f"python3 scripts/expand_docs.py --file {warning['file']} --min-size {{min_size}}"
            })
        elif "outdated" in warning["message"]:
            suggestions.append({
                "action": "UPDATE_FILE",
                "file": warning["file"],
                "priority": "low",
                "instruction": "Review and update content for current project state",
                "command": f"python3 scripts/update_docs.py --file {warning['file']}"
            })
    
    return suggestions
```

---

## 💻 Complete Python Implementation (CLI/CI Ready)

```python
#!/usr/bin/env python3
"""
Documentation Validation Script
Validates documentation compliance against tier-index.yaml
Usage: python3 validate_docs.py --tier core [--verbose] [--json]
"""

import yaml
import os
import sys
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any

class ValidationError(Exception):
    pass

class DocumentationValidator:
    def __init__(self, index_path="tier-index.yaml"):
        self.index_path = index_path
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
            if any(exclude in str(file_path) for exclude in ['node_modules', 'build', 'dist', '.git']):
                continue
            
            rel_path = str(file_path.relative_to(base_path))
            stat = file_path.stat()
            
            doc_files[rel_path] = {
                "size": stat.st_size,
                "modified": stat.st_mtime,
                "age_days": (time.time() - stat.st_mtime) / (24 * 3600),
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
                    "message": f"File may be outdated: {file_path} (last modified {file_info['age_days']:.1f} days ago)",
                    "severity": "medium"
                })
        
        return warnings
    
    def _generate_compliance_report(self, required_files: List[str], existing_files: Dict, 
                                   errors: List[Dict], warnings: List[Dict], notices: List[Dict]) -> Dict[str, Any]:
        """Generate compliance metrics."""
        required_present = len([f for f in required_files if f in existing_files])
        required_total = len(required_files)
        compliance_percentage = (required_present / required_total * 100) if required_total > 0 else 0
        
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
            "status": "PASS" if compliance_percentage >= 100 and len(errors) == 0 else "FAIL"
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
                    "template": f"Use appropriate template from tier-index.yaml for {error['file']}",
                    "command": f"python3 scripts/generate_docs.py --file {error['file']}"
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

def main():
    parser = argparse.ArgumentParser(description="Validate documentation compliance")
    parser.add_argument("--tier", required=True, choices=["mvp", "core", "full"], help="Target tier")
    parser.add_argument("--path", default=".", help="Repository path to validate")
    parser.add_argument("--index", default="tier-index.yaml", help="Tier index file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--fix", action="store_true", help="Attempt to fix issues automatically")
    
    args = parser.parse_args()
    
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
            print(f"Required Files: {result['report']['required_files']['present']}/{result['report']['required_files']['total']}")
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

if __name__ == "__main__":
    main()
```

---

## 📊 Output Format Specification

### Human-Readable Format
```
=== DOCUMENTATION VALIDATION REPORT ===
Tier: CORE
Status: PASS
Compliance: 100.0%
Required Files: 15/15
Issues: 0 errors, 1 warnings, 2 notices

WARNINGS:
  ⚠️  File may be outdated: docs/OLD-FEATURE.md (last modified 45.2 days ago)

NOTICES:
  ℹ️  Missing recommended file: ANALYTICS.md
  ℹ️  Missing recommended file: CONFIGURATION.md

SUGGESTED FIXES:
  🔧 UPDATE_FILE: docs/OLD-FEATURE.md (priority: low)
  🔧 GENERATE_FILE: ANALYTICS.md (priority: medium)
```

### Machine-Parseable JSON Format
```json
{
  "tier": "core",
  "timestamp": 1702123456.789,
  "report": {
    "compliance_score": 100.0,
    "required_files": {
      "present": 15,
      "total": 15,
      "missing": 0
    },
    "issues": {
      "errors": 0,
      "warnings": 1,
      "notices": 2
    },
    "status": "PASS"
  },
  "issues": {
    "errors": [],
    "warnings": [
      {
        "type": "WARNING",
        "file": "docs/OLD-FEATURE.md",
        "message": "File may be outdated: docs/OLD-FEATURE.md (last modified 45.2 days ago)",
        "severity": "medium"
      }
    ],
    "notices": [
      {
        "type": "NOTICE",
        "file": "ANALYTICS.md",
        "message": "Missing recommended file: ANALYTICS.md",
        "severity": "low"
      }
    ]
  },
  "suggestions": [
    {
      "action": "UPDATE_FILE",
      "file": "docs/OLD-FEATURE.md",
      "priority": "low",
      "instruction": "Review and update content for current project state"
    }
  ],
  "requirements": {
    "required": ["README.md", "ARCHITECTURE.md", ...],
    "recommended": ["ANALYTICS.md", "CONFIGURATION.md", ...],
    "coverage_target": "85%+",
    "min_file_size": 200,
    "max_age_days": 30
  }
}
```

---

## 🚀 Usage Instructions

### For AI Agents (LLM Reasoning)
1. **Load tier-index.yaml** to get requirements
2. **Scan repository** to catalog existing files
3. **Run validation steps** to identify issues
4. **Generate compliance report** with metrics
5. **Suggest fixes** for each identified issue
6. **Report results** to human with actionable recommendations

### For CLI Usage
```bash
# Basic validation
python3 validate_docs.py --tier core

# Verbose output
python3 validate_docs.py --tier core --verbose

# JSON output for CI/CD
python3 validate_docs.py --tier core --json

# Custom index file
python3 validate_docs.py --tier core --index custom-index.yaml

# Validate specific directory
python3 validate_docs.py --tier core --path ./my-project
```

### For CI/CD Integration
```yaml
# GitHub Actions example
- name: Validate Documentation
  run: |
    python3 validate_docs.py --tier core --json > validation-report.json
    if [ $? -ne 0 ]; then
      echo "Documentation validation failed"
      cat validation-report.json
      exit 1
    fi
```

---

**Performance**: O(n) where n = number of documentation files, typically < 50.  
**Reliability**: Deterministic results, consistent across environments.  
**Integration**: Works with LLM agents, CLI tools, and CI/CD pipelines.

---

*This validation system ensures your documentation always matches tier requirements while providing actionable feedback for improvement.*
