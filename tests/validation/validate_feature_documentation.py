#!/usr/bin/env python3
"""
Feature Documentation Validation Script Template
Validates that documented features match actual API implementation
"""

import os
import sys
import ast
import re
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
import argparse


@dataclass
# Resolve project root for path consistency
PROJECT_ROOT = Path(__file__).parent.parent.parent

class EndpointInfo:
    """Information about an API endpoint"""
    path: str
    method: str
    module: str
    line_number: int
    function_name: str


@dataclass
class ValidationResult:
    """Result of validation comparison"""
    documented_endpoints: int
    actual_endpoints: int
    missing_from_docs: List[EndpointInfo]
    extra_in_docs: List[str]
    gap_percentage: float
    is_valid: bool


class APIEndpointExtractor:
    """Extracts API endpoints from [FRAMEWORK] router files"""
    
    def __init__(self, api_dir: str):
        self.api_dir = Path(api_dir)
        self.endpoints: List[EndpointInfo] = []
    
    def extract_endpoints(self) -> List[EndpointInfo]:
        """Extract all endpoints from API router files"""
        self.endpoints = []
        
        for router_file in self.api_dir.glob("*.py"):
            if router_file.name == "__init__.py":
                continue
            
            endpoints = self._extract_from_file(router_file)
            self.endpoints.extend(endpoints)
        
        return self.endpoints
    
    def _extract_from_file(self, file_path: Path) -> List[EndpointInfo]:
        """Extract endpoints from a single Python file using regex parsing"""
        endpoints = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Use regex to extract [FRAMEWORK] router endpoints
            # Pattern matches: @[ROUTER_NAME].[METHOD]("/path") or @[ROUTER_NAME].[METHOD]("/path")
            pattern = r'@[ROUTER_NAME]\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
            matches = re.finditer(pattern, content)
            
            for match in matches:
                method = match.group(1).upper()
                path = match.group(2)
                
                # Find the line number for this endpoint
                line_number = content[:match.start()].count('\n') + 1
                
                # Try to find the function name after this decorator
                function_name = "unknown"
                lines_after = content[match.start():].split('\n')
                if len(lines_after) > 1:
                    next_line = lines_after[1].strip()
                    if next_line.startswith('def '):
                        function_name = next_line[4:].split('(')[0].strip()
                
                endpoint = EndpointInfo(
                    path=path,
                    method=method,
                    module=file_path.stem,
                    line_number=line_number,
                    function_name=function_name
                )
                endpoints.append(endpoint)
        
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
        
        return endpoints


class FeatureDocumentationParser:
    """Parses feature documentation to extract documented endpoints"""
    
    def __init__(self, features_file: str):
        self.features_file = Path(features_file)
    
    def extract_documented_endpoints(self) -> Set[str]:
        """Extract documented API endpoints from [FEATURES_FILE]"""
        if not self.features_file.exists():
            print(f"Warning: {self.features_file} not found")
            return set()
        
        with open(self.features_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract API endpoint patterns
        endpoint_patterns = [
            rPROJECT_ROOT / '`GET\s+([API_PREFIX] / [^`]+)`',
            rPROJECT_ROOT / '`POST\s+([API_PREFIX] / [^`]+)`',
            rPROJECT_ROOT / '`PUT\s+([API_PREFIX] / [^`]+)`',
            rPROJECT_ROOT / '`DELETE\s+([API_PREFIX] / [^`]+)`',
            rPROJECT_ROOT / '`PATCH\s+([API_PREFIX] / [^`]+)`',
        ]
        
        documented = set()
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, content)
            documented.update(matches)
        
        return documented


class FeatureValidator:
    """Validates feature documentation against actual implementation"""
    
    def __init__(self, api_dir: str, features_file: str):
        self.extractor = APIEndpointExtractor(api_dir)
        self.parser = FeatureDocumentationParser(features_file)
    
    def validate(self) -> ValidationResult:
        """Perform validation comparison"""
        # Get actual endpoints
        actual_endpoints = self.extractor.extract_endpoints()
        actual_paths = {f"{ep.method} {ep.path}" for ep in actual_endpoints}
        
        # Get documented endpoints
        documented_endpoints = self.parser.extract_documented_endpoints()
        
        # Find missing from documentation
        missing_from_docs = [
            ep for ep in actual_endpoints 
            if f"{ep.method} {ep.path}" not in documented_endpoints
        ]
        
        # Find extra in documentation
        extra_in_docs = [
            doc for doc in documented_endpoints
            if doc not in actual_paths
        ]
        
        # Calculate gap
        documented_count = len(documented_endpoints)
        actual_count = len(actual_endpoints)
        
        if documented_count > 0:
            gap_percentage = ((documented_count - actual_count) / documented_count) * 100
        else:
            gap_percentage = 0
        
        is_valid = len(missing_from_docs) == 0 and len(extra_in_docs) == 0
        
        return ValidationResult(
            documented_endpoints=documented_count,
            actual_endpoints=actual_count,
            missing_from_docs=missing_from_docs,
            extra_in_docs=extra_in_docs,
            gap_percentage=gap_percentage,
            is_valid=is_valid
        )
    
    def generate_report(self, result: ValidationResult) -> str:
        """Generate a detailed validation report"""
        report = []
        report.append("=" * 60)
        report.append("FEATURE DOCUMENTATION VALIDATION REPORT")
        report.append("=" * 60)
        report.append("")
        
        # Summary
        report.append("📊 SUMMARY")
        report.append("-" * 20)
        report.append(f"Documented Endpoints: {result.documented_endpoints}")
        report.append(f"Actual Endpoints: {result.actual_endpoints}")
        report.append(f"Gap: {result.gap_percentage:.1f}%")
        report.append(f"Status: {'✅ VALID' if result.is_valid else '❌ INVALID'}")
        report.append("")
        
        # Missing from documentation
        if result.missing_from_docs:
            report.append("❌ MISSING FROM DOCUMENTATION")
            report.append("-" * 30)
            for endpoint in result.missing_from_docs:
                report.append(f"  {endpoint.method} {endpoint.path} ({endpoint.module}:{endpoint.line_number})")
            report.append("")
        
        # Extra in documentation
        if result.extra_in_docs:
            report.append("⚠️  EXTRA IN DOCUMENTATION")
            report.append("-" * 30)
            for endpoint in result.extra_in_docs:
                report.append(f"  {endpoint}")
            report.append("")
        
        # Module breakdown
        report.append("📋 MODULE BREAKDOWN")
        report.append("-" * 20)
        module_counts = {}
        for endpoint in self.extractor.endpoints:
            module_counts[endpoint.module] = module_counts.get(endpoint.module, 0) + 1
        
        for module, count in sorted(module_counts.items()):
            report.append(f"  {module}: {count} endpoints")
        report.append("")
        
        # Recommendations
        report.append("💡 RECOMMENDATIONS")
        report.append("-" * 20)
        
        if result.missing_from_docs:
            report.append("• Update [FEATURES_FILE] to include missing endpoints")
            report.append("• Add endpoint descriptions and implementation status")
        
        if result.extra_in_docs:
            report.append("• Remove or implement extra documented endpoints")
            report.append("• Update test coverage to match actual implementation")
        
        if result.gap_percentage > [GAP_THRESHOLD]:
            report.append("• Consider updating completion percentage in [FEATURES_FILE]")
            report.append("• Review test coverage vs implementation gap")
        
        if result.is_valid:
            report.append("• Documentation is up to date! 🎉")
        
        report.append("")
        report.append("=" * 60)
        
        return "\n".join(report)
    
    def update_documentation_gap(self, result: ValidationResult):
        """Update the gap section in [FEATURES_FILE]"""
        features_file = self.parser.features_file
        
        if not features_file.exists():
            print(f"Features file {features_file} not found")
            return
        
        with open(features_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Update the gap section
        gap_section = f"""### Test Coverage vs Implementation Gap

**Critical Discovery**: There is a significant gap between documented features and actual implementation.

| Metric | Documented | Actually Implemented | Gap |
|--------|------------|---------------------|-----|
| **API Endpoints** | {result.documented_endpoints} (comprehensive tests) | {result.actual_endpoints} (actual routers) | {result.documented_endpoints - result.actual_endpoints} |
| **Test Coverage** | [DOCUMENTED_COVERAGE]% (comprehensive test suite) | {result.actual_endpoints/result.documented_endpoints*100:.1f}% (current implementation) | {[DOCUMENTED_COVERAGE] - (result.actual_endpoints/result.documented_endpoints*100):.1f}% |
| **Feature Completion** | [DOCUMENTED_COMPLETION]% (documented) | {result.actual_endpoints/result.documented_endpoints*100:.1f}% (actual endpoints) | {[DOCUMENTED_COMPLETION] - (result.actual_endpoints/result.documented_endpoints*100):.1f}% |

**Actual API Endpoint Audit:**
"""
        
        # Add module breakdown
        module_counts = {}
        for endpoint in self.extractor.endpoints:
            module_counts[endpoint.module] = module_counts.get(endpoint.module, 0) + 1
        
        for module, count in sorted(module_counts.items()):
            gap_section += f"- **{module}.py**: {count} endpoints\n"
        
        gap_section += f"""
**Total: {result.actual_endpoints} actual endpoints vs {result.documented_endpoints} endpoints assumed in comprehensive tests**

**Honest Completion Status**: {result.actual_endpoints/result.documented_endpoints*100:.1f}% ({result.actual_endpoints}/{result.documented_endpoints} endpoints)"""
        
        # Replace existing gap section
        pattern = r'### Test Coverage vs Implementation Gap.*?(?=###|\Z)'
        new_content = re.sub(pattern, gap_section, content, flags=re.DOTALL)
        
        with open(features_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"Updated {features_file} with current implementation gap")


def main():
    """Main validation function"""
    parser = argparse.ArgumentParser(description="Validate feature documentation against API implementation")
    parser.add_argument("--api-dir", default="[API_DIR]", help="API directory path")
    parser.add_argument("--features-file", default="[FEATURES_FILE]", help="Features documentation file")
    parser.add_argument("--update", action="store_true", help="Update documentation with current gap")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--threshold", type=float, default=[GAP_THRESHOLD], help="Gap threshold for validation failure (use 80 for MVP, 50 for production)")
    
    args = parser.parse_args()
    
    # Initialize validator
    validator = FeatureValidator(args.api_dir, args.features_file)
    
    # Perform validation
    result = validator.validate()
    
    # Generate report
    report = validator.generate_report(result)
    
    if args.json:
        # Output JSON for CI/CD
        json_result = {
            "documented_endpoints": result.documented_endpoints,
            "actual_endpoints": result.actual_endpoints,
            "gap_percentage": result.gap_percentage,
            "is_valid": result.is_valid and result.gap_percentage <= args.threshold,
            "missing_count": len(result.missing_from_docs),
            "extra_count": len(result.extra_in_docs),
            "threshold_met": result.gap_percentage <= args.threshold
        }
        print(json.dumps(json_result, indent=2))
    else:
        # Output human-readable report
        print(report)
    
    # Update documentation if requested
    if args.update:
        validator.update_documentation_gap(result)
        print(f"Updated {args.features_file} with current implementation gap")
    
    # Exit with appropriate code
    # Fail if invalid OR if gap exceeds threshold
    should_fail = not result.is_valid or result.gap_percentage > args.threshold
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()
