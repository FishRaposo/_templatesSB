#!/usr/bin/env python3
"""
Template Consistency Audit Script
Verifies parity across all stacks, tiers, and tasks
"""

import os
import yaml
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Resolve project root for path consistency
PROJECT_ROOT = Path(__file__).parent.parent.parent

class TemplateConsistencyAuditor:
    def __init__(self):
        self.templates_root = Path(__file__).parent.parent
        self.issues = []
        self.warnings = []
        
    def audit_reference_projects(self):
        """Audit reference project consistency across all stacks and tiers"""
        print("🔍 Auditing Reference Project Consistency")
        print("=" * 60)
        
        stacks = ['flutter', 'react_native', 'react', 'node', 'go', 'python', 'r', 'sql', 'generic', 'typescript']
        tiers = ['mvp', 'core', 'enterprise']
        
        # Expected files by stack
        expected_files = {
            'flutter': ['main.dart', 'widget_test.dart', 'pubspec.yaml', 'README.md'],
            'react_native': ['App.jsx', 'App.test.jsx', 'package.json', 'README.md'],
            'react': ['src/App.jsx', 'src/App.test.jsx', 'App.css', 'package.json', 'README.md'],
            'node': ['app.js', 'app.test.js', 'package.json', 'README.md'],
            'go': ['main.go', 'main_test.go', 'go.mod', 'README.md'],
            'python': ['app.py', 'test_main.py', 'requirements.txt', 'README.md'],
            'r': ['main.R', 'tests/testthat.R', 'README.md'],
            'sql': ['schema.sql', 'queries.sql', 'README.md']
        }
        
        consistency_report = {}
        
        for stack in stacks:
            consistency_report[stack] = {}
            for tier in tiers:
                project_path = self.templates_root / PROJECT_ROOT / 'reference-projects' / tier / f'{tier}-{stack}-reference'
                
                if not project_path.exists():
                    self.issues.append(f"Missing project: {stack}/{tier}")
                    continue
                
                # Check expected files
                expected = expected_files.get(stack, [])
                actual_files = []
                
                for file_path in project_path.rglob('*'):
                    if file_path.is_file():
                        rel_path = file_path.relative_to(project_path)
                        actual_files.append(str(rel_path))
                
                # Check for missing expected files
                missing_files = []
                for expected_file in expected:
                    normalized_expected = expected_file.replace('\\', '/')
                    found = False
                    for actual_file in actual_files:
                        normalized_actual = actual_file.replace('\\', '/')
                        if normalized_actual == normalized_expected:
                            found = True
                            break
                    if not found:
                        missing_files.append(expected_file)
                
                # Check for unexpected files (ignore runtime artifacts)
                unexpected_files = []
                ignore_patterns = ['__pycache__', '.pytest_cache', '.git', '.DS_Store', '*.pyc', 'node_modules', 'coverage', '.dart_tool', 'pubspec.lock', 'package-lock.json']
                
                for actual_file in actual_files:
                    should_ignore = False
                    for pattern in ignore_patterns:
                        if pattern.replace('*', '') in actual_file:
                            should_ignore = True
                            break
                    
                    # Normalize path separators for comparison
                    normalized_file = actual_file.replace('\\', '/')
                    if not should_ignore and normalized_file not in expected and not normalized_file.startswith('.env'):
                        unexpected_files.append(actual_file)
                
                consistency_report[stack][tier] = {
                    'missing_files': missing_files,
                    'unexpected_files': unexpected_files,
                    'total_files': len(actual_files)
                }
                
                if missing_files:
                    self.issues.append(f"{stack}/{tier}: Missing expected files: {missing_files}")
                
                if unexpected_files:
                    self.warnings.append(f"{stack}/{tier}: Unexpected files: {unexpected_files}")
        
        return consistency_report
    
    def audit_readme_consistency(self):
        """Audit README.md consistency across reference projects"""
        print("\n📚 Auditing README.md Consistency")
        print("=" * 60)
        
        stacks = ['flutter', 'react_native', 'react', 'node', 'go', 'python', 'r', 'sql', 'generic', 'typescript']
        tiers = ['mvp', 'core', 'enterprise']
        
        readme_issues = []
        
        for stack in stacks:
            for tier in tiers:
                readme_path = self.templates_root / PROJECT_ROOT / 'reference-projects' / tier / f'{tier}-{stack}-reference' / 'README.md'
                
                if not readme_path.exists():
                    continue
                
                content = readme_path.read_text(encoding='utf-8')
                
                # Check for required sections
                required_sections = ['## Overview', '## Features', '## Setup', '## Testing']
                missing_sections = []
                
                for section in required_sections:
                    if section not in content:
                        missing_sections.append(section)
                
                if missing_sections:
                    readme_issues.append(f"{stack}/{tier}: Missing sections: {missing_sections}")
                
                # Check for tier-appropriate content
                if tier not in content.lower():
                    readme_issues.append(f"{stack}/{tier}: README doesn't mention tier '{tier}'")
        
        return readme_issues
    
    def audit_task_templates(self):
        """Audit task template consistency"""
        print("\n🛠️  Auditing Task Template Consistency")
        print("=" * 60)
        
        tasks_dir = self.templates_root / PROJECT_ROOT / 'tasks'
        task_template_issues = []
        
        if not tasks_dir.exists():
            self.issues.append("Tasks directory not found")
            return task_template_issues
        
        # Check each task directory
        for task_dir in tasks_dir.iterdir():
            if not task_dir.is_dir() or task_dir.name.startswith('.') or task_dir.name.endswith('.yaml'):
                continue
            
            # Check for universal templates
            universal_dir = task_dir / 'universal'
            if not universal_dir.exists():
                task_template_issues.append(f"{task_dir.name}: Missing universal templates")
                continue
            
            # Check for stack-specific templates
            stacks_dir = task_dir / PROJECT_ROOT / 'stacks'
            if stacks_dir.exists():
                available_stacks = [d.name for d in stacks_dir.iterdir() if d.is_dir()]
                
                # Verify each stack has required template files
                for stack in available_stacks:
                    stack_dir = stacks_dir / stack
                    if not any(stack_dir.iterdir()):
                        task_template_issues.append(f"{task_dir.name}/{stack}: Empty stack directory")
        
        return task_template_issues
    
    def audit_dependency_files(self):
        """Audit dependency file consistency"""
        print("\n📦 Auditing Dependency File Consistency")
        print("=" * 60)
        
        dependency_issues = []
        
        # Check package.json consistency for Node/React stacks
        npm_stacks = ['react_native', 'react', 'node']
        for stack in npm_stacks:
            for tier in ['mvp', 'core', 'enterprise']:
                package_json_path = self.templates_root / PROJECT_ROOT / 'reference-projects' / tier / f'{tier}-{stack}-reference' / 'package.json'
                
                if package_json_path.exists():
                    try:
                        content = package_json_path.read_text()
                        package_data = yaml.safe_load(content)
                        
                        # Check for required fields
                        required_fields = ['name', 'version', 'scripts']
                        missing_fields = []
                        
                        for field in required_fields:
                            if field not in package_data:
                                missing_fields.append(field)
                        
                        if missing_fields:
                            dependency_issues.append(f"{stack}/{tier}: package.json missing fields: {missing_fields}")
                    
                    except Exception as e:
                        dependency_issues.append(f"{stack}/{tier}: Invalid package.json: {e}")
        
        return dependency_issues
    
    def audit_test_file_consistency(self):
        """Audit test file naming and structure consistency"""
        print("\n🧪 Auditing Test File Consistency")
        print("=" * 60)
        
        test_issues = []
        
        expected_test_files = {
            'flutter': 'widget_test.dart',
            'react_native': 'App.test.jsx',
            'react': 'src/App.test.jsx',
            'node': 'app.test.js',
            'go': 'main_test.go',
            'python': 'test_main.py',
            'r': 'tests/testthat.R',
            'sql': None  # SQL doesn't have traditional test files
        }
        
        for stack, test_file in expected_test_files.items():
            if test_file is None:
                continue
                
            for tier in ['mvp', 'core', 'enterprise']:
                test_path = self.templates_root / PROJECT_ROOT / 'reference-projects' / tier / f'{tier}-{stack}-reference' / test_file
                
                if not test_path.exists():
                    test_issues.append(f"{stack}/{tier}: Missing test file {test_file}")
        
        return test_issues
    
    def run_full_audit(self):
        """Run comprehensive consistency audit"""
        print("🔍 COMPREHENSIVE TEMPLATE CONSISTENCY AUDIT")
        print("=" * 80)
        
        # Run all audits
        reference_report = self.audit_reference_projects()
        readme_issues = self.audit_readme_consistency()
        task_issues = self.audit_task_templates()
        dependency_issues = self.audit_dependency_files()
        test_issues = self.audit_test_file_consistency()
        
        # Consolidate all issues
        all_issues = (
            self.issues + 
            readme_issues + 
            task_issues + 
            dependency_issues + 
            test_issues
        )
        
        # Generate summary report
        print("\n📊 AUDIT SUMMARY")
        print("=" * 80)
        
        print(f"🔴 Critical Issues: {len(all_issues)}")
        print(f"🟡 Warnings: {len(self.warnings)}")
        
        if all_issues:
            print("\n🔴 CRITICAL ISSUES FOUND:")
            for i, issue in enumerate(all_issues, 1):
                print(f"  {i}. {issue}")
        
        if self.warnings:
            print("\n🟡 WARNINGS:")
            for i, warning in enumerate(self.warnings, 1):
                print(f"  {i}. {warning}")
        
        if not all_issues and not self.warnings:
            print("\n✅ No consistency issues found!")
        
        # Save detailed report
        report_path = self.templates_root / 'consistency_audit_report.md'
        self.generate_detailed_report(reference_report, all_issues, self.warnings, report_path)
        
        print(f"\n📄 Detailed report saved to: {report_path}")
        
        return len(all_issues), len(self.warnings)
    
    def generate_detailed_report(self, reference_report, issues, warnings, report_path):
        """Generate detailed markdown report"""
        report_content = f"""# Template Consistency Audit Report

Generated: {Path(__file__).name}

## Summary
- Critical Issues: {len(issues)}
- Warnings: {len(warnings)}

## Reference Project Analysis

### File Structure Consistency
"""
        
        for stack, tiers in reference_report.items():
            report_content += f"\n#### {stack.title()}\n"
            for tier, data in tiers.items():
                report_content += f"\n**{tier.title()} Tier:**\n"
                if data['missing_files']:
                    report_content += f"- Missing files: {data['missing_files']}\n"
                if data['unexpected_files']:
                    report_content += f"- Unexpected files: {data['unexpected_files']}\n"
                report_content += f"- Total files: {data['total_files']}\n"
        
        if issues:
            report_content += "\n## Critical Issues\n\n"
            for i, issue in enumerate(issues, 1):
                report_content += f"{i}. {issue}\n"
        
        if warnings:
            report_content += "\n## Warnings\n\n"
            for i, warning in enumerate(warnings, 1):
                report_content += f"{i}. {warning}\n"
        
        report_path.write_text(report_content)

if __name__ == "__main__":
    auditor = TemplateConsistencyAuditor()
    issues, warnings = auditor.run_full_audit()
    
    # Exit with error code if critical issues found
    if issues > 0:
        exit(1)
    else:
        exit(0)
