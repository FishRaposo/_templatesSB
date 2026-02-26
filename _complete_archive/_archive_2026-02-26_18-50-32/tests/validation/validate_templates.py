#!/usr/bin/env python3
"""
Comprehensive Template Validation System

Validates all 46 task templates for:
1. Structure completeness - required files and directories
2. Content quality - placeholder consistency and syntax
3. File mapping accuracy - task-index.yaml vs actual files
4. Integration compatibility - resolver and detection system
5. Metadata consistency - task descriptions and categories

Usage:
    python scripts/validate_templates.py --full
    python scripts/validate_templates.py --structure
    python scripts/validate_templates.py --content
    python scripts/validate_templates.py --integration
    python scripts/validate_templates.py --task web-scraping
"""

import argparse
import yaml
import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional
from collections import defaultdict
import re
import subprocess

# Resolve project root for path consistency
PROJECT_ROOT = Path(__file__).parent.parent.parent

class TemplateValidator:
    """Comprehensive template validation system"""
    
    def __init__(self):
        self.templates_dir = PROJECT_ROOT
        self.tasks_dir = PROJECT_ROOT / "tasks"
        self.task_index_path = PROJECT_ROOT / "tasks" / "task-index.yaml"
        
        # Load task index
        with open(self.task_index_path, 'r', encoding='utf-8') as f:
            self.task_index = yaml.safe_load(f)
        
        self.tasks = self.task_index.get('tasks', {})
        
        # Validation results
        self.issues = {
            "structure": [],
            "content": [],
            "mappings": [],
            "integration": [],
            "metadata": []
        }
        
        self.stats = {
            "total_tasks": len(self.tasks),
            "validated_tasks": 0,
            "tasks_with_issues": 0,
            "total_files": 0,
            "missing_files": 0,
            "invalid_yaml": 0
        }
    
    def validate_all(self, detailed: bool = False) -> Dict[str, Any]:
        """Run comprehensive validation of all templates"""
        print("🔍 Starting comprehensive template validation...")
        print("=" * 60)
        
        # Step 1: Structure validation
        print("📁 Validating template structure...")
        self._validate_structure()
        
        # Step 2: Content validation
        print("📝 Validating template content...")
        self._validate_content()
        
        # Step 3: File mapping validation
        print("🗺️  Validating file mappings...")
        self._validate_file_mappings()
        
        # Step 4: Integration validation
        print("🔗 Validating integration compatibility...")
        self._validate_integration()
        
        # Step 5: Metadata validation
        print("📋 Validating metadata consistency...")
        self._validate_metadata()
        
        # Generate report
        report = self._generate_validation_report(detailed)
        
        return report
    
    def _validate_structure(self):
        """Validate directory structure and required files"""
        required_files = {
            "universal/code/CONFIG.tpl.yaml",
            "universal/code/SKELETON.tpl.md"
        }
        
        for task_id, task_data in self.tasks.items():
            task_dir = self.tasks_dir / task_id
            
            if not task_dir.exists():
                self.issues["structure"].append(f"{task_id}: Task directory missing")
                continue
            
            # Check required subdirectories
            required_dirs = ["universal", "stacks"]
            for dir_name in required_dirs:
                dir_path = task_dir / dir_name
                if not dir_path.exists():
                    self.issues["structure"].append(f"{task_id}: Missing {dir_name}/ directory")
            
            # Check universal template structure
            universal_dir = task_dir / "universal"
            if universal_dir.exists():
                code_dir = universal_dir / "code"
                if not code_dir.exists():
                    self.issues["structure"].append(f"{task_id}: Missing universal/code/ directory")
                else:
                    # Check for required template files
                    template_files = list(code_dir.glob("*.tpl.*"))
                    if not template_files:
                        self.issues["structure"].append(f"{task_id}: No template files in universal/code/")
                    else:
                        self.stats["total_files"] += len(template_files)
                        
                        # Check for CONFIG file
                        config_file = code_dir / "CONFIG.tpl.yaml"
                        if not config_file.exists():
                            self.issues["structure"].append(f"{task_id}: Missing CONFIG.tpl.yaml")
            
            # Check stack implementations
            stacks_dir = task_dir / "stacks"
            if stacks_dir.exists():
                stack_dirs = [d for d in stacks_dir.iterdir() if d.is_dir()]
                
                # Check if task is "agnostic" - may not need stack implementations
                allowed_stacks = task_data.get('allowed_stacks', [])
                is_agnostic = 'agnostic' in allowed_stacks or len(allowed_stacks) == 0
                
                if not stack_dirs and not is_agnostic:
                    self.issues["structure"].append(f"{task_id}: No stack implementations found")
                elif stack_dirs and is_agnostic:
                    # Agnostic task shouldn't have stack-specific implementations
                    pass  # This is actually fine
            
            self.stats["validated_tasks"] += 1
    
    def _validate_content(self):
        """Validate template content quality and consistency"""
        placeholder_patterns = [
            r'\{\{PROJECT_NAME\}\}',
            r'\{\{STACK\}\}',
            # Note: TIER and DESCRIPTION are not required in CONFIG files
        ]
        
        jinja_patterns = [
            r'\{\%\s*if\s+.*?\s*\%\}',
            r'\{\%\s*elif\s+.*?\s*\%\}',
            r'\{\%\s*else\s*\%\}',
            r'\{\%\s*endif\s*\%\}'
        ]
        
        for task_id, task_data in self.tasks.items():
            task_dir = self.tasks_dir / task_id
            universal_code_dir = task_dir / "universal" / "code"
            
            if not universal_code_dir.exists():
                continue
            
            # Validate each template file
            for template_file in universal_code_dir.glob("*.tpl.*"):
                try:
                    content = template_file.read_text(encoding='utf-8')
                    
                    # Check for empty files
                    if len(content.strip()) < 50:
                        self.issues["content"].append(f"{task_id}: {template_file.name} appears empty or minimal")
                    
                    # Skip YAML syntax validation for .tpl.yaml files (they contain Jinja2)
                    if template_file.suffix in ['.yaml', '.yml'] and '.tpl.' not in template_file.name:
                        try:
                            yaml.safe_load(content)
                        except yaml.YAMLError as e:
                            self.issues["content"].append(f"{task_id}: {template_file.name} invalid YAML: {str(e)[:50]}")
                            self.stats["invalid_yaml"] += 1
                    
                    # Check placeholder consistency for CONFIG files
                    if template_file.name == "CONFIG.tpl.yaml":
                        missing_placeholders = []
                        for pattern in placeholder_patterns:
                            if not re.search(pattern, content):
                                missing_placeholders.append(pattern.replace(r'\{\{', '').replace(r'\}\}', ''))
                        
                        # Only check for PROJECT_NAME and STACK placeholders in CONFIG files
                        required_missing = [p for p in missing_placeholders if p in ['PROJECT_NAME', 'STACK']]
                        if required_missing:
                            self.issues["content"].append(f"{task_id}: {template_file.name} missing required placeholders: {', '.join(required_missing)}")
                    
                    # Check template syntax (Jinja2 tags)
                    if_tags = re.findall(r'\{\%\s*if\s+.*?\s*\%\}', content)
                    endif_tags = re.findall(r'\{\%\s*endif\s*\%\}', content)
                    
                    if len(if_tags) != len(endif_tags):
                        self.issues["content"].append(f"{task_id}: {template_file.name} unmatched Jinja2 if / endif tags")
                    
                    # Check for obvious template errors
                    if '{{' in content and '}}' not in content:
                        self.issues["content"].append(f"{task_id}: {template_file.name} has unclosed template placeholders")
                    
                    if '}}' in content and '{{' not in content:
                        self.issues["content"].append(f"{task_id}: {template_file.name} has orphaned template closures")
                
                except Exception as e:
                    self.issues["content"].append(f"{task_id}: {template_file.name} read error: {str(e)[:50]}")
    
    def _validate_file_mappings(self):
        """Validate file mappings in task-index.yaml against actual files"""
        for task_id, task_data in self.tasks.items():
            files = task_data.get('files', [])
            
            if not files:
                self.issues["mappings"].append(f"{task_id}: No file mappings defined")
                continue
            
            file_ids = set()
            for file_mapping in files:
                file_id = file_mapping.get('id', '')
                universal_template = file_mapping.get('universal_template', 'PROJECT_ROOT / ')
                
                # Check for duplicate IDs
                if file_id in file_ids:
                    self.issues["mappings"].append(f"{task_id}: Duplicate file ID: {file_id}")
                file_ids.add(file_id)
                
                # Check if template file exists
                if universal_template:
                    template_path = self.templates_dir  /  universal_template
                    if not template_path.exists():
                        self.issues["mappings"].append(f"{task_id}: Template file missing: {universal_template}")
                        self.stats["missing_files"] += 1
                
                # Check merge behavior
                merge_behavior = file_mapping.get('merge_behavior', '')
                if merge_behavior not in ['create', 'append', 'replace', '']:
                    self.issues["mappings"].append(f"{task_id}: Invalid merge behavior: {merge_behavior}")
                
                # Check target path format
                target_path = file_mapping.get('target_path', '')
                if not target_path:
                    self.issues["mappings"].append(f"{task_id}: Missing target path for {file_id}")
                elif '\\' in target_path:
                    self.issues["mappings"].append(f"{task_id}: Target path uses backslashes: {target_path}")
    
    def _validate_integration(self):
        """Validate integration with detection and resolver systems"""
        # Test task detection system
        try:
            import sys
            sys.path.insert(0, str(PROJECT_ROOT / 'scripts'))
            from detect_project_tasks import TaskDetectionSystem
            
            detector = TaskDetectionSystem()
            
            # Test with sample descriptions
            test_cases = [
                ("web scraping", ["web-scraping"]),
                ("user authentication", ["auth-basic", "auth-oauth"]),
                ("rest api", ["rest-api-service"]),
                ("data analytics", ["analytics-event-pipeline", "data-exploration-report"])
            ]
            
            for description, expected_tasks in test_cases:
                try:
                    matched_tasks, gaps, stack_rec = detector.analyze_requirements(description, suggest_stacks=False)
                    
                    detected_ids = [task.task_id for task in matched_tasks]
                    missing_expected = [t for t in expected_tasks if t not in detected_ids]
                    
                    if missing_expected:
                        self.issues["integration"].append(f"Detection: '{description}' should detect {missing_expected}")
                
                except Exception as e:
                    self.issues["integration"].append(f"Detection error for '{description}': {str(e)[:50]}")
        
        except ImportError:
            self.issues["integration"].append("Task detection system not available")
        
        # Test resolver script availability
        resolver_script = self.templates_dir / "scripts" / "resolve_project.py"
        if not resolver_script.exists():
            self.issues["integration"].append("Resolver script not found")
        else:
            # Test resolver help
            try:
                result = subprocess.run([
                    sys.executable, str(resolver_script), "--help"
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode != 0:
                    self.issues["integration"].append("Resolver script help command failed")
            except Exception as e:
                self.issues["integration"].append(f"Resolver script test failed: {str(e)[:50]}")
    
    def _validate_metadata(self):
        """Validate metadata consistency across tasks"""
        required_fields = ['description', 'categories', 'allowed_stacks']
        valid_categories = {
            'data-ingestion', 'automation', 'web', 'api', 'backend', 'crud',
            'graphql', 'frontend', 'dashboard', 'analytics', 'marketing',
            'security', 'infrastructure', 'auth', 'users', 'integration',
            'billing', 'saas', 'teams', 'permissions', 'background',
            'queue', 'scheduling', 'communication', 'notifications',
            'webhooks', 'files', 'processing', 'pipeline', 'data-processing',
            'etl', 'events', 'data', 'data-science', 'reporting',
            'forecasting', 'ml', 'segmentation', 'testing', 'statistics',
            'search', 'vectors', 'seo', 'research', 'auditing', 'analysis',
            'tracking', 'content', 'generation', 'email', 'monitoring',
            'links', 'scaffold', 'productivity', 'admin', 'management',
            'ui', 'features', 'flags', 'multitenancy', 'architecture',
            'audit', 'logging', 'devops', 'health', 'ci', 'config',
            '12factor', 'deployment', 'reliability', 'ai', 'llm',
            'routing', 'rag', 'retrieval', 'agents', 'orchestration',
            'refactoring', 'development', 'meta', 'bootstrap', 'tooling',
            'docs', 'site', 'documentation'
        }
        valid_stacks = {'python', 'node', 'go', 'react', 'react_native', 'nextjs', 'flutter', 'sql', 'r', 'agnostic', 'generic', 'typescript'}
        
        for task_id, task_data in self.tasks.items():
            # Check required fields
            for field in required_fields:
                if field not in task_data or not task_data[field]:
                    self.issues["metadata"].append(f"{task_id}: Missing or empty {field}")
            
            # Check description quality
            description = task_data.get('description', '')
            if len(description) < 10:
                self.issues["metadata"].append(f"{task_id}: Description too short")
            elif len(description) > 200:
                self.issues["metadata"].append(f"{task_id}: Description too long")
            
            # Check categories
            categories = task_data.get('categories', [])
            if not categories:
                self.issues["metadata"].append(f"{task_id}: No categories defined")
            else:
                invalid_cats = [cat for cat in categories if cat not in valid_categories]
                if invalid_cats:
                    self.issues["metadata"].append(f"{task_id}: Invalid categories: {invalid_cats}")
            
            # Check stacks
            allowed_stacks = task_data.get('allowed_stacks', [])
            if not allowed_stacks:
                self.issues["metadata"].append(f"{task_id}: No allowed stacks defined")
            else:
                invalid_stacks = [stack for stack in allowed_stacks if stack not in valid_stacks]
                if invalid_stacks:
                    self.issues["metadata"].append(f"{task_id}: Invalid stacks: {invalid_stacks}")
            
            # Check default stacks are subset of allowed
            default_stacks = task_data.get('default_stacks', [])
            if default_stacks:
                invalid_defaults = [stack for stack in default_stacks if stack not in allowed_stacks]
                if invalid_defaults:
                    self.issues["metadata"].append(f"{task_id}: Default stacks not in allowed: {invalid_defaults}")
    
    def _generate_validation_report(self, detailed: bool = False) -> Dict[str, Any]:
        """Generate comprehensive validation report"""
        total_issues = sum(len(issues) for issues in self.issues.values())
        self.stats["tasks_with_issues"] = len(set(
            issue.split(':')[0] for issues in self.issues.values() for issue in issues
        ))
        
        print(f"\n📊 VALIDATION SUMMARY")
        print("=" * 40)
        print(f"Total tasks: {self.stats['total_tasks']}")
        print(f"Validated tasks: {self.stats['validated_tasks']}")
        print(f"Tasks with issues: {self.stats['tasks_with_issues']}")
        print(f"Total template files: {self.stats['total_files']}")
        print(f"Missing files: {self.stats['missing_files']}")
        print(f"Invalid YAML files: {self.stats['invalid_yaml']}")
        print(f"Total issues found: {total_issues}")
        
        print(f"\n🔍 ISSUES BY CATEGORY:")
        for category, issues in self.issues.items():
            if issues:
                print(f"  {category}: {len(issues)} issues")
                if detailed:
                    for issue in issues[:5]:  # Show first 5
                        print(f"    - {issue}")
                    if len(issues) > 5:
                        print(f"    ... and {len(issues) - 5} more")
        
        # Overall health assessment
        if total_issues == 0:
            health = "EXCELLENT"
            status = "✅ All templates are in perfect condition"
        elif total_issues < 10:
            health = "GOOD"
            status = "✅ Templates are healthy with minor issues"
        elif total_issues < 50:
            health = "FAIR"
            status = "⚠️  Templates need some attention"
        else:
            health = "POOR"
            status = "❌ Templates require significant fixes"
        
        print(f"\n🎯 OVERALL HEALTH: {health}")
        print(f"   {status}")
        
        return {
            "timestamp": str(Path(__file__).stat().st_mtime),
            "stats": self.stats,
            "issues": self.issues,
            "total_issues": total_issues,
            "health_assessment": health,
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on issues"""
        recommendations = []
        
        if self.issues["structure"]:
            recommendations.append("Fix missing directories and template files using scaffolding script")
        
        if self.issues["content"]:
            recommendations.append("Review and fix template content, YAML syntax, and placeholders")
        
        if self.issues["mappings"]:
            recommendations.append("Update task-index.yaml file mappings to match actual template files")
        
        if self.issues["integration"]:
            recommendations.append("Fix integration issues with detection and resolver systems")
        
        if self.issues["metadata"]:
            recommendations.append("Standardize task metadata, categories, and stack definitions")
        
        if not recommendations:
            recommendations.append("Templates are in excellent condition - maintain current quality")
        
        return recommendations

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Comprehensive Template Validation")
    parser.add_argument("--full", action="store_true", help="Run full validation")
    parser.add_argument("--structure", action="store_true", help="Validate structure only")
    parser.add_argument("--content", action="store_true", help="Validate content only")
    parser.add_argument("--mappings", action="store_true", help="Validate file mappings only")
    parser.add_argument("--integration", action="store_true", help="Validate integration only")
    parser.add_argument("--metadata", action="store_true", help="Validate metadata only")
    parser.add_argument("--task", help="Validate specific task only")
    parser.add_argument("--detailed", action="store_true", help="Show detailed issue listings")
    parser.add_argument("--report", help="Save validation report to file")
    
    args = parser.parse_args()
    
    validator = TemplateValidator()
    
    if args.task:
        print(f"🔍 Validating specific task: {args.task}")
        # Validate single task (implementation needed)
        pass
    elif args.full or not any([args.structure, args.content, args.mappings, args.integration, args.metadata]):
        # Run full validation
        report = validator.validate_all(args.detailed)
    else:
        # Run specific validations
        if args.structure:
            print("📁 Validating template structure...")
            validator._validate_structure()
        if args.content:
            print("📝 Validating template content...")
            validator._validate_content()
        if args.mappings:
            print("🗺️  Validating file mappings...")
            validator._validate_file_mappings()
        if args.integration:
            print("🔗 Validating integration compatibility...")
            validator._validate_integration()
        if args.metadata:
            print("📋 Validating metadata consistency...")
            validator._validate_metadata()
        
        report = validator._generate_validation_report(args.detailed)
    
    # Save report if requested
    if args.report:
        with open(args.report, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n📄 Validation report saved: {args.report}")

if __name__ == "__main__":
    main()
