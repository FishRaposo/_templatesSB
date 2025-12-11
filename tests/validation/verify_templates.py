#!/usr/bin/env python3
"""
Template Verification Script
Validates all Tier 1 templates for completeness, formatting, and registration
"""

import os
import yaml
import re
from pathlib import Path

# Resolve project root for path consistency
PROJECT_ROOT = Path(__file__).parent.parent.parent

class TemplateVerifier:
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent
        self.tier_index_path = self.templates_dir / "tier-index.yaml"
        self.issues = []
        self.expected_templates = {
            'flutter': ['README', 'PACKAGE-MANAGEMENT', 'PERFORMANCE', 'ERROR-HANDLING'],
            'python': ['README', 'PERFORMANCE', 'ERROR-HANDLING'],  # Already had PACKAGE-MANAGEMENT
            'node': ['README', 'PERFORMANCE', 'ERROR-HANDLING'],    # Already had PACKAGE-MANAGEMENT
            'react': ['README', 'PACKAGE-MANAGEMENT', 'PERFORMANCE', 'ERROR-HANDLING'],
            'react_native': ['README', 'PACKAGE-MANAGEMENT', 'PERFORMANCE', 'ERROR-HANDLING'],
            'go': ['README', 'PACKAGE-MANAGEMENT', 'PERFORMANCE']  # Already had ERROR-HANDLING
        }
        
    def load_tier_index(self):
        """Load tier-index.yaml"""
        try:
            with open(self.tier_index_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.issues.append(f"Failed to load tier-index.yaml: {e}")
            return None
    
    def verify_file_exists(self, file_path):
        """Check if template file exists"""
        full_path = self.templates_dir / file_path
        if not full_path.exists():
            self.issues.append(f"Missing file: {file_path}")
            return False
        return True
    
    def verify_file_size(self, file_path, min_size=10000):
        """Check if template file has reasonable size"""
        full_path = self.templates_dir / file_path
        if full_path.stat().st_size < min_size:
            self.issues.append(f"File too small ({full_path.stat().st_size} bytes): {file_path}")
            return False
        return True
    
    def verify_template_structure(self, file_path, template_name):
        """Verify template has proper structure and placeholders"""
        full_path = self.templates_dir / file_path
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            self.issues.append(f"Failed to read {file_path}: {e}")
            return False
        
        # Check for title
        if not re.search(r'^# .+', content, re.MULTILINE):
            self.issues.append(f"Missing title in {file_path}")
        
        # Check for placeholders based on template type
        placeholders = {
            'README': [r'\[PROJECT_NAME\]', r'\[VERSION\]', r'\[DATE\]'],
            'PACKAGE-MANAGEMENT': [r'\[VERSION\]', r'\[DATE\]'],
            'PERFORMANCE': [r'\[VERSION\]', r'\[DATE\]'],
            'ERROR-HANDLING': [r'\[VERSION\]', r'\[DATE\]']
        }
        
        for placeholder in placeholders.get(template_name, []):
            if not re.search(placeholder, content):
                self.issues.append(f"Missing placeholder {placeholder} in {file_path}")
        
        # Check for sections
        required_sections = {
            'README': ['## 🚀', '## 📋', '## 🛠️'],
            'PACKAGE-MANAGEMENT': ['## 📦', '## 🚀', '## 📋'],
            'PERFORMANCE': ['## 🚀', '## 📊', '## 🛠️'],
            'ERROR-HANDLING': ['## 🚨', '## 📊', '## 🛡️']
        }
        
        for section in required_sections.get(template_name, []):
            if section not in content:
                self.issues.append(f"Missing section {section} in {file_path}")
        
        return True
    
    def verify_tier_index_registration(self):
        """Verify all templates are registered in tier-index.yaml"""
        tier_index = self.load_tier_index()
        if not tier_index:
            return False
        
        stack_patterns = tier_index.get('stack_patterns', {})
        
        for stack, templates in self.expected_templates.items():
            stack_config = stack_patterns.get(stack, {})
            base_docs = stack_config.get('base', {}).get('docs', [])
            
            registered_files = [doc.get('file', '') for doc in base_docs]
            
            for template in templates:
                template_file = f"{template}.tpl.md"
                if template_file not in registered_files:
                    self.issues.append(f"Template {template_file} not registered for {stack}")
        
        return True
    
    def verify_all_templates(self):
        """Run all verification checks"""
        print("🔍 Verifying Tier 1 Templates...")
        print("=" * 50)
        
        # Check each stack's templates
        total_templates = 0
        verified_templates = 0
        
        for stack, templates in self.expected_templates.items():
            print(f"\n📱 Checking {stack} stack...")
            
            for template in templates:
                total_templates += 1
                file_path = f"stacks/{stack}/base/docs/{template}.tpl.md"
                
                print(f"  📄 {template}.tpl.md", end="")
                
                if self.verify_file_exists(file_path):
                    if self.verify_file_size(file_path):
                        if self.verify_template_structure(file_path, template):
                            print(" ✅")
                            verified_templates += 1
                        else:
                            print(" ⚠️ (structure issues)")
                    else:
                        print(" ⚠️ (too small)")
                else:
                    print(" ❌ (missing)")
        
        # Verify tier-index registration
        print(f"\n📋 Checking tier-index.yaml registration...")
        if self.verify_tier_index_registration():
            print("  ✅ All templates registered")
        else:
            print("  ❌ Registration issues found")
        
        # Summary
        print("\n" + "=" * 50)
        print(f"📊 SUMMARY: {verified_templates}/{total_templates} templates verified")
        
        if self.issues:
            print(f"\n⚠️  ISSUES FOUND ({len(self.issues)}):")
            for i, issue in enumerate(self.issues, 1):
                print(f"  {i}. {issue}")
            return False
        else:
            print("\n✅ All templates verified successfully!")
            return True
    
    def create_template_report(self):
        """Create a detailed report of all templates"""
        print("\n📋 TEMPLATE REPORT")
        print("=" * 50)
        
        total_files = 0
        total_size = 0
        
        for stack, templates in self.expected_templates.items():
            print(f"\n📱 {stack.upper()} STACK:")
            
            stack_total = 0
            stack_size = 0
            
            for template in templates:
                file_path = self.templates_dir / f"stacks/{stack}/base/docs/{template}.tpl.md"
                
                if file_path.exists():
                    size = file_path.stat().st_size
                    stack_total += 1
                    stack_size += size
                    total_files += 1
                    total_size += size
                    
                    print(f"  ✅ {template}.tpl.md ({size:,} bytes)")
                else:
                    print(f"  ❌ {template}.tpl.md (missing)")
            
            print(f"  📊 Stack total: {stack_total} files, {stack_size:,} bytes")
        
        print(f"\n📊 OVERALL TOTAL: {total_files} files, {total_size:,} bytes")
        print(f"📈 Average file size: {total_size // total_files:,} bytes")

if __name__ == "__main__":
    verifier = TemplateVerifier()
    success = verifier.verify_all_templates()
    verifier.create_template_report()
    
    exit(0 if success else 1)
