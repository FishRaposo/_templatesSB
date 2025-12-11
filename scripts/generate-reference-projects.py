#!/usr/bin/env python3
"""
Batch Reference Project Generator
Purpose: Generate reference projects for all stack and tier combinations
Usage: python scripts/generate-reference-projects.py
"""

import sys
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Tuple

class ReferenceProjectGenerator:
    def __init__(self):
        self.templates_root = Path(__file__).parent.parent
        self.reference_projects_dir = self.templates_root / "reference-projects"
        
        # Define all project combinations
        self.tiers = ["mvp", "core", "enterprise"]
        self.stacks = [
            ("node", "Node.js", "Backend API Service"),
            ("react", "React", "Web Frontend Application"),
            ("flutter", "Flutter", "Mobile Application"),
            ("go", "Go", "High-performance Service"),
            ("python", "Python", "Backend Service"),
            ("react_native", "React Native", "Cross-platform Mobile"),
            ("r", "R", "Data Analysis Application")
        ]
        
        # Project descriptions for each tier
        self.descriptions = {
            "mvp": "Minimal Viable Product reference implementation",
            "core": "Production-ready reference implementation with comprehensive testing",
            "enterprise": "Enterprise-grade reference with security and scalability features"
        }
    
    def create_directory_structure(self):
        """Create the reference projects directory structure"""
        print("📁 Creating directory structure...")
        
        for tier in self.tiers:
            tier_dir = self.reference_projects_dir / tier
            tier_dir.mkdir(parents=True, exist_ok=True)
            print(f"  Created: {tier_dir}")
    
    def generate_single_project(self, tier: str, stack_key: str, stack_name: str, stack_desc: str) -> bool:
        """Generate a single reference project"""
        project_name = f"{tier}-{stack_key}-reference"
        project_desc = f"{self.descriptions[tier]} - {stack_desc}"
        
        print(f"\n🚀 Generating {tier.upper()} {stack_name.upper()} Reference Project")
        print(f"   Project: {project_name}")
        print(f"   Description: {project_desc}")
        
        # Define project directory (don't create yet - let setup script handle it)
        project_dir = self.reference_projects_dir / tier / project_name
        
        try:
            # Simplified script is non-interactive, no input needed
            
            # Run simplified setup script (no emojis, non-interactive)
            setup_script = self.templates_root / "scripts" / "setup-project-simple.py"
            cmd = [sys.executable, str(setup_script), tier, stack_key, project_name, project_desc]
            
            print(f"   Running: {' '.join(cmd)}")
            
            # Set environment variables for UTF-8 encoding
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            
            # Run setup from parent directory to prevent nesting
            parent_dir = project_dir.parent
            result = subprocess.run(
                cmd,
                text=True,
                capture_output=True,
                cwd=str(parent_dir),
                timeout=300,  # 5 minute timeout
                env=env,
                encoding='utf-8'
            )
            
            if result.returncode == 0:
                print(f"   ✅ Successfully generated {project_name}")
                return True
            else:
                print(f"   ❌ Failed to generate {project_name}")
                print(f"   Error: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"   ⏰ Timeout generating {project_name}")
            return False
        except Exception as e:
            print(f"   ❌ Exception generating {project_name}: {e}")
            return False
    
    def generate_all_projects(self) -> Dict[str, List[str]]:
        """Generate all reference projects"""
        print("🏗️  Starting batch generation of reference projects...")
        print("=" * 60)
        
        results = {
            "successful": [],
            "failed": []
        }
        
        total_projects = len(self.tiers) * len(self.stacks)
        current_project = 0
        
        for tier in self.tiers:
            print(f"\n📦 Generating {tier.upper()} tier projects...")
            print("-" * 40)
            
            for stack_key, stack_name, stack_desc in self.stacks:
                current_project += 1
                print(f"\n[{current_project}/{total_projects}] ", end="")
                
                success = self.generate_single_project(tier, stack_key, stack_name, stack_desc)
                
                if success:
                    results["successful"].append(f"{tier}/{tier}-{stack_key}-reference")
                else:
                    results["failed"].append(f"{tier}/{tier}-{stack_key}-reference")
        
        return results
    
    def verify_projects(self, results: Dict[str, List[str]]):
        """Verify generated projects"""
        print("\n🔍 Verifying generated projects...")
        print("=" * 40)
        
        for project_path in results["successful"]:
            full_path = self.reference_projects_dir / project_path
            if full_path.exists():
                # Check for expected files
                expected_files = ["README.md", "main.go", "app.js", "index.jsx", "main.dart", "main.py"]
                found_files = [f.name for f in full_path.iterdir() if f.is_file()]
                
                print(f"  ✅ {project_path}: {len(found_files)} files generated")
            else:
                print(f"  ❌ {project_path}: Directory not found")
    
    def create_index_file(self, results: Dict[str, List[str]]):
        """Create an index file for all reference projects"""
        index_file = self.reference_projects_dir / "REFERENCE-PROJECTS-INDEX.md"
        
        content = """# Reference Projects Index

> Reference implementations for all universal template combinations  
> Generated: {date}

## Overview

This directory contains reference projects generated from the universal template system. Each project demonstrates the boilerplate, testing patterns, and documentation standards for its specific tier and technology stack.

## Project Structure

```
reference-projects/
├── mvp/           # Minimal Viable Product projects
├── core/          # Production-ready projects  
└── enterprise/    # Enterprise-grade projects
```

## Generated Projects

### MVP Tier - Minimal Viable Product

""".format(date="2025-12-10")
        
        # Add MVP projects
        for stack_key, stack_name, stack_desc in self.stacks:
            project_path = f"mvp/{stack_key}-reference"
            if project_path in results["successful"]:
                content += f"- **{stack_name}**: [`{stack_key}-reference/`](mvp/{stack_key}-reference/) - {stack_desc}\n"
        
        content += """
### Core Tier - Production Ready

"""
        
        # Add Core projects
        for stack_key, stack_name, stack_desc in self.stacks:
            project_path = f"core/{stack_key}-reference"
            if project_path in results["successful"]:
                content += f"- **{stack_name}**: [`{stack_key}-reference/`](core/{stack_key}-reference/) - {stack_desc}\n"
        
        content += """
### Enterprise Tier - Enterprise Grade

"""
        
        # Add Enterprise projects
        for stack_key, stack_name, stack_desc in self.stacks:
            project_path = f"enterprise/{stack_key}-reference"
            if project_path in results["successful"]:
                content += f"- **{stack_name}**: [`{stack_key}-reference/`](enterprise/{stack_key}-reference/) - {stack_desc}\n"
        
        # Add failed projects if any
        if results["failed"]:
            content += "\n## ⚠️ Failed Generations\n\n"
            for project in results["failed"]:
                content += f"- {project}\n"
        
        content += """
## Usage

Each reference project can be used as:

1. **Learning Example**: Study the structure and patterns
2. **Starting Point**: Copy and modify for new projects
3. **Testing Ground**: Experiment with changes safely
4. **Documentation Reference**: See implemented standards

## Build Commands

### Node.js Projects
```bash
cd reference-projects/[tier]/node-reference
npm install
npm start
```

### React Projects  
```bash
cd reference-projects/[tier]/react-reference
npm install
npm start
```

### Flutter Projects
```bash
cd reference-projects/[tier]/flutter-reference
flutter pub get
flutter run
```

### Go Projects
```bash
cd reference-projects/[tier]/go-reference
go mod init reference
go run main.go
```

### Python Projects
```bash
cd reference-projects/[tier]/python-reference
pip install -r requirements.txt
python main.py
```

### React Native Projects
```bash
cd reference-projects/[tier]/react_native-reference
npm install
npx react-native run-android  # or run-ios
```

## Maintenance

To regenerate all projects:
```bash
python scripts/generate_reference_projects.py
```

To regenerate a specific project:
```bash
python scripts/setup-project.py --manual-tier [tier]
# Follow prompts to select stack and enter project name
```
"""
        
        with open(index_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"📄 Created index file: {index_file}")
    
    def print_summary(self, results: Dict[str, List[str]]):
        """Print generation summary"""
        print("\n" + "=" * 60)
        print("📊 GENERATION SUMMARY")
        print("=" * 60)
        
        total = len(results["successful"]) + len(results["failed"])
        success_rate = (len(results["successful"]) / total * 100) if total > 0 else 0
        
        print(f"Total Projects: {total}")
        print(f"Successful: {len(results['successful'])} ✅")
        print(f"Failed: {len(results['failed'])} ❌")
        print(f"Success Rate: {success_rate:.1f}%")
        
        if results["successful"]:
            print(f"\n✅ Successfully Generated:")
            for project in sorted(results["successful"]):
                print(f"  - {project}")
        
        if results["failed"]:
            print(f"\n❌ Failed to Generate:")
            for project in sorted(results["failed"]):
                print(f"  - {project}")
        
        print(f"\n📁 All projects located in: {self.reference_projects_dir}")
        print(f"📄 See index: {self.reference_projects_dir}/REFERENCE-PROJECTS-INDEX.md")

def main():
    """Main execution"""
    print("🏗️  Universal Reference Project Generator")
    print("=" * 50)
    print("This script will generate reference projects for all")
    print("combinations of tiers and technology stacks.")
    print()
    
    generator = ReferenceProjectGenerator()
    
    # Create directory structure
    generator.create_directory_structure()
    
    # Generate all projects
    results = generator.generate_all_projects()
    
    # Verify projects
    generator.verify_projects(results)
    
    # Create index file
    generator.create_index_file(results)
    
    # Print summary
    generator.print_summary(results)
    
    # Return appropriate exit code
    if results["failed"]:
        print(f"\n⚠️  {len(results['failed'])} projects failed to generate.")
        return 1
    else:
        print(f"\n🎉 All projects generated successfully!")
        return 0

if __name__ == "__main__":
    sys.exit(main())
