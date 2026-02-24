#!/usr/bin/env python3
"""
Auto Setup Script
Purpose: Automated project setup with command-line options
Usage: python scripts/auto-setup.py --tier mvp --stack flutter
"""

import sys
import os
import json
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Optional
from stack_config import get_all_stacks

class AutoSetup:
    def __init__(self):
        self.templates_root = Path(__file__).parent.parent
        
    def validate_template_exists(self, tier: str, stack: str, template_type: str) -> bool:
        """Validate that the specified template exists"""
        template_patterns = {
            "code": {
                "flutter": "minimal-boilerplate-flutter.tpl.dart",
                "react_native": "minimal-boilerplate-react_native.tpl.jsx", 
                "react": "minimal-boilerplate-react.tpl.jsx",
                "node": "minimal-boilerplate-node.tpl.js",
                "python": "minimal-boilerplate-python.tpl.py",
                "go": "minimal-boilerplate-go.tpl.go"
            },
            "tests": {
                "flutter": "basic-tests-flutter.tpl.dart",
                "react_native": "basic-tests-react_native.tpl.jsx",
                "react": "basic-tests-react.tpl.jsx", 
                "node": "basic-tests-node.tpl.js",
                "python": "basic-tests-python.tpl.py",
                "go": "basic-tests-go.tpl.go"
            }
        }
        
        if tier == "core":
            template_patterns["code"] = {
                "flutter": "production-boilerplate-flutter.tpl.dart",
                "react_native": "production-boilerplate-react_native.tpl.jsx",
                "react": "production-boilerplate-react.tpl.jsx",
                "node": "production-boilerplate-node.tpl.js", 
                "python": "production-boilerplate-python.tpl.py",
                "go": "production-boilerplate-go.tpl.go"
            }
            template_patterns["tests"] = {
                "flutter": "comprehensive-tests-flutter.tpl.dart",
                "react_native": "comprehensive-tests-react_native.tpl.jsx",
                "react": "comprehensive-tests-react.tpl.jsx",
                "node": "comprehensive-tests-node.tpl.js",
                "python": "comprehensive-tests-python.tpl.py", 
                "go": "comprehensive-tests-go.tpl.go"
            }
        elif tier == "enterprise":
            template_patterns["code"] = {
                "flutter": "enterprise-boilerplate-flutter.tpl.dart",
                "react_native": "enterprise-boilerplate-react_native.tpl.jsx",
                "react": "enterprise-boilerplate-react.tpl.jsx",
                "node": "enterprise-boilerplate-node.tpl.js",
                "python": "enterprise-boilerplate-python.tpl.py",
                "go": "enterprise-boilerplate-go.tpl.go"
            }
            template_patterns["tests"] = {
                "flutter": "enterprise-tests-flutter.tpl.dart",
                "react_native": "enterprise-tests-react_native.tpl.jsx", 
                "react": "enterprise-tests-react.tpl.jsx",
                "node": "enterprise-tests-node.tpl.js",
                "python": "enterprise-tests-python.tpl.py",
                "go": "enterprise-tests-go.tpl.go"
            }
        
        template_file = template_patterns.get(template_type, {}).get(stack)
        if not template_file:
            return False
            
        template_path = self.templates_root / "tiers" / tier / template_type / template_file
        return template_path.exists()
    
    def validate_all_templates(self, tier: str, stack: str) -> bool:
        """Validate that all required templates exist"""
        required_templates = ["code", "tests"]
        
        for template_type in required_templates:
            if not self.validate_template_exists(tier, stack, template_type):
                print(f"❌ Missing template: {tier}/{template_type} for {stack}")
                return False
        
        print(f"✅ All templates validated for {tier}/{stack}")
        return True
    
    def detect_tier_from_project(self) -> Optional[str]:
        """Automatically detect tier based on current project analysis"""
        current_dir = Path.cwd()
        
        # Analyze project characteristics
        indicators = {
            "enterprise": 0,
            "core": 0, 
            "mvp": 0
        }
        
        # Check for enterprise indicators
        enterprise_files = ["docker-compose.yml", "k8s/", ".github/workflows/", "security/", "compliance/"]
        for pattern in enterprise_files:
            if (current_dir / pattern).exists() or any(current_dir.glob(pattern)):
                indicators["enterprise"] += 2
                indicators["core"] += 1
        
        # Check for production indicators  
        production_files = ["package.json", "requirements.txt", "go.mod", "pubspec.yaml", "Dockerfile"]
        for file in production_files:
            if (current_dir / file).exists():
                indicators["core"] += 2
                indicators["mvp"] += 1
        
        # Check for basic indicators
        if any(current_dir.glob("*.js")) or any(current_dir.glob("*.py")) or any(current_dir.glob("*.go")) or any(current_dir.glob("*.dart")):
            indicators["mvp"] += 1
        
        # Check directory structure complexity
        dirs = [d for d in current_dir.iterdir() if d.is_dir()]
        if len(dirs) > 5:
            indicators["enterprise"] += 1
        elif len(dirs) > 2:
            indicators["core"] += 1
        else:
            indicators["mvp"] += 1
        
        # Determine tier
        recommended_tier = max(indicators, key=indicators.get)
        if indicators[recommended_tier] == 0:
            return "core"  # Default fallback
        
        return recommended_tier
    
    def setup_project(self, tier: str, stack: str, project_name: str = "my-project", config_file: Optional[str] = None):
        """Setup project with specified tier and stack"""
        print(f"🚀 Auto Setup: {tier.upper()} {stack.upper()}")
        print("=" * 50)
        
        # Validate templates exist
        if not self.validate_all_templates(tier, stack):
            print("❌ Template validation failed. Cannot proceed with setup.")
            return False
        
        # Load configuration if provided
        config = {}
        if config_file and Path(config_file).exists():
            with open(config_file, 'r') as f:
                config = json.load(f)
            print(f"📄 Loaded configuration from {config_file}")
        
        # Create project directory
        project_dir = Path.cwd() / project_name
        if project_dir.exists():
            print(f"⚠️  Directory '{project_name}' already exists.")
            response = input("Overwrite? (y/N): ")
            if response.lower() != 'y':
                print("Setup cancelled.")
                return False
            import shutil
            shutil.rmtree(project_dir)
        
        project_dir.mkdir()
        os.chdir(project_dir)
        print(f"📁 Created project: {project_dir}")
        
        # Execute setup commands
        try:
            success = self.execute_setup_commands(tier, stack, config)
            if success:
                print("\n✅ Setup completed successfully!")
                print(f"📂 Project location: {project_dir}")
                print(f"🎯 Tier: {tier.upper()}")
                print(f"🔧 Stack: {stack.upper()}")
                return True
            else:
                print("❌ Setup failed during execution.")
                return False
        except Exception as e:
            print(f"❌ Setup error: {e}")
            return False
    
    def execute_setup_commands(self, tier: str, stack: str, config: Dict) -> bool:
        """Execute setup commands for the specified tier and stack"""
        # Import setup functionality from setup-project.py
        sys.path.append(str(Path(__file__).parent))
        try:
            from setup_project import ProjectSetup
            
            setup = ProjectSetup()
            commands = setup.get_setup_commands(tier, stack)
            
            for step, cmd_list in commands.items():
                print(f"\n🔨 {step}")
                for cmd in cmd_list:
                    print(f"   $ {cmd}")
                    try:
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                        if result.returncode != 0:
                            print(f"   ❌ Error: {result.stderr.strip()}")
                            return False
                        else:
                            print("   ✅ Done")
                    except subprocess.TimeoutExpired:
                        print("   ⏱️  Command timed out")
                        return False
                    except Exception as e:
                        print(f"   ❌ Error: {e}")
                        return False
            
            return True
            
        except ImportError as e:
            print(f"❌ Cannot import setup functionality: {e}")
            return False
    
    def list_available_options(self):
        """List all available tier and stack combinations"""
        print("📋 Available Setup Options:")
        print("=" * 30)
        
        tiers = ["mvp", "core", "enterprise"]
        stacks = get_all_stacks()
        
        for tier in tiers:
            print(f"\n{tier.upper()} Tier:")
            for stack in stacks:
                if self.validate_all_templates(tier, stack):
                    print(f"  ✅ {stack}")
                else:
                    print(f"  ❌ {stack} (templates missing)")
    
    def create_sample_config(self, output_file: str = "setup-config.json"):
        """Create a sample configuration file"""
        sample_config = {
            "project_name": "my-awesome-project",
            "description": "An awesome project built with universal templates",
            "tier": "core",
            "stack": "react",
            "features": {
                "authentication": True,
                "database": True,
                "api": True,
                "testing": True
            },
            "custom_dependencies": [],
            "environment_variables": {
                "NODE_ENV": "development",
                "PORT": "3000"
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(sample_config, f, indent=2)
        
        print(f"📄 Sample configuration created: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Automated project setup")
    parser.add_argument("--tier", choices=["mvp", "core", "enterprise"], help="Target tier")
    parser.add_argument("--stack", choices=["flutter", "react_native", "react", "node", "python", "go"], help="Technology stack")
    parser.add_argument("--project", default="my-project", help="Project name")
    parser.add_argument("--detect", action="store_true", help="Auto-detect tier from current project")
    parser.add_argument("--config", help="Configuration file")
    parser.add_argument("--list", action="store_true", help="List available options")
    parser.add_argument("--create-config", help="Create sample configuration file")
    parser.add_argument("--validate", action="store_true", help="Validate template availability")
    
    args = parser.parse_args()
    
    auto_setup = AutoSetup()
    
    try:
        if args.list:
            auto_setup.list_available_options()
        elif args.create_config:
            auto_setup.create_sample_config(args.create_config)
        elif args.validate:
            if args.tier and args.stack:
                auto_setup.validate_all_templates(args.tier, args.stack)
            else:
                print("❌ --validate requires --tier and --stack")
        elif args.detect:
            tier = auto_setup.detect_tier_from_project()
            if tier:
                print(f"🎯 Detected tier: {tier.upper()}")
                print(f"💡 Run: python scripts/auto-setup.py --tier {tier} --stack <your-stack>")
            else:
                print("❌ Could not detect tier. Use --tier to specify manually.")
        elif args.tier and args.stack:
            success = auto_setup.setup_project(args.tier, args.stack, args.project, args.config)
            sys.exit(0 if success else 1)
        else:
            print("🚀 Universal Auto Setup")
            print("\nUsage examples:")
            print("  python scripts/auto-setup.py --tier mvp --stack flutter")
            print("  python scripts/auto-setup.py --tier core --stack react --project my-app")
            print("  python scripts/auto-setup.py --detect")
            print("  python scripts/auto-setup.py --list")
            print("  python scripts/auto-setup.py --create-config my-config.json")
            print("\nUse --help for full options.")
    
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
