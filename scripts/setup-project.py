#!/usr/bin/env python3
"""
Interactive Project Setup Script
Purpose: Guide users through complete project setup with tier detection and template copying
Usage: python scripts/setup-project.py [--manual-tier] [--config CONFIG]
"""

import sys
import os
import json
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Optional, Tuple
from dataclasses import asdict

# Import existing configuration systems
from stack_config import get_all_stacks
from blueprint_config import (
    get_available_blueprints, 
    get_blueprint_summary, 
    get_supported_stacks,
    get_task_configuration,
    get_tier_defaults
)
from blueprint_resolver import BlueprintResolver, ProjectSpecification, IntermediateRepresentation

class ProjectSetup:
    def __init__(self):
        self.templates_root = Path(__file__).parent.parent
        self.project_config = {}
        self.blueprint_mode = False
        self.blueprint_resolver = BlueprintResolver()
        
    def print_header(self):
        print("🚀 Universal Project Setup Wizard")
        print("=" * 50)
        print("This wizard will help you set up a complete project")
        print("with the optimal tier and technology stack.")
        print()
    
    def select_blueprint(self) -> Optional[str]:
        """Blueprint selection step - first step in setup process"""
        print("🏗️  Step 1: Select Blueprint (Optional)")
        print("-" * 40)
        print("Blueprints are product archetypes that preconfigure")
        print("architecture, features, and monetization patterns.")
        print()
        
        available_blueprints = get_available_blueprints()
        
        if not available_blueprints:
            print("No blueprints available. Continuing with manual setup...")
            return None
        
        print("Available blueprints:")
        print("0. Skip (manual stack/tier selection)")
        
        for i, blueprint_id in enumerate(available_blueprints, 1):
            summary = get_blueprint_summary(blueprint_id)
            name = summary.get('name', blueprint_id)
            description = summary.get('description', 'No description available')
            print(f"{i}. {name}")
            print(f"   {description[:80]}{'...' if len(description) > 80 else ''}")
            print()
        
        while True:
            try:
                choice = input("Select blueprint (0-{}): ".format(len(available_blueprints))).strip()
                choice_num = int(choice)
                
                if choice_num == 0:
                    print("Skipping blueprint selection...")
                    return None
                elif 1 <= choice_num <= len(available_blueprints):
                    selected_blueprint = available_blueprints[choice_num - 1]
                    print(f"Selected blueprint: {selected_blueprint}")
                    
                    # Show blueprint details
                    self.show_blueprint_details(selected_blueprint)
                    
                    confirm = input("Use this blueprint? (y/n): ").strip().lower()
                    if confirm in ['y', 'yes']:
                        self.blueprint_mode = True
                        return selected_blueprint
                    else:
                        print("Selecting different blueprint...")
                        continue
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a valid number.")
            except KeyboardInterrupt:
                print("\nSetup cancelled.")
                sys.exit(0)
    
    def show_blueprint_details(self, blueprint_id: str):
        """Show detailed information about a blueprint"""
        summary = get_blueprint_summary(blueprint_id)
        stacks = get_supported_stacks(blueprint_id)
        tasks = get_task_configuration(blueprint_id)
        
        print(f"\n📋 Blueprint Details: {summary.get('name', blueprint_id)}")
        print("=" * 50)
        print(f"Category: {summary.get('category', 'Unknown')}")
        print(f"Type: {summary.get('type', 'Unknown')}")
        print(f"\nDescription: {summary.get('description', 'No description')}")
        
        print(f"\n🔧 Stack Requirements:")
        if stacks['required']:
            print(f"  Required: {', '.join(stacks['required'])}")
        if stacks['recommended']:
            print(f"  Recommended: {', '.join(stacks['recommended'])}")
        if stacks['supported']:
            print(f"  Supported: {', '.join(stacks['supported'])}")
        
        print(f"\n📦 Task Configuration:")
        if tasks['required']:
            print(f"  Required: {', '.join(tasks['required'])}")
        if tasks['recommended']:
            print(f"  Recommended: {', '.join(tasks['recommended'])}")
        if tasks['optional']:
            print(f"  Optional: {', '.join(tasks['optional'])}")
        
        print()
    
    def select_stacks_with_blueprint(self, blueprint_id: str) -> Dict[str, str]:
        """Stack selection driven by blueprint requirements"""
        print(f"\n🔧 Step 2: Stack Selection (Blueprint: {blueprint_id})")
        print("-" * 50)
        
        stacks = get_supported_stacks(blueprint_id)
        selected_stacks = {}
        
        # Handle required stacks
        if stacks['required']:
            print("Required stacks (automatically included):")
            for stack in stacks['required']:
                print(f"  ✓ {stack}")
                # Determine layer for required stack
                layer = self.determine_stack_layer(stack)
                selected_stacks[layer] = stack
        
        # Handle recommended stacks
        if stacks['recommended']:
            print(f"\nRecommended stacks:")
            for stack in stacks['recommended']:
                include = input(f"  Include {stack}? (Y/n): ").strip().lower()
                if include in ['', 'y', 'yes']:
                    layer = self.determine_stack_layer(stack)
                    selected_stacks[layer] = stack
        
        # Handle optional supported stacks
        if stacks['supported']:
            print(f"\nAdditional supported stacks:")
            for stack in stacks['supported']:
                if stack not in selected_stacks.values():
                    include = input(f"  Include {stack}? (y/N): ").strip().lower()
                    if include in ['y', 'yes']:
                        layer = self.determine_stack_layer(stack)
                        selected_stacks[layer] = stack
        
        return selected_stacks
    
    def determine_stack_layer(self, stack: str) -> str:
        """Determine the layer (frontend/backend) for a stack"""
        frontend_stacks = ['flutter', 'react', 'react_native', 'next', 'typescript']
        backend_stacks = ['python', 'node', 'go', 'sql', 'r']
        
        if stack in frontend_stacks:
            return 'frontend'
        elif stack in backend_stacks:
            return 'backend'
        else:
            return 'main'  # Generic layer
    
    def select_tiers_with_blueprint(self, blueprint_id: str, stacks: Dict[str, str]) -> Dict[str, str]:
        """Tier selection with blueprint defaults"""
        print(f"\n🎯 Step 3: Tier Selection (Blueprint: {blueprint_id})")
        print("-" * 50)
        
        from blueprint_config import get_tier_defaults
        blueprint_tiers = get_tier_defaults(blueprint_id)
        selected_tiers = {}
        
        print("Blueprint tier defaults:")
        print(f"  Overall: {blueprint_tiers.get('overall', 'core')}")
        print(f"  Frontend: {blueprint_tiers.get('frontend', 'mvp')}")
        print(f"  Backend: {blueprint_tiers.get('backend', 'core')}")
        
        use_defaults = input("\nUse blueprint tier defaults? (Y/n): ").strip().lower()
        
        if use_defaults in ['', 'y', 'yes']:
            # Apply blueprint defaults
            for layer, stack in stacks.items():
                if stack in ['flutter', 'react', 'react_native', 'next']:
                    selected_tiers[stack] = blueprint_tiers.get('frontend', 'mvp')
                elif stack in ['python', 'node', 'go']:
                    selected_tiers[stack] = blueprint_tiers.get('backend', 'core')
                else:
                    selected_tiers[stack] = blueprint_tiers.get('overall', 'core')
        else:
            # Manual tier selection for each stack
            for stack in stacks.values():
                tier = self.select_tier_manual_for_stack(stack)
                selected_tiers[stack] = tier
        
        return selected_tiers
    
    def select_tier_manual_for_stack(self, stack: str) -> str:
        """Manual tier selection for a specific stack"""
        available_tiers = ['mvp', 'core', 'enterprise']
        
        print(f"\nSelect tier for {stack}:")
        for i, tier in enumerate(available_tiers, 1):
            print(f"{i}. {tier.title()}")
        
        while True:
            try:
                choice = input(f"Select tier (1-{len(available_tiers)}): ").strip()
                choice_num = int(choice)
                
                if 1 <= choice_num <= len(available_tiers):
                    return available_tiers[choice_num - 1]
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a valid number.")
    
    def collect_project_info(self) -> Tuple[str, str]:
        """Collect basic project information"""
        print("\n📝 Project Information")
        print("-" * 25)
        
        name = input("Project name: ").strip()
        while not name:
            print("Project name is required.")
            name = input("Project name: ").strip()
        
        description = input("Project description (optional): ").strip()
        
        return name, description
    
    def run_blueprint_setup(self) -> IntermediateRepresentation:
        """Run the blueprint-driven setup flow"""
        print("\n🏗️  Blueprint-Driven Setup")
        print("=" * 40)
        
        # Step 1: Collect project info
        project_name, project_description = self.collect_project_info()
        
        # Step 2: Select blueprint
        blueprint_id = self.select_blueprint()
        if not blueprint_id:
            print("No blueprint selected. Use manual setup instead.")
            return None
        
        # Step 3: Select stacks based on blueprint
        stacks = self.select_stacks_with_blueprint(blueprint_id)
        
        # Step 4: Select tiers based on blueprint
        tiers = self.select_tiers_with_blueprint(blueprint_id, stacks)
        
        # Step 5: Select optional tasks
        tasks = self.select_optional_tasks(blueprint_id)
        
        # Step 6: Create project specification
        project_spec = ProjectSpecification(
            name=project_name,
            blueprint=blueprint_id,
            stacks=stacks,
            tier=tiers,
            tasks=tasks,
            description=project_description
        )
        
        # Step 7: Resolve to intermediate representation
        print("\n🔄 Resolving Blueprint Configuration...")
        ir = self.blueprint_resolver.resolve(project_spec)
        
        # Step 8: Validate resolution
        errors = self.blueprint_resolver.validate_resolution(ir)
        if errors:
            print("⚠️  Resolution warnings:")
            for error in errors:
                print(f"  - {error}")
        
        print("✅ Blueprint resolution complete!")
        return ir
    
    def select_optional_tasks(self, blueprint_id: str) -> Dict[str, List[str]]:
        """Select optional tasks for the blueprint"""
        tasks = get_task_configuration(blueprint_id)
        
        if not tasks['optional']:
            return {'optional': []}
        
        print(f"\n📦 Optional Tasks (Blueprint: {blueprint_id})")
        print("-" * 45)
        
        selected_optional = []
        for task in tasks['optional']:
            include = input(f"  Include {task}? (y/N): ").strip().lower()
            if include in ['y', 'yes']:
                selected_optional.append(task)
        
        return {'optional': selected_optional}
    
    def run_legacy_setup(self) -> Dict:
        """Run the legacy setup flow (no blueprint)"""
        print("\n🔧 Manual Setup (Legacy Mode)")
        print("=" * 35)
        
        # Collect project info
        project_name, project_description = self.collect_project_info()
        
        # Use existing legacy methods
        tier, tier_details = self.detect_tier()
        stack, stack_recommendations = self.detect_stack(tier)
        
        # Create legacy project config
        self.project_config = {
            'name': project_name,
            'description': project_description,
            'tier': tier,
            'stack': stack,
            'tier_details': tier_details,
            'stack_recommendations': stack_recommendations,
            'blueprint_mode': False
        }
        
        return self.project_config
    
    def run(self):
        """Main setup orchestration method"""
        self.print_header()
        
        try:
            # Try blueprint setup first
            ir = self.run_blueprint_setup()
            
            if ir is None:
                # Blueprint setup cancelled or failed, fall back to legacy
                print("\nFalling back to manual setup...")
                config = self.run_legacy_setup()
                self.scaffold_legacy_project(config)
            else:
                # Blueprint setup successful
                self.scaffold_blueprint_project(ir)
                
        except KeyboardInterrupt:
            print("\n\nSetup cancelled by user.")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ Setup failed: {e}")
            sys.exit(1)
    
    def scaffold_blueprint_project(self, ir: IntermediateRepresentation):
        """Scaffold project using blueprint intermediate representation"""
        print(f"\n🚀 Scaffolding Project: {ir.name}")
        print("=" * 40)
        
        print(f"Blueprint: {ir.blueprint}")
        print(f"Stacks: {', '.join(ir.stacks)}")
        print(f"Tiers: {ir.tiers}")
        print(f"Tasks: {len(ir.tasks['all'])} tasks configured")
        
        # Convert IR to dict for compatibility with existing scaffolding code
        project_config = asdict(ir)
        
        # TODO: Implement actual scaffolding logic
        print("\n📋 Project Configuration:")
        for key, value in project_config.items():
            if key not in ['metadata', 'constraints', 'overlays', 'llm_hints']:
                print(f"  {key}: {value}")
        
        print(f"\n✅ Project '{ir.name}' ready for generation!")
        print("Next steps:")
        print("  1. Review the configuration above")
        print("  2. Run project generation with: python scripts/generate-project.py")
        print(f"  3. Apply blueprint overlays from: blueprints/{ir.blueprint}/overlays/")
    
    def scaffold_legacy_project(self, config: Dict):
        """Scaffold project using legacy configuration"""
        print(f"\n🚀 Scaffolding Project: {config['name']}")
        print("=" * 40)
        
        print(f"Stack: {config['stack']}")
        print(f"Tier: {config['tier']}")
        print("Mode: Legacy (no blueprint)")
        
        # TODO: Implement existing scaffolding logic
        print(f"\n✅ Project '{config['name']}' ready for generation!")
        print("Next steps:")
        print("  1. Review the configuration above")
        print("  2. Run project generation with: python scripts/generate-project.py")
    
    def detect_tier(self) -> Tuple[str, Dict]:
        """Run tier detection"""
        print("🎯 Step 1: Detecting Optimal Tier")
        print("-" * 30)
        
        try:
            # Import and run tier detector
            sys.path.append(str(Path(__file__).parent))
            from detect_tier import TierDetector
            
            detector = TierDetector(verbose=False)
            tier, details = detector.detect_interactive()
            return tier, details
            
        except Exception as e:
            print(f"Error running tier detection: {e}")
            print("Falling back to Core tier...")
            return "core", {"fallback": True}
    
    def detect_stack(self, tier: str = None) -> Tuple[str, List]:
        """Intelligent stack detection"""
        print("\n🧠 Step 2: Intelligent Stack Detection")
        print("-" * 40)
        
        try:
            # Import and run stack detector
            sys.path.append(str(Path(__file__).parent))
            from detect_stack import StackDetector
            
            detector = StackDetector(verbose=False)
            stack, recommendations = detector.detect_interactive()
            return stack, recommendations
            
        except Exception as e:
            print(f"Error running stack detection: {e}")
            print("Falling back to manual selection...")
            return self.select_stack_manual(), []
    
    def select_stack_manual(self) -> str:
        """Fallback manual stack selection"""
        print("\n🔧 Manual Stack Selection")
        print("-" * 30)
        
        stack_options = {
            "flutter": "Flutter (Mobile Apps)",
            "react_native": "React Native (Mobile Apps)", 
            "react": "React (Web Applications)",
            "next": "Next.js (Full-stack Web Applications)",
            "node": "Node.js (Backend APIs)",
            "python": "Python (Backend Services)",
            "r": "R (Data Analysis & Visualization)",
            "go": "Go (High-performance Services)",
            "sql": "SQL (Database Projects)"
        }
        
        for i, (key, desc) in enumerate(stack_options.items(), 1):
            print(f"{i}. {desc}")
        
        while True:
            try:
                choice = input("\nEnter your choice (1-9): ").strip()
                if choice.isdigit() and 1 <= int(choice) <= 9:
                    return list(stack_options.keys())[int(choice) - 1]
                else:
                    print("Invalid choice. Please enter a number between 1-6.")
            except KeyboardInterrupt:
                print("\nExiting...")
                sys.exit(1)
    
    def get_project_info(self) -> Dict:
        """Get project information"""
        print("\n📝 Step 3: Project Information")
        print("-" * 30)
        
        project_name = input("Project name: ").strip() or "my-project"
        project_desc = input("Project description: ").strip() or "A new project"
        
        return {
            "name": project_name,
            "description": project_desc
        }
    
    def execute_setup_commands(self, tier: str, stack: str, project_info: Dict):
        """Execute the appropriate setup commands"""
        print(f"\n⚙️  Step 4: Setting up {tier.upper()} {stack.upper()} Project")
        print("-" * 50)
        
        # Create project directory
        project_dir = Path.cwd() / project_info["name"]
        if project_dir.exists():
            response = input(f"Directory '{project_info['name']}' exists. Overwrite? (y/N): ")
            if response.lower() != 'y':
                print("Setup cancelled.")
                return
            shutil.rmtree(project_dir)
        
        project_dir.mkdir()
        os.chdir(project_dir)
        print(f"Created project directory: {project_dir}")
        
        # Define setup commands based on tier and stack
        setup_commands = self.get_setup_commands(tier, stack)
        
        for step, commands in setup_commands.items():
            print(f"\n🔨 {step}")
            for cmd in commands:
                print(f"   $ {cmd}")
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                    if result.returncode != 0:
                        print(f"   ❌ Error: {result.stderr}")
                        response = input("Continue anyway? (y/N): ")
                        if response.lower() != 'y':
                            print("Setup cancelled.")
                            return
                    else:
                        print("   ✅ Done")
                except subprocess.TimeoutExpired:
                    print("   ⏱️  Command timed out")
                    response = input("Continue anyway? (y/N): ")
                    if response.lower() != 'y':
                        print("Setup cancelled.")
                        return
                except Exception as e:
                    print(f"   ❌ Error: {e}")
                    response = input("Continue anyway? (y/N): ")
                    if response.lower() != 'y':
                        print("Setup cancelled.")
                        return
    
    def get_setup_commands(self, tier: str, stack: str) -> Dict[str, list]:
        """Get setup commands for specific tier and stack combination"""
        templates_root = self.templates_root
        
        commands = {
            "Initialize project": []
        }
        
        # Stack-specific initialization
        if stack == "flutter":
            commands["Initialize project"] = [
                "flutter create . --org com.example",
                "flutter pub get"
            ]
        elif stack == "react_native":
            commands["Initialize project"] = [
                "npx react-native init . --template react-native-template-typescript",
                "npm install"
            ]
        elif stack == "react":
            commands["Initialize project"] = [
                "npx create-react-app . --template typescript",
                "npm install"
            ]
        elif stack == "next":
            commands["Initialize project"] = [
                "npx create-next-app@latest . --typescript --tailwind --eslint",
                "npm install"
            ]
        elif stack == "node":
            commands["Initialize project"] = [
                "npm init -y"
            ]
        elif stack == "python":
            commands["Initialize project"] = [
                "python -m venv venv",
                "pip install --upgrade pip"
            ]
        elif stack == "go":
            commands["Initialize project"] = [
                "go mod init my-service"
            ]
        
        # Tier-specific dependencies and templates
        if tier == "mvp":
            commands["Install MVP dependencies"] = self.get_mvp_dependencies(stack)
            commands["Copy MVP templates"] = self.get_mvp_template_commands(stack, templates_root)
        elif tier == "core":
            commands["Install Core dependencies"] = self.get_core_dependencies(stack)
            commands["Copy Core templates"] = self.get_core_template_commands(stack, templates_root)
        elif tier == "enterprise":
            commands["Install Enterprise dependencies"] = self.get_enterprise_dependencies(stack)
            commands["Copy Enterprise templates"] = self.get_enterprise_template_commands(stack, templates_root)
        
        # Common setup steps
        commands["Create project structure"] = self.get_structure_commands(tier, stack)
        commands["Run initial tests"] = self.get_test_commands(stack)
        
        return commands
    
    def get_mvp_dependencies(self, stack: str) -> list:
        """Get MVP tier dependency commands"""
        if stack == "flutter":
            return ["dart pub global activate flutter_test_runner"]
        elif stack == "react_native":
            return ["npm install @react-navigation/native @react-navigation/stack",
                    "npm install react-native-screens react-native-safe-area-context",
                    "npm install --dev @testing-library/react-native jest"]
        elif stack == "react":
            return ["npm install axios react-router-dom",
                    "npm install --dev @testing-library/react @testing-library/jest-dom"]
        elif stack == "node":
            return ["npm install express cors helmet morgan",
                    "npm install --dev jest supertest nodemon"]
        elif stack == "python":
            return ["pip install fastapi uvicorn pydantic",
                    "pip install --dev pytest pytest-asyncio httpx"]
        elif stack == "go":
            return ["go get github.com/gin-gonic/gin",
                    "go get github.com/stretchr/testify/assert"]
        return []
    
    def get_core_dependencies(self, stack: str) -> list:
        """Get Core tier dependency commands"""
        if stack == "flutter":
            return ["flutter pub add provider http shared_preferences connectivity",
                    "flutter pub add --dev flutter_test integration_test mockito"]
        elif stack == "react_native":
            return ["npm install @react-navigation/native @react-navigation/stack @react-navigation/bottom-tabs",
                    "npm install @reduxjs/toolkit react-redux redux-persist",
                    "npm install react-native-async-storage react-native-netinfo",
                    "npm install --dev @testing-library/react-native jest @testing-library/jest-native"]
        elif stack == "react":
            return ["npm install axios react-router-dom @reduxjs/toolkit react-redux",
                    "npm install react-query react-hook-form @mui/material @emotion/react @emotion/styled",
                    "npm install --dev @testing-library/react @testing-library/jest-dom @testing-library/user-event msw"]
        elif stack == "node":
            return ["npm install express cors helmet morgan compression",
                    "npm install mongoose redis jsonwebtoken bcryptjs",
                    "npm install express-rate-limit express-validator",
                    "npm install --dev jest supertest nodemon mongodb-memory-server"]
        elif stack == "python":
            return ["pip install fastapi uvicorn pydantic sqlalchemy alembic",
                    "pip install redis celery python-multipart python-jose passlib",
                    "pip install --dev pytest pytest-asyncio httpx pytest-cov factory-boy"]
        elif stack == "go":
            return ["go get github.com/gin-gonic/gin",
                    "go get github.com/go-redis/redis/v8",
                    "go get go.mongodb.org/mongo-driver/mongo",
                    "go get github.com/golang-jwt/jwt/v5",
                    "go get golang.org/x/crypto/bcrypt",
                    "go get github.com/stretchr/testify/assert",
                    "go get github.com/stretchr/testify/suite"]
        return []
    
    def get_enterprise_dependencies(self, stack: str) -> list:
        """Get Enterprise tier dependency commands"""
        if stack == "flutter":
            return ["flutter pub add provider http shared_preferences connectivity",
                    "flutter pub add local_auth flutter_secure_storage device_info_plus",
                    "flutter pub add firebase_auth firebase_core firebase_analytics",
                    "flutter pub add --dev flutter_test integration_test mockito build_runner"]
        elif stack == "react_native":
            return ["npm install @react-navigation/native @react-navigation/stack @react-navigation/bottom-tabs",
                    "npm install @reduxjs/toolkit react-redux redux-persist",
                    "npm install react-native-async-storage react-native-netinfo",
                    "npm install react-native-fingerprint-auth react-native-keychain",
                    "npm install @react-native-firebase/app @react-native-firebase/auth @react-native-firebase/analytics",
                    "npm install --dev @testing-library/react-native jest @testing-library/jest-native detox"]
        elif stack == "react":
            return ["npm install axios react-router-dom @reduxjs/toolkit react-redux",
                    "npm install react-query react-hook-form @mui/material @emotion/react @emotion/styled",
                    "npm install @auth0/auth0-react react-helmet-react react-intersection-observer",
                    "npm install --dev @testing-library/react @testing-library/jest-dom @testing-library/user-event msw cypress"]
        elif stack == "node":
            return ["npm install express cors helmet morgan compression",
                    "npm install mongoose redis jsonwebtoken bcryptjs",
                    "npm install express-rate-limit express-validator winston express-winston",
                    "npm install helmet-csp express-mongo-sanitize express-no-sqli",
                    "npm install --dev jest supertest nodemon mongodb-memory-server newman"]
        elif stack == "python":
            return ["pip install fastapi uvicorn pydantic sqlalchemy alembic",
                    "pip install redis celery python-multipart python-jose passlib",
                    "pip install boto3 cryptography pydantic-settings structlog",
                    "pip install --dev pytest pytest-asyncio httpx pytest-cov factory-boy locust"]
        elif stack == "go":
            return ["go get github.com/gin-gonic/gin",
                    "go get github.com/go-redis/redis/v8",
                    "go get go.mongodb.org/mongo-driver/mongo",
                    "go get github.com/golang-jwt/jwt/v5",
                    "go get golang.org/x/crypto/bcrypt",
                    "go get github.com/sony/gobreaker",
                    "go get github.com/prometheus/client_golang",
                    "go get github.com/stretchr/testify/assert",
                    "go get github.com/stretchr/testify/suite"]
        return []
    
    def get_mvp_template_commands(self, stack: str, templates_root: Path) -> list:
        """Get MVP template copy commands"""
        template_path = templates_root / "tiers" / "mvp"
        
        if stack == "flutter":
            return [f"cp {template_path}/code/minimal-boilerplate-flutter.tpl.dart lib/main.dart",
                    f"cp {template_path}/tests/basic-tests-flutter.tpl.dart test/widget_test.dart"]
        elif stack == "react_native":
            return [f"cp {template_path}/code/minimal-boilerplate-react_native.tpl.jsx App.js",
                    f"cp {template_path}/tests/basic-tests-react_native.tpl.jsx App.test.js"]
        elif stack == "react":
            return [f"cp {template_path}/code/minimal-boilerplate-react.tpl.jsx src/App.tsx",
                    f"cp {template_path}/tests/basic-tests-react.tpl.jsx src/App.test.tsx"]
        elif stack == "node":
            return [f"cp {template_path}/code/minimal-boilerplate-node.tpl.js index.js",
                    f"cp {template_path}/tests/basic-tests-node.tpl.js index.test.js"]
        elif stack == "python":
            return [f"cp {template_path}/code/minimal-boilerplate-python.tpl.py main.py",
                    f"cp {template_path}/tests/basic-tests-python.tpl.py test_main.py"]
        elif stack == "go":
            return [f"cp {template_path}/code/minimal-boilerplate-go.tpl.go main.go",
                    f"cp {template_path}/tests/basic-tests-go.tpl.go main_test.go"]
        return []
    
    def get_core_template_commands(self, stack: str, templates_root: Path) -> list:
        """Get Core template copy commands"""
        template_path = templates_root / "tiers" / "core"
        
        if stack == "flutter":
            return [f"cp {template_path}/code/production-boilerplate-flutter.tpl.dart lib/main.dart",
                    f"cp {template_path}/tests/comprehensive-tests-flutter.tpl.dart test/app_test.dart"]
        elif stack == "react_native":
            return [f"cp {template_path}/code/production-boilerplate-react_native.tpl.jsx App.js",
                    f"cp {template_path}/tests/comprehensive-tests-react_native.tpl.jsx App.test.js"]
        elif stack == "react":
            return [f"cp {template_path}/code/production-boilerplate-react.tpl.jsx src/App.tsx",
                    f"cp {template_path}/tests/comprehensive-tests-react.tpl.jsx src/App.test.tsx"]
        elif stack == "node":
            return [f"cp {template_path}/code/production-boilerplate-node.tpl.js index.js",
                    f"cp {template_path}/tests/comprehensive-tests-node.tpl.js index.test.js"]
        elif stack == "python":
            return [f"cp {template_path}/code/production-boilerplate-python.tpl.py main.py",
                    f"cp {template_path}/tests/comprehensive-tests-python.tpl.py test_main.py"]
        elif stack == "go":
            return [f"cp {template_path}/code/production-boilerplate-go.tpl.go main.go",
                    f"cp {template_path}/tests/comprehensive-tests-go.tpl.go main_test.go"]
        return []
    
    def get_enterprise_template_commands(self, stack: str, templates_root: Path) -> list:
        """Get Enterprise template copy commands"""
        template_path = templates_root / "tiers" / "enterprise"
        
        if stack == "flutter":
            return [f"cp {template_path}/code/enterprise-boilerplate-flutter.tpl.dart lib/main.dart",
                    f"cp {template_path}/tests/enterprise-tests-flutter.tpl.dart test/enterprise_test.dart"]
        elif stack == "react_native":
            return [f"cp {template_path}/code/enterprise-boilerplate-react_native.tpl.jsx App.js",
                    f"cp {template_path}/tests/enterprise-tests-react_native.tpl.jsx App.test.js"]
        elif stack == "react":
            return [f"cp {template_path}/code/enterprise-boilerplate-react.tpl.jsx src/App.tsx",
                    f"cp {template_path}/tests/enterprise-tests-react.tpl.jsx src/App.test.tsx"]
        elif stack == "node":
            return [f"cp {template_path}/code/enterprise-boilerplate-node.tpl.js index.js",
                    f"cp {template_path}/tests/enterprise-tests-node.tpl.js index.test.js"]
        elif stack == "python":
            return [f"cp {template_path}/code/enterprise-boilerplate-python.tpl.py main.py",
                    f"cp {template_path}/tests/enterprise-tests-python.tpl.py test_main.py"]
        elif stack == "go":
            return [f"cp {template_path}/code/enterprise-boilerplate-go.tpl.go main.go",
                    f"cp {template_path}/tests/enterprise-tests-go.tpl.go main_test.go"]
        return []
    
    def get_structure_commands(self, tier: str, stack: str) -> list:
        """Get directory structure creation commands"""
        if tier == "mvp":
            if stack in ["flutter", "react_native"]:
                return ["mkdir -p lib/{models,services,widgets}", "mkdir -p test/{unit,widget}"]
            elif stack in ["react", "node"]:
                return ["mkdir -p src/{components,pages,services,utils}", "mkdir -p test/{unit,integration}"]
            elif stack == "python":
                return ["mkdir -p app tests", "mkdir -p tests/{unit,integration}"]
            elif stack == "go":
                return ["mkdir -p handlers middleware models utils", "mkdir -p test/{unit,integration}"]
        elif tier == "core":
            if stack in ["flutter", "react_native"]:
                return ["mkdir -p lib/{models,services,widgets,pages,utils,config}", 
                        "mkdir -p test/{unit,widget,integration,feature}"]
            elif stack in ["react", "node"]:
                return ["mkdir -p src/{components,pages,services,utils,store,hooks}",
                        "mkdir -p test/{unit,integration,feature}"]
            elif stack == "python":
                return ["mkdir -p app tests alembic", "mkdir -p app/{models,schemas,crud,api,core,db}",
                        "mkdir -p tests/{unit,integration,feature}"]
            elif stack == "go":
                return ["mkdir -p handlers middleware models utils config",
                        "mkdir -p test/{unit,integration,feature}"]
        elif tier == "enterprise":
            if stack in ["flutter", "react_native"]:
                return ["mkdir -p lib/{models,services,widgets,pages,utils,config,security,compliance}",
                        "mkdir -p test/{unit,widget,integration,feature,security,compliance,resilience}"]
            elif stack in ["react", "node"]:
                return ["mkdir -p src/{components,pages,services,utils,store,hooks,security,compliance}",
                        "mkdir -p test/{unit,integration,feature,security,compliance,resilience,performance}"]
            elif stack == "python":
                return ["mkdir -p app tests alembic", "mkdir -p app/{models,schemas,crud,api,core,db,security,compliance}",
                        "mkdir -p tests/{unit,integration,feature,security,compliance,resilience,performance}"]
            elif stack == "go":
                return ["mkdir -p handlers middleware models utils config security compliance",
                        "mkdir -p test/{unit,integration,feature,security,compliance,resilience,performance}"]
        return []
    
    def get_test_commands(self, stack: str) -> list:
        """Get test execution commands"""
        if stack == "flutter":
            return ["flutter test --coverage"]
        elif stack in ["react_native", "react", "node"]:
            return ["npm test", "npm test -- --coverage"]
        elif stack == "python":
            return ["pytest --cov=app"]
        elif stack == "go":
            return ["go test ./... -cover"]
        return []
    
    def generate_readme(self, tier: str, stack: str, project_info: Dict):
        """Generate project-specific README"""
        readme_content = f"""# {project_info['name']}

{project_info['description']}

## Project Setup

This project was generated using the universal template system with:
- **Tier**: {tier.upper()}
- **Stack**: {stack.upper()}

## Getting Started

### Prerequisites
- Install the required dependencies for {stack}

### Installation
```bash
# Follow the stack-specific setup instructions
# See QUICKSTART.md for detailed commands
```

### Running Tests
```bash
# Run the test suite
{self.get_test_commands(stack)[0] if self.get_test_commands(stack) else '# Check test commands'}
```

## Project Structure

The project follows the {tier.upper()} tier structure:
- Basic functionality and testing
- Production-ready features
- Enterprise-grade security and compliance (if Full tier)

## Next Steps

1. Customize the generated code for your specific needs
2. Update configuration files
3. Add your business logic
4. Deploy to your preferred environment

## Support

For more information, see:
- Universal System Map: [SYSTEM-MAP.tpl.md](../SYSTEM-MAP.tpl.md)
- Best Practices: [TEMPLATE-BEST-PRACTICES.tpl.md](../universal/docs/TEMPLATE-BEST-PRACTICES.tpl.md)
- Quick Start Guide: [QUICKSTART.md](../QUICKSTART.md)

Generated on: {self.get_timestamp()}
"""
        
        with open("README.md", "w") as f:
            f.write(readme_content)
        
        print("📄 Generated project README.md")
    
    def execute_autonomous_setup(self, ir: IntermediateRepresentation, project_name: str):
        """Execute autonomous project setup using resolved blueprint"""
        print("🔧 Executing Autonomous Setup...")
        print("-" * 40)
        
        # Create project directory structure
        project_dir = Path(project_name)
        if project_dir.exists():
            print(f"⚠️  Directory {project_name} already exists")
            response = input("Continue anyway? (y/N): ")
            if response.lower() != 'y':
                return
        
        project_dir.mkdir(exist_ok=True)
        
        # Generate project configuration
        project_config = {
            'name': project_name,
            'blueprint': ir.blueprint,
            'stacks': ir.stacks,
            'tiers': ir.tiers,
            'tasks': ir.tasks,
            'constraints': ir.constraints,
            'metadata': ir.metadata,
            'generated_at': self.get_timestamp()
        }
        
        # Save project configuration
        config_file = project_dir / 'project-config.json'
        with open(config_file, 'w') as f:
            json.dump(project_config, f, indent=2)
        print(f"📋 Saved project configuration to {config_file}")
        
        # Generate project structure for each stack
        for stack in ir.stacks:
            stack_dir = project_dir / stack
            stack_dir.mkdir(exist_ok=True)
            
            # Copy base templates for stack
            self.copy_stack_templates(stack, stack_dir, ir.tiers.get(stack, 'core'))
            
            # Apply blueprint overlays if available
            if stack in ir.overlays and ir.overlays[stack]['enabled']:
                self.apply_blueprint_overlays(stack, stack_dir, ir)
        
        # Generate README with blueprint information
        self.generate_blueprint_readme(project_dir, ir, project_name)
        
        print(f"✅ Project structure generated in {project_dir}/")
    
    def copy_stack_templates(self, stack: str, target_dir: Path, tier: str):
        """Copy stack-specific templates to project directory"""
        source_dir = self.templates_root / 'stacks' / stack / 'base'
        if source_dir.exists():
            print(f"📁 Copying {stack} templates...")
            # Copy all template files (in real implementation, this would process templates)
            for item in source_dir.rglob('*'):
                if item.is_file():
                    relative_path = item.relative_to(source_dir)
                    target_file = target_dir / relative_path
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    # Handle Unicode encoding for Windows
                    try:
                        content = item.read_text(encoding='utf-8')
                        target_file.write_text(content, encoding='utf-8')
                    except UnicodeDecodeError:
                        # Fallback to binary copy for non-text files
                        target_file.write_bytes(item.read_bytes())
    
    def apply_blueprint_overlays(self, stack: str, target_dir: Path, ir: IntermediateRepresentation):
        """Apply blueprint-specific overlays to project"""
        overlay_dir = self.templates_root / 'blueprints' / ir.blueprint / 'overlays' / stack
        if overlay_dir.exists():
            print(f"🏗️  Applying {ir.blueprint} overlays for {stack}...")
            for item in overlay_dir.rglob('*'):
                if item.is_file():
                    relative_path = item.relative_to(overlay_dir)
                    target_file = target_dir / relative_path
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    # Handle Unicode encoding for Windows
                    try:
                        content = item.read_text(encoding='utf-8')
                        target_file.write_text(content, encoding='utf-8')
                    except UnicodeDecodeError:
                        # Fallback to binary copy for non-text files
                        target_file.write_bytes(item.read_bytes())
    
    def generate_blueprint_readme(self, project_dir: Path, ir: IntermediateRepresentation, project_name: str):
        """Generate README with blueprint information"""
        readme_content = f"""# {project_name}

## 🏗️  Blueprint Configuration

**Blueprint**: {ir.blueprint}
**Generated**: {ir.metadata.get('generated_at', 'Unknown')}
**Resolution Confidence**: {ir.metadata.get('resolution_confidence', 0):.2f}

### Technology Stack
{chr(10).join(f"- **{stack.upper()}**: {ir.tiers.get(stack, 'core').title()} tier" for stack in ir.stacks)}

### Features & Tasks
{chr(10).join(f"- **{task}**" for task in ir.tasks.get('all', []))}

### Constraints
{chr(10).join(f"- **{key}**: {value}" for key, value in ir.constraints.items())}

## 🚀 Getting Started

This project was generated autonomously using the Universal Template System's blueprint-driven approach.

### Development Commands

"""
        
        # Add stack-specific development commands
        for stack in ir.stacks:
            if stack == 'flutter':
                readme_content += "```bash\n# Flutter development\ncd flutter\nflutter pub get\nflutter run\n```\n\n"
            elif stack == 'python':
                readme_content += "```bash\n# Python development\ncd python\npip install -r requirements.txt\npython app.py\n```\n\n"
            elif stack == 'node':
                readme_content += "```bash\n# Node.js development\ncd node\nnpm install\nnpm start\n```\n\n"
        
        readme_file = project_dir / 'README.md'
        try:
            readme_file.write_text(readme_content, encoding='utf-8')
        except UnicodeEncodeError:
            # Fallback for Windows systems with encoding issues
            with open(readme_file, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(readme_content)
        print(f"📄 Generated blueprint README.md")

    def get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def print_completion(self, tier: str, stack: str, project_info: Dict):
        """Print completion message"""
        print("\n" + "=" * 50)
        print("🎉 PROJECT SETUP COMPLETE!")
        print("=" * 50)
        print(f"✅ Project: {project_info['name']}")
        print(f"✅ Tier: {tier.upper()}")
        print(f"✅ Stack: {stack.upper()}")
        print(f"✅ Location: {Path.cwd()}")
        
        print(f"\n🚀 Next Steps:")
        print(f"   1. cd {project_info['name']}")
        print(f"   2. Customize the generated code")
        print(f"   3. Run tests to verify setup")
        print(f"   4. Start building your features!")
        
        print(f"\n📚 Documentation:")
        print(f"   - QUICKSTART.md for setup guides")
        print(f"   - TEMPLATE-BEST-PRACTICES.tpl.md for best practices")
        print(f"   - SYSTEM-MAP.tpl.md for system overview")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Interactive project setup wizard")
    parser.add_argument("--manual-tier", help="Skip detection and use specified tier")
    parser.add_argument("--manual-stack", help="Skip detection and use specified stack")
    parser.add_argument("--config", help="Load configuration from file")
    parser.add_argument("--auto", action="store_true", help="Autonomous mode for LLM agents")
    parser.add_argument("--description", help="Project description for autonomous blueprint resolution")
    parser.add_argument("--name", help="Project name for autonomous mode")
    
    args = parser.parse_args()
    
    setup = ProjectSetup()
    
    # Handle autonomous mode for LLM agents
    if args.auto:
        if not args.description or not args.name:
            print("❌ Autonomous mode requires --description and --name arguments")
            print("Usage: python scripts/setup-project.py --auto --name 'MyProject' --description 'project description'")
            return
        
        print("🤖 Autonomous Mode Activated")
        print("=" * 50)
        print(f"Project Name: {args.name}")
        print(f"Description: {args.description}")
        print()
        
        # Use blueprint resolver for autonomous decision making
        try:
            # Create project specification from description
            spec = ProjectSpecification(
                name=args.name,
                description=args.description,
                blueprint="mins",  # Default to mins for autonomous mode
                stacks={"frontend": "flutter"}  # Default stack for autonomous mode
            )
            
            # Resolve blueprint to get optimal configuration
            ir = setup.blueprint_resolver.resolve(spec)
            
            print(f"🏗️  Blueprint: {ir.blueprint}")
            print(f"📊 Resolution Confidence: {ir.metadata['resolution_confidence']:.2f}")
            print(f"🔧 Stacks: {', '.join(ir.stacks)}")
            print(f"📈 Tiers: {ir.tiers}")
            print(f"📋 Tasks: {len(ir.tasks['all'])} total")
            print()
            
            # Execute autonomous setup
            setup.execute_autonomous_setup(ir, args.name)
            print("✅ Autonomous project setup completed!")
            return
            
        except Exception as e:
            import traceback
            print(f"❌ Autonomous setup failed: {e}")
            print(f"Full error traceback:\n{traceback.format_exc()}")
            print("Falling back to interactive mode...")
            setup.print_header()
    
    setup.print_header()
    
    try:
        # Get tier
        if args.manual_tier:
            tier = args.manual_tier.lower()
            if tier not in ["mvp", "core", "enterprise"]:
                print("Invalid tier. Use: mvp, core, or enterprise")
                return
            tier_details = {"manual": True}
        else:
            tier, tier_details = setup.detect_tier()
        
        # Get stack
        if args.manual_stack:
            stack = args.manual_stack.lower()
            valid_stacks = get_all_stacks()
            if stack not in valid_stacks:
                print(f"Invalid stack. Use: {', '.join(valid_stacks)}")
                return
            stack_recommendations = []
            print(f"Using manual stack: {stack.upper()}")
        else:
            stack, stack_recommendations = setup.detect_stack(tier)
        
        # Get project info
        project_info = setup.get_project_info()
        
        # Execute setup
        setup.execute_setup_commands(tier, stack, project_info)
        
        # Generate README
        setup.generate_readme(tier, stack, project_info)
        
        # Print completion
        setup.print_completion(tier, stack, project_info)
        
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
