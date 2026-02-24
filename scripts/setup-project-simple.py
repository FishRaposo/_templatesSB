#!/usr/bin/env python3
"""
Simplified Project Setup Script (No Emojis)
Purpose: Non-interactive project setup for automation
Usage: python scripts/setup-project-simple.py [tier] [stack] [project_name] [project_desc]
"""

import sys
import os
import json
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Optional, Tuple
from stack_config import get_all_stacks

class SimpleProjectSetup:
    def __init__(self):
        self.templates_root = Path(__file__).parent.parent
        
    def copy_template(self, tier: str, stack: str, project_info: Dict, project_dir: Path):
        """Copy and process templates"""
        print(f"Setting up {tier.upper()} {stack.upper()} project: {project_info['name']}")
        
        # Define template mappings
        template_mappings = {
            "node": "minimal-boilerplate-node.tpl.js",
            "react": "minimal-boilerplate-react.tpl.jsx", 
            "flutter": "minimal-boilerplate-flutter.tpl.dart",
            "go": "minimal-boilerplate-go.tpl.go",
            "python": "minimal-boilerplate-python.tpl.py",
            "react_native": "minimal-boilerplate-react_native.tpl.jsx",
            "r": "minimal-boilerplate-r.tpl.R"
        }
        
        if tier == "core":
            template_mappings = {
                "node": "production-boilerplate-node.tpl.js",
                "react": "production-boilerplate-react.tpl.jsx",
                "flutter": "production-boilerplate-flutter.tpl.dart", 
                "go": "production-boilerplate-go.tpl.go",
                "python": "production-boilerplate-python.tpl.py",
                "react_native": "production-boilerplate-react_native.tpl.jsx",
                "r": "production-boilerplate-r.tpl.R"
            }
        elif tier == "enterprise":
            template_mappings = {
                "node": "enterprise-boilerplate-node.tpl.js",
                "react": "enterprise-boilerplate-react.tpl.jsx",
                "flutter": "enterprise-boilerplate-flutter.tpl.dart",
                "go": "enterprise-boilerplate-go.tpl.go", 
                "python": "enterprise-boilerplate-python.tpl.py",
                "react_native": "enterprise-boilerplate-react_native.tpl.jsx",
                "r": "enterprise-boilerplate-r.tpl.R"
            }
        
        # Copy main code template
        template_file = self.templates_root / "tiers" / tier / "code" / template_mappings[stack]
        if template_file.exists():
            content = template_file.read_text(encoding='utf-8')
            
            # Extract code from markdown fences if present
            import re
            code_pattern = r'```(?:dart|go|py|js|jsx|r)\n(.*?)\n```'
            match = re.search(code_pattern, content, re.DOTALL)
            if match:
                content = match.group(1)
            
            # Replace placeholders
            content = content.replace("{{PROJECT_NAME}}", project_info['name'])
            content = content.replace("{{PROJECT_DESCRIPTION}}", project_info['description'])
            
            # Determine output filename
            if stack == "node":
                output_file = "app.js"
            elif stack in ["react", "react_native"]:
                output_file = "App.jsx"
            elif stack == "flutter":
                output_file = "main.dart"
            elif stack == "go":
                output_file = "main.go"
            elif stack == "python":
                output_file = "main.py"
            elif stack == "r":
                output_file = "app.R"
            
            # Write processed template
            (project_dir / output_file).write_text(content, encoding='utf-8')
            print(f"  Created: {output_file}")
        
        # Copy test template
        test_mappings = {
            "node": "basic-tests-node.tpl.js",
            "react": "basic-tests-react.tpl.jsx",
            "flutter": "basic-tests-flutter.tpl.dart",
            "go": "basic-tests-go.tpl.go",
            "python": "basic-tests-python.tpl.py", 
            "react_native": "basic-tests-react_native.tpl.jsx",
            "r": "basic-tests-r.tpl.R"
        }
        
        if tier == "core":
            test_mappings = {
                "node": "comprehensive-tests-node.tpl.js",
                "react": "comprehensive-tests-react.tpl.jsx",
                "flutter": "comprehensive-tests-flutter.tpl.dart",
                "go": "comprehensive-tests-go.tpl.go",
                "python": "comprehensive-tests-python.tpl.py",
                "react_native": "comprehensive-tests-react_native.tpl.jsx",
                "r": "comprehensive-tests-r.tpl.R"
            }
        elif tier == "enterprise":
            test_mappings = {
                "node": "enterprise-tests-node.tpl.js",
                "react": "enterprise-tests-react.tpl.jsx", 
                "flutter": "enterprise-tests-flutter.tpl.dart",
                "go": "enterprise-tests-go.tpl.go",
                "python": "enterprise-tests-python.tpl.py",
                "react_native": "enterprise-tests-react_native.tpl.jsx",
                "r": "enterprise-tests-r.tpl.R"
            }
        
        test_template = self.templates_root / "tiers" / tier / "tests" / test_mappings[stack]
        if test_template.exists():
            test_content = test_template.read_text(encoding='utf-8')
            
            # Extract code from markdown fences if present
            import re
            code_pattern = r'```(?:dart|go|py|js|jsx|r)\n(.*?)\n```'
            match = re.search(code_pattern, test_content, re.DOTALL)
            if match:
                test_content = match.group(1)
            
            test_content = test_content.replace("{{PROJECT_NAME}}", project_info['name'])
            
            # Determine test filename
            if stack == "node":
                test_file = "test/app.test.js"
                (project_dir / "test").mkdir(exist_ok=True)
            elif stack in ["react", "react_native"]:
                test_file = "src/__tests__/App.test.jsx"
                (project_dir / "src" / "__tests__").mkdir(parents=True, exist_ok=True)
            elif stack == "flutter":
                test_file = "test/widget_test.dart"
                (project_dir / "test").mkdir(exist_ok=True)
            elif stack == "go":
                test_file = "main_test.go"
            elif stack == "python":
                test_file = "test_main.py"
            elif stack == "r":
                test_file = "test_app.R"
            
            (project_dir / test_file).write_text(test_content, encoding='utf-8')
            print(f"  Created: {test_file}")
        
        # Copy README template
        readme_template = self.templates_root / "tiers" / tier / "docs" / "README.tpl.md"
        if readme_template.exists():
            readme_content = readme_template.read_text(encoding='utf-8')
            readme_content = readme_content.replace("{{PROJECT_NAME}}", project_info['name'])
            readme_content = readme_content.replace("{{PROJECT_DESCRIPTION}}", project_info['description'])
            readme_content = readme_content.replace("{{STACK}}", stack.upper())
            readme_content = readme_content.replace("{{TIER}}", tier.upper())
            
            (project_dir / "README.md").write_text(readme_content, encoding='utf-8')
            print(f"  Created: README.md")
        
        # Create basic package.json for Node.js projects
        if stack == "node":
            package_json = {
                "name": project_info['name'],
                "version": "1.0.0",
                "description": project_info['description'],
                "main": "app.js",
                "scripts": {
                    "start": "node app.js",
                    "test": "jest",
                    "dev": "nodemon app.js"
                },
                "dependencies": {
                    "express": "^4.18.0"
                },
                "devDependencies": {
                    "jest": "^29.0.0",
                    "nodemon": "^3.0.0"
                }
            }
            (project_dir / "package.json").write_text(json.dumps(package_json, indent=2), encoding='utf-8')
            print(f"  Created: package.json")
        
        # Create basic pubspec.yaml for Flutter projects
        elif stack == "flutter":
            # Convert dashes to underscores for Flutter package name (Dart identifier requirement)
            flutter_package_name = project_info['name'].replace('-', '_')
            pubspec_yaml = f"""
name: {flutter_package_name}
description: {project_info['description']}
version: 1.0.0+1

environment:
  sdk: '>=3.0.0 <4.0.0'

dependencies:
  flutter:
    sdk: flutter

dev_dependencies:
  flutter_test:
    sdk: flutter

flutter:
  uses-material-design: true
"""
            (project_dir / "pubspec.yaml").write_text(pubspec_yaml.strip(), encoding='utf-8')
            print(f"  Created: pubspec.yaml")
        
        # Create go.mod for Go projects
        elif stack == "go":
            go_mod = f"""module {project_info['name']}

go 1.21
"""
            (project_dir / "go.mod").write_text(go_mod.strip(), encoding='utf-8')
            print(f"  Created: go.mod")
        
        # Create requirements.txt for Python projects
        elif stack == "python":
            requirements_txt = """flask==2.3.0
pytest==7.4.0
"""
            (project_dir / "requirements.txt").write_text(requirements_txt.strip(), encoding='utf-8')
            print(f"  Created: requirements.txt")
        
        # Create package.json for React projects
        elif stack in ["react", "react_native"]:
            if stack == "react":
                package_json = {
                    "name": project_info['name'],
                    "version": "1.0.0",
                    "description": project_info['description'],
                    "main": "src/App.jsx",
                    "scripts": {
                        "start": "react-scripts start",
                        "build": "react-scripts build",
                        "test": "react-scripts test"
                    },
                    "dependencies": {
                        "react": "^18.2.0",
                        "react-dom": "^18.2.0",
                        "react-scripts": "5.0.1"
                    },
                    "devDependencies": {
                        "@testing-library/react": "^13.4.0",
                        "@testing-library/jest-dom": "^5.16.0"
                    }
                }
            else:  # React Native
                package_json = {
                    "name": project_info['name'],
                    "version": "1.0.0",
                    "description": project_info['description'],
                    "main": "index.js",
                    "scripts": {
                        "android": "react-native run-android",
                        "ios": "react-native run-ios",
                        "start": "react-native start",
                        "test": "jest"
                    },
                    "dependencies": {
                        "react": "^18.2.0",
                        "react-native": "^0.72.0"
                    },
                    "devDependencies": {
                        "@testing-library/react-native": "^12.0.0",
                        "jest": "^29.0.0"
                    }
                }
            
            (project_dir / "package.json").write_text(json.dumps(package_json, indent=2), encoding='utf-8')
            print(f"  Created: package.json")
            
            # Create src directory for React
            if stack == "react":
                (project_dir / "src").mkdir(exist_ok=True)
                print(f"  Created: src/ directory")

def detect_stack_automatically(project_desc: str) -> str:
        """Automatically detect stack from project description"""
        try:
            sys.path.append(str(Path(__file__).parent))
            from detect_stack import StackDetector
            
            detector = StackDetector(verbose=False)
            stack, recommendations = detector.detect_non_interactive(project_desc)
            return stack
        except Exception as e:
            print(f"Warning: Stack detection failed ({e}), falling back to node.js", file=sys.stderr)
            return "node"

def main():
    """Main execution"""
    if len(sys.argv) < 5:
        print("Usage: python setup-project-simple.py [tier] [stack] [project_name] [project_desc]")
        print("Tiers: mvp, core, enterprise")
        print("Stacks: node, react, flutter, go, python, react_native, auto")
        print("Use 'auto' for intelligent stack detection based on project_desc")
        return 1
    
    tier = sys.argv[1].lower()
    stack = sys.argv[2].lower()
    project_name = sys.argv[3]
    project_desc = sys.argv[4]
    
    if tier not in ["mvp", "core", "enterprise"]:
        print("Invalid tier. Use: mvp, core, or enterprise")
        return 1
    
    # Handle automatic stack detection
    if stack == "auto":
        stack = detect_stack_automatically(project_desc)
        print(f"Auto-detected stack: {stack.upper()}")
    
    valid_stacks = get_all_stacks()
    if stack not in valid_stacks:
        print(f"Invalid stack. Use: {', '.join(valid_stacks)}")
        return 1
    
    setup = SimpleProjectSetup()
    
    # Create project directory
    project_dir = Path.cwd() / project_name
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy templates
    project_info = {
        "name": project_name,
        "description": project_desc
    }
    
    setup.copy_template(tier, stack, project_info, project_dir)
    
    print(f"\nProject '{project_name}' created successfully!")
    print(f"Location: {project_dir}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
