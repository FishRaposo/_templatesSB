#!/usr/bin/env python3
"""
Automatic Test Generation Script
Generates comprehensive unit tests for core Python scripts
Protects automation infrastructure reliability
"""

import ast
import inspect
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Tuple
import re

# Resolve project root for path consistency
PROJECT_ROOT = Path(__file__).parent.parent.parent

class TestGenerator:
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent
        self.scripts_dir = self.templates_dir / "scripts"
        self.tests_dir = self.templates_dir / "tests" / "unit"
        self.core_scripts = [
            "analyze_and_build.py",
            "validate_templates.py", 
            "detect_project_tasks.py",
            "sync_documentation.py",
            "list_tasks_by_category.py"
        ]
        
    def ensure_tests_dir(self):
        """Ensure tests directory exists"""
        self.tests_dir.mkdir(parents=True, exist_ok=True)
        
    def analyze_script(self, script_path: Path) -> Dict[str, Any]:
        """Analyze Python script to extract functions and classes"""
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            print(f"❌ Syntax error in {script_path}: {e}")
            return {}
        
        functions = []
        classes = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Get function signature
                args = [arg.arg for arg in node.args.args]
                defaults = len(node.args.defaults)
                
                # Get docstring
                docstring = ast.get_docstring(node) or ""
                
                functions.append({
                    'name': node.name,
                    'args': args,
                    'defaults': defaults,
                    'docstring': docstring,
                    'is_private': node.name.startswith('_'),
                    'lineno': node.lineno
                })
            elif isinstance(node, ast.ClassDef):
                # Get class methods
                methods = []
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        method_args = [arg.arg for arg in item.args.args]
                        if method_args and method_args[0] == 'self':
                            method_args = method_args[1:]  # Remove 'self'
                        
                        methods.append({
                            'name': item.name,
                            'args': method_args,
                            'docstring': ast.get_docstring(item) or ""
                        })
                
                classes.append({
                    'name': node.name,
                    'methods': methods,
                    'docstring': ast.get_docstring(node) or ""
                })
        
        return {
            'functions': functions,
            'classes': classes,
            'imports': self.extract_imports(content)
        }
    
    def extract_imports(self, content: str) -> List[str]:
        """Extract import statements from script"""
        imports = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('import ') or line.startswith('from '):
                imports.append(line)
        return imports
    
    def generate_function_test(self, func: Dict[str, Any], script_name: str) -> str:
        """Generate test code for a function"""
        func_name = func['name']
        args = func['args']
        docstring = func['docstring']
        
        # Skip private functions unless specifically requested
        if func['is_private']:
            return f"    # Skipping private function: {func_name}\n"
        
        test_code = f"    def test_{func_name}(self):\n"
        test_code += f'        """Test {func_name} function"""\n'
        
        if docstring:
            test_code += f"        # TODO: Implement based on docstring: {docstring[:50]}...\n"
        
        # Generate basic test structure based on arguments
        if args:
            test_code += "        # Arrange\n"
            for arg in args:
                if arg in ['data', 'content', 'text']:
                    test_code += f"        {arg} = 'test_data'\n"
                elif arg in ['path', 'file_path', 'directory']:
                    test_code += f"        {arg} = PROJECT_ROOT / 'test_path'\n"
                elif arg in ['config', 'settings', 'options']:
                    test_code += f"        {arg} = {{'key': 'value'}}\n"
                elif arg in ['debug', 'verbose', 'dry_run']:
                    test_code += f"        {arg} = False\n"
                else:
                    test_code += f"        {arg} = 'test_value'\n"
            
            test_code += "\n        # Act & Assert\n"
            test_code += "        # TODO: Add actual test implementation\n"
            test_code += "        with self.assertRaises(NotImplementedError):\n"
            test_code += "            self.fail('Test not implemented yet')\n"
        else:
            test_code += "        # TODO: Add actual test implementation\n"
            test_code += "        with self.assertRaises(NotImplementedError):\n"
            test_code += "            self.fail('Test not implemented yet')\n"
        
        test_code += "\n"
        return test_code
    
    def generate_class_test(self, cls: Dict[str, Any], script_name: str) -> str:
        """Generate test code for a class"""
        class_name = cls['name']
        methods = cls['methods']
        
        test_code = f"    class Test{class_name}:\n"
        test_code += f'        """Test {class_name} class"""\n\n'
        
        # Generate setup method if class has initialization
        test_code += "        def setup_method(self):\n"
        test_code += "            \"\"\"Setup for each test method\"\"\"\n"
        test_code += "            # TODO: Initialize class instance\n"
        test_code += "            pass\n\n"
        
        # Generate test methods
        for method in methods:
            if method['name'].startswith('_'):
                continue
                
            method_name = method['name']
            method_args = method['args']
            
            test_code += f"        def test_{method_name}(self):\n"
            test_code += f'            """Test {method_name} method"""\n'
            
            if method['docstring']:
                test_code += f"            # TODO: Implement based on docstring: {method['docstring'][:50]}...\n"
            
            test_code += "            # TODO: Add actual test implementation\n"
            test_code += "            with self.assertRaises(NotImplementedError):\n"
            test_code += "                self.fail('Test not implemented yet')\n\n"
        
        return test_code
    
    def generate_test_file(self, script_name: str, analysis: Dict[str, Any]) -> str:
        """Generate complete test file for a script"""
        module_name = script_name.replace('.py', '')
        class_name = module_name.replace('_', ' ').title().replace(' ', '')
        
        # Generate header
        test_content = f'''#!/usr/bin/env python3
"""
Auto-generated unit tests for {module_name}
Generated by generate_tests.py on {self.get_timestamp()}
TODO: Review and implement actual test logic
"""

import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

try:
    import {module_name}
except ImportError as e:
    print(f"Warning: Could not import {{module_name}}: {{e}}")
    {module_name} = None

'''
        
        # Generate main test class
        test_content += f"class Test{class_name}(unittest.TestCase):\n"
        test_content += f'    """Test suite for {module_name}"""\n\n'
        
        # Generate setup method
        test_content += '''    def setUp(self):
        """Setup for each test"""
        # TODO: Add common setup logic
        pass

    def tearDown(self):
        """Cleanup after each test"""
        # TODO: Add cleanup logic
        pass

'''
        
        # Generate function tests
        for func in analysis['functions']:
            test_content += self.generate_function_test(func, script_name)
        
        # Generate class tests
        for cls in analysis['classes']:
            test_content += self.generate_class_test(cls, script_name)
        
        # Generate integration test placeholder
        test_content += '''
    def test_integration_smoke(self):
        """Smoke test for basic functionality"""
        # TODO: Add basic integration test
        if ''' + module_name + ''' is None:
            self.skipTest("Module not available")
        else:
            with self.assertRaises(NotImplementedError):
                self.fail("Integration test not implemented yet")

'''
        
        # Generate main section
        test_content += '''if __name__ == '__main__':
    unittest.main()
'''
        
        return test_content
    
    def generate_integration_tests(self) -> str:
        """Generate integration tests for the pipeline"""
        integration_content = '''#!/usr/bin/env python3
"""
Integration tests for the template system pipeline
Tests end-to-end functionality: description → detection → validation → building
"""

import unittest
import tempfile
import shutil
import yaml
from pathlib import Path
import sys

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

try:
    import detect_project_tasks
    import analyze_and_build
    import validate_templates
except ImportError as e:
    print(f"Warning: Could not import modules: {e}")

class TestPipelineIntegration(unittest.TestCase):
    """Test the complete template system pipeline"""
    
    def setUp(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.test_description = "Simple web API with user authentication"
    
    def tearDown(self):
        """Cleanup test environment"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_task_detection_basic(self):
        """Test basic task detection functionality"""
        # TODO: Implement task detection test
        with self.assertRaises(NotImplementedError):
            self.fail("Integration test not implemented yet")
    
    def test_validation_system(self):
        """Test template validation system"""
        # TODO: Implement validation test
        with self.assertRaises(NotImplementedError):
            self.fail("Integration test not implemented yet")
    
    def test_documentation_sync(self):
        """Test documentation synchronization"""
        # TODO: Implement documentation sync test
        with self.assertRaises(NotImplementedError):
            self.fail("Integration test not implemented yet")
    
    def test_end_to_end_pipeline(self):
        """Test complete pipeline from description to build"""
        # TODO: Implement end-to-end test
        with self.assertRaises(NotImplementedError):
            self.fail("Integration test not implemented yet")

if __name__ == '__main__':
    unittest.main()
'''
        
        return integration_content
    
    def get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def generate_all_tests(self, force: bool = False) -> bool:
        """Generate tests for all core scripts"""
        print("🧪 Generating Automatic Tests")
        print("=" * 40)
        
        self.ensure_tests_dir()
        
        success = True
        
        for script_name in self.core_scripts:
            script_path = self.scripts_dir / script_name
            test_path = self.tests_dir / f"test_{script_name}"
            
            if not script_path.exists():
                print(f"⚠️  Script not found: {script_name}")
                continue
            
            # Check if test already exists
            if test_path.exists() and not force:
                print(f"⏭️  Test already exists: {test_path.name} (use --force to overwrite)")
                continue
            
            print(f"📝 Analyzing {script_name}...")
            
            # Analyze script
            analysis = self.analyze_script(script_path)
            if not analysis:
                print(f"❌ Failed to analyze {script_name}")
                success = False
                continue
            
            print(f"   Found {len(analysis['functions'])} functions, {len(analysis['classes'])} classes")
            
            # Generate test file
            test_content = self.generate_test_file(script_name, analysis)
            
            # Write test file
            with open(test_path, 'w', encoding='utf-8') as f:
                f.write(test_content)
            
            print(f"✅ Generated: {test_path.name}")
        
        # Generate integration tests
        integration_path = self.tests_dir  /  "test_integration.py"
        if not integration_path.exists() or force:
            print("📝 Generating integration tests...")
            integration_content = self.generate_integration_tests()
            with open(integration_path, 'w', encoding='utf-8') as f:
                f.write(integration_content)
            print(f"✅ Generated: {integration_path.name}")
        
        # Generate pytest configuration
        pytest_config = self.tests_dir  /  "pytest.ini"
        if not pytest_config.exists():
            pytest_content = '''[tool:pytest]
testpaths = .
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
markers =
    slow: marks tests as slow
    integration: marks tests as integration tests
    unit: marks tests as unit tests
'''
            with open(pytest_config, 'w', encoding='utf-8') as f:
                f.write(pytest_content)
            print("✅ Generated: pytest.ini")
        
        # Generate requirements file for testing
        requirements_path = self.tests_dir  /  "requirements.txt"
        if not requirements_path.exists():
            requirements_content = '''pytest>=7.0.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0
coverage>=7.0.0
'''
            with open(requirements_path, 'w', encoding='utf-8') as f:
                f.write(requirements_content)
            print("✅ Generated: requirements.txt")
        
        if success:
            print("\n🎉 Test generation completed!")
            print(f"📁 Tests generated in: {self.tests_dir}")
            print("\n📋 Next Steps:")
            print("1. Review generated tests and implement actual test logic")
            print("2. Install test dependencies: pip install -r tests/requirements.txt")
            print("3. Run tests: pytest tests/ -v")
            print("4. Add to CI/CD pipeline for automated testing")
        else:
            print("\n❌ Some test generation failed")
        
        return success

def main():
    """Main CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate automatic tests for core scripts')
    parser.add_argument('--force', '-f', action='store_true',
                       help='Overwrite existing test files')
    parser.add_argument('--script', '-s', metavar='SCRIPT_NAME',
                       help='Generate tests for specific script only')
    
    args = parser.parse_args()
    
    generator = TestGenerator()
    
    if args.script:
        # Generate tests for specific script
        script_path = generator.scripts_dir / args.script
        if not script_path.exists():
            print(f"❌ Script not found: {args.script}")
            sys.exit(1)
        
        # TODO: Implement single script generation
        print("Single script generation not yet implemented")
        sys.exit(1)
    else:
        # Generate all tests
        success = generator.generate_all_tests(force=args.force)
        
        if not success:
            sys.exit(1)

if __name__ == "__main__":
    main()
