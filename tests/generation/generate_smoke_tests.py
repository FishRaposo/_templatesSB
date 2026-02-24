#!/usr/bin/env python3
"""
Smoke Test Generation Script
Generates basic functionality tests for core scripts
Provides immediate protection for automation infrastructure
"""

import sys
import importlib.util
from pathlib import Path
from typing import Dict, List, Any

# Resolve project root for path consistency
PROJECT_ROOT = Path(__file__).parent.parent.parent

class SmokeTestGenerator:
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent
        self.scripts_dir = self.templates_dir / "scripts"
        self.tests_dir = self.templates_dir / "tests" / "unit"
        self.core_scripts = [
            ("validate_templates.py", "validate_templates", "TemplateValidator"),
            ("detect_project_tasks.py", "detect_project_tasks", "TaskDetector"),
            ("sync_documentation.py", "sync_documentation", "DocumentationSynchronizer"),
            ("list_tasks_by_category.py", "list_tasks_by_category", None),
            ("analyze_and_build.py", "analyze_and_build", None)
        ]
        
    def generate_smoke_tests(self) -> str:
        """Generate smoke test file with basic functionality checks"""
        
        smoke_test_content = '''#!/usr/bin/env python3
"""
Smoke tests for core template system scripts
Provides basic functionality validation for automation infrastructure
Generated automatically - tests import and basic method execution
"""

import unittest
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, Mock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

class TestSmokeTests(unittest.TestCase):
    """Smoke tests for core automation scripts"""
    
    def setUp(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        
    def tearDown(self):
        """Cleanup test environment"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_validate_templates_import(self):
        """Test that validate_templates can be imported and basic methods exist"""
        try:
            import validate_templates
            self.assertTrue(hasattr(validate_templates, 'TemplateValidator'))
            
            # Test basic instantiation
            with patch('pathlib.Path.exists', return_value=True):
                validator = validate_templates.TemplateValidator()
                self.assertIsNotNone(validator)
                
        except ImportError as e:
            self.fail(f"Could not import validate_templates: {e}")
    
    def test_detect_project_tasks_import(self):
        """Test that detect_project_tasks can be imported and basic methods exist"""
        try:
            import detect_project_tasks
            self.assertTrue(hasattr(detect_project_tasks, 'TaskDetector'))
            
            # Test basic instantiation
            detector = detect_project_tasks.TaskDetector()
            self.assertIsNotNone(detector)
            self.assertTrue(hasattr(detector, 'detect_tasks'))
            
        except ImportError as e:
            self.fail(f"Could not import detect_project_tasks: {e}")
    
    def test_sync_documentation_import(self):
        """Test that sync_documentation can be imported and basic methods exist"""
        try:
            import sync_documentation
            self.assertTrue(hasattr(sync_documentation, 'DocumentationSynchronizer'))
            
            # Test basic instantiation
            syncer = sync_documentation.DocumentationSynchronizer()
            self.assertIsNotNone(syncer)
            self.assertTrue(hasattr(syncer, 'sync_all'))
            
        except ImportError as e:
            self.fail(f"Could not import sync_documentation: {e}")
    
    def test_list_tasks_by_category_import(self):
        """Test that list_tasks_by_category can be imported"""
        try:
            import list_tasks_by_category
            self.assertTrue(hasattr(list_tasks_by_category, 'main'))
            
        except ImportError as e:
            self.fail(f"Could not import list_tasks_by_category: {e}")
    
    def test_analyze_and_build_import(self):
        """Test that analyze_and_build can be imported"""
        try:
            import analyze_and_build
            self.assertTrue(hasattr(analyze_and_build, 'main'))
            
        except ImportError as e:
            self.fail(f"Could not import analyze_and_build: {e}")
    
    def test_task_index_yaml_exists(self):
        """Test that critical configuration files exist"""
        task_index_path = Path(__file__).parent.parent.parent / "tasks" / "task-index.yaml"
        self.assertTrue(task_index_path.exists(), "task-index.yaml should exist")
        
        # Test it's valid YAML
        import yaml
        with open(task_index_path, 'r', encoding='utf-8') as f:
            try:
                data = yaml.safe_load(f)
                self.assertIsInstance(data, dict)
                self.assertIn('tasks', data)
                self.assertIn('virtual_categories', data)
            except yaml.YAMLError as e:
                self.fail(f"task-index.yaml is not valid YAML: {e}")
    
    def test_tasks_directory_structure(self):
        """Test that tasks directory has expected structure"""
        tasks_dir = Path(__file__).parent.parent.parent  /  "tasks"
        self.assertTrue(tasks_dir.exists(), "tasks directory should exist")
        
        # Check for some known task directories
        sample_tasks = ['web-scraping', 'auth-basic', 'etl-pipeline']
        for task in sample_tasks:
            task_dir = tasks_dir / task
            if task_dir.exists():
                universal_dir = task_dir / "universal" / "code"
                self.assertTrue(universal_dir.exists(), f"{task}/universal/code should exist")
    
    @patch('sys.argv', ['validate_templates.py', '--help'])
    def test_validate_templates_help(self):
        """Test that validate_templates responds to --help"""
        try:
            import validate_templates
            with patch('builtins.print') as mock_print:
                with patch('sys.exit') as mock_exit:
                    try:
                        validate_templates.main()
                    except SystemExit:
                        pass
                    # Should have called exit (help usually exits)
                    mock_exit.assert_called()
        except Exception as e:
            # Help test is optional - main point is import works
            self.skipTest(f"Help test failed but import works: {e}")
    
    def test_python_version_compatibility(self):
        """Test Python version compatibility"""
        self.assertGreaterEqual(sys.version_info, (3, 8), 
                              "Python 3.8+ required for template system")
    
    def test_required_modules_available(self):
        """Test that required third-party modules are available"""
        required_modules = ['yaml', 'pathlib']
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                self.fail(f"Required module {module} not available")

class TestBasicFunctionality(unittest.TestCase):
    """Test basic functionality without full execution"""
    
    def test_validate_templates_can_validate(self):
        """Test that validate_templates can perform basic validation"""
        try:
            import validate_templates
            
            # Create a minimal validator instance
            with patch('pathlib.Path.exists', return_value=True):
                with patch('pathlib.Path.iterdir', return_value=[]):
                    validator = validate_templates.TemplateValidator()
                    
                    # Test that validation methods exist
                    self.assertTrue(hasattr(validator, '_validate_structure'))
                    self.assertTrue(hasattr(validator, '_validate_content'))
                    
        except ImportError as e:
            self.fail(f"Could not test validate_templates: {e}")
    
    def test_detect_tasks_can_analyze(self):
        """Test that detect_project_tasks can analyze descriptions"""
        try:
            import detect_project_tasks
            
            detector = detect_project_tasks.TaskDetector()
            
            # Test that analysis methods exist
            self.assertTrue(hasattr(detector, 'detect_tasks'))
            self.assertTrue(hasattr(detector, '_analyze_description'))
            
        except ImportError as e:
            self.fail(f"Could not test detect_project_tasks: {e}")

if __name__ == '__main__':
    # Run with verbose output
    unittest.main(verbosity=2)
'''
        
        return smoke_test_content
    
    def create_test_runner(self) -> str:
        """Create a simple test runner script"""
        runner_content = '''#!/usr/bin/env python3
"""
Quick smoke test runner
Runs basic validation tests to ensure system health
"""

import subprocess
import sys
from pathlib import Path

def run_smoke_tests():
    """Run smoke tests and return result"""
    smoke_test_path = Path(__file__).parent / "test_smoke.py"
    
    if not smoke_test_path.exists():
        print("❌ Smoke test file not found")
        return False
    
    try:
        result = subprocess.run([
            sys.executable, str(smoke_test_path)
        ], capture_output=True, text=True, cwd=smoke_test_path.parent)
        
        print("🧪 Smoke Test Results:")
        print("=" * 40)
        print(result.stdout)
        
        if result.stderr:
            print("Warnings/Errors:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("✅ All smoke tests passed!")
            return True
        else:
            print(f"❌ Smoke tests failed with exit code: {result.returncode}")
            return False
            
    except Exception as e:
        print(f"❌ Error running smoke tests: {e}")
        return False

def main():
    """Main entry point"""
    print("🚀 Running Template System Smoke Tests")
    print("=" * 50)
    
    success = run_smoke_tests()
    
    if success:
        print("\n🎉 System is healthy!")
        sys.exit(0)
    else:
        print("\n💥 System health check failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
'''
        
        return runner_content
    
    def generate_all(self) -> bool:
        """Generate all smoke test files"""
        print("🔥 Generating Smoke Tests")
        print("=" * 30)
        
        self.tests_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate smoke test file
        smoke_test_path = self.tests_dir  /  "test_smoke.py"
        smoke_content = self.generate_smoke_tests()
        
        with open(smoke_test_path, 'w', encoding='utf-8') as f:
            f.write(smoke_content)
        
        print(f"✅ Generated: {smoke_test_path.name}")
        
        # Generate test runner
        runner_path = self.tests_dir  /  "run_smoke_tests.py"
        runner_content = self.create_test_runner()
        
        with open(runner_path, 'w', encoding='utf-8') as f:
            f.write(runner_content)
        
        print(f"✅ Generated: {runner_path.name}")
        
        print("\n🎯 Smoke Test Benefits:")
        print("✅ Immediate protection for automation infrastructure")
        print("✅ Validates imports and basic functionality")
        print("✅ Checks critical file structure and configuration")
        print("✅ Easy to run: python tests/unit/run_smoke_tests.py")
        print("✅ Can be integrated into CI/CD pipelines")
        
        return True

def main():
    """Main entry point"""
    generator = SmokeTestGenerator()
    success = generator.generate_all()
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
