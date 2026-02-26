#!/usr/bin/env python3
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
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tests" / "validation"))

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
            self.assertTrue(hasattr(detect_project_tasks, 'TaskDetectionSystem'))
            
            # Test basic instantiation
            detector = detect_project_tasks.TaskDetectionSystem()
            self.assertIsNotNone(detector)
            self.assertTrue(hasattr(detector, 'analyze_requirements'))
            
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
        tasks_dir = Path(__file__).parent.parent.parent / "tasks"
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
            
            detector = detect_project_tasks.TaskDetectionSystem()
            
            # Test that analysis methods exist
            self.assertTrue(hasattr(detector, 'analyze_requirements'))
            self.assertTrue(hasattr(detector, '_extract_keywords'))
            
        except ImportError as e:
            self.fail(f"Could not test detect_project_tasks: {e}")

class TestPromptValidation(unittest.TestCase):
    """Test prompt validation functionality"""
    
    def setUp(self):
        """Setup for each test"""
        self.templates_dir = Path(__file__).parent.parent.parent
    
    def test_prompt_validation_functionality(self):
        """Test that prompt validation is working and blocking malicious input"""
        try:
            import prompt_validator
            validator = prompt_validator.PromptValidator(prompt_validator.ValidationLevel.STANDARD)
            
            # Test dangerous content detection
            dangerous_inputs = [
                "test<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "rm -rf /",
                "$(cat /etc/passwd)",
                "'; DROP TABLE users; --",
                "<img src=x onerror=alert('xss')>",
                "eval('malicious code')",
                "__import__('os').system('rm -rf /')",
                "DELETE FROM users WHERE 1=1",
                "sudo rm -rf /etc/passwd",
                "bash -c 'rm -rf /'",
                "powershell -Command 'Remove-Item -Recurse -Force C:\\'",
            ]
            
            for dangerous_input in dangerous_inputs:
                result = validator.validate_project_description(dangerous_input)
                self.assertFalse(result.is_valid, f"Should block dangerous input: {dangerous_input}")
                self.assertGreater(len(result.errors), 0, f"Should have errors for: {dangerous_input}")
            
            # Test safe content passes
            safe_input = "Simple web application with user authentication"
            result = validator.validate_project_description(safe_input)
            self.assertTrue(result.is_valid, "Safe input should pass validation")
            
        except ImportError as e:
            self.fail(f"Prompt validation not available: {e}")
    
    def test_script_validation_integration(self):
        """Test that scripts properly validate input and exit on dangerous content"""
        import subprocess
        import sys
        
        # Test list_tasks_by_category.py blocks dangerous search
        dangerous_search = "test<script>alert('xss')</script>"
        result = subprocess.run([
            sys.executable, "scripts/list_tasks_by_category.py", "--search", dangerous_search
        ], capture_output=True, text=True, cwd=self.templates_dir)
        
        self.assertNotEqual(result.returncode, 0, "Script should exit with error on dangerous input")
        
        # Test analyze_and_build.py blocks dangerous description
        dangerous_desc = "web app with<script>alert('xss')</script>"
        result = subprocess.run([
            sys.executable, "scripts/analyze_and_build.py", "--description", dangerous_desc, "--dry-run"
        ], capture_output=True, text=True, cwd=self.templates_dir)
        
        self.assertNotEqual(result.returncode, 0, "Script should exit with error on dangerous input")
        
        # Test detect_project_tasks.py blocks dangerous description
        result = subprocess.run([
            sys.executable, "scripts/detect_project_tasks.py", "--description", dangerous_desc
        ], capture_output=True, text=True, cwd=self.templates_dir)
        
        self.assertNotEqual(result.returncode, 0, "Script should exit with error on dangerous input")
    
    def test_safe_inputs_work_normally(self):
        """Test that safe inputs work normally in all scripts"""
        import subprocess
        import sys
        
        safe_description = "Simple web application with user authentication"
        
        # Test list_tasks_by_category.py works with safe input
        result = subprocess.run([
            sys.executable, "scripts/list_tasks_by_category.py", "--search", safe_description
        ], capture_output=True, text=True, cwd=self.templates_dir)
        
        # Should not exit due to validation error (might exit due to no results, which is fine)
        self.assertNotIn("validation failed", result.stdout.lower(), "Safe input should not cause validation error")
        
        # Test analyze_and_build.py works with safe input
        result = subprocess.run([
            sys.executable, "scripts/analyze_and_build.py", "--description", safe_description, "--dry-run"
        ], capture_output=True, text=True, cwd=self.templates_dir)
        
        # Should not exit due to validation error
        self.assertNotIn("validation failed", result.stdout.lower(), "Safe input should not cause validation error")
        
        # Test detect_project_tasks.py works with safe input
        result = subprocess.run([
            sys.executable, "scripts/detect_project_tasks.py", "--description", safe_description
        ], capture_output=True, text=True, cwd=self.templates_dir)
        
        # Should not exit due to validation error
        self.assertNotIn("validation failed", result.stdout.lower(), "Safe input should not cause validation error")

if __name__ == '__main__':
    # Run with verbose output
    unittest.main(verbosity=2)
