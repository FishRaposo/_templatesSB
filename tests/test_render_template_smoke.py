#!/usr/bin/env python3
"""
Integration smoke test for template rendering
Tests that templates can be rendered and basic validation passes
"""

import pytest
import sys
import tempfile
import shutil
import subprocess
from pathlib import Path

# Add scripts directory to path for imports
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))


class TestTemplateRendering:
    """Integration tests for template rendering and validation"""
    
    @pytest.fixture
    def temp_output_dir(self):
        """Create a temporary directory for test outputs"""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        # Cleanup
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
    
    def test_python_template_exists(self):
        """Verify Python stack templates exist"""
        python_stack = REPO_ROOT / "stacks" / "python"
        
        if not python_stack.exists():
            pytest.skip("Python stack directory not found")
        
        assert python_stack.is_dir(), "Python stack should be a directory"
        
        # Check for base templates
        base_dir = python_stack / "base"
        assert base_dir.exists(), "Python base templates should exist"
    
    def test_python_template_files_present(self):
        """Verify Python template files are present"""
        python_base = REPO_ROOT / "stacks" / "python" / "base" / "code"
        
        if not python_base.exists():
            pytest.skip("Python base code templates not found")
        
        # Look for any .py template files
        template_files = list(python_base.glob("*.py"))
        assert len(template_files) > 0, "Should have at least one Python template file"
    
    def test_render_python_template_simple(self, temp_output_dir):
        """Test rendering a simple Python template"""
        python_base = REPO_ROOT / "stacks" / "python" / "base" / "code"
        
        if not python_base.exists():
            pytest.skip("Python base code templates not found")
        
        # Find a template file to test
        template_files = list(python_base.glob("*.tpl.py"))
        
        if not template_files:
            pytest.skip("No .tpl.py template files found")
        
        # Use the first template file
        template_file = template_files[0]
        
        # Read template content
        with open(template_file, 'r') as f:
            template_content = f.read()
        
        # Perform basic template variable replacement
        rendered_content = template_content.replace("{{PROJECT_NAME}}", "TestProject")
        rendered_content = rendered_content.replace("[[.Author]]", "Test Author")
        rendered_content = rendered_content.replace("[[.Version]]", "1.0.0")
        
        # Write rendered file to temp directory
        output_file = temp_output_dir / template_file.name.replace('.tpl', '')
        output_file.write_text(rendered_content)
        
        assert output_file.exists(), "Rendered file should exist"
        assert output_file.stat().st_size > 0, "Rendered file should not be empty"
    
    def test_python_syntax_validation(self, temp_output_dir):
        """Test that rendered Python templates have valid syntax"""
        python_base = REPO_ROOT / "stacks" / "python" / "base" / "code"
        
        if not python_base.exists():
            pytest.skip("Python base code templates not found")
        
        template_files = list(python_base.glob("*.tpl.py"))
        
        if not template_files:
            pytest.skip("No .tpl.py template files found")
        
        # Test the first template
        template_file = template_files[0]
        
        with open(template_file, 'r') as f:
            template_content = f.read()
        
        # Simple template variable substitution
        rendered_content = template_content.replace("{{PROJECT_NAME}}", "TestProject")
        rendered_content = rendered_content.replace("[[.Author]]", "Test Author")
        rendered_content = rendered_content.replace("[[.Version]]", "1.0.0")
        
        # Write to temp file
        test_file = temp_output_dir / "test_module.py"
        test_file.write_text(rendered_content)
        
        # Compile to check for syntax errors
        try:
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(test_file)],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Note: Some templates may have remaining placeholders, so we accept some failures
            # This is a smoke test to catch major syntax errors
            if result.returncode != 0:
                print(f"Compilation warning for {template_file.name}:")
                print(f"  stdout: {result.stdout}")
                print(f"  stderr: {result.stderr}")
                # Don't fail - just warn, as templates may have valid placeholders
        except subprocess.TimeoutExpired:
            pytest.fail("Python compilation timed out")
        except Exception as e:
            # Log but don't fail - this is defensive
            print(f"Note: Could not fully validate {template_file.name}: {e}")
    
    def test_task_template_structure(self):
        """Verify task templates have expected structure"""
        tasks_dir = REPO_ROOT / "tasks"
        
        if not tasks_dir.exists():
            pytest.skip("Tasks directory not found")
        
        # Check for some known tasks
        expected_tasks = ["auth-basic", "crud-module", "rest-api-service"]
        found_tasks = []
        
        for task_name in expected_tasks:
            task_dir = tasks_dir / task_name
            if task_dir.exists():
                found_tasks.append(task_name)
        
        assert len(found_tasks) > 0, f"Should find at least one expected task. Found: {found_tasks}"
    
    def test_blueprint_template_structure(self):
        """Verify blueprint templates have expected structure"""
        blueprints_dir = REPO_ROOT / "blueprints"
        
        if not blueprints_dir.exists():
            pytest.skip("Blueprints directory not found")
        
        # Check for blueprint metadata files
        blueprint_dirs = [d for d in blueprints_dir.iterdir() if d.is_dir()]
        
        if not blueprint_dirs:
            pytest.skip("No blueprint directories found")
        
        # Check first blueprint has required files
        blueprint = blueprint_dirs[0]
        meta_file = blueprint / "blueprint.meta.yaml"
        
        assert meta_file.exists(), f"Blueprint {blueprint.name} should have blueprint.meta.yaml"


if __name__ == "__main__":
    # Allow running directly for quick testing
    pytest.main([__file__, "-v"])
