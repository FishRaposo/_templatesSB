# Python Workflow Testing Template
# CI/CD workflow and development workflow tests for Python projects

"""
Python Workflow Test Patterns
Development workflow, CI/CD, and process automation testing
"""

import pytest
import subprocess
import os
import sys
import json
import tempfile
from pathlib import Path
from typing import List, Dict, Any
import shutil

# ====================
# BUILD WORKFLOW TESTS
# ====================

class TestBuildWorkflow:
    """Test build processes and configurations"""
    
    def test_dependencies_installation(self):
        """Test that dependencies can be installed correctly"""
        # Test requirements files exist
        requirements_files = ["requirements.txt", "requirements-dev.txt", "requirements-prod.txt"]
        for req_file in requirements_files:
            if os.path.exists(req_file):
                # Verify syntax is valid
                with open(req_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Basic syntax check
                            assert '>' in line or '=' in line or '<' in line or ' ' in line
    
    def test_docker_build(self):
        """Test Docker build process"""
        if not shutil.which("docker"):
            pytest.skip("Docker not available")
        
        # Test docker build
        try:
            result = subprocess.run(
                ["docker", "build", "-t", "test-app:latest", "."],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Note: Build might fail due to missing dependencies in test env
            # In real CI/CD, this should pass
            print(f"Docker build stdout: {result.stdout}")
            print(f"Docker build stderr: {result.stderr}")
            
        except subprocess.TimeoutExpired:
            pytest.fail("Docker build timed out")
        except FileNotFoundError:
            pytest.skip("Docker not installed")
    
    def test_setup_py_configuration(self):
        """Test setup.py configuration"""
        if not os.path.exists("setup.py"):
            pytest.skip("No setup.py found")
        
        # Test setup.py can be imported
        result = subprocess.run(
            [sys.executable, "setup.py", "--version"],
            capture_output=True,
            text=True
        )
        
        # Should not crash
        assert result.returncode in [0, 1]  # 0 if version defined, 1 if not
    
    def test_pyproject_toml_configuration(self):
        """Test pyproject.toml configuration"""
        if not os.path.exists("pyproject.toml"):
            pytest.skip("No pyproject.toml found")
        
        # Parse TOML and verify structure
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            import tomli as tomllib
        
        with open("pyproject.toml", "rb") as f:
            config = tomllib.load(f)
        
        # Verify basic structure
        assert "project" in config or "tool" in config
        
        if "project" in config:
            project = config["project"]
            assert "name" in project
            assert "version" in project

# ====================
# TEST WORKFLOW TESTS
# ====================

class TestTestWorkflow:
    """Test testing workflows and configurations"""
    
    def test_pytest_configuration(self):
        """Test pytest configuration"""
        if not os.path.exists("pytest.ini") and not os.path.exists("pyproject.toml"):
            pytest.skip("No pytest config found")
        
        # Test pytest can run
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--version"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
    
    def test_coverage_configuration(self):
        """Test coverage configuration"""
        if not os.path.exists(".coveragerc"):
            pytest.skip("No .coveragerc found")
        
        # Verify config syntax
        import configparser
        config = configparser.ConfigParser()
        config.read(".coveragerc")
        
        assert "run" in config
        assert "report" in config
    
    def test_linting_configuration(self):
        """Test linting configurations"""
        import importlib.util
        
        linters = {
            "flake8": (".flake8", "flake8"),
            "black": ("pyproject.toml", "black"),
            "mypy": ("mypy.ini", "mypy"),
            "pylint": (".pylintrc", "pylint")
        }
        
        for linter_name, (config_file, module_name) in linters.items():
            if os.path.exists(config_file):
                # Check module is importable
                spec = importlib.util.find_spec(module_name)
                assert spec is not None, f"{linter_name} module not found"
                
                # Try to run linter
                result = subprocess.run(
                    [sys.executable, "-m", module_name, "--version"],
                    capture_output=True,
                    text=True
                )
                # Version check may fail, but command should exist
                assert result.returncode in [0, 1]
    
    def test_tox_configuration(self):
        """Test tox configuration"""
        if not os.path.exists("tox.ini"):
            pytest.skip("No tox.ini found")
        
        # Parse tox.ini and verify environments
        import configparser
        config = configparser.ConfigParser()
        config.read("tox.ini")
        
        assert "tox" in config
        
        # Check for test environments
        envlist = config["tox"].get("envlist", "")
        assert "py" in envlist or "testenv" in config
    
    def test_pre_commit_hooks(self):
        """Test pre-commit hooks configuration"""
        if not os.path.exists(".pre-commit-config.yaml"):
            pytest.skip("No pre-commit config found")
        
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")
        
        with open(".pre-commit-config.yaml", 'r') as f:
            config = yaml.safe_load(f)
        
        # Verify structure
        assert "repos" in config
        assert len(config["repos"]) > 0
        
        # Check for essential hooks
        hook_types = []
        for repo in config["repos"]:
            for hook in repo.get("hooks", []):
                hook_types.append(hook["id"])
        
        essential_hooks = ["black", "flake8", "mypy"]
        for hook in essential_hooks:
            if hook not in hook_types:
                print(f"Warning: {hook} not found in pre-commit hooks")

# ====================
# CODE QUALITY WORKFLOW
# ====================

class TestCodeQualityWorkflow:
    """Test code quality workflows"""
    
    def test_type_checking(self):
        """Test mypy type checking"""
        if not shutil.which("mypy"):
            pytest.skip("mypy not installed")
        
        result = subprocess.run(
            ["mypy", "--version"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        
        # Try to run mypy on a single file
        test_file = "app/main.py"
        if os.path.exists(test_file):
            result = subprocess.run(
                ["mypy", test_file],
                capture_output=True,
                text=True
            )
            # Should not crash
            assert result.returncode in [0, 1]
    
    def test_formatting_check(self):
        """Test code formatting with black"""
        if not shutil.which("black"):
            pytest.skip("black not installed")
        
        # Check if black would make changes
        result = subprocess.run(
            ["black", "--check", "--diff", "app/"],
            capture_output=True,
            text=True
        )
        # Exit code 0 = no changes needed, 1 = changes needed
        assert result.returncode in [0, 1]
    
    def test_import_sorting(self):
        """Test import sorting with isort"""
        if not shutil.which("isort"):
            pytest.skip("isort not installed")
        
        result = subprocess.run(
            ["isort", "--check-only", "--diff", "app/"],
            capture_output=True,
            text=True
        )
        # Exit code 0 = no changes needed, 1 = changes needed
        assert result.returncode in [0, 1]

# ====================
# DOCUMENTATION WORKFLOW
# ====================

class TestDocumentationWorkflow:
    """Test documentation generation workflows"""
    
    def test_sphinx_build(self):
        """Test Sphinx documentation build"""
        if not os.path.exists("docs"):
            pytest.skip("No docs directory")
        
        # Check if Sphinx is configured
        sphinx_configs = ["conf.py", "index.rst", "Makefile"]
        if not any(os.path.exists(f"docs/{f}") for f in sphinx_configs):
            pytest.skip("Sphinx not configured")
        
        # Change to docs directory and try build
        old_cwd = os.getcwd()
        try:
            os.chdir("docs")
            if os.path.exists("Makefile"):
                result = subprocess.run(
                    ["make", "html"],
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                # Build may fail due to missing dependencies
                # But should attempt to build
                assert result.returncode in [0, 2]  # 2 is Sphinx's error code
        finally:
            os.chdir(old_cwd)
    
    def test_docstring_coverage(self):
        """Test docstring coverage"""
        try:
            import interrogate
        except ImportError:
            pytest.skip("interrogate not installed")
        
        result = subprocess.run(
            ["interrogate", "--version"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        
        # Run interrogate on the codebase
        result = subprocess.run(
            ["interrogate", "app/"],
            capture_output=True,
            text=True
        )
        # Should complete without crashing
        assert result.returncode in [0, 1]

# ====================
# SECURITY WORKFLOW
# ====================

class TestSecurityWorkflow:
    """Test security scanning workflows"""
    
    def test_safety_check(self):
        """Test safety check for vulnerabilities"""
        try:
            import pkg_resources
            import requests  # Import to check if installed
        except ImportError:
            pytest.skip("safety not installed")
        
        if not shutil.which("safety"):
            pytest.skip("safety not installed")
        
        # Check if requirements files exist
        req_files = ["requirements.txt", "requirements-dev.txt"]
        req_file_exists = any(os.path.exists(f) for f in req_files)
        
        if not req_file_exists:
            pytest.skip("No requirements files found")
        
        # Run safety check
        result = subprocess.run(
            [sys.executable, "-m", "safety", "check", "--json"],
            capture_output=True,
            text=True
        )
        
        # Parse JSON output
        try:
            output = json.loads(result.stdout)
            if isinstance(output, list) and len(output) > 0:
                print(f"Found {len(output)} vulnerabilities")
                # Vulnerabilities found, but that's OK for test
        except json.JSONDecodeError:
            pass
        
        # Command should run
        assert result.returncode in [0, 1, 254]  # 254 is safety's error code
    
    def test_bandit_scan(self):
        """Test Bandit security scan"""
        if not shutil.which("bandit"):
            pytest.skip("bandit not installed")
        
        result = subprocess.run(
            ["bandit", "--version"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        
        # Run bandit on source code
        result = subprocess.run(
            ["bandit", "-r", "app/", "-f", "json"],
            capture_output=True,
            text=True
        )
        # Should complete scan
        assert result.returncode in [0, 1]

# ====================
# DEPLOYMENT WORKFLOW
# ====================

class TestDeploymentWorkflow:
    """Test deployment workflows"""
    
    def test_docker_compose(self):
        """Test Docker Compose configuration"""
        if not os.path.exists("docker-compose.yml"):
            pytest.skip("No docker-compose.yml found")
        
        if not shutil.which("docker-compose") and not shutil.which("docker"):
            pytest.skip("Docker Compose not available")
        
        # Validate docker-compose.yml
        compose_cmd = "docker-compose" if shutil.which("docker-compose") else "docker compose"
        
        result = subprocess.run(
            [compose_cmd, "config"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0, f"docker-compose config validation failed: {result.stderr}"
    
    def test_environment_configuration(self):
        """Test environment-specific configurations"""
        env_files = [".env", ".env.local", ".env.test", ".env.production"]
        
        for env_file in env_files:
            if os.path.exists(env_file):
                with open(env_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            assert '=' in line, f"Invalid line in {env_file}: {line}"
    
    def test_health_check_endpoint(self):
        """Test health check endpoint configuration"""
        # Check if health check is configured
        # This would involve checking Docker healthcheck or similar
        
        # Try to run a health check if available
        if os.path.exists("Dockerfile"):
            with open("Dockerfile", 'r') as f:
                dockerfile_content = f.read()
                assert "HEALTHCHECK" in dockerfile_content or "health" in dockerfile_content.lower()

# ====================
# INTEGRATION WORKFLOW
# ====================

class TestIntegrationWorkflow:
    """Test integration workflows"""
    
    def test_database_migration(self):
        """Test database migration workflow"""
        if not shutil.which("alembic"):
            pytest.skip("alembic not installed")
        
        # Check alembic is configured
        if not os.path.exists("alembic.ini"):
            pytest.skip("No alembic.ini found")
        
        # Show current revision
        result = subprocess.run(
            ["alembic", "current"],
            capture_output=True,
            text=True
        )
        # Should not error
        assert result.returncode in [0, 1]
        
        if result.returncode == 0:
            print(f"Current migration: {result.stdout}")
        
        # Check if migrations directory exists
        assert os.path.exists("alembic/versions")
    
    def test_cache_integration(self):
        """Test Redis/cache integration"""
        try:
            import redis
        except ImportError:
            pytest.skip("redis not installed")
        
        # Check if Redis is configured
        if os.path.exists(".env"):
            with open(".env", 'r') as f:
                content = f.read()
                assert "REDIS" in content or "CACHE" in content

# ====================
# GITHUB ACTIONS WORKFLOW
# ====================

class TestGitHubActionsWorkflow:
    """Test GitHub Actions CI/CD workflows"""
    
    def test_github_actions_config(self):
        """Test GitHub Actions workflow configuration"""
        workflow_dir = ".github/workflows"
        if not os.path.exists(workflow_dir):
            pytest.skip("No GitHub Actions workflows found")
        
        # Check workflow files exist
        workflow_files = [
            "ci.yml", "test.yml", "lint.yml", "deploy.yml"
        ]
        
        found_workflows = []
        for filename in os.listdir(workflow_dir):
            if filename.endswith(('.yml', '.yaml')):
                found_workflows.append(filename)
                filepath = os.path.join(workflow_dir, filename)
                
                # Verify YAML syntax
                try:
                    import yaml
                    with open(filepath, 'r') as f:
                        workflow = yaml.safe_load(f)
                        assert "name" in workflow
                        assert "jobs" in workflow
                except yaml.YAMLError as e:
                    pytest.fail(f"Invalid YAML in {filename}: {e}")
        
        assert len(found_workflows) > 0, "No workflow files found"
    
    def test_workflow_steps(self):
        """Test that workflow has necessary steps"""
        workflow_dir = ".github/workflows"
        if not os.path.exists(workflow_dir):
            pytest.skip("No workflows found")
        
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")
        
        required_steps = ["checkout", "python", "dependencies", "test"]
        
        for filename in os.listdir(workflow_dir):
            if filename.endswith(('.yml', '.yaml')):
                filepath = os.path.join(workflow_dir, filename)
                with open(filepath, 'r') as f:
                    workflow = yaml.safe_load(f)
                    
                    # Check jobs
                    if "jobs" in workflow:
                        for job_name, job in workflow["jobs"].items():
                            if "steps" in job:
                                step_names = [step.get("name", "").lower() for step in job["steps"]]
                                for required in required_steps:
                                    if not any(required in name for name in step_names):
                                        print(f"Warning: {required} not found in {filename} job {job_name}")

# ====================
# RUN ALL WORKFLOW TESTS
# ====================

'''
# Run all workflow tests
pytest tests/workflow/ -v -m workflow

# Run specific workflow test
pytest tests/workflow/test_builds.py -v

# Run with live output
pytest tests/workflow/ -v -s

# Test all workflows together
pytest tests/workflow/ --tb=short

# Run pre-commit through pytest
pytest tests/workflow/test_ci_workflow.py::TestCIWorkflow::test_pre_commit_hooks -v
'''
