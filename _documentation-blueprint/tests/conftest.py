"""Pytest configuration and shared fixtures."""

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def blueprint_dir():
    """Return the path to the documentation blueprint directory."""
    return Path(__file__).parent.parent.resolve()


@pytest.fixture
def sample_config():
    """Return a sample project configuration."""
    return {
        "project": {
            "name": "TestProject",
            "description": "A test project",
            "tagline": "Test project tagline",
            "repo_url": "https://github.com/test/testproject",
            "tier": "core",
            "stack": "python",
            "primary_language": "Python",
        },
        "license": {"name": "MIT"},
        "commands": {
            "install": "pip install -r requirements.txt",
            "run": "python main.py",
            "test": "pytest",
            "lint": "ruff check .",
            "build": "python -m build",
        },
        "features": ["Feature 1", "Feature 2", "Feature 3"],
        "tech_stack": ["Python 3.11", "FastAPI", "PostgreSQL"],
        "ai_tools": [],
        "components": [],
        "security": {"email": "security@test.com", "disclosure_delay_days": 7},
    }
