"""Tests for template rendering."""

import sys
from pathlib import Path

import pytest
import yaml


class TestTemplateFiles:
    """Tests for template files exist and are valid."""

    def test_all_templates_exist(self, blueprint_dir):
        """Test all template files exist."""
        templates_dir = blueprint_dir / "templates"

        required_templates = [
            "AGENTS.md.tpl.md",
            "CHANGELOG.md.tpl.md",
            "README.md.tpl.md",
            "TODO.md.tpl.md",
            "QUICKSTART.md.tpl.md",
            "CONTRIBUTING.md.tpl.md",
            "SECURITY.md.tpl.md",
            "WORKFLOW.md.tpl.md",
            "CODE_OF_CONDUCT.md.tpl.md",
            "LICENSE.md.tpl.md",
            "EVALS.md.tpl.md",
            "DOCUMENTATION-OVERVIEW.md.tpl.md",
            "SYSTEM-MAP.md.tpl.md",
            "PROMPT-VALIDATION.md.tpl.md",
            "AI-TOOL.md.tpl.md",
            "memory/graph.md.tpl.md",
            "memory/context.md.tpl.md",
            "github/PULL_REQUEST_TEMPLATE.md",
            "github/CODEOWNERS",
            "github/config.yml",
            "github/bug_report.md",
            "github/feature_request.md",
        ]

        for template in required_templates:
            template_path = templates_dir / template
            assert template_path.exists(), f"Missing template: {template}"

    def test_memory_templates_exist(self, blueprint_dir):
        """Test memory template files exist."""
        templates_dir = blueprint_dir / "templates" / "memory"

        assert (templates_dir / "graph.md.tpl.md").exists()
        assert (templates_dir / "context.md.tpl.md").exists()

    def test_github_templates_exist(self, blueprint_dir):
        """Test GitHub template files exist."""
        templates_dir = templates_dir = blueprint_dir / "templates" / "github"

        assert (templates_dir / "PULL_REQUEST_TEMPLATE.md").exists()
        assert (templates_dir / "CODEOWNERS").exists()
        assert (templates_dir / "config.yml").exists()
        assert (templates_dir / "bug_report.md").exists()
        assert (templates_dir / "feature_request.md").exists()


class TestStackProfiles:
    """Tests for stack profile files."""

    def test_all_stacks_exist(self, blueprint_dir):
        """Test all stack profile files exist."""
        stacks_dir = blueprint_dir / "stacks"

        assert (stacks_dir / "python.yaml").exists()
        assert (stacks_dir / "node.yaml").exists()
        assert (stacks_dir / "go.yaml").exists()
        assert (stacks_dir / "generic.yaml").exists()

    def test_python_stack_valid_yaml(self, blueprint_dir):
        """Test Python stack profile is valid YAML."""
        stack_file = blueprint_dir / "stacks" / "python.yaml"

        with open(stack_file) as f:
            stack = yaml.safe_load(f)

        assert "name" in stack
        assert "commands" in stack
        assert "prerequisites" in stack
        assert stack["commands"]["test"] == "pytest"

    def test_node_stack_valid_yaml(self, blueprint_dir):
        """Test Node stack profile is valid YAML."""
        stack_file = blueprint_dir / "stacks" / "node.yaml"

        with open(stack_file) as f:
            stack = yaml.safe_load(f)

        assert "name" in stack
        assert "commands" in stack
        assert stack["commands"]["test"] == "npm test"

    def test_go_stack_valid_yaml(self, blueprint_dir):
        """Test Go stack profile is valid YAML."""
        stack_file = blueprint_dir / "stacks" / "go.yaml"

        with open(stack_file) as f:
            stack = yaml.safe_load(f)

        assert "name" in stack
        assert "commands" in stack
        assert stack["commands"]["test"] == "go test ./..."

    def test_generic_stack_valid_yaml(self, blueprint_dir):
        """Test Generic stack profile is valid YAML."""
        stack_file = blueprint_dir / "stacks" / "generic.yaml"

        with open(stack_file) as f:
            stack = yaml.safe_load(f)

        assert "name" in stack
        assert "commands" in stack


class TestProjectConfig:
    """Tests for project configuration."""

    def test_example_config_valid_yaml(self, blueprint_dir):
        """Test project.yaml.example is valid YAML."""
        config_file = blueprint_dir / "project.yaml.example"

        with open(config_file) as f:
            config = yaml.safe_load(f)

        assert "project" in config
        assert "name" in config["project"]
        assert "tier" in config["project"]
        assert "stack" in config["project"]


class TestDocumentationFiles:
    """Tests for documentation files."""

    def test_readme_exists(self, blueprint_dir):
        """Test README exists."""
        assert (blueprint_dir / "QUICKSTART.md").exists()

    def test_blueprint_exists(self, blueprint_dir):
        """Test main blueprint exists."""
        assert (blueprint_dir / "DOCUMENTATION-BLUEPRINT.md").exists()

    def test_quick_reference_exists(self, blueprint_dir):
        """Test quick reference exists."""
        assert (blueprint_dir / "QUICK-REFERENCE.md").exists()
