"""Tests for scaffold.py CLI tool."""

import sys
from pathlib import Path

import pytest
import yaml


class TestSPDXMapping:
    """Tests for SPDX ID mapping."""

    def test_mit_spdx(self, blueprint_dir):
        """Test MIT license maps to correct SPDX ID."""
        sys.path.insert(0, str(blueprint_dir))
        from scaffold import get_spdx_id

        assert get_spdx_id("MIT") == "MIT"

    def test_apache_spdx(self, blueprint_dir):
        """Test Apache license maps to correct SPDX ID."""
        sys.path.insert(0, str(blueprint_dir))
        from scaffold import get_spdx_id

        assert get_spdx_id("Apache-2.0") == "Apache-2.0"
        assert get_spdx_id("Apache License 2.0") == "Apache-2.0"

    def test_gpl_spdx(self, blueprint_dir):
        """Test GPL license maps to correct SPDX ID."""
        sys.path.insert(0, str(blueprint_dir))
        from scaffold import get_spdx_id

        assert get_spdx_id("GPL-3.0") == "GPL-3.0"
        assert get_spdx_id("GPLv3") == "GPL-3.0"
        assert get_spdx_id("GNU General Public License v3.0") == "GPL-3.0"

    def test_bsd_spdx(self, blueprint_dir):
        """Test BSD license maps to correct SPDX ID."""
        sys.path.insert(0, str(blueprint_dir))
        from scaffold import get_spdx_id

        assert get_spdx_id("BSD-3-Clause") == "BSD-3-Clause"
        assert get_spdx_id("BSD 3-Clause") == "BSD-3-Clause"

    def test_unknown_license(self, blueprint_dir):
        """Test unknown license returns as-is."""
        sys.path.insert(0, str(blueprint_dir))
        from scaffold import get_spdx_id

        assert get_spdx_id("Proprietary") == "Proprietary"
        assert get_spdx_id("Custom License") == "Custom License"


class TestTierFiles:
    """Tests for tier file definitions."""

    def test_mvp_files(self, blueprint_dir):
        """Test MVP tier has correct files."""
        sys.path.insert(0, str(blueprint_dir))
        from scaffold import TIER_FILES

        mvp_files = TIER_FILES["mvp"]
        assert "AGENTS.md" in mvp_files
        assert "CHANGELOG.md" in mvp_files
        assert "README.md" in mvp_files
        assert ".memory/context.md" in mvp_files
        assert len(mvp_files) == 4

    def test_core_files(self, blueprint_dir):
        """Test Core tier has correct files."""
        sys.path.insert(0, str(blueprint_dir))
        from scaffold import TIER_FILES

        core_files = TIER_FILES["core"]
        assert "AGENTS.md" in core_files
        assert "TODO.md" in core_files
        assert "QUICKSTART.md" in core_files
        assert "CONTRIBUTING.md" in core_files
        assert "SECURITY.md" in core_files
        assert ".memory/graph.md" in core_files
        assert "docs/SYSTEM-MAP.md" in core_files
        assert "docs/PROMPT-VALIDATION.md" in core_files

    def test_full_files(self, blueprint_dir):
        """Test Full tier has correct files."""
        sys.path.insert(0, str(blueprint_dir))
        from scaffold import TIER_FILES

        full_files = TIER_FILES["full"]
        assert "WORKFLOW.md" in full_files
        assert "CODE_OF_CONDUCT.md" in full_files
        assert "LICENSE.md" in full_files
        assert "EVALS.md" in full_files
        assert ".github/PULL_REQUEST_TEMPLATE.md" in full_files
        assert ".github/ISSUE_TEMPLATE/bug_report.md" in full_files


class TestStackProfiles:
    """Tests for stack profiles."""

    def test_python_stack(self, blueprint_dir):
        """Test Python stack profile loads correctly."""
        stack_file = blueprint_dir / "stacks" / "python.yaml"
        with open(stack_file) as f:
            stack = yaml.safe_load(f)

        assert stack["name"] == "Python"
        assert stack["commands"]["test"] == "pytest"
        assert stack["commands"]["lint"] == "ruff check ."
        assert "Python" in stack["prerequisites"][0]["name"]

    def test_node_stack(self, blueprint_dir):
        """Test Node.js stack profile loads correctly."""
        stack_file = blueprint_dir / "stacks" / "node.yaml"
        with open(stack_file) as f:
            stack = yaml.safe_load(f)

        assert stack["name"] == "Node.js"
        assert stack["commands"]["test"] == "npm test"
        assert "Node.js" in stack["prerequisites"][0]["name"]

    def test_go_stack(self, blueprint_dir):
        """Test Go stack profile loads correctly."""
        stack_file = blueprint_dir / "stacks" / "go.yaml"
        with open(stack_file) as f:
            stack = yaml.safe_load(f)

        assert stack["name"] == "Go"
        assert stack["commands"]["test"] == "go test ./..."


class TestTemplateMap:
    """Tests for template mapping."""

    def test_template_map_complete(self, blueprint_dir):
        """Test template map covers all required files."""
        sys.path.insert(0, str(blueprint_dir))
        from scaffold import TIER_FILES, TEMPLATE_MAP

        all_files = set()
        for files in TIER_FILES.values():
            all_files.update(files)

        for file_path in all_files:
            if file_path.endswith(".md") or file_path.endswith(".yml"):
                assert file_path in TEMPLATE_MAP, f"Missing template for {file_path}"


class TestCLIArguments:
    """Tests for CLI argument parsing."""

    def test_list_files_mvp(self, blueprint_dir, capsys):
        """Test --list-files mvp outputs correct files."""
        sys.path.insert(0, str(blueprint_dir))
        from scaffold import main

        with pytest.raises(SystemExit) as exc:
            sys.argv = ["scaffold.py", "--list-files", "mvp"]
            main()

        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "AGENTS.md" in captured.out
        assert "CHANGELOG.md" in captured.out

    def test_list_files_full(self, blueprint_dir, capsys):
        """Test --list-files full outputs correct files."""
        sys.path.insert(0, str(blueprint_dir))
        from scaffold import main

        with pytest.raises(SystemExit) as exc:
            sys.argv = ["scaffold.py", "--list-files", "full"]
            main()

        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "WORKFLOW.md" in captured.out
        assert "CODE_OF_CONDUCT.md" in captured.out
        assert "ISSUE_TEMPLATE" in captured.out
