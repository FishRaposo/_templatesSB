"""Tests for validate.py validation tool."""

import sys
from pathlib import Path

import pytest


class TestValidateTIERFiles:
    """Tests for validate.py tier file definitions."""

    def test_validate_mvp_files(self, blueprint_dir):
        """Test validate.py MVP tier has correct files."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import TIER_FILES

        mvp_files = TIER_FILES["mvp"]
        assert "AGENTS.md" in mvp_files
        assert "CHANGELOG.md" in mvp_files
        assert "README.md" in mvp_files

    def test_validate_core_files(self, blueprint_dir):
        """Test validate.py Core tier has correct files."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import TIER_FILES

        core_files = TIER_FILES["core"]
        assert "AGENTS.md" in core_files
        assert "TODO.md" in core_files

    def test_validate_full_files_issue_templates(self, blueprint_dir):
        """Test validate.py Full tier includes ISSUE_TEMPLATE files."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import TIER_FILES

        full_files = TIER_FILES["full"]
        assert ".github/ISSUE_TEMPLATE/config.yml" in full_files
        assert ".github/ISSUE_TEMPLATE/bug_report.md" in full_files
        assert ".github/ISSUE_TEMPLATE/feature_request.md" in full_files


class TestCorePlaceholders:
    """Tests for core placeholder detection."""

    def test_core_placeholders_defined(self, blueprint_dir):
        """Test core placeholders are properly defined."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import CORE_PLACEHOLDERS

        assert "PROJECT_NAME" in CORE_PLACEHOLDERS
        assert "PROJECT_DESCRIPTION" in CORE_PLACEHOLDERS
        assert "PROJECT_TAGLINE" in CORE_PLACEHOLDERS
        assert "REPO_URL" in CORE_PLACEHOLDERS
        assert "TIER" in CORE_PLACEHOLDERS
        assert "STACK" in CORE_PLACEHOLDERS
        assert "LICENSE_NAME" in CORE_PLACEHOLDERS


class TestRequiredSections:
    """Tests for required section detection."""

    def test_agents_sections(self, blueprint_dir):
        """Test AGENTS.md has required sections."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import REQUIRED_SECTIONS

        agents_sections = REQUIRED_SECTIONS["AGENTS.md"]
        assert "## Project Identity" in agents_sections
        assert "## Do" in agents_sections
        assert "## Don't" in agents_sections

    def test_changelog_sections(self, blueprint_dir):
        """Test CHANGELOG.md has required sections."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import REQUIRED_SECTIONS

        changelog_sections = REQUIRED_SECTIONS["CHANGELOG.md"]
        assert "## Event Log" in changelog_sections

    def test_readme_sections(self, blueprint_dir):
        """Test README.md has required sections."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import REQUIRED_SECTIONS

        readme_sections = REQUIRED_SECTIONS["README.md"]
        assert "## What It Does" in readme_sections
        assert "## Quick Start" in readme_sections
        assert "## Key Features" in readme_sections


class TestTierDetection:
    """Tests for tier detection from AGENTS.md."""

    def test_detect_tier_from_agents(self, temp_dir, blueprint_dir):
        """Test tier can be detected from AGENTS.md."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import detect_tier

        agents_file = temp_dir / "AGENTS.md"
        agents_file.write_text("# AGENTS.md\n\n**Tier**: core\n")

        tier = detect_tier(temp_dir)
        assert tier == "core"

    def test_detect_tier_missing(self, temp_dir, blueprint_dir):
        """Test detection returns None when AGENTS.md missing."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import detect_tier

        tier = detect_tier(temp_dir)
        assert tier is None


class TestValidationChecks:
    """Tests for validation check functions."""

    def test_required_files_check(self, temp_dir, blueprint_dir):
        """Test required files check works correctly."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import check_required_files

        (temp_dir / "AGENTS.md").write_text("# Test")
        (temp_dir / "CHANGELOG.md").write_text("# Test")
        (temp_dir / "README.md").write_text("# Test")
        (temp_dir / ".memory").mkdir()
        (temp_dir / ".memory" / "context.md").write_text("# Test")

        result = check_required_files(temp_dir, "mvp")
        assert result.passed

    def test_placeholder_check_no_placeholders(self, temp_dir, blueprint_dir):
        """Test placeholder check passes when no placeholders."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import check_placeholders

        (temp_dir / "README.md").write_text("# Project\n\nNo placeholders here.")

        result = check_placeholders(temp_dir, strict=False)
        assert result.passed

    def test_placeholder_check_with_core_placeholder(self, temp_dir, blueprint_dir):
        """Test placeholder check fails on core placeholders."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import check_placeholders

        (temp_dir / "README.md").write_text("# {{PROJECT_NAME}}")

        result = check_placeholders(temp_dir, strict=False)
        assert not result.passed
        assert len(result.errors) > 0

    def test_placeholder_check_fill_me_strict(self, temp_dir, blueprint_dir):
        """Test placeholder check fails on FILL_ME in strict mode."""
        sys.path.insert(0, str(blueprint_dir))
        from validate import check_placeholders

        (temp_dir / "README.md").write_text("# {{FILL_ME:PROJECT_NAME}}")

        result = check_placeholders(temp_dir, strict=True)
        assert not result.passed
