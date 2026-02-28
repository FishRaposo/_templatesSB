#!/usr/bin/env python3
"""Validate scaffolded documentation.

Usage:
    python validate.py [PATH]
    python validate.py --strict [PATH]

Checks:
    1. Required files exist per tier (reads AGENTS.md to detect tier)
    2. No unfilled core placeholders ({{...}} except {{FILL_ME:...}})
    3. Required sections present in key files
    4. Internal links resolve
    5. File naming conventions (UPPER_CASE.md for root docs)

Options:
    --strict    Also check for {{FILL_ME:...}} markers

Exit codes:
    0 - All checks pass
    1 - One or more checks failed
    2 - Cannot determine tier or missing AGENTS.md
"""

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

from config import TIERS, TIER_FILES, REQUIRED_SECTIONS, CORE_PLACEHOLDERS


class CheckResult(NamedTuple):
    name: str
    passed: bool
    errors: list[str]
    warnings: list[str]


def detect_tier(project_dir: Path) -> str | None:
    agents_file = project_dir / "AGENTS.md"
    if not agents_file.exists():
        return None

    content = agents_file.read_text(encoding="utf-8")
    tier_match = re.search(r"\*\*Tier\*\*:\s*(mvp|core|full)", content, re.IGNORECASE)
    if tier_match:
        return tier_match.group(1).lower()

    if "WORKFLOW.md" in content or (project_dir / "WORKFLOW.md").exists():
        return "full"
    if "TODO.md" in content or (project_dir / "TODO.md").exists():
        return "core"
    return "mvp"


def check_required_files(project_dir: Path, tier: str) -> CheckResult:
    errors = []
    warnings = []
    required = TIER_FILES.get(tier, [])

    for file_path in required:
        full_path = project_dir / file_path
        if not full_path.exists():
            errors.append(f"Missing required file: {file_path}")

    name = "Required Files"
    passed = len(errors) == 0
    return CheckResult(name, passed, errors, warnings)


def check_placeholders(project_dir: Path, strict: bool) -> CheckResult:
    errors = []
    warnings = []

    placeholder_pattern = re.compile(r"\{\{([A-Z_0-9]+)\}\}")
    fill_me_pattern = re.compile(r"\{\{FILL_ME:([A-Z_0-9]+)\}\}")

    for md_file in project_dir.rglob("*.md"):
        if ".git" in str(md_file) or "node_modules" in str(md_file):
            continue

        try:
            content = md_file.read_text(encoding="utf-8")
        except Exception:
            continue

        rel_path = md_file.relative_to(project_dir)

        for match in placeholder_pattern.finditer(content):
            placeholder = match.group(1)
            if placeholder in CORE_PLACEHOLDERS:
                errors.append(
                    f"{rel_path}: unfilled core placeholder {{{{{placeholder}}}}}"
                )
            elif not strict:
                warnings.append(
                    f"{rel_path}: unfilled placeholder {{{{{placeholder}}}}}"
                )
            else:
                errors.append(f"{rel_path}: unfilled placeholder {{{{{placeholder}}}}}")

        for match in fill_me_pattern.finditer(content):
            placeholder = match.group(1)
            if strict:
                errors.append(
                    f"{rel_path}: unfilled placeholder {{FILL_ME:{placeholder}}}"
                )
            else:
                warnings.append(
                    f"{rel_path}: unfilled placeholder {{FILL_ME:{placeholder}}}"
                )

    name = "Placeholders"
    passed = len(errors) == 0
    return CheckResult(name, passed, errors, warnings)


def check_required_sections(project_dir: Path) -> CheckResult:
    errors = []
    warnings = []

    for file_path, required in REQUIRED_SECTIONS.items():
        full_path = project_dir / file_path
        if not full_path.exists():
            continue

        try:
            content = full_path.read_text(encoding="utf-8")
        except Exception:
            continue

        for section in required:
            if section not in content:
                errors.append(f"{file_path}: missing section '{section}'")

    name = "Required Sections"
    passed = len(errors) == 0
    return CheckResult(name, passed, errors, warnings)


def check_internal_links(project_dir: Path) -> CheckResult:
    errors = []
    warnings = []

    link_pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")

    for md_file in project_dir.rglob("*.md"):
        if ".git" in str(md_file) or "node_modules" in str(md_file):
            continue

        try:
            content = md_file.read_text(encoding="utf-8")
        except Exception:
            continue

        rel_path = md_file.relative_to(project_dir)

        for match in link_pattern.finditer(content):
            link_text = match.group(1)
            link_target = match.group(2)

            if link_target.startswith("http://") or link_target.startswith("https://"):
                continue

            if link_target.startswith("#"):
                continue

            target_path = project_dir / link_target
            if not target_path.exists():
                if not link_target.endswith(".md"):
                    target_path = project_dir / f"{link_target}.md"
                if not target_path.exists():
                    errors.append(f"{rel_path}: broken link '{link_target}'")

    name = "Internal Links"
    passed = len(errors) == 0
    return CheckResult(name, passed, errors, warnings)


def check_naming_conventions(project_dir: Path) -> CheckResult:
    errors = []
    warnings = []

    for md_file in project_dir.glob("*.md"):
        name = md_file.name
        if name.startswith("."):
            continue

        if name in (
            "QUICKSTART.md",
            "README.md",
            "CHANGELOG.md",
            "LICENSE.md",
            "TODO.md",
        ):
            continue

        if "-" in name and name == name.lower():
            warnings.append(
                f"{name}: consider using UPPER_CASE.md for project-level docs"
            )

    name = "Naming Conventions"
    passed = len(errors) == 0
    return CheckResult(name, passed, errors, warnings)


def print_results(results: list[CheckResult]) -> int:
    total_errors = 0
    total_warnings = 0

    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"\n[{status}] {result.name}")

        for error in result.errors:
            print(f"  ERROR: {error}")
            total_errors += 1

        for warning in result.warnings:
            print(f"  WARN:  {warning}")
            total_warnings += 1

    print("\n" + "=" * 50)
    if total_errors == 0:
        print(f"All checks passed ({total_warnings} warnings)")
        return 0
    else:
        print(f"FAILED: {total_errors} errors, {total_warnings} warnings")
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate scaffolded documentation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=Path.cwd(),
        help="Project directory to validate",
    )
    parser.add_argument(
        "--strict", action="store_true", help="Also check for FILL_ME markers"
    )

    args = parser.parse_args()

    project_dir = args.path.resolve()

    if not (project_dir / "AGENTS.md").exists():
        print(f"Error: AGENTS.md not found in {project_dir}")
        print("Cannot determine tier or validate without AGENTS.md")
        sys.exit(2)

    tier = detect_tier(project_dir)
    if tier is None:
        print("Error: Could not detect tier from AGENTS.md")
        sys.exit(2)

    print(f"Validating documentation in: {project_dir}")
    print(f"Detected tier: {tier.upper()}")
    print("=" * 50)

    results = [
        check_required_files(project_dir, tier),
        check_placeholders(project_dir, args.strict),
        check_required_sections(project_dir),
        check_internal_links(project_dir),
        check_naming_conventions(project_dir),
    ]

    exit_code = print_results(results)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
