#!/usr/bin/env python3
"""Scaffold documentation for a new project.

Usage:
    python scaffold.py --interactive
    python scaffold.py --name "MyProject" --tier core --stack python
    python scaffold.py --config project.yaml --output ./my-project
    python scaffold.py --existing --output ./my-project

Options:
    --name TEXT           Project name
    --tier [mvp|core|full]  Documentation tier (default: core)
    --stack TEXT          Tech stack (python, node, go, generic)
    --description TEXT    Project description (2-3 sentences)
    --tagline TEXT        One-line tagline
    --repo-url TEXT       Git repository URL
    --config PATH         Load values from YAML config
    --output PATH         Output directory (default: current dir)
    --dry-run             Show what would be created without writing
    --force, -f           Allow overwriting existing files
    --existing            Add docs to existing project (skip existing files)
    --detect-tier         Analyze project and recommend tier
    --list-files          List files that would be created for tier

The script loads configuration from (in order of priority):
    1. CLI arguments (--name, --tier, --stack, etc.)
    2. Config file (--config project.yaml)
    3. Stack profile defaults (stacks/{stack}.yaml)
    4. Computed values (date, time, etc.)

Unfilled placeholders become {{FILL_ME:name}} markers in output files.

Exit codes:
    0 - Success
    1 - Error (missing required, invalid tier, etc.)
"""

import argparse
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("Error: PyYAML required. Install with: pip install pyyaml")
    sys.exit(1)

from config import TIERS, STACKS, TIER_FILES, CORE_PLACEHOLDERS


def get_spdx_id(license_name: str) -> str:
    """Map common license names to SPDX identifiers."""
    spdx_map = {
        "MIT": "MIT",
        "Apache-2.0": "Apache-2.0",
        "Apache License 2.0": "Apache-2.0",
        "GPL-3.0": "GPL-3.0",
        "GPLv3": "GPL-3.0",
        "GNU General Public License v3.0": "GPL-3.0",
        "BSD-3-Clause": "BSD-3-Clause",
        "BSD 3-Clause": "BSD-3-Clause",
        "ISC": "ISC",
        "Unlicense": "Unlicense",
        "MPL-2.0": "MPL-2.0",
        "Mozilla Public License 2.0": "MPL-2.0",
    }
    return spdx_map.get(license_name, license_name)


TEMPLATE_MAP = {
    "AGENTS.md": "AGENTS.md.tpl.md",
    "CHANGELOG.md": "CHANGELOG.md.tpl.md",
    "README.md": "README.md.tpl.md",
    "TODO.md": "TODO.md.tpl.md",
    "QUICKSTART.md": "QUICKSTART.md.tpl.md",
    "CONTRIBUTING.md": "CONTRIBUTING.md.tpl.md",
    "SECURITY.md": "SECURITY.md.tpl.md",
    "WORKFLOW.md": "WORKFLOW.md.tpl.md",
    "CODE_OF_CONDUCT.md": "CODE_OF_CONDUCT.md.tpl.md",
    "LICENSE.md": "LICENSE.md.tpl.md",
    "EVALS.md": "EVALS.md.tpl.md",
    "DOCUMENTATION-OVERVIEW.md": "DOCUMENTATION-OVERVIEW.md.tpl.md",
    ".memory/graph.md": "memory/graph.md.tpl.md",
    ".memory/context.md": "memory/context.md.tpl.md",
    "docs/SYSTEM-MAP.md": "SYSTEM-MAP.md.tpl.md",
    "docs/PROMPT-VALIDATION.md": "PROMPT-VALIDATION.md.tpl.md",
    ".github/PULL_REQUEST_TEMPLATE.md": "github/PULL_REQUEST_TEMPLATE.md",
    ".github/CODEOWNERS": "github/CODEOWNERS",
    ".github/ISSUE_TEMPLATE/config.yml": "github/config.yml",
    ".github/ISSUE_TEMPLATE/bug_report.md": "github/bug_report.md",
    ".github/ISSUE_TEMPLATE/feature_request.md": "github/feature_request.md",
}


def get_blueprint_dir() -> Path:
    return Path(__file__).resolve().parent


def load_stack_profile(stack: str) -> dict:
    blueprint_dir = get_blueprint_dir()
    stack_file = blueprint_dir / "stacks" / f"{stack}.yaml"
    if not stack_file.exists():
        print(f"Warning: Stack profile not found: {stack_file}")
        return {}
    with open(stack_file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_config(config_path: Path | None) -> dict:
    if config_path is None:
        return {}
    if not config_path.exists():
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def merge_configs(cli_args: dict, file_config: dict, stack_profile: dict) -> dict:
    merged = {
        "project": {},
        "license": {},
        "commands": {},
        "features": [],
        "tech_stack": [],
        "ai_tools": [],
        "components": [],
        "security": {},
    }

    merged["project"]["name"] = cli_args.get("name") or file_config.get(
        "project", {}
    ).get("name", "")
    merged["project"]["description"] = cli_args.get("description") or file_config.get(
        "project", {}
    ).get("description", "")
    merged["project"]["tagline"] = cli_args.get("tagline") or file_config.get(
        "project", {}
    ).get("tagline", "")
    merged["project"]["repo_url"] = cli_args.get("repo_url") or file_config.get(
        "project", {}
    ).get("repo_url", "")
    merged["project"]["tier"] = cli_args.get("tier") or file_config.get(
        "project", {}
    ).get("tier", "core")
    merged["project"]["stack"] = cli_args.get("stack") or file_config.get(
        "project", {}
    ).get("stack", "generic")
    merged["project"]["primary_language"] = file_config.get("project", {}).get(
        "primary_language"
    ) or stack_profile.get("primary_language", "")

    merged["license"]["name"] = file_config.get("license", {}).get("name", "MIT")

    stack_commands = stack_profile.get("commands", {})
    file_commands = file_config.get("commands", {})
    merged["commands"]["install"] = file_commands.get("install") or stack_commands.get(
        "install", ""
    )
    merged["commands"]["run"] = file_commands.get("run") or stack_commands.get(
        "run", ""
    )
    merged["commands"]["test"] = file_commands.get("test") or stack_commands.get(
        "test", ""
    )
    merged["commands"]["lint"] = file_commands.get("lint") or stack_commands.get(
        "lint", ""
    )
    merged["commands"]["build"] = file_commands.get("build") or stack_commands.get(
        "build", ""
    )

    merged["local_url"] = stack_profile.get("local_url", "http://localhost:3000")

    merged["features"] = file_config.get(
        "features",
        stack_profile.get(
            "tech_stack_default", ["Feature 1", "Feature 2", "Feature 3"]
        ),
    )
    merged["tech_stack"] = file_config.get(
        "tech_stack", stack_profile.get("tech_stack_default", [])
    )

    merged["ai_tools"] = file_config.get("ai_tools", [])

    merged["components"] = file_config.get("components", [])

    merged["security"]["email"] = file_config.get("security", {}).get(
        "email", "security@example.com"
    )
    merged["security"]["disclosure_delay_days"] = file_config.get("security", {}).get(
        "disclosure_delay_days", 7
    )

    merged["style_rules"] = stack_profile.get(
        "style_rules",
        [
            "Follow the project's established conventions",
            "Write clear, self-documenting code",
            "Document public APIs",
        ],
    )

    merged["prerequisites"] = stack_profile.get("prerequisites", [])

    now = datetime.now()
    merged["computed"] = {
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M"),
        "year": now.strftime("%Y"),
        "agent": "scaffold",
    }

    return merged


def build_placeholder_map(config: dict) -> dict[str, str]:
    p = {}

    p["PROJECT_NAME"] = config["project"]["name"] or ""
    p["PROJECT_DESCRIPTION"] = config["project"]["description"]
    p["PROJECT_DESCRIPTION_2_3_SENTENCES"] = config["project"]["description"]
    p["PROJECT_TAGLINE"] = config["project"]["tagline"]
    p["REPO_URL"] = config["project"]["repo_url"]
    p["TIER"] = config["project"]["tier"]
    p["STACK"] = config["project"]["stack"]
    p["PRIMARY_LANGUAGE"] = config["project"]["primary_language"]

    p["LICENSE_NAME"] = config["license"]["name"]
    p["SPDX_ID"] = get_spdx_id(config["license"]["name"])

    p["INSTALL_COMMAND"] = config["commands"]["install"]
    p["RUN_COMMAND"] = config["commands"]["run"]
    p["TEST_COMMAND"] = config["commands"]["test"]
    p["LINT_COMMAND"] = config["commands"]["lint"]
    p["BUILD_COMMAND"] = config["commands"]["build"]

    p["LOCAL_URL"] = config["local_url"]

    features = config["features"][:3] if config["features"] else []
    while len(features) < 3:
        features.append(f"Feature {len(features) + 1}")
    for i, feature in enumerate(features, 1):
        p[f"FEATURE_{i}"] = feature

    tech_stack = config["tech_stack"][:3] if config["tech_stack"] else []
    while len(tech_stack) < 3:
        tech_stack.append(f"Technology {len(tech_stack) + 1}")
    for i, tech in enumerate(tech_stack, 1):
        p[f"TECH_{i}"] = tech

    p["SECURITY_EMAIL"] = config["security"]["email"]
    p["DISCLOSURE_DELAY"] = str(config["security"]["disclosure_delay_days"])

    p["DATE"] = config["computed"]["date"]
    p["TIME"] = config["computed"]["time"]
    p["YEAR"] = config["computed"]["year"]
    p["AGENT"] = config["computed"]["agent"]

    for i, rule in enumerate(config["style_rules"][:3], 1):
        p[f"STYLE_RULE_{i}"] = rule

    for i, prereq in enumerate(config["prerequisites"][:3], 1):
        p[f"PREREQ_{i}"] = prereq.get("name", "")
        p[f"PREREQ_{i}_VERSION"] = prereq.get("version", "")
        p[f"PREREQ_{i}_CHECK_COMMAND"] = prereq.get("check", "")
        p[f"PREREQ_{i}_INSTALL_URL"] = prereq.get("install_url", "")

    for i, comp in enumerate(config["components"][:3], 1):
        p[f"COMPONENT_{i}"] = comp.get("name", "")
        p[f"COMPONENT_{i}_PURPOSE"] = comp.get("purpose", "")
        p[f"COMPONENT_{i}_PATH"] = comp.get("path", "")
        p[f"COMPONENT_{i}_OWNER"] = comp.get("owner", "")

    return p


def render_template(content: str, placeholders: dict[str, str]) -> str:
    def replace_match(match):
        key = match.group(1)
        if key in placeholders and placeholders[key]:
            return placeholders[key]
        return f"{{{{FILL_ME:{key}}}}}"

    pattern = r"\{\{([A-Z_0-9]+)\}\}"
    return re.sub(pattern, replace_match, content)


def get_existing_files(output_dir: Path, files_to_create: list[str]) -> list[str]:
    """Get list of files that already exist."""
    existing = []
    for file_path in files_to_create:
        if (output_dir / file_path).exists():
            existing.append(file_path)
    return existing


def scaffold_project(
    config: dict,
    output_dir: Path,
    dry_run: bool = False,
    force: bool = False,
    existing: bool = False,
) -> list[str]:
    tier = config["project"]["tier"]
    if tier not in TIERS:
        print(f"Error: Invalid tier '{tier}'. Must be one of: {TIERS}")
        sys.exit(1)

    files_to_create = TIER_FILES[tier].copy()
    ai_tools = config.get("ai_tools", [])
    if tier in ("core", "full") and ai_tools:
        for tool in ai_tools:
            tool_file = f"{tool.upper()}.md"
            if tool_file not in files_to_create:
                files_to_create.append(tool_file)

    existing_files = get_existing_files(output_dir, files_to_create)

    if existing:
        if existing_files:
            print(f"Note: {len(existing_files)} file(s) already exist, will skip:")
            for f in existing_files:
                print(f"  - {f}")
            files_to_create = [f for f in files_to_create if f not in existing_files]
            if not files_to_create:
                print("All documentation files already exist. Nothing to create.")
                return []
    else:
        if not force and output_dir.exists() and existing_files:
            print(
                f"Warning: Output directory contains {len(existing_files)} existing file(s)"
            )
            print("Use --force to overwrite existing files")
            print(
                "Use --existing to add docs to existing project (skip existing files)"
            )
            sys.exit(1)

    blueprint_dir = get_blueprint_dir()
    templates_dir = blueprint_dir / "templates"
    placeholders = build_placeholder_map(config)
    created_files = []

    for file_path in files_to_create:
        template_name = TEMPLATE_MAP.get(file_path)
        if template_name is None:
            if file_path.endswith(".md") and "/" not in file_path:
                tool_name = file_path.replace(".md", "").lower()
                template_name = "AI-TOOL.md.tpl.md"
                placeholders["AI_TOOL_NAME"] = tool_name.capitalize()
                placeholders["AI_TOOL_LAUNCH_INSTRUCTIONS"] = (
                    f"Launch {tool_name.capitalize()} in this directory"
                )
                placeholders["AI_TOOL_LAUNCH_COMMAND"] = (
                    f"See {tool_name.capitalize()} documentation"
                )
                placeholders["AI_TOOL_SPECIFIC_NOTES"] = ""
            else:
                print(f"Warning: No template for {file_path}")
                continue

        template_path = templates_dir / template_name
        if not template_path.exists():
            print(f"Warning: Template not found: {template_path}")
            continue

        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()

        rendered = render_template(content, placeholders)

        output_path = output_dir / file_path
        if dry_run:
            print(f"  Would create: {output_path}")
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(rendered)
            print(f"  Created: {output_path}")

        created_files.append(str(output_path))

    return created_files


def detect_tier(project_dir: Path) -> str:
    """Analyze project and recommend a tier."""
    print(f"Analyzing project at: {project_dir}")
    print("-" * 50)

    indicators = {
        "mvp": 0,
        "core": 0,
        "full": 0,
    }

    git_dir = project_dir / ".git"
    has_git = git_dir.exists()

    if has_git:
        try:
            result = subprocess.run(
                ["git", "log", "--since=2000-01-01", "--format=%ai"],
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout:
                dates = result.stdout.strip().split("\n")
                if dates:
                    first_commit = dates[-1][:10]
                    from datetime import date

                    try:
                        first_date = date.fromisoformat(first_commit)
                        age_days = (date.today() - first_date).days
                        if age_days > 180:
                            indicators["full"] += 3
                            indicators["core"] += 1
                        elif age_days > 30:
                            indicators["core"] += 3
                            indicators["mvp"] += 1
                        else:
                            indicators["mvp"] += 2
                    except ValueError:
                        pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    src_count = sum(1 for _ in project_dir.rglob("*.py"))
    src_count += sum(1 for _ in project_dir.rglob("*.js"))
    src_count += sum(1 for _ in project_dir.rglob("*.ts"))
    src_count += sum(1 for _ in project_dir.rglob("*.go"))

    if src_count > 50:
        indicators["full"] += 2
        indicators["core"] += 1
    elif src_count > 10:
        indicators["core"] += 2
        indicators["mvp"] += 1

    doc_files = list(project_dir.glob("*.md"))
    doc_files += list(project_dir.glob("docs/*.md"))
    doc_count = len(doc_files)

    if doc_count > 15:
        indicators["full"] += 2
        indicators["core"] += 1
    elif doc_count > 3:
        indicators["core"] += 2

    existing_docs = {
        "CHANGELOG.md": "mvp",
        "TODO.md": "core",
        "CONTRIBUTING.md": "core",
        "docs/SYSTEM-MAP.md": "core",
        "WORKFLOW.md": "full",
        ".github/": "full",
    }

    for doc, tier in existing_docs.items():
        if (project_dir / doc).exists() or any(project_dir.glob(doc.replace("/", "/"))):
            indicators[tier] += 2

    pyproject = project_dir / "pyproject.toml"
    package_json = project_dir / "package.json"
    go_mod = project_dir / "go.mod"

    if pyproject.exists() or package_json.exists() or go_mod.exists():
        indicators["core"] += 1

    contributors = project_dir / "CONTRIBUTORS"
    if contributors.exists():
        indicators["full"] += 1

    print("Analysis results:")
    print(f"  - Git history: {'Yes' if has_git else 'No'}")
    print(f"  - Source files: ~{src_count}")
    print(f"  - Existing docs: {doc_count}")
    print()
    print("Indicators score:")
    print(f"  - MVP: {indicators['mvp']}")
    print(f"  - Core: {indicators['core']}")
    print(f"  - Full: {indicators['full']}")
    print()

    recommended = max(indicators.items(), key=lambda x: x[1])[0]
    print(f"Recommended tier: {recommended.upper()}")
    print()
    print("Run with:")
    if project_dir != Path.cwd():
        print(
            f"  python scaffold.py --existing --tier {recommended} --output {project_dir}"
        )
    else:
        print(f"  python scaffold.py --existing --tier {recommended}")

    return recommended


def interactive_prompt() -> dict:
    print("Interactive configuration:")
    print("-" * 40)

    name = input("Project name [MyProject]: ").strip() or "MyProject"
    description = (
        input("Description (2-3 sentences): ").strip() or "A software project."
    )
    tagline = input("One-line tagline: ").strip() or "A software project"
    repo_url = input("Repository URL: ").strip() or "https://github.com/user/repo"

    print(f"\nTiers: mvp (solo/short), core (team), full (enterprise)")
    tier = input("Tier [core]: ").strip().lower() or "core"
    while tier not in TIERS:
        print(f"Invalid tier. Must be one of: {TIERS}")
        tier = input("Tier [core]: ").strip().lower() or "core"

    print(f"\nStacks: python, node, go, generic")
    stack = input("Stack [generic]: ").strip().lower() or "generic"
    while stack not in STACKS:
        print(f"Invalid stack. Must be one of: {STACKS}")
        stack = input("Stack [generic]: ").strip().lower() or "generic"

    return {
        "name": name,
        "tier": tier,
        "stack": stack,
        "description": description,
        "tagline": tagline,
        "repo_url": repo_url,
    }


def list_files_for_tier(tier: str) -> None:
    if tier not in TIERS:
        print(f"Error: Invalid tier '{tier}'. Must be one of: {TIERS}")
        sys.exit(1)

    print(f"Files for {tier.upper()} tier:")
    print("-" * 40)
    for f in TIER_FILES[tier]:
        print(f"  {f}")
    print(f"\nTotal: {len(TIER_FILES[tier])} files")
    sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scaffold documentation for a new project",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--name", help="Project name")
    parser.add_argument(
        "--tier", choices=TIERS, help="Documentation tier (mvp, core, full)"
    )
    parser.add_argument(
        "--stack", choices=STACKS, help="Tech stack (python, node, go, generic)"
    )
    parser.add_argument("--description", help="Project description (2-3 sentences)")
    parser.add_argument("--tagline", help="One-line tagline")
    parser.add_argument("--repo-url", help="Git repository URL")
    parser.add_argument("--config", type=Path, help="Load values from YAML config")
    parser.add_argument(
        "--output", type=Path, default=Path.cwd(), help="Output directory"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be created without writing",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Allow overwriting existing files",
    )
    parser.add_argument(
        "--existing",
        action="store_true",
        help="Add docs to existing project (skip existing files)",
    )
    parser.add_argument(
        "--detect-tier",
        action="store_true",
        help="Analyze project and recommend tier",
    )
    parser.add_argument(
        "--list-files", metavar="TIER", help="List files that would be created for tier"
    )

    args = parser.parse_args()

    if args.list_files:
        list_files_for_tier(args.list_files)
        return

    if args.detect_tier:
        detect_tier(args.output.resolve())
        return

    cli_args = {
        "name": args.name,
        "tier": args.tier,
        "stack": args.stack,
        "description": args.description,
        "tagline": args.tagline,
        "repo_url": args.repo_url,
    }

    if args.config:
        file_config = load_config(args.config)
        if file_config.get("project", {}).get("name"):
            cli_args["name"] = cli_args["name"] or file_config["project"]["name"]
        if file_config.get("project", {}).get("tier"):
            cli_args["tier"] = cli_args["tier"] or file_config["project"]["tier"]
        if file_config.get("project", {}).get("stack"):
            cli_args["stack"] = cli_args["stack"] or file_config["project"]["stack"]
    else:
        file_config = {}

    tier = cli_args["tier"] or file_config.get("project", {}).get("tier", "core")
    stack = cli_args["stack"] or file_config.get("project", {}).get("stack", "generic")

    stack_profile = load_stack_profile(stack)
    config = merge_configs(cli_args, file_config, stack_profile)

    config["project"]["tier"] = tier
    config["project"]["stack"] = stack

    if not config["project"]["name"]:
        agents_file = args.output.resolve() / "AGENTS.md"
        if args.existing and agents_file.exists():
            try:
                content = agents_file.read_text(encoding="utf-8")
                name_match = re.search(
                    r"^\*\*Project\*\*:\s*(.+)$", content, re.MULTILINE
                )
                if name_match:
                    config["project"]["name"] = name_match.group(1).strip()
            except Exception:
                pass

        if not config["project"]["name"] and not args.dry_run:
            print(
                "Error: Project name is required. Use --name, --config, --description, or --existing with existing AGENTS.md."
            )
            sys.exit(1)

    output_dir = args.output.resolve()

    mode = "existing project" if args.existing else "new project"
    print(
        f"Scaffolding {tier.upper()} tier documentation for '{config['project']['name']}' ({mode})"
    )
    print(f"Stack: {stack}")
    print(f"Output: {output_dir}")
    print("-" * 50)

    if args.dry_run:
        print("DRY RUN - no files will be created\n")

    created = scaffold_project(
        config,
        output_dir,
        dry_run=args.dry_run,
        force=args.force,
        existing=args.existing,
    )

    print("-" * 50)
    if args.dry_run:
        print(f"\nWould create {len(created)} files")
    else:
        print(f"\nCreated {len(created)} files")
        if len(created) > 0:
            print("\nNext steps:")
            print("  1. Fill any {{FILL_ME:...}} markers in generated files")
            print("  2. Run: python validate.py .")
            print("  3. Review AGENTS.md for behavioral rules")
            print(
                "  4. Commit: git add . && git commit -m 'docs: initialize documentation'"
            )
        else:
            print("\nAll documentation files already exist.")
            print("Run validation to check documentation health:")
            print("  python validate.py .")


if __name__ == "__main__":
    main()
