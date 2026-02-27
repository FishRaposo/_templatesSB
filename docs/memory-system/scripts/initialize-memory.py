#!/usr/bin/env python3
"""Initialize memory system files for a new project.

Usage:
    python initialize-memory.py <project_name> [tier] [--project-root PATH]

Arguments:
    project_name: Name of the project (used in templates)
    tier: Memory system tier (mvp, core, full) - default: mvp

Tiers:
    mvp  - CHANGELOG.md only
    core - CHANGELOG.md + .memory/context.md
    full - CHANGELOG.md + .memory/graph.md + .memory/context.md + TODO.md

Template paths are relative to this script's parent (memory-system/).
Run from project root or use --project-root.

Exit codes:
    0 - Initialization successful
    1 - Initialization failed
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path


def get_module_dir() -> Path:
    """Get the memory-system module directory (parent of scripts/)."""
    return Path(__file__).resolve().parent.parent


def initialize_mvp(
    project_root: Path, module_dir: Path, project_name: str
) -> None:
    """Initialize MVP tier: CHANGELOG.md only."""
    template_path = module_dir / "templates" / "changelog.md"
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")

    content = template_path.read_text(encoding="utf-8")
    content = content.replace(
        "YYYY-MM-DD", datetime.now().strftime("%Y-%m-%d")
    )

    output_path = project_root / "CHANGELOG.md"
    output_path.write_text(content, encoding="utf-8")
    print(f"  Created: {output_path}")


def initialize_core(
    project_root: Path, module_dir: Path, project_name: str
) -> None:
    """Initialize Core tier: CHANGELOG.md + .memory/context.md."""
    initialize_mvp(project_root, module_dir, project_name)

    memory_dir = project_root / ".memory"
    memory_dir.mkdir(exist_ok=True)
    print(f"  Created: {memory_dir}")

    # Prefer .tpl.md if present; otherwise use plain context.md
    template_path = module_dir / "templates" / "context.md.tpl.md"
    if not template_path.exists():
        template_path = module_dir / "templates" / "context.md"
    if not template_path.exists():
        raise FileNotFoundError(f"Context template not found under {module_dir / 'templates'}")

    content = template_path.read_text(encoding="utf-8")
    content = content.replace("{{PROJECT_NAME}}", project_name)
    content = content.replace("{{DATE}}", datetime.now().strftime("%Y-%m-%d"))
    content = content.replace("{{TIME}}", datetime.now().strftime("%H:%M"))
    content = content.replace("{{TIER}}", "core")
    content = content.replace("{{SESSION_DESCRIPTION}}", "Initial setup")
    # Optional placeholders in .tpl.md
    for placeholder, value in [
        ("{{ACTIVE_MISSION_PARAGRAPH}}", "(fill in)"),
        ("{{TASK_1}}", "Setup"),
        ("{{TASK_2}}", "—"),
        ("{{CONSTRAINT_1}}", "(none)"),
        ("{{CONSTRAINT_2}}", "—"),
        ("{{CHANGE_1_SUMMARY}}", "Memory system initialized"),
        ("{{DEPENDENCY_1}}", "—"),
        ("{{DEPENDENCY_2}}", "—"),
        ("{{NEXT_ACTION_1}}", "Review and customize context.md"),
        ("{{NEXT_ACTION_2}}", "Append first event to CHANGELOG.md"),
        ("{{NEXT_ACTION_3}}", "—"),
    ]:
        content = content.replace(placeholder, value)

    output_path = memory_dir / "context.md"
    output_path.write_text(content, encoding="utf-8")
    print(f"  Created: {output_path}")


def initialize_full(
    project_root: Path, module_dir: Path, project_name: str
) -> None:
    """Initialize Full tier: all layers including graph and TODO."""
    initialize_core(project_root, module_dir, project_name)

    memory_dir = project_root / ".memory"

    graph_tpl = module_dir / "templates" / "graph.md.tpl.md"
    if not graph_tpl.exists():
        graph_tpl = module_dir / "templates" / "graph.md"
    if graph_tpl.exists():
        content = graph_tpl.read_text(encoding="utf-8")
        content = content.replace("{{PROJECT_NAME}}", project_name)
        content = content.replace("{{DATE}}", datetime.now().strftime("%Y-%m-%d"))
        content = content.replace("{{TIER}}", "full")
        content = content.replace("{{NODE_COUNT}}", "2")
        content = content.replace("{{EDGE_COUNT}}", "1")
        content = content.replace("{{COMPONENT_1}}", "core")
        content = content.replace("{{COMPONENT_1_PATH}}", "src/")

        output_path = memory_dir / "graph.md"
        output_path.write_text(content, encoding="utf-8")
        print(f"  Created: {output_path}")

    todo_content = f"""# TODO

> Pending tasks, planned work, and progress tracking for {project_name}.

## In Progress
- [ ] **Setup** — Initial project configuration (evt-001)

## Up Next
- [ ] **Task** — description

## Completed
- [x] **Memory System** — Initialized {datetime.now().strftime("%Y-%m-%d")} (evt-001)

## Backlog
- [ ] **Task** — description
"""
    (project_root / "TODO.md").write_text(todo_content, encoding="utf-8")
    print(f"  Created: {project_root / 'TODO.md'}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Initialize memory system files for a new project"
    )
    parser.add_argument("project_name", help="Name of the project")
    parser.add_argument(
        "tier",
        nargs="?",
        default="mvp",
        choices=["mvp", "core", "full"],
        help="Memory system tier (default: mvp)",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="Path to project root (default: current directory)",
    )
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    module_dir = get_module_dir()

    print(f"Initializing {args.tier} tier memory system for '{args.project_name}'")
    print(f"Project root: {project_root}")
    print("-" * 50)

    try:
        if args.tier == "mvp":
            initialize_mvp(project_root, module_dir, args.project_name)
        elif args.tier == "core":
            initialize_core(project_root, module_dir, args.project_name)
        else:
            initialize_full(project_root, module_dir, args.project_name)

        print("-" * 50)
        print("✓ Memory system initialized successfully")
        print("\nNext steps:")
        print("  1. Review and customize CHANGELOG.md")
        if args.tier in ("core", "full"):
            print("  2. Review and customize .memory/context.md")
        if args.tier == "full":
            print("  3. Review and customize .memory/graph.md")
            print("  4. Add tasks to TODO.md")
        print("  5. Add Memory System Protocol section to AGENTS.md (see memory-system/memory-system-setup/agents-integration-snippet.md)")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
