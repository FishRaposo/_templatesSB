# Memory System Initialization Script

This document contains the initialization script for the memory system. Copy this to `memory-system/scripts/initialize-memory.py` to use it.

## Script Code

```python
#!/usr/bin/env python3
"""Initialize memory system files for a new project.

Usage:
    python initialize-memory.py <project_name> [tier]

Arguments:
    project_name: Name of the project (used in templates)
    tier: Memory system tier (mvp, core, full) - default: mvp

Tiers:
    mvp  - CHANGELOG.md only
    core - CHANGELOG.md + .memory/context.md
    full - CHANGELOG.md + .memory/graph.md + .memory/context.md + TODO.md

Exit codes:
    0 - Initialization successful
    1 - Initialization failed
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime


def get_module_dir() -> Path:
    """Get the memory-system module directory."""
    return Path(__file__).parent.parent


def initialize_mvp(project_root: Path, module_dir: Path, project_name: str) -> None:
    """Initialize MVP tier: CHANGELOG.md only."""
    changelog_template = module_dir / "changelog.md"
    
    if not changelog_template.exists():
        raise FileNotFoundError(f"Template not found: {changelog_template}")
    
    content = changelog_template.read_text()
    content = content.replace("YYYY-MM-DD", datetime.now().strftime("%Y-%m-%d"))
    
    output_path = project_root / "CHANGELOG.md"
    output_path.write_text(content)
    print(f"  Created: {output_path}")


def initialize_core(project_root: Path, module_dir: Path, project_name: str) -> None:
    """Initialize Core tier: CHANGELOG.md + .memory/context.md."""
    # First, do MVP initialization
    initialize_mvp(project_root, module_dir, project_name)
    
    # Create .memory directory
    memory_dir = project_root / ".memory"
    memory_dir.mkdir(exist_ok=True)
    print(f"  Created: {memory_dir}")
    
    # Create context.md from template
    template_path = module_dir / "templates" / "context.md.tpl.md"
    if template_path.exists():
        content = template_path.read_text()
        content = content.replace("{{PROJECT_NAME}}", project_name)
        content = content.replace("{{DATE}}", datetime.now().strftime("%Y-%m-%d"))
        content = content.replace("{{TIME}}", datetime.now().strftime("%H:%M"))
        content = content.replace("{{TIER}}", "core")
        content = content.replace("{{SESSION_DESCRIPTION}}", "Initial setup")
        
        output_path = memory_dir / "context.md"
        output_path.write_text(content)
        print(f"  Created: {output_path}")


def initialize_full(project_root: Path, module_dir: Path, project_name: str) -> None:
    """Initialize Full tier: All layers."""
    # First, do Core initialization
    initialize_core(project_root, module_dir, project_name)
    
    memory_dir = project_root / ".memory"
    
    # Create graph.md from template
    template_path = module_dir / "templates" / "graph.md.tpl.md"
    if template_path.exists():
        content = template_path.read_text()
        content = content.replace("{{PROJECT_NAME}}", project_name)
        content = content.replace("{{DATE}}", datetime.now().strftime("%Y-%m-%d"))
        content = content.replace("{{TIER}}", "full")
        content = content.replace("{{NODE_COUNT}}", "1")
        content = content.replace("{{EDGE_COUNT}}", "0")
        content = content.replace("{{COMPONENT_1}}", "core")
        content = content.replace("{{COMPONENT_1_PATH}}", "src/")
        
        output_path = memory_dir / "graph.md"
        output_path.write_text(content)
        print(f"  Created: {output_path}")
    
    # Create TODO.md
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
    output_path = project_root / "TODO.md"
    output_path.write_text(todo_content)
    print(f"  Created: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Initialize memory system files for a new project"
    )
    parser.add_argument("project_name", help="Name of the project")
    parser.add_argument("tier", nargs="?", default="mvp", 
                        choices=["mvp", "core", "full"],
                        help="Memory system tier (default: mvp)")
    parser.add_argument("--project-root", type=Path, default=Path.cwd(),
                        help="Path to project root (default: current directory)")
    
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
        elif args.tier == "full":
            initialize_full(project_root, module_dir, args.project_name)
        
        print("-" * 50)
        print(f"✓ Memory system initialized successfully")
        print(f"\nNext steps:")
        print(f"  1. Review and customize CHANGELOG.md")
        if args.tier in ("core", "full"):
            print(f"  2. Review and customize .memory/context.md")
        if args.tier == "full":
            print(f"  3. Review and customize .memory/graph.md")
            print(f"  4. Add tasks to TODO.md")
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

## Usage

```bash
# Initialize MVP tier (default)
python initialize-memory.py my-project

# Initialize Core tier
python initialize-memory.py my-project core

# Initialize Full tier
python initialize-memory.py my-project full

# Initialize in specific directory
python initialize-memory.py my-project full --project-root /path/to/project
```

## Tier Comparison

| Tier | Files Created | Use Case |
|------|--------------|----------|
| **mvp** | `CHANGELOG.md` | Solo, < 1 month, prototype |
| **core** | `CHANGELOG.md`, `.memory/context.md` | Team, 1-6 months, real project |
| **full** | `CHANGELOG.md`, `.memory/graph.md`, `.memory/context.md`, `TODO.md` | Enterprise, 6+ months, multi-agent |

## Output Structure

### MVP Tier
```
project/
├── CHANGELOG.md
```

### Core Tier
```
project/
├── CHANGELOG.md
└── .memory/
    └── context.md
```

### Full Tier
```
project/
├── CHANGELOG.md
├── TODO.md
└── .memory/
    ├── graph.md
    └── context.md
```

## Template Variables

The following variables are replaced in templates:

| Variable | Description | Example |
|----------|-------------|---------|
| `{{PROJECT_NAME}}` | Project name | my-project |
| `{{DATE}}` | Current date | 2026-02-27 |
| `{{TIME}}` | Current time | 14:30 |
| `{{TIER}}` | Selected tier | full |
| `{{SESSION_DESCRIPTION}}` | Session description | Initial setup |
| `{{NODE_COUNT}}` | Initial node count | 1 |
| `{{EDGE_COUNT}}` | Initial edge count | 0 |
| `{{COMPONENT_1}}` | First component name | core |
| `{{COMPONENT_1_PATH}}` | First component path | src/ |
