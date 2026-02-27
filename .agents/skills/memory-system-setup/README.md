# Memory System Setup Skill

Sets up the event-sourced memory system **in a new project**: CHANGELOG.md at root, optional .memory/graph.md and .memory/context.md, and Memory System Protocol in AGENTS.md. Pure markdown — no runtime required. For ongoing use (regeneration, archival), follow the project's Memory System Protocol or `memory-system/README.md`.

## Quick Start

1. Ensure this skill is available to the agent (project or global skills path).
2. Trigger with: "Set up the memory system for this project", "Initialize memory system", "Add event-sourced memory to this repo", "Create .memory/ and CHANGELOG".
3. Follow SKILL.md: choose tier (MVP/Core/Full), create layout (manually or via script), integrate into AGENTS.md, optionally run validation.

**Template paths:** `memory-system/memory-system-setup/memory-system-setup/templates/` (or under the skill dir, e.g. `~/.cursor/skills/memory-system-setup/memory-system-setup/templates/`). Use `changelog.md` → `CHANGELOG.md`, `context.md` → `.memory/context.md`, `graph.md` → `.memory/graph.md`.  
**Scripts (when memory-system is in project):** `python memory-system/scripts/initialize-memory.py <name> [tier]`, `python memory-system/scripts/validate-memory.py`.

## Skill Structure

```
memory-system-setup/
├── SKILL.md                      # Setup instructions
├── README.md                     # This file
├── config.json                   # Triggers (setup-focused)
├── event-format-and-types.md    # Event template, types, graph materialization
├── agents-integration-snippet.md # AGENTS.md section to add
├── install.ps1 / install.sh
└── memory-system-setup/          # Same-name subfolder
    ├── templates/                # changelog.md, graph.md, context.md
    └── _examples/                # worked-example.md
```

## What This Skill Does

- **Scope:** Initial setup only. Chooses tier (MVP/Core/Full), creates file layout (via script or manual copy), initializes CHANGELOG.md and optional .memory/ files and TODO.md, adds Memory System Protocol to AGENTS.md. Optional: run validation script.
- **Out of scope:** Ongoing operations (context regeneration, archival, conflict resolution) — use the project's Memory System Protocol or `memory-system/README.md`.

## Triggers

Keywords: "set up memory system", "initialize memory system", "memory system new project", ".memory folder", "changelog init".  
Patterns: `set.*up.*memory`, `initialize.*memory.*system`, `add.*memory.*system.*project`.

## Requirements

- **Permissions:** `file_read`, `file_write`
- **Tools:** None
- **Compatible with:** Claude, Roo, Cascade, Cursor, Generic

## Tiers

| Signal | MVP | Core | Full |
|--------|-----|------|------|
| Solo, &lt; 1 month | ✅ | | |
| Multiple agents, 1–6 months | | ✅ | |
| Complex deps, 6+ months | | | ✅ |

## Related

- **SKILL.md** — Full setup steps and validation
- **event-format-and-types.md** — Event template, types, materialization
- **agents-integration-snippet.md** — AGENTS.md section to paste
- **memory-system/scripts/** — initialize-memory.py, validate-memory.py
- **memory-system-setup/_examples/worked-example.md** — 8 events through all layers
- **memory-system/README.md** — Protocol and ongoing operations
