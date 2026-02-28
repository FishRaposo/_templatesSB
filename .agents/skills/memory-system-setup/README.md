# Memory System Setup Skill

**Protocol skill** for the **Memory System Protocol** (Protocols template type). Sets up the event-sourced memory system in a new project: installs `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md`, creates CHANGELOG.md at root, optional .memory/graph.md and .memory/context.md, and integrates the protocol reference into AGENTS.md. For ongoing use (regeneration, archival), follow the project's `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` or the Memory System section in AGENTS.md.

## Quick Start

1. Ensure this skill is available to the agent (project or global skills path).
2. Trigger with: "Set up the memory system for this project", "Initialize memory system", "Add event-sourced memory to this repo", "Create .memory/ and CHANGELOG", "Install Memory System Protocol".
3. Follow SKILL.md: install protocol to docs/protocols/, choose tier (MVP/Core/Full), create layout (manually or via script), integrate into AGENTS.md, optionally run validation.

**Template paths:** `memory-system/memory-system-setup/memory-system-setup/templates/` (or under the skill dir, e.g. `~/.cursor/skills/memory-system-setup/memory-system-setup/templates/`). Use `changelog.md` → `CHANGELOG.md`, `context.md` → `.memory/context.md`, `graph.md` → `.memory/graph.md`.  
**Scripts (when memory-system is in project):** Setup: `python memory-system/scripts/initialize-memory.py <name> [tier]`, `python memory-system/scripts/validate-memory.py`. **Retrieval (after setup):** `get_event.py`, `search_events.py`, `relevant_events.py`, `summarize_events.py`, `suggest_event.py`, `generate_memory_viewer.py` — see `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` §15 and memory-system README (Retrieval and Tools).  
**AGENTS.md snippet:** Use `agents-integration-snippet.md`; it includes the load-memory sequence and staleness check so agents boot correctly in any rule file (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md).

## Skill Structure

```
memory-system-setup/
├── SKILL.md                      # Setup instructions (protocol skill)
├── README.md                     # This file
├── config.json                   # Triggers (setup-focused)
├── templates/
│   └── MEMORY-SYSTEM-PROTOCOL.md # Protocol template → install to docs/protocols/
├── event-format-and-types.md    # Event template, types, graph materialization
├── agents-integration-snippet.md # AGENTS.md section (references docs/protocols/MEMORY-SYSTEM-PROTOCOL.md)
├── install.ps1 / install.sh
└── memory-system-setup/          # Same-name subfolder
    ├── templates/                # changelog.md, graph.md, context.md
    └── _examples/                # worked-example.md
```

## What This Skill Does

- **Scope:** Protocol skill for the Memory System Protocol. Installs docs/protocols/MEMORY-SYSTEM-PROTOCOL.md, chooses tier (MVP/Core/Full), creates file layout (via script or manual copy), initializes CHANGELOG.md and optional .memory/ files and TODO.md, adds Memory System Protocol section to AGENTS.md (linking to the protocol). Optional: run validation script.
- **Out of scope:** Ongoing operations (context regeneration, archival, conflict resolution) — use the project's docs/protocols/MEMORY-SYSTEM-PROTOCOL.md or the Memory System section in AGENTS.md.

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

- **protocol-setup** — Create or audit the Protocols template type; memory-system-setup is the protocol skill for the Memory System Protocol
- **SKILL.md** — Full setup steps (including protocol install) and validation
- **event-format-and-types.md** — Event template, types, materialization
- **agents-integration-snippet.md** — AGENTS.md section to paste
- **memory-system/scripts/** — initialize-memory.py, validate-memory.py; retrieval: get_event.py, search_events.py, relevant_events.py, summarize_events.py, suggest_event.py, generate_memory_viewer.py (see protocol §15)
- **memory-system-setup/_examples/worked-example.md** — 8 events through all layers
- **memory-system/README.md** — Protocol and ongoing operations
