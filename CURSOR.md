# CURSOR.md - Unified AI Development Ecosystem

**Purpose**: Cursor AI guide for the seven template types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols).  
**Last Updated**: 2025

See `AGENTIC-ASSETS-FRAMEWORK.md` for complete framework documentation.

**Rule files**: This project uses four rule files—**AGENTS.md** (canonical), **CLAUDE.md**, **CURSOR.md** (this file), **WINDSURF.md**—one per tool or audience. All are examples of the **Rules** template type. **AGENTS.md** is the full source: Tech Stack, Commands (prefer scripts), Testing, Code Style, Repository Structure, Boundaries, **Safety and Permissions**, Git Workflow, Memory System, Prompt Validation (4 checks), Three Pillars (with change-type doc table), Workflows, Tool Selection, **Subagents for execution**, **Right tool for the job**, Key References.

---

## Quick Start

This repository is built on **seven template types**:

1. **Rules** — How agents must behave (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, .cursor/rules)
2. **Blueprints** — What to build (product archetypes)
3. **Tasks** — How to implement (feature units)
4. **Recipes** — Feature combinations (bundles)
5. **Subagents** — Who does the work (configured sub-agents)
6. **Skills** — How to do it well (capabilities)
7. **Protocols** — How processes are defined (e.g. prompt validation, memory; in `docs/protocols/`)

**"Templates"** = all seven types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols). **Rules** are loaded by Cursor from this file or from `.cursor/rules/`. **In this repo** only **Rules**, **Protocols** (in `docs/protocols/`), and **nine Skills** are active: **memory-system-setup**, **rules-setup**, **skill-setup**, **blueprints-setup**, **tasks-setup**, **recipes-setup**, **subagents-setup**, **prompt-validation-setup**, **protocol-setup** (under `.agents/skills/`). Other template-type implementations are archived.

```bash
# Validate JSON (skills)
find . -name "*.json" -exec python -m json.tool {} \; > /dev/null

# When the project includes scripts/ with template automation:
# Validate templates & blueprints (CRITICAL before commits)
python scripts/validate-templates.py --full

# Generate project
python scripts/setup-project.py --auto --name "Project" --description "desc"
# This repo does not currently ship these scripts.
```

**Cursor paths**: Skills can live in `~/.cursor/skills/` or `.cursor/skills/`. Do not use `~/.cursor/skills-cursor/` (reserved for built-in skills).

---

## Repository Structure

```
├── AGENTS.md                  # 📜 RULES — Canonical (tool-agnostic)
├── CLAUDE.md                  # 📜 RULES — Claude entry
├── CURSOR.md                  # 📜 RULES — Cursor entry (this file)
├── WINDSURF.md                # 📜 RULES — Windsurf entry
├── AGENTIC-ASSETS-FRAMEWORK.md
├── CHANGELOG.md, README.md, CURRENT-REPOSITORY-STATE.md
├── .agents/skills/            # 🧠 SKILLS (nine)
├── .memory/                   # Memory data (when in use)
├── docs/, plans/, _documentation-blueprint/
│   └── protocols/            # 📋 PROTOCOLS (e.g. PROMPT-VALIDATION-PROTOCOL.md)
├── .cursor/rules/             # Optional Cursor rule files
├── blueprints/, tasks/, recipes/, subagents/   # When present or archived
└── scripts/                   # When present (framework/archive)
```

---

## Memory System

**Load memory at session start:** This project uses an event-sourced memory system. Before doing work:

1. Read **AGENTS.md** for behavioral constraints (canonical rules).
2. Read **`.memory/context.md`** for current trajectory. If the file is missing, create it from `CHANGELOG.md` (and `.memory/graph.md` if present) per `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md`.
3. **Check staleness:** In `.memory/context.md`, find the "Event horizon" comment (e.g. `Event horizon: evt-002`). In `CHANGELOG.md`, find the last event under `## Event Log` (e.g. `### evt-002`). If they differ or context is missing, regenerate `.memory/context.md` (and `.memory/graph.md` if used) from the event log before proceeding.
4. Optionally: run `python docs/memory-system/scripts/relevant_events.py` (when present) for a compact recent-events index.

**After tasks:** Append a new event to `CHANGELOG.md` under `## Event Log` (next evt-NNN), then update `.memory/graph.md` and `.memory/context.md`. See AGENTS.md and `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` for full lifecycle.

---

## Key References

| File | Purpose |
|------|---------|
| `AGENTIC-ASSETS-FRAMEWORK.md` | **Seven template types** — Full framework |
| `AGENTS.md` | 📜 **Rules** — Canonical (build/test/lint, conventions, **memory load**) |
| `CLAUDE.md` | 📜 **Rules** — Claude-specific |
| `CURSOR.md` | 📜 **Rules** — This file (Cursor-specific) |
| `WINDSURF.md` | 📜 **Rules** — Windsurf-specific |
| `docs/protocols/` | 📋 **Protocols** — Process definitions (prompt validation, memory) |
| `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` | Memory system — boot, staleness, Event Log |
| `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` | Prompt validation (install via prompt-validation-setup skill) |
| `.agents/skills/prompt-validation-setup/` | Install/maintain Prompt Validation Protocol |
| `.agents/skills/protocol-setup/` | Create/audit Protocols template type |

When in doubt, read `AGENTS.md` and `AGENTIC-ASSETS-FRAMEWORK.md`.
