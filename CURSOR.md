# CURSOR.md - Unified AI Development Ecosystem

**Purpose**: Cursor AI guide for the six template types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills).  
**Last Updated**: 2025

See `AGENTIC-ASSETS-FRAMEWORK.md` for complete framework documentation.

**Rule files**: This project uses four rule files—**AGENTS.md** (canonical), **CLAUDE.md**, **CURSOR.md** (this file), **WINDSURF.md**—one per tool or audience. All are examples of the **Rules** template type. **AGENTS.md** is the full source: Tech Stack, Commands (prefer scripts), Testing, Code Style, Repository Structure, Boundaries, **Safety and Permissions**, Git Workflow, Memory System, Prompt Validation (4 checks), Three Pillars (with change-type doc table), Workflows, Tool Selection, **Subagents for execution**, **Right tool for the job**, Key References.

---

## Quick Start

This repository is built on **six template types**:

1. **Rules** — How agents must behave (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, .cursor/rules)
2. **Blueprints** — What to build (product archetypes)
3. **Tasks** — How to implement (feature units)
4. **Recipes** — Feature combinations (bundles)
5. **Subagents** — Who does the work (configured sub-agents)
6. **Skills** — How to do it well (capabilities)

**"Templates"** = all six types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills). **Rules** are loaded by Cursor from this file or from `.cursor/rules/`. **In this repo** only **Rules** and **seven Skills** are active: **memory-system-setup**, **rules-setup**, **skill-builder**, **blueprints-setup**, **tasks-setup**, **recipes-setup**, **subagents-setup** (under `.agents/skills/`). Other template-type implementations are archived.

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
├── .agents/skills/            # 🧠 SKILLS (seven)
├── .memory/                   # Memory data (when in use)
├── docs/, plans/, _documentation-blueprint/
├── .cursor/rules/             # Optional Cursor rule files
├── blueprints/, tasks/, recipes/, subagents/   # When present or archived
└── scripts/                   # When present (framework/archive)
```

---

## Key References

| File | Purpose |
|------|---------|
| `AGENTIC-ASSETS-FRAMEWORK.md` | **Six template types** — Full framework |
| `AGENTS.md` | 📜 **Rules** — Canonical (build/test/lint, conventions, memory) |
| `CLAUDE.md` | 📜 **Rules** — Claude-specific |
| `CURSOR.md` | 📜 **Rules** — This file (Cursor-specific) |
| `WINDSURF.md` | 📜 **Rules** — Windsurf-specific |

When in doubt, read `AGENTS.md` and `AGENTIC-ASSETS-FRAMEWORK.md`.
