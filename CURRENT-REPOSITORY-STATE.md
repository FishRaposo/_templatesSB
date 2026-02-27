# Current Repository State

**Generated**: 2026-02-26  
**Purpose**: Inventory of current implementation in this repository  

**Current implementation**: Only **Rules** (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md) and **seven Skills** are actively maintained: **memory-system-setup**, **rules-setup**, **skill-builder**, **blueprints-setup**, **tasks-setup**, **recipes-setup**, **subagents-setup** (under `.agents/skills/`). Blueprints, Tasks, Recipes, Subagents, and legacy skill-packs are **archived** (see `_complete_archive/` and framework doc). The six template types are defined in `AGENTIC-ASSETS-FRAMEWORK.md` for reference.

**Total Items**: 600+ files across 10 main directories (including archived content).

---

## Root Directory Files

### Core Documentation
- **AGENTS.md** (21.4KB) - Agent framework with Three Pillars
- **CLAUDE.md** (39.8KB) - Claude AI comprehensive guide
- **WINDSURF.md** (2.8KB) - Windsurf AI guide
- **README.md** (3.2KB) - Repository overview and navigation

---

## Directory Structure Overview

```
├── .memory/                        # Memory data directory
├── .agents/
│   └── skills/                     # 🧠 Current skills (seven)
│       ├── memory-system-setup/
│       ├── rules-setup/
│       ├── skill-builder/
│       ├── blueprints-setup/
│       ├── tasks-setup/
│       ├── recipes-setup/
│       └── subagents-setup/
├── docs/                           # Documentation hub (~68 items)
├── plans/                          # Planning artifacts
├── _documentation-blueprint/       # Documentation blueprint system
└── _complete_archive/              # Archived content (legacy skill-packs, blueprints, tasks, etc.)
```

**Note:** This repo does not have top-level `blueprints/`, `tasks/`, `recipes/`, `subagents/`, `scripts/`, or `memory-system/`. Those are defined in the framework; implementations live in `_complete_archive/` or under `docs/` (e.g. `docs/memory-system/`).

---

## Detailed Directory Contents

### 📖 docs/ - Documentation Hub (~68 items)

#### Core Files
- **INDEX.md** - Complete documentation index
- **MEMORY_SYSTEM.md** - Memory system overview (when present)
- **THREE_PILLARS.md** - Three Pillars framework

#### Subdirectories
- **core/** - AGENTIC-RULES.md and agent behavior rules
- **guides/** - AGENT_SKILLS_GUIDE, TEMPLATE-SYSTEM-GUIDE, ADD-NEW-*-TEMPLATE guides
- **protocols/** - MEMORY-SYSTEM-PROTOCOL.md, PROMPT-VALIDATION-PROTOCOL.md
- **memory-system/** - Memory system docs, templates, scripts, and examples
- **templates/**, **examples/**, **technical/**, **universal/** - As documented in INDEX.md

### 📋 _documentation-blueprint/ - Blueprint System (25 items)

#### Core Files
- **DOCUMENTATION-BLUEPRINT.md** (25.4KB) - Complete blueprint system
- **QUICK-REFERENCE.md** (4.0KB) - Quick reference guide
- **QUICKSTART.md** (13.6KB) - Getting started guide

#### Subdirectories
- **templates/** (22 files) - Template collection

### 💾 docs/memory-system/ - Memory system reference

Memory system documentation, templates, scripts, and examples live under `docs/memory-system/`. Runtime data lives in `.memory/` at project root. See `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` and `.agents/skills/memory-system-setup/` for setup.

### 🤖 rules-setup / .agents/skills/rules-setup — Rules Template Setup

Creates and maintains the **Rules** template type: AGENTS.md (canonical) + CLAUDE.md, CURSOR.md, WINDSURF.md (ALL CAPS). Three Pillars (AUTOMATING with prefer scripts, TESTING, DOCUMENTING), Prompt Validation, six core areas. Fits the six-template-types framework.

#### Core Files
- **README.md** — Setup overview
- **SKILL.md** — Comprehensive setup skill
- **config.json** — Configuration

#### Subdirectories
- **_examples/** — Setup examples

### 🔧 skill-builder / .agents/skills/skill-builder — Skill Development

Skill creation and improvement. Use when creating or updating skills (SKILL.md, config.json, README, examples).

#### Core Files
- **README.md** — Quick-start guide
- **SKILL.md** — Complete skill definition
- **config.json** — Configuration

#### Guides
- **creating-skills-from-scratch.md** — Skill creation guide
- (Other conversion guides when present)

#### Subdirectories
- **reference/**, **scripts/**, **templates/**, **_examples/** — As needed

### 📚 skill-packs (archived)

Legacy skill packs (e.g. 1-programming-core, 2-code-quality) and HOW_TO_CREATE_SKILL_PACKS.md are **archived**. See `_complete_archive/`. Current skills live in `.agents/skills/` (memory-system-setup, rules-setup, skill-builder, blueprints-setup, tasks-setup, recipes-setup, subagents-setup).

### 🏗️ blueprints/ - Template Blueprints (archived)

Blueprint definitions (e.g. mins, saas-api, web-dashboard) are **archived**. See `AGENTIC-ASSETS-FRAMEWORK.md` for the Blueprints type; implementations in this repo are in `_complete_archive/` or archived directories.

### 🏗️ blueprints/, tasks/, recipes/, subagents/, features/, workflows/

**Not present at project root.** These are defined in `AGENTIC-ASSETS-FRAMEWORK.md`. Implementations in this repo are in `_complete_archive/` (e.g. archive_2026-02-26_18-50-32, templates-main). When a project adopts them, create the corresponding directories and use the framework docs.

### 📜 scripts/ - Automation (when present)

This repo has no top-level `scripts/`. Template automation is in framework reference or `_complete_archive/`. In-repo automation: `docs/memory-system/scripts/` (memory) when present, and `.agents/skills/skill-builder/scripts/` (validate-skill.js, etc.). When a project has top-level `scripts/`, use them per AGENTS.md.

### 📦 _complete_archive/ - Archived Content

Previous repository states, legacy skill-packs, blueprints, tasks, scripts, features, and workflows. See archive index and summary docs inside the archive. Restore or reference as needed; do not modify for current implementation.

---

## System Capabilities

### 🧠 Agent Framework
- **Three Pillars**: Automating, Testing, Documenting
- **Multi-agent support**: Claude, Windsurf, and other AI tools
- **Complete setup system**: Configuration and deployment

### 💾 Memory System
- **Event-sourced memory**: Complete protocol and implementation
- **Context management**: Graph-based context tracking
- **Automated maintenance**: Scripts for memory health

### 📋 Documentation System
- **Blueprint framework**: 18 required documentation files
- **Template system**: Multiple template categories
- **Automated generation**: Scripts for documentation creation

### 🔧 Skill Development
- **Skill builder**: `.agents/skills/skill-builder/` — skill creation and improvement
- **Current skills**: memory-system-setup, rules-setup, skill-builder, blueprints-setup, tasks-setup, recipes-setup, subagents-setup (in `.agents/skills/`)
- Legacy skill-packs are archived

### 🏗️ Template System
- **Blueprints, Tasks, Recipes, Subagents**: Defined in framework; implementations in this repo are archived

### ⚡ Automation
- **In this repo**: memory-system/scripts/ (memory), .agents/skills/skill-builder/scripts/ (skill validation)
- **When present**: Top-level scripts/ (validate-templates, setup-project, etc.) as in framework/archive

---

## Usage Statistics

- **Root**: Core docs (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, README, CHANGELOG, framework), `.agents/skills/` (7 skills), `.memory/`, `docs/` (~68 items), `_documentation-blueprint/`, `plans/`, `_complete_archive/`
- **Skills**: Seven skills in `.agents/skills/` (memory-system-setup, rules-setup, skill-builder, blueprints-setup, tasks-setup, recipes-setup, subagents-setup)
- **Documentation**: INDEX.md, protocols, guides, memory-system docs, and supporting dirs under `docs/`

---

## Integration Points

### Cross-System Dependencies
- **Memory System** ↔ **Agent Framework** via `.memory/` directory
- **Documentation Blueprint** ↔ **Skill Builder** via template system
- **Scripts** ↔ **All Systems** via automation and validation
- **Archive** ↔ **Current State** via restoration capability

### Workflow Integration
1. **Setup Phase**: Use `.agents/skills/rules-setup/` and `.agents/skills/skill-builder/`
2. **Development Phase**: When the project adopts them, use blueprints/, tasks/, recipes/, subagents/ (see framework and archive)
3. **Documentation Phase**: Use `_documentation-blueprint/` and `docs/`
4. **Maintenance Phase**: Use memory-system protocol, CHANGELOG, and skill-builder scripts as applicable

---

*Repository state captured: 2026-02-26*  
*Active: Rules (four rule files) + seven Skills in `.agents/skills/`. Blueprints, Tasks, Recipes, Subagents, and legacy skill-packs archived.*
