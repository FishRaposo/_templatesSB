# CLAUDE.md - Unified AI Development Ecosystem

**Purpose**: Guide for Claude Code working with Skills, Templates, and Blueprints.  
**Last Updated**: 2025

---

## Project Overview

This repository is built on **six template types**:

1. **Rules** — How agents must behave. **AGENTS.md**, **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md** are examples of Rules.
2. **Blueprints** — What to build (product archetypes)
3. **Tasks** — How to implement a feature (implementation units)
4. **Recipes** — Feature combinations (bundles of Tasks + Skills)
5. **Subagents** — Who does the work (configured sub-agents)
6. **Skills** — How to do it well (capabilities, best practices)

**"Templates"** = all six types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills). **Rules** (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, .cursor/rules) are one template type; Subagents and Skills run within them. See `AGENTIC-ASSETS-FRAMEWORK.md` → "Rules, Skills, and Subagents."

See `AGENTIC-ASSETS-FRAMEWORK.md` for complete framework documentation. **AGENTS.md** is the canonical rules file and includes: Tech Stack, Commands (prefer scripts), Testing, Code Style, Repository Structure, Boundaries, **Safety and Permissions**, Git Workflow, Memory System, Prompt Validation (4 checks), Three Pillars (with change-type doc table), Workflows, Tool Selection, **Subagents for execution**, **Right tool for the job**, Key References.

**Current implementation in this repo**: Only **Rules** (four rule files) and **seven Skills** are active—**memory-system-setup**, **rules-setup**, **skill-builder**, **blueprints-setup**, **tasks-setup**, **recipes-setup**, **subagents-setup** (under `.agents/skills/`). Blueprints, Tasks, Recipes, Subagents, and legacy skill-packs are archived.

---

## Essential Commands

### Skills (Markdown + JSON)
```bash
# Validate JSON
find . -name "*.json" -exec python -m json.tool {} \; > /dev/null

# Check cross-references
grep -r "\[.*\](.*)" --include="*.md" . | grep -v "http" | head -20
```

### Templates & Blueprints (Python)
```bash
# When the project includes a scripts/ directory with template automation:
# CRITICAL: Run before any commit
python scripts/validate-templates.py --full

# Blueprint-driven project setup
python scripts/setup-project.py --auto --name "Project" --description "desc"

# Blueprint validation
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"

# Task analysis
python scripts/detect_project_tasks.py --description "project requirements"
# This repo does not currently ship these scripts; they are framework/archived reference.
```

---

## Architecture

The framework defines six template types; **in this repo** only **Rules** and **Skills** (the seven in `.agents/skills/`) are implemented. The following are reference structures for when a project adopts each type.

### Blueprints (archived in this repo)
- **Location**: `blueprints/`. Structure: `BLUEPRINT.md`, `blueprint.meta.yaml`, `overlays/<stack>/`. See `AGENTIC-ASSETS-FRAMEWORK.md`.

### Tasks (archived in this repo)
- **Location**: `tasks/`. Structure: `task-index.yaml`, per-task `TASK.md`, `config.yaml`, `universal/`, `stacks/<stack>/`. See `AGENTIC-ASSETS-FRAMEWORK.md`.

### Recipes (archived in this repo)
- **Location**: `recipes/`. Structure: `recipe.yaml`, `RECIPE.md`. See `AGENTIC-ASSETS-FRAMEWORK.md`.

### Subagents (archived in this repo)
- **Location**: `subagents/`. Structure: `subagent.yaml`, `SUBAGENT.md`, `workflows/`. See `AGENTIC-ASSETS-FRAMEWORK.md`.

### Skills (current)
- **Location**: `.agents/skills/`. Current skills: **memory-system-setup**, **rules-setup**, **skill-builder**, **blueprints-setup**, **tasks-setup**, **recipes-setup**, **subagents-setup**. Use `.agents/skills/skill-builder/` to create or improve skills; `.agents/skills/rules-setup/` for the four rule files; `.agents/skills/memory-system-setup/` for the memory system.

### Directory Overview
```
<project root>/
├── AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md   # 📜 RULES
├── AGENTIC-ASSETS-FRAMEWORK.md   # Six template types
├── CHANGELOG.md, README.md
├── .agents/
│   └── skills/                   # 🧠 SKILLS (seven)
│       ├── memory-system-setup/
│       ├── rules-setup/
│       ├── skill-builder/
│       ├── blueprints-setup/
│       ├── tasks-setup/
│       ├── recipes-setup/
│       └── subagents-setup/
├── .memory/, docs/, plans/, _documentation-blueprint/
├── blueprints/, tasks/, recipes/, subagents/     # When present or archived
├── scripts/                      # When present (framework/archive)
└── _complete_archive/            # Preserved history
```

---

## Code Style

### Skills

**SKILL.md:**
```yaml
---
name: skill-name
description: Use this skill when {scenarios}. This includes {capabilities}.
---

# Skill Title
I'll help you {primary benefit}...

## Core Approach

## Step-by-Step Instructions

### JavaScript
```javascript
// ✅ Good example
const result = await fetch('/api/data');
```

### Python
```python
# ✅ Good example
result = requests.get('/api/data')
```

### Go
```go
// ✅ Good example
resp, err := http.Get("/api/data")
```

## Best Practices
## Validation Checklist
## Related Skills
```

**config.json:**
```json
{
  "agent_support": { "claude": {}, "roo": {}, "cascade": {}, "generic": {} },
  "triggers": { "keywords": ["term1", "term2"], "patterns": ["pattern1", "pattern2"] },
  "requirements": { "tools": [], "permissions": ["file_read", "file_write"] },
  "examples": { "simple": ["ex1", "ex2"], "complex": ["ex3"] }
}
```

### Templates

**Template Pattern:**
```python
"""
# {Name} Template ({Tier} - {Stack})

## Purpose
Provides {tier-specific} {stack} code for {task}.

## Usage
- {use case 1}
- {use case 2}

## Structure
```python
def {{function_name}}({{parameters}}):
    \"\"\"{{description}}\"\"\" 
    {{implementation}}
```
"""
```

**Python Standards:**
- PEP 8, max line length 100
- Type hints required
- pathlib for cross-platform paths
- f-strings preferred

### Blueprints

**blueprint.meta.yaml:**
```yaml
blueprint:
  id: "blueprint-id"
  version: "1.0.0"
  name: "Blueprint Name"
  category: "micro_saas"
  stacks:
    required: ["flutter"]
    recommended: ["python"]
    supported: ["node", "go"]
  tier_defaults:
    flutter: "mvp"
    python: "core"
  tasks:
    required: ["auth-basic", "crud-module"]
    recommended: ["analytics-event-pipeline"]
  overlays:
    flutter:
      - "overlays/flutter/app-structure.tpl.dart"
```

---

## Three Pillars Framework

Every task must satisfy:

1. **AUTOMATING** — Validates against structural rules; prefer scripts over manual steps
   - If a task can be done with a script (especially a reusable one in `scripts/`), use the script instead of doing it manually.
   - Blueprints: YAML valid, metadata complete
   - Tasks: Structure valid, implementations complete
   - Recipes: Configuration valid, dependencies resolve
   - Subagents: subagent.yaml valid, workflows defined
   - Skills: Frontmatter valid, JSON valid

2. **TESTING** — Verification passes
   - Run: `python scripts/validate-templates.py --full`
   - Blueprints: Resolution ≥ 1.00
   - Tasks: All stack variants work
   - Recipes: All bundled tasks resolve
   - Subagents: Workflows execute correctly
   - Skills: Trigger keywords work

3. **DOCUMENTING** — Update related docs
   - New skill (in `.agents/skills/`): Update AGENTS.md or skills index if present.
   - (When adopted: blueprint index, task-index.yaml, recipe registry, subagent registry.)

---

## Common Tasks

### Add a Skill to Pack
1. Create `<skill-name>/` in pack directory
2. Add `SKILL.md`, `config.json`, `README.md`
3. Add `_examples/basic-examples.md`
4. Update `PACK.md`, `QUICK_REFERENCE.md`
5. Validate & update `CHANGELOG.md`

### Create Reference Files
1. Write tasks per `TASKS-TEMPLATE.md`
2. Save outputs to `task-outputs/`
3. Convert to standalone files
4. Create `INDEX.md`, cross-link

### Add a Blueprint
1. Create `blueprints/<name>/`
2. Add `blueprint.meta.yaml`, `BLUEPRINT.md`
3. Create `overlays/<stack>/` templates
4. Validate resolution
5. Update documentation

### Add a Task
1. Create `tasks/<task-name>/`
2. Add `TASK.md` and `config.yaml`
3. Add universal + stack-specific implementations
4. Update `task-index.yaml`
5. Run validation

### Add a Recipe
1. Create `recipes/<recipe-name>/`
2. Add `recipe.yaml` with tasks and skills
3. Create `RECIPE.md`
4. Validate configuration
5. Update documentation

### Autonomous Project Generation
```bash
python scripts/setup-project.py --auto --name "MyApp" --description "minimalist mobile app"
# Output: 🤖 Blueprint: mins | Confidence: 1.00 | Stacks: flutter, python
```

---

## Key Files

| File | Purpose |
|------|---------|
| `AGENTIC-ASSETS-FRAMEWORK.md` | **Six template types** — Complete framework |
| `AGENTS.md` | 📜 **Rules** — Canonical (start here) |
| `CLAUDE.md` | 📜 **Rules** — Claude entry |
| `CURSOR.md` | 📜 **Rules** — Cursor entry |
| `WINDSURF.md` | 📜 **Rules** — Windsurf entry |
| `.agents/skills/` | 🧠 **Skills** — memory-system-setup, rules-setup, skill-builder, blueprints-setup, tasks-setup, recipes-setup, subagents-setup |
| `scripts/validate-templates.py` | Validation (when project includes it) |
| `scripts/setup-project.py` | Project generation (when project includes it) |
| `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` | Prompt validation |
| `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` | Memory system |

---

## Memory System

**Before tasks:**
1. Read `AGENTS.md`
2. Check `CHANGELOG.md`
3. Read `.memory/context.md`

**After tasks:**
1. Append to `CHANGELOG.md`
2. Update `.memory/graph.md`, `.memory/context.md`
3. Update `AGENTS.md` if conventions changed

---

## When Stuck

- **Rules**: Read `AGENTS.md`; see `AGENTIC-ASSETS-FRAMEWORK.md` → "Rules, Skills, and Subagents."
- **Skills**: Use `.agents/skills/rules-setup/`, `.agents/skills/memory-system-setup/`, or `.agents/skills/skill-builder/`; see `.agents/skills/skill-builder/` for creating skills.
- **Blueprints, Tasks, Recipes, Subagents**: Defined in `AGENTIC-ASSETS-FRAMEWORK.md`; implementations in this repo are archived.
- **Validation**: When the project includes `scripts/validate-templates.py`, run `python scripts/validate-templates.py --full` when templates/scripts are in use.

---

## Critical Policies

1. **Always validate**: When the project includes it, run `python scripts/validate-templates.py --full`
2. **Three Pillars mandatory**: Every task must satisfy all three
3. **Update CHANGELOG.md**: After every task
4. **No educational content**: Action-oriented only
5. **Preserve archive**: Never modify `_complete_archive/`
6. **Keep task outputs**: Never delete `task-outputs/`
