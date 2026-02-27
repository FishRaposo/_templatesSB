# WINDSURF.md - Unified AI Development Guide

**Purpose**: Windsurf AI guide for the six template types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills).  
**Last Updated**: 2025

See `AGENTIC-ASSETS-FRAMEWORK.md` for complete framework documentation.

**Rule files**: This project uses four rule files—**AGENTS.md** (canonical), **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md** (this file)—one per tool or audience. All are examples of the **Rules** template type. **AGENTS.md** is the full source: Tech Stack, Commands (prefer scripts), Testing, Code Style, Repository Structure, Boundaries, **Safety and Permissions**, Git Workflow, Memory System, Prompt Validation (4 checks), Three Pillars (with change-type doc table), Workflows, Tool Selection, **Subagents for execution**, **Right tool for the job**, Key References.

---

## Quick Start

This repository is built on **six template types**:
1. **Rules** — How agents must behave (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md)
2. **Blueprints** — What to build (product archetypes)
3. **Tasks** — How to implement (feature units)
4. **Recipes** — Feature combinations (bundles)
5. **Subagents** — Who does the work (configured sub-agents)
6. **Skills** — How to do it well (capabilities)

**"Templates"** = all six types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills). **In this repo** only **Rules** and **seven Skills** are active: **memory-system-setup**, **rules-setup**, **skill-builder**, **blueprints-setup**, **tasks-setup**, **recipes-setup**, **subagents-setup** (under `.agents/skills/`). Other template-type implementations are archived.

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

---

## Repository Structure

```
├── AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md   # 📜 RULES
├── AGENTIC-ASSETS-FRAMEWORK.md
├── .agents/skills/            # 🧠 SKILLS (seven)
├── .memory/, docs/, plans/, _documentation-blueprint/
├── blueprints/, tasks/, recipes/, subagents/      # When present or archived
└── scripts/                  # When present (framework/archive)
```

---

## Skills System

### SKILL.md Template
```yaml
---
name: skill-name
description: Use this skill when {scenarios}. This includes {capabilities}.
---

# Skill Title
I'll help you {benefit}...

## Core Approach
## Step-by-Step Instructions

### JavaScript
```javascript
// ✅ Good
const result = await fetch('/api/data');
```

### Python
```python
# ✅ Good
result = requests.get('/api/data')
```

## Best Practices
## Validation Checklist
## Related Skills
```

### config.json Template
```json
{
  "agent_support": { "claude": {}, "roo": {}, "cascade": {}, "generic": {} },
  "triggers": { 
    "keywords": ["term1", "term2"], 
    "patterns": ["pattern1", "pattern2"] 
  },
  "requirements": { "tools": [], "permissions": ["file_read", "file_write"] },
  "examples": { "simple": ["ex1"], "complex": ["ex2"] }
}
```

### Skills Code Style
- Action-oriented: "I'll help you..."
- Multi-language examples (JS/Python/Go)
- ❌/✅ before/after format
- Minimal frontmatter (name, description only)
- `"tools": []` in config.json
- README.md < 80 lines
- `kebab-case` names
- `_examples/`, `_reference-files/` (underscore prefix)

---

## Templates System

### Template Structure
```python
"""
# {Name} ({Tier} - {Stack})

## Purpose
{What this template does}

## Usage
- {Use case 1}

## Structure
```python
def {{function}}({{params}}):
    {{body}}
```
"""
```

### Python Standards
- PEP 8, max 100 chars/line
- Type hints required
- pathlib for paths
- f-strings preferred

---

## Blueprints System

### blueprint.meta.yaml
```yaml
blueprint:
  id: "blueprint-id"
  name: "Blueprint Name"
  stacks:
    required: ["flutter"]
    recommended: ["python"]
  tier_defaults:
    flutter: "mvp"
  tasks:
    required: ["auth-basic"]
  overlays:
    flutter:
      - "overlays/flutter/file.tpl.dart"
```

### Validation
```bash
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"
```

---

## Three Pillars

Every task must satisfy:

1. **AUTOMATING** — Content validates; prefer scripts over manual steps
   - If something can be done with a script (especially reusable in `scripts/`), use the script.
   - Blueprints: YAML valid
   - Tasks: Structure valid
   - Recipes: Config valid
   - Subagents: subagent.yaml valid
   - Skills: Frontmatter/JSON valid

2. **TESTING** — Verification passes
   - Run: `python scripts/validate-templates.py --full`
   - Blueprints: Resolution ≥ 1.00
   - Tasks: All variants work
   - Recipes: Bundles resolve
   - Subagents: Workflows execute
   - Skills: Triggers work

3. **DOCUMENTING** — Docs updated
   - New skill (in `.agents/skills/`): Update AGENTS.md or skills index if present.
   - (When adopted: Blueprints → Index; Tasks → task-index.yaml; Recipes/Subagents → Registry.)

---

## Common Tasks

### Add Skill
1. Create `<skill>/` in pack
2. Add `SKILL.md`, `config.json`, `README.md`
3. Add `_examples/basic-examples.md`
4. Update `PACK.md`
5. Validate & update `CHANGELOG.md`

### Add Task
1. Create `tasks/<task>/`
2. Add `TASK.md`, `config.yaml`
3. Add universal + stack implementations
4. Update `task-index.yaml`
5. Run validation

### Add Recipe
1. Create `recipes/<recipe>/`
2. Add `recipe.yaml` with tasks + skills
3. Create `RECIPE.md`
4. Validate configuration

### Add Blueprint
1. Create `blueprints/<name>/`
2. Add `blueprint.meta.yaml`, `BLUEPRINT.md`
3. Create `overlays/<stack>/`
4. Validate resolution

### Add Subagent
1. Create `subagents/<name>/`
2. Add `subagent.yaml` with skills, workflows
3. Create `SUBAGENT.md`, `workflows/`
4. See `AGENTIC-ASSETS-FRAMEWORK.md` for examples

### Generate Project
```bash
python scripts/setup-project.py --auto --name "MyApp" --description "mobile app"
```

---

## Key Files

| File | Purpose |
|------|---------|
| `AGENTIC-ASSETS-FRAMEWORK.md` | **Six template types** — Complete framework |
| `AGENTS.md` | 📜 **Rules** — Canonical (main guide) |
| `CLAUDE.md` | 📜 **Rules** — Claude entry |
| `CURSOR.md` | 📜 **Rules** — Cursor entry |
| `WINDSURF.md` | 📜 **Rules** — This file (Windsurf entry) |
| `.agents/skills/` | 🧠 **Skills** — memory-system-setup, rules-setup, skill-builder, blueprints-setup, tasks-setup, recipes-setup, subagents-setup |
| `scripts/validate-templates.py` | Validation (when project includes scripts/) |
| `scripts/setup-project.py` | Project generation (when blueprints in use) |

---

## Memory System

**Before:** Read `AGENTS.md` → Check `CHANGELOG.md` → Read `.memory/context.md`

**After:** Append `CHANGELOG.md` → Update `.memory/*` → Update `AGENTS.md` if needed

---

## When Stuck

- **Skills**: Use `.agents/skills/rules-setup/`, `.agents/skills/memory-system-setup/`, or `.agents/skills/skill-builder/`; see `.agents/skills/skill-builder/` for creating skills.
- **Blueprints, Tasks, Recipes, Subagents**: See `AGENTIC-ASSETS-FRAMEWORK.md`; implementations in this repo are archived.
- **Validation**: When the project includes `scripts/validate-templates.py`, run it when templates/scripts are in use.
