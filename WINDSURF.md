# Windsurf.md - Unified AI Development Guide

**Purpose**: Windsurf AI guide for five agentic asset types.  
**Last Updated**: 2025

See `AGENTIC-ASSETS-FRAMEWORK.md` for complete framework documentation.

---

## Quick Start

This repository is built on **five asset types**:
1. **Blueprints** — What to build (product archetypes)
2. **Tasks** — How to implement (feature units)
3. **Recipes** — Feature combinations (bundles)
4. **Agent Personas** — Who does the work (configured workers)
5. **Skills** — How to do it well (capabilities)

**"Templates"** = all five types together

```bash
# Validate JSON (skills)
find . -name "*.json" -exec python -m json.tool {} \; > /dev/null

# Validate templates & blueprints (CRITICAL before commits)
python scripts/validate-templates.py --full

# Generate project
python scripts/setup-project.py --auto --name "Project" --description "desc"
```

---

## Repository Structure

```
├── blueprints/               # 📋 BLUEPRINTS (YAML)
│   └── mins/
│       ├── blueprint.meta.yaml
│       └── overlays/
│
├── tasks/                    # 🏗️ TASKS (Python/YAML/Jinja2)
│   ├── task-index.yaml
│   └── <task>/
│       ├── TASK.md
│       ├── config.yaml
│       ├── universal/
│       └── stacks/
│
├── recipes/                  # 🍳 RECIPES (proposed)
│   └── <recipe>/
│       ├── recipe.yaml
│       └── RECIPE.md
│
├── agent-personas/           # 🤖 AGENT PERSONAS (proposed)
│   └── <persona>/
│       ├── persona.yaml
│       ├── PERSONA.md
│       └── workflows/
│
├── skill-packs/              # 🧠 SKILLS (Markdown + JSON)
│   ├── 1-programming-core/   # 12 skills
│   └── 2-code-quality/       # 12 skills
│
└── scripts/                  # 🔧 AUTOMATION
    ├── setup-project.py
    └── validate-templates.py
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

1. **AUTOMATING** — Content validates
   - Blueprints: YAML valid
   - Tasks: Structure valid
   - Recipes: Config valid
   - Agent Personas: persona.yaml valid
   - Skills: Frontmatter/JSON valid

2. **TESTING** — Verification passes
   - Run: `python scripts/validate-templates.py --full`
   - Blueprints: Resolution ≥ 1.00
   - Tasks: All variants work
   - Recipes: Bundles resolve
   - Agent Personas: Workflows execute
   - Skills: Triggers work

3. **DOCUMENTING** — Docs updated
   - Blueprints → Index
   - Tasks → `task-index.yaml`
   - Recipes → Registry
   - Agent Personas → Registry
   - Skills → `SKILLS_MASTER_LIST.md`

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

### Add Agent Persona
1. Create `agent-personas/<name>/`
2. Add `persona.yaml` with skills, workflows
3. Create `PERSONA.md`, `workflows/`
4. See `AGENTIC-ASSETS-FRAMEWORK.md` for examples

### Generate Project
```bash
python scripts/setup-project.py --auto --name "MyApp" --description "mobile app"
```

---

## Key Files

| File | Purpose |
|------|---------|
| `AGENTIC-ASSETS-FRAMEWORK.md` | **Five asset types** — Complete framework |
| `AGENTS.md` | Main guide |
| `blueprints/mins/` | Blueprint example |
| `tasks/task-index.yaml` | Task definitions |
| `recipes/` | Recipes (proposed) |
| `agent-personas/` | Agent Personas (proposed) |
| `SKILLS_MASTER_LIST.md` | 766 skills |
| `HOW_TO_CREATE_SKILL_PACKS.md` | Creation guide |
| `scripts/validate-templates.py` | Validation |
| `1-programming-core/` | Gold standard |

---

## Memory System

**Before:** Read `AGENTS.md` → Check `CHANGELOG.md` → Read `.memory/context.md`

**After:** Append `CHANGELOG.md` → Update `.memory/*` → Update `AGENTS.md` if needed

---

## When Stuck

- Skills: `1-programming-core/clean-code/`
- Templates: `tasks/web-scraping/`
- Blueprints: `blueprints/mins/`
- Validation: `python scripts/validate-templates.py --full`
