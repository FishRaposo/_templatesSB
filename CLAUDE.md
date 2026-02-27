# CLAUDE.md - Unified AI Development Ecosystem

**Purpose**: Guide for Claude Code working with Skills, Templates, and Blueprints.  
**Last Updated**: 2025

---

## Project Overview

This repository is built on **five types of agentic assets**:

1. **Blueprints** — What to build (product archetypes)
2. **Tasks** — How to implement a feature (implementation units)
3. **Recipes** — Feature combinations (bundles of Tasks + Skills)
4. **Agent Personas** — Who does the work (configured workers)
5. **Skills** — How to do it well (capabilities, best practices)

**"Templates"** refers collectively to all five asset types.

See `AGENTIC-ASSETS-FRAMEWORK.md` for complete framework documentation.

**Statistics**:
- **766 skills** across **60 packs** (2 completed)
- **47 tasks** across **9 categories**
- **12 technology stacks** with **MVP/Core/Enterprise tiers**

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
# CRITICAL: Run before any commit
python scripts/validate-templates.py --full

# Blueprint-driven project setup
python scripts/setup-project.py --auto --name "Project" --description "desc"

# Blueprint validation
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"

# Task analysis
python scripts/detect_project_tasks.py --description "project requirements"
```

---

## Architecture

### Blueprints System
```
blueprints/
└── mins/                         # MINS blueprint example
    ├── BLUEPRINT.md              # Human-readable docs
    ├── blueprint.meta.yaml       # Machine-readable metadata
    └── overlays/                 # Stack-specific extensions
        ├── flutter/
        └── python/
```

### Tasks System
```
tasks/
├── task-index.yaml               # Master task configuration
└── <task-name>/
    ├── TASK.md                   # Task documentation
    ├── config.yaml               # Task configuration
    ├── universal/                # Universal implementations
    │   └── {task}-universal.tpl.py
    └── stacks/                   # Stack-specific
        ├── python/
        ├── node/
        └── ...
```

### Recipes System (Proposed)
```
recipes/
└── <recipe-name>/                # e.g., ecommerce, saas-starter
    ├── recipe.yaml               # Recipe configuration
    └── RECIPE.md                 # Human-readable docs
```

### Agent Personas System (Proposed)
```
agent-personas/
└── <persona-name>/               # e.g., code-reviewer, testing-agent
    ├── persona.yaml              # Agent configuration
    ├── PERSONA.md                # Human-readable docs
    └── workflows/                # Workflow definitions
        └── *.yaml
```

### Skills System
```
skill-packs/
├── 1-programming-core/           # 12 skills (COMPLETED)
│   ├── PACK.md                   # Pack overview
│   ├── QUICK_REFERENCE.md        # Decision tree
│   └── <skill>/
│       ├── SKILL.md              # Full skill definition
│       ├── config.json           # Triggers & patterns
│       ├── README.md             # Quick-start
│       └── _examples/
└── 2-code-quality/               # 12 skills (COMPLETED)
```

### Directory Overview
```
_templates/
├── AGENTS.md, AGENTIC-ASSETS-FRAMEWORK.md  # Core docs
├── CHANGELOG.md                            # Event log
├── blueprints/                             # Blueprints
├── tasks/                                  # Tasks
├── recipes/                                # Recipes (proposed)
├── agent-personas/                         # Agent Personas (proposed)
├── skill-packs/                            # Skills
├── scripts/                                # Automation
│   ├── setup-project.py
│   ├── validate-templates.py
│   ├── blueprint_config.py
│   └── task_resolver.py
├── stacks/                                 # Stack configurations
├── tiers/                                  # Tier configurations
└── _complete_archive/                      # Preserved history
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

1. **AUTOMATING** — Validates against structural rules
   - Blueprints: YAML valid, metadata complete
   - Tasks: Structure valid, implementations complete
   - Recipes: Configuration valid, dependencies resolve
   - Agent Personas: persona.yaml valid, workflows defined
   - Skills: Frontmatter valid, JSON valid

2. **TESTING** — Verification passes
   - Run: `python scripts/validate-templates.py --full`
   - Blueprints: Resolution ≥ 1.00
   - Tasks: All stack variants work
   - Recipes: All bundled tasks resolve
   - Agent Personas: Workflows execute correctly
   - Skills: Trigger keywords work

3. **DOCUMENTING** — Update related docs
   - New blueprint → Blueprint index
   - New task → `task-index.yaml`
   - New recipe → Recipe registry
   - New agent persona → Persona registry
   - New skill → `SKILLS_MASTER_LIST.md`, `PACK.md`

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
| `AGENTIC-ASSETS-FRAMEWORK.md` | **Five asset types** — Complete framework |
| `AGENTS.md` | Behavioral constraints |
| `blueprints/mins/` | Blueprint example |
| `tasks/task-index.yaml` | Task definitions |
| `recipes/` | Recipes (proposed) |
| `agent-personas/` | Agent Personas (proposed) |
| `SKILLS_MASTER_LIST.md` | 766 skills catalog |
| `HOW_TO_CREATE_SKILL_PACKS.md` | Creation guide for all assets |
| `scripts/setup-project.py` | Project generation |
| `scripts/validate-templates.py` | Validation |
| `1-programming-core/` | Gold standard pack |
| `PROMPT-VALIDATION-PROTOCOL.md` | Prompt validation |
| `MEMORY-SYSTEM-PROTOCOL.md` | Memory system |

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

- **Skills**: Check `1-programming-core/clean-code/`
- **Templates**: Review `tasks/web-scraping/`
- **Blueprints**: Study `blueprints/mins/`
- **Validation**: Run `python scripts/validate-templates.py --full --detailed`
- **Guidelines**: Read `HOW_TO_CREATE_SKILL_PACKS.md`

---

## Critical Policies

1. **Always validate**: `python scripts/validate-templates.py --full`
2. **Three Pillars mandatory**: Every task must satisfy all three
3. **Update CHANGELOG.md**: After every task
4. **No educational content**: Action-oriented only
5. **Preserve archive**: Never modify `_complete_archive/`
6. **Keep task outputs**: Never delete `task-outputs/`
