# AGENTS.md

## Project Overview

This repository is a **unified AI development ecosystem** built on five types of agentic assets:

1. **Blueprints** — What to build (product archetypes)
2. **Tasks** — How to implement a feature (implementation units)
3. **Recipes** — Feature combinations (bundles of Tasks + Skills)
4. **Agent Personas** — Who does the work (configured workers)
5. **Skills** — How to do it well (capabilities, best practices)

**"Templates"** refers collectively to all five asset types.

See `AGENTIC-ASSETS-FRAMEWORK.md` for complete definitions and relationships.

**Statistics**:
- **766 skills** across **60 planned packs** (2 completed)
- **47 tasks** across **9 categories**
- **12 technology stacks** with **3 complexity tiers** (MVP, Core, Enterprise)
- **Multi-file types**: Markdown, JSON, Python, YAML, Jinja2

---

## Build/Test/Lint Commands

### Skills (Markdown + JSON)
```bash
# Validate JSON syntax
find . -name "*.json" -exec python -m json.tool {} \; > /dev/null

# Check for broken cross-references
grep -r "\[.*\](.*)" --include="*.md" . | grep -v "http" | head -20

# Count skills and packs
find skill-packs -name "SKILL.md" | wc -l
```

### Tasks, Blueprints & Other Templates (Python)
```bash
# Full template system validation (CRITICAL - run before commits)
python scripts/validate-templates.py --full

# Blueprint validation
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"

# Task validation
python -c "from scripts.task_resolver import validate_task; print(validate_task('auth-basic'))"

# Autonomous project generation
python scripts/setup-project.py --auto --name "MyProject" --description "project description"

# Python syntax check
python -m py_compile scripts/*.py
```

---

## Code Style Guidelines

### Skills (Markdown + JSON)

**SKILL.md Structure:**
```yaml
---
name: skill-name
description: Use this skill when {specific scenarios}. This includes {capabilities}.
---

# Skill Title
I'll help you {primary benefit}...

# Core Approach
# Step-by-Step Instructions (JS/Python/Go examples)
# Best Practices
# Validation Checklist
## Related Skills
```

**config.json Structure:**
```json
{
  "agent_support": { "claude": {}, "roo": {}, "cascade": {}, "generic": {} },
  "triggers": { "keywords": ["8-10 terms"], "patterns": ["6-7 regex"] },
  "requirements": { "tools": [], "permissions": ["file_read", "file_write"] },
  "examples": { "simple": ["3 examples"], "complex": ["3 examples"] }
}
```

**DO:**
- Use action-oriented descriptions ("I'll help you...")
- Provide multi-language examples (JS/Python/Go minimum)
- Use ❌/✅ format for before/after code examples
- Keep YAML frontmatter minimal: only `name` and `description`
- Set `"tools": []` in config.json (language-agnostic)
- Keep README.md under 80 lines
- Use `kebab-case` for skill names
- Use underscore prefix for `_examples/` and `_reference-files/`

**DON'T:**
- Add curriculum/educational content (prerequisites, learning paths)
- Include theory, history, or background in SKILL.md files
- Use educational language ("learn", "study", "practice")
- Delete raw task outputs in `task-outputs/`
- Modify files in `_complete_archive/`

### Templates (Python + YAML + Jinja2)

**Naming Conventions:**
- Task directories: `kebab-case` (e.g., `web-scraping`, `auth-basic`)
- Template files: `.tpl.{ext}` extension
- Blueprint files: `blueprint.meta.yaml` + `BLUEPRINT.md`
- Stack directories: lowercase (e.g., `python/`, `flutter/`)

**Template Structure:**
```python
"""
# {Template Name} ({Tier} Tier - {Stack})

## Purpose
Provides {tier-specific} {stack} code structure for {task}.

## Usage
- {specific use cases}

## Structure
```{language}
{template code with {{placeholders}}}
```
"""
```

**Python Code Style:**
- Follow PEP 8, max line length 100
- Use type hints for function parameters
- Use pathlib for cross-platform paths
- Use f-strings for string formatting

### Blueprints (YAML)

**blueprint.meta.yaml Structure:**
```yaml
blueprint:
  id: "blueprint-id"
  version: "1.0.0"
  name: "Blueprint Name"
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
```

---

## Repository Structure

```
_templates/
├── AGENTS.md                     # This file - behavioral constraints
├── AGENTIC-ASSETS-FRAMEWORK.md   # Five asset types definitions
├── CHANGELOG.md                  # Event log (append-only)
├── README.md                     # Repository overview
├── SKILLS_MASTER_LIST.md         # 766 skills catalog
│
├── blueprints/                   # 📋 BLUEPRINTS
│   └── mins/
│       ├── BLUEPRINT.md          # Human-readable docs
│       ├── blueprint.meta.yaml   # Machine-readable config
│       └── overlays/             # Stack-specific extensions
│           ├── flutter/
│           ├── python/
│           └── ...
│
├── tasks/                        # 🏗️ TASKS
│   ├── task-index.yaml           # Unified task definitions
│   └── <task-name>/
│       ├── TASK.md               # Task documentation
│       ├── config.yaml           # Task configuration
│       ├── universal/            # Universal implementations
│       └── stacks/               # Stack-specific implementations
│           ├── python/
│           ├── node/
│           └── ...
│
├── recipes/                      # 🍳 RECIPES
│   └── <recipe-name>/
│       ├── recipe.yaml           # Recipe configuration
│       └── RECIPE.md             # Human-readable docs
│
├── agent-personas/               # 🤖 AGENT PERSONAS
│   └── <persona-name>/
│       ├── persona.yaml          # Agent configuration
│       ├── PERSONA.md            # Human-readable docs
│       └── workflows/            # Workflow definitions
│
├── skill-packs/                  # 🧠 SKILLS
│   ├── HOW_TO_CREATE_SKILL_PACKS.md
│   ├── 1-programming-core/       # 12 skills (COMPLETED)
│   │   ├── PACK.md
│   │   ├── QUICK_REFERENCE.md
│   │   └── <skill>/
│   │       ├── SKILL.md
│   │       ├── config.json
│   │       ├── README.md
│   │       └── _examples/
│   └── 2-code-quality/           # 12 skills (COMPLETED)
│
├── scripts/                      # 🔧 AUTOMATION
│   ├── setup-project.py          # Blueprint-driven setup
│   ├── validate-templates.py     # Template validation
│   ├── blueprint_config.py       # Blueprint management
│   └── task_resolver.py          # Task resolution
│
├── stacks/                       # Stack configurations
├── tiers/                        # Tier configurations
│
└── _complete_archive/            # PRESERVED HISTORY
```

---

## Memory System Protocol

Follow `MEMORY-SYSTEM-PROTOCOL.md`:

**Before every task:**
1. Read `AGENTS.md` (this file) — behavioral constraints
2. Check `CHANGELOG.md` — what happened recently
3. Read `.memory/context.md` — current trajectory

**After every task:**
1. Append event to `CHANGELOG.md`
2. Update derived views (graph.md, context.md)
3. Update this AGENTS.md if conventions changed

---

## Three Pillars — Task Completion Checklist

A task is **not complete** until all three pillars are satisfied:

1. ✅ **AUTOMATING** — Content validates against structural rules
   - Blueprints: YAML valid, metadata complete
   - Tasks: Task structure valid, implementations complete
   - Recipes: Recipe configuration valid, dependencies resolve
   - Agent Personas: persona.yaml valid, workflows defined
   - Skills: SKILL.md frontmatter valid, config.json valid

2. ✅ **TESTING** — Verification passes
   - Blueprints: Resolution confidence ≥ 1.00
   - Tasks: All stack variants work, examples are runnable
   - Recipes: All bundled tasks resolve correctly
   - Agent Personas: Workflows execute correctly
   - Skills: Trigger keywords work, examples are runnable

3. ✅ **DOCUMENTING** — Related docs updated
   - New blueprint: Update blueprint index, integration guides
   - New task: Update `task-index.yaml`, relevant docs
   - New recipe: Update recipe registry, cross-reference tasks
   - New agent persona: Update persona registry, add examples
   - New skill: Update `SKILLS_MASTER_LIST.md`, pack's `PACK.md`

---

## Workflows

### Adding a Blueprint
1. Create `blueprints/<name>/` directory
2. Create `blueprint.meta.yaml` with constraints
3. Create `BLUEPRINT.md` with human-readable docs
4. Create `overlays/<stack>/` for stack-specific extensions
5. Validate: `python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('name'))"`
6. Update documentation

### Adding a Task
1. Create `tasks/<task-name>/` directory
2. Create `TASK.md` with documentation
3. Create `config.yaml` with task configuration
4. Add `universal/` implementation (applies to all stacks)
5. Add `stacks/<stack>/` implementations (stack-specific)
6. Update `tasks/task-index.yaml`
7. Run `python scripts/validate-templates.py --full`

### Adding a Recipe
1. Create `recipes/<recipe-name>/` directory
2. Create `recipe.yaml` with task bundles and skills
3. Create `RECIPE.md` with human-readable docs
4. Validate recipe configuration
5. Update recipe registry
6. Update documentation

### Adding an Agent Persona
1. Create `agent-personas/<name>/` directory
2. Create `persona.yaml` with skills, blueprints, and workflows
3. Create `PERSONA.md` with human-readable docs
4. Create `workflows/` with defined workflow automations
5. Validate persona configuration
6. Update documentation

### Creating a Skill Pack
1. Create `PACK.md` with overview, skills list, relationships
2. Create `QUICK_REFERENCE.md` with decision tree
3. For each skill: `SKILL.md`, `config.json`, `README.md`, `_examples/`
4. Write verification tasks per `TASKS-TEMPLATE.md`
5. Run tasks, convert outputs to reference files
6. Create `_reference-files/INDEX.md`

### Autonomous Project Generation
```bash
python scripts/setup-project.py --auto --name "ProjectName" --description "project description"
```

---

## Tool Selection

| Task Type | Tool to Use |
|-----------|-------------|
| Single file edit | `edit` with exact text |
| Pattern matching | `bash` with `sed`/`python` |
| Multi-file changes | `task` tool with sub-agent |
| Complex logic | `bash` with Python script |
| Repo-wide refactoring | Spawn specialized sub-agent |

---

## Key References

### Asset Types Framework
- `AGENTIC-ASSETS-FRAMEWORK.md` — Complete definitions of the five asset types

### Blueprints
- `blueprints/mins/` — Example blueprint
- `blueprints/` directory — Product archetypes

### Tasks
- `tasks/task-index.yaml` — Unified task definitions
- `tasks/` directory — Implementation units

### Recipes
- `recipes/` directory — Feature combinations (proposed)

### Agent Personas
- `agent-personas/` directory — Configured workers (proposed)

### Skills
- `SKILLS_MASTER_LIST.md` — 766 skills catalog
- `HOW_TO_CREATE_SKILL_PACKS.md` — Pack creation guide
- `1-programming-core/` — Gold standard reference pack

### System & Tools
- `scripts/setup-project.py` — Project generation
- `scripts/validate-templates.py` — Validation
- `PROMPT-VALIDATION-PROTOCOL.md` — Validate before execution
- `MEMORY-SYSTEM-PROTOCOL.md` — Event-sourced memory

---

## When Stuck

- **Blueprints**: Study `blueprints/mins/` example
- **Tasks**: Review `tasks/web-scraping/` structure
- **Recipes**: See examples in `AGENTIC-ASSETS-FRAMEWORK.md`
- **Agent Personas**: See examples in `AGENTIC-ASSETS-FRAMEWORK.md`
- **Skills**: Check `1-programming-core/clean-code/` as reference
- **Framework**: Read `AGENTIC-ASSETS-FRAMEWORK.md` for complete definitions
- **Guidelines**: Read `HOW_TO_CREATE_SKILL_PACKS.md`
- **Validation**: Run `python scripts/validate-templates.py --full`
