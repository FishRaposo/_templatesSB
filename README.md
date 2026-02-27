# Unified AI Development Ecosystem

A comprehensive repository built on **four types of agentic assets** for AI-assisted software development.

**Last Updated**: 2025  
**Status**: Active Development

See `AGENTIC-ASSETS-FRAMEWORK.md` for complete framework documentation.

---

## 🎯 Five-Pillar Architecture

This repository is organized around five complementary asset types:

### 1. 📋 Blueprints
**What to build** — Product archetypes (YAML + Markdown)
- Product pattern definitions (MINS, SaaS API, etc.)
- Drive automated project generation
- Stack constraints and tier defaults
- 7-step resolution algorithm (1.00 confidence target)

### 2. 🏗️ Tasks
**How to implement** — Feature implementation units (Code + Config)
- **47 tasks** across **9 development categories**
- **12 technology stacks** with **3 complexity tiers** (MVP/Core/Enterprise)
- Complete feature implementations (not just code snippets)
- Stack-specific and tier-specific variants

### 3. 🍳 Recipes
**Feature combinations** — Bundles of Tasks + Skills (YAML + Markdown)
- Pre-configured feature sets for common scenarios
- E-commerce, SaaS starter, Analytics platform, etc.
- Stack/tier-agnostic (inherits from Tasks)
- Curated best practices via Skills

### 4. 🤖 Agent Personas
**Who does the work** — Configured workers (YAML + Markdown)
- Curated skill bundles for specific domains
- Defined workflows and automations
- Compatible blueprints and recipes
- Deployable AI workers (Code Reviewer, Tester, Architect, etc.)

### 5. 🧠 Skills
**How to do it well** — Capabilities & best practices (Markdown + JSON)
- **766 skills** across **60 planned packs** (2 completed)
- **14 categories** covering programming through industry verticals
- Multi-language examples (JavaScript, Python, Go, Rust)
- Action-oriented instruction packages

**"Templates"** refers collectively to all five asset types — the complete reusable system.

---

## 📁 Repository Structure

```
_templates/
├── AGENTS.md                      # Behavioral constraints for all agents
├── AGENTIC-ASSETS-FRAMEWORK.md    # Five asset types definitions
├── CLAUDE.md                      # Claude Code guide
├── Windsurf.md                    # Windsurf AI guide
├── CHANGELOG.md                   # Event log (append-only)
├── README.md                      # This file
├── SKILLS_MASTER_LIST.md          # 766 skills catalog
│
├── blueprints/                    # 📋 BLUEPRINTS
│   └── mins/
│       ├── BLUEPRINT.md           # Human-readable docs
│       ├── blueprint.meta.yaml    # Machine-readable config
│       └── overlays/              # Stack-specific extensions
│           ├── flutter/
│           ├── python/
│           └── ...
│
├── tasks/                         # 🏗️ TASKS
│   ├── task-index.yaml            # Unified task definitions
│   └── <task-name>/
│       ├── TASK.md                # Task documentation
│       ├── config.yaml            # Task configuration
│       ├── universal/             # Universal implementations
│       └── stacks/                # Stack-specific implementations
│           ├── python/
│           ├── node/
│           └── ...
│
├── recipes/                       # 🍳 RECIPES (proposed)
│   └── <recipe-name>/
│       ├── recipe.yaml            # Recipe configuration
│       └── RECIPE.md              # Human-readable docs
│
├── agent-personas/                # 🤖 AGENT PERSONAS (proposed)
│   └── <persona-name>/
│       ├── persona.yaml           # Agent configuration
│       ├── PERSONA.md             # Human-readable docs
│       └── workflows/             # Workflow definitions
│
├── skill-packs/                   # 🧠 SKILLS
│   ├── HOW_TO_CREATE_SKILL_PACKS.md
│   ├── 1-programming-core/        # 12 skills (COMPLETED)
│   │   ├── PACK.md
│   │   ├── QUICK_REFERENCE.md
│   │   └── <skill>/
│   │       ├── SKILL.md
│   │       ├── config.json
│   │       ├── README.md
│   │       └── _examples/
│   └── 2-code-quality/            # 12 skills (COMPLETED)
│
├── scripts/                       # 🔧 AUTOMATION
│   ├── setup-project.py           # Blueprint-driven setup
│   ├── validate-templates.py      # Template validation
│   ├── blueprint_config.py        # Blueprint management
│   └── task_resolver.py           # Task resolution
│
├── stacks/                        # Stack configurations
├── tiers/                         # Tier configurations
├── docs/                          # Documentation
│   ├── protocols/
│   │   ├── MEMORY-SYSTEM-PROTOCOL.md
│   │   └── PROMPT-VALIDATION-PROTOCOL.md
│   └── guides/
├── memory-system/                 # Memory system implementation
├── skill-builder/                 # Skill creation tools
└── _complete_archive/             # Preserved history
```

---

## 🚀 Quick Start

### Validate the System
```bash
# Validate JSON (skills)
find . -name "*.json" -exec python -m json.tool {} \; > /dev/null

# Validate templates & blueprints (CRITICAL before commits)
python scripts/validate-templates.py --full
```

### Generate a Project
```bash
# Autonomous blueprint-driven setup
python scripts/setup-project.py --auto --name "MyApp" --description "minimalist mobile app"

# Output example:
# 🤖 Blueprint: mins
# 📊 Resolution Confidence: 1.00
# 🔧 Stacks: flutter, python
# 📈 Tiers: {'flutter': 'mvp', 'python': 'core'}
# 📋 Tasks: 5 total
```

### Create a Skill
1. See `skill-packs/HOW_TO_CREATE_SKILL_PACKS.md`
2. Use `1-programming-core/` as gold standard
3. Follow Three Pillars framework

### Create a Blueprint
1. Create `blueprints/<name>/` directory
2. Add `blueprint.meta.yaml` and `BLUEPRINT.md`
3. Create overlay templates in `overlays/<stack>/`
4. Validate: `python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('name'))"`

### Create a Task
1. Create `tasks/<task-name>/` directory
2. Add `TASK.md` with documentation and `config.yaml` with configuration
3. Add `universal/` implementation (applies to all stacks)
4. Add `stacks/<stack>/` implementations (stack-specific)
5. Update `tasks/task-index.yaml`
6. Run `python scripts/validate-templates.py --full`

### Create a Recipe
1. Create `recipes/<recipe-name>/` directory
2. Add `recipe.yaml` with task bundles and skills
3. Create `RECIPE.md` with human-readable docs
4. Validate recipe configuration
5. Update recipe registry
6. Update documentation

### Create an Agent Persona
1. Create `agent-personas/<name>/` directory
2. Add `persona.yaml` with skills, blueprints, and workflows
3. Create `PERSONA.md` and `workflows/` definitions
4. See `AGENTIC-ASSETS-FRAMEWORK.md` for examples

---

## 🏛️ Three Pillars Framework

Every task must satisfy all three pillars:

1. **AUTOMATING** — Content validates against structural rules
   - Blueprints: YAML valid, metadata complete
   - Tasks: Task structure valid, implementations complete
   - Recipes: Recipe configuration valid, dependencies resolve
   - Agent Personas: persona.yaml valid, workflows defined
   - Skills: SKILL.md frontmatter valid, config.json valid

2. **TESTING** — Verification passes
   - Blueprints: Resolution confidence ≥ 1.00
   - Tasks: All stack variants work, examples are runnable
   - Recipes: All bundled tasks resolve correctly
   - Agent Personas: Workflows execute correctly
   - Skills: Trigger keywords work, examples are runnable

3. **DOCUMENTING** — Related docs updated
   - New blueprint: Update blueprint index, integration guides
   - New task: Update `task-index.yaml`, relevant docs
   - New recipe: Update recipe registry, cross-reference tasks
   - New agent persona: Update persona registry, add examples
   - New skill: Update `SKILLS_MASTER_LIST.md`, pack's `PACK.md`

---

## 📚 Key Documentation

| File | Purpose |
|------|---------|
| `AGENTIC-ASSETS-FRAMEWORK.md` | **Five asset types** — Complete framework definitions |
| `AGENTS.md` | **Start here** — Behavioral constraints for all agents |
| `CLAUDE.md` | Claude Code comprehensive guide |
| `Windsurf.md` | Windsurf AI quick reference |
| `SKILLS_MASTER_LIST.md` | Complete catalog of 766 skills |
| `HOW_TO_CREATE_SKILL_PACKS.md` | Creation guide for all asset types |
| `MEMORY-SYSTEM-PROTOCOL.md` | Event-sourced memory system |
| `PROMPT-VALIDATION-PROTOCOL.md` | Prompt validation rules |

---

## 🔧 Code Style

### Skills (Markdown + JSON)
- **SKILL.md**: Minimal YAML frontmatter (`name`, `description` only)
- **config.json**: Language-agnostic (`"tools": []`)
- Multi-language examples (JS/Python/Go)
- ❌/✅ before/after format
- `kebab-case` names

### Tasks (Python + YAML + Jinja2)
- **TASK.md**: Usage documentation and examples
- **config.yaml**: Task configuration and dependencies
- PEP 8, max 100 chars/line
- Type hints required
- `pathlib` for cross-platform paths
- `.tpl.{ext}` files are implementation detail inside Tasks

### Recipes (YAML + Markdown)
- **recipe.yaml**: Task bundles and skill combinations
- **RECIPE.md**: Human-readable documentation
- Versioned combinations
- Tested configurations

### Agent Personas (YAML + Markdown)
- **persona.yaml**: Skills, blueprints, workflows configuration
- **PERSONA.md**: Human-readable documentation
- **workflows/**: Defined automation workflows

### Blueprints (YAML)
- **blueprint.meta.yaml**: Machine-readable configuration
- **BLUEPRINT.md**: Human-readable documentation
- Stack constraints: `required`, `recommended`, `supported`
- Tier defaults per stack

---

## 🧪 Validation Commands

```bash
# Skills
find . -name "*.json" -exec python -m json.tool {} \; > /dev/null
grep -r "\[.*\](.*)" --include="*.md" . | grep -v "http" | head -20

# Tasks, Blueprints & Other Templates
python scripts/validate-templates.py --full
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"
python -c "from scripts.task_resolver import validate_task; print(validate_task('auth-basic'))"
python -m py_compile scripts/*.py
```

---

## 📊 Statistics

| Asset Type | Count | Status |
|------------|-------|--------|
| **Blueprints** | Multiple archetypes | MINS, SaaS API, etc. |
| **Tasks** | 47 across 9 categories | 655+ code templates |
| **Recipes** | Proposed | E-commerce, SaaS starter, etc. |
| **Agent Personas** | Proposed | Code reviewer, tester, architect |
| **Skills** | 766 across 60 packs | 2 completed packs (24 skills) |
| **Stacks** | 12 supported | Python, Node, Go, Flutter, React, etc. |
| **Tiers** | 3 complexity levels | MVP, Core, Enterprise |

---

## 🆘 When Stuck

- **Framework**: Read `AGENTIC-ASSETS-FRAMEWORK.md` for complete definitions
- **Blueprints**: Study `blueprints/mins/` example
- **Tasks**: Review `tasks/web-scraping/` structure
- **Recipes**: See examples in `AGENTIC-ASSETS-FRAMEWORK.md`
- **Agent Personas**: See examples in `AGENTIC-ASSETS-FRAMEWORK.md`
- **Skills**: Check `1-programming-core/clean-code/` as reference
- **Validation**: Run `python scripts/validate-templates.py --full --detailed`
- **Guidelines**: Read `HOW_TO_CREATE_SKILL_PACKS.md`

---

## 📝 Archive

Previous repository content preserved in `_complete_archive/` for reference.

---

**Remember**: This is a unified ecosystem. Skills inform templates, templates implement blueprints, blueprints drive project generation. All three systems work together.
