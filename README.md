# Unified AI Development Ecosystem

A comprehensive repository built on **six template types** for AI-assisted software development.

**Last Updated**: 2025  
**Status**: Active Development

See `AGENTIC-ASSETS-FRAMEWORK.md` for complete framework documentation.

---

## 🎯 Six-Pillar Architecture

This repository is organized around **six complementary template types**:

### 1. 📜 Rules
**How agents must behave** — Tool- and audience-specific constraints (Markdown)
- **AGENTS.md** — Canonical, tool-agnostic rules (start here)
- **CLAUDE.md** — Claude Code guide
- **CURSOR.md** — Cursor AI guide
- **WINDSURF.md** — Windsurf AI guide
- Same project, different entry points per tool; Subagents and Skills run within these Rules

### 2. 📋 Blueprints
**What to build** — Product archetypes (YAML + Markdown). Defined in the framework; implementations in this repo are **archived**.

### 3. 🏗️ Tasks
**How to implement** — Feature implementation units. Defined in the framework; implementations in this repo are **archived**.

### 4. 🍳 Recipes
**Feature combinations** — Bundles of Tasks + Skills. Defined in the framework; implementations in this repo are **archived**.

### 5. 🤖 Subagents
**Who does the work** — Configured workers. Defined in the framework; implementations in this repo are **archived**.

### 6. 🧠 Skills
**How to do it well** — Capabilities & best practices (Markdown + JSON)
- **Current skills in this repo**: **memory-system-setup**, **rules-setup**, **skill-builder**, **blueprints-setup**, **tasks-setup**, **recipes-setup**, **subagents-setup** (under `.agents/skills/`)
- Use `.agents/skills/skill-builder/` to create or improve skills; `.agents/skills/rules-setup/` for the four rule files; `.agents/skills/memory-system-setup/` for the memory system
- Legacy skill-packs (e.g. 1-programming-core, 2-code-quality) are **archived**

**"Templates"** refers to all six types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills).

---

## 📁 Repository Structure

```
<project root>/
├── AGENTS.md                      # 📜 RULES — Canonical
├── CLAUDE.md                      # 📜 RULES — Claude
├── CURSOR.md                      # 📜 RULES — Cursor
├── WINDSURF.md                    # 📜 RULES — Windsurf
├── AGENTIC-ASSETS-FRAMEWORK.md    # Six template types definitions
├── CHANGELOG.md                   # Event log (append-only)
├── README.md                      # This file
├── CURRENT-REPOSITORY-STATE.md    # Repository inventory
│
├── .agents/
│   └── skills/                    # 🧠 SKILLS (seven skills)
│       ├── memory-system-setup/
│       ├── rules-setup/
│       ├── skill-builder/
│       ├── blueprints-setup/
│       ├── tasks-setup/
│       ├── recipes-setup/
│       └── subagents-setup/
│
├── .memory/                       # Memory system data (when in use)
├── docs/                          # Documentation & protocols
├── plans/                         # Planning artifacts (when present)
├── _documentation-blueprint/      # Documentation blueprint
│
├── blueprints/, tasks/, recipes/, subagents/, scripts/  # Not at root; see framework or _complete_archive/
└── _complete_archive/             # Preserved history (incl. legacy skill-packs)
```

---

## 🚀 Quick Start

### Validate the System
```bash
# Validate JSON (skills)
find . -name "*.json" -exec python -m json.tool {} \; > /dev/null

# When the project includes a scripts/ directory with template automation:
python scripts/validate-templates.py --full
```

### Generate a Project
```bash
# When the project includes scripts/setup-project.py (e.g. from framework or archive):
# Autonomous blueprint-driven setup
python scripts/setup-project.py --auto --name "MyApp" --description "minimalist mobile app"
# This repo does not currently ship this script.
```

### Create a Skill
1. Use `.agents/skills/skill-builder/` for creating or improving skills
2. Follow the SKILL.md and config.json patterns (see any of the seven skills in `.agents/skills/`)
3. Follow Three Pillars framework

### Create a Blueprint
1. Create `blueprints/<name>/` directory (when the project adopts blueprints)
2. Add `blueprint.meta.yaml` and `BLUEPRINT.md`
3. Create overlay templates in `overlays/<stack>/`
4. Validate: `python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('name'))"` (when scripts/ is present)

### Create a Task
1. Create `tasks/<task-name>/` directory (when the project adopts tasks)
2. Add `TASK.md` with documentation and `config.yaml` with configuration
3. Add `universal/` implementation (applies to all stacks)
4. Add `stacks/<stack>/` implementations (stack-specific)
5. Update `tasks/task-index.yaml`
6. Run `python scripts/validate-templates.py --full` when scripts/ is present

### Create a Recipe
1. Create `recipes/<recipe-name>/` directory
2. Add `recipe.yaml` with task bundles and skills
3. Create `RECIPE.md` with human-readable docs
4. Validate recipe configuration
5. Update recipe registry
6. Update documentation

### Create a Subagent
1. Create `subagents/<name>/` directory
2. Add `subagent.yaml` with skills, blueprints, and workflows
3. Create `SUBAGENT.md` and `workflows/` definitions
4. See `AGENTIC-ASSETS-FRAMEWORK.md` for examples

---

## 🏛️ Three Pillars Framework

Every task must satisfy all three pillars:

1. **AUTOMATING** — Content validates against structural rules; prefer scripts over manual steps
   - If a task can be done with a script (especially a reusable one in `scripts/`), use the script instead of doing it manually.
   - Blueprints: YAML valid, metadata complete
   - Tasks: Task structure valid, implementations complete
   - Recipes: Recipe configuration valid, dependencies resolve
   - Subagents: subagent.yaml valid, workflows defined
   - Skills: SKILL.md frontmatter valid, config.json valid

2. **TESTING** — Verification passes
   - Blueprints: Resolution confidence ≥ 1.00
   - Tasks: All stack variants work, examples are runnable
   - Recipes: All bundled tasks resolve correctly
   - Subagents: Workflows execute correctly
   - Skills: Trigger keywords work, examples are runnable

3. **DOCUMENTING** — Related docs updated
   - New skill (in `.agents/skills/`): Update AGENTS.md or a skills index if present
   - (When adopted: blueprint index, task-index.yaml, recipe registry, subagent registry)

---

## 📚 Key Documentation

| File | Purpose |
|------|---------|
| `AGENTIC-ASSETS-FRAMEWORK.md` | **Six template types** — Complete framework definitions |
| `AGENTS.md` | **📜 Rules** — Canonical behavioral constraints (start here) |
| `CLAUDE.md` | **📜 Rules** — Claude Code guide |
| `CURSOR.md` | **📜 Rules** — Cursor AI guide |
| `WINDSURF.md` | **📜 Rules** — Windsurf AI guide |
| `CURRENT-REPOSITORY-STATE.md` | Repository inventory and directory overview |
| `.agents/skills/` | **🧠 Skills** — memory-system-setup, rules-setup, skill-builder, blueprints-setup, tasks-setup, recipes-setup, subagents-setup |
| `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` | Event-sourced memory system |
| `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` | Prompt validation rules |

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

### Subagents (YAML + Markdown)
- **subagent.yaml**: Skills, blueprints, workflows configuration
- **SUBAGENT.md**: Human-readable documentation
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

# When the project includes scripts/ with template automation:
python scripts/validate-templates.py --full
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"
python -c "from scripts.task_resolver import validate_task; print(validate_task('auth-basic'))"
python -m py_compile scripts/*.py
```

---

## 📊 Current Implementation

| Asset Type | In this repo | Notes |
|------------|--------------|-------|
| **Rules** | ✅ Active | AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md |
| **Skills** | ✅ Active (7) | memory-system-setup, rules-setup, skill-builder, blueprints-setup, tasks-setup, recipes-setup, subagents-setup in `.agents/skills/` |
| **Blueprints** | Archived | Framework defined; see `AGENTIC-ASSETS-FRAMEWORK.md` |
| **Tasks** | Archived | Framework defined |
| **Recipes** | Archived | Framework defined |
| **Subagents** | Archived | Framework defined |

---

## 🆘 When Stuck

- **Framework**: Read `AGENTIC-ASSETS-FRAMEWORK.md` for complete definitions
- **Rules**: AGENTS.md is canonical; use `.agents/skills/rules-setup/` for setting up the four rule files
- **Skills**: Use `.agents/skills/rules-setup/`, `.agents/skills/memory-system-setup/`, or `.agents/skills/skill-builder/`; see `.agents/skills/skill-builder/` for creating skills
- **Blueprints, Tasks, Recipes, Subagents**: Defined in the framework; implementations in this repo are archived
- **Validation**: When the project includes `scripts/validate-templates.py`, run it when templates/scripts are in use.

---

## 📝 Archive

Previous repository content preserved in `_complete_archive/` for reference.

---

**Remember**: This is a unified ecosystem. Skills inform templates, templates implement blueprints, blueprints drive project generation. All three systems work together.
