# AGENTS.md

## Project Overview

This repository is a **unified AI development ecosystem** built on **seven template types**:

1. **Rules** — How agents must behave (tool- and audience-specific). **AGENTS.md**, **CLAUDE.md**, **CURSOR.md**, and **WINDSURF.md** are examples of Rules—same project, different entry points.
2. **Blueprints** — What to build (product archetypes)
3. **Tasks** — How to implement a feature (implementation units)
4. **Recipes** — Feature combinations (bundles of Tasks + Skills)
5. **Subagents** — Who does the work (configured sub-agents)
6. **Skills** — How to do it well (capabilities, best practices)
7. **Protocols** — How processes are defined (repeatable procedures in `docs/protocols/` that Rules and agents reference)

**"Templates"** refers collectively to **all seven types**—Rules, Blueprints, Tasks, Recipes, Subagents, Skills, and Protocols. **Rules** (this file, CLAUDE.md, CURSOR.md, WINDSURF.md, .cursor/rules) govern behavior; agents and subagents operate within them and use Skills for capability. **Protocols** are installed and maintained by **protocol skills** (e.g. prompt-validation-setup). See `AGENTIC-ASSETS-FRAMEWORK.md` → "Rules, Skills, and Subagents" and "Protocols."

See `AGENTIC-ASSETS-FRAMEWORK.md` for complete definitions and relationships.

**Current implementation in this repo**: Only **Rules** (this file and the four rule files), **Protocols** (in `docs/protocols/`), and **eleven Skills** are actively maintained: **memory-system-setup**, **rules-setup**, **skill-setup**, **agents-md-setup**, **blueprints-setup**, **tasks-setup**, **recipes-setup**, **subagents-setup**, **prompt-validation-setup**, **protocol-setup**, **flutter-setup** (under `.agents/skills/`). Blueprints, Tasks, Recipes, Subagents, and legacy skill-packs are archived; the framework defines all seven types for reference and future use.

**Tech stack (this repo)**:
- **Languages**: Markdown, JSON, Python, YAML, Jinja2
- **Framework**: Seven template types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols) — see `AGENTIC-ASSETS-FRAMEWORK.md`
- **Validation**: When the project includes template automation, run `scripts/validate-templates.py` (Python 3). This repo does not currently include a top-level `scripts/` with that script; it is part of the framework reference or archived content.
- **Key tools**: Python for scripts; JSON for skill configs; YAML for blueprints, tasks, recipes, subagents

---

## Build/Test/Lint Commands

### Skills (Markdown + JSON)
```bash
# Validate JSON syntax
find . -name "*.json" -exec python -m json.tool {} \; > /dev/null

# Check for broken cross-references
grep -r "\[.*\](.*)" --include="*.md" . | grep -v "http" | head -20

# Count skills (when using .agents/skills/ directory)
find .agents/skills -name "SKILL.md" 2>/dev/null | wc -l
```

### Tasks, Blueprints & Other Templates (Python)
```bash
# When the project includes a scripts/ directory with template automation:
# Full template system validation (CRITICAL - run before commits)
python scripts/validate-templates.py --full

# Blueprint validation
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"

# Task validation
python -c "from scripts.task_resolver import validate_task; print(validate_task('auth-basic'))"

# Autonomous project generation
python scripts/setup-project.py --auto --name "MyProject" --description "project description"
# This repo does not currently ship these scripts; they are framework/archived reference.

# Python syntax check (when Python scripts exist)
python -m py_compile scripts/*.py
```

**Prefer scripts over manual steps**: If a check or transformation can be done with a script in `scripts/` (e.g. `validate-templates.py`), use the script instead of running steps manually. (This repo does not currently include a top-level `scripts/` with template automation.)

---

## Testing

- **Template system**: When the project includes `scripts/validate-templates.py`, run `python scripts/validate-templates.py --full` before considering a task complete when you changed tasks, blueprints, recipes, or scripts.
- **Skills**: Validate JSON (`python -m json.tool` on configs); run or inspect examples when adding or changing a skill.
- **Per change type**:
  - New or changed task → run validation; ensure all referenced stacks/tiers resolve.
  - New or changed blueprint → run blueprint resolution; confidence ≥ 1.00.
  - New or changed skill → trigger keywords and examples are accurate.
- Do not remove or weaken existing tests or validation; add regression coverage when fixing bugs.

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
<project root>/
├── AGENTS.md                     # 📜 RULES — Canonical (this file)
├── CLAUDE.md                     # 📜 RULES — Claude entry
├── CURSOR.md                     # 📜 RULES — Cursor entry
├── WINDSURF.md                   # 📜 RULES — Windsurf entry
├── AGENTIC-ASSETS-FRAMEWORK.md   # Six template types definitions
├── CHANGELOG.md                  # Event log (append-only)
├── README.md                     # Repository overview
├── CURRENT-REPOSITORY-STATE.md   # Repository inventory (when present)
│
├── .agents/                      # Agent assets (skills)
│   └── skills/                  # 🧠 SKILLS (nine skills)
│       ├── memory-system-setup/
│       ├── rules-setup/
│       ├── skill-setup/
│       ├── blueprints-setup/
│       ├── tasks-setup/
│       ├── recipes-setup/
│       ├── subagents-setup/
│       ├── prompt-validation-setup/
│       ├── protocol-setup/
│       └── agents-md-setup/
│
├── .memory/                      # Memory system data (when in use)
├── docs/                         # Documentation & protocols (incl. memory-system, protocols)
│   └── protocols/                # 📋 PROTOCOLS — Process definitions (e.g. PROMPT-VALIDATION-PROTOCOL.md)
├── plans/                        # Planning artifacts (when present)
├── _documentation-blueprint/     # Documentation blueprint (when present)
│
├── blueprints/, tasks/, recipes/, subagents/, scripts/  # When present or archived; see framework
└── _complete_archive/            # Preserved history (incl. legacy skill-packs)
```

---

## Boundaries

- ✅ **Always**: Run `python scripts/validate-templates.py --full` before commit when you changed tasks, blueprints, recipes, or scripts **and the project includes that script**; prefer scripts in `scripts/` over manual steps when available; satisfy all Three Pillars; append to CHANGELOG.md when completing a task; update AGENTS.md (and other rule files if needed) when conventions or structure change.
- ⚠️ **Ask first**: New template type or new top-level script; changes to validation logic; archiving or moving content into `_complete_archive/`; deleting or renaming rule files.
- 🚫 **Never**: Modify files in `_complete_archive/`; delete raw task outputs in `task-outputs/`; commit without running validation when templates or scripts changed; remove or weaken tests or validation to make a suite pass; hardcode secrets or commit credentials.

---

## Safety and Permissions

**Allowed without asking:**
- Read/list files; validate JSON (`python -m json.tool`); run file-scoped lint/format/type-check on changed files
- Append to CHANGELOG.md; update AGENTS.md (and other rule files) when conventions or structure change
- Create or edit files in `.agents/skills/`, `docs/`, and project structure per Boundaries

**Ask first:**
- New template type or new top-level script; changes to validation logic
- Archiving or moving content into `_complete_archive/`; deleting or renaming rule files
- Package installs; git push or force operations; full build or E2E suites when not explicitly requested

---

## Git Workflow

- **Before commit**: When the project includes `scripts/validate-templates.py`, run `python scripts/validate-templates.py --full` if you changed anything under `tasks/`, `blueprints/`, `recipes/`, `subagents/`, or `scripts/`. Validate JSON for any changed `config.json` (e.g. `python -m json.tool < file.json`).
- **CHANGELOG**: Append-only. Add a new dated section for each logical change set; include what changed and why (see existing entries).
- **Rule files**: When adding or renaming a rule file (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md), update `AGENTIC-ASSETS-FRAMEWORK.md` and the Key References in all four rule files.
- **Branches**: Prefer short-lived branches; merge after validation passes and docs are updated.

---

## Memory System Protocol

This project uses an event-sourced memory system. See `.memory/` for live state.

- **Layer 0** (`AGENTS.md`): Immutable during execution. Read at boot only.
- **Layer 1** (`CHANGELOG.md`): Append-only source of truth.
- **Layer 2** (`.memory/graph.md`): Materialized view. Update only from L1.
- **Layer 3** (`.memory/context.md`): Derived projection. Regenerate when stale.

### Agent lifecycle
BOOT:   Read AGENTS.md → Read .memory/context.md → Check staleness (Event horizon vs last evt in CHANGELOG) → If stale/missing, regenerate context (and graph) → Optionally run relevant_events.py for recent index
EXECUTE: Work within constraints → Append events to CHANGELOG.md (Event Log section)
SHUTDOWN: (1) Append event(s) to CHANGELOG.md (## Event Log) → (2) Materialize .memory/graph.md (event horizon = last evt-NNN) → (3) Regenerate .memory/context.md from L1+L2 → (4) Commit all changes. Never edit graph or context backward to match an older event.

### Core rules
1. Append-only — if it is not in the event log, it did not happen
2. One-way flow — Event Log → Graph → Narrative; never backward
3. Stateless agents — boot from files, execute, write, terminate
4. Rebuild, don't repair — regenerate derived layers from upstream when inconsistent

---

Follow `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md`:

**Before every task (load memory):**
1. Read `AGENTS.md` (this file) — behavioral constraints
2. Read `.memory/context.md` — current trajectory (if missing, create from CHANGELOG + graph per protocol)
3. **Check staleness:** Compare the "Event horizon" line in `.memory/context.md` with the last event ID in `CHANGELOG.md` (under `## Event Log`). If they differ or context is missing, regenerate `.memory/context.md` (and `.memory/graph.md` if in use) from the event log before proceeding
4. Optionally: when `docs/memory-system/scripts/relevant_events.py` exists, run it for a compact recent-events index to inject at session start

**After every task:**
1. Append event to `CHANGELOG.md` (under `## Event Log`, next evt-NNN).
2. **Materialize** `.memory/graph.md`: update nodes/edges/meta so event horizon equals the new last event ID; never edit graph backward.
3. **Regenerate** `.memory/context.md` from CHANGELOG + graph (event horizon = last evt).
4. Commit all changes (CHANGELOG, graph, context, and any other modified files) in one atomic commit.
5. Update this AGENTS.md if conventions changed.

---

## Prompt Validation — Before Every Task

**All agents MUST validate user prompts before execution.** Use `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` for the full process. As a minimum, run these **4 checks** before starting:

1. **Purpose in first line** — Can you state what the prompt wants in one sentence?
2. **All variables defined** — Are all `{{`, `[`, `{` placeholders defined or defaulted?
3. **No dangerous patterns** — No `eval`, `exec`, `rm -rf`, `DROP TABLE`, `sudo`, secrets, or other blocked patterns (see protocol).
4. **Output format specified** — Does the prompt say what the output should look like?

If **any** check fails, ask for clarification before proceeding. For full validation levels, security patterns, and scoring, see `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`.

---

## Three Pillars — Task Completion Checklist

A task is **not complete** until all three pillars are satisfied:

1. ✅ **AUTOMATING** — Content validates against structural rules; prefer scripts over manual steps
   - If a task can be done with a script (especially a reusable one in `scripts/`), use the script instead of doing it manually.
   - Blueprints: YAML valid, metadata complete
   - Tasks: Task structure valid, implementations complete
   - Recipes: Recipe configuration valid, dependencies resolve
   - Subagents: subagent.yaml valid, workflows defined
   - Skills: SKILL.md frontmatter valid, config.json valid
   - Protocols: Protocol document in `docs/protocols/` valid; Rules reference correct path

2. ✅ **TESTING** — Verification passes
   - Blueprints: Resolution confidence ≥ 1.00
   - Tasks: All stack variants work, examples are runnable
   - Recipes: All bundled tasks resolve correctly
   - Subagents: Workflows execute correctly
   - Skills: Trigger keywords work, examples are runnable
   - Protocols: Protocol file present where referenced; protocol skill used for install when applicable

3. ✅ **DOCUMENTING** — Related docs updated

   **By change type:**

   | Change type | Update these |
   |-------------|--------------|
   | New feature or module | README.md, docs/SYSTEM-MAP.md or CURRENT-REPOSITORY-STATE.md, CHANGELOG.md |
   | New rule file | AGENTIC-ASSETS-FRAMEWORK.md → Key Files; Key References in AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md |
   | New protocol | `docs/protocols/` protocol file; AGENTS.md or Rules reference if needed; protocol skill or docs/INDEX.md |
   | New skill (in `.agents/skills/`) | AGENTS.md (Key References / Skills) or skills index; README or cross-links as needed; docs/INDEX.md |
   | New blueprint | Blueprint index, integration guides (when adopted) |
   | New task | `tasks/task-index.yaml`, relevant docs (when adopted) |
   | New recipe | Recipe registry, cross-reference tasks (when adopted) |
   | New subagent | Subagent registry, examples (when adopted) |
   | Repository structure change | CURRENT-REPOSITORY-STATE.md, docs/INDEX.md, docs/SYSTEM-MAP.md if applicable, CHANGELOG.md |
   | Conventions or structure change | AGENTS.md and other rule files if affected |

   **How to update:** After completing the primary task, update the relevant section(s) in the same commit; keep updates minimal and factual. If you add or change a rule file, update all four rule files' Key References.

---

## Workflows

The following workflows describe how to add each template type when a project adopts it. **In this repo**, only **Rules**, **Protocols** (in `docs/protocols/`), and the **eleven skills** in `.agents/skills/` (memory-system-setup, rules-setup, skill-setup, agents-md-setup, blueprints-setup, tasks-setup, recipes-setup, subagents-setup, prompt-validation-setup, protocol-setup, flutter-setup) are active; Blueprints, Tasks, Recipes, and Subagents are defined in the framework but their implementations here are archived.

### Adding a Rule File
1. Create the rule file at project root (e.g. `MYTOOL.md`). **Use ALL CAPS for the filename** (e.g. AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md).
2. Add it to `AGENTIC-ASSETS-FRAMEWORK.md` → Rules section "Key Files (examples of Rules)".
3. Add a row to the Key Files / Key References table in AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md (and the new file's own references).
4. Keep content aligned with AGENTS.md (canonical); tool-specific files can be thin and point to it.

### Adding a Protocol
1. Create or adopt a protocol document (e.g. `PROMPT-VALIDATION-PROTOCOL.md`). Use a **protocol skill** (e.g. `.agents/skills/prompt-validation-setup/`) to install it into a project, or use **protocol-setup** to create/audit the Protocols template type.
2. Ensure `docs/protocols/` exists; place the protocol file there (or at project root if minimal).
3. Reference the protocol from AGENTS.md (e.g. "Prompt Validation — Before Every Task" section pointing to `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`).
4. Update framework and rule files if adding a new protocol type or protocol skill.

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

### Adding a Subagent
1. Create `subagents/<name>/` directory
2. Create `subagent.yaml` with skills, blueprints, and workflows
3. Create `SUBAGENT.md` with human-readable docs
4. Create `workflows/` with defined workflow automations
5. Validate subagent configuration
6. Update documentation

### Creating a Skill Pack
(When the project adopts skill packs: create PACK.md, QUICK_REFERENCE.md, per-skill SKILL.md/config.json/README.md/_examples, run verification tasks, create reference-files/INDEX.md. See `.agents/skills/skill-setup/` for creating individual skills.)

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

## Subagents for Execution

Use the **main session** for strategy and decisions; **spawn subagents** for implementation, research, coding, and analysis.

**Spawn when:**
- Research (literature, docs, benchmarks)
- Code review
- Long-running or parallelizable tasks
- Independent analysis (e.g. separate codebase scan, focused refactor)

**Don't spawn for:**
- Simple lookups (file path, one-off grep)
- Highly context-dependent or creative collaboration (e.g. designing an API together with the user)
- When the human needs to iterate live with you (tight feedback loop)

**When spawning:** Give clear inputs and deliverables; synthesize subagent results for the human (summarize, highlight decisions, and any follow-up needed).

---

## Right Tool for the Job

Use this order instead of brute force:

1. **Skills** — Check SKILL.md (and skill docs) before coding. Invoke the right skill when the task matches its triggers.
2. **MCPs** — External services (verify before installing new ones). Use existing MCP tools when they fit the task.
3. **Subagents** — For parallel or specialized work (see [Subagents for execution](#subagents-for-execution)).
4. **External APIs** — `web_search`, `web_fetch`, browser when appropriate for live or documented data.
5. **Standard tools** — File ops, exec, etc. Prefer scripts in `scripts/` over ad-hoc commands.
6. **Brute force** — Only as last resort. No manual parsing or loops when a tool exists (e.g. use JSON parsing, not regex hacks; use a script, not hand-written one-off code).

---

## Key References

### Template Types Framework
- `AGENTIC-ASSETS-FRAMEWORK.md` — Complete definitions of the seven template types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols)

### Rule Files (same project, different tools)
- `AGENTS.md` — This file (canonical)
- `CLAUDE.md` — Claude entry
- `CURSOR.md` — Cursor entry
- `WINDSURF.md` — Windsurf entry

### Blueprints
- `blueprints/` directory — Product archetypes (archived in this repo; see `AGENTIC-ASSETS-FRAMEWORK.md` for structure)

### Tasks
- `tasks/` directory — Implementation units (archived in this repo; when adopted: `task-index.yaml` in `tasks/`)

### Recipes
- `recipes/` directory — Feature combinations (archived; framework defines the type)

### Subagents
- `subagents/` directory — Configured sub-agents (archived; framework defines the type)

### Protocols
- `docs/protocols/` directory — Process definitions (e.g. PROMPT-VALIDATION-PROTOCOL.md, MEMORY-SYSTEM-PROTOCOL.md). Installed and maintained by **protocol skills** (e.g. `.agents/skills/prompt-validation-setup/`).

### Skills
- `.agents/skills/` directory — Current skills: **memory-system-setup**, **rules-setup**, **skill-setup**, **agents-md-setup**, **blueprints-setup**, **tasks-setup**, **recipes-setup**, **subagents-setup**, **prompt-validation-setup**, **protocol-setup**, **flutter-setup**
- Use `.agents/skills/skill-setup/` when creating or improving skills
- Use `.agents/skills/rules-setup/` when setting up the four rule files (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md)
- Use `.agents/skills/agents-md-setup/` when creating or editing AGENTS.md as the primary rule (canonical source)
- Use `.agents/skills/memory-system-setup/` when setting up the memory system
- Use `.agents/skills/prompt-validation-setup/` when installing or maintaining the Prompt Validation Protocol
- Use `.agents/skills/protocol-setup/` when creating or auditing the Protocols template type
- Use `.agents/skills/blueprints-setup/`, `.agents/skills/tasks-setup/`, `.agents/skills/recipes-setup/`, `.agents/skills/subagents-setup/` when creating or auditing those template types
- Use `.agents/skills/flutter-setup/` when creating, configuring, or maintaining Flutter/Dart projects

### System & Tools
- `scripts/setup-project.py` — Project generation (when project includes it)
- `scripts/validate-templates.py` — Validation (when project includes it)
- `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` — Validate before execution (install via prompt-validation-setup skill)
- `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` — Event-sourced memory

---

## When Stuck

- **Rules**: AGENTS.md (this file) is canonical; CLAUDE.md, CURSOR.md, WINDSURF.md are tool entries. See `AGENTIC-ASSETS-FRAMEWORK.md` → "Rules, Skills, and Subagents."
- **Blueprints, Tasks, Recipes, Subagents**: Defined in `AGENTIC-ASSETS-FRAMEWORK.md`; implementations in this repo are archived.
- **Skills**: Use `.agents/skills/rules-setup/`, `.agents/skills/agents-md-setup/`, `.agents/skills/memory-system-setup/`, `.agents/skills/prompt-validation-setup/`, `.agents/skills/protocol-setup/`, or `.agents/skills/skill-setup/` as reference; use `.agents/skills/blueprints-setup/`, `.agents/skills/tasks-setup/`, `.agents/skills/recipes-setup/`, `.agents/skills/subagents-setup/`, `.agents/skills/flutter-setup/` for those template types; see `.agents/skills/skill-setup/` for creating new skills.
- **Framework**: Read `AGENTIC-ASSETS-FRAMEWORK.md` for complete definitions
- **Validation**: When the project includes `scripts/validate-templates.py`, run `python scripts/validate-templates.py --full` when templates or scripts exist and are in use.
