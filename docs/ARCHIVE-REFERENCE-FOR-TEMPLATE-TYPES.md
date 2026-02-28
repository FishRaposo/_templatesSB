# Archive Reference for Template Types

**Purpose**: Use the repository archive as the reference when building or auditing any of the six template types. All paths below are under `_complete_archive/`. **Do not modify files in the archive.**

**Archive locations**:
- Main snapshot: `_complete_archive/_archive_2026-02-26_18-50-32/`
- Implementations snapshot: `_complete_archive/_archive_2026-02-26_20-26-42_implementations/`
- Legacy templates: `_complete_archive/_templates-main/` (when present)
- Archive index: `_complete_archive/ARCHIVE-DOCUMENTATION-INDEX.md`

---

## 1. Rules

**What to use**: AGENTS.md, tool-specific rule files (CLAUDE.md, CURSOR.md, WINDSURF.md), Three Pillars, prompt validation.

| Need | Archive path | Notes |
|------|---------------|--------|
| Full AGENTS.md (historical) | `_archive_2026-02-26_18-50-32/AGENTS.md` | Multi-agent, Three Pillars, validation |
| Documentation blueprint (18 required docs) | `_archive_2026-02-26_18-50-32/DOCUMENTATION-BLUEPRINT.tpl.md` or `_documentation-blueprint/` | Three Pillars, doc parity |
| Agent templates (five-agent, orchestration) | `_templates-main/docs/universal/AGENTS.tpl.md`, `AGENT-ORCHESTRATION.tpl.md` | Role boundaries, handoff |
| Tool-specific guides | `_archive_2026-02-26_18-50-32/CLAUDE.md`, `CURSOR.md`, `WINDSURF.md` | Production rule content |
| ADD-NEW extension guides | `_archive_2026-02-26_18-50-32/ADD-NEW-BLUEPRINT-TEMPLATE.md` (structure patterns) | Cross-cutting structure |

Use **rules-setup** skill for creating/auditing Rules; use archive for historical patterns and full examples.

---

## 2. Blueprints

**What to use**: blueprint.meta.yaml schema, BLUEPRINT.md structure, overlays per stack.

| Need | Archive path | Notes |
|------|---------------|--------|
| Blueprint template (directory + schema) | `_archive_2026-02-26_18-50-32/ADD-NEW-BLUEPRINT-TEMPLATE.md` | Required structure, YAML template |
| MINS blueprint (full example) | `_archive_2026-02-26_20-26-42_implementations/blueprints/mins/` | blueprint.meta.yaml, BLUEPRINT.md, overlays/flutter, overlays/python |
| blueprint.meta.yaml (real) | `_archive_2026-02-26_20-26-42_implementations/blueprints/mins/blueprint.meta.yaml` | id, version, stacks, tier_defaults, tasks, constraints, overlays, hooks, llm |
| BLUEPRINT.md (real) | `_archive_2026-02-26_20-26-42_implementations/blueprints/mins/BLUEPRINT.md` | Product archetype, architecture, task integration, UX |
| saas-api, web-dashboard | `_archive_2026-02-26_20-26-42_implementations/blueprints/saas-api/`, `web-dashboard/` | Additional blueprint examples |

Use **blueprints-setup** skill; reference archive for schema and MINS/saas-api patterns.

---

## 3. Tasks

**What to use**: task-index.yaml format, TASK.md, config, universal/ + stacks/<stack>/ layout.

| Need | Archive path | Notes |
|------|---------------|--------|
| Task index (master registry) | `_archive_2026-02-26_18-50-32/tasks/task-index.yaml` | tasks.<id>.description, categories, default_stacks, files[], stack_overrides |
| New task template | `_archive_2026-02-26_18-50-32/ADD-NEW-TASK-TEMPLATE.md` | Directory structure, meta schema |
| auth-basic (full example) | `_archive_2026-02-26_18-50-32/tasks/auth-basic/` | universal/docs, universal/code, universal/tests; stacks/python, node, nextjs |
| web-scraping (task-index entry) | `_archive_2026-02-26_18-50-32/tasks/task-index.yaml` (web-scraping) | files[], universal_template, stack_overrides, merge_behavior |
| Invariants (optional) | `_archive_2026-02-26_18-50-32/tasks/_invariants/*.yaml` | Per-task invariant rules |

Use **tasks-setup** skill; reference archive for task-index schema and auth-basic/web-scraping layout.

---

## 4. Recipes

**What to use**: recipe.yaml schema, RECIPE.md, task/skill bundles, blueprint compatibility (framework-defined; archive may have fewer examples).

| Need | Archive path | Notes |
|------|---------------|--------|
| Framework definition | `AGENTIC-ASSETS-FRAMEWORK.md` (repo root) | Recipe section: recipe.yaml, tasks, skills, blueprints.compatible |
| E-commerce / SaaS examples | Described in framework only | recipe.yaml structure in framework doc |

The archive does not contain a `recipes/` directory with recipe.yaml files; use the framework doc and **recipes-setup** skill. When restoring or adding recipes, follow the schema in AGENTIC-ASSETS-FRAMEWORK.md.

---

## 5. Subagents

**What to use**: subagent.yaml schema, SUBAGENT.md, workflows/ (framework-defined; archive may have workflow schemas only).

| Need | Archive path | Notes |
|------|---------------|--------|
| Framework definition | `AGENTIC-ASSETS-FRAMEWORK.md` (repo root) | Subagents section: subagent.yaml, skills, workflows |
| Workflow schema | `_archive_2026-02-26_18-50-32/workflows/workflow-schema.yaml`, `WORKFLOW-SCHEMA.md` | Workflow definition format |
| Workflow stack templates | `_archive_2026-02-26_18-50-32/workflows/stacks/` | e.g. python, node, go workflow-orchestrator.tpl.* |

The archive does not contain a `subagents/` directory with subagent.yaml; use the framework doc and **subagents-setup** skill. Workflow definitions in the archive can inform subagent workflow structure.

---

## 6. Skills

**What to use**: SKILL.md format, config.json, PACK.md, QUICK_REFERENCE.md, _examples, _reference-files.

| Need | Archive path | Notes |
|------|---------------|--------|
| Skill pack structure | `_archive_2026-02-26_18-50-32/skill-packs/1-programming-core/` | PACK.md, QUICK_REFERENCE.md, skills/<name>/SKILL.md, config.json, _examples, _reference-files |
| PACK.md example | `_archive_2026-02-26_18-50-32/skill-packs/1-programming-core/PACK.md` | Overview, skills list, relationships, structure |
| Single skill (e.g. clean-code) | `_archive_2026-02-26_18-50-32/skill-packs/2-code-quality/skills/clean-code/` | SKILL.md, config.json, README.md |
| How to create packs | `_archive_2026-02-26_18-50-32/skill-packs/HOW_TO_CREATE_SKILL_PACKS.md` | Pack creation guide (legacy format) |
| Universal skill standards | `_complete_archive/_supporting-files/UNIVERSAL_SKILL_STANDARDS.md` (if present) | Progressive disclosure, config schema |

Use **skill-setup** skill for creating skills; reference archive for pack layout and 1-programming-core / 2-code-quality as gold standards.

---

## 7. Memory System (not a template type)

**What to use**: CHANGELOG event format, .memory/ layout, protocol.

| Need | Archive path | Notes |
|------|---------------|--------|
| Memory protocol | `_complete_archive/PROJECT-MEMORY-SYSTEM-REFERENCE.md` | Full memory system reference |
| Protocol (repo) | `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` | Current protocol in repo |

Use **memory-system-setup** skill; archive holds the full reference doc.

---

## Quick lookup

| Template type | Primary skill | Key archive paths |
|---------------|---------------|--------------------|
| Rules | rules-setup | AGENTS.md, DOCUMENTATION-BLUEPRINT, ADD-NEW-* |
| Blueprints | blueprints-setup | ADD-NEW-BLUEPRINT-TEMPLATE.md, blueprints/mins/ |
| Tasks | tasks-setup | task-index.yaml, ADD-NEW-TASK-TEMPLATE.md, tasks/auth-basic/ |
| Recipes | recipes-setup | AGENTIC-ASSETS-FRAMEWORK.md (Recipes section) |
| Subagents | subagents-setup | AGENTIC-ASSETS-FRAMEWORK.md (Subagents), workflows/ |
| Skills | skill-setup | skill-packs/1-programming-core/, 2-code-quality/ (in archive). In this repo: `.agents/skills/` |
| Protocols | protocol-setup, prompt-validation-setup | docs/protocols/ (current). In this repo: `docs/protocols/` |
| Memory | memory-system-setup | PROJECT-MEMORY-SYSTEM-REFERENCE.md |

---

*Do not modify files under `_complete_archive/`. Use for read-only reference when building or auditing template types.*
