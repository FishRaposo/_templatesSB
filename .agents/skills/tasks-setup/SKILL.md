---
name: tasks-setup
description: Use this skill when creating, editing, or auditing Tasks — the template type that defines how to implement a feature (implementation units). This includes TASK.md, config.yaml, universal/ and stacks/<stack>/ implementations, task-index.yaml registration, and tier/stack variants. Fits the seven-template-types framework (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols).
---

# Tasks Setup Skill

This skill creates and maintains **Tasks**: the template type that defines **how to implement a feature** (implementation units). Tasks live under `tasks/<task-name>/` with universal and stack-specific implementations and a registry in `tasks/task-index.yaml`.

## Your Role

Help users **create** and **modify** Tasks through:

1. **Creating New Tasks** — Add a new task directory with `TASK.md`, `config.yaml`, `universal/` and `stacks/<stack>/` implementations, and register in `task-index.yaml`
2. **Editing Existing Tasks** — Update `TASK.md` or `config.yaml`, add or change stack implementations, or adjust tier/stack variants
3. **Auditing Tasks** — Check structure and task-index registration; ensure all stack variants resolve when a validation script exists

When invoked, produce or update task files so they conform to the framework. Run full validation when the project includes `scripts/validate-templates.py`.

## Core Approach

Tasks answer **"How do I implement [feature]?"** They live under `tasks/<task-name>/` with a master registry in `tasks/task-index.yaml`. Each task has universal (stack-agnostic) and stack-specific implementations (e.g. `stacks/python/`, `stacks/node/`). Templates use placeholders (e.g. Jinja2) for customization. Validation ensures structure and that all stack variants resolve when the project uses a validation script.

## Step-by-Step Instructions

### 1. Create the task directory

```
tasks/<task-name>/
├── TASK.md           # Task documentation and usage guide
├── config.yaml       # Task configuration and dependencies
├── universal/         # Applies to all stacks
│   └── *.tpl.*       # Universal templates
└── stacks/
    ├── python/
    ├── node/
    └── ...           # Stack-specific implementations
```

### 2. Add TASK.md

Document the task’s purpose, when to use it, inputs/outputs, and how to run or integrate it. Reference the framework’s task structure.

### 3. Add config.yaml

Define task metadata, dependencies on other tasks (if any), and any tier or stack constraints. Match the format expected by `task-index.yaml` and any validation script (when present).

### 4. Add universal implementation

Under `universal/`, add templates or logic that apply to every stack. Use `.tpl.<ext>` for generator-friendly templates.

### 5. Add stack-specific implementations

Under `stacks/<stack>/`, add implementations per stack (e.g. Python, Node, Flutter). Include dependencies (e.g. requirements.txt, package.json) and follow project conventions for tiers (MVP/Core/Enterprise).

### 6. Register in task-index.yaml

Add an entry for the task in `tasks/task-index.yaml` with id, name, description, and any categories or tags used by the project. For registry format (e.g. description, categories, default_stacks, files with universal_template and stack_overrides), use the project's existing `tasks/task-index.yaml` or, when the project has an archive, the project's archive reference doc for task-index location.

### 7. Validate (when the project has a validation script)

When the project includes `scripts/validate-templates.py`, run full validation so all stack variants are checked.

## Editing Tasks

When modifying an existing task:

- **TASK.md** — Update purpose, usage, inputs/outputs, or run instructions
- **config.yaml** — Change metadata, dependencies, or tier/stack constraints
- **universal/** — Add or edit stack-agnostic templates
- **stacks/<stack>/** — Add a new stack, or change implementations for an existing stack
- **task-index.yaml** — Update the task’s entry (id, name, description, categories) so it stays in sync

Re-run validation after edits when the project has a validation script.

## Best Practices

- Keep tasks self-contained and composable; reference other tasks via config rather than duplicating logic.
- Use consistent naming: kebab-case for task names and stack directories.
- Document tier expectations (MVP ~50–200 lines, Core ~200–500, Enterprise 500+).

## Validation Checklist

- [ ] `tasks/<task-name>/` exists with `TASK.md` and `config.yaml`
- [ ] `universal/` and/or `stacks/<stack>/` contain the expected templates
- [ ] `tasks/task-index.yaml` includes an entry for this task
- [ ] When validation script exists: task validation passes for all stacks
- [ ] Dependencies and file paths are consistent across stacks

## Troubleshooting

**Validation script missing** — The project may not include a top-level `scripts/`; task structure still follows the framework. Add validation when adopting the full template system.

**Stack variant missing** — Add a directory under `stacks/<stack>/` with at least one implementation; document in TASK.md which stacks are supported.

## Related Skills

- **blueprints-setup** — When blueprints reference this task in required/recommended lists
- **recipes-setup** — When recipes bundle this task with others
- **rules-setup** — When updating AGENTS.md or rule files that reference tasks

## Supporting Files

- **Framework and Tasks section:** `AGENTIC-ASSETS-FRAMEWORK.md` at project root (when present)
- **Archive:** When the project has an archive, an archive reference doc may list task-index and ADD-NEW-TASK-TEMPLATE paths; do not modify archive files
- **Task registry:** `tasks/task-index.yaml` at project root (when present)
