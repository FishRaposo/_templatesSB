---
name: recipes-setup
description: Use this skill when creating, editing, or auditing Recipes — the template type that bundles Tasks and Skills for common scenarios (feature combinations). This includes recipe.yaml, RECIPE.md, task and skill lists, blueprint compatibility, and configuration overrides. Fits the six-template-types framework (Rules, Blueprints, Tasks, Recipes, Subagents, Skills).
---

# Recipes Setup Skill

This skill creates and maintains **Recipes**: pre-configured bundles of Tasks and Skills for common development scenarios (e.g. e-commerce, SaaS starter). When invoked, it can add a new recipe, update task/skill lists or blueprint compatibility, or audit recipe configuration against the framework.

## Core Approach

Recipes answer **"What features do I need for [scenario]?"** They live under `recipes/<recipe-name>/` with `recipe.yaml` (machine-readable) and `RECIPE.md` (human-readable). Each recipe declares tasks, skills, compatible blueprints, and optional per-task configuration. Dependencies should resolve when the project uses a validation script (e.g. all referenced tasks and skills exist).

## Step-by-Step Instructions

### 1. Create the recipe directory

```
recipes/<recipe-name>/
├── recipe.yaml   # Recipe configuration
├── RECIPE.md     # Human-readable documentation
└── examples/     # Optional: example implementations
```

### 2. Add recipe.yaml

Include at minimum:

- `recipe.id`, `name`, `description`
- `tasks`: list of task IDs (required/recommended order if the schema supports it)
- `skills`: list of skill identifiers
- `blueprints.compatible`: list of blueprint IDs this recipe works with
- `configuration`: optional overrides per task (tier, features, etc.)

Reference the full schema and examples in the project's framework doc (`AGENTIC-ASSETS-FRAMEWORK.md` at project root, when present) → Recipes.

### 3. Write RECIPE.md

Document the scenario this recipe targets, which tasks and skills it includes, and how it fits with compatible blueprints. Keep it human-readable and link to the framework.

### 4. Validate dependencies (when the project has validation)

When the project includes validation for recipes, ensure every task ID exists in `tasks/task-index.yaml` and every skill/task reference resolves. Fix broken references before considering the recipe complete.

## Best Practices

- Keep recipes focused on one scenario (e.g. e-commerce, SaaS starter); split broad scenarios into multiple recipes.
- List tasks in dependency order where possible; document optional vs required tasks in RECIPE.md.
- Specify compatible blueprints so users know which blueprints can use this recipe.

## Validation Checklist

- [ ] `recipes/<name>/` exists with `recipe.yaml` and `RECIPE.md`
- [ ] `recipe.yaml` has valid YAML with `id`, `name`, `tasks`, `skills`, and `blueprints.compatible` (or equivalent)
- [ ] Task IDs in `tasks` exist in `tasks/task-index.yaml` when Tasks are adopted
- [ ] RECIPE.md describes the scenario, included tasks/skills, and usage
- [ ] When validation script exists: recipe dependencies resolve

## Troubleshooting

**Task or skill not found** — Ensure task IDs match the project's `tasks/task-index.yaml` and skill names match the project's skills system. Recipe task/skill lists may reference project-specific or archived content; resolve to the current project layout.

**Validation script missing** — The project may not include a top-level `scripts/`; recipe structure still follows the framework.

## Related Skills

- **blueprints-setup** — When defining which blueprints are compatible with this recipe
- **tasks-setup** — When adding or changing tasks referenced by the recipe
- **rules-setup** — When updating AGENTS.md or rule files that reference recipes

## Supporting Files

- **Framework and Recipes section:** `AGENTIC-ASSETS-FRAMEWORK.md` at project root (when present)
- **Archive:** When the project has an archive, an archive reference doc may indicate Recipes are framework-defined only; use the framework doc and this skill when creating recipes
- **Example recipes:** `recipes/` at project root when the project adopts the template system
