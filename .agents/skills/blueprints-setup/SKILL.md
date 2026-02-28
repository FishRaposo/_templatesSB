---
name: blueprints-setup
description: Use this skill when creating, editing, or auditing Blueprints — the template type that defines what to build (product archetypes). This includes blueprint.meta.yaml (stacks, tiers, tasks, overlays), BLUEPRINT.md, overlays per stack, and validating resolution. Fits the seven-template-types framework (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols).
---

# Blueprints Setup Skill

This skill creates and maintains **Blueprints**: the template type that defines **what to build** (product archetypes). Blueprints are YAML + Markdown artifacts under `blueprints/<name>/` with stacks, tiers, tasks, and overlay templates.

## Your Role

Help users **create** and **modify** Blueprints through:

1. **Creating New Blueprints** — Add a new blueprint directory with `blueprint.meta.yaml`, `BLUEPRINT.md`, and overlays per stack
2. **Editing Existing Blueprints** — Update `blueprint.meta.yaml` (stacks, tier_defaults, tasks, overlays), revise `BLUEPRINT.md`, or add/edit overlay templates
3. **Auditing Blueprints** — Check structure and resolution (e.g. confidence ≥ 1.00 when a validation script exists); fix missing or invalid references

When invoked, produce or update blueprint files so they conform to the framework. Validate resolution when the project includes `scripts/validate-templates.py` or equivalent.

## Core Approach

Blueprints answer **"What should I build?"** They are YAML + Markdown artifacts under `blueprints/<name>/`. Each blueprint declares required/recommended stacks, tier defaults per stack, required/recommended/optional tasks, and overlay templates for stack-specific code. Validation ensures resolution confidence (e.g. ≥ 1.00 when using a validation script).

## Step-by-Step Instructions

### 1. Create the blueprint directory

```
blueprints/<blueprint-id>/
├── blueprint.meta.yaml   # Machine-readable configuration
├── BLUEPRINT.md          # Human-readable documentation
└── overlays/
    └── <stack>/          # e.g. flutter/, python/, node/
        └── *.tpl.<ext>  # Stack-specific template extensions
```

### 2. Add blueprint.meta.yaml

Include at minimum:

- `blueprint.id`, `version`, `name`, `category`
- `stacks`: `required`, `recommended`, `supported` (e.g. `["flutter"]`, `["python"]`, `["node","go"]`)
- `tier_defaults`: per-stack tier (e.g. `flutter: "mvp"`, `python: "core"`)
- `tasks`: `required`, `recommended`, `optional` task IDs
- `overlays`: per-stack list of overlay template paths

Reference the full schema and examples in the project's framework doc (`AGENTIC-ASSETS-FRAMEWORK.md` at project root, when present) → Blueprints. When the project has an archive, a full example (schema + overlays) may be under `blueprints/mins/` or an archive folder; use the project's archive reference doc if present.

### 3. Write BLUEPRINT.md

Document purpose, when to use this blueprint, stack/tier expectations, and how it composes with tasks and overlays. Keep it human-readable and link to the framework.

### 4. Add overlay templates (per stack)

Under `overlays/<stack>/`, add `.tpl.*` files that extend or generate stack-specific code. Reference existing blueprints (e.g. `blueprints/mins/`) for patterns when the repo contains them.

### 5. Validate (when the project has a validation script)

When the project includes `scripts/validate-templates.py`, run blueprint validation (e.g. resolution check). Ensure resolution confidence meets project thresholds (e.g. ≥ 1.00).

## Editing Blueprints

When modifying an existing blueprint:

- **blueprint.meta.yaml** — Update `stacks`, `tier_defaults`, `tasks`, or `overlays`; keep YAML valid and IDs consistent with `tasks/task-index.yaml` when Tasks are adopted
- **BLUEPRINT.md** — Revise purpose, usage, or stack/tier documentation to match changes
- **overlays/** — Add, remove, or edit `.tpl.*` files under `overlays/<stack>/`; ensure paths in `blueprint.meta.yaml` match

Re-run validation after edits when the project has a validation script.

## Best Practices

- Start with a minimal `blueprint.meta.yaml` and expand; keep overlays focused per stack.
- Use consistent task IDs that exist in `tasks/task-index.yaml` when the Tasks template type is adopted.
- Version blueprints and document breaking changes in BLUEPRINT.md.

## Validation Checklist

- [ ] `blueprints/<id>/` exists with `blueprint.meta.yaml` and `BLUEPRINT.md`
- [ ] `blueprint.meta.yaml` has valid YAML with `id`, `version`, `name`, `stacks`, `tier_defaults`, `tasks`, `overlays`
- [ ] Overlay paths under `overlays/<stack>/` exist and are referenced correctly
- [ ] When validation script exists: blueprint resolution passes (e.g. confidence ≥ 1.00)
- [ ] BLUEPRINT.md describes purpose, stacks, and usage

## Troubleshooting

**Validation script missing** — The project may not include a top-level `scripts/`; blueprint structure still follows the framework. Add validation when adopting the full template system.

**Task IDs not found** — Ensure task IDs in `tasks` match entries in `tasks/task-index.yaml` when Tasks are in use; otherwise document expected task IDs for future adoption.

## Related Skills

- **rules-setup** — When adding or updating AGENTS.md or rule files that reference blueprints
- **tasks-setup** — When defining or changing tasks referenced by blueprints
- **skill-setup** — When creating or editing skills used in the same ecosystem

## Supporting Files

- **Framework and Blueprints section:** `AGENTIC-ASSETS-FRAMEWORK.md` at project root (when present)
- **Archive:** When the project has an archive, an archive reference doc (e.g. `docs/ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md`) may list blueprint paths and ADD-NEW-BLUEPRINT-TEMPLATE location; do not modify archive files
- **Example blueprint:** `blueprints/<id>/` in the project (e.g. `blueprints/mins/`) when present
