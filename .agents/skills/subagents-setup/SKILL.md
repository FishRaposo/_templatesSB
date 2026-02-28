---
name: subagents-setup
description: Use this skill when creating, editing, or auditing Subagents — the template type that defines who does the work (configured sub-agents with skills and workflows). This includes subagent.yaml, SUBAGENT.md, workflows/, skill lists, and blueprint compatibility. Fits the seven-template-types framework (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols).
---

# Subagents Setup Skill

This skill creates and maintains **Subagents**: the template type that defines **who does the work** (configured sub-agents with skills and workflows). Subagents live under `subagents/<name>/` with `subagent.yaml` (machine-readable) and `SUBAGENT.md` (human-readable).

## Your Role

Help users **create** and **modify** Subagents through:

1. **Creating New Subagents** — Add a new subagent directory with `subagent.yaml` (skills, compatible blueprints, workflows), `SUBAGENT.md`, and optional `workflows/` definitions
2. **Editing Existing Subagents** — Update skill lists (primary/secondary), blueprint compatibility, or workflow definitions; revise `SUBAGENT.md` to match
3. **Auditing Subagents** — Check that skill identifiers match the project’s skills (e.g. `.agents/skills/`) and workflows execute correctly when the project has validation

When invoked, produce or update subagent files so they conform to the framework. Subagents run within Rules and use Skills for capability.

## Core Approach

Subagents answer **"Who does the work?"** They live under `subagents/<name>/` with `subagent.yaml` (machine-readable) and `SUBAGENT.md` (human-readable). Each subagent declares primary and optional skills, compatible blueprints, and workflows. They run within the Rules loaded by the active tool and use Skills for capability.

## Step-by-Step Instructions

### 1. Create the subagent directory

```
subagents/<name>/
├── subagent.yaml   # Subagent configuration
├── SUBAGENT.md     # Human-readable documentation
└── workflows/      # Defined workflow automations
    └── *.yaml      # Workflow definitions (or project convention)
```

### 2. Add subagent.yaml

Include at minimum:

- `subagent.id`, `name`, `description`
- `skills`: `primary` and optionally `secondary` skill identifiers
- `blueprints.compatible`: list of blueprint IDs this subagent works with (or equivalent)
- References to workflows under `workflows/` if the schema supports it

Reference the full schema and examples in the project's framework doc (`AGENTIC-ASSETS-FRAMEWORK.md` at project root, when present) → Subagents.

### 3. Write SUBAGENT.md

Document the subagent’s role, when to invoke it, which skills it uses, and how workflows are triggered. Keep it human-readable and link to the framework.

### 4. Add workflows (optional)

Under `workflows/`, add workflow definitions (e.g. YAML or tool-specific format) for automations this subagent can run. Follow project or tool conventions for workflow structure.

### 5. Validate (when the project has validation)

When the project includes validation for subagents, ensure workflows execute correctly and skill references resolve. Fix any reported errors before considering the subagent complete.

## Editing Subagents

When modifying an existing subagent:

- **subagent.yaml** — Update `skills` (primary/secondary), `blueprints.compatible`, or workflow references; keep YAML valid and skill IDs matching the project’s skills
- **SUBAGENT.md** — Revise role, when to invoke, or which skills/workflows are used
- **workflows/** — Add, remove, or edit workflow definition files per project or tool conventions

Re-run validation after edits when the project has a validation script.

## Best Practices

- Assign a focused set of primary skills; use secondary for optional or fallback capability.
- Document when to use this subagent vs others (e.g. code-reviewer vs testing-agent).
- Keep workflows small and testable; reference the Rules (AGENTS.md) for execution boundaries.

## Validation Checklist

- [ ] `subagents/<name>/` exists with `subagent.yaml` and `SUBAGENT.md`
- [ ] `subagent.yaml` has valid YAML with `id`, `name`, `skills`, and blueprint compatibility (or equivalent)
- [ ] Skill identifiers match the skills system in use (e.g. the project's skills directory such as `.agents/skills/` or `skills/`, or the platform's skill registry)
- [ ] SUBAGENT.md describes role, skills, and when to use
- [ ] When validation script exists: workflows execute correctly

## Troubleshooting

**Skill not found** — Ensure skill names match the project’s skills (e.g. under `.agents/skills/` or `skills/`) or the platform’s skill registry. Subagent skill lists may reference project-specific or archived content; resolve to the current project layout.

**Workflows not executing** — Check workflow format against the tool’s documentation (e.g. Cursor subagents, Claude sub-agents). Ensure paths and permissions are correct.

## Related Skills

- **rules-setup** — When updating AGENTS.md or rule files that reference subagents or execution boundaries
- **skill-setup** — When creating or editing skills that this subagent uses
- **blueprints-setup** — When defining which blueprints are compatible with this subagent

## Supporting Files

- **Framework and Subagents section:** `AGENTIC-ASSETS-FRAMEWORK.md` at project root (when present)
- **Archive:** When the project has an archive, an archive reference doc may list workflow-schema and workflows paths; do not modify archive files
- **Execution and subagents:** The project's AGENTS.md → "Subagents for execution" (when present)
