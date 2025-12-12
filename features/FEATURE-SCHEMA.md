# Feature Schema

This document defines the canonical, machine-readable feature specification used by the template system.

## Required Fields

- `id`
- `name`
- `summary`
- `user_story`
- `acceptance_criteria`
- `tier_impact`
- `stacks`
- `tasks`
- `inputs`
- `outputs`

## Notes

- `id` should be stable and machine-safe.
- `tasks` should reference task IDs from `tasks/task-index.yaml`.
- `dependencies` should reference other feature IDs.
