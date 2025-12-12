# Workflow Schema

This document defines the canonical, machine-readable workflow specification used by the template system.

## Required Fields

- `id`
- `name`
- `summary`
- `primary_actor`
- `preconditions`
- `postconditions`
- `happy_path`
- `steps`

## Notes

- `id` should be stable and machine-safe.
- Each `step` should reference a valid `feature_id`.
- `system_tasks` should reference task IDs from `tasks/task-index.yaml`.
