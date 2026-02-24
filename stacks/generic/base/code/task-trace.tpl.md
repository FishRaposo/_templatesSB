# Task Trace Probe

This file documents the task trace probe interface used by generated projects.

Trace events are newline-delimited JSON written to:

- `artifacts/task-trace.jsonl`

Each event should include:

- `task_id` (string)
- `type` (string)
- `ts` (number; unix seconds)

Optional fields (depending on `type`):

- `name`, `key`, `table`, `keys`, `value`

The template system provides per-stack implementations in the corresponding `task-trace.*` source file for your stack.
