# Tool Call Limits & Efficiency

> Guidelines for AI assistants working on {{PROJECT_NAME}}

## Principles

- Batch file reads when possible
- Prefer targeted search over broad search
- Cache findings to avoid re-reading
- Avoid generating large diffs unnecessarily

## Practical Guidelines

- Prefer search tools for discovery, file reads for confirmation.
- Minimize repeated scans of the repo.
- When changing code, identify all call sites before editing.

---

**Last Updated**: {{LAST_UPDATED_DATE}}
