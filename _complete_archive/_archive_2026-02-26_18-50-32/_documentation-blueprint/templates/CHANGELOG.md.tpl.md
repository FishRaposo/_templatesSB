# CHANGELOG.md

_Event log for {{PROJECT_NAME}} — all decisions, changes, and milestones_

---

## Event Format

```
### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type

**Scope**: area affected
**Summary**: one-line description

**Details**:
- key: value

**Refs**: evt-XXX (prior related events, or "none")
**Tags**: tag1, tag2
```

**Event types**: `decision` `create` `modify` `delete` `test` `fix` `dependency` `blocker` `milestone` `escalation` `handoff`

**Append rules**:
- Never edit or delete existing events
- One event per logical action
- Sequential IDs (evt-001, evt-002, ...)
- Summary must be understandable without reading Details
- Archive to `CHANGELOG-archive.md` when log exceeds 50 events

---

## Events

### evt-001 | {{DATE}} {{TIME}} | {{AGENT}} | create

**Scope**: repository
**Summary**: Initialize {{PROJECT_NAME}} documentation

**Details**:
- entity: {{PROJECT_NAME}}
- path: /
- purpose: Project documentation foundation established from documentation blueprint template
- tier: {{TIER}}
- stack: {{STACK}}

**Refs**: none
**Tags**: initialization, documentation, foundation
