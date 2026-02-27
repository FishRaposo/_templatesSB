# Current Context — {{PROJECT_NAME}}

_Immediate trajectory and active work. Ephemeral — regenerate every session from CHANGELOG.md + graph.md._

**Last updated**: {{DATE}} {{TIME}}  
**Event horizon**: evt-001  
**Session**: {{SESSION_DESCRIPTION}}

---

## Active Mission

{{ACTIVE_MISSION_PARAGRAPH}}

_Source: most recent milestone or decision events in CHANGELOG.md_

---

## Active Tasks

_Rename to "Current Sprint" if your project uses sprint methodology._

| Task | Priority | Status | Blockers |
|------|----------|--------|---------|
| {{TASK_1}} | high | active | none |
| {{TASK_2}} | medium | active | none |

_Source: graph.md nodes where Type = task, Status = active_

---

## Active Constraints

- {{CONSTRAINT_1}} — evt-NNN
- {{CONSTRAINT_2}} — evt-NNN

_Source: recent decision events defining boundaries_

---

## Blockers

- None currently

_Source: graph.md edges where Relation = blocks and target is active node_

---

## Recent Changes

- {{DATE}} — {{CHANGE_1_SUMMARY}} — evt-001
- _Add entries as events are appended to CHANGELOG.md_

_Source: last 20 events or last 48 hours from CHANGELOG.md_

---

## Key Dependencies

- {{DEPENDENCY_1}} depends on {{DEPENDENCY_2}} — evt-NNN

_Source: graph.md edges where Relation = depends_on for active components_

---

## Next Actions

1. {{NEXT_ACTION_1}}
2. {{NEXT_ACTION_2}}
3. {{NEXT_ACTION_3}}

_Source: active tasks minus blockers, respecting precedes edges in graph.md_

---

## Staleness Check

Compare `Event horizon` above with the last event ID in CHANGELOG.md.  
If they differ → regenerate this file before proceeding.

**Algorithm**:
1. Read graph.md — list all nodes with Status = active or blocked
2. Read CHANGELOG.md — last 20 events or last 48 hours (whichever is more)
3. Fill each section above mechanically — do not editorialize

---

_Regenerate: every session start_
