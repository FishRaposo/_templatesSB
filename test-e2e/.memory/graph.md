# Knowledge Graph — TestProject

_Materialized view of entities and relationships. Never edit directly — materialize from CHANGELOG.md._

---

## Nodes

| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| TestProject | component | active | evt-001 | evt-001 | path: /, tier: core |
| core | component | active | evt-001 | evt-001 | path: src/ |
| docs_foundation | milestone | completed | evt-001 | evt-001 | criteria: blueprint initialized |

**Node types**: `component` `task` `dependency` `decision` `document` `milestone`  
**Node statuses**: `active` `blocked` `completed` `deprecated` `planned`

---

## Edges

| From | To | Relation | Created (evt) | Attributes |
|------|----|----------|---------------|------------|
| core | TestProject | contains | evt-001 | |

**Edge relations**: `depends_on` `blocks` `implements` `tests` `documents` `contains` `precedes` `related_to`

---

## Meta

- **Last updated**: 2026-02-28
- **Event horizon**: evt-001
- **Nodes**: 3
- **Edges**: 1

---

## Materialization Rules

When new events are appended to CHANGELOG.md, update this graph:

| Event Type | Graph Update |
|-----------|-------------|
| `create` | Add row to Nodes: type, status=active, created=evt-ID |
| `modify` | Update Last Event and relevant Attributes on existing node |
| `delete` | Set node Status to `deprecated` (never remove the row) |
| `decision` | Add `decision` node + `implements` edge to affected component |
| `dependency` | Add/update `dependency` node + `depends_on` edge |
| `blocker` | Add `blocks` edge between entities |
| `test` | Update target node Attributes (e.g., coverage %) |
| `fix` | Update target node; remove `blocks` edges if resolved |
| `milestone` | Add/update `milestone` node |
| `handoff` | Update `task` node: phase, assignee |

After updating: increment Meta event horizon to match latest processed event.

---

_Regenerate: replay all events from CHANGELOG.md if graph becomes inconsistent._
