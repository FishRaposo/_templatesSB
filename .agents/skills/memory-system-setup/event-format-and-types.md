# Event Format, Types, and Graph Materialization

Reference for the memory-system-setup skill. See `SKILL.md` for deployment steps.

## Event template

Every event is appended under the `## Event Log` section in `CHANGELOG.md`:

```markdown
### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type

**Scope**: area affected
**Summary**: one-line description

**Details**:
- key: value

**Refs**: evt-XXX (or "none")
**Tags**: tag1, tag2
```

## Event types

| Type | When to Use |
|------|-------------|
| `decision` | Architectural or design choice — include `from`, `to`, `rationale` |
| `create` | New file/component/entity — include `entity`, `path`, `purpose` |
| `modify` | Existing code changed — include `entity`, `changes` |
| `delete` | File/component removed — include `entity`, `reason` |
| `test` | Test executed — include `target`, `result` |
| `fix` | Bug fixed — include `symptom`, `root_cause`, `resolution` |
| `dependency` | External dep added/changed — include `entity`, `version` |
| `blocker` | Progress blocked — include `blocked_entity`, `blocking_entity` |
| `milestone` | Significant threshold — include `name`, `criteria_met` |
| `escalation` | Escalated to human — include `reason`, `requested_action` |
| `handoff` | Pipeline handoff — include `from_agent`, `to_agent` |

## Append rules

1. **Only append** — never edit, delete, or reorder existing events
2. **One event per action** — do not batch multiple decisions
3. **Self-contained summaries** — Summary must make sense without Details
4. **Reference prior events** — use Refs to link cause-and-effect
5. **Sequential IDs** — increment for each new event

## Graph materialization (Full tier)

After appending events to `CHANGELOG.md`, update `.memory/graph.md`:

| Event Type | Graph Update |
|------------|--------------|
| `create` | Add row to Nodes table |
| `modify` | Update node's Last Event and Attributes |
| `delete` | Set Status to `deprecated` (never remove) |
| `decision` | Add decision node + `implements` edge |
| `dependency` | Add dependency node + `depends_on` edge |
| `blocker` | Add `blocks` edge |
| `fix` | Update node; remove `blocks` edges if resolved |
| `milestone` | Add/update milestone node |

**Node types:** `component` | `task` | `dependency` | `decision` | `document` | `milestone`

**Node statuses:** `active` | `blocked` | `completed` | `deprecated` | `planned`

**Edge relations:** `depends_on` | `blocks` | `implements` | `tests` | `documents` | `contains` | `precedes` | `related_to`
