# System Map — {{PROJECT_NAME}}

_Architecture overview — keep this current with every structural change_

**Last updated**: {{DATE}} (evt-NNN)

---

## System Overview

```
{{ASCII_OR_MERMAID_DIAGRAM}}

Example (replace with actual):

┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│     API     │────▶│  Database   │
│ {{CLIENT}}  │     │  {{API}}    │     │   {{DB}}    │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                    ┌──────▼──────┐
                    │   Cache     │
                    │ {{CACHE}}   │
                    └─────────────┘
```

---

## Component Inventory

| Component | Purpose | Location | Owner | Status |
|-----------|---------|----------|-------|--------|
| {{COMPONENT_1}} | {{COMPONENT_1_PURPOSE}} | `{{COMPONENT_1_PATH}}` | {{COMPONENT_1_OWNER}} | Active |
| {{COMPONENT_2}} | {{COMPONENT_2_PURPOSE}} | `{{COMPONENT_2_PATH}}` | {{COMPONENT_2_OWNER}} | Active |
| {{COMPONENT_3}} | {{COMPONENT_3_PURPOSE}} | `{{COMPONENT_3_PATH}}` | {{COMPONENT_3_OWNER}} | Active |

---

## Data Flow

{{DATA_FLOW_DESCRIPTION}}

1. {{STEP_1}}
2. {{STEP_2}}
3. {{STEP_3}}

---

## Dependency Map

### External Dependencies

| Dependency | Version | Purpose | Risk |
|------------|---------|---------|------|
| {{DEP_1}} | {{DEP_1_VERSION}} | {{DEP_1_PURPOSE}} | {{DEP_1_RISK}} |
| {{DEP_2}} | {{DEP_2_VERSION}} | {{DEP_2_PURPOSE}} | {{DEP_2_RISK}} |

### Internal Dependencies

```
{{COMPONENT_A}} depends on {{COMPONENT_B}}
{{COMPONENT_C}} depends on {{COMPONENT_A}}, {{COMPONENT_B}}
```

---

## Architecture Decisions

Key decisions recorded as `decision` events in `CHANGELOG.md`:

| Decision | Event | Rationale Summary |
|----------|-------|------------------|
| {{DECISION_1}} | evt-NNN | {{DECISION_1_RATIONALE}} |
| {{DECISION_2}} | evt-NNN | {{DECISION_2_RATIONALE}} |

For full ADR content, see `docs/adr/` (Full tier) or search CHANGELOG.md for `type: decision`.

---

## Boundaries and Constraints

- **{{BOUNDARY_1}}**: {{BOUNDARY_1_DESCRIPTION}}
- **{{BOUNDARY_2}}**: {{BOUNDARY_2_DESCRIPTION}}
- **{{BOUNDARY_3}}**: {{BOUNDARY_3_DESCRIPTION}}

---

_Update this file whenever architecture changes. Log the update as a `modify` event in CHANGELOG.md._
