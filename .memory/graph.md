# Knowledge Graph

<!-- LAYER 2: Materialized view. Updated only from the Event Log. Never edited directly. -->
<!-- See docs/protocols/MEMORY-SYSTEM-PROTOCOL.md and memory-system README for materialization rules. -->

## Nodes

<!-- Node Types: component, task, dependency, decision, document, milestone -->
<!-- Statuses: active, blocked, completed, deprecated, planned -->

| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| _templatesSB | component | active | evt-001 | evt-012 | path: /, tier: MVP+Core |
| memory-system-setup | component | active | evt-001 | evt-008 | path: .agents/skills/memory-system-setup/, protocol skill |
| memory-system | component | active | evt-001 | evt-005 | path: docs/memory-system/, scripts + protocol refs |
| protocols | component | active | evt-006 | evt-008 | path: docs/protocols/, PROMPT-VALIDATION, MEMORY-SYSTEM |
| prompt-validation-setup | component | active | evt-006 | evt-008 | path: .agents/skills/prompt-validation-setup/, protocol skill |
| protocol-setup | component | active | evt-007 | evt-007 | path: .agents/skills/protocol-setup/, Protocols template type |
| skill-setup | component | active | evt-007 | evt-007 | path: .agents/skills/skill-setup/, renamed from skill-builder |
| documentation-blueprint | component | active | evt-011 | evt-013 | path: _documentation-blueprint/, v3.0; blueprint ↔ current |
| docs-core | component | active | evt-012 | evt-012 | path: docs/, SYSTEM-MAP, PROMPT-VALIDATION, INDEX; root QUICKSTART, CONTRIBUTING, SECURITY, WORKFLOW |
| flutter-setup | component | active | evt-014 | evt-014 | path: .agents/skills/flutter-setup/, Flutter/Dart project setup skill |

## Edges

<!-- Relations: depends_on, blocks, implements, tests, documents, contains, precedes, related_to -->

| From | To | Relation | Created (evt) | Attributes |
|------|----|----------|---------------|------------|
| memory-system-setup | _templatesSB | contains | evt-001 | |
| memory-system | _templatesSB | contains | evt-001 | |
| protocols | _templatesSB | contains | evt-006 | |
| prompt-validation-setup | protocols | implements | evt-006 | installs PROMPT-VALIDATION-PROTOCOL |
| memory-system-setup | protocols | implements | evt-008 | installs MEMORY-SYSTEM-PROTOCOL |
| protocol-setup | _templatesSB | contains | evt-007 | |
| skill-setup | _templatesSB | contains | evt-007 | |
| documentation-blueprint | _templatesSB | contains | evt-011 | |
| docs-core | _templatesSB | contains | evt-012 | |
| flutter-setup | _templatesSB | contains | evt-014 | |

## Meta

- **Last updated**: 2026-02-28
- **Event horizon**: evt-014
- **Nodes**: 10
- **Edges**: 10
