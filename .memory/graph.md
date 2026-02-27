# Knowledge Graph

<!-- LAYER 2: Materialized view. Updated only from the Event Log. Never edited directly. -->
<!-- See memory-system/README.md for materialization rules, node types, edge relations. -->

## Nodes

<!-- Node Types: component, task, dependency, decision, document, milestone -->
<!-- Statuses: active, blocked, completed, deprecated, planned -->

| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| _templatesSB | component | active | evt-001 | evt-001 | path: /, tier: full |
| memory-system-setup | component | active | evt-001 | evt-001 | path: skills/memory-system-setup/, memory system setup skill |
| memory-system | component | active | evt-001 | evt-001 | path: memory-system/, scripts + protocol + skill refs |

## Edges

<!-- Relations: depends_on, blocks, implements, tests, documents, contains, precedes, related_to -->

| From | To | Relation | Created (evt) | Attributes |
|------|----|----------|---------------|------------|
| memory-system-setup | _templatesSB | contains | evt-001 | |
| memory-system | _templatesSB | contains | evt-001 | |

## Meta

- **Last updated**: 2026-02-26
- **Event horizon**: evt-001
- **Nodes**: 3
- **Edges**: 2
