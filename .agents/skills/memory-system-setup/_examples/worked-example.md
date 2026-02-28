# Memory System Worked Example

**A complete walkthrough of 8 events through all 4 memory system layers.**

This example demonstrates how the four layers (L0: AGENTS.md, L1: CHANGELOG.md, L2: graph.md, L3: context.md) work together in a real project scenario.

---

## Scenario

A solo developer is building a task management API. They start with the **Core** tier (L0, L1, L3) and the project grows over 3 days.

---

## Layer 0: AGENTS.md (Behavioral Core)

Read once at boot, immutable during execution:

```markdown
# AGENTS.md - Task Management API

## Tech Stack
- Language: Python 3.11
- Framework: FastAPI
- Database: PostgreSQL

## Commands
- Test: `pytest tests/`
- Lint: `ruff check .`

## Do
- Use Pydantic models for all inputs/outputs
- Write tests for new endpoints

## Don't
- Do not commit `.env` files
- Do not use raw SQL without parameterization

## Boundaries
- Always: Update CHANGELOG.md after task completion
- Ask first: Database schema changes
- Never: Delete events from CHANGELOG.md
```

---

## Event Timeline (Layer 1 → 2 → 3)

### Event 1: Project Initialization

**Layer 1 (CHANGELOG.md):**
```markdown
### evt-001 | 2025-02-10 09:00 | developer | create

**Scope**: project_root
**Summary**: Initialize task management API project

**Details**:
- entity: task_management_api
- path: /
- purpose: Core task management service with REST endpoints

**Refs**: none
**Tags**: milestone, init
```

**Layer 2 (graph.md):**
```markdown
## Nodes
| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| task_management_api | component | active | evt-001 | evt-001 | path: / |
```

**Layer 3 (context.md):**
```markdown
## Active Mission
Initialize task management API project - Core REST service foundation.

## Recent Changes
- 2025-02-10 09:00 — Initialize task management API — evt-001

## Next Actions
1. Set up FastAPI project structure
2. Create initial database schema
3. Implement basic CRUD endpoints
```

---

### Event 2: Database Schema Decision

**Layer 1 (CHANGELOG.md):**
```markdown
### evt-002 | 2025-02-10 09:15 | developer | decision

**Scope**: database
**Summary**: Choose SQLAlchemy + Alembic for ORM and migrations

**Details**:
- entity: database_stack
- attribute: orm_tooling
- from: considering options
- to: SQLAlchemy + Alembic
- rationale: Team familiarity, good FastAPI integration, migration support

**Refs**: evt-001
**Tags**: decision, database
```

**Layer 2 (graph.md):**
```markdown
## Nodes
| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| task_management_api | component | active | evt-001 | evt-001 | path: / |
| database_stack | decision | active | evt-002 | evt-002 | orm: SQLAlchemy |

## Edges
| From | To | Relation | Created (evt) | Attributes |
|------|----|----------|---------------|------------|
| task_management_api | database_stack | implements | evt-002 | |
```

---

### Event 3: Create Database Models

**Layer 1 (CHANGELOG.md):**
```markdown
### evt-003 | 2025-02-10 10:30 | developer | create

**Scope**: src/models/
**Summary**: Create Task and User SQLAlchemy models

**Details**:
- entity: database_models
- path: src/models/task.py, src/models/user.py
- purpose: Core data models for tasks and users

**Refs**: evt-002
**Tags**: create, database, models
```

**Layer 2 (graph.md):**
```markdown
## Nodes
| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| task_management_api | component | active | evt-001 | evt-001 | path: / |
| database_stack | decision | active | evt-002 | evt-002 | orm: SQLAlchemy |
| database_models | component | active | evt-003 | evt-003 | path: src/models/ |

## Edges
| From | To | Relation | Created (evt) | Attributes |
|------|----|----------|---------------|------------|
| task_management_api | database_stack | implements | evt-002 | |
| database_models | database_stack | depends_on | evt-003 | |
```

---

### Event 4: Blocker - Migration Issue

**Layer 1 (CHANGELOG.md):**
```markdown
### evt-004 | 2025-02-10 11:00 | developer | blocker

**Scope**: database_migrations
**Summary**: Alembic migration fails on nullable constraint

**Details**:
- blocked_entity: database_migrations
- blocking_entity: task_model_nullable_fields
- resolution_path: Review Task model field constraints, fix nullable=True settings

**Refs**: evt-003
**Tags**: blocker, database
```

**Layer 2 (graph.md):**
```markdown
## Nodes
| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| database_models | component | blocked | evt-003 | evt-004 | path: src/models/ |
| task_model_nullable_fields | dependency | active | evt-004 | evt-004 | issue: nullable |

## Edges
| From | To | Relation | Created (evt) | Attributes |
|------|----|----------|---------------|------------|
| task_model_nullable_fields | database_models | blocks | evt-004 | |
```

**Layer 3 (context.md):**
```markdown
## Active Mission
Initialize task management API project. Currently resolving database migration blockers.

## Current Sprint
| Task | Priority | Status | Blockers |
|------|----------|--------|----------|
| Fix nullable fields in Task model | high | blocked | evt-004 |

## Blockers
- **task_model_nullable_fields** blocks **database_models** — evt-004
  - Issue: Alembic migration fails on nullable constraint
  - Resolution: Review Task model field constraints

## Recent Changes
- 2025-02-10 11:00 — Alembic migration fails — evt-004
- 2025-02-10 10:30 — Create Task and User models — evt-003
- 2025-02-10 09:15 — Choose SQLAlchemy + Alembic — evt-002
- 2025-02-10 09:00 — Initialize project — evt-001
```

---

### Event 5: Fix Migration Blocker

**Layer 1 (CHANGELOG.md):**
```markdown
### evt-005 | 2025-02-10 11:30 | developer | fix

**Scope**: src/models/task.py
**Summary**: Fix nullable constraints in Task model

**Details**:
- entity: database_models
- symptom: Alembic migration failed with nullable constraint error
- root_cause: due_date field marked nullable=False but no default
- resolution: Changed due_date to nullable=True, added validator

**Refs**: evt-004
**Tags**: fix, database, models
```

**Layer 2 (graph.md):**
```markdown
## Nodes
| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| database_models | component | active | evt-003 | evt-005 | path: src/models/ |
| task_model_nullable_fields | dependency | resolved | evt-004 | evt-005 | |

## Edges
| From | To | Relation | Created (evt) | Attributes |
|------|----|----------|---------------|------------|
| (blocks edge removed - resolved by evt-005) |
```

---

### Event 6: Test Suite Created

**Layer 1 (CHANGELOG.md):**
```markdown
### evt-006 | 2025-02-10 14:00 | developer | create

**Scope**: tests/
**Summary**: Create test suite for Task endpoints

**Details**:
- entity: task_tests
- path: tests/test_tasks.py
- purpose: Unit and integration tests for Task CRUD operations

**Refs**: evt-005
**Tags**: create, testing
```

**Layer 2 (graph.md):**
```markdown
## Nodes
| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| task_tests | component | active | evt-006 | evt-006 | coverage: 85% |

## Edges
| From | To | Relation | Created (evt) | Attributes |
|------|----|----------|---------------|------------|
| task_tests | database_models | tests | evt-006 | |
```

---

### Event 7: Test Execution

**Layer 1 (CHANGELOG.md):**
```markdown
### evt-007 | 2025-02-10 14:30 | developer | test

**Scope**: tests/test_tasks.py
**Summary**: Run test suite - 12 pass, 0 fail

**Details**:
- target: task_tests
- result: pass
- coverage: 87%

**Refs**: evt-006
**Tags**: test, validation
```

**Layer 2 (graph.md):**
```markdown
## Nodes
| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| task_tests | component | active | evt-006 | evt-007 | coverage: 87% |
```

---

### Event 8: Milestone - MVP Complete

**Layer 1 (CHANGELOG.md):**
```markdown
### evt-008 | 2025-02-11 09:00 | developer | milestone

**Scope**: project
**Summary**: MVP complete - Core task CRUD API functional

**Details**:
- name: mvp_complete
- criteria_met:
  - Task and User models implemented
  - CRUD endpoints working
  - Test coverage > 80%
  - Database migrations functional

**Refs**: evt-001, evt-007
**Tags**: milestone, mvp
```

**Layer 2 (graph.md):**
```markdown
## Nodes
| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| mvp_complete | milestone | achieved | evt-008 | evt-008 | criteria: 4/4 |

## Edges
| From | To | Relation | Created (evt) | Attributes |
|------|----|----------|---------------|------------|
| task_management_api | mvp_complete | contains | evt-008 | |
| task_tests | mvp_complete | tests | evt-008 | |

## Meta
- **Last updated**: 2025-02-11 09:05
- **Event horizon**: evt-008
- **Nodes**: 7
- **Edges**: 6
```

**Layer 3 (context.md):**
```markdown
## Active Mission
MVP complete - Core task management API is functional with CRUD operations, models, and tests.

## Current Sprint
| Task | Priority | Status | Blockers |
|------|----------|--------|----------|
| MVP Release | — | completed | — |

## Active Constraints
- Use Pydantic models for all inputs/outputs — evt-002
- Test coverage > 80% — evt-008

## Recent Changes
- 2025-02-11 09:00 — MVP complete milestone — evt-008
- 2025-02-10 14:30 — Tests pass (87% coverage) — evt-007
- 2025-02-10 14:00 — Create test suite — evt-006
- 2025-02-10 11:30 — Fix nullable constraints — evt-005

## Key Dependencies
- database_models depends on database_stack — evt-003
- task_tests tests database_models — evt-006

## Next Actions
1. Deploy to staging environment
2. Add authentication endpoints
3. Implement task filtering and search

---
*Event horizon: evt-008 | Generated: 2025-02-11 09:05*
```

---

## Key Observations

### One-Way Data Flow
1. **Agent action** → Append to CHANGELOG.md (evt-001 through evt-008)
2. **Materialize** → graph.md updated with nodes/edges for each event
3. **Regenerate** → context.md derived from L1 + L2

### Anti-Drift Mechanisms in Action
- **Blocker tracked**: evt-004 created a `blocks` edge, removed by evt-005
- **Node status changes**: database_models went from `active` → `blocked` → `active`
- **Attribute updates**: task_tests coverage updated from 85% → 87%

### Query Patterns Demonstrated
- "What blocks what?" → `task_model_nullable_fields blocks database_models`
- "What's the status of X?" → `database_models: active`
- "What changed recently?" → Last 4 events in context.md
- "What depends on what?" → `database_models depends_on database_stack`

### Tier Usage
This example uses **Core tier**: AGENTS.md + CHANGELOG.md + context.md. The graph.md shown is optional but helps visualize the knowledge graph structure used in **Full tier**.
