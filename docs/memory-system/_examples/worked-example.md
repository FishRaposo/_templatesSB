# Worked Example: Memory System in Action

This example shows 8 events flowing through all 4 layers for a small project: building an authentication module for a web API.

---

## Layer 0: Behavioral Core (AGENTS.md excerpt)

The project's `AGENTS.md` establishes these constraints before any work begins:

```markdown
## Do
- Use JWT for all authentication (no session storage)
- PostgreSQL for all persistent data
- Test coverage must exceed 80%

## Don't
- Do not store passwords in plain text
- Do not modify the database schema without an architecture decision
```

This is immutable during execution. Every agent reads it at boot and cannot change it.

---

## Layer 1: Event Log (CHANGELOG.md)

Eight events, appended chronologically as work progresses:

### evt-001 | 2025-02-10 09:00 | architect-01 | decision

**Scope**: database
**Summary**: Selected PostgreSQL as primary database engine
**Details**:
- Entity: database
- Attribute: engine
- From: (none)
- To: PostgreSQL
- Rationale: ACID compliance required for financial transactions; mandated by AGENTS.md

**Refs**: none
**Tags**: architecture, database, core

---

### evt-002 | 2025-02-10 09:15 | architect-01 | decision

**Scope**: auth_module
**Summary**: Auth module will use JWT tokens with 15-minute expiry
**Details**:
- Entity: auth_module
- Attribute: token_strategy
- From: (none)
- To: JWT with 15-min expiry, refresh tokens with 7-day expiry
- Rationale: Stateless auth per AGENTS.md constraints; short-lived tokens limit exposure

**Refs**: evt-001
**Tags**: architecture, authentication, security

---

### evt-003 | 2025-02-10 09:30 | architect-01 | create

**Scope**: auth_module
**Summary**: Created auth module directory structure
**Details**:
- Entity: auth_module
- Path: src/auth/
- Purpose: Handles user registration, login, token refresh, and password reset
- Files: src/auth/routes.py, src/auth/models.py, src/auth/utils.py

**Refs**: evt-002
**Tags**: auth, create

---

### evt-004 | 2025-02-10 09:45 | architect-01 | handoff

**Scope**: auth_module
**Summary**: Architecture phase complete, handing off to builder
**Details**:
- From agent: architect-01
- To agent: builder
- Payload:
  - Invariants: JWT only, no session storage, PostgreSQL backend
  - Boundaries: src/auth/ only, max 5 files
  - Constraints: Do not modify database schema directly (use migrations)
  - Artifacts: evt-001, evt-002, evt-003

**Refs**: evt-001, evt-002, evt-003
**Tags**: handoff, architecture-to-build

---

### evt-005 | 2025-02-10 10:30 | builder-01 | modify

**Scope**: auth_module
**Summary**: Implemented user registration and login endpoints
**Details**:
- Entity: auth_module
- Path: src/auth/routes.py, src/auth/models.py
- Changes:
  - Added POST /register endpoint with bcrypt password hashing
  - Added POST /login endpoint returning JWT access + refresh tokens
  - Added User model with email, hashed_password, created_at fields

**Refs**: evt-003, evt-004
**Tags**: implementation, auth, api

---

### evt-006 | 2025-02-10 11:00 | builder-01 | dependency

**Scope**: auth_module
**Summary**: Added PyJWT and bcrypt as project dependencies
**Details**:
- Entity: auth_module
- Dependencies added: PyJWT 2.8.0, bcrypt 4.1.2
- Reason: JWT token generation (evt-002 decision) and password hashing (security requirement)
- Updated: requirements.txt

**Refs**: evt-002, evt-005
**Tags**: dependency, security

---

### evt-007 | 2025-02-10 11:30 | builder-01 | handoff

**Scope**: auth_module
**Summary**: Build phase complete, handing off to tester
**Details**:
- From agent: builder-01
- To agent: tester
- Payload:
  - New functions: register_user(), login_user(), generate_tokens(), verify_token()
  - Expected behaviors: Registration returns 201 with user ID; Login returns 200 with JWT; Invalid credentials return 401
  - Modified flows: New /register and /login routes
  - Test targets: Token expiry, password hashing, duplicate email rejection
  - Artifacts: evt-005, evt-006

**Refs**: evt-004, evt-005, evt-006
**Tags**: handoff, build-to-test

---

### evt-008 | 2025-02-10 12:30 | tester-01 | test

**Scope**: auth_module
**Summary**: Auth module test suite complete — 12 tests, all passing, 91% coverage
**Details**:
- Target: auth_module
- Result: pass
- Coverage: 91%
- Tests added:
  - test_register_success (201 + user created)
  - test_register_duplicate_email (409 conflict)
  - test_login_success (200 + valid JWT returned)
  - test_login_wrong_password (401 unauthorized)
  - test_login_nonexistent_user (401 unauthorized)
  - test_token_expiry (token invalid after 15 min)
  - test_refresh_token (new access token from valid refresh)
  - test_refresh_token_expired (401 after 7 days)
  - test_password_not_stored_plaintext (bcrypt hash verified)
  - test_register_missing_fields (400 bad request)
  - test_login_missing_fields (400 bad request)
  - test_concurrent_logins (multiple valid tokens allowed)
- Uncovered: password reset flow (not yet implemented)

**Refs**: evt-005, evt-007
**Tags**: testing, auth, coverage

---

## Layer 2: Knowledge Graph (graph.md)

After processing all 8 events, the graph looks like this:

### Nodes

| Node | Type | Status | Created (evt) | Last Event | Attributes |
|------|------|--------|---------------|------------|------------|
| database | decision | active | evt-001 | evt-001 | engine: PostgreSQL, rationale: ACID compliance |
| auth_module | component | active | evt-003 | evt-008 | path: src/auth/, coverage: 91%, token: JWT 15-min |
| pyjwt | dependency | active | evt-006 | evt-006 | version: 2.8.0 |
| bcrypt | dependency | active | evt-006 | evt-006 | version: 4.1.2 |
| auth_test_suite | component | active | evt-008 | evt-008 | tests: 12, passing: 12, coverage: 91% |

### Edges

| From | To | Relation | Created (evt) | Attributes |
|------|----|----------|---------------|------------|
| auth_module | database | depends_on | evt-001 | engine: PostgreSQL |
| auth_module | database | implements | evt-002 | JWT strategy decision |
| auth_module | pyjwt | depends_on | evt-006 | (none) |
| auth_module | bcrypt | depends_on | evt-006 | (none) |
| auth_test_suite | auth_module | tests | evt-008 | coverage: 91% |

### Meta

- **Last updated**: 2025-02-10 12:30
- **Event horizon**: evt-008
- **Nodes**: 5
- **Edges**: 5

---

## Layer 3: Narrative (context.md)

Generated from the graph + recent changelog events:

<!-- Last generated: 2025-02-10 12:35 | Event horizon: evt-008 -->

### Active Mission

Building a secure authentication module for the web API. Architecture and implementation are complete. Testing phase finished with 91% coverage (exceeds the 80% threshold from AGENTS.md). Password reset flow is the remaining gap.

### Current Sprint

| Task | Priority | Assignee | Status | Blockers |
|------|----------|----------|--------|----------|
| Auth module implementation | high | builder-01 | completed | (none) |
| Auth module testing | high | tester-01 | completed | (none) |

### Active Constraints

- JWT only, no session storage — evt-002
- PostgreSQL for all persistent data — evt-001
- Do not modify database schema directly, use migrations — evt-004

### Blockers

- (none)

### Recent Changes

- 2025-02-10 12:30 — Auth test suite complete: 12 tests, 91% coverage — evt-008
- 2025-02-10 11:30 — Build phase complete, handed off to tester — evt-007
- 2025-02-10 11:00 — Added PyJWT 2.8.0 and bcrypt 4.1.2 dependencies — evt-006
- 2025-02-10 10:30 — Implemented registration and login endpoints — evt-005
- 2025-02-10 09:45 — Architecture phase complete, handed off to builder — evt-004
- 2025-02-10 09:30 — Created auth module directory structure — evt-003
- 2025-02-10 09:15 — JWT tokens with 15-min expiry selected for auth — evt-002
- 2025-02-10 09:00 — PostgreSQL selected as primary database — evt-001

### Key Dependencies

- auth_module depends on database (PostgreSQL) — evt-001
- auth_module depends on PyJWT 2.8.0 — evt-006
- auth_module depends on bcrypt 4.1.2 — evt-006

### Next Actions

1. Hand off to doc manager — document the auth module API endpoints
2. Implement password reset flow — identified as uncovered in evt-008
3. Run validator phase — verify all Three Pillars satisfied

---

## How the Layers Connected

```
evt-001 (decision: PostgreSQL)
    → Node: database (decision, active)
    → Edge: auth_module depends_on database
    → Context: Listed in Active Constraints + Key Dependencies

evt-005 (modify: implemented endpoints)
    → Node: auth_module updated (last_event: evt-005)
    → Context: Listed in Recent Changes

evt-008 (test: 91% coverage)
    → Node: auth_test_suite (component, active)
    → Node: auth_module updated (coverage: 91%)
    → Edge: auth_test_suite tests auth_module
    → Context: Coverage noted in Active Mission, listed in Recent Changes
```

### Anti-Drift in Action

If a new agent boots and claims "we decided to use Firebase," the system rejects this:
- **Changelog**: No event records a Firebase decision
- **Graph**: No node for Firebase exists; `database` node shows PostgreSQL
- **Context**: Active Constraints lists "PostgreSQL for all persistent data — evt-001"
- **AGENTS.md**: States "Use PostgreSQL for all persistent data"

The hallucination has no grounding in any layer. Ground truth wins.
