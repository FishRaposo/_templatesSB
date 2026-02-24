# REFACTOR-SAFETY-DASHBOARD.md - Human-Facing Control Panel for Safe Refactoring

**Purpose**: Centralized, human-readable control panel for tracking structural changes, migrations, and dangerous refactors.  
**Design**: Simple to scan in 30 seconds, strict enough to prevent catastrophic merges, structured for agents, readable for humans.  
**Integration**: Human-facing interface for the entire agentic platform engineering system.

---

## 🛡️ REFACTOR SAFETY DASHBOARD (Template v1.0)

A centralized, human-readable control panel for tracking structural changes, migrations, and dangerous refactors.

### Refactor Safety Dashboard — {PROJECT_NAME}
**Last Updated**: {DATE}  
**Refactor Owner**: {Name or Agent}  
**Refactor Tier**: (MVP / Core / Full)  
**Dashboard Status**: (Active / Review / Approved / Archived)

---

## 1. Summary of Active Refactor

**Refactor Name**: {Short descriptive title}  
**Goal**: {What is being improved and why}  
**Scope**: {Local / Module-Level / Architecture-Level / Migration}  
**Risk Level**: {Low / Medium / High / Critical}  
**Expected Duration**: {X days}

---

## 2. Change Map (High-Level Overview)

This is the "where in the building we're moving walls" section.

### Modules Affected
- {module1} — reason for change
- {module2} — reason for change
- {module3} — reason for change

### Public Interfaces Affected
- {API/function/class} — expected behavior change or preservation

### Cross-Cutting Concerns
- Error handling
- Performance implications
- Security implications
- Analytics/logging changes
- Platform constraints (mobile/web/backend)

---

## 3. Safety Invariants

Things that MUST NOT change.

- {Invariant 1}
- {Invariant 2}
- {Invariant 3}
- {Invariant 4}

**Examples**:
- "User login flow MUST remain functional."
- "Public API endpoint names MUST remain unchanged."
- "Persistence layer MUST remain schema-compatible."

---

## 4. No-Go Zones

Code regions or modules that MUST NOT be touched during this refactor.

- {module/file} — justification
- {module/file} — justification

**Examples**:
- Payment logic
- Legacy encryption module
- Platform-specific widget with undocumented code

---

## 5. Migration Phases (If Applicable)

Break large changes into safe, reversible steps.

| Phase | Description | Status | Risk | Owner |
|-------|-------------|--------|------|-------|
| 1 | Introduce new structure with no behavior change | ☐ | Low | |
| 2 | Migrate internal calls | ☐ | Medium | |
| 3 | Update public APIs | ☐ | High | |
| 4 | Remove deprecated paths | ☐ | Medium | |
| 5 | Final cleanup & docs | ☐ | Low | |

---

## 6. Patch Queue

All diffs waiting for review or merge.

1. `patch_2025_01_17_a.diff` — Awaiting validation
2. `patch_2025_01_17_b.diff` — Fails tests
3. `patch_2025_01_17_c.diff` — Needs doc sync

---

## 7. Tests Impact Assessment

What tests must change, be added, or be re-run?

**Required new tests**:
- {test name}

**Tests that must be updated**:
- {test name}

**Tests covering critical paths**:
- {test name}

**Also note**:
- Coverage risk: {Low/Medium/High}
- Blocking test failures: {List}

---

## 8. Documentation Sync Plan

Which docs need updating after the refactor?

- **ARCHITECTURE.md** — {what to update}
- **DATA-MODEL.md** — {what changed}
- **MIGRATION-GUIDE.md** — {phase added}
- **API-DOCUMENTATION.md** — {new/updated endpoints}
- **ROADMAP.md** — {milestone updates}

---

## 9. Rollback Plan

How to safely revert if the refactor goes sideways.

**Rollback Trigger**: {conditions}

**Rollback Steps**:
1. Revert patches: {list}
2. Restore previous architecture definition
3. Re-run critical path tests
4. Notify maintainers

---

## 10. Final Approval Checklist

Before merging the final refactor, ALL must be true.

- [ ] All invariants preserved
- [ ] No-go zones untouched
- [ ] All patches pass Diff Validator
- [ ] All tests green
- [ ] Documentation fully updated
- [ ] Migration Guide updated
- [ ] Architecture still consistent with FRAMEWORK-PATTERNS.md
- [ ] Validation Protocol v2 run twice
- [ ] Human review completed

---

## 11. Post-Merge Notes

- **Lessons learned**:
- **Unexpected challenges**:
- **Recommended follow-up tasks**:
- **Risks deferred**:

---

## 🔧 Integration with Agentic Platform Engineering System

### Component → Dashboard Section Mapping

| Component | Dashboard Sections | Role |
|-----------|-------------------|------|
| **docs/platform-engineering/REFACTOR-SIMULATION-ENGINE.md** | 1-4 | Pre-flight analysis, invariants, no-go zones |
| **docs/platform-engineering/MIGRATION-ENGINE.md** | 5 | Phased migration planning and execution |
| **docs/platform-engineering/CODE-DIFF-REASONER.md** | 6 | Generates patches for the queue |
| **docs/platform-engineering/DIFF-VALIDATOR.md** | 7, 10 | Test impact assessment, validation checklist |
| **docs/platform-engineering/VALIDATION-PROTOCOL-v2.md** | 8, 10 | Documentation sync, final validation |
| **tier-index.yaml** | 1 | Tier-based risk assessment |
| **ARCHITECTURE.md** | 2, 3, 10 | Module mapping, invariants, compliance |
| **FRAMEWORK-PATTERNS.md** | 2, 10 | Cross-cutting concerns, pattern compliance |

### Agent Contract Usage

**For AI Agents**:
- Use dashboard as contract for refactor scope and constraints
- Update appropriate sections after each phase completion
- Respect invariants and no-go zones absolutely
- Populate patch queue with validated diffs only

**For Human Reviewers**:
- Scan dashboard in 30 seconds for risk assessment
- Review migration phases for safety and reversibility
- Verify checklist completion before approval
- Monitor patch queue and test impact

### Workflow Integration

```bash
# Complete refactor workflow with dashboard
1. Initialize dashboard from REFACTOR-SIMULATION-ENGINE output
2. Update migration phases from MIGRATION-ENGINE plan
3. Add patches to queue from CODE-DIFF-REASONER
4. Validate patches with DIFF-VALIDATOR
5. Update documentation sync from VALIDATION-PROTOCOL-v2
6. Human reviews dashboard and checklist
7. Apply approved patches and update status
8. Complete post-merge notes and archive
```

---

## 📋 Dashboard Lifecycle

### Status Transitions
```
Active → Review → Approved → Archived
    ↑        ↓         ↓
    └── Rejected ←─────┘
```

### Status Definitions
- **Active**: Refactor in progress, patches being generated
- **Review**: Ready for human review, checklist verification
- **Approved**: All checks passed, ready for merge
- **Rejected**: Critical issues found, needs rework
- **Archived**: Completed and documented

---

## 🎯 Usage Examples

### Simple Refactor Example:
```
Refactor Name: Extract validation logic
Risk Level: Low
Duration: 1 day
Status: Active
Invariants: User service API behavior unchanged
No-Go Zones: Authentication middleware
```

### Architecture Migration Example:
```
Refactor Name: Redux to Zustand migration
Risk Level: High
Duration: 2 weeks
Status: Review
Phases: 5-phase migration with compatibility layer
Invariants: Component props, state shape, async behavior
No-Go Zones: Server API calls, critical user paths
```

---

**This dashboard serves as the critical human oversight layer that makes agentic platform engineering safe, legible, and reversible - the mission control panel for dangerous changes.**
