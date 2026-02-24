# MIGRATION-ENGINE.md - Large-Scale Architecture Migration Module

**Purpose**: Plan and execute large-scale architecture or module migrations in controlled phases.  
**Design**: Multi-phase planning, compatibility layers, sequential execution, documentation sync.  
**Integration**: Handles architecture-level transformations beyond simple refactors.

---

## 🧠 Core Idea

**Migration Engine = "Transform the shape of the system safely, across multiple steps, with compatibility layers and documentation."**

For:
- Splitting monolith modules
- Moving to feature-based structure  
- Renaming domains
- Replacing whole subsystems

---

## ✅ MIGRATION ENGINE v1.0 — SPEC

```
MIGRATION ENGINE — v1.0
-----------------------

Purpose:
Plan and execute large-scale architecture or module migrations in controlled phases.

Inputs:
- Current architecture (ARCHITECTURE.md, DATA-MODEL.md)
- Target architecture (either described or partially specified)
- MIGRATION-GUIDE.md (universal template)
- TESTING-STRATEGY.md
- FRAMEWORK-PATTERNS.md
- Codebase view (file tree + key modules)

Outputs:
- Migration plan (phased)
- Compatibility strategy
- Set of diffs for each phase
- Updated migration docs and roadmap
```

---

## 🔁 Migration Reasoning Loop

### STEP 1 — MIGRATION CLASSIFICATION
- Identify migration type:
  • Module split (one → many)
  • Module merge (many → one)
  • Layer reorganization
  • Domain rename
  • Tech replacement (e.g. state mgmt, DB, API)
- Identify if it is:
  • non-breaking (internal only)
  • breaking (public contracts change)

### STEP 2 — SOURCE → TARGET MAPPING
- Summarize current architecture.
- Describe target architecture.
- Create a mapping table:
  • from: module/file/class
  • to:   module/file/class

### STEP 3 — COMPATIBILITY STRATEGY
- Decide:
  • do we need adapters/shims?
  • do we maintain old interfaces temporarily?
  • do we run both systems in parallel (strangler pattern)?
- List compatibility modules required.

### STEP 4 — PHASED PLAN
Define phases, for example:
  Phase 1 — Introduce new structure (no behavior change)
  Phase 2 — Migrate internal calls
  Phase 3 — Redirect public APIs
  Phase 4 — Remove legacy paths
  Phase 5 — Cleanup and simplify

For each phase:
  - Files to change
  - Expected test impact
  - Rollback plan (if applicable)

### STEP 5 — TESTING STRATEGY
- For each phase:
  • which tests must exist before migrating?
  • which tests must be added?
  • which tests need updating?
- Ensure critical paths are fully tested BEFORE major moves.

### STEP 6 — MIGRATION DIFF GENERATION
- For each phase:
  • call Code Diff Reasoner with scoped instructions + invariants
  • generate diffs
  • validate them with Diff Validator

### STEP 7 — DOCUMENTATION UPDATES
- Update:
  • ARCHITECTURE.md
  • DATA-MODEL.md
  • MIGRATION-GUIDE.md (record current phase and decisions)
  • PROJECT-ROADMAP.md (mark migration milestones)
- Ensure docs describe both "before" and "after" clearly.

### STEP 8 — COMPLETION & DEBRIEF
- Confirm all old modules really removed if planned.
- Confirm tests fully cover new structure.
- Update MIGRATION-GUIDE.md:
  • final state
  • lessons learned
  • follow-up cleanups.

**This gives you safe, multi-phase, architecture-level migrations with no cowboy surgery.**

---

## 🔧 Integration with Documentation OS

### Dependencies:
- **ARCHITECTURE.md** - Current system architecture and boundaries
- **DATA-MODEL.md** - Current data structures and relationships
- **MIGRATION-GUIDE.md** - Migration template and tracking
- **TESTING-STRATEGY.md** - Testing requirements for each phase
- **FRAMEWORK-PATTERNS.md** - Framework-specific migration patterns
- **docs/platform-engineering/CODE-DIFF-REASONER.md** - Generates phase-specific diffs
- **docs/platform-engineering/DIFF-VALIDATOR.md** - Validates each phase's diffs

### Integration Points:
| Component | Role in Migration |
|-----------|-------------------|
| tier-index.yaml | Determines migration complexity allowed |
| docs/platform-engineering/REFACTOR-SIMULATION-ENGINE.md | Pre-flight analysis for major changes |
| docs/platform-engineering/VALIDATION-PROTOCOL-v2.md | Post-migration consistency validation |

### Agent Workflow Integration:
```bash
# Migration workflow
1. Receive migration request and target architecture
2. Load current architecture and constraints
3. Run MIGRATION-ENGINE 8-step loop
4. Generate phased migration plan
5. For each phase:
   - Call docs/platform-engineering/REFACTOR-SIMULATION-ENGINE.md
   - Call docs/platform-engineering/CODE-DIFF-REASONER.md
   - Call docs/platform-engineering/DIFF-VALIDATOR.md
   - Apply diffs if validation passes
6. Update all documentation
7. Run final validation
```

---

## 📋 Migration Plan Format

### Standard Migration Structure:
```markdown
## Migration Plan: [Migration Name]

**Type**: [Module Split/Merge/Layer Reorganization/Domain Rename/Tech Replacement]
**Breaking**: [Yes/No]
**Estimated Phases**: [Number]

### Current Architecture
[Summary of current structure]

### Target Architecture  
[Summary of target structure]

### Mapping Table
| From | To | Notes |
|------|----|-------|
| module/old | module/new | Split into feature modules |
| class/UserService | features/auth/UserService | Moved to auth feature |

### Compatibility Strategy
- [Adapters/Shims required]
- [Parallel systems description]
- [Interface preservation plan]

### Phased Execution

#### Phase 1: [Phase Name]
**Duration**: [Estimated]
**Risk**: [Low/Medium/High]
**Files**: [List]
**Tests**: [Requirements]
**Rollback**: [Plan]

#### Phase 2: [Phase Name]
[Continue for all phases]

### Documentation Updates
- ARCHITECTURE.md: [Changes needed]
- DATA-MODEL.md: [Changes needed]
- MIGRATION-GUIDE.md: [Phase tracking]
- PROJECT-ROADMAP.md: [Milestone updates]
```

---

## 🎯 Migration Examples

### Module Split Example:
```
Input: "Split the monolithic 'services' module into feature-based modules"

Migration Plan:
- Type: Module split (one → many)
- Phases: 4
- Phase 1: Create new feature modules (auth, payments, users)
- Phase 2: Move implementations to feature modules
- Phase 3: Update imports and create compatibility layer
- Phase 4: Remove old services module
- Compatibility: Temporary adapter in services/ module
- Tests: Parallel test suites during transition
```

### Tech Replacement Example:
```
Input: "Replace Redux with Zustand state management"

Migration Plan:
- Type: Tech replacement (state management)
- Phases: 5
- Phase 1: Install Zustand and create state slices
- Phase 2: Migrate non-critical components
- Phase 3: Migrate critical components with parallel state
- Phase 4: Switch to Zustand as primary store
- Phase 5: Remove Redux and clean up
- Compatibility: Dual store during transition
- Tests: A/B testing for state consistency
```

---

## 🛡️ Safety Constraints

### Migration Rules:
- Never break public APIs without explicit compatibility layer
- Always maintain rollback capability for each phase
- Ensure critical paths have 100% test coverage before migration
- Document all interim states and compatibility layers
- Monitor performance during migration phases

### Risk Mitigation:
- **Feature Flags**: Enable/disable new systems during transition
- **Canary Releases**: Gradual rollout of migrated components
- **Monitoring**: Track error rates and performance during migration
- **Rollback Triggers**: Automatic rollback on error threshold breach

---

## 🔄 Migration Patterns

### Strangler Pattern:
```markdown
1. Build new system alongside old
2. Redirect traffic gradually
3. Monitor and validate
4. Decommission old system
```

### Parallel Run Pattern:
```markdown
1. Implement new system
2. Run both systems in parallel
3. Compare outputs for consistency
4. Switch to new system
5. Remove old system
```

### Adapter Pattern:
```markdown
1. Create adapter/shim layer
2. Implement new system behind adapter
3. Migrate callers to new interface
4. Remove adapter
```

---

**This module enables any AI agent to perform complex architecture migrations safely, with proper planning, compatibility layers, and phased execution - eliminating "cowboy surgery" and ensuring system stability during major transformations.**
