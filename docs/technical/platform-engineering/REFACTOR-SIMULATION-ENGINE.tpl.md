# REFACTOR-SIMULATION-ENGINE.md - Behavioral Impact Simulation Module

**Purpose**: Simulate the behavioral impact of planned refactors BEFORE generating any code diffs.  
**Design**: Pre-flight analysis, behavior modeling, invariant identification, change scoping.  
**Integration**: Runs before Code Diff Reasoner to provide context and constraints.

---

## 🧠 Core Idea

**Refactor Simulation = "If I apply this conceptual change, how do requests, data, and control flow change across the system?"**

It doesn't touch code. It models code.

---

## ✅ REFACTOR SIMULATION ENGINE v1.0 — SPEC

```
REFACTOR SIMULATION ENGINE — v1.0
----------------------------------

Purpose:
Simulate the behavioral impact of a planned refactor BEFORE generating any code diffs.

Inputs:
- Refactor intent (natural language)
- List of target files/modules
- ARCHITECTURE.md
- FRAMEWORK-PATTERNS.md
- TESTING docs
- (Optional) API-DOCUMENTATION.md, DATA-MODEL.md

Outputs:
- Simulation report
- A list of invariants to preserve
- A list of no-go areas
- A scoped change plan for the Code Diff Reasoner
```

---

## 🔁 Reasoning Loop

### STEP 1 — INTENT CLARITY
- Restate the refactor in one sentence.
- Classify it:
  • Local refactor (inside one module)
  • Cross-module refactor
  • Architecture-level refactor
  • Behavioral change (feature-level)
- Identify whether public behavior MUST be preserved.

### STEP 2 — CONTEXT MAPPING
- Map the intent onto:
  • specific files
  • specific modules
  • specific public APIs
- Identify all call sites and call chains for affected functions.

### STEP 3 — FLOW SIMULATION
For each affected entrypoint:
  - Describe current control flow:
    • input → processing → output
  - Describe current data flow:
    • where data comes from
    • where it goes
  - Describe current side effects:
    • DB / storage / network / logs / analytics

### STEP 4 — CHANGE PROJECTION
- Describe how control flow WILL change.
- Describe how data flow WILL change.
- Describe how errors WILL change (if at all).
- Identify which tests should fail or need updating.

### STEP 5 — INVARIANTS & NO-GO ZONES
- List explicit invariants:
  • behaviors that MUST NOT change
  • interfaces that MUST NOT break
- List no-go zones:
  • legacy modules not to be touched
  • critical hot paths
  • security-sensitive code

### STEP 6 — SCOPED CHANGE PLAN
- Break the refactor into steps:
  • Step 1: internal restructuring
  • Step 2: tests update
  • Step 3: doc sync
- For each step, specify:
  • files affected
  • expected outcome
  • what tests should verify

### STEP 7 — HANDOFF
- Emit:
  • invariants[]
  • no_go_zones[]
  • step_plan[]
  • affected_files[]
- Pass this to the Code Diff Reasoner.

**Agents now think like senior engineers before touching a single line.**

---

## 🔧 Integration with Documentation OS

### Dependencies:
- **ARCHITECTURE.md** - System boundaries and constraints
- **FRAMEWORK-PATTERNS.md** - Framework-specific flow patterns
- **TESTING.md** - Current test coverage and strategy
- **API-DOCUMENTATION.md** - Public interface contracts
- **DATA-MODEL.md** - Data flow and entity relationships

### Integration Points:
| Component | Role in Simulation |
|-----------|-------------------|
| tier-index.yaml | Determines simulation complexity allowed |
| docs/platform-engineering/CODE-DIFF-REASONER.md | Receives simulation output as input |
| docs/platform-engineering/VALIDATION-PROTOCOL-v2.md | Validates simulation assumptions |

### Agent Workflow Integration:
```bash
# Pre-refactor simulation workflow
1. Receive refactor request and scope
2. Load architecture and framework constraints
3. Run REFACTOR-SIMULATION-ENGINE 7-step loop
4. Generate simulation report with invariants
5. Pass output to docs/platform-engineering/CODE-DIFF-REASONER.md
6. Continue with diff generation
```

---

## 📋 Simulation Output Format

### Standard Report Structure:
```markdown
## Refactor Simulation Report

**Intent**: [One-sentence restatement]
**Classification**: [Local/Cross-module/Architecture/Behavioral]
**Public Behavior Preservation**: [Required/Optional]

### Current System Analysis
**Affected Modules**: [List]
**Public APIs**: [List]
**Call Sites**: [List]

### Flow Simulation
**Control Flow**: [Current → Projected]
**Data Flow**: [Current → Projected]
**Side Effects**: [Current → Projected]

### Invariants to Preserve
1. [Behavior that must not change]
2. [Interface that must not break]
3. [Performance characteristic]

### No-Go Zones
1. [Legacy module]
2. [Critical hot path]
3. [Security-sensitive code]

### Scoped Change Plan
**Step 1**: [Internal restructuring]
  - Files: [List]
  - Expected: [Outcome]
  - Tests: [Verification]

**Step 2**: [Tests update]
  - Files: [List]
  - Expected: [Outcome]
  - Tests: [Verification]

**Step 3**: [Doc sync]
  - Files: [List]
  - Expected: [Outcome]
  - Tests: [Verification]
```

---

## 🎯 Usage Examples

### Local Refactor Example:
```
Input: "Extract validation logic from user_service.py into a separate validator module"

Simulation Output:
- Intent: Separate validation concerns from user service
- Classification: Local refactor (single module split)
- Invariants: User service API behavior must remain identical
- No-go zones: Authentication middleware, database connection handling
- Change Plan: Create validator module → Move validation logic → Update imports → Add tests
```

### Architecture-Level Refactor Example:
```
Input: "Replace Redux with Zustand state management across the entire app"

Simulation Output:
- Intent: Migrate from Redux to Zustand state management
- Classification: Architecture-level refactor
- Invariants: Component public props, state shape, async behavior
- No-go zones: Server API calls, authentication flow, critical user paths
- Change Plan: Install Zustand → Create state slices → Migrate components → Remove Redux → Update tests
```

---

## 🛡️ Safety Constraints

### Simulation Rules:
- Never assume behavior changes without explicit evidence
- Always identify public contract boundaries
- Map all data dependencies before suggesting changes
- Consider error handling and edge cases in projections
- Identify performance implications of proposed changes

### Risk Assessment:
- **LOW**: Local refactors with clear boundaries
- **MEDIUM**: Cross-module changes with documented interfaces
- **HIGH**: Architecture-level changes affecting multiple layers
- **CRITICAL**: Changes to authentication, payments, or data persistence

---

**This module transforms any coding agent from a "code generator" into a "system thinker" that models impact before making changes, preventing catastrophic refactors and ensuring behavioral preservation.**
