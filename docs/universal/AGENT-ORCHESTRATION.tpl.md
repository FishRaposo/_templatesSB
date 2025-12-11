# AGENT-ORCHESTRATION.md - Multi-Agent Assembly Line Protocol

**Purpose**: Coordinate Architect → Builder → Tester → Doc Manager → Validator → Merge roles in deterministic phases.
**Version**: 1.0
**Design**: LLM-friendly, architecture-first, deterministic handoffs

---

## ★ OVERVIEW

Every work item (feature, refactor, migration, update) passes through six stations, each with strict entry/exit conditions.

1. **Architect** — define shape & constraints
2. **Builder** — implement code within the constraints  
3. **Tester** — verify behavior, coverage, safety
4. **Doc Manager** — update docs to match code
5. **Validator** — perform final structural checks
6. **Merge** — integrate safely into main branch

Each station produces a handoff artifact, so the next agent begins with clear context.

---

## ★ PHASE 1 — ARCHITECT PASS

### Goal
Establish the architectural boundary and invariants for the work item.

### Output
- Architecture delta
- Invariants  
- No-go zones
- Folder structure updates
- Blueprint-to-code mapping

### Handoff → Builder
Work cannot proceed unless the Architect explicitly completes this pass.

### Entry Conditions
- Clear work item description
- Existing blueprint and architecture available
- Tier selection determined

### Exit Conditions
- All invariants declared
- Module boundaries defined
- No-go zones identified
- Handoff artifact generated

---

## ★ PHASE 2 — BUILDER PASS

### Goal
Generate code only within the boundaries set by Architect.

### Input
- Architect's constraints
- Handoff artifact from Phase 1

### Output
- Code changes
- New modules  
- Updated test skeletons
- TODO/ROADMAP updates

### Handoff → Tester

### Entry Conditions
- Valid architecture constraints received
- Clear implementation scope defined
- Framework patterns identified

### Exit Conditions
- Code generated within boundaries
- Test skeletons created
- TODO/ROADMAP updated
- Handoff artifact generated

---

## ★ PHASE 3 — TESTER PASS

### Goal
Ensure code behaves correctly and safely.

### Input
- Builder output + Architect constraints
- Handoff artifact from Phase 2

### Output
- Regenerated tests
- Test pass/fail result
- List of missing tests
- Behavior notes
- Regression detections

### Handoff Rules
- **If tests fail** → send back to Builder
- **If tests reveal architectural invalidity** → send back to Architect
- **If tests pass** → handoff to Doc Manager

### Entry Conditions
- Code changes received from Builder
- Architect constraints available
- Testing strategy identified

### Exit Conditions
- All tests generated and passing
- Coverage thresholds met
- No regressions detected
- Handoff artifact generated

---

## ★ PHASE 4 — DOC MANAGER PASS

### Goal
Align documentation with the final code & architecture.

### Input
- Tester validation + Builder code
- Handoff artifact from Phase 3

### Output
- Updated docs
- API documentation updates
- Architecture updates
- Migration entries
- Roadmap adjustments

### Handoff → Validator

### Entry Conditions
- Validated code received from Tester
- Changes identified that need documentation
- Documentation templates available

### Exit Conditions
- All documentation updated
- API docs current
- Migration entries created
- Handoff artifact generated

---

## ★ PHASE 5 — VALIDATOR PASS

### Goal
Perform global consistency & structural integrity check.

### Runs
- Validation Protocol v2
- Diff Validator
- Hotspot Radar (if relevant)

### Failure Recovery
- **If fails** → return to appropriate role (Architect, Builder, Refactorer, Doc Manager)
- **If passes** → go to Merge

### Entry Conditions
- Updated documentation from Doc Manager
- Complete code and test suite
- All previous handoff artifacts

### Exit Conditions
- All validation checks pass
- Structural integrity confirmed
- Ready for merge

---

## ★ PHASE 6 — MERGE PASS

Everything is now safe to integrate.

### Final Checks
- Merge Safety Checklist
- Changelog Generator

### Entry Conditions
- Validator approval received
- All artifacts complete
- No outstanding issues

### Exit Conditions
- Successfully merged to main branch
- Changelog updated
- Pipeline complete

---

## 🔄 HANDOFF ARTIFACTS

### Standard Artifact Format
```yaml
handoff_artifact:
  from_agent: [agent_name]
  to_agent: [agent_name]  
  work_item: [description]
  timestamp: [iso_timestamp]
  
  # Agent-specific content
  constraints: {}
  outputs: {}
  notes: []
  
  # Validation
  entry_conditions_met: true
  exit_conditions_met: true
  ready_for_handoff: true
```

### Artifact Transfer Protocol
1. **Source agent** generates artifact
2. **Validation system** checks completeness
3. **Target agent** receives and validates
4. **Work begins** only after artifact acceptance

---

## ⚡ PIPELINE EXECUTION

### Sequential Mode
Standard feature development follows the 6-phase sequence exactly.

### Parallel Mode (Advanced)
For large features, multiple Builders can work in parallel under the same Architect constraints.

### Refactor Mode
Replaces Phase 2 (Builder) with Refactorer Agent for structural changes.

### Migration Mode  
Adds Migration Engine after Architect for multi-phase changes.

---

## 🛡️ SAFETY GUARDRAILS

### Mandatory Checkpoints
- Each phase must complete before next begins
- Handoff artifacts must be complete and valid
- Any failure returns to appropriate previous phase
- No phase can be skipped

### Abort Conditions
- Architecture violations detected
- Role boundaries crossed
- Safety filters triggered
- Human intervention requested

### Recovery Protocols
- Automatic retry (max 3 attempts per phase)
- Escalation to Architect for complex issues
- Human override for critical decisions

---

## 📊 PERFORMANCE METRICS

### Phase Success Rates
- Architect pass completion time
- Builder code quality scores
- Tester validation success rate
- Doc Manager sync accuracy
- Validator pass/fail ratio
- Merge success rate

### Pipeline Metrics
- End-to-end completion time
- Handoff failure frequency
- Rollback requirements
- Escalation incidents

---

**This orchestration protocol ensures deterministic, safe, and high-quality software development through strict phase sequencing and clear handoff procedures.**
