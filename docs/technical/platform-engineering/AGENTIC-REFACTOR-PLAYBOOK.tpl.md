# AGENTIC-REFACTOR-PLAYBOOK.md - Standard Operating Procedure for AI Agents

**Purpose**: Ensure every agent behaves like a disciplined senior engineer during refactoring operations.  
**Design**: 8-step mandatory procedure with clear checkpoints and integration points.  
**Integration**: Required workflow for any AI agent performing code modifications.

---

## 🤖 Agentic Refactor Playbook — v1.0

**This is now the standard operating procedure for any agent performing modifications.**

---

## Step 1 — Intent Extraction

**Clarify exactly what is being changed, why, and what must remain unchanged.**

### Required Analysis:
- **What**: Precise description of the refactor goal
- **Why**: Business or technical justification
- **Scope**: Local, Module, Architecture, or Migration level
- **Invariants**: Behaviors that MUST NOT change
- **Success Criteria**: How to verify the refactor succeeded

### Output Format:
```markdown
## Refactor Intent
**Goal**: [Clear, concise statement]
**Justification**: [Business/technical reason]
**Scope**: [Local/Module/Architecture/Migration]
**Invariants**: 
- [Behavior 1 that must not change]
- [Behavior 2 that must not change]
**Success Criteria**: 
- [Criteria 1]
- [Criteria 2]
```

### Integration Points:
- Load from `REFACTOR-SAFETY-DASHBOARD.md` if active refactor exists
- Reference `tier-index.yaml` for scope limitations
- Consult `ARCHITECTURE.md` for boundary definitions

---

## Step 2 — Context Gathering

**Load only relevant files and architectural constraints.**

### Required Context:
- **Target Files**: Only files directly involved in refactor
- **ARCHITECTURE.md**: System boundaries and constraints
- **FRAMEWORK-PATTERNS.md**: Framework-specific rules
- **TESTING.md**: Current test strategy and coverage
- **API-DOCUMENTATION.md**: Public interface contracts
- **MIGRATION-GUIDE.md**: If part of larger migration

### Context Loading Rules:
```bash
# Load context based on refactor scope
if [ "$SCOPE" == "Local" ]; then
    load target_module + immediate dependencies
elif [ "$SCOPE" == "Module" ]; then
    load module + all dependencies + ARCHITECTURE.md
elif [ "$SCOPE" == "Architecture" ]; then
    load ARCHITECTURE.md + FRAMEWORK-PATTERNS.md + all modules
elif [ "$SCOPE" == "Migration" ]; then
    load MIGRATION-GUIDE.md + ARCHITECTURE.md + all affected modules
fi
```

### Public Interface Identification:
- List all public APIs in target scope
- Identify all external dependencies
- Map all call chains that will be affected

---

## Step 3 — Simulation Pass (Refactor Simulation Engine)

**Simulate the resulting system before making changes.**

### Simulation Requirements:
- **Control Flow**: How execution paths will change
- **Data Flow**: How data moves through the system
- **Error Behavior**: How errors are handled and propagated
- **Module Boundaries**: How boundaries are affected

### Integration with docs/platform-engineering/REFACTOR-SIMULATION-ENGINE.md:
```bash
# Run simulation engine with extracted context
python3 scripts/simulation_engine.py \
  --intent "$(cat intent.md)" \
  --context "$(cat context.md)" \
  --architecture ARCHITECTURE.md \
  --framework FRAMEWORK-PATTERNS.md \
  --output simulation_report.md
```

### Expected Simulation Output:
- Change impact analysis
- Risk assessment
- Invariants confirmation
- No-go zones identification
- Scoped change recommendations

---

## Step 4 — Impact Assessment

**Identify all affected components and potential breakage points.**

### Impact Categories:
- **Affected Modules**: List all modules that will change
- **Affected Tests**: Tests that need updating or addition
- **Risky Dependencies**: High-risk external dependencies
- **Potential Breakage Points**: Areas most likely to fail
- **Required Documentation Updates**: Docs that need changes

### Risk Scoring:
```
Risk Level: LOW/MEDIUM/HIGH/CRITICAL
Factors:
- Number of modules affected
- Public interface changes
- Critical path involvement
- Test coverage gaps
- Documentation complexity
```

### Impact Report Format:
```markdown
## Impact Assessment
**Risk Level**: [Calculated risk]
**Modules Affected**: [List with risk scores]
**Tests Impact**: [Required test changes]
**Breakage Points**: [High-risk areas]
**Documentation Updates**: [Required doc changes]
**Recommended Approach**: [Execution strategy]
```

---

## Step 5 — Refactor Plan

**Break the refactor into atomic, reversible steps.**

### Planning Principles:
- **Atomic Steps**: Each step does one thing completely
- **Reversible**: Every step can be safely rolled back
- **Testable**: Each step can be verified independently
- **Documented**: Clear purpose and expected outcome

### Step Template:
```markdown
### Step N: [Step Title]
**Purpose**: [What this step accomplishes]
**Files**: [List of files to modify]
**Expected Outcome**: [What should be true after this step]
**Verification**: [How to verify success]
**Rollback**: [How to revert if needed]
**Dependencies**: [Prerequisites for this step]
```

### Example Refactor Plan:
```markdown
## Refactor Plan: Extract Validation Logic

### Step 1: Create validator module
**Purpose**: Introduce new validation structure
**Files**: 
- src/validation/user_validator.dart (new)
- src/validation/validation_rules.dart (new)
**Expected Outcome**: Validation structure exists, no behavior change
**Verification**: All existing tests pass
**Rollback**: Delete new files
**Dependencies**: None

### Step 2: Move validation logic
**Purpose**: Extract validation from user service
**Files**: 
- src/services/user_service.dart (modify)
- src/validation/user_validator.dart (extend)
**Expected Outcome**: Validation logic moved, behavior preserved
**Verification**: All tests pass, validation behavior identical
**Rollback**: Revert user_service.dart, remove validator additions
**Dependencies**: Step 1 complete

### Step 3: Update imports and tests
**Purpose**: Wire up new validation module
**Files**: 
- All files importing user_service.dart
- test/validation/ (new tests)
**Expected Outcome**: System uses new validation, fully tested
**Verification**: Full test suite passes, coverage maintained
**Rollback**: Revert imports, remove new tests
**Dependencies**: Step 2 complete
```

---

## Step 6 — Diff Generation (Code Diff Reasoner)

**Produce minimal unified diffs following architectural rules.**

### Diff Generation Rules:
- **Minimal Changes**: Smallest possible diffs to achieve goal
- **No Full Rewrites**: Prefer targeted patches over complete rewrites
- **Architectural Compliance**: Follow ARCHITECTURE.md and FRAMEWORK-PATTERNS.md
- **Behavior Preservation**: Maintain all identified invariants

### Integration with docs/platform-engineering/CODE-DIFF-REASONER.md:
```bash
# Generate diffs for each step
for step in refactor_plan_steps; do
  python3 scripts/diff_reasoner.py \
    --step "$step" \
    --invariants "$(cat invariants.md)" \
    --architecture ARCHITECTURE.md \
    --framework FRAMEWORK-PATTERNS.md \
    --output "patches/step_${step}_patch.diff"
done
```

### Diff Quality Requirements:
- Each diff addresses single concern
- Clear intent in each change block
- No formatting noise unless part of lint step
- Proper import management
- Consistent style and patterns

---

## Step 7 — Diff Validation (Diff Validator)

**Check all diffs for safety and correctness.**

### Validation Dimensions:
- **Syntax**: Generated code is syntactically valid
- **Scope**: Changes are limited to intended areas
- **Architecture**: No boundary violations or pattern breaks
- **Behavior**: Public interfaces preserved unless intentional
- **Testing**: Proper test coverage for changes
- **Documentation**: Documentation updated appropriately

### Integration with docs/platform-engineering/DIFF-VALIDATOR.md:
```bash
# Validate each generated diff
for patch in patches/*.diff; do
  python3 scripts/diff_validator.py \
    --patch "$patch" \
    --original_files src/ \
    --architecture ARCHITECTURE.md \
    --framework FRAMEWORK-PATTERNS.md \
    --testing TESTING.md \
    --output "validation/$(basename $patch .diff)_validation.json"
done
```

### Validation Outcomes:
- **PASS**: Diff is safe to apply
- **WARN**: Minor issues that should be fixed
- **FAIL**: Critical issues requiring diff regeneration

### Failure Handling:
```bash
if any_validation_failed; then
  echo "❌ Critical validation issues found"
  echo "Regenerating problematic diffs..."
  # Regenerate diffs with updated constraints
  # Re-run validation
  # Block proceed if still failing
fi
```

---

## Step 8 — Documentation Sync + Merge Prep

**Update all documentation and prepare for merge.**

### Documentation Updates:
- **ARCHITECTURE.md**: Update if structure changed
- **API-DOCUMENTATION.md**: Update for API changes
- **MIGRATION-GUIDE.md**: Record migration progress
- **ROADMAP.md**: Update milestone status
- **TODO.md**: Update task completion status
- **REFACTOR-SAFETY-DASHBOARD.md**: Update dashboard state

### Integration with docs/platform-engineering/VALIDATION-PROTOCOL-v2.md:
```bash
# Run final validation and sync
python3 scripts/validation_protocol_v2.py \
  --mode "sync" \
  --docs ARCHITECTURE.md API-DOCUMENTATION.md MIGRATION-GUIDE.md \
  --patches patches/ \
  --output validation_report.json
```

### Merge Safety Checklist:
- Run complete docs/platform-engineering/MERGE-SAFETY-CHECKLIST.md
- Verify all items pass
- Generate final merge decision
- Prepare PR description and documentation

---

## 🔧 Integration with Agentic Platform Engineering System

### Component Dependencies:
- **docs/platform-engineering/REFACTOR-SIMULATION-ENGINE.md**: Step 3 (Simulation)
- **docs/platform-engineering/CODE-DIFF-REASONER.md**: Step 6 (Diff Generation)
- **docs/platform-engineering/DIFF-VALIDATOR.md**: Step 7 (Validation)
- **docs/platform-engineering/VALIDATION-PROTOCOL-v2.md**: Step 8 (Documentation Sync)
- **docs/platform-engineering/MERGE-SAFETY-CHECKLIST.md**: Step 8 (Merge Preparation)
- **REFACTOR-SAFETY-DASHBOARD.md**: Throughout (Tracking)

### Workflow Orchestration:
```bash
#!/bin/bash
# Complete agentic refactor workflow
echo "🤖 Starting Agentic Refactor Playbook"

# Step 1: Intent Extraction
extract_intent "$1" > intent.md

# Step 2: Context Gathering
gather_context "$(cat intent.md)" > context.md

# Step 3: Simulation Pass
run_simulation_engine intent.md context.md > simulation_report.md

# Step 4: Impact Assessment
assess_impact simulation_report.md > impact_assessment.md

# Step 5: Refactor Plan
create_refactor_plan impact_assessment.md > refactor_plan.md

# Step 6: Diff Generation
generate_diffs refactor_plan.md

# Step 7: Diff Validation
validate_all_diffs

# Step 8: Documentation Sync + Merge Prep
sync_documentation
run_merge_safety_checklist

echo "✅ Refactor playbook completed successfully"
```

### Agent Contract Requirements:
- **Mandatory Compliance**: All 8 steps must be completed in order
- **Checkpoint Validation**: Cannot proceed to next step if current step fails
- **Documentation Required**: Every step must produce documented output
- **Rollback Capability**: Must maintain ability to rollback at any point
- **Human Oversight**: Critical steps require human verification

---

## 📋 Usage Examples

### Simple Local Refactor:
```
Step 1: Extract validation logic from user service
Step 2: Load user service module and dependencies
Step 3: Simulate behavior with extracted validation
Step 4: Assess impact on dependent modules
Step 5: Plan: Create validator → Move logic → Update imports
Step 6: Generate minimal diffs for each step
Step 7: Validate syntax, scope, and behavior preservation
Step 8: Update docs, run safety checklist, prepare PR
```

### Architecture Migration:
```
Step 1: Migrate from Redux to Zustand state management
Step 2: Load entire app architecture and state management docs
Step 3: Simulate state flow with new management system
Step 4: Assess impact on all components and tests
Step 5: Plan: Install Zustand → Create state slices → Migrate components → Remove Redux
Step 6: Generate phased migration diffs
Step 7: Validate each phase for safety and correctness
Step 8: Update architecture docs, run safety checklist, prepare PR
```

---

## 🛡️ Safety Constraints

### Forbidden Actions:
- Skip steps or change order without explicit justification
- Generate diffs without running simulation first
- Apply changes without validation approval
- Modify public interfaces without updating documentation
- Proceed with failed validation without addressing issues

### Required Safeguards:
- Maintain rollback capability throughout process
- Document all decisions and their rationale
- Verify test coverage before applying changes
- Update documentation before considering merge complete
- Run complete safety checklist before final approval

---

**This playbook ensures every AI agent performs refactoring with the discipline and safety of a senior engineer, preventing catastrophic changes while enabling efficient evolution of the codebase.**
