# DIFF-VALIDATOR.md - Critical Patch Inspection Module

**Purpose**: Evaluate generated diffs for correctness, safety, scope, and architectural alignment.  
**Design**: Paranoid senior engineer review, multi-dimensional validation, auto-fix suggestions.  
**Integration**: Runs after Code Diff Reasoner and Migration Engine to ensure patch safety.

---

## 🧠 Core Idea

**Diff Validator = "Given this diff, is it syntactically valid, scoped correctly, architecturally legal, and behaviorally sane?"**

It acts like a paranoid senior engineer who doesn't trust the junior's PR.

---

## ✅ DIFF VALIDATOR v1.0 — SPEC

```
DIFF VALIDATOR — v1.0
---------------------

Purpose:
Evaluate generated diffs for correctness, safety, scope, and architectural alignment.

Inputs:
- Proposed diffs (unified diff format)
- Original files
- ARCHITECTURE.md
- FRAMEWORK-PATTERNS.md
- TESTING docs
- (Optional) build/test feedback logs

Outputs:
- PASS / WARN / FAIL decision
- A list of issues
- Optional auto-fix suggestions
```

---

## 🔍 Validation Dimensions

### Syntax Validity
Does the patch produce syntactically valid code?
Are brackets, parentheses, and imports coherent?

### Scope Check
Does the diff only touch relevant regions?
Are unrelated parts of the file changed randomly?
Did indentation or formatting explode unnecessarily?

### Architectural Safety
Does the patch violate known boundaries?
Does it create new cross-module dependencies?
Does it break patterns in FRAMEWORK-PATTERNS.md?

### Behavior Safety
Are public interfaces altered unintentionally?
Are error cases or guards removed?
Are return types or invariants weakened?

### Testing Alignment
Are existing tests updated when behavior changes?
Are new tests added for new branches or features?
Are previously tested cases still covered?

### Documentation Alignment
If architecture or API changed, did the diff include doc updates?
Is MIGRATION-GUIDE updated when migrations implied?

---

## 🔁 Validation Loop (LLM Reasoning)

### STEP 1 — PARSE DIFFS
- For each file in the patch:
  • load original content
  • apply the diff mentally
  • reason about the resulting file

### STEP 2 — SYNTAX CHECK (STATIC)
- For each resulting file:
  • verify structural correctness (blocks, imports, declarations)
  • flag anything clearly invalid or incomplete.

### STEP 3 — SCOPE CHECK
- Confirm that:
  • changes are localized to relevant regions
  • no random renames or format noise
  • no surprise deletion blocks

### STEP 4 — ARCHITECTURE CHECK
- Compare imports, module boundaries, and folder placements
  with ARCHITECTURE.md and FRAMEWORK-PATTERNS.md.
- Flag:
  • new cross-module imports
  • direct access to forbidden modules
  • bypassing defined interfaces.

### STEP 5 — BEHAVIOR CHECK
- For each changed function:
  • summarize before behavior → after behavior
  • verify invariants are preserved (unless intentionally altered)
  • confirm inputs/outputs still align with their callers.

### STEP 6 — TESTS CHECK
- If behavior changed:
  • verify tests were updated/added.
  • if not, flag as REQUIRED_FIX.

### STEP 7 — DOCS CHECK
- If structure/API changed:
  • check for relevant doc updates in:
     - ARCHITECTURE.md
     - API-DOCUMENTATION.md
     - MIGRATION-GUIDE.md

### STEP 8 — DECISION
- If any CRITICAL issue:
  → FAIL (must regenerate or fix)
- If only WARN-level issues:
  → WARN, with explicit fix suggestions
- Else:
  → PASS

### STEP 9 — OPTIONAL AUTO-FIX
- For minor issues:
  • propose diff patches to fix style, imports, missing tests/docs.

---

## ✅ Example Diff Validator Output (Shape)

```markdown
Validation Result: WARN

Issues:
- [ARCH] New dependency from module `payments` to `auth` added indirectly.
- [TEST] New error path in `createInvoice` not tested.
- [DOC] API-DOCUMENTATION.md not updated for new error code.

Required Fixes:
- Add interface in `auth_public_api` instead of importing internal module.
- Add unit test for failing invoice creation due to auth failure.
- Update API-DOCUMENTATION.md with new error response.

Suggested Next Step:
- Regenerate patch for imports and public API layer.
- Append new test case to tests/invoice/create_invoice_test.ext
- Update API doc section "POST /invoice".
```

---

## 🔧 Integration with Documentation OS

### Dependencies:
- **ARCHITECTURE.md** - System boundaries and constraints
- **FRAMEWORK-PATTERNS.md** - Framework-specific patterns
- **TESTING.md** - Testing requirements and coverage
- **API-DOCUMENTATION.md** - Public interface specifications
- **docs/platform-engineering/CODE-DIFF-REASONER.md** - Receives diffs for validation
- **docs/platform-engineering/MIGRATION-ENGINE.md** - Validates migration phase diffs

### Integration Points:
| Component | Role in Validation |
|-----------|-------------------|
| tier-index.yaml | Determines validation strictness level |
| docs/platform-engineering/REFACTOR-SIMULATION-ENGINE.md | Provides invariants for validation |
| docs/platform-engineering/VALIDATION-PROTOCOL-v2.md | Final consistency check after validation |

### Agent Workflow Integration:
```bash
# Validation workflow
1. Receive diffs from docs/platform-engineering/CODE-DIFF-REASONER.md or docs/platform-engineering/MIGRATION-ENGINE.md
2. Load architecture and framework constraints
3. Run DIFF-VALIDATOR 9-step loop
4. Generate validation report with PASS/WARN/FAIL
5. If WARN/FAIL, provide specific fix suggestions
6. If PASS, proceed to docs/platform-engineering/VALIDATION-PROTOCOL-v2.md
7. Apply diffs and run final validation
```

---

## 📋 Validation Report Format

### Standard Validation Structure:
```markdown
## Diff Validation Report

**Validation Result**: [PASS/WARN/FAIL]
**Files Changed**: [Number]
**Risk Level**: [Low/Medium/High]

### Issues Found
#### Critical Issues
- [SYNTAX] Invalid syntax in file.ext at line X
- [ARCH] Violates architectural boundary
- [BEHAVIOR] Breaks public interface contract

#### Warning Issues
- [SCOPE] Changes unrelated code regions
- [TEST] Missing test coverage for new behavior
- [DOC] Documentation not updated

### Required Actions
1. [Fix syntax error in file.ext]
2. [Add missing test case]
3. [Update API documentation]

### Suggested Auto-Fixes
```diff
--- src/components/Button.jsx
+++ src/components/Button.jsx
@@ -15,7 +15,7 @@
 export function Button({ label, onClick }) {
-  return <button onclick={onClick}>{label}</button>;
+  return <button onClick={onClick}>{label}</button>;
 }
```

### Validation Checklist
- [x] Syntax is valid
- [x] Scope is appropriate
- [x] Architecture is respected
- [x] Behavior is preserved
- [ ] Tests are updated
- [ ] Documentation is synced
```

---

## 🎯 Validation Examples

### Simple Refactor Validation:
```
Input: Extract function from component

Validation Result: PASS
Issues: None
Notes: Clean extraction with proper imports, no scope issues
```

### Architecture Violation:
```
Input: Direct import from internal module

Validation Result: FAIL
Issues: 
- [ARCH] Direct access to internal 'database' module from UI layer
- [BEHAVIOR] Bypasses defined repository interface

Required Fix: Use public repository interface instead
```

### Missing Test Coverage:
```
Input: Add new error handling path

Validation Result: WARN
Issues:
- [TEST] New error path not covered by tests
- [DOC] Error response not documented

Required Fixes:
1. Add test case for error scenario
2. Update API documentation
```

---

## 🛡️ Safety Rules

### Critical Failures (Must Fix):
- Syntax errors or invalid code
- Architectural boundary violations
- Public interface contract breaks
- Security model violations
- Performance regression risks

### Warning Issues (Should Fix):
- Scope creep beyond intended changes
- Missing test coverage for new behavior
- Documentation not updated
- Style or formatting inconsistencies
- Unused imports or dead code

### Auto-Fix Eligibility:
- Simple syntax errors
- Import statement corrections
- Formatting issues
- Missing documentation stubs
- Test template generation

---

## 🔧 Validation Rules Engine

### Rule Categories:
```yaml
syntax_rules:
  - check_bracket_balance
  - validate_imports
  - verify_declarations

architecture_rules:
  - enforce_layer_boundaries
  - check_dependency_directions
  - validate_module_access

behavior_rules:
  - preserve_public_interfaces
  - maintain_error_handling
  - verify_return_types

testing_rules:
  - require_coverage_for_new_paths
  - validate_test_updates
  - check_test_assertions

documentation_rules:
  - require_api_doc_updates
  - check_architecture_docs
  - validate_migration_guides
```

---

## 🔄 Integration with Development Workflow

### Pre-Commit Validation:
```bash
# Git hook integration
git diff --cached | python3 diff_validator.py --pre-commit
if [ $? -ne 0 ]; then
  echo "Validation failed - fix issues before committing"
  exit 1
fi
```

### CI/CD Integration:
```bash
# Pipeline validation
python3 diff_validator.py --diffs PR.diff --strict
if [ $? -eq 0 ]; then
  echo "✅ All diffs passed validation"
else
  echo "❌ Validation failed - blocking merge"
  exit 1
fi
```

---

**This module acts as the critical safety net that prevents dangerous patches from reaching production, ensuring that every generated diff is syntactically valid, architecturally sound, behaviorally safe, and properly documented and tested.**
