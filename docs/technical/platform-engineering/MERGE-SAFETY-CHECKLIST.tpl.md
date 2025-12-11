# MERGE-SAFETY-CHECKLIST.md - Pull Request Safety Validation

**Purpose**: Prevent "oops I broke production" moments for junior developers, senior engineers, and AI agents.  
**Design**: Comprehensive safety validation across 7 categories with final merge decision.  
**Integration**: Required validation step before any PR merge, integrates with all platform engineering components.

---

## 🛡️ Merge Safety Checklist — v1.0

**For ANY pull request, all items must be TRUE before merge.**

---

## 1. Structural Safety

- [ ] **Only intended modules/files were changed**  
  - Verify changes match PR description and scope
  - No accidental modifications to unrelated files

- [ ] **No unrelated files were touched**  
  - Check for unexpected file modifications
  - Ensure clean, focused change set

- [ ] **No unexpected deletions or renames**  
  - All deletions are intentional and documented
  - No surprise file removals or renames

- [ ] **Folder boundaries still match ARCHITECTURE.md**  
  - Module structure respects defined boundaries
  - No cross-boundary violations

- [ ] **No circular dependencies introduced**  
  - Dependency graph remains acyclic
  - No new import cycles between modules

- [ ] **No cross-module leakage (violations of FRAMEWORK-PATTERNS.md)**  
  - Framework patterns still followed
  - No inappropriate cross-module access

---

## 2. Behavioral Safety

- [ ] **All public interfaces preserve original behavior**  
  - API contracts unchanged unless explicitly documented
  - Function signatures and return types stable

- [ ] **No accidental API contract change**  
  - Public APIs maintain expected behavior
  - No breaking changes without proper migration

- [ ] **Error-handling not weakened**  
  - Error cases still properly handled
  - No removal of error guards or validation

- [ ] **Edge cases unchanged unless intentional**  
  - Boundary conditions preserved
  - No regression in edge case handling

- [ ] **Performance not degraded in critical paths**  
  - No performance regressions in hot paths
  - Memory usage patterns unchanged

---

## 3. Diff Quality

- [ ] **Patches are minimal and scoped**  
  - Changes are focused and atomic
  - No over-engineering or scope creep

- [ ] **No full-file rewrites without explicit reason**  
  - Prefer targeted diffs over complete rewrites
  - Full rewrites justified and documented

- [ ] **Diffs show clear intent (one type of change per block)**  
  - Each diff block has single, clear purpose
  - No mixed-purpose changes in same block

- [ ] **No formatting noise unless part of lint step**  
  - Formatting changes separated from logic changes
  - No unnecessary whitespace or style modifications

---

## 4. Tests

- [ ] **All tests pass**  
  - Full test suite green
  - No test failures or regressions

- [ ] **Tests updated for any intentional behavior changes**  
  - Test expectations updated for new behavior
  - No outdated test assertions

- [ ] **New tests added for new logic branches**  
  - Coverage for new code paths
  - Edge cases properly tested

- [ ] **Critical path tests explicitly rerun**  
  - High-risk areas manually verified
  - Integration tests for critical flows

- [ ] **Coverage unchanged or improved**  
  - Test coverage percentage maintained or increased
  - No coverage regressions

---

## 5. Documentation

- [ ] **ARCHITECTURE.md updated if structure changed**  
  - Module structure documented
  - Dependencies and boundaries updated

- [ ] **API-DOCUMENTATION.md updated for API changes**  
  - New endpoints documented
  - Changed APIs properly described

- [ ] **MIGRATION-GUIDE.md updated if refactor was part of migration**  
  - Migration steps documented
  - Phase progress tracked

- [ ] **ROADMAP updated if milestone completed**  
  - Completed milestones marked
  - Future planning adjusted

- [ ] **TODO updated if tasks completed**  
  - Completed tasks removed or marked done
  - New tasks added for follow-up work

---

## 6. Validation

- [ ] **Validation Protocol v2 passed**  
  - Documentation-code parity verified
  - All validation checks green

- [ ] **Diff Validator passed (no FAIL-level issues)**  
  - All critical issues resolved
  - Only WARN-level issues (if any) addressed

- [ ] **Refactor Safety Dashboard updated if relevant**  
  - Dashboard reflects current state
  - All sections properly populated

---

## 7. Human Review (Optional but recommended)

- [ ] **Reviewed by maintainer or architect**  
  - Expert review completed
  - Architecture compliance verified

- [ ] **Comments addressed**  
  - All review feedback resolved
  - No outstanding concerns

---

## 🎯 Final Merge Decision

- [ ] **SAFE TO MERGE**  
  - All checkboxes checked
  - No blocking issues identified

- [ ] **WAIT (needs fixes)**  
  - Some items require attention
  - Address issues before merge

- [ ] **REJECT (violates architecture or safety)**  
  - Critical violations found
  - Must be reworked completely

---

## 🔧 Integration with Agentic Platform Engineering System

### Component Integration

| Component | Checklist Section | Role |
|-----------|-------------------|------|
| **docs/platform-engineering/REFACTOR-SIMULATION-ENGINE.md** | 1, 2 | Pre-flight structural and behavioral analysis |
| **docs/platform-engineering/MIGRATION-ENGINE.md** | 1, 5 | Architecture changes and documentation updates |
| **docs/platform-engineering/CODE-DIFF-REASONER.md** | 3 | Diff quality and minimal change generation |
| **docs/platform-engineering/DIFF-VALIDATOR.md** | 1-4, 6 | Comprehensive validation and safety checks |
| **docs/platform-engineering/VALIDATION-PROTOCOL-v2.md** | 5, 6 | Documentation sync and validation |
| **REFACTOR-SAFETY-DASHBOARD.md** | 6 | Dashboard state verification |
| **tier-index.yaml** | 1 | Tier-based structural requirements |

### Automated Integration

```bash
# Pre-merge validation workflow
1. Run docs/platform-engineering/DIFF-VALIDATOR.md on all patches
2. Run docs/platform-engineering/VALIDATION-PROTOCOL-v2.md for documentation sync
3. Verify REFACTOR-SAFETY-DASHBOARD.md status
4. Execute automated test suite
5. Generate docs/platform-engineering/MERGE-SAFETY-CHECKLIST.md report
6. Block merge if any critical items fail
```

### CI/CD Pipeline Integration

```yaml
# GitHub Actions example
name: Merge Safety Check
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  safety-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Diff Validator
        run: python3 scripts/diff_validator.py --strict
      - name: Run Validation Protocol
        run: python3 scripts/validation_protocol_v2.py
      - name: Generate Safety Checklist
        run: python3 scripts/merge_safety_checklist.py
      - name: Block unsafe merges
        run: |
          if [[ "$(cat safety_checklist.json | jq -r '.decision')" != "SAFE_TO_MERGE" ]]; then
            echo "❌ Merge blocked by safety checklist"
            exit 1
          fi
```

---

## 📋 Usage Examples

### Simple Feature Addition:
```
✅ Structural Safety: Only feature module changed
✅ Behavioral Safety: New function, no API changes
✅ Diff Quality: Clean, focused changes
✅ Tests: New tests added, coverage improved
✅ Documentation: API docs updated
✅ Validation: All checks pass
✅ Human Review: Reviewed and approved

Decision: SAFE TO MERGE
```

### Architecture Refactor:
```
❌ Structural Safety: Cross-module dependency introduced
⚠️ Behavioral Safety: API contract changed (documented)
✅ Diff Quality: Minimal patches, clear intent
✅ Tests: Updated for new behavior
✅ Documentation: Architecture docs updated
✅ Validation: Diff validator shows WARN issues
✅ Human Review: Architect review pending

Decision: WAIT (needs fixes)
```

---

## 🛠️ Implementation Notes

### Checklist Automation
- Parse git diff for structural changes
- Run static analysis for dependency detection
- Execute test suite and capture coverage
- Validate documentation updates
- Generate checklist report automatically

### Risk Assessment
- **LOW**: Simple feature additions, clear scope
- **MEDIUM**: Module refactors, some API changes
- **HIGH**: Architecture changes, breaking changes
- **CRITICAL**: Core system modifications, security changes

### Enforcement Levels
- **Advisory**: Warn about violations but allow merge
- **Blocking**: Prevent merge until issues resolved
- **Critical**: Require multiple approvals for high-risk changes

---

**This checklist serves as the final safety net that ensures no harmful changes reach production, whether authored by humans or AI agents.**
