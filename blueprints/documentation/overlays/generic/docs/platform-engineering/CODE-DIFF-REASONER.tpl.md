# CODE-DIFF-REASONER.md - Universal Cognitive Module for Safe Refactoring

**Purpose**: Universal cognitive module for any AI agent to perform safe, large-scale refactoring.  
**Design**: Agent-agnostic, behavior-preserving, documentation-aligned, diff-first approach.  
**Integration**: Works with Documentation OS, Code Generation Templates, and Validation Protocol.

---

## 🧠 1. CORE PHILOSOPHY

Large-scale refactoring must follow three laws:

### Law 1 — Never Mutate Code Directly
Always propose diffs. Agents should not rewrite whole files. They should produce:
- Contextual diffs
- Patch blocks  
- Minimal changes

### Law 2 — Preserve Public Behavior
Internal structure may change; API must not (unless project owner approves).

### Law 3 — Align with Architecture + Documentation
All changes propagate bidirectionally:
- docs → code
- code → docs

---

## 🔁 2. MULTI-PASS REASONING LOOP

### CODE DIFF REASONER LOOP v1.0

**Step 1 — Intent Extraction**
- What is the exact change requested?
- Which files/modules are affected?
- What is the scope? (local, module-level, architecture-level)

**Step 2 — Context Gathering**
- Load relevant files (but do not rewrite them)
- Load ARCHITECTURE.md for constraints
- Load FRAMEWORK-PATTERNS.md for rules
- Load TESTING.md + TESTING-EXAMPLES.md
- Identify public interfaces and invariants

**Step 3 — Impact Analysis**
- Determine direct impacts (functions, files, tests)
- Determine indirect impacts (types, modules, contracts)
- Determine forbidden impacts (public API invariants)

**Step 4 — Refactor Plan**
- Summarize changes in plain language
- Break refactor into patches
- Map patches to files

**Step 5 — Generate Diffs (Patch Mode)**
- For each file:
  - produce minimal patch
  - preserve formatting/style
  - do not rewrite everything
  - ensure diff is logically consistent

**Step 6 — Behavioral Verification**
- Simulate expected behavior before/after change
- Detect accidental API changes
- Identify tests that need updates

**Step 7 — Documentation Sync**
- Update ARCHITECTURE.md if structure changed
- Update TODO / ROADMAP
- Update public contract docs

**Step 8 — Consolidation**
- Re-run analysis using updated files
- Confirm that all patches are consistent
- Output final diff set

---

## 🧩 3. DIFF GENERATION CONTRACT

### Agent-Safe Patch Format
Agents must output diffs in strict unified diff format:

```
--- path/to/file.ext
+++ path/to/file.ext
@@ context markers @@
- old line
+ new line
```

### Rules:
- Only modify specific lines
- Never rewrite entire files (unless explicitly required)
- Always include at least 3 lines of context
- Preserve indentation and style
- Do not include commentary inside the diff
- After every diff block, include verification note outside the diff

### Example Output:
```
--- lib/state/user_manager.dart
+++ lib/state/user_manager.dart
@@ -42,7 +42,7 @@
   Future<User?> loadUser() async {
-    final raw = await storage.read("user");
+    final raw = await storage.readSecure("user");
     if (raw == null) return null;
     return User.fromJson(raw);
   }

Verification: Changed storage method to secure variant, preserving return type.
```

---

## 🛡️ 4. SAFETY CONSTRAINTS

These rules prevent catastrophic refactors:

- Never remove error handling unless requested
- Never weaken type constraints
- Never rename public methods automatically
- Never introduce new dependencies without approval
- Never break existing tests unless part of explicit migration
- Never create new architecture patterns (must follow FRAMEWORK-PATTERNS.md)
- Never refactor multiple concerns in one pass

---

## 📚 5. DOCUMENTATION SYNC PASS

Every refactor must sync with repo docs. Agents must update:

- ARCHITECTURE.md (if structure changed)
- API-DOCUMENTATION.md (if interfaces changed)
- TODO.md (if tasks completed or new ones created)
- PROJECT-ROADMAP.md (if phase progressed)
- MIGRATION-GUIDE.md (if breaking changes introduced)
- TESTING.md (if test layers affected)

### Doc Sync Loop:
1. Identify all files affected by code diffs
2. Check which docs refer to those files or modules
3. For every inconsistency:
   - propose a doc update diff (same patch format)
4. Re-validate doc-code parity

**Agents must treat documentation as first-class code.**

---

## 🧠 6. FULL CODE DIFF REASONER v1.0 (AGENT MODULE)

```
===========================================
CODE DIFF REASONER — MODULE v1.0
===========================================

Purpose:
Perform safe, large-scale refactors using minimal diffs,
architectural reasoning, and documentation sync.

-------------------------------------------
OPERATING RULES
-------------------------------------------
1. Never rewrite entire files.
2. Always produce unified diffs.
3. Preserve public interface behavior.
4. Follow architectural constraints.
5. Follow framework patterns.
6. Update documentation when structure changes.
7. Validate consistency after applying patches.

-------------------------------------------
REASONING PROCESS
-------------------------------------------
1. INTENT EXTRACTION
   - Clarify the requested change.
   - Determine refactor scope: local, module-level, project-wide.

2. CONTEXT GATHERING
   - Load only relevant files.
   - Load ARCHITECTURE.md, FRAMEWORK-PATTERNS.md, TESTING docs.

3. IMPACT ANALYSIS
   - Identify affected modules.
   - Identify public API boundaries.
   - Predict required test updates.

4. PLAN GENERATION
   - Produce plain-language refactor plan.
   - Break into file-level patches.

5. DIFF GENERATION
   - Generate changes as unified diffs.
   - Minimal and context-rich.
   - Never modify unrelated lines.

6. VERIFICATION
   - Ensure refactor preserves intended behavior.
   - Ensure tests remain logically consistent.

7. DOCUMENTATION SYNC
   - Update architecture, API docs, roadmap, migration guides if needed.

8. FINAL CONSOLIDATION
   - Re-check all diffs for cohesion.
   - Produce final patch set.

-------------------------------------------
OUTPUT FORMAT
-------------------------------------------
- Sequential list of diffs (unified diff format)
- Summary of refactor plan
- Documentation diffs if necessary
- Verification checklist

===========================================
END OF MODULE
===========================================
```

---

## 🧩 7. OPTIONAL ENHANCEMENTS

### Semantic Diff Mode
Agents reason about behavior change rather than file change.

### Migration Planning Mode
Full system for architecture migrations with automated test regeneration.

### Refactor Simulation Mode
Agent simulates runtime flow before generating diffs.

### Constraints Mode
Attach constraints like:
- "no new dependencies"
- "keep everything public API compatible"  
- "use only functional patterns"

---

## 🔧 INTEGRATION WITH DOCUMENTATION OS

### Dependencies:
- **ARCHITECTURE.md** - Structural constraints and boundaries
- **FRAMEWORK-PATTERNS.md** - Framework-specific refactoring rules
- **docs/platform-engineering/VALIDATION-PROTOCOL-v2.md** - Post-refactor consistency validation
- **docs/platform-engineering/CODE-GENERATION-TEMPLATES.md** - Tier-specific code structure rules

### Cross-Reference Integration:
| Component | Role in Refactoring |
|-----------|-------------------|
| tier-index.yaml | Tier constraints for refactoring scope |
| docs/TIER-SELECTION.md | Determines refactoring complexity allowed |
| VALIDATION.md | Validates refactor doesn't break tier compliance |
| BLUEPRINT-MAPPING.md | Ensures refactors align with blueprint |

### Agent Workflow Integration:
```bash
# Typical refactoring workflow
1. Detect refactor request and scope
2. Load appropriate tier and architecture constraints
3. Run CODE-DIFF-REASONER 8-step loop
4. Generate unified diffs for code changes
5. Generate documentation sync diffs
6. Run docs/platform-engineering/VALIDATION-PROTOCOL-v2.md for consistency
7. Apply diffs if validation passes
8. Update all documentation to maintain parity
```

---

## 📋 REFACTORING CHECKLISTS

### Pre-Refactor Checklist:
- [ ] Intent clearly defined and scoped
- [ ] Architecture constraints loaded
- [ ] Framework patterns identified
- [ ] Public API boundaries mapped
- [ ] Test impact analysis completed

### Post-Refactor Checklist:
- [ ] All diffs in unified format with context
- [ ] Public behavior preserved (unless explicitly changed)
- [ ] Documentation sync diffs generated
- [ ] docs/platform-engineering/VALIDATION-PROTOCOL-v2.md passed
- [ ] Test coverage maintained
- [ ] Architecture compliance verified

---

**This module transforms any coding agent into a surgical refactoring tool that can safely operate at architectural scale while maintaining perfect documentation and behavior consistency.**
