# CODE-GENERATION-TEMPLATES.md - Tiered Code Generation Reasoning Contracts

**Purpose**: Universal reasoning contracts for code output that work with any coding agent.  
**Design**: Stack-agnostic, architecture-agnostic, LLM-native, multi-agent compatible.  
**Integration**: Works seamlessly with Documentation OS and Testing OS.  

---

## 🎯 AGENT USAGE OVERVIEW

### How Agents Use These Templates
When generating code, agents follow tier-specific behavior patterns:

**MVP Agent Behavior**:
- Minimal files
- Minimal abstractions  
- No architecture complexity
- Fast, cheap, functional

**Core Agent Behavior**:
- Structured project
- Test coverage
- Documentation alignment
- Scalable patterns

**Full Agent Behavior**:
- Enterprise architecture
- Strict layering
- Full test matrix
- Documentation parity
- Migration-aware coding

### Cross-Reference Integration
- **MVP Code** → MVP Documentation templates (TIERED-TEMPLATES.md)
- **Core Code** → Core Documentation templates  
- **Full Code** → Full Documentation templates
- **Testing Rules** → tier-index.yaml coverage targets
- **Validation** → docs/platform-engineering/VALIDATION-PROTOCOL-v2.md ensures code-doc parity

---

## 🟩 MVP CODE GENERATION TEMPLATE

### Goal: Working Prototype Quickly
**Philosophy**: "Speed, clarity, and small surface area."

### 1. Code Structure (MVP)
```markdown
# MVP Code Structure Template

1. Create a minimal folder structure:
   - src/ (or lib/, app/, etc.)
   - core logic in single-purpose modules
   - UI/screens/views in simple flat structure
   - no premature layering

2. Do NOT introduce:
   - unnecessary abstractions
   - complex state management
   - custom architecture patterns
   - dependency injection frameworks

3. Keep functions small and explicit.
4. Prefer inline logic over indirection.
5. Use defaults and simple patterns provided by the framework.
```

### 2. Code Generation Rules (MVP)
- Write the simplest code that works.
- Avoid abstract interfaces and over-generalization.
- Prioritize readability over extensibility.
- Avoid optimizing performance.
- No advanced error messages; basic try/catch is enough.
- Generate only what is needed for functional prototype.

### 3. Testing Rules (MVP)
- Only generate smoke tests.
- One test per core feature.
- Do NOT write full unit or integration suites.
- Tests are allowed to be shallow.

### 4. Example MVP Reasoning Pattern
```markdown
Goal: Implement Feature X in MVP tier.

1. What is the smallest version of Feature X that works?
2. What is the simplest file structure?
3. What is the minimal API shape?
4. Implement directly in one or two files.
5. Add one smoke test.
6. Stop. Do not expand the scope.
```

---

## 🟦 CORE CODE GENERATION TEMPLATE

### Goal: Maintainable, Scalable, Well-Structured Code
**Philosophy**: "Structure without overengineering."

### 1. Code Structure (Core)
```markdown
# Core Code Structure Template

1. Enforce architectural boundaries:
   - Separate UI / State / Domain / Data layers.
   - Keep files and modules small.
   - Consistent naming conventions.

2. Build a predictable folder structure:
   - src/
      ui/
      state/
      domain/
      data/
      shared/
      utils/

3. Use patterns defined in FRAMEWORK-PATTERNS.md:
   - navigation
   - data access
   - state management
   - dependency rules
```

### 2. Code Generation Rules (Core)
- Implement code that balances readability and extensibility.
- Introduce abstractions only where needed.
- Follow a test-first or test-parallel approach.
- Ensure all public interfaces are documented.
- Maintain consistency with ARCHITECTURE.md.
- Use dependency injection or factory patterns if the framework recommends it.
- Avoid premature optimization but enforce clean contracts.

### 3. Testing Rules (Core)
- Write unit tests for all business logic.
- Write integration tests where modules interact.
- UI tests for all screens/routes.
- Follow TESTING-EXAMPLES.md for the specific framework.
- Enforce error handling and edge-case testing.

### 4. Example Core Reasoning Pattern
```markdown
Goal: Implement Feature Y in Core tier.

1. Identify affected layers.
2. Update architecture if a new module is needed.
3. Create/update domain models.
4. Implement data layer logic.
5. Implement state layer.
6. Implement UI and interaction.
7. Write unit + integration + UI tests.
8. Update documentation:
   - TODO
   - ROADMAP
   - API-DOCUMENTATION
   - ARCHITECTURE
9. Ensure code reflects the project patterns.
```

---

## 🟧 FULL CODE GENERATION TEMPLATE

### Goal: Enterprise-Level Clarity and Long-Term Maintainability
**Philosophy**: "Explicit, documented, modular, test-driven."

### 1. Code Structure (Full)
```markdown
# Full Code Structure Template

1. Enforce strict architecture rules:
   - Modular boundaries must be explicit.
   - Public API layers vs internal modules clearly separated.

2. Full folder structure:
   src/
     modules/
        featureA/
           ui/
           state/
           domain/
           data/
           tests/
        featureB/
     shared/
     infrastructure/
     analytics/
     configuration/
     scripts/
```

### 2. Code Generation Rules (Full)
- Every module must have:
  • Domain models
  • Interfaces
  • Error handling strategy
  • Full test suite
  • Documentation references

- Follow strict dependency rules:
  - No cross-module leakage.
  - Internal modules are private by default.

- Implement resilient error handling and logging.
- Ensure code supports future migrations.
- Add analytics events.
- Enable feature flags if appropriate.
- Validate all inputs.
- Ensure code is traceable across layers.
- Prioritize long-term stability over speed.

### 3. Testing Rules (Full)
- Full test matrix:
  • Unit tests
  • Integration tests
  • UI tests
  • E2E tests
  • Regression tests
  • Snapshot tests (if UI-heavy)

- Enforce high coverage for critical logic.
- Tests must reflect real production flows.
- CI rules: no merges without test success.

### 4. Example Full Reasoning Pattern
```markdown
Goal: Implement Feature Z in Full tier.

1. Check if architecture changes are needed.
2. Update DATA-MODEL.md if new entities needed.
3. Create or update modules.
4. Ensure proper layering and file placement.
5. Implement domain logic with clear contracts.
6. Implement data access with error resilience.
7. Implement state management with immutability guarantees.
8. Implement UI following framework patterns.
9. Write:
   - unit tests
   - integration tests
   - UI tests
   - E2E tests
   - analytics tests

10. Update all documentation:
    • ARCHITECTURE.md
    • API-DOCUMENTATION.md
    • ROADMAP
    • MIGRATION-GUIDE.md (if needed)
    • ANALYTICS.md
    • TESTING.md

11. Run Validation Protocol v2.
12. Refactor for clarity and future safety.
13. Run Validation again.
```

---

## 🔧 INTEGRATION WITH DOCUMENTATION OS

### Tier Alignment
| Code Generation Tier | Documentation Tier | Testing Coverage | File Structure |
|----------------------|-------------------|------------------|----------------|
| MVP | MVP | 0-20% (smoke tests) | Minimal (4-7 files) |
| Core | Core | 85%+ (unit/integration/UI) | Structured (15-25 files) |
| Full | Full | 95%+ (full matrix) | Enterprise (22+ files) |

### Validation Integration
- **Code-Documentation Parity**: docs/platform-engineering/VALIDATION-PROTOCOL-v2.md ensures generated code matches documentation tier
- **Test Coverage Validation**: tier-index.yaml coverage targets enforced
- **Architecture Compliance**: FRAMEWORK-PATTERNS.md rules validated
- **File Structure Consistency**: TIERED-TEMPLATES.md structure enforced

### Agent Workflow Integration
```bash
# Typical agent workflow using these templates
1. Detect tier using docs/TIER-SELECTION.md
2. Load appropriate code generation template
3. Generate code following tier-specific rules
4. Create tests according to tier requirements
5. Update documentation to match code changes
6. Run docs/platform-engineering/VALIDATION-PROTOCOL-v2.md for compliance
7. Auto-repair any inconsistencies found
```

---

## 📋 TIER-SPECIFIC CHECKLISTS

### MVP Generation Checklist
- [ ] Minimal folder structure (src/, simple UI)
- [ ] No unnecessary abstractions
- [ ] Framework defaults used
- [ ] Functions small and explicit
- [ ] Basic error handling only
- [ ] One smoke test per feature
- [ ] Documentation matches MVP tier

### Core Generation Checklist
- [ ] Clear layer separation (UI/State/Domain/Data)
- [ ] Consistent naming conventions
- [ ] Framework patterns followed
- [ ] Public interfaces documented
- [ ] Unit tests for business logic
- [ ] Integration tests for module interactions
- [ ] UI tests for all screens
- [ ] Documentation updated (TODO, ROADMAP, API, ARCHITECTURE)

### Full Generation Checklist
- [ ] Strict modular boundaries
- [ ] Explicit public/private APIs
- [ ] Complete error handling and logging
- [ ] Analytics events added
- [ ] Feature flags where appropriate
- [ ] Full test matrix (unit/integration/UI/E2E/regression)
- [ ] High coverage for critical logic
- [ ] All documentation updated
- [ ] Migration guides created if needed
- [ ] Validation Protocol v2 passed

---

## 🚀 USAGE EXAMPLES

### Agent Integration Pattern
```python
def generate_code_for_tier(blueprint, tier, framework):
    """Universal code generation using tier templates."""
    
    # Load appropriate template
    if tier == "mvp":
        template = load_mvp_code_template()
    elif tier == "core":
        template = load_core_code_template()
    elif tier == "full":
        template = load_full_code_template()
    
    # Apply framework-specific patterns
    patterns = load_framework_patterns(framework)
    
    # Generate code following tier rules
    code_structure = apply_template(template, blueprint, patterns)
    
    # Generate tests according to tier
    tests = generate_tests(code_structure, tier, framework)
    
    # Update documentation
    update_documentation(code_structure, tier)
    
    # Validate compliance
    validation_result = run_validation_protocol(tier)
    
    return {
        "code": code_structure,
        "tests": tests,
        "validation": validation_result
    }
```

### CLI Integration Example
```bash
#!/bin/bash
# code-generation-agent.sh

TIER=$(python3 -c "from tier_selection import select_tier; print(select_tier('$BLUEPRINT'))")

echo "[AI] Generating code for $TIER tier..."

case "$TIER" in
    "mvp")
        python3 generate_mvp_code.py --blueprint "$BLUEPRINT"
        ;;
    "core")
        python3 generate_core_code.py --blueprint "$BLUEPRINT" --framework "$FRAMEWORK"
        ;;
    "full")
        python3 generate_full_code.py --blueprint "$BLUEPRINT" --framework "$FRAMEWORK"
        ;;
esac

# Run validation to ensure compliance
python3 scripts/validation_protocol_v2.py --tier "$TIER"
```

---

**These templates turn any agent into a mode-aware code generator that produces consistent, tier-appropriate code while maintaining perfect documentation and testing parity.**
