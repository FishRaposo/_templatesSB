# BLUEPRINT-COMPILER.md - The Universal Codebase Generator

**Purpose**: Automatically generate a complete codebase and documentation set from a project blueprint, tier, and framework patterns.  
**Version**: 1.0  
**Last Updated**: 2025-12-09  
**Design**: LLM-native, deterministic, self-healing, agent-agnostic  

---

## 🎯 BLUEPRINT COMPILER PHILOSOPHY

The compiler's job is not to "guess" what to build. Its job is to interpret your blueprint as if it were a programming language.

Your blueprints ARE:
- A DSL for architecture
- A DSL for documentation  
- A DSL for code structure
- A DSL for multi-agent reasoning

The blueprint compiler treats:
- Docs as source code
- Index as schema
- Patterns as semantics
- Tier as compilation mode
- Blueprint as AST (Abstract Syntax Tree)

You're basically creating a compiler for software systems, not just code.

---

## 📦 INPUTS & OUTPUTS

### Inputs
1. **Blueprint** (project-specific)
2. **Universal Documentation Templates**
3. **Framework Patterns** (Flutter/React/Node/etc)
4. **Tier** (MVP/Core/Full)
5. **docs_index.yaml**
6. **Testing Strategy + Examples**
7. **Folder structure rules**
8. **Optional**: Migrations, APIs, Data Models

### Outputs
1. **Generated project folder structure**
2. **Fully populated docs for selected tier**
3. **Generated code skeleton (or full implementation)**
4. **Tests pre-generated using testing strategy**
5. **Roadmap + TODO synced**
6. **Validation report**
7. **Optional**: Seed migrations
8. **Optional**: End-to-end agent handoff instructions

It gives you a production-ready repo.

---

## 🏗️ COMPILER ARCHITECTURE

The compiler has 7 core modules:

### 🔷 3.1 Blueprint Parser
Extracts structured meaning from your blueprint:
- Project type (mobile, API, CLI, etc)
- Features
- Screens/routes/endpoints
- Architecture choices 
- Data needs
- State management
- Persistence strategy
- Monetization flows (if MINS)
- Dependencies
- Testing requirements

Essentially turns the blueprint into a project AST:
```yaml
blueprint_ast = {
  name: "...",
  features: [...],
  architecture: {...},
  routes: [...],
  data_models: {...},
  api: {...},
  monetization: {...},
  stack: "flutter",
}
```

### 🔷 3.2 Tier Manager
Decides what files must be generated:
```yaml
tier_requirements = index[tier]
```

It uses:
- Required docs
- Recommended docs
- Ignored docs
- File descriptors
- Tiered code generation templates (MVP/Core/Full)

This ensures the compiler adjusts depth + complexity automatically.

### 🔷 3.3 Index Resolver
The schema enforcer. Maps each file to its appropriate content sources:
- README → blueprint.summary
- ARCHITECTURE → blueprint.architecture + patterns + tier rules
- TESTING → testing strategy
- ROADMAP → blueprint.milestones
- FRAMEWORK-PATTERNS → tech-specific rules

This eliminates hallucination because every file has explicit provenance.

### 🔷 3.4 Documentation Generator
Uses:
- Universal templates
- Tier templates
- Index-resolved content
- Blueprint AST

To output the entire documentation set. Docs become deterministic and self-consistent.

### 🔷 3.5 Pattern Engine (Framework-Specific)
This is what makes your system architecture-native. If the blueprint chooses Flutter, this module references:
- FRAMEWORK-PATTERNS.md
- TESTING-EXAMPLES.md
- State Management Rules
- Folder Structure Templates
- Navigation Patterns
- Data Access Patterns

The engine enforces your engineering philosophy inside the code itself.

Patterns generate:
- Folder structures
- Boilerplates
- Service skeletons
- Widget/page templates
- State models
- DI setups
- Tests

This is where your system becomes a real code generator, not a toy.

### 🔷 3.6 Code Generator
Guided by:
- Blueprint AST
- Tier templates
- Framework patterns
- Testing strategy
- Architecture rules

It generates:
```
lib/ or src/
  modules/
    featureA/
    featureB/
shared/
data/
domain/
state/
ui/
widgets/
tests/
```

In Core/Full tiers, it also:
- Generates domain models
- Builds API layer
- Builds persistence
- Builds mocks
- Scaffolds UI tests
- Enforces architecture invariants

In MVP, it produces only minimal structure.

### 🔷 3.7 Validation + Sync Engine
Runs:
- Validation Protocol v2
- Diff Validator
- Documentation Sync Pass
- Test generation checks
- Architecture parity checks

The compiler refuses to output a repo that isn't internally consistent.

---

## ⚡ EXECUTION PIPELINE v1.0

### STEP 1 — Load Inputs
- blueprint.md
- docs_index.yaml
- framework patterns
- universal docs
- tier
- testing strategy

### STEP 2 — Parse Blueprint
Convert blueprint into structured AST.

### STEP 3 — Determine Tier
Use tier logic (MVP/Core/Full).

### STEP 4 — Resolve Schema
Map each documentation file to its content sources.

### STEP 5 — Generate Documentation
Using:
- Universal templates
- Tier templates
- Blueprint AST
- Index mapping

### STEP 6 — Generate Folder Structure
Follow FRAMEWORK-PATTERNS.md and ARCHITECTURE.md rules.

### STEP 7 — Generate Code Skeleton
Based on:
- Blueprint features
- Patterns
- Tiered code generation templates

### STEP 8 — Generate Tests
Based on:
- TESTING-STRATEGY.md
- TESTING-EXAMPLES.md
- Tier requirements

### STEP 9 — Generate Optional Assets
- Migrations
- Configs
- API schemas
- Analytics

### STEP 10 — Run Validation Pass
- Validation Protocol v2
- Refactor Simulation (if architecture changed)
- Diff Validator (on generated code)
- Documentation Sync Check

### STEP 11 — Emit Final Repo
- src/lib/
- tests/
- docs/
- root files
- scripts/
- CHANGELOG.md

This pipeline is your compiler IR → output sequence.

---

## 🤖 AGENT ROLES INSIDE THE COMPILER

The Blueprint Compiler orchestrates five operational personas as behavioral modes. See **universal/AGENTS.md** for complete agent role specifications, responsibilities, forbidden actions, reasoning loops, and handoff conditions.

### Agent Mode Integration
- **Phase 1-2**: Architect Agent mode (blueprint parsing, tier selection)
- **Phase 3-5**: Builder Agent mode (code generation) 
- **Phase 6**: Tester Agent mode (validation)
- **Phase 7**: Doc Manager Agent mode (documentation sync)
- **Refactor operations**: Refactorer Agent mode (with simulation)

Each mode enforces strict role boundaries and deterministic reasoning loops to ensure predictable, safe software development.

---

## 🛠️ ERROR HANDLING & RECOVERY

The compiler should self-correct using this loop:
```
If any validation step fails:
  → Identify missing/inconsistent files
  → Regenerate missing/invalid docs
  → Re-run code generation for missing modules
  → Auto-create stubs for missing tests
  → Update architecture docs
  → Re-run validation
```

This is the self-healing mechanism.

---

## 📋 FORMAL SPECIFICATION

============================================
BLUEPRINT COMPILER — FORMAL SPEC v1.0
============================================

**Purpose**: Automatically generate a complete codebase and documentation set from a project blueprint, tier, and framework patterns.

**Inputs**:
- blueprint.md
- docs_index.yaml
- tier selection
- universal documentation templates
- framework patterns
- testing strategy
- migration rules (optional)
- API/data model specs (optional)

**Outputs**:
- project skeleton
- full documentation set
- code modules
- tests
- scripts/config
- validation report
- CHANGELOG.md

--------------------------------------------
COMPILER MODULES
--------------------------------------------
1. Blueprint Parser
2. Tier Manager
3. Index Resolver
4. Documentation Generator
5. Pattern Engine
6. Code Generator
7. Validation + Sync Engine

--------------------------------------------
COMPILER EXECUTION PIPELINE
--------------------------------------------
1. Load Inputs
2. Parse Blueprint
3. Resolve Tier
4. Resolve Documentation Schema
5. Generate Documentation
6. Generate Folder Structure
7. Generate Code Skeleton
8. Generate Tests
9. Generate Optional Assets
10. Validation Pass
11. Emit Final Repo

--------------------------------------------
BEHAVIOR RULES
--------------------------------------------
- Never generate code without validating architecture.
- Documentation and code must remain consistent.
- All generated code must follow framework patterns.
- Respect tier constraints.
- Always run Validation Protocol v2 before finalizing.
- Never hallucinate file locations; follow resolver mappings.
- Blueprint is the source of truth for project scope.

--------------------------------------------
FAILURE RECOVERY
--------------------------------------------
If validation fails:
- regenerate missing docs
- fix schema mismatches
- generate missing modules/tests
- update architecture docs
- repeat validation

--------------------------------------------
INTEGRATION POINTS
--------------------------------------------
- **tier-index.yaml**: Source of truth for tier requirements
- **examples/FRAMEWORK-PATTERNS.md**: Framework-specific rules and templates
- **docs/platform-engineering/VALIDATION-PROTOCOL-v2.md**: Self-healing validation system
- **docs/platform-engineering/CODE-GENERATION-TEMPLATES.md**: Tier-specific code generation contracts
- **BLUEPRINT-MAPPING.md**: Blueprint interpretation and mapping
- **TIERED-TEMPLATES.md**: Documentation templates by tier
- **universal/TESTING-STRATEGY.md**: Testing requirements and examples
- **universal/ARCHITECTURE.md**: System architecture constraints
- **universal/AGENTS.md**: Five-agent role system specifications
- **universal/AGENT-ORCHESTRATION.md**: Multi-agent assembly line protocol
- **universal/AGENT-DELEGATION-MATRIX.md**: Agent delegation rules and triggers
- **universal/AGENT-MEMORY-RULES.md**: Role-based memory model and state transfer
- **universal/AGENT-FAILURE-MODES.md**: Failure detection and recovery protocols
- **universal/AGENT-SAFETY-FILTERS.md**: Runaway agent protection system
- **universal/EXECUTION-ENGINE.md**: Multi-agent execution engine and orchestration runtime

============================================
END OF SPEC
============================================

---

## 🔧 IMPLEMENTATION NOTES

### **Dependencies**: tier-index.yaml (tier requirements), examples/FRAMEWORK-PATTERNS.md (framework-specific rules), docs/platform-engineering/VALIDATION-PROTOCOL-v2.md (validation), docs/platform-engineering/CODE-GENERATION-TEMPLATES.md (tiered code generation), BLUEPRINT-MAPPING.md (blueprint parsing), TIERED-TEMPLATES.md (documentation generation), universal/TESTING-STRATEGY.md (test generation), universal/ARCHITECTURE.md (architecture validation), universal/AGENTS.md (agent role specifications), universal/AGENT-ORCHESTRATION.md (assembly line protocol), universal/AGENT-DELEGATION-MATRIX.md (delegation rules), universal/AGENT-MEMORY-RULES.md (memory model), universal/AGENT-FAILURE-MODES.md (recovery protocols), universal/AGENT-SAFETY-FILTERS.md (runaway protection), universal/EXECUTION-ENGINE.md (orchestration runtime)

### Usage
The Blueprint Compiler is typically invoked through:
1. **QUICKSTART-AI.md**: Phase 4-5 orchestration
2. **Agent workflows**: Direct compilation calls

### Tier Requirements
- **MVP**: Basic project structure + core documentation
- **Core**: Full documentation + structured code generation
- **Full**: Complete codebase + advanced features + comprehensive testing

### Validation Requirements
All generated repositories must pass:
- Validation Protocol v2
- Architecture parity checks
- Documentation consistency validation
- Test coverage verification
- Framework pattern compliance

---

## 🎯 EXECUTION EXAMPLE

```bash
# Example compiler invocation
blueprint-compiler \
  --input blueprint.md \
  --tier core \
  --framework flutter \
  --output ./my-project \
  --validate
```

This would:
1. Parse the blueprint into AST
2. Load Core tier requirements from tier-index.yaml
3. Apply Flutter framework patterns
4. Generate complete documentation set
5. Create structured codebase
6. Generate tests and validation
7. Output production-ready repository

---

**The Blueprint Compiler is the closest thing to a "Create Vini App" command - turning your architectural vision into working, documented, tested code.**
