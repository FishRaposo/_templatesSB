# Agentic Assets Framework

**Version**: 2.0  
**Last Updated**: 2025  
**Status**: Active

This document defines the **seven types of templates** that comprise the unified AI development ecosystem: **Rules**, Blueprints, Tasks, Recipes, Subagents, Skills, and **Protocols**. Rules (e.g. AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md) are one template type among seven.

**Implementation status in this repo**: Only **Rules** (the four rule files), **Protocols** (in `docs/protocols/`), and **Skills** are actively implemented. The eleven current skills are **memory-system-setup**, **rules-setup**, **skill-setup**, **agents-md-setup**, **blueprints-setup**, **tasks-setup**, **recipes-setup**, **subagents-setup**, **prompt-validation-setup**, **protocol-setup**, **flutter-setup** (under `.agents/skills/`). Blueprints, Tasks, Recipes, Subagents, and legacy skill-packs (e.g. 1-programming-core, 2-code-quality) are **archived**; the framework describes all seven types for reference and future use.

---

## Overview

The repository is organized around **seven complementary template types** that work together to enable AI-assisted software development:

1. **Rules** — How agents must behave (tool- and audience-specific constraints)
2. **Blueprints** — What to build (product archetypes)
3. **Tasks** — How to implement a feature (implementation units)
4. **Recipes** — Feature combinations (bundles of Tasks + Skills)
5. **Subagents** — Who does the work (configured sub-agents)
6. **Skills** — How to do it well (capabilities, best practices)
7. **Protocols** — How processes are defined (repeatable procedures agents and rules reference)

**Rules** are one template type: Markdown files at project root (or in `.cursor/rules/`) that each tool or audience reads at agent boot. **AGENTS.md**, **CLAUDE.md**, **CURSOR.md**, and **WINDSURF.md** are examples of Rules—same project, different entry points. Skills and Subagents operate within whatever Rules the active tool loads. **Protocols** are standalone process documents (e.g. in `docs/protocols/`) that Rules and agents reference; they are installed and maintained by **protocol skills** (e.g. prompt-validation-setup, memory-system-setup). See [Rules, Skills, and Subagents](#rules-skills-and-subagents) below.

**"Templates"** refers collectively to **all seven types**—Rules, Blueprints, Tasks, Recipes, Subagents, Skills, and Protocols—the complete reusable system.

---

## The Seven Template Types

### 1. RULES — How Agents Must Behave

**Definition**: Tool- or audience-specific behavioral constraints that govern how agents and subagents behave. Rules are Markdown files read at agent boot; they define conventions, guardrails, and what agents must or must not do.

**Purpose**: Ensure consistent behavior across tools (Cursor, Claude, Windsurf, etc.) by providing a single project worldview—with one canonical source (e.g. AGENTS.md) and tool-specific entry points that point to it or adapt it.

**Format**: Markdown (optionally with YAML frontmatter for metadata)

**Location**: Project root and, for Cursor, `.cursor/rules/` (one rule per file, e.g. `RULE.md` or named `.md` files). **Naming**: Rule files at project root use **ALL CAPS** filenames (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md).

**Key Files (examples of Rules)**:
- **AGENTS.md** — Canonical, tool-agnostic rules (build/test/lint, conventions, memory, three pillars). Reference this from tool-specific rules when possible.
- **CLAUDE.md** — Claude-specific entry: overview, commands, structure, memory. Points to `AGENTIC-ASSETS-FRAMEWORK.md` and AGENTS.md.
- **CURSOR.md** — Cursor-specific entry: same framework, Cursor-oriented commands and paths. Points to framework and AGENTS.md.
- **WINDSURF.md** — Windsurf-specific entry: same framework, Windsurf-oriented quick start and structure. Points to framework and AGENTS.md.
- **.cursor/rules/*.md** — Cursor rule files (file- or scope-specific). Can reference AGENTS.md for project-wide behavior.

**Characteristics**:
- Rule files at project root are named in **ALL CAPS** (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md).
- One project, multiple rule files: AGENTS.md (source of truth) + CLAUDE.md, CURSOR.md, WINDSURF.md (tool-specific views).
- Read at agent/subagent boot; not modified during execution.
- Skills and Subagents run *within* the Rules loaded by the active tool.
- Keep constraints explicit and testable; reference the template system (blueprints, tasks, recipes, subagents, skills) where relevant.

**When to Use**: For every project using this framework. Prefer one AGENTS.md and thin tool-specific files (CLAUDE.md, CURSOR.md, WINDSURF.md) that point to it and add tool-specific commands or structure.

**Question Answered**: "What must agents do or avoid, and how is this project set up for this tool?"

---

### 2. BLUEPRINTS — What to Build

**Definition**: Product archetypes that define what kind of application to build and how to architect it.

**Purpose**: Drive automated project generation by specifying stacks, tiers, and required tasks.

**Format**: YAML (machine-readable) + Markdown (human-readable)

**Location**: `blueprints/`

**Key Files**:
- `blueprint.meta.yaml` — Machine-readable configuration
- `BLUEPRINT.md` — Human-readable documentation
- `overlays/{stack}/*.tpl.{ext}` — Stack-specific template extensions

**Examples**:
- `mins` — Minimalist Income Niche SaaS (mobile app pattern)
- `saas-api` — SaaS API architecture
- `data-pipeline` — ETL and data processing
- `web-dashboard` — Analytics dashboard

**Structure (blueprint.meta.yaml)**:
```yaml
blueprint:
  id: "blueprint-id"
  version: "1.0.0"
  name: "Blueprint Name"
  category: "micro_saas"
  
  stacks:
    required: ["flutter"]
    recommended: ["python"]
    supported: ["node", "go"]
  
  tier_defaults:
    flutter: "mvp"
    python: "core"
  
  tasks:
    required: ["auth-basic", "crud-module"]
    recommended: ["analytics-event-pipeline"]
    optional: ["notification-center"]
  
  overlays:
    flutter:
      - "overlays/flutter/app-structure.tpl.dart"
```

**Characteristics**:
- Defines product category and type
- Specifies stack constraints (required/recommended/supported)
- Sets tier defaults per stack
- Lists tasks by priority (required/recommended/optional)
- Includes overlay templates for stack customization
- Versioned for evolution

**When to Use**: When defining a product pattern that will drive automated project generation.

**Question Answered**: "What should I build?"

---

### 3. TASKS — How to Implement a Feature

**Definition**: Implementation units that contain all code, configuration, and documentation needed to implement a specific feature across technology stacks and complexity tiers.

**Purpose**: Generate production-ready feature implementations (not just code files, but complete feature units).

**Format**: Python/YAML/Jinja2 templates + Documentation + Configuration

**Location**: `tasks/`

**Key Files**:
- `task-index.yaml` — Master task registry
- `TASK.md` — Task documentation and usage guide
- `universal/*` — Universal implementation (applies to all stacks)
- `stacks/{stack}/*` — Stack-specific implementations
- `config.yaml` — Task configuration and dependencies

**Examples**:
- `auth-basic` — Authentication system (login, signup, password reset)
- `crud-module` — Full CRUD operations with validation
- `web-scraping` — Data extraction and parsing
- `analytics-event-pipeline` — Event tracking and analytics

**Structure**:
```
tasks/
└── auth-basic/
    ├── TASK.md                    # Task documentation
    ├── config.yaml                # Task configuration
    ├── universal/
    │   ├── auth-service.tpl.py    # Universal auth logic
    │   └── auth-models.tpl.yaml   # Universal data models
    └── stacks/
        ├── python/
        │   ├── fastapi-auth.tpl.py     # FastAPI implementation
        │   ├── sqlalchemy-models.tpl.py # SQLAlchemy models
        │   └── requirements.txt         # Dependencies
        ├── node/
        │   ├── express-auth.tpl.js     # Express implementation
        │   ├── mongoose-models.tpl.js  # Mongoose models
        │   └── package.json            # Dependencies
        └── flutter/
            ├── auth-service.tpl.dart   # Flutter auth service
            └── auth-provider.tpl.dart  # State management
```

**Task Tiers**:
- **MVP** (50-200 lines) — Proof of concept, minimal features
- **Core** (200-500 lines) — Production-ready, comprehensive
- **Enterprise** (500-1000+ lines) — Full-featured, scalable

**Characteristics**:
- Complete feature implementation, not just code snippets
- Stack-specific and tier-specific variants
- Includes documentation, tests, and configuration
- Jinja2 placeholders for customization
- Universal fallbacks when stack-specific missing
- Self-contained and composable

**When to Use**: When implementing a specific feature within a blueprint-driven project.

**Question Answered**: "How do I implement [feature]?"

---

### 4. RECIPES — Feature Combinations

**Definition**: Pre-configured bundles that combine Tasks and Skills for common development scenarios.

**Purpose**: Provide ready-made combinations of Tasks and Skills that work well together, eliminating the need to manually select and configure individual components.

**Format**: YAML (configuration) + Markdown (documentation)

**Location**: `recipes/`

**Key Files**:
- `recipe.yaml` — Recipe configuration
- `RECIPE.md` — Human-readable documentation
- `examples/` — Example implementations

**Examples**:

#### E-Commerce Recipe
```yaml
# recipes/ecommerce/recipe.yaml
recipe:
  id: "ecommerce"
  name: "E-Commerce Platform"
  description: "Complete e-commerce feature set"
  
  tasks:
    - "auth-basic"
    - "user-profile-management"
    - "product-catalog"
    - "shopping-cart"
    - "checkout-flow"
    - "payment-processing"
    - "order-management"
    - "inventory-tracking"
  
  skills:
    - "clean-code"
    - "error-handling"
    - "input-validation"
    - "security-best-practices"
    - "testing-strategies"
  
  blueprints:
    compatible:
      - "saas-api"
      - "web-dashboard"
  
  configuration:
    auth-basic:
      tier: "core"
      features: ["oauth", "2fa"]
    payment-processing:
      tier: "enterprise"
      providers: ["stripe", "paypal"]
```

#### SaaS Starter Recipe
```yaml
# recipes/saas-starter/recipe.yaml
recipe:
  id: "saas-starter"
  name: "SaaS Starter Kit"
  description: "Essential features for SaaS applications"
  
  tasks:
    - "auth-basic"
    - "team-workspaces"
    - "billing-stripe"
    - "notification-center"
    - "analytics-event-pipeline"
  
  skills:
    - "clean-code"
    - "api-design"
    - "database-design"
    - "security-best-practices"
  
  blueprints:
    compatible:
      - "mins"
      - "saas-api"
```

**Characteristics**:
- Curated bundles of Tasks + Skills
- Stack/tier-agnostic (inherits from Tasks)
- Compatible blueprints specified
- Configuration overrides for Tasks
- Best practices built-in via Skills
- Versioned and tested combinations

**When to Use**: When you need a complete feature set for a common scenario without manually selecting individual Tasks.

**Question Answered**: "What features do I need for [scenario]?"

---

### 5. SUBAGENTS — Who Does the Work

**Definition**: Pre-configured sub-agents with curated skills, compatible blueprints, and defined workflows for specific domains.

**Purpose**: Provide ready-to-use AI sub-agents optimized for specific development workflows (e.g. code review, testing, architecture).

**Format**: YAML (configuration) + Markdown (documentation)

**Location**: `subagents/`

**Key Files**:
- `subagent.yaml` — Subagent configuration
- `SUBAGENT.md` — Human-readable documentation
- `workflows/` — Defined workflow automations

**Examples**:

#### Code Reviewer Subagent
```yaml
# subagents/code-reviewer/subagent.yaml
subagent:
  id: "code-reviewer"
  name: "Code Review Subagent"
  description: "Subagent for comprehensive code reviews"
  
  skills:
    primary:
      - "clean-code"
      - "code-quality-review"
      - "error-handling"
    secondary:
      - "security-review"
      - "performance-optimization"
  
  blueprints:
    compatible:
      - "saas-api"
      - "web-dashboard"
  
  recipes:
    can_apply:
      - "saas-starter"
  
  workflows:
    code_review:
      steps:
        - "analyze_code_structure"
        - "check_best_practices"
        - "identify_bugs"
        - "suggest_improvements"
        - "generate_report"
  
  triggers:
    - "review this code"
    - "code review"
    - "check pull request"
```

#### Testing Specialist Subagent
```yaml
# subagents/testing-specialist/subagent.yaml
subagent:
  id: "testing-specialist"
  name: "Testing Specialist Subagent"
  description: "Subagent focused on comprehensive test coverage"
  
  skills:
    primary:
      - "unit-testing"
      - "test-driven-development"
      - "integration-testing"
    secondary:
      - "performance-testing"
      - "mutation-testing"
  
  blueprints:
    compatible:
      - "mins"
      - "saas-api"
  
  workflows:
    generate_tests:
      steps:
        - "analyze_code_for_testability"
        - "identify_test_cases"
        - "generate_unit_tests"
        - "generate_integration_tests"
        - "verify_coverage"
```

**Characteristics**:
- Curated skill bundles (primary + secondary)
- Compatible blueprints and recipes
- Defined workflows (step-by-step automations)
- Trigger keywords for invocation
- Domain-specific knowledge
- Can apply recipes automatically

**When to Use**: When you need a specialized sub-agent for a specific domain or repetitive workflow.

**Question Answered**: "Which subagent should I use for [task]?"

---

### 6. SKILLS — How to Do It Well

**Definition**: Reusable AI instruction packages that teach best practices and capabilities.

**Purpose**: Enable agents to invoke capabilities on-demand through trigger keywords.

**Format**: Markdown + JSON

**Location**: `.agents/skills/` (in this repo). Skills may also live in `~/.cursor/skills/` or `.cursor/skills/` for Cursor. Legacy structure used `skill-packs/` (archived).

**Current skills in this repo**: **memory-system-setup**, **rules-setup**, **skill-setup**, **agents-md-setup**, **blueprints-setup**, **tasks-setup**, **recipes-setup**, **subagents-setup**, **prompt-validation-setup**, **protocol-setup**, **flutter-setup**. Use `.agents/skills/skill-setup/` to create or improve skills; `.agents/skills/rules-setup/` for the four rule files; `.agents/skills/memory-system-setup/` for the memory system; `.agents/skills/prompt-validation-setup/` to install and maintain the Prompt Validation Protocol; `.agents/skills/protocol-setup/` to create or audit the Protocols template type; `.agents/skills/flutter-setup/` for Flutter/Dart projects.

**Key Files**:
- `SKILL.md` — Main definition with YAML frontmatter
- `config.json` — Trigger keywords, patterns, examples
- `README.md` — Quick-start guide (< 80 lines)
- `_examples/basic-examples.md` — Before/after code examples

**Examples (in this repo)**:
- `memory-system-setup` — Memory system setup
- `rules-setup` — Rules template type (four rule files)
- `skill-setup` — Skill creation and improvement

**SKILL.md Structure**:
```yaml
---
name: skill-name
description: Use this skill when {specific scenarios}. This includes {capabilities}.
---

# Skill Title

I'll help you {primary benefit}...

## Core Approach

## Step-by-Step Instructions

### JavaScript
```javascript
// ✅ Good example
const result = await fetch('/api/data');
```

### Python
```python
# ✅ Good example
result = requests.get('/api/data')
```

### Go
```go
// ✅ Good example
resp, err := http.Get("/api/data")
```

## Best Practices
## Validation Checklist
## Related Skills
```

**Characteristics**:
- Action-oriented descriptions ("I'll help you...")
- Multi-language code examples (JS/Python/Go minimum)
- Minimal YAML frontmatter (`name`, `description` only)
- ❌/✅ format for before/after comparisons
- `kebab-case` naming convention
- Language-agnostic (`"tools": []` in config.json)

**When to Use**: When you need to teach an AI agent a specific capability that can be invoked on demand.

**Question Answered**: "How do I do [capability] well?"

---

### 7. PROTOCOLS — How Processes Are Defined

**Definition**: Standalone process documents that define repeatable procedures—validation, memory, safety, or other cross-cutting behaviors—that agents and Rules reference before or during execution.

**Purpose**: Provide a single source of truth for how a process works (e.g. prompt validation, memory lifecycle). Rules (e.g. AGENTS.md) reference protocols by path; protocol **skills** install and maintain the protocol files in a project.

**Format**: Markdown (optionally with YAML frontmatter for metadata)

**Location**: `docs/protocols/` (or project root for minimal setups). **Naming**: `PROTOCOL-NAME-PROTOCOL.md` or `PROTOCOL-NAME.md` (e.g. `PROMPT-VALIDATION-PROTOCOL.md`, `MEMORY-SYSTEM-PROTOCOL.md`).

**Key Files (examples of Protocols)**:
- **PROMPT-VALIDATION-PROTOCOL.md** — Full validation process (4 checks, security patterns, scoring). Installed by the **prompt-validation-setup** skill. Referenced by AGENTS.md "Prompt Validation — Before Every Task."
- **MEMORY-SYSTEM-PROTOCOL.md** — Event-sourced memory lifecycle (layers, boot, append, regenerate). Installed or referenced by the **memory-system-setup** skill. Referenced by AGENTS.md "Memory System Protocol."

**Characteristics**:
- One document per process; agents and Rules reference by path.
- Installed and updated by **protocol skills** (e.g. `.agents/skills/prompt-validation-setup/`, `.agents/skills/memory-system-setup/`).
- Rules do not duplicate protocol content; they link to it and summarize the minimal gate (e.g. 4 checks for prompt validation).
- Protocols can live at project root or under `docs/protocols/`; the framework recommends `docs/protocols/` for consistency.

**When to Use**: When defining a repeatable process that agents must follow and that deserves a single, versionable document. Use a **protocol skill** to install the protocol into a new project.

**Question Answered**: "How is [process] defined and where do I find it?"

---

## Asset Relationships

### Rules, Skills, and Subagents

**Rules**, **Skills**, and **Subagents** work together as the agent-execution layer:

| Layer | Purpose | Where it lives | When it applies |
|-------|---------|----------------|-----------------|
| **Rules** | Constrain behavior — what agents must or must not do, conventions, guardrails | **AGENTS.md**, **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md** (project root); `.cursor/rules/*.md` | Read at agent/subagent boot; tool loads its rule file (e.g. Cursor → CURSOR.md or .cursor/rules) |
| **Skills** | Add capability — how to do something well, on demand | `.agents/skills/` (this repo: eleven skills); `~/.cursor/skills/`, `.cursor/skills/` | Invoked when trigger keywords match or agent selects the skill |
| **Subagents** | Who does the work — configured workers with curated skills and workflows | `subagents/` | Selected for a domain task; load their skills and run within project rules |

**Flow**: Rules are loaded first (e.g. from `AGENTS.md`). Rules reference **Protocols** (e.g. `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`) for process definitions. Subagents reference Skills and run within Rules. Skills do not override Rules; they add know-how. **Protocol skills** (e.g. prompt-validation-setup) install and maintain Protocol files; they do not replace Rules. When a subagent runs, it obeys the project’s Rules and uses its configured Skills.

**Practical use**: Put project-wide constraints in **AGENTS.md**; add **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md** as tool-specific entries that point to it. Use **Protocols** in `docs/protocols/` for defined processes (prompt validation, memory); use **protocol skills** to install them. Use **Skills** for reusable capabilities; use **Subagents** for dedicated workers that bundle Skills and run under the same Rules.

### Hierarchy

```
┌────────────────────────────────────────────────────────────────────┐
│  SEVEN TEMPLATE TYPES: Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols │
│  Rule files: AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md           │
├────────────────────────────────────────────────────────────────────┤
│  RULES (loaded by tool) → reference PROTOCOLS, constrain SUBAGENTS and agents;        │
│  SUBAGENTS use SKILLS within those rules                            │
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                 SUBAGENTS                                    │  │
│  │           (The Workers — Apply Recipes + Tasks)              │  │
│  └────────────────────┬────────────────────────────────────────┘  │
│                       │                                            │
│         ┌─────────────┴───────────────┐                           │
│         ▼                               ▼                          │
│  ┌─────────────┐              ┌──────────────────────┐            │
│  │   RECIPES   │              │   BLUEPRINTS         │            │
│  │ (Feature    │              │   (Product Archetypes)│            │
│  │  bundles)   │              │                      │            │
│  └──────┬──────┘              └──────────┬───────────┘            │
│         │                                 │                        │
│         │         ┌───────────────────────┘                        │
│         │         ▼                                                │
│         │  ┌─────────────────┐                                     │
│         └──┤     TASKS       │                                     │
│            │ (Implementation │                                     │
│            │     Units)      │                                     │
│            └────────┬────────┘                                     │
│                     │                                              │
│                     ▼                                              │
│            ┌─────────────────┐                                     │
│            │     SKILLS      │                                     │
│            │  (Best Practices)│                                    │
│            │  How to do it well│                                   │
│            └────────┬────────┘                                     │
│                     │                                              │
│  ┌──────────────────┴──────────────────┐                           │
│  │     PROTOCOLS (docs/protocols/)     │                           │
│  │  Process definitions (prompt validation, memory, etc.)          │
│  │  Installed by protocol skills (prompt-validation-setup, etc.)   │
│  └─────────────────────────────────────┘                           │
└────────────────────────────────────────────────────────────────────┘
```

### Workflow Integration

```
User Request
      │
      ▼
┌──────────────────────────────────────────┐
│         SUBAGENT                         │
│  (Who does the work)                     │
│  ──▶ Selects appropriate Recipe or       │
│  ──▶ Loads compatible Blueprints        │
└──────────────┬───────────────────────────┘
               │
         ┌─────┴──────┐
         ▼            ▼
   ┌──────────┐  ┌──────────┐
   │  RECIPE  │  │ BLUEPRINT│
   │(Features)│  │(Product) │
   └────┬─────┘  └────┬─────┘
        │             │
        └──────┬──────┘
               ▼
   ┌───────────────────────────┐
   │          TASKS            │
   │    (Implementation)       │
   │  ──▶ Stack-specific code  │
│  ──▶ Configuration         │
│  ──▶ Tests                 │
└───────────┬───────────────┘
            │
            ▼
   ┌───────────────────────────┐
   │          SKILLS           │
   │     (Best Practices)      │
│  ──▶ Apply clean code      │
│  ──▶ Handle errors         │
│  ──▶ Ensure quality        │
└───────────────────────────┘
            │
            ▼
    Generated Implementation
```

---

## Asset Type Comparison

| Aspect | Rules | Blueprints | Tasks | Recipes | Subagents | Skills | Protocols |
|--------|--------|------------|-------|---------|----------------|--------|------------|
| **Question** | "What must agents do/avoid?" | "What to build?" | "How to implement?" | "What features?" | "Who does it?" | "How to do well?" | "How is [process] defined?" |
| **Purpose** | Constrain behavior | Define products | Implement features | Bundle features | Deploy workers | Teach capabilities | Define processes |
| **Format** | Markdown | YAML + Markdown | Code + Config | YAML + Markdown | YAML + Markdown | Markdown + JSON | Markdown |
| **Scope** | Project / file | Complete product | Single feature | Feature set | Domain worker | Capability | Process |
| **Location** | AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, .cursor/rules/ | `blueprints/` | `tasks/` | `recipes/` | `subagents/` | `.agents/skills/` (this repo: eleven skills) | `docs/protocols/` |

*All seven are template types.*

---

## Terminology

### "Templates" (All Seven Types)
**"Templates"** refers collectively to **all seven template types**—the complete reusable system:
- Rule templates (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, .cursor/rules)
- Blueprint templates
- Task templates  
- Recipe templates
- Subagent templates
- Skill templates
- Protocol templates (e.g. docs/protocols/PROMPT-VALIDATION-PROTOCOL.md)

When we say "the template system," we mean all seven types working together.

### Implementation Detail: `.tpl` Files
Inside **Tasks**, you'll find `.tpl.{ext}` files (e.g., `auth-service.tpl.py`). These are:
- **Not** standalone assets
- **Not** invoked directly
- **Implementation detail** inside Tasks
- Jinja2 templates for code generation
- Delivered as part of the complete Task unit

---

## Usage Patterns

### Pattern 1: Blueprint-Driven Development
```
Have product idea → Select Blueprint → Apply Recipes/Tasks → Generate project
```
**Example**: "Build a mobile app" → Select `mins` blueprint → Apply `saas-starter` recipe → Generate Flutter project

### Pattern 2: Task-First Implementation
```
Need specific feature → Select Task → Customize for stack/tier → Implement
```
**Example**: "Add authentication" → Use `auth-basic` task → Select Python/Core tier → Full auth implementation

### Pattern 3: Recipe-Assisted Setup
```
Common scenario → Select Recipe → Auto-configure Tasks + Skills → Fast setup
```
**Example**: "Build e-commerce" → Use `ecommerce` recipe → All features pre-configured

### Pattern 4: Subagent-Enabled Workflows
```
Domain task → Select Subagent → Apply Recipe/Task → Automated execution
```
**Example**: "Review this PR" → Invoke `code-reviewer` subagent → Automated code review

### Pattern 5: Skill-First Learning
```
Learn technique → Invoke Skill → Apply knowledge → Improve code
```
**Example**: "Write better tests" → Invoke `unit-testing` skill → Get best practices

### Pattern 6: Complete Project Automation
```
Product idea → Architect Subagent → Blueprint → Recipe → Tasks + Skills → Working code
```
**Example**: "Build analytics dashboard" → Architecture Subagent → `web-dashboard` blueprint → `saas-starter` recipe → Tasks + Skills → Full implementation

---

## File Organization

**Rules** are at project root (and in `.cursor/rules/` for Cursor). **Protocols** live in `docs/protocols/` and are installed by protocol skills. The rest of the framework lives under the repository root, often in a `_templates/` or project directory.

```
<project root>
├── AGENTS.md                          # 📜 RULES — Canonical (tool-agnostic)
├── CLAUDE.md                          # 📜 RULES — Claude entry
├── CURSOR.md                          # 📜 RULES — Cursor entry
├── WINDSURF.md                        # 📜 RULES — Windsurf entry
├── AGENTIC-ASSETS-FRAMEWORK.md        # This document — Asset definitions
├── CHANGELOG.md                       # Event log
├── README.md                          # Repository overview
│
├── .cursor/rules/                     # 📜 RULES — Cursor rule files (optional)
│   └── *.md
│
├── docs/
│   └── protocols/                    # 📋 PROTOCOLS — Process definitions (prompt validation, memory, etc.)
│       ├── PROMPT-VALIDATION-PROTOCOL.md
│       └── MEMORY-SYSTEM-PROTOCOL.md
│
├── blueprints/                        # 📋 BLUEPRINTS
│   ├── mins/
│   ├── saas-api/
│   └── web-dashboard/
│
├── tasks/                             # 🏗️ TASKS
│   ├── task-index.yaml
│   ├── auth-basic/
│   │   ├── TASK.md
│   │   ├── config.yaml
│   │   ├── universal/
│   │   └── stacks/
│   ├── crud-module/
│   └── web-scraping/
│
├── recipes/                           # 🍳 RECIPES
│   ├── ecommerce/
│   │   ├── recipe.yaml
│   │   └── RECIPE.md
│   └── saas-starter/
│
├── subagents/                       # 🤖 SUBAGENTS (archived in this repo)
│   ├── code-reviewer/
│   ├── testing-specialist/
│   └── architecture-subagent/
│
├── .agents/
│   └── skills/                   # 🧠 SKILLS (current: eleven skills)
│   ├── memory-system-setup/
│   ├── rules-setup/
│   ├── skill-setup/
│   ├── blueprints-setup/
│   ├── tasks-setup/
│   ├── recipes-setup/
│   ├── subagents-setup/
│   ├── prompt-validation-setup/
│   └── protocol-setup/
│
├── scripts/                           # 🔧 AUTOMATION
│   ├── setup-project.py
│   ├── validate-templates.py
│   ├── blueprint_config.py
│   └── task_resolver.py
│
└── _complete_archive/                 # Preserved history
```

---

## Best Practices

### For Rules (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, .cursor/rules)
- Keep one canonical source (AGENTS.md) and thin tool-specific files that point to it.
- List the four rule files (AGENTS, CLAUDE, Cursor, WINDSURF) in framework docs so contributors know they are equal examples of Rules.
- Keep constraints explicit and testable; reference the template system where relevant.
- Document memory system and validation requirements when the project uses them.

### For Blueprints
- Define clear constraints
- Specify stack compatibility
- Include tier recommendations
- Document overlay templates
- Version your blueprints

### For Tasks
- Include complete implementation (not just code)
- Provide stack-specific variants
- Include tests and documentation
- Follow tier complexity guidelines
- Use clear placeholder names

### For Recipes
- Curate complementary Tasks
- Include relevant Skills
- Specify compatible Blueprints
- Provide configuration examples
- Test the complete bundle

### For Subagents
- Curate complementary skills
- Define clear workflows
- Specify compatible blueprints/recipes
- Document trigger phrases
- Include domain knowledge

### For Protocols (docs/protocols/)
- Keep one document per process; reference by path from Rules (e.g. AGENTS.md).
- Use a **protocol skill** (e.g. prompt-validation-setup) to install the protocol file in a new project.
- Do not duplicate full protocol content in Rules; link to the protocol and summarize the minimal gate (e.g. 4 checks).

### For Skills
- Keep descriptions action-oriented
- Provide multi-language examples
- Use minimal YAML frontmatter
- Follow ❌/✅ format
- Test trigger keywords

---

## Summary

The seven template types create a complete ecosystem:

1. **Rules** define how agents must behave (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, .cursor/rules).
2. **Blueprints** provide the vision (what to build).
3. **Tasks** provide the implementation (how to build features).
4. **Recipes** provide the combinations (what features to include).
5. **Subagents** provide the workers (who does the work).
6. **Skills** provide the expertise (how to do it well).
7. **Protocols** provide process definitions (how validation, memory, and other procedures work); they live in `docs/protocols/` and are installed by protocol skills.

**"Templates"** refers to all seven types together—the complete reusable system for AI-assisted software development. Subagents and Skills operate within whatever Rules the active tool loads. Rules reference Protocols for process definitions.

---

*See also: AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md (Rules); README.md for repository overview*
