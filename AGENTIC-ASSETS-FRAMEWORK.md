# Agentic Assets Framework

**Version**: 2.0  
**Last Updated**: 2025  
**Status**: Active

This document defines the five types of agentic assets that comprise the unified AI development ecosystem.

---

## Overview

The repository is organized around **five complementary asset types** that work together to enable AI-assisted software development:

1. **Blueprints** — What to build (product archetypes)
2. **Tasks** — How to implement a feature (implementation units)
3. **Recipes** — Feature combinations (bundles of Tasks + Skills)
4. **Agent Personas** — Who does the work (configured workers)
5. **Skills** — How to do it well (capabilities, best practices)

**"Templates"** refers collectively to all five asset types—the entire system of reusable, composable assets.

---

## The Five Asset Types

### 1. BLUEPRINTS — What to Build

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

### 2. TASKS — How to Implement a Feature

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

### 3. RECIPES — Feature Combinations

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

### 4. AGENT PERSONAS — Who Does the Work

**Definition**: Pre-configured agent workers with curated skills, compatible blueprints, and defined workflows for specific domains.

**Purpose**: Provide ready-to-use AI workers optimized for specific development workflows.

**Format**: YAML (configuration) + Markdown (documentation)

**Location**: `agent-personas/`

**Key Files**:
- `persona.yaml` — Agent configuration
- `PERSONA.md` — Human-readable documentation
- `workflows/` — Defined workflow automations

**Examples**:

#### Code Reviewer
```yaml
# agent-personas/code-reviewer/persona.yaml
persona:
  id: "code-reviewer"
  name: "Code Review Agent"
  description: "Specialized agent for comprehensive code reviews"
  
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

#### Testing Specialist
```yaml
# agent-personas/testing-agent/persona.yaml
persona:
  id: "testing-agent"
  name: "Testing Specialist"
  description: "Agent focused on comprehensive test coverage"
  
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

**When to Use**: When you need a specialized AI worker for a specific domain or repetitive workflow.

**Question Answered**: "Which agent should I use for [task]?"

---

### 5. SKILLS — How to Do It Well

**Definition**: Reusable AI instruction packages that teach best practices and capabilities.

**Purpose**: Enable agents to invoke capabilities on-demand through trigger keywords.

**Format**: Markdown + JSON

**Location**: `skill-packs/`

**Key Files**:
- `SKILL.md` — Main definition with YAML frontmatter
- `config.json` — Trigger keywords, patterns, examples
- `README.md` — Quick-start guide (< 80 lines)
- `_examples/basic-examples.md` — Before/after code examples

**Examples**:
- `clean-code` — Code quality best practices
- `error-handling` — Exception handling patterns
- `web-scraping` — Data extraction techniques
- `unit-testing` — Test writing methodologies

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

## Asset Relationships

### Hierarchy

```
┌────────────────────────────────────────────────────────────────────┐
│                    TEMPLATES (All 5 Asset Types)                    │
│                    The Complete Reusable System                     │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                 AGENT PERSONAS                               │  │
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
│            └─────────────────┘                                     │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Workflow Integration

```
User Request
      │
      ▼
┌──────────────────────────────────────────┐
│         AGENT PERSONA                     │
│  (Who does the work)                      │
│  ──▶ Selects appropriate Recipe or        │
│  ──▶ Loads compatible Blueprints          │
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

| Aspect | Blueprints | Tasks | Recipes | Agent Personas | Skills |
|--------|------------|-------|---------|----------------|--------|
| **Question** | "What to build?" | "How to implement?" | "What features?" | "Who does it?" | "How to do well?" |
| **Purpose** | Define products | Implement features | Bundle features | Deploy workers | Teach capabilities |
| **Format** | YAML + Markdown | Code + Config | YAML + Markdown | YAML + Markdown | Markdown + JSON |
| **Scope** | Complete product | Single feature | Feature set | Domain worker | Capability |
| **Contains** | Architecture, constraints | Code, tests, config | Tasks + Skills | Skills + Workflows | Instructions, examples |
| **Composed Of** | Tasks + Overlays | Skills + Templates | Tasks + Skills | Skills + Recipes/Blueprints | N/A |
| **Examples** | mins, saas-api | auth-basic, crud | ecommerce, saas-starter | code-reviewer, tester | clean-code, testing |
| **Location** | `blueprints/` | `tasks/` | `recipes/` | `agent-personas/` | `skill-packs/` |

---

## Terminology

### "Templates" (Umbrella Term)
**"Templates" refers collectively to all five asset types**—the entire system of reusable, composable assets:
- Blueprint templates
- Task templates  
- Recipe templates
- Agent Persona templates
- Skill templates

When we say "the template system," we mean the entire ecosystem of all five asset types working together.

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

### Pattern 4: Persona-Enabled Workflows
```
Domain task → Select Agent Persona → Apply Recipe/Task → Automated execution
```
**Example**: "Review this PR" → Invoke `code-reviewer` persona → Automated code review

### Pattern 5: Skill-First Learning
```
Learn technique → Invoke Skill → Apply knowledge → Improve code
```
**Example**: "Write better tests" → Invoke `unit-testing` skill → Get best practices

### Pattern 6: Complete Project Automation
```
Product idea → Architect Persona → Blueprint → Recipe → Tasks + Skills → Working code
```
**Example**: "Build analytics dashboard" → Architecture Agent → `web-dashboard` blueprint → `saas-starter` recipe → Tasks + Skills → Full implementation

---

## File Organization

```
_templates/
├── AGENTS.md                          # Behavioral constraints
├── AGENTIC-ASSETS-FRAMEWORK.md        # This document — Asset definitions
├── CHANGELOG.md                       # Event log
├── README.md                          # Repository overview
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
├── agent-personas/                    # 🤖 AGENT PERSONAS
│   ├── code-reviewer/
│   │   ├── persona.yaml
│   │   ├── PERSONA.md
│   │   └── workflows/
│   ├── testing-agent/
│   └── architecture-agent/
│
├── skill-packs/                       # 🧠 SKILLS
│   ├── 1-programming-core/
│   ├── 2-code-quality/
│   └── HOW_TO_CREATE_SKILL_PACKS.md
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

### For Agent Personas
- Curate complementary skills
- Define clear workflows
- Specify compatible blueprints/recipes
- Document trigger phrases
- Include domain knowledge

### For Skills
- Keep descriptions action-oriented
- Provide multi-language examples
- Use minimal YAML frontmatter
- Follow ❌/✅ format
- Test trigger keywords

---

## Summary

The five asset types create a complete ecosystem:

1. **Blueprints** provide the vision (what to build)
2. **Tasks** provide the implementation (how to build features)
3. **Recipes** provide the combinations (what features to include)
4. **Agent Personas** provide the workers (who does the work)
5. **Skills** provide the expertise (how to do it well)

**"Templates"** refers to all five types together—the complete reusable system for AI-assisted software development.

---

*See also: `AGENTS.md` for behavioral constraints, `README.md` for repository overview*
