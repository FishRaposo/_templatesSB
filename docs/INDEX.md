# Documentation Index

**Purpose**: Complete index of all organized documentation in this repository.

## Quick Reference

| System | Main Document | Location | Purpose |
|--------|---------------|----------|---------|
| **Agent Framework** | AGENTS.md | **Project root** (`../`) | AI agent operating instructions |
| **Memory System** | MEMORY-SYSTEM-PROTOCOL.md | `protocols/` | Memory management protocol |
| **System map** | SYSTEM-MAP.md | `SYSTEM-MAP.md` | Architecture overview, components, data flow |
| **Prompt validation** | PROMPT-VALIDATION.md | `PROMPT-VALIDATION.md` | 4-check gate; full protocol in `protocols/PROMPT-VALIDATION-PROTOCOL.md` |
| **Documentation Blueprint** | DOCUMENTATION-BLUEPRINT.tpl.md | `templates/` | Complete documentation system |
| **Skill Builder** | SKILL.md | `../.agents/skills/skill-setup/` | Skill creation system |
| **Archive reference (template types)** | ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md | `ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md` | Where to look in the archive for each template type (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Memory); read-only reference |
| **Templates system (all 7 types)** | TEMPLATES-SYSTEM-OVERVIEW.md | `TEMPLATES-SYSTEM-OVERVIEW.md` | Full overview of Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols |
| **Suggestions for new templates** | SUGGESTIONS-FOR-NEW-TEMPLATES.md | `SUGGESTIONS-FOR-NEW-TEMPLATES.md` | Ideas for new Skills, Tasks, Blueprints, Subagents, Rules, Recipes, Protocols |
| **Documentation blueprint vs current** | DOCUMENTATION-BLUEPRINT-VS-CURRENT-SETUP.md | `DOCUMENTATION-BLUEPRINT-VS-CURRENT-SETUP.md` | Comparison of _documentation-blueprint requirements to repo (MVP/Core/Full tiers, gaps, recommendations) |
| **Blueprint ↔ current (full, bidirectional)** | BLUEPRINT-AND-CURRENT-SYSTEM-FULL-COMPARISON.md | `BLUEPRINT-AND-CURRENT-SYSTEM-FULL-COMPARISON.md` | Full comparison; how current system improves blueprint; how blueprint improves current system |

## Core Documentation (`core/`)

### TEMPLATES-SYSTEM-OVERVIEW.md
- **Content**: Full overview of all seven template types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols)
- **Location**: `TEMPLATES-SYSTEM-OVERVIEW.md` (docs root)
- **Purpose**: Single-document reference for the templates system; relationships, comparison table, file layout, implementation status
- **Related**: `../AGENTIC-ASSETS-FRAMEWORK.md` (detailed definitions and examples), `../AGENTS.md` (canonical rules)

### SUGGESTIONS-FOR-NEW-TEMPLATES.md
- **Content**: Actionable suggestions for new templates across all seven types
- **Location**: `SUGGESTIONS-FOR-NEW-TEMPLATES.md` (docs root)
- **Purpose**: Ideas for Skills, Tasks, Blueprints, Subagents, Rules, Recipes, and Protocols; tables per type; suggested implementation order
- **Related**: `TEMPLATES-SYSTEM-OVERVIEW.md`, `.agents/skills/skill-setup/`

### DOCUMENTATION-BLUEPRINT-VS-CURRENT-SETUP.md
- **Content**: Comparison of Documentation Blueprint (MVP/Core/Full tiers) to current repo
- **Location**: `DOCUMENTATION-BLUEPRINT-VS-CURRENT-SETUP.md` (docs root)
- **Purpose**: Required file inventory vs actual files; gaps (QUICKSTART, CONTRIBUTING, SECURITY, SYSTEM-MAP, .github); memory/graph staleness; recommendations
- **Related**: `_documentation-blueprint/DOCUMENTATION-BLUEPRINT.md`, `CURRENT-REPOSITORY-STATE.md`

### BLUEPRINT-AND-CURRENT-SYSTEM-FULL-COMPARISON.md
- **Content**: Full comparison plus bidirectional improvements (current → blueprint, blueprint → current)
- **Location**: `BLUEPRINT-AND-CURRENT-SYSTEM-FULL-COMPARISON.md` (docs root)
- **Purpose**: Part I full comparison; Part II how current system can improve the blueprint (Protocols, docs/INDEX, event log, staleness, repo state, protocol skills, AI file exception); Part III how blueprint can improve current (QUICKSTART/CONTRIBUTING/SECURITY, SYSTEM-MAP, graph materialization, DOCUMENTING table, tier, section specs, shutdown sequence); Part IV summary tables
- **Related**: `DOCUMENTATION-BLUEPRINT-VS-CURRENT-SETUP.md`, `_documentation-blueprint/DOCUMENTATION-BLUEPRINT.md`

### AGENTS.md
- **Content**: Complete AI agent operating instructions
- **Location**: **Project root** (`../AGENTS.md`), not in docs/core/
- **Framework**: Three Pillars (Automating, Testing, Documenting)
- **Related**: `AGENTIC-RULES.md` (this directory), `../.agents/skills/rules-setup/`

### AGENTIC-RULES.md
- **Content**: Agent rules and constraints
- **Size**: 6.4KB
- **Purpose**: Define agent behavior boundaries

## Guides (`guides/`)

### AGENT_SKILLS_GUIDE.md
- **Content**: Comprehensive guide to building agent skills
- **Size**: 22.1KB
- **Purpose**: Skill development principles and practices

### TEMPLATE-SYSTEM-GUIDE.md
- **Content**: Guide to the template system
- **Size**: 16.5KB
- **Purpose**: Understanding and using templates

### Template Creation Guides
- **ADD-NEW-BLUEPRINT-TEMPLATE.md** (14.5KB)
- **ADD-NEW-STACK-TEMPLATE.md** (12.5KB)
- **ADD-NEW-TASK-TEMPLATE.md** (18.0KB)

## Protocols (`protocols/`)

**Protocols** are a template type: process definitions that Rules and agents reference. Location: `docs/protocols/`.

### MEMORY-SYSTEM-PROTOCOL.md
- **Content**: Complete memory system protocol
- **Related**: `memory-system/` (this docs folder), `../.memory/` (project root when in use)

### PROMPT-VALIDATION-PROTOCOL.md
- **Content**: Prompt validation system (4 checks, security patterns, scoring)
- **Purpose**: Ensure prompt quality and consistency before execution
- **Install**: Use **prompt-validation-setup** skill (`.agents/skills/prompt-validation-setup/`) to install the protocol file in a new project

## Templates (`templates/`)

### DOCUMENTATION-BLUEPRINT.tpl.md
- **Content**: Comprehensive documentation blueprint
- **Size**: 25.8KB
- **Features**: 18 required documentation files
- **Related**: `../_documentation-blueprint/`

## Supporting Directories

### Existing Structure
- **`examples/`** - Example implementations
- **`technical/`** - Technical documentation
- **`universal/`** - Universal templates
- **`memory-system/`** - Memory system docs, templates, scripts (see also protocols/MEMORY-SYSTEM-PROTOCOL.md)
- **`MEMORY_SYSTEM.md`** - Memory system overview (when present)
- **`THREE_PILLARS.md`** - Three Pillars framework

## Navigation

### For New Users
1. Start with **project root** `AGENTS.md` for agent framework (not in docs/core/)
2. Use `templates/DOCUMENTATION-BLUEPRINT.tpl.md` for new projects when applicable
3. Follow `guides/AGENT_SKILLS_GUIDE.md` for skill development

### For System Integration
1. Implement `protocols/MEMORY-SYSTEM-PROTOCOL.md` for memory
2. Use `memory-system/` and `.agents/skills/memory-system-setup/` for memory setup
3. Use `protocols/PROMPT-VALIDATION-PROTOCOL.md` for validation; install via `.agents/skills/prompt-validation-setup/` when setting up a new project. Use `.agents/skills/protocol-setup/` to create or audit the Protocols template type.
4. Follow `guides/TEMPLATE-SYSTEM-GUIDE.md` for templates

### For Development
1. Use `../.agents/skills/skill-setup/` for skill creation
2. Reference `guides/ADD-NEW-*-TEMPLATE.md` for new templates when applicable
3. Follow `core/AGENTIC-RULES.md` for agent constraints

---

*Documentation organized: 2026-02-26*  
*See project root `CURRENT-REPOSITORY-STATE.md` for full repository inventory.*
