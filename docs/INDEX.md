# Documentation Index

**Purpose**: Complete index of all organized documentation in this repository.

## Quick Reference

| System | Main Document | Location | Purpose |
|--------|---------------|----------|---------|
| **Agent Framework** | AGENTS.md | **Project root** (`../`) | AI agent operating instructions |
| **Memory System** | MEMORY-SYSTEM-PROTOCOL.md | `protocols/` | Memory management protocol |
| **Documentation Blueprint** | DOCUMENTATION-BLUEPRINT.tpl.md | `templates/` | Complete documentation system |
| **Skill Builder** | SKILL.md | `../.agents/skills/skill-builder/` | Skill creation system |
| **Archive reference (template types)** | ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md | `ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md` | Where to look in the archive for each template type (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Memory); read-only reference |

## Core Documentation (`core/`)

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

### MEMORY-SYSTEM-PROTOCOL.md
- **Content**: Complete memory system protocol
- **Related**: `memory-system/` (this docs folder), `../.memory/` (project root when in use)

### PROMPT-VALIDATION-PROTOCOL.md
- **Content**: Prompt validation system
- **Size**: 14.9KB
- **Purpose**: Ensure prompt quality and consistency

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
3. Use `protocols/PROMPT-VALIDATION-PROTOCOL.md` for validation
4. Follow `guides/TEMPLATE-SYSTEM-GUIDE.md` for templates

### For Development
1. Use `../.agents/skills/skill-builder/` for skill creation
2. Reference `guides/ADD-NEW-*-TEMPLATE.md` for new templates when applicable
3. Follow `core/AGENTIC-RULES.md` for agent constraints

---

*Documentation organized: 2026-02-26*  
*See project root `CURRENT-REPOSITORY-STATE.md` for full repository inventory.*
