# Template System Guide - Universal Template System

> **META-DOCUMENTATION** - Complete guide to the template system architecture, design, and maintenance

**Purpose**: This document explains how the Universal Template System works, its architecture, and how to extend or maintain it.  
**Last Updated**: {{LAST_UPDATED_DATE}}  
**System Version**: {{SYSTEM_VERSION}}  
**Total Templates**: 746

---

## 🏗️ System Architecture Overview

### Core Design Philosophy

The Universal Template System is built on **blueprint-driven architecture** with these principles:
1. **Blueprints as Primitives** - Product archetypes drive all decisions
2. **Task-Based Organization** - All functionality organized around 47 production tasks
3. **Universal + Stack-Specific** - Base templates with stack optimizations
4. **Tiered Complexity** - MVP, Core, Enterprise for different needs
5. **AI-First Design** - Built for LLM interaction from day one

### System Components

```
Universal Template System/
├── 🎯 LLM-ENTRYPOINT.md          # Primary LLM starting point
├── 📋 blueprint.meta.yaml        # Master configuration
├── 📊 tier-index.yaml            # Tier selection rules
├── 🚀 AI-QUICK-START.md          # Automated setup
│
├── 📚 Core Documentation (Root)
│   ├── AGENTS.md                  # Project-specific AI guide (TEMPLATE)
│   ├── CLAUDE.md                  # Claude-specific guide (TEMPLATE)
│   ├── README.md                  # Project overview (TEMPLATE)
│   ├── CONTEXT.md                 # Philosophy (TEMPLATE)
│   └── [Other templates...]       # 11 more templates
│
├── 🛠️ System Documentation
│   ├── ADD-NEW-BLUEPRINT-TEMPLATE.md    # How to add blueprints
│   ├── ADD-NEW-STACK-TEMPLATE.md        # How to add stacks
│   ├── ADD-NEW-TASK-TEMPLATE.md         # How to add tasks
│   └── TEMPLATE-SYSTEM-GUIDE.md         # THIS FILE
│
├── 🏗️ Blueprint System
│   └── blueprints/
│       ├── documentation/         # Documentation blueprint
│       │   ├── BLUEPRINT.md       # Blueprint definition
│       │   ├── blueprint.meta.yaml # Blueprint metadata
│       │   └── overlays/          # Stack-specific templates
│       └── mins/                  # Mobile app blueprint
│
├── 🎯 Task Library
│   └── tasks/                     # 47 production tasks
│       ├── web-scraping/          # Example task
│       │   ├── universal/         # Base templates
│       │   └── stacks/            # Stack-specific
│       └── [46 more tasks...]
│
├── 📦 Stack Definitions
│   └── stacks/                    # Technology stacks
│       ├── python/                # Python stack
│       ├── node/                  # Node.js stack
│       └── [6 more stacks...]
│
└── 📊 Tier System
    └── tiers/                     # Complexity tiers
        ├── mvp/                   # 50-200 lines
        ├── core/                  # 200-500 lines
        └── enterprise/            # 500+ lines
```

---

## 🔧 Blueprint System Mechanics

### How Blueprints Work

1. **Blueprint Definition** (`BLUEPRINT.md`)
   - Describes product archetype
   - Defines required features
   - Specifies constraints

2. **Blueprint Metadata** (`blueprint.meta.yaml`)
   - Maps blueprints to stacks
   - Defines template lists
   - Configures tiers

3. **Overlay System**
   - `universal/` - Base templates
   - `stacks/` - Stack-specific overrides
   - `tiers/` - Complexity adjustments

### Blueprint Resolution Algorithm

```yaml
# 7-step resolution process:
1. Load blueprint definition
2. Select stack based on tech
3. Determine tier from requirements
4. Apply universal templates
5. Overlay stack-specific templates
6. Adjust for tier complexity
7. Generate intermediate representation
```

### Example: Documentation Blueprint

```yaml
blueprint:
  name: "documentation"
  purpose: "Generate project documentation"
  constraints:
    - mandatory_files: 16
    - automatic_updates: true
  
overlays:
  generic:
    # Base templates (93 files)
    - Root/ (16 LLM entrypoints)
    - agents/ (9 AI guides)
    - blueprints/ (7 system docs)
    - docs/ (19 technical docs)
    - examples/ (7 code examples)
    - scripts/ (7 automation)
    - templates/ (2 meta-templates)
    - universal/ (15 universal)
    - .github/ (1 workflow)
  
  python:
    # Python-specific additions
    - "requirements.txt"
    - "pyproject.toml"
    - "pytest.ini"
```

---

## 📁 Root Files: System vs Templates

### System Documentation (Meta)
These files document the template system itself:

| File | Purpose | Audience |
|------|---------|----------|
| `LLM-ENTRYPOINT.md` | LLM starting point | AI Agents |
| `TEMPLATE-SYSTEM-GUIDE.md` | System architecture | Developers |
| `ADD-NEW-*-TEMPLATE.md` | Extension guides | Contributors |
| `blueprint.meta.yaml` | System configuration | System |
| `tier-index.yaml` | Tier definitions | System |

### Template Files (To Be Copied)
These are templates that get copied to generated projects:

| File | Type | When Used |
|------|------|----------|
| `AGENTS.md` | Project-specific | Every project |
| `CLAUDE.md` | Project-specific | Claude projects |
| `README.md` | Project-specific | Every project |
| `CONTEXT.md` | Project-specific | Every project |
| [All files in `blueprints/default-project/overlays/generic/`] | Templates | Generation |

### Key Distinction
- **System docs** stay in `_templates/` repository
- **Templates** get copied to generated projects
- **Root agent files** are project-specific implementations
- **`agents/` subdirectory** contains individual AI guides

---

## 🔄 Component Relationships

### Data Flow

```
1. Blueprint Definition → 2. Metadata → 3. Template Selection
                                    ↓
4. Tier Detection → 5. Stack Application → 6. Generation
                                    ↓
7. Validation → 8. Project Output
```

### Dependencies

```yaml
blueprint.meta.yaml:
  depends_on:
    - tier-index.yaml
    - task-index.yaml
    - stack definitions

templates:
  inherit_from:
    - universal/ (base)
    - stacks/ (overrides)
    - tiers/ (complexity)

validation:
  checks:
    - schema compliance
    - template syntax
    - file existence
    - link integrity
```

---

## 🛠️ Extension Guide

### Adding a New Blueprint

1. Create blueprint directory:
   ```bash
   mkdir blueprints/my-blueprint
   ```

2. Define blueprint:
   ```markdown
   # blueprints/my-blueprint/BLUEPRINT.md
   ## Purpose
   ## Constraints
   ## Required Features
   ```

3. Create metadata:
   ```yaml
   # blueprints/my-blueprint/blueprint.meta.yaml
   name: "my-blueprint"
   overlays:
     generic: [...]
   ```

4. Add templates:
   ```bash
   blueprints/my-blueprint/overlays/generic/
   ```

### Adding a New Stack

1. Create stack directory:
   ```bash
   mkdir stacks/my-stack
   ```

2. Define stack:
   ```yaml
   # stacks/my-stack/stack.yaml
   name: "my-stack"
   files: ["main.ext", "test.ext"]
   tiers: ["mvp", "core"]
   ```

3. Add templates:
   ```bash
   stacks/my-stack/templates/
   ```

### Adding a New Task

1. Create task directory:
   ```bash
   mkdir tasks/my-task
   ```

2. Define task:
   ```yaml
   # tasks/my-task/task.yaml
   name: "my-task"
   category: "development"
   ```

3. Add templates:
   ```bash
   tasks/my-task/universal/
   tasks/my-task/stacks/
   ```

---

## 🧭 Navigation Guide

### For AI Agents

1. **Start Here**: `LLM-ENTRYPOINT.md`
2. **Understand**: `blueprint.meta.yaml`
3. **Select Tier**: `tier-index.yaml`
4. **Generate**: Follow `AI-QUICK-START.md`

### For Developers

1. **Learn System**: `TEMPLATE-SYSTEM-GUIDE.md`
2. **Add Features**: `ADD-NEW-*-TEMPLATE.md`
3. **Understand Tasks**: `tasks/task-index.yaml`
4. **Validate**: `scripts/validate-templates.py`

### For Maintainers

1. **Schema**: `template_schema/`
2. **Validation**: `scripts/`
3. **Reports**: `reports/`
4. **Archive**: `_archive/`

---

## 📊 System Statistics

| Component | Count | Purpose |
|-----------|-------|---------|
| Blueprints | 2 | documentation, mins |
| Stacks | 8 | python, node, flutter, etc. |
| Tiers | 3 | mvp, core, enterprise |
| Tasks | 47 | Production tasks |
| Templates | 746 | Total system templates |
| Scripts | 49 | Automation/validation |
| Tests | 37 | Test templates |

---

## 🔍 Design Decisions

### Why Blueprint-Driven?

- **Consistency**: Same archetype generates similar structure
- **Predictability**: Knowing blueprint = knowing output
- **Scalability**: Easy to add new blueprints
- **AI-Friendly**: Clear decision tree for LLMs

### Why Universal + Stack-Specific?

- **DRY Principle**: Don't repeat common patterns
- **Flexibility**: Stack can override anything
- **Maintainability**: Changes in universal propagate
- **Optimization**: Stack can provide optimal implementations

### Why Tier System?

- **Project Reality**: Not all projects need enterprise complexity
- **Progressive Enhancement**: Start MVP, grow to Enterprise
- **Resource Efficiency**: Generate only what's needed
- **Clear Scope**: Each tier has defined boundaries

---

## 🚀 Best Practices

### For Template Design

1. **Use Placeholders**: `{{PROJECT_NAME}}`, `{{TECH_STACK}}`
2. **Include Comments**: Explain complex sections
3. **Provide Examples**: Show usage patterns
4. **Test Templates**: Validate with real projects

### For System Maintenance

1. **Run Validation**: `python scripts/validate-templates.py --full`
2. **Update Metadata**: Keep `blueprint.meta.yaml` in sync
3. **Document Changes**: Update this guide
4. **Archive Old**: Move deprecated to `_archive/`

### For AI Integration

1. **Clear Entry Points**: LLMs know where to start
2. **Explicit Workflows**: Step-by-step instructions
3. **Tool Optimization**: Minimize tool calls
4. **Error Recovery**: Handle failures gracefully

---

## � Placeholder Syntax Reference

### Standard Placeholders

| Placeholder | Purpose | Example |
|-------------|---------|---------|
| `{{PROJECT_NAME}}` | Project name | "MyAPI" |
| `{{VERSION}}` | Version number | "1.0.0" |
| `{{TECH_STACK}}` | Technology stack | "python/fastapi" |
| `{{TIER}}` | Project tier | "mvp|core|enterprise" |
| `{{LAST_UPDATED_DATE}}` | Current date | "2025-12-11" |
| `{{SYSTEM_VERSION}}` | Template version | "3.2" |
| `{{MAINTAINER}}` | Project maintainer | "Team Name" |
| `{{LICENSE}}` | License type | "MIT" |

### Conditional Placeholders

```yaml
# Tier-specific
{{#if tier.mvp}}
Minimal implementation
{{/if}}

{{#if tier.enterprise}}
Full security & monitoring
{{/if}}

# Stack-specific
{{#if stack.python}}
requirements.txt
{{/if}}

{{#if stack.flutter}}
pubspec.yaml
{{/if}}
```

---

## 🧪 Validation System

### Running Validation

```bash
# Full validation
python scripts/validate-templates.py --full

# Quick check
python scripts/validate-templates.py --quick

# Specific blueprint
python scripts/validate-templates.py --blueprint documentation

# Specific stack
python scripts/validate-templates.py --stack python
```

### Validation Checks

1. **Schema Compliance**
   - YAML schema validation
   - Required field presence
   - Data type correctness

2. **Template Syntax**
   - Placeholder format
   - Conditional blocks
   - File references

3. **File Structure**
   - Required files exist
   - Directory hierarchy
   - Naming conventions

4. **Link Integrity**
   - Internal links work
   - External references valid
   - No broken paths

5. **Content Quality**
   - Header comments present
   - Main titles exist
   - Documentation complete

### Validation Output

```
=====================================
TEMPLATE VALIDATION SUMMARY
=====================================
Total Files: 746
Validated Files: 746
Errors: 0
Warnings: 10
Broken Links: 0
```

---

## 🔧 Troubleshooting

### Common Issues

#### Template Not Found
```
Error: Template not found: agents/XYZ.md
```
**Solution**: Check if file exists in `blueprints/default-project/overlays/generic/agents/`

#### Invalid Placeholder
```
Error: Invalid placeholder syntax: {PROJECT_NAME}
```
**Solution**: Use double braces: `{{PROJECT_NAME}}`

#### Schema Validation Failed
```
Error: Missing required field: 'name' in blueprint.meta.yaml
```
**Solution**: Add required field to metadata

#### Tier Detection Failed
```
Warning: Could not determine tier for project
```
**Solution**: Check `tier-index.yaml` rules or manually specify tier

### Debug Mode

```bash
# Enable debug output
python scripts/validate-templates.py --full --debug

# Check specific template
python scripts/validate-templates.py --template agents/COPILOT.md
```

### Getting Help

1. Check this guide first
2. Review validation output
3. Search existing issues
4. Create new issue with:
   - Error message
   - Steps to reproduce
   - System info

---

## 📚 Root Files Clarification

### Why Agent Files are in Root

**Root Agent Files (System Documentation)**
- **AIDER.md, CODEX.md, CODY.md, COPILOT.md, CURSOR.md, GEMINI.md, WARP.md, WINDSURF.md**
- **Purpose**: Actual implementation guides for THIS repository
- **Content**: Repo-specific instructions, commands, and patterns
- **Audience**: AI agents working on _templates repo
- **Status**: Active system documentation

**agents/*.tpl.md (Templates)**
- **Purpose**: Templates to COPY to generated projects
- **Content**: Generic agent guide placeholders
- **Audience**: AI agents in GENERATED projects
- **Status**: Templates for customization

**Root AGENTS.md (22KB)**
- **Purpose**: Multi-agent coordination for THIS repository
- **Content**: System-specific rules and coordination
- **Audience**: AI agents working on _templates repo
- **Status**: Active system documentation

**Root CLAUDE.md (39KB)**
- **Purpose**: Claude-specific guide for THIS repository
- **Content**: Repo-specific Claude instructions
- **Audience**: Claude Code users on _templates repo
- **Status**: Active system documentation

### The Pattern

| Location | Type | Example | Purpose |
|----------|------|---------|---------|
| `root/` | System Doc | `AGENTS.md`, `AIDER.md` | Documents THIS repo |
| `agents/` | Template | `AGENTS.tpl.md` | Copied to projects |
| `universal/` | Universal | `AGENTS.md` | Generic template |

**Key Distinction**: Root `.md` files are system documentation, while `agents/*.tpl.md` are templates for generated projects.

---

## �📚 Related Documentation

| Document | Purpose | Link |
|----------|---------|------|
| LLM Entry Point | AI agent starting guide | [LLM-ENTRYPOINT.md](LLM-ENTRYPOINT.md) |
| Template Manifest | Complete template inventory | [blueprints/default-project/overlays/generic/TEMPLATE-MANIFEST.md](blueprints/default-project/overlays/generic/TEMPLATE-MANIFEST.md) |
| Add Blueprints | How to add new blueprints | [ADD-NEW-BLUEPRINT-TEMPLATE.md](ADD-NEW-BLUEPRINT-TEMPLATE.md) |
| Add Stacks | How to add new stacks | [ADD-NEW-STACK-TEMPLATE.md](ADD-NEW-STACK-TEMPLATE.md) |
| Add Tasks | How to add new tasks | [ADD-NEW-TASK-TEMPLATE.md](ADD-NEW-TASK-TEMPLATE.md) |

---

## 🔄 Evolution History

### v3.2 (Current)
- Added blueprint-driven architecture
- 746 templates across 8 stacks
- AI-first design principles
- Comprehensive validation

### v3.1
- Introduced tier system
- Added universal templates
- Improved stack overlays

### v3.0
- Complete restructure
- Blueprint system introduced
- Task-based organization

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Maintainers**: {{MAINTAINER}}  
**License**: {{LICENSE}}

---

*This is meta-documentation about the template system itself. For template documentation that gets copied to projects, see the `blueprints/default-project/overlays/generic/` directory.*
