# Documentation Blueprint

> Universal documentation standards and patterns for the Universal Template System

## Overview

This blueprint defines the **universal documentation style** used across all templates, stacks, tasks, and generated projects in the Universal Template System. It ensures consistency, accessibility, and maintainability of documentation.

## Purpose

- Establish consistent documentation patterns across all components
- Provide templates for agent-specific guides (CLAUDE.md, COPILOT.md, etc.)
- Define documentation structure for generated projects
- Ensure all coding agents can work effectively with the system

## Documentation Hierarchy

```
Project/
├── README.md                 # Main project overview (humans + agents)
├── QUICKSTART.md            # Getting started guide
├── SYSTEM-MAP.md            # Complete architecture reference
│
├── Agent-Specific Guides/   # AI coding assistant guides
│   ├── CLAUDE.md            # Claude Code guide
│   ├── COPILOT.md           # GitHub Copilot guide
│   ├── GEMINI.md            # Google Gemini guide
│   ├── CURSOR.md            # Cursor AI guide
│   ├── CODY.md              # Sourcegraph Cody guide
│   ├── AIDER.md             # Aider guide
│   ├── CODEX.md             # OpenAI GPT/Codex guide
│   ├── WINDSURF.md          # Windsurf/Codeium guide
│   ├── WARP.md              # Warp terminal guide
│   └── AGENTS.md            # Multi-agent coordination
│
├── Technical Documentation/
│   ├── docs/                # Detailed documentation
│   ├── examples/            # Code examples
│   └── guides/              # How-to guides
│
└── Reference/
    ├── API.md               # API documentation
    ├── CHANGELOG.md         # Version history
    └── CONTRIBUTING.md      # Contribution guidelines
```

## Agent Guide Template

Each agent-specific guide MUST include:

### Required Sections

1. **Header Block**
   ```markdown
   # {AGENT}.md - Universal Template System Guide for {Agent Name}
   
   **Purpose**: Guidance for {Agent} when working with this repository.
   **Version**: X.X
   **Last Updated**: YYYY-MM-DD
   ```

2. **Project Overview**
   - System name and purpose
   - Key metrics (tasks, templates, stacks)
   - Current status

3. **Essential Commands**
   - Project generation command
   - Validation commands
   - Common workflows

4. **Architecture Summary**
   - Directory structure
   - Key files and their purposes

5. **Task/Feature Summary**
   - Categories with counts
   - Key examples

6. **Validation Requirements**
   - Pre-commit checks
   - Expected outputs

7. **Agent-Specific Tips**
   - Optimizations for that agent
   - Best practices

8. **Documentation Links**
   - Related files
   - Further reading

### Standard Metrics Block

```yaml
# Include in all agent guides
tasks: 47
templates: 667
stacks: 12
tiers: 3
blueprints: 2
validation: EXCELLENT (0 errors)
status: PRODUCTION READY ✅
```

## Documentation Style Guide

### Formatting Standards

1. **Headers**: Use ATX-style (`#`) headers
2. **Code Blocks**: Always specify language
3. **Tables**: Use for structured data
4. **Lists**: Use for sequential or categorical items
5. **Links**: Use relative paths within repository

### Content Standards

1. **Be Concise**: Agents have context limits
2. **Be Specific**: Include exact paths and commands
3. **Be Current**: Update dates and metrics regularly
4. **Be Consistent**: Follow established patterns

### Visual Hierarchy

```markdown
# Level 1: Main Sections
## Level 2: Subsections
### Level 3: Details
#### Level 4: Rarely used

**Bold** for emphasis
`code` for commands/paths
> Blockquotes for notes
```

## Template Placeholders

Standard placeholders for templates:

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{{PROJECT_NAME}}` | Project name | MyApp |
| `{{STACK}}` | Technology stack | python |
| `{{TIER}}` | Complexity tier | mvp |
| `{{VERSION}}` | Version number | 1.0.0 |
| `{{AUTHOR}}` | Author name | Developer |
| `{{DATE}}` | Current date | 2025-12-11 |

## File Naming Conventions

| Type | Pattern | Example |
|------|---------|---------|
| Agent guides | `{AGENT}.md` (uppercase) | CLAUDE.md |
| Templates | `*.tpl.{ext}` | config.tpl.py |
| Documentation | `*.md` | README.md |
| Configuration | `*.yaml` or `*.yml` | config.yaml |

## Validation Checklist

All documentation must pass:

- [ ] Correct header format
- [ ] Updated metrics
- [ ] Valid internal links
- [ ] Code blocks have language specified
- [ ] Tables are properly formatted
- [ ] Agent-specific sections present
- [ ] Status indicators current

## Integration with Coding Agents

### Supported Agents

| Agent | Guide File | Primary Use |
|-------|------------|-------------|
| Claude | CLAUDE.md | Full-featured coding |
| GitHub Copilot | COPILOT.md | Code completion, chat |
| Google Gemini | GEMINI.md | Code assist |
| Cursor | CURSOR.md | AI-first editor |
| Sourcegraph Cody | CODY.md | Code search + AI |
| Aider | AIDER.md | CLI pair programming |
| OpenAI GPT | CODEX.md | Code generation |
| Windsurf | WINDSURF.md | Codeium editor |
| Warp | WARP.md | AI terminal |
| Multi-agent | AGENTS.md | Coordination |

### Agent Detection

Agents should look for their specific guide file:
1. Check for `{AGENT}.md` in repository root
2. Fall back to `README.md` if not found
3. Reference `SYSTEM-MAP.md` for architecture

## Maintenance

### Update Frequency

- **Metrics**: After any task/template changes
- **Commands**: After script modifications
- **Structure**: After architectural changes
- **Agent guides**: After system updates

### Automation

```bash
# Validate all documentation
python scripts/validate-templates.py --full

# Check documentation links
grep -r "](\./" *.md | head -20
```

---

**Blueprint Version**: 1.0  
**Created**: 2025-12-11  
**Status**: ACTIVE ✅
