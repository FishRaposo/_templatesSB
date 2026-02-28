# Skill Setup

Toolkit for creating, editing, converting, and organizing AI agent skills across Claude, Roo Code, Cascade, Cursor, Windsurf, and custom agents. Covers description best practices, instruction patterns, and anti-patterns.

## Overview

**Create** and **edit** skills, **convert** sub-agents/configs to skill format, **organize** packs, **validate** against best practices. Full layout and templates: see `SKILL.md` and `templates/`.

## Quick Start

1. **Create directory** (e.g. `~/.claude/skills/your-skill-name` or `.cursor/skills/your-skill-name`).
2. **Copy** `templates/skill-template.md` → `SKILL.md`, `templates/config-template.json` → `config.json`.
3. **Edit**: `name` (gerund, lowercase, hyphens, max 64 chars), `description` ("Use this skill when..." + triggers, max 1024 chars), required sections (minimum: Core Approach, Step-by-Step, Validation Checklist; see SKILL.md), real examples. Keep SKILL.md under 500 lines.
4. **Validate** (if using the skill-setup scripts): `node scripts/validate-skill.js path/to/skill`.

**Packs:** Use a pack creation guide (e.g. HOW_TO_CREATE_SKILL_PACKS.md) when the project provides one. Projects may use a flat `skills/` directory or a `skill-packs/` layout; follow the project's convention.  
**Walkthrough:** `creating-skills-from-scratch.md`  
**Examples:** `_examples/complete-skill-cli-focused.md`, `_examples/complete-skill-conceptual.md` (or `examples/` per convention)  
**Converting:** `converting-sub-agents-to-skills.md`, `converting-configurations-to-skills.md`

## Platform Paths

| Platform | Global | Project |
|----------|--------|---------|
| Claude | `~/.claude/skills/` | `.claude/skills/` |
| Roo Code | `~/.roo/skills/` | `.roo/skills/` |
| Cascade | `~/.codeium/windsurf/skills/` | `.windsurf/skills/` |
| Cursor | `~/.cursor/skills/` | `.cursor/skills/` |
| Generic | `~/.agent/skills/` | `.agent/skills/` |

**Cursor:** Do not use `~/.cursor/skills-cursor/` (reserved for built-in skills).

## Skill Basics

- **Minimum:** One `SKILL.md` with YAML frontmatter: `name`, `description` only (no `model`, `tools`).
- **Required sections:** Core Approach, Step-by-Step Instructions, Best Practices, Validation Checklist, Troubleshooting, Related Skills, Supporting Files (optional; minimum: Core Approach, Step-by-Step, Validation Checklist — see SKILL.md).
- **config.json:** `agent_support`, `triggers` (keywords, patterns), `requirements` with `"tools": []`.
- **Structure:** `skill-name/SKILL.md`, optional `README.md`, `config.json` (use `templates/config-template.json`; set `"tools": []`), `examples/` or `_examples/` per project convention. Use intention-revealing file names.

Full structure, patterns, anti-patterns, and validation checklist: see `SKILL.md`.

## Reference & Validation

Guides in `reference/`: best practices, platforms, editing, security, Node/CLI patterns. Validation checklist in `SKILL.md`.

## Related Resources

[Agent Skills Standard](https://agentskills.io/) · [Claude Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/) · [Cursor Agent Skills](https://cursor.com/docs/context/skills) · [Roo Code](https://docs.roocode.com/features/skills) · [Windsurf Cascade](https://docs.windsurf.com/windsurf/cascade/skills)
