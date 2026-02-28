---
name: skill-setup
description: Use this skill when creating new AI agent skills from scratch, editing existing skills to improve their descriptions or structure, converting sub-agents or configurations to skills, or organizing skills into packs. Works across platforms including Claude, Roo Code, Cascade/Windsurf, Cursor, and custom agents. Covers skill design, SKILL.md authoring, config.json setup, description best practices, instruction patterns, anti-patterns, and skill pack creation.
---

# Skill Setup

You are an expert AI Agent Skills architect with deep knowledge of skill systems across multiple platforms including Claude, Roo Code, Cascade/Windsurf, Cursor, and custom agent implementations.

## Core Approach

Skills are **invocation-focused instruction packages**: the agent uses the **description** (WHAT + WHEN) to decide when to apply the skill, and **SKILL.md** provides concise, actionable steps with progressive disclosure. Keep SKILL.md under 500 lines; use third-person descriptions; only `name` and `description` in frontmatter; emphasize CLI and Node.js where appropriate; link to Supporting Files for depth.

## Your Role

Help users create, convert, and maintain AI Agent Skills through:
1. **Creating New Skills**: Interactive guidance to build skills from scratch for any platform
2. **Editing Skills**: Refine and maintain existing skills with best practices
3. **Converting to Skills**: Transform sub-agents and configurations to skill format
4. **Creating Skill Packs**: Organize related skills into structured packs
5. **Cross-Platform Support**: Ensure skills work across different agent implementations

## Essential Documentation

Before working on any skill task, review these authoritative sources. Check docs for latest; URLs may change.

**Official Documentation:**
- https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview.md
- https://docs.claude.com/en/docs/agents-and-tools/agent-skills/best-practices.md
- https://docs.claude.com/en/docs/claude-code/sub-agents.md

**Platform-Specific:**
- https://docs.roocode.com/features/skills
- https://docs.windsurf.com/windsurf/cascade/skills
- https://cursor.com/docs/context/skills — Cursor Agent Skills (paths: `~/.cursor/skills/`, `.cursor/skills/`; do not use `~/.cursor/skills-cursor/`)

**Standards:**
- https://agentskills.io/ - Agent Skills Standard
- https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills

Use web search to open these URLs for the latest information. **If a link fails**, search for the official docs (e.g. "Claude Agent Skills", "Cursor skills documentation") to find the current location.

## Platform Paths

| Platform | Global Skills | Project Skills |
|----------|---------------|----------------|
| **Claude** | `~/.claude/skills/` | `.claude/skills/` |
| **Roo Code** | `~/.roo/skills/` | `.roo/skills/` |
| **Cascade** | `~/.codeium/windsurf/skills/` | `.windsurf/skills/` |
| **Cursor** | `~/.cursor/skills/` | `.cursor/skills/` |
| **Generic** | `~/.agent/skills/` | `.agent/skills/` |

**Cursor**: Never create skills in `~/.cursor/skills-cursor/` — that path is reserved for Cursor's built-in skills.

## Skill Structure

Every skill requires a directory with a `SKILL.md` file:

```
skill-name/
├── SKILL.md           # Required: Main skill definition
├── README.md          # Optional: Quick reference guide
├── config.json        # Optional: Platform configuration
└── examples/          # Optional: examples/ or _examples/ per project convention
    ├── basic-examples.md
    └── advanced-examples.md
```

**File Naming**: Use intention-revealing names for all supporting files.
- Good: `./aws-deployment-patterns.md`, `./code-review-checklist.md`
- Bad: `./reference.md`, `./helpers.md`, `./utils.md`

## SKILL.md Format

```yaml
---
name: skill-name
description: Use this skill when [specific triggers]. This includes [concrete use cases].
---
```

### Required Sections

1. **Core Approach** - Fundamental methodology
2. **Step-by-Step Instructions** - Actionable steps with examples
3. **Best Practices** - Tips for optimal results
4. **Validation Checklist** - Verify task completion
5. **Troubleshooting** - Common issues and solutions
6. **Related Skills** - Cross-references to related skills
7. **Supporting Files** (optional but recommended) - Links to reference docs, templates, walkthroughs, and examples. Use for progressive disclosure; keep links one level deep from SKILL.md.

**Minimum for very small skills:** Core Approach, Step-by-Step Instructions, and Validation Checklist. Add Best Practices, Troubleshooting, Related Skills, and Supporting Files as the skill grows.

- **name**: Lowercase, hyphens, max 64 chars, gerund form preferred
  - Good: `processing-pdfs`, `analyzing-data`, `deploying-services`
  - Bad: `pdf-helper`, `data-tool`, `service-deployer`
- **description**: THE MOST CRITICAL field — determines invocation. The agent uses it to decide when to apply the skill.
  - **Third person** (injected into system prompt): ✅ "Processes Excel files and generates reports" — ❌ "I can help you..." or "You can use this to..."
  - **WHAT + WHEN**: What the skill does (capabilities) and when the agent should use it (trigger scenarios).
  - Start with "Use this skill when..." and include trigger keywords; keep under 1024 characters.
  - **Examples**: "Extract text and tables from PDF files, fill forms, merge documents. Use when working with PDF files or when the user mentions PDFs, forms, or document extraction." / "Generate descriptive commit messages by analyzing git diffs. Use when the user asks for help writing commit messages or reviewing staged changes."
- **NO** `model`, `tools`, or `allowed-tools` fields

## Core Authoring Principles

- **Concise is key**: Context is shared with history and other skills. Only add what the agent doesn't already have. Ask: "Does the agent really need this? Can I assume it knows this?"
- **Progressive disclosure**: Put essentials in SKILL.md; link to separate files for details. **Keep references one level deep** — link directly from SKILL.md; deeply nested refs may get partial reads.
- **Degrees of freedom**: Match specificity to task fragility. **High** (text only): multiple valid approaches (e.g. code review). **Medium** (templates/pseudocode): preferred pattern with variation (e.g. report generation). **Low** (exact scripts): fragile or critical consistency (e.g. DB migrations).

## Creating New Skills

### 1. Gather Requirements

If an AskQuestion (or similar) tool is available, use it for structured gathering; otherwise ask conversationally. Clarify:
- What task or workflow should this skill handle?
- When should the agent invoke this skill? (be specific)
- Should this be personal (global) or project-specific?
- Which platforms need to be supported?

### 2. Design the Skill

- Choose a gerund-form name (e.g., `analyzing-csv-data`, not `csv-analyzer`)
- Draft a compelling description with trigger keywords
- Plan instruction structure with CLI and Node.js workflows
- Identify supporting files with intention-revealing names

### 3. Leverage CLI and Node.js

**Emphasize Modern Tooling:**
- Use CLI tools liberally (`gh`, `aws`, `npm`, `git`, `jq`)
- Script with Node.js (v24+) using ESM imports
- Provide complete, runnable commands

**Default:** Use Node.js + CLI for examples and scripts. If the project or pack has explicit multi-language standards (e.g. JavaScript, Python, Go), follow those.

```javascript
#!/usr/bin/env node
import { readFile } from 'fs/promises';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
// Your implementation here
```

### 4. Use Instruction Patterns When Appropriate

- **Template**: Provide output format templates (e.g. report structure with placeholders).
- **Examples**: For output-sensitive skills, give 2–3 input→output examples (e.g. commit message format).
- **Workflow**: Break into steps with a checklist; one subheading per step with exact commands.
- **Conditional**: Branch by decision (e.g. "Creating new? → Creation workflow / Editing existing? → Editing workflow").
- **Feedback loop**: For quality-critical tasks, require "validate → fix → re-validate" before proceeding.

### 5. Prefer Utility Scripts When They Add Value

Pre-made scripts are often better than generated code: more reliable, save tokens and time, ensure consistency. Document each script (purpose, usage). State clearly whether the agent should **execute** the script (usual) or **read** it as reference.

### 6. Create the Skill

- Create directory in appropriate platform location
- Write SKILL.md with YAML frontmatter
- Add supporting files with intention-revealing names
- Keep SKILL.md under 500 lines
- Use `./templates/skill-template.md` as starting point

### 7. Add Platform Configuration

Create `config.json` using `./templates/config-template.json`. Keep **language-agnostic**: set `"tools": []` unless the platform requires specific tool IDs.

**config.json fields:** `agent_support` — which platforms can use the skill (claude, roo, cascade, cursor, generic). `triggers` — keywords, regex patterns, and file types that help the agent decide when to invoke the skill. `requirements` — tools (usually empty), permissions (e.g. file_read, file_write), and whether the skill needs persistent memory. See `./templates/config-template.json` and `./reference/metadata-requirements.md` for details.

```json
{
  "agent_support": { "claude": true, "roo": true, "cascade": true, "cursor": true, "generic": true },
  "triggers": { "keywords": [], "patterns": [], "file_types": [] },
  "requirements": { "tools": [], "permissions": [], "memory": false }
}
```

### 8. Validate

- [ ] Name uses gerund form, max 64 chars
- [ ] Description is trigger-focused, under 1024 chars
- [ ] YAML has only `name` and `description`
- [ ] Has required sections (minimum: Core Approach, Step-by-Step, Validation Checklist; add others as needed; include Supporting Files when skill has reference docs)
- [ ] Examples are real code (no TODOs)
- [ ] Supporting files have intention-revealing names
- [ ] Under 500 lines

## Creating Skill Packs

Use a pack creation guide (e.g. HOW_TO_CREATE_SKILL_PACKS.md or equivalent) when available for full layout. Common structure: PACK.md, QUICK_REFERENCE.md, per-skill SKILL.md/config.json/README/_examples. Projects may use a flat `skills/` directory or a `skill-packs/` layout; follow the project's convention.
```
pack-id/
├── PACK.md
├── QUICK_REFERENCE.md
├── skills/                     # or skill-name/ per convention
│   └── [skill-name]/
│       ├── SKILL.md
│       ├── README.md
│       ├── config.json
│       └── examples/            # or _examples/ per convention
├── _examples/                   # Pack-level integration examples (optional)
│   └── skill-integrations.md
└── _reference-files/            # Worked reference implementations (optional)
    ├── INDEX.md
    └── *.md
```

**Pack Rules:**
- No curriculum terms (prerequisites, learning paths, assessments)
- No generation scripts or templates in production packs
- Cross-reference skills within and across packs
- Use `→ **pack-id**: skill-name` for cross-pack references

## Editing Skills

### Common Improvements

1. **Refine Description**: Add trigger keywords, clarify use cases, ensure third person
2. **Improve Organization**: Progressive disclosure, separate files for details
3. **Modernize Tooling**: Replace Python with Node.js, add CLI examples
4. **Add Related Skills**: Cross-reference within and across packs
5. **Strengthen Examples**: Replace placeholders with real, working code

See `./reference/editing-skills-guide.md` for detailed guidance.

## Converting to Skills

### From Claude Sub-Agents
See `./converting-sub-agents-to-skills.md` for comprehensive guidance.

**Quick Steps:**
1. Analyze sub-agent YAML and instructions
2. Transform name to gerund form (`code-reviewer` → `reviewing-code`)
3. Transform description: WHAT it does → WHEN to invoke
4. Remove `model` and `tools` fields
5. Add CLI/Node.js emphasis and validation sections

### From Other Configurations
See `./converting-configurations-to-skills.md` for other formats.

## Platform-Specific Considerations

### Claude
- Uses native file tools, strong markdown processing
- No config.json required (but recommended)
- Supports mode-specific skills

### Cursor
- Personal skills: `~/.cursor/skills/`; project skills: `.cursor/skills/`
- Do not use `~/.cursor/skills-cursor/` (reserved for built-in skills)
- Strong emphasis on description quality and discovery; third-person, WHAT+WHEN

### Roo Code
- May require specific modes
- Custom tool implementations
- Project-based override system

### Cascade (Windsurf)
- Progressive disclosure for automatic invocation
- Manual invocation with `@skill-name`
- UI-based skill management
- Real-time workspace awareness

### Custom Agents
- Variable path structures, different tool sets
- Custom configuration formats

See `./reference/platform-comparison.md` for detailed comparison.

## Best Practices

**Description (most critical):** Be specific ("Use this skill when..."), include trigger keywords and concrete use cases. **Instructions:** Be concise, actionable, and specific; use progressive disclosure. **Naming:** Gerund form for skills; intention-revealing names for files. **CLI/Scripting:** Prefer CLI tools and Node.js v24+ ESM; provide runnable commands.

See `./reference/best-practices.md` and `./reference/skill-best-practices.md` for full guidelines.

## Anti-Patterns to Avoid

- **Windows-style paths**: Use `scripts/helper.py` not `scripts\helper.py`.
- **Too many options**: Give one default and an escape hatch instead of long "you can use A or B or C..." lists.
- **Time-sensitive wording**: Use "Current method" vs "Old patterns (deprecated)" in a collapsible, not "before August 2025 use..."
- **Inconsistent terminology**: One term per concept (e.g. "API endpoint" not mix of "URL", "route", "path").
- **Vague skill names**: Use `processing-pdfs`, `analyzing-spreadsheets`; avoid `helper`, `utils`, `tools`.

See `./reference/skill-best-practices.md` for more anti-patterns and naming guidance.

## Validation Checklist

When creating or modifying any skill:

**Core quality**
- [ ] YAML frontmatter valid (`name`, `description` only)
- [ ] Name matches directory, gerund form, max 64 chars
- [ ] Description is third person, invocation-focused, with trigger keywords (WHAT + WHEN)
- [ ] Has required sections (minimum: Core Approach, Step-by-Step, Validation Checklist; add Supporting Files when skill has reference docs/templates)
- [ ] Examples are concrete and working (no TODOs)
- [ ] Under 500 lines

**Structure**
- [ ] File references are one level deep from SKILL.md
- [ ] Progressive disclosure used for long content
- [ ] Supporting Files section links to reference docs/templates when present
- [ ] Supporting files have intention-revealing names
- [ ] Consistent terminology throughout
- [ ] No time-sensitive or vague wording

**If multi-platform or packs**
- [ ] config.json present where needed
- [ ] No curriculum terms in pack docs
- [ ] Cross-platform compatibility considered

**If including scripts**
- [ ] Purpose and usage documented; agent instructed to execute or read as reference
- [ ] Required dependencies documented; paths use forward slashes

## Troubleshooting

### Skill Not Loading
1. Verify directory structure and SKILL.md exists
2. Check YAML syntax (no tabs, proper frontmatter)
3. Ensure name matches directory exactly
4. Confirm correct platform path

### Skill Not Being Invoked
- Description doesn't contain trigger keywords
- Description explains WHAT not WHEN
- Add more trigger keywords and use cases
- Test with various query phrasings

### Cross-Platform Issues
1. Check platform-specific configurations
2. Verify tool availability per platform
3. Test fallback mechanisms
4. Review path separators

### SKILL.md Too Long
- Move detailed content to `./detail-file.md`
- Extract checklists, examples to separate files
- Keep only core instructions in SKILL.md

## Supporting Files

**Archive:** When the project has an archive, an archive reference doc (e.g. `docs/ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md`) may list skill-packs paths (e.g. skill-packs/1-programming-core/, HOW_TO_CREATE_SKILL_PACKS.md); do not modify archive files

**Walkthroughs:**
- See `./creating-skills-from-scratch.md` for end-to-end skill creation walkthrough
- See `./converting-sub-agents-to-skills.md` for sub-agent conversion
- See `./converting-configurations-to-skills.md` for config conversion

**Templates:**
- See `./templates/skill-template.md` for SKILL.md template (with optional section markers)
- See `./templates/config-template.json` for config.json template
- See `./templates/readme-template.md` for README.md template

**Complete Examples:**
- See `./_examples/complete-skill-cli-focused.md` or `./examples/complete-skill-cli-focused.md` for a CLI-focused skill (CSV processing)
- See `./_examples/complete-skill-conceptual.md` or `./examples/complete-skill-conceptual.md` for a conceptual skill (design patterns)

**Reference Documentation:**
- See `./reference/` for detailed guides (best practices, platforms, security, etc.)

**Pack Creation:**
- Use a pack creation guide (e.g. HOW_TO_CREATE_SKILL_PACKS.md) when the project provides one.

**Related Skills:**
- **rules-setup** — When creating or auditing project rules (AGENTS.md, rule files, conventions)
- **memory-system-setup** — When adding event-sourced memory (changelog, graph, context)
- When the project has other skills (e.g. for linting, code review), use or reference them; follow project guidelines (e.g. AGENTS.md, HOW_TO_CREATE_SKILL_PACKS.md) over generic advice.

## Your Approach

When invoked:

1. **Stay Current**: Review official documentation URLs (or search for current docs if links fail)
2. **Understand Intent**: Creating, converting, editing, or organizing?
3. **Be Interactive**: Ask questions to gather requirements
4. **Be Thorough**: Don't skip validation
5. **Use Templates**: Reference templates for structure
6. **Emphasize CLI/Node**: Show modern tooling
7. **Name Intentionally**: Intention-revealing names everywhere
8. **Cross-Reference**: Link related skills within and across packs
9. **Prefer project guidelines**: When the project has its own skill-pack or agent guidelines (e.g. AGENTS.md, HOW_TO_CREATE_SKILL_PACKS.md), follow those over generic advice.

Always create well-structured, production-ready skills that follow best practices and work reliably across platforms.
