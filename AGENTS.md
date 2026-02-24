# AGENTS.md

## Agent Operational Principles

**How agents should work on this project:**

### Right Tool for the Job

| Task Type | Tool to Use |
|-----------|-------------|
| Single file, simple edit | `edit` with exact text |
| Pattern matching across files | `run_command` with `sed` or `python` |
| Multi-file batch changes | `skill` tool with sub-agent |
| Complex logic (parsing, generation) | `run_command` with Python script |
| Small file rewrite | `write_to_file` entire file |
| Repository-wide refactoring | Spawn specialized sub-agent |

### Prioritize Sub-Agents Over Direct Work

**Always spawn sub-agents when:**
- Processing multiple files (>3 files)
- Running verification tasks across skills
- Generating reference files (Three-Phase Process)
- Cross-referencing and link validation
- Any task that can run in parallel

**Pattern:**
```
You: "Do X, Y, and Z"
Me: "Spawning 3 sub-agents to work in parallel..."
[Spawn X-agent, Y-agent, Z-agent simultaneously]
"All 3 running. I'll update as they complete."
```

### Write to Files, Not Mental Notes

**If it's worth remembering, write it:**
- Skill decisions → Update relevant SKILL.md
- Project changes → Append to CHANGELOG.md
- Conventions learned → Update this AGENTS.md
- Cross-references found → Update INDEX.md
- Task completion → Update TODO.md

**Rule:** Text > Brain. If you think "I should remember this," write it to a file immediately.

### Spawn and Forget (Keep Conversation Flowing)

**Don't block the conversation waiting for work:**
1. Spawn sub-agent with the task
2. Report to user: "Started, will update when done"
3. Continue the conversation
4. Report back when sub-agent completes

**Anti-pattern:**
❌ "Let me work on this for 10 minutes..."

**Correct pattern:**
✅ "Spawning sub-agent to handle this. While that's running, what else are we working on?"

### Batching Rules

**Parallel (no waiting):**
- Independent skill edits
- Multiple documentation updates
- Cross-reference validations
- File searches and queries

**Serial (must wait):**
- CHANGELOG.md updates (append-only, order matters)
- PACK.md updates after skill creation
- INDEX.md updates after reference file generation
- Any task with dependencies

### Memory System Integration

**Before every task:**
1. Read `AGENTS.md` (this file) — behavioral constraints
2. Check `CHANGELOG.md` — what happened recently
3. Read `.memory/context.md` — current trajectory
4. Query `.memory/graph.md` — find related entities

**After every task:**
1. Append event to `CHANGELOG.md`
2. Update derived views (graph.md, context.md)
3. Commit with descriptive message
4. Update this AGENTS.md if conventions changed

### Text > Brain — No Mental Notes

- **"Remember this"** → Write to `memory/YYYY-MM-DD.md`
- **"This is important"** → Update `MEMORY.md`
- **"I learned X"** → Update relevant SKILL.md or AGENTS.md
- **"Made a mistake"** → Document in CHANGELOG.md so future agents don't repeat

---

## Project Overview

This is a **Skills Repository** — a curated collection of AI agent skill packs organized by domain. Skills are reusable instruction packages (Markdown + JSON) that enable AI coding agents to perform specialized tasks. There is no application code, no build system, and no runtime — the entire project is structured documentation.

- **766 skills** across **60 planned packs** (2 completed, 58 pending)
- **14 categories** covering programming fundamentals through industry verticals
- All content is **Markdown files** and **JSON config files**
- Target audience: AI coding agents (Claude, Copilot, Cursor, Windsurf, Codex, etc.)

## Project Structure

```
_templates/
├── AGENTS.md                     ← You are here (Layer 0: Behavioral Core)
├── CHANGELOG.md                  ← Layer 1: Event Log (append-only, source of truth)
├── TODO.md                       ← Layer 1 Extension: Task Tracker
├── .memory/                      ← Derived views (knowledge graph, narrative)
│   ├── graph.md                  ← Layer 2: Knowledge Graph (materialized from L1)
│   └── context.md                ← Layer 3: Narrative (derived, regenerate per session)
├── README.md                     ← Repo overview
├── SKILLS_MASTER_LIST.md         ← Single source of truth: 766 skills, 60 packs, 14 categories
├── AGENT_SKILLS_GUIDE.md         ← Comprehensive guide to building agent skills
├── ARCHIVE_INDEX.md              ← Index of archived source material
├── skill-packs/
│   ├── HOW_TO_CREATE_SKILL_PACKS.md  ← Step-by-step pack creation guide
│   ├── TASKS-TEMPLATE.md             ← Template for writing verification tasks
│   ├── 1-programming-core/           ← Pack 1: 12 skills, 19 reference files (COMPLETED)
│   │   ├── PACK.md
│   │   ├── QUICK_REFERENCE.md
│   │   ├── <skill>/SKILL.md, config.json, README.md, examples/
│   │   └── reference-files/INDEX.md, TASKS.md, *.md, task-outputs/
│   └── 2-code-quality/               ← Pack 2: 12 skills, 19 reference files (COMPLETED)
│       ├── PACK.md
│       ├── QUICK_REFERENCE.md
│       ├── <skill>/SKILL.md, config.json, README.md, examples/
│       └── reference-files/INDEX.md, TASKS.md, *.md, task-outputs/
├── skill-builder/                ← Standalone skill: creating/editing/converting AI agent skills
│   ├── SKILL.md, config.json, README.md
│   ├── templates/, reference/, scripts/
│   └── _examples/complete-skill-*.md
├── generating-agents-md/         ← Standalone skill: generating and auditing AGENTS.md files
│   ├── SKILL.md, config.json, README.md
│   └── _examples/basic-examples.md, three-pillars-reference.md
├── MEMORY-SYSTEM-PROTOCOL.md     ← Required protocol: event-sourced memory system for multi-agent cognition
├── memory-system/                ← Standalone skill + templates: deploying event-sourced memory to any project
│   ├── SKILL.md, config.json, README.md
│   ├── changelog.md, graph.md, context.md  ← Deployable templates
│   └── _examples/worked-example.md
├── PROMPT-VALIDATION-PROTOCOL.md ← Required protocol: all agents must validate prompts before execution
└── _complete_archive/            ← Previous repo content preserved for reference
    ├── ARCHIVE-DOCUMENTATION-INDEX.md  ← Index of all documentation templates, blueprints, and instructions in the archive
    ├── PROMPT-VALIDATION-SYSTEM-REFERENCE.md  ← Complete reference for the archive's validation system (8 scripts, 4 specs, 3 reports)
    └── PROJECT-MEMORY-SYSTEM-REFERENCE.md  ← Complete reference for the archive's memory, context, state tracking, and project awareness system
```

## Do

- Follow the exact directory structure defined in `skill-packs/HOW_TO_CREATE_SKILL_PACKS.md`
- Use `1-programming-core/` as the gold-standard reference when creating new packs
- Keep all skill descriptions **action-oriented** — focus on what the agent can DO
- Use **minimal YAML frontmatter** in SKILL.md files: only `name` and `description`
- Provide **multi-language examples** (JavaScript, Python, Go minimum) in SKILL.md and examples
- Use **before/after format** (❌/✅) for code examples in `_examples/basic-examples.md`
- Keep config.json **language-agnostic**: always set `"tools": []`
- Use **lowercase with hyphens** for skill names: `data-structures`, `problem-solving`
- Add `<!-- Generated from task-outputs/task-NN-name.md -->` header to reference files
- Preserve all code snippets and technical content when converting task outputs to reference files
- Cross-link reference files from `PACK.md` and `QUICK_REFERENCE.md`
- Keep README.md files under 80 lines — quick-start only, not the full skill definition
- Use `_examples/` (with underscore prefix) for example directories inside skill directories
- Use `_reference-files/` (with underscore prefix) for the reference files directory
- **Update this AGENTS.md** in the same commit when you change project structure, conventions, or add new files/directories
- **Update related documentation** (README.md, SKILLS_MASTER_LIST.md, PACK.md, INDEX.md) when your changes affect their content

## Don't

- Do not add **curriculum or educational content**: no prerequisites, learning paths, estimated times, phases, schedules, assessments, or "after completing this" sections
- Do not add version, tags, or category fields to SKILL.md frontmatter — those are curriculum artifacts
- Do not include theory explanations, history, or background in SKILL.md files
- Do not create overlapping skills — merge or clearly differentiate similar concepts
- Do not use generic skill names like `design` — prefer `api-design`
- Do not include generation scripts, utility files, or build tools in operational packs
- Do not delete raw task outputs in `task-outputs/` — keep them permanently as history
- Do not modify files in `_complete_archive/` — that content is preserved as-is
- Do not add new top-level files or directories without explicit approval
- Do not use educational language like "learn", "study", "practice" — use "invoke", "apply", "use"
- Do not skip documentation updates because "it's a small change" — small drift compounds into major inconsistencies
- Do not rewrite AGENTS.md sections unrelated to your current change
- Do not remove existing rules from this AGENTS.md without explicit approval

## File Types and Conventions

**This project contains only two file types:**
- `.md` — Markdown files (all content, guides, skills, references, examples)
- `.json` — JSON config files (one `config.json` per skill)

**Naming conventions:**
- Skill directories: `kebab-case` (e.g., `clean-code`, `error-handling`)
- Pack directories: `{number}-{kebab-case}` (e.g., `1-programming-core`, `2-code-quality`)
- Reference files: `descriptive-kebab-case.md` (e.g., `sorting-algorithms.md`, `clean-code-patterns.md`)
- Task outputs: `task-{NN}-{skill-name}.md` (e.g., `task-01-clean-code.md`)
- Pack-level files: `UPPER_CASE.md` (e.g., `PACK.md`, `QUICK_REFERENCE.md`, `INDEX.md`, `TASKS.md`)

## Key File Roles

| File | Purpose | One Per |
|------|---------|---------|
| `SKILLS_MASTER_LIST.md` | Single source of truth for all 766 skills | Repo |
| `HOW_TO_CREATE_SKILL_PACKS.md` | Step-by-step pack creation instructions | Repo |
| `TASKS-TEMPLATE.md` | Template for writing verification tasks | Repo |
| `PACK.md` | Pack overview, skill list, relationships, structure tree | Pack |
| `QUICK_REFERENCE.md` | Decision tree, scenarios, skill selection guidance | Pack |
| `SKILL.md` | Full skill definition with instructions and examples | Skill |
| `config.json` | Cross-platform config with triggers and keywords | Skill |
| `README.md` | Quick-start guide (under 80 lines) | Skill |
| `_examples/basic-examples.md` | Runnable before/after code snippets | Skill |
| `_reference-files/INDEX.md` | Categorized index of all reference files | Pack |
| `_reference-files/TASKS.md` | Verification tasks to generate references | Pack |

## Workflows

### Creating a New Skill Pack

Follow `skill-packs/HOW_TO_CREATE_SKILL_PACKS.md` exactly:

1. Create `PACK.md` with overview, skills list, relationships, structure tree, reference files table
2. Create `QUICK_REFERENCE.md` with decision tree, scenarios, skill relationships
3. Create `_examples/skill-integrations.md` showing skills working together
4. For each skill: create `SKILL.md`, `config.json`, `README.md`, `_examples/basic-examples.md`
5. Write verification tasks using `TASKS-TEMPLATE.md` (individual + combined + capstone)
6. Run all tasks, save raw outputs to `_reference-files/task-outputs/`
7. Convert each output into standalone reference file in `_reference-files/`
8. Create `_reference-files/INDEX.md`
9. Cross-link reference files from `PACK.md` and `QUICK_REFERENCE.md`

### Generating Reference Files (Three-Phase Process)

**Phase 1** — Run tasks as fresh agent conversations, save raw outputs to `task-outputs/`
**Phase 2** — Convert each output: remove task language, rename descriptively, rewrite intro, add header comment, save alongside INDEX.md
**Phase 3** — Create/update INDEX.md, cross-link from PACK.md and QUICK_REFERENCE.md

### Creating a SKILL.md

```
---
name: skill-name
description: Use this skill when {specific scenarios}. This includes {capabilities}.
---

# Skill Title

I'll help you {primary benefit}...

# Core Approach
# Step-by-Step Instructions (with multi-language examples)
# Best Practices
# Validation Checklist
# Troubleshooting
# Supporting Files
## Related Skills
```

### Creating a config.json

```json
{
  "agent_support": { "claude": {}, "roo": {}, "cascade": {}, "generic": {} },
  "triggers": { "keywords": ["8-10 terms"], "patterns": ["6-7 regex"] },
  "requirements": { "tools": [], "permissions": ["file_read", "file_write"] },
  "examples": { "simple": ["3 examples"], "complex": ["3 examples"] }
}
```

## Completed Packs (Use as Reference)

- **`1-programming-core/`** — 12 skills, 19 reference files, multi-language (JS/Python/Go/Rust). **Gold standard.**
- **`2-code-quality/`** — 12 skills, 19 reference files, multi-language (JS/Python/Go).

## Boundaries

- ✅ **Always**: Follow the pack structure in `HOW_TO_CREATE_SKILL_PACKS.md`, use Pack 1 as the reference template, keep content action-oriented, **satisfy all Three Pillars (AUTOMATING, TESTING, DOCUMENTING) before considering a task complete**
- ⚠️ **Ask first**: Creating new packs, modifying `SKILLS_MASTER_LIST.md`, changing pack structure conventions, adding new top-level files
- 🚫 **Never**: Add curriculum content, modify `_complete_archive/`, delete task outputs, add build tools or runtime dependencies

## Memory System Protocol

**All agents MUST follow the memory system defined in `MEMORY-SYSTEM-PROTOCOL.md`.** This project uses the memory system — `CHANGELOG.md` is the event log, `.memory/` has the derived knowledge graph and narrative.

- **Layer 0 — Behavioral Core** (`AGENTS.md`): Immutable during execution. Read at boot only.
- **Layer 1 — Event Log** (`CHANGELOG.md`): Append-only source of truth. Every decision, change, and result.
- **Layer 2 — Knowledge Graph** (`.memory/graph.md`): Materialized view of entities and relations. Queryable.
- **Layer 3 — Narrative** (`.memory/context.md`): Derived projection of current trajectory. Ephemeral.

### Agent Lifecycle (Every Task)

```
BOOT:     Read AGENTS.md → Read context.md → Check staleness → Query graph
EXECUTE:  Work within constraints → Append events to CHANGELOG.md
SHUTDOWN: Append → Materialize → Regenerate → Commit → Handoff → Die
```

### Core Rules

1. **Append-only** — if it is not in the event log, it did not happen
2. **One-way data flow** — Event Log → Graph → Narrative; never backward
3. **Stateless agents** — boot from files, execute, write results, die; no retained state
4. **Rebuild, don't repair** — regenerate derived layers from upstream when inconsistent

See `MEMORY-SYSTEM-PROTOCOL.md` for complete schemas, tier scaling, handoff payloads, ACID guarantees, and validation rules.

## Prompt Validation Protocol

**All agents MUST validate user prompts before execution** using `PROMPT-VALIDATION-PROTOCOL.md`. This ensures clarity, completeness, security, and effectiveness.

### Quick Reference

Before any task, run these 4 checks from the protocol:

1. **Purpose in first line** — Can you state what the prompt wants in one sentence?
2. **All variables defined** — Are all `{{`, `[`, `{` placeholders defined?
3. **No dangerous patterns** — No `eval`, `exec`, `rm -rf`, `DROP TABLE`, `sudo`, secrets
4. **Output format specified** — Does the prompt say what output should look like?

If ANY fail, ask for clarification before proceeding.

### Full Protocol

See `PROMPT-VALIDATION-PROTOCOL.md` for:
- Validation Levels (PERMISSIVE / STANDARD / STRICT)
- 27 Security Patterns (blocked injection vectors)
- 5-Dimension Scoring (Clarity, Completeness, Structure, Security, Effectiveness)
- 3-Dimension Checklist (Content, Structure, Technical)
- Type-Specific Checks (Code Gen, Refactoring, Documentation, Analysis, Conversion, Testing, Configuration)
- 4-Step Validation Process
- Common Failures & Fix Patterns
- Validation Log Template
- Grade Calculation (A-F)
- Escalation Criteria
- Integration with Three Pillars

### Integration with Three Pillars

- **AUTOMATING**: Validate prompts before any automated task execution
- **TESTING**: Verify prompt clarity and completeness before starting work
- **DOCUMENTING**: Log validation results when prompts need clarification

## Three Pillars — Every Task Must Satisfy All Three

A task is **not complete** until all three pillars are satisfied:

1. ✅ **AUTOMATING** — Content validates against the project's structural rules
2. ✅ **TESTING** — Skill verification tasks pass, examples are runnable, cross-references resolve
3. ✅ **DOCUMENTING** — This AGENTS.md and related docs are updated if the change affects them

Skipping any pillar = incomplete work.

### Pillar 1: AUTOMATING

After every content change, verify:
- SKILL.md has only `name` and `description` in frontmatter (no curriculum fields)
- config.json is valid JSON with `"tools": []`
- Directory structure matches `HOW_TO_CREATE_SKILL_PACKS.md`
- Reference files have `<!-- Generated from task-outputs/task-NN-name.md -->` headers
- README.md files are under 80 lines
- No educational language ("learn", "study", "practice") — use "invoke", "apply", "use"

### Pillar 2: TESTING

After every content change, verify:
- **New skills**: Skill can be invoked with the trigger keywords in config.json
- **New reference files**: Code snippets are syntactically correct and multi-language (JS/Python/Go)
- **New tasks**: Tasks produce outputs that can be converted to standalone reference files
- **Changed examples**: Before/after code examples are accurate and follow ❌/✅ format
- **Cross-references**: All file paths in `PACK.md`, `QUICK_REFERENCE.md`, and `INDEX.md` point to existing files

### Pillar 3: DOCUMENTING

After completing any task, check whether your changes require documentation updates:

| Change Type | Update These |
|-------------|-------------|
| New skill pack or standalone skill | This AGENTS.md (Project Structure), `SKILLS_MASTER_LIST.md`, `README.md` |
| New skill in existing pack | Pack's `PACK.md`, `QUICK_REFERENCE.md`, `reference-files/INDEX.md` |
| New reference file | Pack's `reference-files/INDEX.md` |
| Completed pack | This AGENTS.md (Completed Packs), `SKILLS_MASTER_LIST.md` |
| New top-level file | This AGENTS.md (Project Structure) |
| Changed conventions | This AGENTS.md (Do/Don't), `HOW_TO_CREATE_SKILL_PACKS.md` |
| New file type or naming convention | This AGENTS.md (File Types and Conventions) |
| New key file role | This AGENTS.md (Key File Roles table) |
| Changed workflow step | This AGENTS.md (Workflows section) |

**How to update:**
1. After completing your primary task, review what changed
2. Update the relevant section(s) in the same commit
3. Keep updates minimal and factual — match the existing style
4. Do not rewrite sections unrelated to your change

## When Stuck

- **Before starting any task**: Run prompt validation using `PROMPT-VALIDATION-PROTOCOL.md` — if it fails the 4 must-pass checks, ask for clarification
- Consult `skill-packs/HOW_TO_CREATE_SKILL_PACKS.md` for structural questions
- Consult `AGENT_SKILLS_GUIDE.md` for skill design principles
- Use `1-programming-core/` as a concrete example of a completed pack
- Use `SKILLS_MASTER_LIST.md` to find which skills belong to which packs
- Use `ARCHIVE_INDEX.md` to locate source material for building new packs
- Use `_complete_archive/ARCHIVE-DOCUMENTATION-INDEX.md` for documentation templates, blueprints, and agent instruction patterns from the archive
- Use `PROMPT-VALIDATION-PROTOCOL.md` for the comprehensive prompt validation protocol (27 security patterns, 5-dimension scoring, 3-dimension checklist, 4-step validation process)
- Use `_complete_archive/PROMPT-VALIDATION-SYSTEM-REFERENCE.md` for the original 8-script validation system (Python implementation details)
- Use `MEMORY-SYSTEM-PROTOCOL.md` for the event-sourced memory system: 4-layer architecture, event log schemas, knowledge graph, agent lifecycle, handoff protocols, ACID guarantees
- Use `_complete_archive/PROJECT-MEMORY-SYSTEM-REFERENCE.md` for the archive's original memory system (predecessor): agent memory rules, execution engine, CONTEXT.md, CHANGELOG.md, TODO.md, WORKFLOW.md, EVALS.md templates
- Use `agents-setup/_examples/three-pillars-reference.md` for Three Pillars multi-stack templates, adaptation patterns, and failure modes
- If unsure about a convention, check how Pack 1 handles it before proposing alternatives
