---
name: agents-md-setup
description: Use this skill when creating or editing AGENTS.md as the primary rule file for a project. This includes structuring the canonical rule with Project Overview, Tech stack, Commands (prefer scripts), Testing, Code Style, Repository Structure, Boundaries, Safety, Git Workflow, Prompt Validation (4 checks), Three Pillars (AUTOMATING, TESTING, DOCUMENTING), Tool Selection, Subagents, Key References, and When Stuck. Use when setting up or refining the single source of truth for agent behavior. For the full four rule files (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md), use rules-setup. Fits the seven-template-types framework (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols).
---

# AGENTS.md Setup Skill

This skill helps you **create** or **edit** **AGENTS.md** — the **primary rule file** that defines how agents must behave in a project. AGENTS.md is the canonical, tool-agnostic source; other rule files (CLAUDE.md, CURSOR.md, WINDSURF.md) can point to it. When invoked, use the project's existing AGENTS.md (when present) as the reference for structure and core principles.

## Your Role

Help users **create** and **modify** AGENTS.md through:

1. **Creating AGENTS.md from scratch** — Generate a complete AGENTS.md with all core sections, Three Pillars, and Prompt Validation reference, tailored to the project's tech stack and structure
2. **Editing existing AGENTS.md** — Add missing sections, refine commands, strengthen Three Pillars or Prompt Validation, update Key References or Repository Structure
3. **Auditing AGENTS.md** — Check that the primary rule has the required sections and principles; suggest concrete additions or fixes

When invoked, analyze the codebase as needed and produce or update AGENTS.md so it serves as the single source of truth for agent behavior. Do not duplicate full protocol text—link to `docs/protocols/` (e.g. PROMPT-VALIDATION-PROTOCOL.md). For creating the four rule files together, use **rules-setup**.

## Core Approach

AGENTS.md is **the primary rule**: read at agent boot, updated when conventions or structure change. Every effective AGENTS.md should:

- **Put commands early** — Agents reference build/lint/test/format constantly; prefer file-scoped commands and **prefer scripts in `scripts/`** over manual steps
- **Enforce the Three Pillars** — A task is not complete until AUTOMATING (verify with scripts/tools), TESTING (run tests, add regression when needed), and DOCUMENTING (update AGENTS.md and related docs when the change affects them) are satisfied
- **Validate prompts before execution** — Include a Prompt Validation section with the 4 must-pass checks and a link to the full protocol; do not paste the full protocol into AGENTS.md
- **Define clear boundaries** — Always / Ask first / Never (and Safety and Permissions when the tool supports it)
- **Stay scannable** — Use bullet points, tables, code blocks; avoid walls of prose

When the project uses the seven-template-types framework, include a **Project Overview** that names the seven types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols) and points to `AGENTIC-ASSETS-FRAMEWORK.md`. Adapt sections to what the project actually uses (e.g. only Rules + Protocols + Skills, or full template system).

## Reference Structure (from canonical AGENTS.md)

Use the project's AGENTS.md at project root as the **reference implementation**. When creating or auditing, ensure these sections exist and are filled appropriately:

| Section | Purpose |
|--------|---------|
| **Project Overview** | What the repo is; when using the framework: seven template types, current implementation (e.g. Rules, Protocols, Skills only), tech stack summary |
| **Build/Test/Lint Commands** | Concrete commands; prefer scripts over manual steps; file-scoped where possible |
| **Testing** | What to run per change type; do not remove or weaken tests |
| **Code Style Guidelines** | Per-artifact rules (e.g. Skills: SKILL.md structure, config.json; Templates: naming, style) |
| **Repository Structure** | Directory tree with short descriptions; key files (AGENTS.md, CHANGELOG.md, .agents/skills/, docs/protocols/, etc.) |
| **Boundaries** | ✅ Always / ⚠️ Ask first / 🚫 Never |
| **Safety and Permissions** | Allowed without asking; ask first (e.g. package installs, git push) |
| **Git Workflow** | Before commit (validation, JSON check); CHANGELOG append-only; rule file updates when adding/renaming rule files |
| **Memory System Protocol** | When the project uses event-sourced memory: layers (L0–L3), agent lifecycle (BOOT/EXECUTE/SHUTDOWN), link to `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` |
| **Prompt Validation — Before Every Task** | 4 checks: purpose in first line, all variables defined, no dangerous patterns, output format specified; link to full protocol |
| **Three Pillars — Task Completion Checklist** | AUTOMATING (prefer scripts; per-type validation), TESTING (per-type verification), DOCUMENTING (change-type table: what to update when) |
| **Workflows** | How to add a Rule, Protocol, Blueprint, Task, Recipe, Subagent, Skill (when project adopts each type) |
| **Tool Selection** | When to use edit vs script vs subagent |
| **Subagents for Execution** | When to spawn vs not; give clear inputs and deliverables |
| **Right Tool for the Job** | Order: Skills → MCPs → Subagents → External APIs → Standard tools → Brute force |
| **Key References** | Framework, rule files, protocols, skills, scripts (with paths) |
| **When Stuck** | Where to look (AGENTS.md canonical, framework, skills) |

Omit or shorten sections the project does not use (e.g. no Memory System if no `.memory/`).

## Step-by-Step Instructions

### 1. Discover the project

Gather tech stack, structure, and existing rules:

- **Tech stack**: Languages, frameworks, package managers (from package.json, pyproject.toml, go.mod, etc.)
- **Commands**: Build, lint, test, format (from scripts, Makefile, CI)
- **Structure**: Key directories (e.g. `.agents/skills/`, `docs/protocols/`, `scripts/`)
- **Existing AGENTS.md**: If present, read it as the reference; identify missing or weak sections

### 2. Draft or update AGENTS.md

- **If creating**: Start with Project Overview (and seven types + current implementation when using the framework), then Tech stack, then Commands, Testing, Code Style, Repository Structure, Boundaries, Safety, Git Workflow. Add Memory System and Prompt Validation sections if the project has `docs/protocols/` or `.memory/`. Add Three Pillars with a change-type doc table. Add Workflows, Tool Selection, Subagents, Right Tool for the Job, Key References, When Stuck.
- **If editing**: Add or refine the sections that are missing or weak. Ensure Three Pillars and Prompt Validation are present and explicit.
- **Prefer scripts**: In Commands and Boundaries, state that if a task can be done with a script in `scripts/`, use it instead of manual steps. Link to or list actual scripts when they exist.

### 3. Include Prompt Validation (minimal gate)

Add a short section that:

1. States that agents must validate user prompts before execution
2. Lists the 4 must-pass checks (purpose, variables defined, no dangerous patterns, output format)
3. Points to `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` (or project path) for the full process

Do not paste the full protocol into AGENTS.md.

### 4. Include the Three Pillars

Add a **Three Pillars — Task Completion Checklist** section that:

1. **AUTOMATING** — Prefer scripts over manual steps; content validates (e.g. YAML valid, configs valid); per template type what “valid” means when applicable
2. **TESTING** — What to run per change type; do not remove or weaken tests
3. **DOCUMENTING** — Change-type table: for each change type (new feature, new rule file, new protocol, new skill, etc.), which docs to update (e.g. AGENTS.md, CHANGELOG.md, Key References)

Include the completion rule: *A task is not complete until all three pillars are satisfied.*

### 5. Set Boundaries and Safety

- **Boundaries**: ✅ Always (e.g. run validation when scripts exist, prefer scripts, satisfy Three Pillars, update AGENTS.md when conventions change); ⚠️ Ask first (e.g. new template type, archiving, deleting rule files); 🚫 Never (e.g. modify archive, delete task outputs, commit without validation when required, hardcode secrets)
- **Safety and Permissions**: List what the agent may do without asking (read/list, append CHANGELOG, update AGENTS.md when conventions change) and what requires asking (package installs, git push, full build/E2E)

### 6. Key References and When Stuck

- **Key References**: Link to `AGENTIC-ASSETS-FRAMEWORK.md`, AGENTS.md (this file), other rule files, `docs/protocols/`, `.agents/skills/`, and key scripts. Keep paths accurate.
- **When Stuck**: Short bullets for Rules (AGENTS.md canonical), framework, skills, validation.

## Editing AGENTS.md

When modifying an existing AGENTS.md:

- **New convention or structure change** — Add or update the relevant section (Code Style, Repository Structure, Boundaries) and the DOCUMENTING change-type row if needed
- **New command or script** — Add to Build/Test/Lint Commands; reinforce “prefer scripts” in Boundaries or Three Pillars
- **New template type adopted** — Add a workflow “Adding a …” and update Project Overview and Key References
- **New protocol or memory** — Add Memory System or Prompt Validation section (or both); link to `docs/protocols/`; do not duplicate full protocol text
- **New skill or rule file** — Update Key References (and Workflows if adding a rule file); update Key References in all four rule files when adding/renaming a rule file (use **rules-setup** for the other three files)

Re-run any validation the project defines (e.g. JSON for configs) after edits.

## Best Practices

- Use the **project's AGENTS.md** as the reference for section order and depth
- **One source of truth**: AGENTS.md is canonical; other rule files (CLAUDE.md, CURSOR.md, WINDSURF.md) should be thin and point to it—use **rules-setup** to create or update those
- **Prefer scripts**: Explicitly state “prefer scripts in `scripts/` over manual steps” in Commands and Three Pillars
- **Link, don’t duplicate**: Link to `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` and `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md`; do not paste full protocol content into AGENTS.md
- **Change-type table**: Include a DOCUMENTING table that maps change types to “Update these” so agents know what to update after each task
- **Keep it scannable**: Bullet points, tables, code blocks; minimal prose

## Validation Checklist

- [ ] AGENTS.md exists at project root
- [ ] Project Overview present (and seven types + current implementation when using the framework)
- [ ] Build/Test/Lint Commands present; “prefer scripts” stated where applicable
- [ ] Testing section present with per-change-type expectations
- [ ] Repository Structure reflects current layout
- [ ] Boundaries (Always / Ask first / Never) and Safety and Permissions defined
- [ ] Git Workflow includes before-commit checks and CHANGELOG append-only
- [ ] Prompt Validation — Before Every Task: 4 checks + link to full protocol (no full protocol in AGENTS.md)
- [ ] Three Pillars — Task Completion Checklist: AUTOMATING, TESTING, DOCUMENTING with completion rule and change-type doc table
- [ ] Key References and When Stuck sections present; paths correct
- [ ] When the project has memory: Memory System section with link to protocol
- [ ] When the project has multiple rule files: Key References list AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md

## Troubleshooting

**AGENTS.md too long** — Move detailed examples or long checklists to linked docs; keep AGENTS.md to essential rules and links. Some platforms have size limits (e.g. ~32 KiB).

**Agents ignore later sections** — Put the most critical items (Commands, Boundaries, Three Pillars) earlier; keep the file scannable with clear headings.

**Unclear what to update after a change** — Add or expand the DOCUMENTING change-type table in the Three Pillars section so every change type has an “Update these” row.

**Need full four rule files** — Use **rules-setup** to create or update AGENTS.md plus CLAUDE.md, CURSOR.md, WINDSURF.md together; use this skill (agents-md-setup) when focusing only on AGENTS.md.

## Related Skills

- **rules-setup** — Create or update the full Rules template type (AGENTS.md + CLAUDE.md, CURSOR.md, WINDSURF.md); use when you need all four rule files or tool-specific entries
- **prompt-validation-setup** — Install or maintain the Prompt Validation Protocol in `docs/protocols/`; use when the project needs the protocol file so AGENTS.md can link to it
- **memory-system-setup** — Set up event-sourced memory (CHANGELOG, .memory/, protocol); use when the project uses memory so AGENTS.md can reference the Memory System Protocol
- **protocol-setup** — Create or audit the Protocols template type and protocol skills; use when adding new process documents AGENTS.md should reference

## Supporting Files

- **Reference implementation:** The project's `AGENTS.md` at project root (when present) — use as the structural and content reference for this skill
- **Framework:** `AGENTIC-ASSETS-FRAMEWORK.md` at project root (when present) — Rules template type, seven types, Key Files
- **rules-setup:** `.agents/skills/rules-setup/` — Full rule-file generation (AGENTS.md + thin CLAUDE.md, CURSOR.md, WINDSURF.md), six core areas, Three Pillars detail, Prompt Validation appendix
- **Protocols:** `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`, `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` (when present) — link from AGENTS.md; do not duplicate
