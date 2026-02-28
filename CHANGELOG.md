# CHANGELOG

## 2026-02-27 - Suggestions for new templates document

### Summary
- Added a document with concrete suggestions for new templates across all seven types: Skills, Tasks, Blueprints, Subagents, Rules, Recipes, and Protocols.

### Added
- **docs/SUGGESTIONS-FOR-NEW-TEMPLATES.md** — Suggestions for: Skills (changelog, git, API design, testing, security, refactor, docs, dependencies); Tasks (billing, email, upload, rate limit, audit, feature flags, search, multi-tenant, health, OpenAPI); Blueprints (API-first, mobile+API, internal tools, data consumer, docs site, event-driven); Subagents (code reviewer, testing, docs, devops, security, refactor); Rules (extra tool entries, frontend/backend/docs/security scopes); Recipes (observability, payments, content/notifications, multi-tenant, search, launch-readiness); Protocols (security review, changelog/events, branching/release, documentation, rollback/incident). Includes cross-type summary and suggested implementation order.

### Changed
- **docs/INDEX.md**: Quick Reference row and Core Documentation section for SUGGESTIONS-FOR-NEW-TEMPLATES.md.

### Rationale
- Single place for contributors and adopters to find ideas when extending the template ecosystem; covers all seven types and points to skill-setup and framework docs.

---

## 2026-02-27 - Templates system overview document

### Summary
- Added a single-document full overview of all seven template types and linked it from the docs index. Corrected framework wording from "six" to "seven" template types.

### Added
- **docs/TEMPLATES-SYSTEM-OVERVIEW.md** — Overview of Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols: purpose, format, location, key files, when to use, question answered; relationship diagram; comparison table; file layout; implementation status in this repo; quick reference by need.

### Changed
- **AGENTIC-ASSETS-FRAMEWORK.md**: "six complementary template types" → "seven complementary template types" in Overview.
- **docs/INDEX.md**: Quick Reference table row for TEMPLATES-SYSTEM-OVERVIEW.md; new section "TEMPLATES-SYSTEM-OVERVIEW.md" under Core Documentation with purpose and related docs.

### Rationale
- One place to see all seven types and how they fit together without reading the full framework. Supports contributors and adopters; DOCUMENTING pillar satisfied.

---

## 2026-02-26 - Documentation accuracy pass

### Summary
- Updated all documentation to match the actual repository layout: no top-level `blueprints/`, `tasks/`, `recipes/`, `subagents/`, `scripts/`, or `memory-system/`; memory system reference lives under `docs/memory-system/`; root dirs are `.agents/`, `.memory/`, `docs/`, `plans/`, `_documentation-blueprint/`, `_complete_archive/`.

### Changed — Documentation
- **CURRENT-REPOSITORY-STATE.md**: Directory structure now lists actual root dirs and all seven skills; moved memory-system to `docs/memory-system/`; removed root-level features/ and workflows/; clarified scripts/ and archive; updated Usage Statistics and Workflow Integration; single-line footer.
- **README.md**: Repository structure tree updated to actual layout; added CURRENT-REPOSITORY-STATE.md, .memory/, plans/, _documentation-blueprint/; validation and create-task/blueprint steps note "when present"; Key Documentation table includes CURRENT-REPOSITORY-STATE.md.
- **AGENTS.md**: Repository structure tree updated (same as above); added CURRENT-REPOSITORY-STATE.md, .memory/, docs note, plans/, _documentation-blueprint/; blueprints/tasks/recipes/subagents/scripts as single line "when present or archived".
- **CLAUDE.md**, **Cursor.md**, **WINDSURF.md**: Directory overviews updated to list all seven skills and actual root dirs; scripts/ and template dirs marked "when present or archived".
- **docs/INDEX.md**: MEMORY-SYSTEM-PROTOCOL Related fixed to `memory-system/` (docs) and `../.memory/`; Supporting Directories add memory-system/ and MEMORY_SYSTEM.md note; For System Integration add memory-system-setup skill; footer points to CURRENT-REPOSITORY-STATE.md.

### Rationale
- Docs had described root-level directories (e.g. memory-system/, features/, scripts/) that do not exist in this repo, and undercounted or omitted docs/ and other real dirs. Aligning docs with reality avoids confusion and wrong paths.

---

## 2026-02-26 - Move Skills into .agents/skills/ and Merge

### Summary
- Moved the root **skills/** folder into **.agents/skills/** so all agent assets live under `.agents/` with **skills** as a subfolder. Removed the duplicate skill folders that were directly under `.agents/` from the earlier local install. Root **skills/** deleted.

### Changed — Structure
- **Before:** `skills/` (seven skills at repo root) and `.agents/` (copy of seven skills as direct children).
- **After:** `.agents/skills/` only — seven skills (memory-system-setup, rules-setup, skill-builder, blueprints-setup, tasks-setup, recipes-setup, subagents-setup) live under `.agents/skills/`. No root `skills/` folder.

### Changed — Documentation (all references `skills/` → `.agents/skills/`)
- **AGENTS.md**: Current implementation, repository structure, count command, Boundaries, Workflows, Key References, Skills paths.
- **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md**: Current implementation, structure tree, New skill row, Skills row, Key Files.
- **README.md**: Current skills, structure tree, Create a Skill, DOCUMENTING, Key Documentation table, Skills row.
- **AGENTIC-ASSETS-FRAMEWORK.md**: Implementation status, Location, Current skills, table Location row, directory tree.
- **CURRENT-REPOSITORY-STATE.md**: Implementation, structure tree, rules-setup/skill-builder paths, skill packs note, scripts path, Skill builder and Current skills.
- **docs/INDEX.md**: Skill Builder location, Related, For Development.

### Rationale
- Single place for agent assets: `.agents/` with `skills/` as subfolder. Tools that read project-local skills can use `.agents/skills/`; Cursor also uses `~/.cursor/skills/` when skills are installed globally.

---

## 2026-02-26 - Local Skills in .agents

### Added
- **`.agents/`** — Project-local copy of all seven skills (memory-system-setup, rules-setup, skill-builder, blueprints-setup, tasks-setup, recipes-setup, subagents-setup). Same content as `skills/`; use for tools or workflows that read skills from a project-local path (e.g. `.agents/` instead of or in addition to `~/.cursor/skills/` or `skills/`).

### Changed
- **AGENTS.md**: Repository structure now includes `.agents/` (local skills); Key References note both `skills/` (source) and `.agents/` (local copy).

### Rationale
- Some agents or tools expect skills under a project folder (e.g. `.agents`). Installing the same seven skills in `.agents/` keeps this repo usable as both the canonical source (`skills/`) and a project with local skills (`.agents/`).

---

## 2026-02-26 - Repository-Agnostic Skills + Global Install

### Summary
- Made all seven skills **repository-agnostic**: removed hardcoded paths (e.g. `../../AGENTS.md`, `_complete_archive/`, `docs/ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md`). Skills now refer to "the project's X at project root (when present)" and "when the project has an archive, an archive reference doc may…". Installed updated skills to global Cursor skills folder.

### Changed — All skills (repository-agnostic)
- **blueprints-setup:** Framework and archive references use "project root (when present)" and "when the project has an archive"; Supporting Files describe by role, not repo-specific paths. "This repo" → "The project."
- **tasks-setup:** Same pattern; task-index format from "project's existing task-index or archive reference doc."
- **recipes-setup:** "In this repo" / "This repo" → "The project"; Supporting Files agnostic.
- **subagents-setup:** "In this repo, seven skills" → "Subagent skill lists may reference project-specific or archived content; resolve to the current project layout." Supporting Files agnostic.
- **rules-setup:** "This repository's AGENTS.md" → "The project's AGENTS.md at project root (when present)." Supporting Files: archive optional, reference implementation = project's AGENTS.md, framework = project's AGENTIC-ASSETS-FRAMEWORK.md, protocol = project root or docs/protocols/. Removed `../../` and `_complete_archive/` paths. Prompt validation note now "project root or docs/protocols/; point to the project's actual path."
- **skill-builder:** "This repo uses a flat skills/" → "Projects may use a flat skills/ or skill-packs/; follow the project's convention." Archive Supporting Files: "when the project has an archive, an archive reference doc may list skill-packs paths."
- **memory-system-setup:** Supporting Files: "When the project has an archive, a memory system reference may exist there;" removed repo-specific archive path.

### Changed — READMEs
- **rules-setup/README.md:** References section uses "The project's AGENTIC-ASSETS-FRAMEWORK.md" and "project root or docs/protocols/."
- **skill-builder/README.md:** "This repo does not currently ship…" → "Projects may use a flat skills/ or skill-packs/; follow the project's convention."

### Global install
- All seven skills synced to `%USERPROFILE%\.cursor\skills\` (memory-system-setup, rules-setup, skill-builder, blueprints-setup, tasks-setup, recipes-setup, subagents-setup). SKILL.md and README.md overwritten with repo-agnostic versions.

### Rationale
- Skills work in any repository; paths are relative to "project root" or "the project"; archive is optional and described by role. Global install ensures Cursor uses the same repo-agnostic skills everywhere.

---

## 2026-02-26 - Use Archive as Reference for All Template Types

### Summary
- Added a single **archive reference** doc and wired all seven template-type skills to use the archive as the reference when building or auditing. Archive content is read-only; skills now point to concrete archive paths and key files.

### Added
- **docs/ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md** — Central index for using `_complete_archive/` when working with each template type: Rules (AGENTS.md, DOCUMENTATION-BLUEPRINT, ADD-NEW-*); Blueprints (ADD-NEW-BLUEPRINT-TEMPLATE.md, blueprints/mins/, saas-api, web-dashboard); Tasks (task-index.yaml, ADD-NEW-TASK-TEMPLATE.md, tasks/auth-basic/); Recipes (framework only; no recipes/ in archive); Subagents (framework + workflows/); Skills (skill-packs/1-programming-core, 2-code-quality, HOW_TO_CREATE_SKILL_PACKS); Memory (PROJECT-MEMORY-SYSTEM-REFERENCE.md). Includes quick lookup table and explicit "do not modify archive" note.

### Changed — Skills (Supporting Files + in-body references)
- **blueprints-setup**: Supporting Files now include `docs/ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md`, archive ADD-NEW-BLUEPRINT-TEMPLATE.md path, and archive MINS blueprint path. Step 2 references archive MINS blueprint.meta.yaml for real-world schema.
- **tasks-setup**: Supporting Files now include archive reference doc, archive task-index.yaml and auth-basic paths, ADD-NEW-TASK-TEMPLATE.md. Step 6 references archive task-index format (web-scraping, auth-basic).
- **recipes-setup**: Supporting Files now include archive reference doc; notes that Recipes are framework-defined and archive has no recipes/ directory.
- **subagents-setup**: Supporting Files now include archive reference doc; notes framework + workflow schema in archive.
- **rules-setup**: Supporting Files now lead with archive reference doc for Rules (AGENTS.md, DOCUMENTATION-BLUEPRINT, etc.).
- **skill-builder**: Supporting Files now include archive reference doc and skill-packs paths (1-programming-core, 2-code-quality, HOW_TO_CREATE_SKILL_PACKS).
- **memory-system-setup**: Supporting Files now include archive reference doc and PROJECT-MEMORY-SYSTEM-REFERENCE.md path.

### Changed — Docs
- **docs/INDEX.md**: Added row for ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md in Quick Reference table.

### Rationale
- One place to look when building or auditing any template type; archive is the single source of truth for structure, schemas, and examples. Skills stay aligned with framework and archive without modifying archive files.

---

## 2026-02-26 - Skills for All Six Template Types

### Added — New skills (one per template type)
- **blueprints-setup** — Create, edit, or audit Blueprints (product archetypes): blueprint.meta.yaml, BLUEPRINT.md, overlays per stack. Location: `skills/blueprints-setup/`.
- **tasks-setup** — Create, edit, or audit Tasks (implementation units): TASK.md, config.yaml, universal/ and stacks/ implementations, task-index.yaml. Location: `skills/tasks-setup/`.
- **recipes-setup** — Create, edit, or audit Recipes (feature combinations): recipe.yaml, RECIPE.md, task/skill bundles, blueprint compatibility. Location: `skills/recipes-setup/`.
- **subagents-setup** — Create, edit, or audit Subagents (configured workers): subagent.yaml, SUBAGENT.md, workflows/, skills and blueprint compatibility. Location: `skills/subagents-setup/`.

Each new skill includes SKILL.md (Core Approach, Step-by-Step, Validation Checklist, Best Practices, Troubleshooting, Related Skills, Supporting Files) and config.json (triggers, requirements, examples), aligned with skill-builder standards.

### Changed — Documentation
- **AGENTS.md**: "Three Skills" → "seven Skills"; added blueprints-setup, tasks-setup, recipes-setup, subagents-setup to repository structure and Key References.
- **AGENTIC-ASSETS-FRAMEWORK.md**: "three current skills" → "seven current skills" and listed all seven; table Location row updated.
- **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md**: Current implementation now lists seven skills.
- **CURRENT-REPOSITORY-STATE.md**: "three Skills" → "seven Skills" with full list.
- **README.md**: "three skills" → "seven skills" in Create a Skill.
- **skills/skill-builder/SKILL.md**: Flat skills directory now "seven skills" with names.
- **skills/recipes-setup/SKILL.md**, **skills/subagents-setup/SKILL.md**: Troubleshooting text updated to "seven skills".
- **.memory/context.md**: Active Mission updated to seven Skills with names.

### Rationale
- One skill per template type (Rules → rules-setup, Blueprints → blueprints-setup, Tasks → tasks-setup, Recipes → recipes-setup, Subagents → subagents-setup, Skills → skill-builder) so agents can create or audit any of the six types. memory-system-setup remains the seventh skill (memory system, not a template type).

**Synced to global Cursor skills:** All four new skills copied to `%USERPROFILE%\.cursor\skills\`; skill-builder SKILL.md updated there as well.

---

## 2026-02-26 - Skills Audit Against Skill-Builder Standards

### Summary
- Audited all three skills (**memory-system-setup**, **rules-setup**, **skill-builder**) against the skill-builder SKILL.md standards and validation checklist. Recorded results in **docs/SKILLS-AUDIT-SKILL-BUILDER-2026-02-26.md**.

### Changed — rules-setup
- **SKILL.md**: Opening paragraph changed from first person ("I'll help you… When you invoke this skill, I can analyze your…") to third person ("This skill creates and maintains… When invoked, it can analyze the codebase…"). Added note that SKILL.md exceeds the 500-line guideline by design (embedded Prompt Validation Protocol appendix) and directing readers to main sections and Supporting Files for quick reference.
- **config.json**: Added `"memory": false` under `requirements` to align with skill-builder standards.

### Changed — skill-builder
- **SKILL.md**: Added **Core Approach** section (invocation-focused instruction packages, description for WHAT + WHEN, SKILL.md under 500 lines, third person, frontmatter only, Supporting Files for depth) for self-consistency.

### Unchanged — memory-system-setup
- Already compliant; no edits.

### Rationale
- Ensures all skills satisfy the skill-builder checklist (frontmatter, description, required sections, config.json, line-count guideline or documented exception). rules-setup 500-line exception is intentional (single-file protocol reference).

### Synced to global Cursor skills
- Applied the same fixes to **%USERPROFILE%\\.cursor\\skills\\**: `rules-setup` (SKILL.md + config.json), `skill-builder` (SKILL.md). `memory-system-setup` was already compliant; full directory synced for parity.

---

## 2026-02-26 - Implement All Rules Audit Fixes and Improvements

### Added — AGENTS.md
- **Safety and Permissions**: New section after Boundaries. **Allowed without asking**: read/list files, validate JSON, file-scoped lint/format/type-check, append CHANGELOG, update rule files when conventions change, create/edit in skills/, docs/ per Boundaries. **Ask first**: new template type or top-level script, validation logic changes, archiving to _complete_archive/, deleting/renaming rule files, package installs, git push/force, full build or E2E when not requested.
- **Change-type documentation table**: Under Three Pillars DOCUMENTING, added **By change type** table (new rule file, new skill, new blueprint/task/recipe/subagent, conventions change) mapping each to required doc updates, plus **How to update** paragraph.

### Changed — Thin rule files and rules-setup skill
- **CLAUDE.md, CURSOR.md, WINDSURF.md**: Canonical/source line updated to list **Safety and Permissions** and **Three Pillars (with change-type doc table)** among AGENTS.md contents.
- **skills/rules-setup/SKILL.md**: Supporting Files reference implementation bullet updated to include Safety and Permissions and change-type doc table.
- **docs/RULES-AUDIT-2026-02-26.md**: Implementation status note added for both optional improvements.

### Rationale
- Completes the optional improvements from the rules-setup audit so AGENTS.md fully satisfies the skill checklist (Safety permissions + change-type table).

---

## 2026-02-26 - Documentation Accuracy Pass

### Summary
- Verified documentation against actual repo state. This repo **does not include** a top-level `scripts/` directory (no validate-templates.py, setup-project.py, blueprint_config.py, task_resolver.py). Those are framework/archived reference. Protocol files live under `docs/protocols/`. AGENTS.md is at project root; skills live under `skills/`.

### Changed — Rule files & README
- **AGENTS.md**: Tech stack validation note — "This repo does not currently include a top-level scripts/ with that script"; Build commands qualified with "When the project includes a scripts/ directory"; Skills count command uses `skills` not `skill-packs`; Testing, Boundaries, Git Workflow, When Stuck validation steps qualified with "when the project includes scripts/validate-templates.py"; Key References use `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` and `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md`; repository structure notes scripts/ optional and not present.
- **CLAUDE.md**: Templates & Blueprints commands qualified; Key Files protocol paths → docs/protocols/; When Stuck and Critical Policies validation qualified.
- **CURSOR.md**, **WINDSURF.md**: Validate/setup commands qualified with "When the project includes scripts/"; Validation When Stuck qualified.
- **README.md**: Validate and Generate sections qualified; protocol paths already used docs/protocols/; Validation When Stuck qualified.

### Changed — Other docs
- **docs/INDEX.md**: AGENTS.md location set to project root (`../`); Skill Builder to `../skills/skill-builder/`; For New Users and For Development paths fixed.
- **docs/THREE_PILLARS.md**: Prompt validation reference → `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`.
- **CURRENT-REPOSITORY-STATE.md**: Directory overview — scripts/ "Not present at root"; scripts section replaced with note that top-level scripts/ is not present and list of current automation (memory-system/scripts/, skills/skill-builder/scripts/); workflows/ and features/ marked not present; System Capabilities (Skill Development, Template System, Automation) updated to match current state.

### Rationale
- Avoid misleading users into running commands that would fail (scripts not present). Keep protocol paths consistent (docs/protocols/). Align INDEX and CURRENT-REPOSITORY-STATE with actual paths and contents.

---

## 2026-02-26 - Archive Clarification; Remove Outdated Implementation Claims

### Summary
- Removed all mentions of implemented six-template-type content (766 skills, 60 packs, 47 tasks, 1-programming-core, 2-code-quality, SKILLS_MASTER_LIST, HOW_TO_CREATE_SKILL_PACKS, etc.). Only **Rules** (four rule files) and **three Skills** are current: **memory-system-setup**, **rules-setup**, **skill-builder** (under `skills/`). Blueprints, Tasks, Recipes, Subagents, and legacy skill-packs are **archived**; the framework still defines all six types for reference.

### Changed — Rule files & README
- **AGENTS.md**: Replaced statistics with "Current implementation in this repo" (Rules + three skills); repository structure now shows `skills/` with the three skills and marks blueprints/tasks/recipes/subagents as archived; DOCUMENTING pillar and Key References point to `skills/` and the three skills; When Stuck updated; Workflows intro notes only Rules and three skills are active.
- **CLAUDE.md**: Removed Statistics; Architecture simplified (Blueprints, Tasks, Recipes, Subagents archived; Skills current with `skills/` and three names); Key Files and When Stuck point to `skills/`; DOCUMENTING updated.
- **CURSOR.md**, **WINDSURF.md**: Added current-implementation note; repository structure shows `skills/` and archived types; Key Files and When Stuck updated.
- **README.md**: Six-pillar section marks Blueprints/Tasks/Recipes/Subagents as archived and Skills as current (three in `skills/`); repository structure updated; Create a Skill points to `skills/skill-builder/`; DOCUMENTING, Key Documentation, Statistics → "Current Implementation" table, When Stuck updated.

### Changed — Framework & docs
- **AGENTIC-ASSETS-FRAMEWORK.md**: Added "Implementation status in this repo" (Rules + three skills active; rest archived); Skills section Location → `skills/` and current three skills; Examples → memory-system-setup, rules-setup, skill-builder; Rules/Skills/Subagents table and directory overview use `skills/` and three skills; removed 1-programming-core/2-code-quality from directory tree.
- **CURRENT-REPOSITORY-STATE.md**: Purpose and current-implementation note at top; directory overview shows `skills/` (3); rules-setup and skill-builder described under skills/; skill-packs section replaced with "archived"; blueprints marked archived.
- **docs/THREE_PILLARS.md**: Structure validation no longer references HOW_TO_CREATE_SKILL_PACKS; DOCUMENTING table references `skills/` and optional packs.

### Changed — skills/skill-builder
- **README.md**, **SKILL.md**: Pack creation guide referenced as "when the project provides one"; note that this repo uses flat `skills/` with three skills.
- **creating-skills-from-scratch.md**, **_examples/complete-skill-conceptual.md**: References to 2-code-quality replaced with generic "code quality / structure skill in the project when available".

### Rationale
- Align documentation with actual state: no active implementations of Blueprints, Tasks, Recipes, Subagents, or legacy skill-packs; only Rules and the three skills (memory-system-setup, rules-setup, skill-builder) are maintained. The six template types remain defined in the framework for reference and future use.

---

## 2026-02-26 - Execution and Tool Guidelines in Rules System

### Added — AGENTS.md
- **Subagents for execution**: Main session for strategy and decisions; spawn subagents for implementation, research, coding, analysis. Spawn when: research, code review, long-running or parallelizable tasks, independent analysis. Don't spawn for: simple lookups, highly context-dependent or creative collaboration, or when the human needs to iterate live. Give clear inputs and deliverables; synthesize subagent results for the human.
- **Right tool for the job**: Ordered preference — (1) Skills (check SKILL.md before coding), (2) MCPs (verify before installing), (3) Subagents, (4) External APIs (web_search, web_fetch, browser), (5) Standard tools (file ops, exec; prefer scripts), (6) Brute force last (no manual parsing/loops when a tool exists).

### Changed — Thin rule files
- **CLAUDE.md, CURSOR.md, WINDSURF.md**: Canonical/source line updated to list **Tool Selection**, **Subagents for execution**, **Right tool for the job** among AGENTS.md contents.

### Changed — rules-setup skill
- **SKILL.md**: "When the project uses the six-template-types framework" paragraph and Supporting Files reference-implementation bullet now include **Subagents for execution** and **Right tool for the job** in the AGENTS.md structure to generate.

### Rationale
- Execution and tool-selection behavior is codified in the rules system and propagated to thin rule files and the rules-setup skill so new projects can adopt the same guidelines.

---

## 2026-02-26 - Integrate Rules-Setup Skill Improvements into System; Align Skill to AGENTS.md

### Changed — AGENTS.md (current system)
- **Tech stack**: Added **Tech stack (this repo)** under Project Overview (languages, framework, validation, key tools).
- **Commands**: Added line **Prefer scripts over manual steps** with pointer to `scripts/` (e.g. validate-templates.py).
- **Testing**: New **Testing** section — template system validation, skills JSON/examples, per-change-type expectations (task/blueprint/skill), do not remove tests.
- **Boundaries**: New **Boundaries** section — Always (validate before commit, prefer scripts, Three Pillars, CHANGELOG, update rule files); Ask first (new template type, validation changes, archive moves); Never (_complete_archive, task-outputs, commit without validation, remove tests, secrets).
- **Git Workflow**: New **Git Workflow** section — run validate-templates.py before commit when relevant; CHANGELOG append-only; rule file updates; branches.
- **Prompt Validation — Before Every Task**: New section before Three Pillars — 4 must-pass checks (purpose, variables, no dangerous patterns, output format); pointer to PROMPT-VALIDATION-PROTOCOL.md.

### Changed — rules-setup skill
- **Minimal structure** (Step 2): Added **Testing** section; added **Prompt Validation — Before Every Task** (4 checks) before Three Pillars; added "Prefer scripts" under Commands; Three Pillars block now includes "Prefer scripts" in AUTOMATING and "other rule files" in DOCUMENTING.
- **Why each section**: Added rows for Testing, Prompt Validation, Git Workflow; added paragraph **When the project uses the six-template-types framework** with full section list and pointer to this repo's AGENTS.md as reference implementation.
- **Validation checklist**: Added **Testing section**; **Git workflow**; **Prompt Validation — Before Every Task** with 4 checks; **prefer scripts** in Commands; DOCUMENTING now "AGENTS.md and other rule files"; change-type table marked optional but recommended.
- **Supporting Files**: First bullet is **Reference implementation** pointing to `../AGENTS.md` with full structure list.

### Rationale
- System and skill are aligned: AGENTS.md implements the six core areas plus Tech Stack, Boundaries, Testing, Git Workflow, and Prompt Validation; the skill teaches that structure and uses this repo's AGENTS.md as the reference.

### Added
- **rules-setup skill** (`skills/rules-setup/`): Rework of the former agents-setup skill to fit the six-template-types framework.
  - **Scope**: Rules template type — AGENTS.md (canonical) + CLAUDE.md, CURSOR.md, WINDSURF.md; all ALL CAPS at project root.
  - **Content**: Three Pillars with AUTOMATING including "prefer scripts over manual steps"; Prompt Validation; six core areas; thin tool-specific files that point to AGENTS.md.
  - **Section 10** renamed to "Set Up the Four Rule Files (Rules Template Type)" with examples for each of the four files and optional .cursor/rules.
  - Discovery step and validation checklist updated for ALL CAPS rule filenames; troubleshooting "Cross-Tool Inconsistency" updated to four rule files; Supporting Files reference AGENTIC-ASSETS-FRAMEWORK.md.
- **config.json**: name `rules-setup`, keywords (CURSOR.md, WINDSURF.md, rule files, four rule files, Rules template), examples aligned to four-rule-file setup.
- **README**: Rules Setup Skill, four rule files, prefer scripts, ALL CAPS, pointer to framework.

### Changed
- **CHANGELOG**, **CURRENT-REPOSITORY-STATE.md**, **docs/INDEX.md**: References to agents-setup updated to rules-setup.

### Removed
- **agents-setup** skill folder — replaced by **rules-setup** (single source).

### Rationale
- Align the skill with the current system: Rules as a template type, four rule files in ALL CAPS, prefer scripts in AUTOMATING, and thin tool files.

---

## 2026-02-26 - Rule Files Named in ALL CAPS

### Changed
- **WINDSURF.md**: Internal title updated from `# Windsurf.md` to `# WINDSURF.md`.
- **AGENTIC-ASSETS-FRAMEWORK.md**: Rules section — Location now states rule files at project root use **ALL CAPS** filenames; Characteristics list this as first bullet; "Adding a Rule File" workflow already used CURSOR.md/WINDSURF.md as examples.
- **AGENTS.md**: Workflow "Adding a Rule File" — new rule file example set to `MYTOOL.md` and explicit note to use ALL CAPS (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md).

### Rationale
- All rule files (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md) are named in caps; document the convention so new rule files follow it.

---

## 2026-02-26 - Standardize CURSOR.md (all caps)

### Changed
- All references to `Cursor.md` updated to **CURSOR.md** for consistency with AGENTS.md, CLAUDE.md, WINDSURF.md.
- **AGENTS.md, CLAUDE.md, WINDSURF.md, README.md, AGENTIC-ASSETS-FRAMEWORK.md, CHANGELOG.md, CURSOR.md**: Filename and in-doc references now use CURSOR.md.

### Rationale
- Rule files use all-caps naming (AGENTS.md, CLAUDE.md, WINDSURF.md); CURSOR.md aligned to same convention.

---

## 2026-02-26 - AUTOMATING: Prefer Scripts Over Manual Steps

### Changed
- **Three Pillars (AUTOMATING)**: Added explicit principle — if a task can be done with a script (especially a reusable one in `scripts/`), use the script instead of doing it manually.
- **AGENTS.md, CLAUDE.md, WINDSURF.md, README.md**: AUTOMATING pillar now includes a leading bullet on preferring scripts; title updated to mention "prefer scripts over manual steps."
- **docs/THREE_PILLARS.md**: Overview and Pillar 1 updated with the principle; self-check question extended ("Did I use scripts instead of manual steps where possible?").
- **docs/protocols/MEMORY-SYSTEM-PROTOCOL.md**: Section 14 "Three Pillars Integration" → AUTOMATING: added first bullet "Prefer scripts over manual steps."

### Rationale
- Automating should prioritize reusable automation; manual steps are a fallback when no script exists or is appropriate.

---

## 2026-02-26 - Rules as Another Template Type

### Changed
- **Framework**: Rules are now treated as **another template type** (not a separate "asset" category). **"Templates"** = all six types: Rules, Blueprints, Tasks, Recipes, Subagents, Skills.
- **AGENTIC-ASSETS-FRAMEWORK.md**: "Six types of templates" (not "six asset types"); "six complementary template types"; Terminology section "Templates (All Six Types)" with rule templates listed first; Summary "six template types"; hierarchy box "SIX TEMPLATE TYPES."
- **AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, README.md**: "Templates" = all six types (including Rules).

### Rationale
- Unify naming: Rules are one of the six template types, so "Templates" refers to the whole set.

---

## 2026-02-26 - Rules Integrated as Sixth Asset Type; Four Rule Files

### Changed
- **Framework**: Rules are now the **first of six asset types** in `AGENTIC-ASSETS-FRAMEWORK.md`. Full section added: definition, purpose, format, location, key files, characteristics, when to use, question answered.
- **Rule file examples**: **AGENTS.md**, **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md** documented as the four canonical rule files (same project, different tool/audience entry points). File organization tree lists all four at project root; comparison table and "Rules, Skills, and Subagents" subsection updated.
- **Terminology**: "Templates" = the five content types (Blueprints, Tasks, Recipes, Subagents, Skills). "Framework" = all six types including Rules.
- **AGENTS.md, CLAUDE.md, WINDSURF.md**: Updated to six asset types and explicit mention of the four rule files.

### Added
- **CURSOR.md**: New rule file (Cursor-specific entry), parallel to CLAUDE.md and WINDSURF.md. Quick start, six asset types, repo structure with four rule files, key references.
- **Best practices**: "For Rules" now references AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md and .cursor/rules; recommend one canonical source and thin tool-specific files.

### Rationale
- Rules are integrated as part of the framework; CURSOR.md, CLAUDE.md, AGENTS.md, and WINDSURF.md are all examples of the Rules asset type for consistent organization across tools.

---

## 2026-02-26 - Rules, Skills, and Subagents in Framework

### Added
- **Rules as part of the system**: Documented Rules (AGENTS.md, .cursor/rules, RULE.md) as the behavioral layer that applies across agents and subagents.
- **"Rules, Skills, and Subagents"** subsection in `AGENTIC-ASSETS-FRAMEWORK.md`: table (Rules = constraints, Skills = capability, Subagents = workers), flow (Rules loaded first; Subagents use Skills within Rules), and practical use.
- **Comparison table**: Rules row added (question, purpose, format, scope, location); note that Rules are the behavioral layer and the other five are template asset types.
- **Hierarchy diagram**: Header updated to include RULES; one-line note that RULES constrain SUBAGENTS and agents and SUBAGENTS use SKILLS.
- **File organization**: AGENTS.md and optional .cursor/rules, RULE.md called out as Rules layer.
- **Best practices**: New "For Rules" subsection (constraints testable, reference template system, memory/validation when used, single source of truth).
- **Summary**: Sentence that Rules govern behavior and Subagents/Skills operate within them.
- **AGENTS.md / CLAUDE.md**: One-sentence mention of Rules and pointer to framework "Rules, Skills, and Subagents."

### Rationale
- Rules, Skills, and Subagents are now explicit parts of the same system: Rules constrain, Skills add capability, Subagents are workers that use Skills under Rules.

---

## 2026-02-26 - Memory System and Skills Integration

### Added
- **memory-system skill**: Complete memory management system with installation scripts and templates
- **rules-setup skill** (formerly agents-setup): Tool for creating and maintaining the Rules template type (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md) with Three Pillars and prompt validation
- **skill-builder toolkit**: Comprehensive skill development and validation tools
- Documentation and examples for all new skills
- Reference guides and best practices

### Technical Details
- 53 files added, 15,441 insertions
- JSON validation confirmed for all config files
- Cross-platform installation scripts (PowerShell and Bash)
- Complete template system for skill development

### Repository State
- Main branch updated successfully
- All critical files committed and pushed
- Archive files excluded from commit due to filename length issues

---

## 2026-02-26 - Git Repository Cleanup

### Changes
- **Removed all subfolder .gitignore files** to prevent nested repository conflicts
- **Added comprehensive .gitignore** covering Python, Node.js, IDE files, and project-specific patterns
- **Excluded _complete_archive/ directory** from version control
- **Cleaned git repository structure** for single-repo setup

### Files Modified
- Deleted: `docs/universal/.gitignore`
- Deleted: `_complete_archive/_archive_2026-02-26_18-50-32/.gitignore`
- Deleted: `_complete_archive/_archive_2026-02-26_18-50-32/docs/universal/.gitignore`
- Added: `.gitignore` (comprehensive 330-line ignore file)

### Repository Status
- ✅ Single git repository structure established
- ✅ No nested git repositories or conflicting .gitignore files
- ✅ Working tree clean and up to date with origin/main

---

## Previous Repository History

### 2026-02-26 - Repository Consolidation
- Consolidated repository structure
- Removed obsolete docs and blueprints
- Updated AGENTS/CLAUDE/README/WINDSURF files

### 2026-02-26 - Repository Reset and Reorganization
- Major repository restructuring
- Updated documentation and file organization

### 2026-02-25 - Documentation Enhancements
- Added section 10 "How the Files Connect" to DOCUMENTATION-BLUEPRINT.md
- Updated QUICK-REFERENCE.md with "What Each File Answers" table
- Simplified placeholder descriptions in README and QUICKSTART templates

### 2026-02-25 - Merge Conflict Resolution
- Merged remote-tracking branch 'origin/main'
- Resolved conflicts keeping local versions

### 2026-02-24 - Initial Repository Setup
- Initial commit with skills repository
- 3 packs, 36 skills, memory system established

---

## Event Log

<!-- LAYER 1: Source of truth. Append-only. If it is not here, it did not happen. -->
<!-- Append new events below this line. Never edit or delete existing events. -->

### evt-001 | 2026-02-26 12:00 | human | milestone

**Scope**: memory-system, skill, scripts
**Summary**: Memory System Setup skill and automation scripts; gaps closed; skill renamed to memory-system-setup.

**Details**:
- skill: name memory-system-setup; setup-only; Option A (script) / Option B (manual)
- scripts: validate-memory.py, initialize-memory.py under memory-system/scripts/
- docs: ARCHITECTURE-AUDIT.md G1–G4 resolved; README script usage; protocol references skill name
- CHANGELOG: Event Log section added for memory-system compliance

**Refs**: none
**Tags**: memory-system, skill, automation, gap-fix

### evt-002 | 2026-02-27 02:00 | human | milestone

**Scope**: memory-system, scripts, docs, protocol, skill
**Summary**: Claude-mem–style retrieval tools implemented; protocol §15, README, CLAUDE-MEM-IMPROVEMENTS, and memory-system-setup skill updated.

**Details**:
- scripts: get_event.py (resolve evt-ID, normalize 1→evt-001), search_events.py (keyword/timeline/list-ids), suggest_event.py (--from-git/--from-stdin), summarize_events.py, relevant_events.py, generate_memory_viewer.py; _events_common.py shared parsing; privacy (private/sensitive tags) in search/summary/viewer
- protocol: MEMORY-SYSTEM-PROTOCOL.md §15 Retrieval and Tools (resolve, search, progressive disclosure, suggester, summarize, relevant at boot, viewer, privacy convention)
- docs: memory-system README Retrieval and Tools table and script list; CLAUDE-MEM-IMPROVEMENTS.md items marked Implemented with Implementation refs; memory-system-setup SKILL.md step 9 (After setup — retrieval), Supporting Files and README updated

**Refs**: evt-001
**Tags**: memory-system, retrieval, documentation, skill

### evt-003 | 2026-02-27 02:15 | human | modify

**Scope**: AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, memory-system-setup
**Summary**: Rule files updated so agents load the memory system properly: explicit staleness check, CURSOR.md memory section, agents-integration-snippet aligned.

**Details**:
- AGENTS.md: Before every task — read context.md, check staleness (Event horizon vs last evt in CHANGELOG Event Log), regenerate if stale/missing; optional relevant_events.py; lifecycle BOOT line includes staleness and script
- CLAUDE.md: Same load sequence and staleness check; link to full protocol
- CURSOR.md: New Memory System section (load context, check staleness, regenerate if needed, optional relevant_events.py); Key References add MEMORY-SYSTEM-PROTOCOL.md
- WINDSURF.md: Before/After include staleness check and protocol link
- agents-integration-snippet.md: Staleness check and Event Log evt-NNN in snippet for new projects

**Refs**: evt-002
**Tags**: memory-system, rules, agent-boot

### evt-004 | 2026-02-27 02:25 | human | modify

**Scope**: .agents/skills/memory-system-setup, global Cursor skills
**Summary**: Memory system skill updated locally and synced to global; snippet and load-memory guidance clarified.

**Details**:
- Local skill (.agents/skills/memory-system-setup): SKILL.md step 7 and Troubleshooting note that agents-integration-snippet includes load-memory sequence and staleness check; Supporting Files note snippet ensures agents boot correctly; README added line on snippet and load-memory for all rule files
- Global skill: synced from repo via robocopy to C:\Users\vinic\.cursor\skills\memory-system-setup so Cursor uses same content
- Snippet (already updated in evt-003) provides Before/After every task with staleness check for projects that add it to AGENTS.md

**Refs**: evt-003
**Tags**: memory-system, skill, global-install

### evt-005 | 2026-02-27 02:35 | human | create

**Scope**: docs/memory-system, documentation
**Summary**: Added MEMORY-SYSTEM-OVERVIEW.md — single full overview of how the memory system works.

**Details**:
- New doc: docs/memory-system/MEMORY-SYSTEM-OVERVIEW.md — purpose and principles, four layers, file layout, event format and types, agent lifecycle (boot/execute/shutdown), staleness and regeneration, retrieval tools (get_event, search_events, relevant_events, summarize, suggest_event, viewer), privacy, archival, tiers, data flow, and pointers to protocol/skill/scripts
- README: link to overview at top and in Further Reading

**Refs**: evt-004
**Tags**: memory-system, documentation

### evt-006 | 2026-02-27 | agent | milestone

**Scope**: framework, protocols, skills, rules
**Summary**: Protocols added as seventh template type; prompt-validation-setup skill created; full integration across framework, rule files, and docs.

**Details**:
- AGENTIC-ASSETS-FRAMEWORK.md: Seven template types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, **Protocols**). Protocols defined as process documents in docs/protocols/, installed by protocol skills; hierarchy, comparison table, file org, Flow/Practical use, terminology, best practices, summary updated. Implementation status: Protocols + eight skills (incl. prompt-validation-setup).
- AGENTS.md: Seven template types; Protocols in list and structure; docs/protocols/ and prompt-validation-setup in repo tree; Three Pillars AUTOMATING/TESTING include Protocols; DOCUMENTING change-type "New protocol"; workflow "Adding a Protocol"; Key References Protocols + prompt-validation-setup; System & Tools protocol path note.
- CLAUDE.md, CURSOR.md, WINDSURF.md: Seven template types; Protocols; eight skills and prompt-validation-setup; docs/protocols/ in structure; Key References/Key Files add Protocols and prompt-validation-setup.
- New skill: .agents/skills/prompt-validation-setup/ — SKILL.md (install protocol to docs/protocols/, ensure Rules reference), config.json, README.md, templates/PROMPT-VALIDATION-PROTOCOL.md (full protocol copy). Prompt validation protocol is now installable via this skill.
- rules-setup: Supporting Files note protocol installed by prompt-validation-setup skill; Related Skills add prompt-validation-setup.
- docs/protocols/PROMPT-VALIDATION-PROTOCOL.md: Intro line updated to mention prompt-validation-setup and docs/protocols/ placement.
- CURRENT-REPOSITORY-STATE.md: Seven template types, eight skills, Protocols (docs/protocols/), prompt-validation-setup; protocols/ and prompt-validation-setup referenced throughout.
- docs/INDEX.md: Protocols as template type; PROMPT-VALIDATION-PROTOCOL install via prompt-validation-setup; For System Integration step 3 updated.

**Refs**: evt-005
**Tags**: protocols, template-type, skill, prompt-validation, framework

### evt-007 | 2026-02-27 | agent | milestone

**Scope**: skills, protocols, naming
**Summary**: protocol-setup skill added (Protocols template type); skill-builder renamed to skill-setup; nine skills total.

**Details**:
- New skill: .agents/skills/protocol-setup/ — SKILL.md (create/edit/audit Protocols, docs/protocols/, protocol skills, Rules references), config.json, README.md. Aligned with other *-setup skills (rules-setup, blueprints-setup, etc.).
- Renamed .agents/skills/skill-builder/ → .agents/skills/skill-setup/; updated name/description/title and package.json; kept "skill builder" in config triggers for backward compatibility.
- All references to skill-builder updated to skill-setup across AGENTSIC-ASSETS-FRAMEWORK.md, AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, CURRENT-REPOSITORY-STATE.md, docs/INDEX.md, .memory/context.md, rules-setup, blueprints-setup, memory-system-setup, prompt-validation-setup. protocol-setup added to skills lists and Key References; skill count updated to nine (memory-system-setup, rules-setup, skill-setup, blueprints-setup, tasks-setup, recipes-setup, subagents-setup, prompt-validation-setup, protocol-setup).

**Refs**: evt-006
**Tags**: protocol-setup, skill-setup, rename, naming-convention

### evt-008 | 2026-02-27 | agent | modify

**Scope**: protocols, memory-system-setup, prompt-validation-setup, docs/protocols
**Summary**: Memory system and prompt validation set up as Protocols; both skills updated as protocol skills.

**Details**:
- memory-system-setup: Framed as **protocol skill** for the Memory System Protocol (Protocols template type). Added step 1 to install protocol document (create docs/protocols/, copy from skill templates/MEMORY-SYSTEM-PROTOCOL.md to docs/protocols/MEMORY-SYSTEM-PROTOCOL.md). Added templates/MEMORY-SYSTEM-PROTOCOL.md (copy of docs/protocols version). Renumbered steps 2–10. Validation checklist and Supporting Files now require/reference protocol file; agents-integration-snippet adds "Full protocol: docs/protocols/MEMORY-SYSTEM-PROTOCOL.md" and closing line to follow protocol. Related Skills add protocol-setup; description and README updated. config.json: added keywords "install memory protocol", "MEMORY-SYSTEM-PROTOCOL", "docs/protocols memory" and complex example for installing the protocol.
- prompt-validation-setup: Core Approach states it is the protocol skill for the Prompt Validation Protocol; Validation Checklist and Related Skills explicitly reference protocol-setup and memory-system-setup as same pattern.
- docs/protocols/MEMORY-SYSTEM-PROTOCOL.md: Intro updated to state it is a Protocol template placed in docs/protocols/ by memory-system-setup; deployment sentence updated to reference .agents/skills/memory-system-setup/.
- protocol-setup: Supporting Files list both prompt-validation-setup and memory-system-setup as example protocol skills.

**Refs**: evt-008
**Tags**: protocols, memory-system, prompt-validation, protocol-skills

### evt-009 | 2026-02-27 | agent | modify

**Scope**: documentation accuracy (CURRENT-REPOSITORY-STATE, README, AGENTS, rules-setup, subagents-setup, ARCHIVE-REFERENCE)
**Summary**: Documentation audit — corrected skill count (eight→nine), six→seven template types, skill-builder→skill-setup, and added Protocols where missing.

**Details**:
- CURRENT-REPOSITORY-STATE.md: "Current skills (eight)" → "(nine)"; "8 skills" → "9 skills"; footer "eight Skills" → "nine Skills".
- README.md: "six template types" → "seven"; "Six-Pillar" → "Seven Template Types"; Skills list and tree updated to nine skills (skill-setup, prompt-validation-setup, protocol-setup); added Protocols section; Key Documentation and Current Implementation tables; When Stuck skill-setup.
- AGENTS.md: Structure tree "seven skills" → "nine skills".
- .agents/skills/rules-setup/SKILL.md: "six-template-types" → "seven-template-types" (frontmatter, body, workflow paragraph); "six template types" → "seven template types".
- .agents/skills/rules-setup/README.md: skill-builder → skill-setup in Related.
- .agents/skills/subagents-setup/SKILL.md: skill-builder → skill-setup in Related Skills.
- docs/ARCHIVE-REFERENCE-FOR-TEMPLATE-TYPES.md: "skill-builder" → "skill-setup" in text and table; added Protocols row (protocol-setup, prompt-validation-setup; docs/protocols/).

**Refs**: evt-008
**Tags**: documentation, accuracy, skills-count, template-types, skill-setup

### evt-010 | 2026-02-27 | agent | modify

**Scope**: global Cursor skills (%USERPROFILE%\.cursor\skills\)
**Summary**: Synced all nine local skills to global; installed missing prompt-validation-setup and protocol-setup; removed legacy skill-builder.

**Details**:
- Synced repo `.agents/skills/` → `%USERPROFILE%\.cursor\skills\` for all nine skills (blueprints-setup, memory-system-setup, prompt-validation-setup, protocol-setup, recipes-setup, rules-setup, skill-setup, subagents-setup, tasks-setup).
- Installed globally: prompt-validation-setup, protocol-setup (were missing).
- Removed legacy `skill-builder` folder from global (replaced by skill-setup).

**Refs**: evt-009
**Tags**: skills, global-install, sync, cursor

### evt-011 | 2026-02-27 | agent | create

**Scope**: docs, documentation blueprint
**Summary**: Added DOCUMENTATION-BLUEPRINT-VS-CURRENT-SETUP.md comparing blueprint tiers to current repo; documented gaps and recommendations.

**Details**:
- New doc: docs/DOCUMENTATION-BLUEPRINT-VS-CURRENT-SETUP.md — Blueprint MVP/Core/Full vs current root, docs/, .memory/, .github/; status table for each required file; note that .memory/graph.md event horizon is stale (evt-001 vs evt-010); recommendations for Core alignment (QUICKSTART, CONTRIBUTING, SECURITY, docs/SYSTEM-MAP.md, graph materialization) and optional Full tier.
- docs/INDEX.md: Quick Reference and Core Documentation entries for DOCUMENTATION-BLUEPRINT-VS-CURRENT-SETUP.md.

**Refs**: evt-010
**Tags**: documentation, blueprint, comparison

### evt-012 | 2026-02-27 | agent | create

**Scope**: docs, documentation blueprint
**Summary**: Added BLUEPRINT-AND-CURRENT-SYSTEM-FULL-COMPARISON.md with full comparison and bidirectional improvements (current → blueprint, blueprint → current).

**Details**:
- New doc: docs/BLUEPRINT-AND-CURRENT-SYSTEM-FULL-COMPARISON.md — Part I full comparison (tiers, root/docs/memory/.github, alignment summary); Part II how current system can improve the blueprint (Protocols as first-class, docs/INDEX alternative, template-types reference, event log naming, staleness rule, repo state doc, protocol skills in AUTOMATING, AI file length exception); Part III how blueprint can improve current (QUICKSTART/CONTRIBUTING/SECURITY, SYSTEM-MAP, prompt validation pointer, graph materialization, DOCUMENTING table, tier and Full-tier items, section specs, shutdown sequence); Part IV summary tables.
- docs/INDEX.md: Quick Reference and Core Documentation entries for BLUEPRINT-AND-CURRENT-SYSTEM-FULL-COMPARISON.md.

**Refs**: evt-011
**Tags**: documentation, blueprint, comparison, bidirectional

### evt-013 | 2026-02-27 | agent | milestone

**Scope**: documentation blueprint, current system, Core tier, AGENTS.md, memory
**Summary**: Implemented all blueprint→current improvements; rebuilt Documentation Blueprint (v3.0) with current-system→blueprint improvements.

**Details**:
- **Current system (blueprint→current)**: Added root QUICKSTART.md, CONTRIBUTING.md, SECURITY.md, WORKFLOW.md. Added docs/SYSTEM-MAP.md (overview, components, data flow, dependencies, decisions). Added docs/PROMPT-VALIDATION.md as pointer to docs/protocols/PROMPT-VALIDATION-PROTOCOL.md. Regenerated .memory/graph.md (event horizon evt-012; nodes/edges for components). AGENTS.md: explicit shutdown sequence (append → materialize graph → regenerate context → commit); DOCUMENTING table extended (New feature/module, Repository structure change, docs/INDEX for skills). README and CURRENT-REPOSITORY-STATE: tier stated (MVP + Core); root and docs file lists updated. docs/INDEX.md: SYSTEM-MAP and PROMPT-VALIDATION entries.
- **Documentation Blueprint (current→blueprint)**: Version 3.0. Added ecosystem alignment (template types, protocol skills). AUTOMATING: protocol skills for installing/updating docs/protocols/. §3: Protocols optional (docs/protocols/, protocol skills); repository state doc optional; PROMPT-VALIDATION.md or protocols path; DOCUMENTATION-OVERVIEW or docs/INDEX.md alternative; AI file ≤60 lines exception. §4: CHANGELOG section "## Events" or "## Event Log"; evt-NNN. §5 Boot: explicit staleness rule (compare event horizon to last CHANGELOG event; regenerate L2/L3 from L1); Shutdown: event horizon = last evt, never edit backward. §6 CHANGELOG: Events or Event Log; PROMPT-VALIDATION: pointer when using protocol skills; DOCUMENTATION-OVERVIEW: docs/INDEX.md alternative. §9: Staleness check wording aligned.

**Refs**: evt-012
**Tags**: documentation, blueprint, core-tier, system-map, workflow, graph, agents
