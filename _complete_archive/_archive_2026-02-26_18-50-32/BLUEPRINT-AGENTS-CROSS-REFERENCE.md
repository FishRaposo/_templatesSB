# Blueprint ↔ AGENTS.md Cross-Reference

_Mapping the Universal Template System (archive) to the current AGENTS.md-based system_

**Archive source**: `_complete_archive/_templates-main/`  
**Current source**: Root of `_templates/` repository  
**Purpose**: Trace conceptual lineage — what was inherited, evolved, replaced, or dropped.

---

## Table of Contents

1. [Systems at a Glance](#1-systems-at-a-glance)
2. [Three Pillars Framework](#2-three-pillars-framework)
3. [Behavioral Core / Agent Rules](#3-behavioral-core--agent-rules)
4. [Memory and State Architecture](#4-memory-and-state-architecture)
5. [Agent Lifecycle](#5-agent-lifecycle)
6. [Handoff Protocol](#6-handoff-protocol)
7. [Multi-Agent Architecture](#7-multi-agent-architecture)
8. [Validation and Quality Gates](#8-validation-and-quality-gates)
9. [Changelog Format](#9-changelog-format)
10. [Documentation Requirements](#10-documentation-requirements)
11. [Tier Scaling](#11-tier-scaling)
12. [Prompt Validation](#12-prompt-validation)
13. [Source of Truth Model](#13-source-of-truth-model)
14. [Concept Lineage Summary](#14-concept-lineage-summary)
15. [Gap Analysis](#15-gap-analysis)

---

## 1. Systems at a Glance

| Dimension | Archive: Universal Template System | Current: AGENTS.md Ecosystem |
|-----------|-------------------------------------|-------------------------------|
| **Primary purpose** | Generate fully-documented project scaffolding from blueprints | Govern AI agent behavior in a skills repository |
| **Target consumer** | LLM agents generating new software projects | AI coding agents maintaining skill packs |
| **Core governance doc** | `DOCUMENTATION-BLUEPRINT.tpl.md` (601 lines) | `AGENTS.md` (~20KB) |
| **Agent rules doc** | `AGENTIC-RULES.md` (271 lines) | Embedded in `AGENTS.md` |
| **Memory protocol** | `PROJECT-MEMORY-SYSTEM-REFERENCE.md` | `MEMORY-SYSTEM-PROTOCOL.md` (698 lines) |
| **Entry point for agents** | `LLM-ENTRYPOINT.md` + `LLM-GUIDE.md` | `AGENTS.md` (boot-time read) |
| **Validation mechanism** | Python scripts (`validate-templates.py`, etc.) | Structural/markdown checklist; per-layer rules |
| **File types** | Templates (`.tpl.md`, `.yaml`), code, scripts, docs | `.md` + `.json` only |
| **Tiers** | MVP / Core / Enterprise | MVP / Core / Full |
| **Source of truth** | Blueprint templates + validation scripts | `AGENTS.md` (L0) + `CHANGELOG.md` (L1) |

---

## 2. Three Pillars Framework

Both systems use a **Three Pillars** framework as the mandatory completion gate for any task. The names and scope differ.

### Archive: SCRIPTING + TESTING + DOCUMENTING

Defined in `DOCUMENTATION-BLUEPRINT.tpl.md`.

| Pillar | Definition |
|--------|-----------|
| **SCRIPTING** | Automation, validation scripts, workflow optimization. Run `.\scripts\ai-workflow.ps1`. |
| **TESTING** | Comprehensive test coverage — 85%+ minimum threshold. |
| **DOCUMENTING** | Complete documentation parity with code changes. Every code change triggers documentation updates. |

Enforcement: Pre-change, during-change, post-change, and final review stages. Mandatory before any commit.

### Current: AUTOMATING + TESTING + DOCUMENTING

Defined in `docs/THREE_PILLARS.md` and `AGENTS.md`.

| Pillar | Definition |
|--------|-----------|
| **AUTOMATING** | Content validates against structural rules (SKILL.md frontmatter, config.json, naming conventions). |
| **TESTING** | Skill triggers work, examples are runnable, cross-references resolve, no broken links. |
| **DOCUMENTING** | `AGENTS.md`, `SKILLS_MASTER_LIST.md`, pack indexes, and related docs updated after every change. |

Enforcement: Checklist per pillar in `docs/THREE_PILLARS.md`. Integrated with memory system (L1 logs pillar completion) and prompt validation (validate before starting).

### Comparison

| Aspect | Archive | Current |
|--------|---------|---------|
| Pillar 1 name | SCRIPTING | AUTOMATING |
| Pillar 1 focus | Shell/Python automation scripts | Structural rule validation (no runtime scripts) |
| Pillar 2 threshold | 85%+ code coverage | Runnable examples + cross-reference integrity |
| Pillar 3 scope | All generated project docs | AGENTS.md + skills index + pack metadata |
| Validation script | `.\scripts\ai-workflow.ps1` | Manual checklist (no automation scripts) |
| Memory integration | Not specified | Explicitly links to L1/L2/L3 |

**Key evolution**: "SCRIPTING" (run scripts to validate) → "AUTOMATING" (validate content structure). Reflects moving from a code-generation system with runtime scripts to a documentation-only repository with no build system.

---

## 3. Behavioral Core / Agent Rules

### Archive: `AGENTIC-RULES.md`

A dedicated, standalone file of mandatory rules — a rules annex for agents working on the template system.

**5 Critical Rules**: (1) Always run `validate-templates.py --full` before any commit · (2) Never break existing templates · (3) Maintain documentation parity · (4) Follow task-based architecture (`tasks/` directory) · (5) Use blueprint-driven development

**4 Quality Gates**: Template validation (0 errors) · Documentation check (titles, links, tables) · Code quality (header comments, stack conventions) · Structure compliance (tasks/stacks pattern, blueprint metadata)

Enforcement model: Script-based. Every rule refers to a specific Python validation script.

### Current: `AGENTS.md` as Layer 0

`AGENTS.md` is the project's constitution, not a rules annex. Agents read it at boot and accept a binding contract.

**Key behavioral rules**: Follow exact directory structure · action-oriented language only (no "learn", "study", "practice") · minimal YAML frontmatter (`name` + `description` only) · multi-language examples (JS/Python/Go minimum) · `config.json` always `"tools": []` · never add top-level files without human approval · never skip documentation updates for "small" changes

Enforcement model: Declarative. Rules written in `AGENTS.md`. No runtime scripts — compliance is structural.

### Comparison

| Aspect | Archive (`AGENTIC-RULES.md`) | Current (`AGENTS.md`) |
|--------|------------------------------|------------------------|
| **Location** | Separate file in `_templates-main/` | Root of repo — L0 of memory system |
| **Role** | Rules annex for agents | Project constitution (boot-time contract) |
| **Enforcement** | Python validation scripts | Declarative behavioral constraints |
| **Immutability** | No explicit rule | Explicitly immutable during execution |
| **Scope** | Template system rules | All agent behavior across all tasks |
| **Boot ritual** | Not specified | Formal 6-step boot sequence |
| **Violation handling** | Fix before committing | Escalate to human if constraints unclear |

**Key evolution**: `AGENTIC-RULES.md` (external rules document) → `AGENTS.md` (constitutional layer). Agent governance elevated from a checklist file to an architectural layer with formal immutability and boot-time contracts.

---

## 4. Memory and State Architecture

### Archive: Project Memory (4 Levels)

From `_complete_archive/PROJECT-MEMORY-SYSTEM-REFERENCE.md`.

| Level | Type | Description |
|-------|------|-------------|
| **Agent Memory** | Ephemeral | In-context working memory; lost on agent death |
| **Pipeline State** | Transient | Handoff payloads between pipeline agents |
| **Project State** | Persistent | Files tracked in git (CHANGELOG.md, docs/, etc.) |
| **System State** | Persistent | Template system metadata, blueprint versions, task indexes |

Memory types: `LOCAL` (own context) · `HANDOFF` (passed to next agent) · `FORBIDDEN` (must never carry) · `GLOBAL` (git-tracked files, available to all)

### Current: Event-Sourced Memory (4 Layers)

From `MEMORY-SYSTEM-PROTOCOL.md` (698 lines).

| Layer | File | Role | Mutability |
|-------|------|------|------------|
| **L0** | `AGENTS.md` | Behavioral Core — constitution | Immutable during execution |
| **L1** | `CHANGELOG.md` | Event Log — source of truth | Append-only |
| **L2** | `.memory/graph.md` | Knowledge Graph — materialized view | Derived from L1 only |
| **L3** | `.memory/context.md` | Narrative — current trajectory | Ephemeral, regenerable |

Core principle: Memory is infrastructure, not cognition. Agents read files — they do not "remember."

One-way data flow: `Agent action → L1 (append) → L2 (materialize) → L3 (regenerate)`

### Comparison

| Aspect | Archive (4 Levels) | Current (4 Layers) |
|--------|---------------------|---------------------|
| **Model type** | Categorized memory types | Event-sourced layered architecture |
| **Primary persistence** | Project State (git files) | L1 Event Log (append-only changelog) |
| **Ephemeral layer** | Agent Memory (in-context) | L3 Narrative (context.md, regenerable) |
| **Structural knowledge** | System State (metadata YAML) | L2 Knowledge Graph (graph.md) |
| **Agent constitution** | Not a separate memory level | L0 (AGENTS.md, immutable) |
| **Data flow direction** | Not formally specified | Strictly one-way (L1→L2→L3) |
| **Recovery mechanism** | Not detailed | Formal: trust L1, rebuild L2, rebuild L3 |
| **ACID guarantees** | Not specified | Formally defined (Atomicity/Consistency/Isolation/Durability) |
| **Anti-drift mechanisms** | Not specified | 6 explicit drift threats and defenses |
| **Forbidden memory** | Named `FORBIDDEN` type | "No forbidden memory" rule in handoff protocol |

**Key evolution**: Archive defines *categories* of memory. Current defines *layers* with formal data flow, immutability rules, and ACID-grade guarantees. Both treat git as the persistence substrate. Both define what agents must not carry across tasks.

---

## 5. Agent Lifecycle

### Archive

Not formally specified. Implied through `LLM-ENTRYPOINT.md` 5-phase generation workflow: environment setup → template discovery → blueprint selection → project generation → validation and delivery.

### Current

Formally specified in `MEMORY-SYSTEM-PROTOCOL.md` §7.

**Boot Sequence** (every agent, every task):
```
1. READ    AGENTS.md              → Load behavioral constraints (L0)
2. READ    .memory/context.md     → Load current trajectory (L3)
3. CHECK   Staleness              → Regenerate context.md if stale or missing
4. READ    .memory/graph.md       → Query task neighborhood (L2)
5. VERIFY  Constraints            → Confirm task is within boundaries
6. EXECUTE Task
```

**Shutdown Sequence**:
```
1. APPEND       All decisions/changes to CHANGELOG.md    (L1)
2. MATERIALIZE  New events into .memory/graph.md         (L2)
3. REGENERATE   .memory/context.md from L1 + L2          (L3)
4. COMMIT       All changes in single git commit
5. HANDOFF      If in pipeline, write handoff event
6. DIE          Purge all local/working memory
```

**Recovery**: Trust L1 → Rebuild L2 → Rebuild L3 → Resume

### Comparison

| Aspect | Archive | Current |
|--------|---------|---------|
| **Lifecycle formalization** | Implied by workflow phases | Formal boot/execute/shutdown/recover sequences |
| **Boot ritual** | Not specified | 6-step sequence with staleness check |
| **Shutdown ritual** | Not specified | 6-step sequence ending in explicit "Die" |
| **Recovery protocol** | Git revert | Formal 5-step rebuild from L1 |
| **Statelessness** | Not emphasized | Core principle: agents are ephemeral processes |
| **Constraint verification** | Pre-commit validation | Boot-time constraint check before execution |

---

## 6. Handoff Protocol

### Archive: Pipeline Handoff Payloads

Pipeline: Architect → Builder → Refactorer → Doc Manager → Tester → Validator

| Stage | Payload Contents |
|-------|-----------------|
| **Architect → Builder** | Invariants, module boundaries, folder structure, no-go zones, tier constraints |
| **Builder → Tester** | New/modified functions, expected behaviors, modified flows, implementation notes |
| **Tester → Doc Manager** | Behavior changes, new test cases, uncovered paths, validation results |
| **Doc Manager → Validator** | Documentation updates, API changes, migration entries, parity status |

Format: Not formally specified in archive sources — structured data passed between agents.

### Current: Event-Log Handoffs

Handoffs are `handoff`-type entries appended to `CHANGELOG.md`. No separate handoff files.

```markdown
### evt-012 | 2025-02-10 10:30 | architect-01 | handoff

**Scope**: auth_module
**Summary**: Architecture phase complete, handing off to builder

**Details**:
- From agent: architect-01
- To agent: builder
- Invariants: JWT tokens only, no session storage
- Boundaries: src/auth/ only, max 5 files
- Artifacts: evt-008, evt-010
```

Rules: Forward-only · scoped · artifact references (event IDs not raw data) · no forbidden memory · consumed once.

### Comparison

| Aspect | Archive | Current |
|--------|---------|---------|
| **Handoff format** | Structured payload (format unspecified) | `handoff` event in CHANGELOG.md |
| **Pipeline direction** | Forward-only (implied) | Forward-only (explicit rule) |
| **Payload content** | Role-specific data | Event ID references (receiver reads events) |
| **Persistence** | Transient (Pipeline State level) | Permanent (part of append-only event log) |
| **Audit trail** | Not guaranteed | Permanent — handoff events never deleted |

**Key evolution**: Archive handoffs are ephemeral pipeline data. Current handoffs are permanent event log entries — auditability gained at no extra cost since the log is append-only anyway.

---

## 7. Multi-Agent Architecture

### Archive: Role-Based Specialist Pipeline

| Role | Primary Responsibility |
|------|------------------------|
| **Architect** | System design, module boundaries, dependency decisions |
| **Builder** | Code implementation within architect's constraints |
| **Refactorer** | Code quality, pattern application, technical debt |
| **Doc Manager** | Documentation parity, API docs, changelog maintenance |
| **Tester** | Test coverage (85%+), behavior verification |
| **Validator** | Final gate — validates Three Pillars completion |

Coordination: Sequential pipeline with handoff payloads.

### Current: Stateless Generalists with Sub-Agent Spawning

No fixed named roles. Any agent reads the same L0 constitution and operates within the same boundaries. Coordination via shared event log + knowledge graph — no direct agent-to-agent communication.

Sub-agent pattern from `AGENTS.md`: spawn for >3 files · verification tasks · reference generation · cross-referencing. Work in parallel where possible. Results committed to shared event log.

### Comparison

| Aspect | Archive | Current |
|--------|---------|---------|
| **Agent model** | Role-based specialists (6 roles) | Stateless generalists with sub-agent spawning |
| **Pipeline structure** | Sequential, ordered | Parallel where possible, serial where dependent |
| **Coordination** | Handoff payloads | Shared event log + knowledge graph |
| **Role boundaries** | Formally defined per role | Defined by task scope, not role |
| **Parallelism** | Not specified (sequential) | Explicitly encouraged for independent tasks |

---

## 8. Validation and Quality Gates

### Archive: Script-Based

Primary: `python scripts/validate-templates.py --full` — must show `Errors: 0 / Warnings: 0`

Specialized validators: `validate_stacks.py` · `validate_tasks.py` · `validate_blueprints.py`

Required metrics: 0 errors · 0 warnings · 0 broken links · 0 missing headers · 0 structure issues · 100% documentation coverage.

### Current: Structural/Declarative

No runtime scripts. Validation is declarative checklists enforced by agent behavior.

Per-layer checks (`MEMORY-SYSTEM-PROTOCOL.md` §12): L0 (AGENTS.md exists, unmodified) · L1 (event format, sequential IDs, monotonic timestamps, valid Refs) · L2 (tables present, event horizon matches L1, no orphan edges) · L3 (exists or regenerable, event horizon matches L2).

Self-healing: identify authoritative layer → rebuild downstream → append corrective event.

### Comparison

| Aspect | Archive | Current |
|--------|---------|---------|
| **Mechanism** | Python scripts (runtime) | Declarative checklists (structural) |
| **Enforcement point** | Pre-commit bash commands | Boot-time check + Three Pillars gate |
| **Error format** | Script stdout | Escalation event in CHANGELOG.md |
| **Recovery** | Fix-and-rerun | Self-healing: rebuild downstream from L1 |
| **Coverage metric** | 85%+ code test coverage | Runnable examples + cross-reference integrity |

---

## 9. Changelog Format

Both use `CHANGELOG.md` as a persistent, append-only record. Formats diverge significantly.

### Archive: Section-Based Narrative

```markdown
## YYYY-MM-DD HH:MM — Event Title

**Type:** [decision|change|result|milestone]
**Scope:** [repository|skill-pack|skill|docs]

### What / Why / Impact / Next Steps
```

Characteristics: Human-readable narrative. No event IDs. No agent identifiers. No cross-references.

### Current Protocol: Structured Event Log

```markdown
### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type

**Scope**: area affected
**Summary**: one-line description

**Details**: key: value pairs
**Refs**: evt-XXX
**Tags**: tag1, tag2
```

Characteristics: Machine-parseable. Sequential IDs. Agent identity recorded. 11 typed events. Archival protocol at 50 events.

### Comparison

| Aspect | Archive Format | Current Protocol |
|--------|----------------|-----------------|
| **Event IDs** | None | Sequential `evt-NNN` |
| **Agent tracking** | None | Agent name in heading |
| **Event types** | 4 | 11 |
| **Cross-references** | None | `Refs:` field with event IDs |
| **Queryability** | Text search only | Graph materialization from event IDs |
| **Archival** | Not specified | Formal protocol at 50 events |
| **Machine-parseable** | No | Yes |

**Known inconsistency**: `_templates/CHANGELOG.md` currently uses the archive's simpler date-based format. `MEMORY-SYSTEM-PROTOCOL.md` specifies the `evt-NNN` format. The project is mid-transition.

---

## 10. Documentation Requirements

### Archive: 30+ Required Root Files per Project

Blueprint mandates: 30+ root files (README.md, AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md, CODEX.md, COPILOT.md, GEMINI.md, AIDER.md, CONTEXT.md, INDEX.md, SYSTEM-MAP.md, CHANGELOG.md, TODO.md, QUICKSTART.md, WORKFLOW.md, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, SUPPORT.md, LICENSE.md, EVALS.md, DOCUMENTATION.md, DOCUMENTATION-BLUEPRINT.md, .gitignore, .editorconfig, .gitattributes...) + 4 docs/ files + 5 GitHub health files.

AI-specific files: one per tool (CLAUDE.md, CURSOR.md, WINDSURF.md, etc.) — each a tool-specific quick-start.

### Current: Minimal Operational Structure

Only what is necessary for the skills repository: ~9 root files (AGENTS.md, CHANGELOG.md, README.md, TODO.md, MEMORY-SYSTEM-PROTOCOL.md, PROMPT-VALIDATION-PROTOCOL.md, SKILLS_MASTER_LIST.md, AGENT_SKILLS_GUIDE.md, ARCHIVE_INDEX.md) + `.memory/` directory + `docs/THREE_PILLARS.md`, `docs/MEMORY_SYSTEM.md`.

### Comparison

| Aspect | Archive | Current |
|--------|---------|---------|
| **Root file count** | 30+ mandatory | ~9 active root files |
| **Per-tool AI files** | Yes (one per AI tool) | No — single AGENTS.md for all agents |
| **GitHub templates** | 5 required | None defined |
| **Audience** | End-project consumers + AI agents | AI agents only |

**Key difference**: Archive blueprint specifies what a fully-documented software *project output* should contain. Current system governs how agents operate on this *specific repository*. Archive's `AGENTS.md` was one of 30+ required output files; in the current system it is the entire governing document.

---

## 11. Tier Scaling

### Archive: MVP / Core / Enterprise

Complexity tiers for generated projects. Determines which blueprint overlays are applied.

| Tier | Scope |
|------|-------|
| **MVP** | Minimal viable project — essential structure only |
| **Core** | Full feature set — standard team project |
| **Enterprise** | Full compliance, audit trails, multi-region, advanced security |

### Current: MVP / Core / Full

Complexity tiers for the memory system itself.

| Tier | Files Used | Use Case | Upgrade Trigger |
|------|-----------|----------|-----------------|
| **MVP** | AGENTS.md + CHANGELOG.md | Solo, < 1 month | Changelog hits 30 events |
| **Core** | + .memory/context.md | Team, 1–6 months | >3 concurrent agents |
| **Full** | All four layers | Enterprise, 6+ months | Complex dependency queries |

### Comparison

| Aspect | Archive | Current |
|--------|---------|---------|
| **Tier names** | MVP / Core / Enterprise | MVP / Core / Full |
| **Tier determines** | Which template overlays apply | Which memory layers are active |
| **Selection basis** | Project type and compliance needs | Duration, team size, agent count |
| **Upgrade path** | Not specified | Explicit triggers defined |

---

## 12. Prompt Validation

### Archive

`docs/PROMPT-VALIDATION.md` listed as a required file in the blueprint's `docs/` inventory. Content not preserved in archive sources reviewed.

### Current: `PROMPT-VALIDATION-PROTOCOL.md` (370 lines)

Three levels: PERMISSIVE / STANDARD / STRICT.

Quick validation (4 checks, must pass for all prompts): (1) Purpose in first line · (2) All variables defined · (3) No dangerous patterns (27 security patterns blocked) · (4) Output format specified.

Security patterns blocked: Script injection (7) · command injection (7) · path traversal (3) · SQL injection (3) · system commands (4) · secrets (3).

Standard validation: 5-dimension scoring — Clarity (25%), Completeness (25%), Structure (15%), Security (20%), Effectiveness (15%).

### Comparison

| Aspect | Archive | Current |
|--------|---------|---------|
| **Existence** | Required file (content not archived) | Full 370-line protocol at repo root |
| **Scope** | Project-level documentation | Pre-task agent behavior |
| **Security patterns** | Not detailed in archive sources | 27 explicitly blocked patterns |
| **Scoring** | Not specified | 5-dimension weighted scoring (A–F) |
| **Integration** | Listed as required file | Referenced in Three Pillars + AGENTS.md |

---

## 13. Source of Truth Model

### Archive: Multi-Source, Script-Validated

Blueprint templates + `task-index.yaml` + validation scripts + documentation files + stack-specific overlays. Truth validated by running scripts. Inconsistency surfaces as script errors.

### Current: Single Chain of Custody

```
AGENTS.md  >  CHANGELOG.md  >  graph.md  >  context.md
(immutable)   (source of truth) (derived)   (ephemeral)
```

When layers conflict: higher layer always wins. L1 is the source of truth for all facts. L0 is the source of truth for behavior. L2 and L3 are always rebuilt from upstream — never edited to fix upstream.

### Comparison

| Aspect | Archive | Current |
|--------|---------|---------|
| **Truth model** | Multi-source, script-validated | Single chain of custody (L0 > L1 > L2 > L3) |
| **Conflict resolution** | Script error → fix the file | Trust order: higher layer always wins |
| **Behavioral truth** | `AGENTIC-RULES.md` | `AGENTS.md` (L0) |
| **Historical truth** | Git log | `CHANGELOG.md` (L1, append-only) |
| **Structural truth** | Blueprint metadata YAML | `.memory/graph.md` (L2, materialized) |

---

## 14. Concept Lineage Summary

| Concept | Archive Origin | Current State | Status |
|---------|---------------|---------------|--------|
| **Three Pillars** | SCRIPTING + TESTING + DOCUMENTING | AUTOMATING + TESTING + DOCUMENTING | **Evolved** — Pillar 1 renamed and refocused |
| **AGENTS.md** | One of 30+ required output files | L0 constitutional layer | **Promoted** — from output file to architectural foundation |
| **CHANGELOG.md** | Required root file, narrative format | L1 event log, structured `evt-NNN` format | **Evolved** — from narrative log to event store |
| **Agent rules** | `AGENTIC-RULES.md` (separate file) | Embedded in `AGENTS.md` | **Merged** — consolidated into constitutional layer |
| **Memory levels** | 4 levels: Agent/Pipeline/Project/System | 4 layers: L0/L1/L2/L3 | **Evolved** — from categories to event-sourced architecture |
| **Handoff protocol** | Pipeline payloads (ephemeral) | `handoff` events in CHANGELOG.md (permanent) | **Evolved** — from transient data to permanent event records |
| **Agent lifecycle** | Implied (5-phase generation workflow) | Formal boot/execute/shutdown/recover sequences | **Formalized** |
| **Multi-agent roles** | 6 named specialists | Stateless generalists + sub-agent spawning | **Changed** — from fixed roles to dynamic task-scoped spawning |
| **Tier scaling** | MVP/Core/Enterprise for project complexity | MVP/Core/Full for memory system complexity | **Repurposed** — same names, different domain |
| **Validation** | Python scripts, 0 errors required | Declarative checklists, self-healing layers | **Changed** — from runtime scripts to structural validation |
| **Prompt validation** | Required docs/ file (content minimal) | Full 370-line protocol (STANDARD/STRICT levels) | **Expanded** |
| **Documentation parity** | Every code change triggers doc update | Every change triggers AGENTS.md + index update | **Inherited** — same principle, adapted to docs-only repo |
| **FORBIDDEN memory** | Explicit type in memory model | "No forbidden memory" rule in handoff protocol | **Inherited** — same concept, different articulation |
| **Git as database** | Implicit (project files in git) | Explicit design principle (commits are transactions) | **Formalized** |
| **Blueprint overlays** | Stack + tier overlay system | Not present | **Dropped** — repo has no stacks or generated projects |
| **Task-based architecture** | `tasks/` directory, `task-index.yaml` | Verification tasks in `_reference-files/TASKS.md` | **Adapted** — same concept, different structure |
| **LLM entry point** | `LLM-ENTRYPOINT.md` + `LLM-GUIDE.md` | `AGENTS.md` (single entry point) | **Consolidated** |
| **Template placeholders** | `{{PROJECT_NAME}}`, `{{STACK}}`, `{{TIER}}` | Not present in live repo | **Dropped** — no code generation in current system |
| **Per-tool AI files** | CLAUDE.md, CURSOR.md, WINDSURF.md, etc. | Not present | **Dropped** — AGENTS.md serves all tools |
| **ACID guarantees** | Not specified | Formally defined across all 4 properties | **Added** |
| **Anti-drift mechanisms** | Not specified | 6 explicit threats and defenses | **Added** |
| **Stateless agent model** | Not emphasized | Core architectural principle | **Added** |
| **Archival protocol** | Not specified | Formal protocol at 50 events | **Added** |

---

## 15. Gap Analysis

Concepts present in one system but absent or underdeveloped in the other.

### Present in Archive — Absent in Current

| Gap | Archive Has | Current Lacks | Recommendation |
|-----|------------|---------------|----------------|
| **Per-tool AI files** | Dedicated CLAUDE.md, CURSOR.md, WINDSURF.md, etc. per project | Only AGENTS.md | Add tool-specific files to `_documentation-blueprint/templates/` ✅ done |
| **GitHub community health** | 5 required .github/ files | None defined | `_documentation-blueprint` templates cover this ✅ done |
| **Architecture map** | SYSTEM-MAP.md required | No equivalent for skills repo | Lower priority — skills repo has minimal architecture |
| **Stack-specific templates** | Blueprint overlays per technology | Not applicable | Out of scope — different system purpose |
| **Validation scripts** | Python scripts for automated enforcement | Manual checklists only | Could add a simple markdown validator script if desired |
| **Documentation coverage metric** | 100% coverage tracked | Not formally tracked | Consider adding to Three Pillars checklist |

### Present in Current — Absent in Archive

| Gap | Current Has | Archive Lacked | Impact |
|-----|------------|----------------|--------|
| **ACID guarantees** | Formally defined 4-property model | Not specified | Current is significantly more rigorous for multi-agent scenarios |
| **Formal agent lifecycle** | Boot/execute/shutdown/recover with explicit sequences | Only implied | Eliminates ambiguity about agent behavior |
| **Anti-drift mechanisms** | 6 explicit threats + defenses | Not specified | Prevents state corruption in long-running multi-agent work |
| **Archival protocol** | Formal at 50 events | Not specified | Prevents CHANGELOG.md from becoming unmanageable |
| **Event ID cross-references** | `evt-NNN` Refs field in CHANGELOG | No cross-references | Enables graph materialization and audit trails |
| **Knowledge graph** | `.memory/graph.md` with node/edge tables | No structural knowledge layer | Enables dependency queries agents cannot answer from narrative alone |
| **Staleness detection** | Formal event horizon comparison | Not specified | Prevents agents from acting on stale context |
| **Self-healing** | Defined rebuild protocol for inconsistent layers | Not specified | Resilience to interrupted agent execution |

### Known Inconsistencies in Current System

These are gaps within the current system itself, identified through this cross-reference:

| Inconsistency | Description | Recommended Fix |
|---------------|-------------|-----------------|
| **CHANGELOG.md format** | Current `_templates/CHANGELOG.md` uses archive's date-based format; `MEMORY-SYSTEM-PROTOCOL.md` specifies `evt-NNN` format | Migrate to `evt-NNN` format in next session |
| **graph.md placeholder data** | `.memory/graph.md` contains placeholder example data (pack-001, pack-002) rather than real skill data | Populate with actual pack/skill nodes |
| **context.md not current** | `.memory/context.md` last updated 2026-02-23; session work since then not reflected | Regenerate from CHANGELOG.md at next session start |
| **Missing BLUEPRINT-AGENTS-CROSS-REFERENCE in ARCHIVE_INDEX.md** | This file and `_documentation-blueprint/` not yet indexed | Update `ARCHIVE_INDEX.md` |

---

_Cross-reference synthesized from: `_complete_archive/_templates-main/DOCUMENTATION-BLUEPRINT.tpl.md`, `AGENTIC-RULES.md`, `PROJECT-MEMORY-SYSTEM-REFERENCE.md`, `LLM-ENTRYPOINT.md`, `LLM-GUIDE.md`, `TEMPLATE-SYSTEM-GUIDE.md` (archive) and `AGENTS.md`, `MEMORY-SYSTEM-PROTOCOL.md`, `PROMPT-VALIDATION-PROTOCOL.md`, `docs/THREE_PILLARS.md`, `docs/MEMORY_SYSTEM.md`, `CHANGELOG.md`, `.memory/graph.md`, `.memory/context.md` (current)._
