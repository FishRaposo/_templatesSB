# Documentation Blueprint

_Canonical documentation baseline for any software project — synthesized from the Universal Template System (archive) and the AGENTS.md event-sourced memory model (current)_

**Version**: 2.0

---

## Table of Contents

1. [Purpose and Philosophy](#1-purpose-and-philosophy)
2. [Three Pillars Framework](#2-three-pillars-framework)
3. [Required File Inventory](#3-required-file-inventory)
4. [Memory Architecture](#4-memory-architecture)
5. [Agent Rules](#5-agent-rules)
6. [Section Specifications](#6-section-specifications)
7. [Implementation Workflow](#7-implementation-workflow)
8. [Tier Scaling](#8-tier-scaling)
9. [Quality Standards](#9-quality-standards)
10. [How the Files Connect](#10-how-the-files-connect)

---

## 1. Purpose and Philosophy

This blueprint defines the documentation baseline for any project that uses AI agents as collaborators. It answers:

- **What files** must exist (§3)
- **What structure** each file must follow (§6)
- **How agents** must behave when reading, writing, and handing off (§4, §5)

### Design Principles

1. **Constitution over checklists** — `AGENTS.md` is the behavioral law, not one of many files
2. **Event-sourced truth** — `CHANGELOG.md` is the single source of truth; all views derive from it
3. **One-way data flow** — events → graph → narrative; never backward
4. **Stateless agents** — agents boot from files, execute, write results, die; no retained state
5. **Documentation parity** — every code or content change is incomplete without a documentation update
6. **Git is the database** — all persistence through version-controlled markdown; commits are transactions
7. **Tier-appropriate complexity** — scale file requirements to actual project complexity

---

## 2. Three Pillars Framework

**A task is not complete until all three pillars are satisfied.**

### Pillar 1: AUTOMATING

Run deterministic scripts for **everything** that can be mechanically verified. **ALWAYS prioritize scripts over manual inspection** — if a script can check it, the script MUST check it. Never use LLM judgment for what a script can verify faster, cheaper, and more accurately. **Use skills when available. Spawn subagents for parallel tasks.** Scripts are token-free, never drift, and produce reproducible results.

**Priority order for any mechanical task**: (1) Use existing project scripts → (2) Use standard tools (grep, find, markdown-lint, link-checker) → (3) Write a new one-liner script → (4) Only as last resort, manual inspection with explicit verification steps.

The goal is to **eliminate all manual inspection** of anything a script can check: structure, placeholders, links, style, format. A task that passes AUTOMATING means every mechanical check was executed by a script and returned 0 errors.

- **Structure validator** (script): required sections present, file naming conventions followed, tier structure matches `AGENTS.md`
- **Placeholder scanner** (script): `grep -r '{{' .` returns 0 matches in committed files
- **Link checker** (script): no broken internal links, all referenced files exist
- **Linter / formatter** (script): code style and format conventions pass with 0 errors
- **All automated checks exit with 0 errors** before committing — no exceptions

When no project-specific scripts exist yet, **write them first**. A one-line grep or a 5-line shell script satisfies this pillar. Use the closest available tool: `grep`, `find`, `markdownlint`, `lychee` (link checker), `prettier`, `black`, `eslint`. **Writing the script IS part of satisfying this pillar.**

### Pillar 2: TESTING

Documentation is accurate and verifiable.

- All code examples are syntactically correct and runnable
- Setup instructions produce the described result when followed exactly
- API documentation matches actual implementation
- Changelog events reference real git commits

### Pillar 3: DOCUMENTING

Documentation parity with code is maintained.

| Change Type | Required Updates |
|-------------|-----------------|
| New feature or module | README.md, SYSTEM-MAP.md, CHANGELOG.md |
| API change | API reference, CHANGELOG.md, QUICKSTART.md if affected |
| Dependency change | CONTRIBUTING.md, QUICKSTART.md, CHANGELOG.md |
| Security fix | SECURITY.md, CHANGELOG.md |
| Architecture decision | SYSTEM-MAP.md, AGENTS.md if behavioral, CHANGELOG.md |
| New contributor workflow | CONTRIBUTING.md, QUICKSTART.md |

**Before starting any task**: Run Quick Validation from `docs/PROMPT-VALIDATION.md`. All 4 checks must pass.

---

## 3. Required File Inventory

### MVP Tier — Minimum Viable

```
{{PROJECT_NAME}}/
├── AGENTS.md                     ← L0: Behavioral core (constitution)
├── CHANGELOG.md                  ← L1: Event log (append-only, source of truth)
├── README.md                     ← Project gateway
└── .memory/
    └── context.md                ← L3: Narrative (ephemeral, regenerated per session)
```

### Core Tier — Standard Project

```
{{PROJECT_NAME}}/
├── AGENTS.md
├── CHANGELOG.md
├── README.md
├── TODO.md                       ← L1 extension: task tracker
├── QUICKSTART.md
├── CONTRIBUTING.md
├── SECURITY.md
├── .memory/
│   ├── graph.md                  ← L2: Knowledge graph (materialized from L1)
│   └── context.md
└── docs/
    ├── PROMPT-VALIDATION.md
    └── SYSTEM-MAP.md
```

### Full Tier — Enterprise / Multi-Agent

```
{{PROJECT_NAME}}/
├── AGENTS.md
├── CHANGELOG.md
├── README.md
├── TODO.md
├── QUICKSTART.md
├── CONTRIBUTING.md
├── SECURITY.md
├── WORKFLOW.md
├── DOCUMENTATION-OVERVIEW.md
├── CODE_OF_CONDUCT.md
├── LICENSE.md
├── EVALS.md
├── .memory/
│   ├── graph.md
│   └── context.md
├── docs/
│   ├── PROMPT-VALIDATION.md
│   ├── SYSTEM-MAP.md
│   ├── api/
│   └── adr/
└── .github/
    ├── PULL_REQUEST_TEMPLATE.md
    ├── CODEOWNERS
    └── ISSUE_TEMPLATE/
        ├── config.yml
        ├── bug_report.md
        └── feature_request.md
```

### AI Agent Files (Core and Full Tiers)

One short file per AI tool used on the project. All behavioral rules live in `AGENTS.md`. These files provide tool-specific onboarding only.

```
├── AGENTS.md       ← Single constitutional document (all agents read this)
├── CLAUDE.md       ← Claude-specific context and memory hints
├── CURSOR.md       ← Cursor IDE context
├── WINDSURF.md     ← Windsurf/Cascade context
├── COPILOT.md      ← GitHub Copilot context
├── CODEX.md        ← OpenAI Codex context
├── GEMINI.md       ← Google Gemini context
└── AIDER.md        ← Aider.chat context
```

Each AI-specific file: ≤60 lines. Links to `AGENTS.md` for all behavioral rules.

---

## 4. Memory Architecture

```
┌──────────────────────────────────────────────────────────┐
│  L3: NARRATIVE  (.memory/context.md)                     │
│  "What matters right now" — ephemeral, rebuilt from L1+L2│
├──────────────────────────────────────────────────────────┤
│  L2: KNOWLEDGE GRAPH  (.memory/graph.md)                 │
│  Entities + relations — materialized from L1 only        │
├──────────────────────────────────────────────────────────┤
│  L1: EVENT LOG  (CHANGELOG.md)                           │
│  Source of truth — append-only, immutable once committed │
├──────────────────────────────────────────────────────────┤
│  L0: BEHAVIORAL CORE  (AGENTS.md)                        │
│  Constitution — immutable during execution               │
└──────────────────────────────────────────────────────────┘
```

**Trust order when layers conflict**: `L0 > L1 > L2 > L3`  
**Recovery**: Trust L1 → Rebuild L2 → Rebuild L3 → Resume

### CHANGELOG.md Event Format

```markdown
### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type

**Scope**: area affected
**Summary**: one-line description

**Details**:
- key: value

**Refs**: evt-XXX (prior related events)
**Tags**: tag1, tag2
```

**Event types**: `decision` `create` `modify` `delete` `test` `fix` `dependency` `blocker` `milestone` `escalation` `handoff`

**Append rules**: Never edit existing events. One event per logical action. Sequential IDs. Self-contained Summary field. Archive when log exceeds 50 events.

### ACID Guarantees

| Property | Implementation |
|----------|---------------|
| **Atomicity** | Each event + git commit = one indivisible transaction |
| **Consistency** | graph.md is always a valid materialization of CHANGELOG.md |
| **Isolation** | Agents work on local copies; conflicts resolved at commit time |
| **Durability** | Git history is immutable; no committed event can be lost |

---

## 5. Agent Rules

### Boot-Time Contract

Reading `AGENTS.md` = accepting a binding contract:
- Act only within defined boundaries
- Follow all structural rules without exception
- Satisfy all Three Pillars before declaring any task complete
- Append all decisions and changes to the event log

### Boot Sequence

```
1. READ    AGENTS.md              → Load behavioral constraints (L0)
2. READ    .memory/context.md     → Load current trajectory (L3)
3. CHECK   Staleness              → Regenerate context.md if stale or missing
4. READ    .memory/graph.md       → Query neighborhood of current task (L2)
                                     [SKIP on MVP tier — graph.md does not exist]
5. VERIFY  Constraints            → Confirm task is within boundaries
6. EXECUTE Task
```

### Shutdown Sequence

```
1. APPEND        All decisions/changes to CHANGELOG.md    (L1)
2. MATERIALIZE   New events into .memory/graph.md         (L2)
3. REGENERATE    .memory/context.md from L1 + L2          (L3)
4. COMMIT        All changes in a single git commit
5. HANDOFF       If in a pipeline, write handoff event
6. DIE           Purge all local/working memory
```

### Documentation Parity Checklist

Before closing any task:
- [ ] README.md reflects the current state of the project
- [ ] CHANGELOG.md has an event for this change
- [ ] SYSTEM-MAP.md updated if architecture changed
- [ ] All affected documentation files match the implementation

### Handoff Protocol

Handoffs are `handoff`-type events in `CHANGELOG.md`. Not separate files. Not transient payloads.

```markdown
### evt-NNN | YYYY-MM-DD HH:MM | from-agent | handoff

**Scope**: module or feature area
**Summary**: What is being handed off and why

**Details**:
- From agent: agent-name
- To agent: next-agent-name
- Invariants: what the next agent must not violate
- Boundaries: scope limits for the next agent
- Artifacts: evt-NNN, evt-NNN (events with relevant context)
```

**Rules**: Forward-only. Scoped to next agent's role. Reference event IDs, not raw data. No undocumented assumptions. No cross-role opinions.

---

## 6. Section Specifications

### AGENTS.md

Required sections: project identity and scope · Do/Don't rules · file naming conventions · workflow definitions · Three Pillars requirements · memory system reference · prompt validation reference.

Must not contain: tutorial content, onboarding narrative, technology history.  
Template: `templates/AGENTS.md.tpl.md`

### CHANGELOG.md

Required sections: header comment · event format documentation block · `## Events` section (all events append here).

Append rules apply from the very first commit. No freeform narrative sections.  
Template: `templates/CHANGELOG.md.tpl.md`

### TODO.md

Required sections: Active · In Progress · Blocked · Done.

Rules: never delete tasks — mark as done. Link each completed task to its CHANGELOG event. Blocked tasks reference the blocking event ID.  
Template: `templates/TODO.md.tpl.md`

### README.md

Required sections: project title + one-line tagline · what it does (2–3 sentences) · quick start (≤5 commands) · key features (bullet list) · links to full docs, CONTRIBUTING.md, SECURITY.md.

Max 150 lines. Long content belongs in `docs/`.  
Template: `templates/README.md.tpl.md`

### QUICKSTART.md

Required sections: prerequisites (exact versions) · installation (copy-pasteable commands) · first run (what success looks like) · common errors and fixes.  
Template: `templates/QUICKSTART.md.tpl.md`

### CONTRIBUTING.md

Required sections: how to report bugs · how to propose features · development setup · branching and commit conventions · PR process and review criteria · Three Pillars requirement for contributors.  
Template: `templates/CONTRIBUTING.md.tpl.md`

### SECURITY.md

Required sections: supported versions table · how to report a vulnerability (private channel) · response timeline commitment · what information to include in a report.  
Template: `templates/SECURITY.md.tpl.md`

### docs/SYSTEM-MAP.md

Required sections: system overview diagram (ASCII or Mermaid) · component inventory (name, purpose, location, owner) · data flow · dependency map · decision log (links to CHANGELOG decision events).  
Template: `templates/SYSTEM-MAP.md.tpl.md`

### .memory/graph.md

Required sections: Nodes table (Node, Type, Status, Created evt, Last Event, Attributes) · Edges table (From, To, Relation, Created evt) · Meta section (last updated, event horizon, counts).

Never edit directly. Materialize from CHANGELOG.md events only.  
Template: `templates/memory/graph.md.tpl.md`

### .memory/context.md

Required sections: Active Mission · Current Sprint · Active Constraints · Blockers · Recent Changes · Key Dependencies · Next Actions.

Ephemeral. Regenerate every session from L1 + L2.  
Template: `templates/memory/context.md.tpl.md`

### docs/PROMPT-VALIDATION.md

Required sections: Quick Validation (4-check pass/fail) · Standard Validation (5-dimension scoring) · Security patterns blocklist · Type-specific checklists.

See `prompt-validation/SKILL.md` for the full protocol if the skill is available in the repo; otherwise use the template as a starting point.  
Template: `templates/PROMPT-VALIDATION.md.tpl.md`

### WORKFLOW.md

Required sections: branching strategy (with rules) · development cycle (starting work, during development, opening a PR, merging) · release process and checklist · commit message convention · CI / automation table (check, trigger, command).

Full tier only. Defines the team's branching, release, and merge conventions.  
Template: `templates/WORKFLOW.md.tpl.md`

### EVALS.md

Required sections: output quality standards table (criterion, minimum, target, how to measure) · task completion criteria (functional + Three Pillars + agent-specific) · evaluation rubric (dimension × score scale) · benchmark tasks table · regression baselines table.

Full tier only. Defines quality gates and acceptance criteria for both agents and humans.  
Template: `templates/EVALS.md.tpl.md`

### DOCUMENTATION-OVERVIEW.md

Required sections: root-level documents table (document, purpose, audience, tier) · docs/ directory table · memory system table · AI agent files table · API reference table (if applicable) · ADR table (if applicable) · documentation health checklist.

Full tier only. Single index of every document in the project.  
Template: `templates/DOCUMENTATION-OVERVIEW.md.tpl.md`

### CODE_OF_CONDUCT.md

Required sections: our pledge · our standards (expected + unacceptable behavior) · responsibilities · enforcement (contact channel) · attribution.

Full tier only. Adapted from the Contributor Covenant.  
Template: `templates/CODE_OF_CONDUCT.md.tpl.md`

### LICENSE.md

Required sections: license name and SPDX identifier · full license text · copyright notice with year and holder.

Full tier only. Choose an OSI-approved license or proprietary notice as appropriate.  
Template: `templates/LICENSE.md.tpl.md`

### .github/ Templates

**.github/PULL_REQUEST_TEMPLATE.md** — Required sections: summary · changes list · related issues/events · Three Pillars checklist (AUTOMATING, TESTING, DOCUMENTING) · screenshots/output · notes for reviewer.

**.github/ISSUE_TEMPLATE/bug_report.md** — Required sections: describe the bug · to reproduce (numbered steps) · expected behavior · actual behavior · environment table · additional context · possible fix.

**.github/ISSUE_TEMPLATE/feature_request.md** — Required sections: problem statement · proposed solution · alternatives considered · acceptance criteria · Three Pillars impact · additional context · implementation notes.

**.github/ISSUE_TEMPLATE/config.yml** — Enables blank issues and links to external resources (e.g. discussions, security reporting).

**.github/CODEOWNERS** — Maps file paths to responsible reviewers.

Full tier only.  
Templates: `templates/github/`

### AI Tool Files (CLAUDE.md, WINDSURF.md, etc.)

Required sections: tool-specific launch instructions · relevant MCP tools or extensions · project-specific hints · link to AGENTS.md for all behavioral rules.

Max 60 lines per file.  
Template: `templates/AI-TOOL.md.tpl.md`

---

## 7. Implementation Workflow

### Phase 1: Foundation

1. Copy `templates/AGENTS.md.tpl.md` → `AGENTS.md`; fill all `{{PLACEHOLDER}}` values
2. Copy `templates/CHANGELOG.md.tpl.md` → `CHANGELOG.md`; record first `create` event
3. Copy `templates/README.md.tpl.md` → `README.md`; fill project-specific content
4. Commit: `"docs: initialize documentation foundation"`

### Phase 2: Memory Setup

5. Create `.memory/` directory
6. Copy `templates/memory/graph.md.tpl.md` → `.memory/graph.md`; initialize nodes for project components
7. Copy `templates/memory/context.md.tpl.md` → `.memory/context.md`; fill current session
8. Commit: `"docs: initialize memory system"`

### Phase 3: Core Documentation

9. Copy and fill: `QUICKSTART.md`, `CONTRIBUTING.md`, `SECURITY.md`, `TODO.md`
10. Create `docs/` directory
11. Copy and fill: `docs/SYSTEM-MAP.md`, `docs/PROMPT-VALIDATION.md`
12. Commit: `"docs: add core documentation"`

### Phase 4: Full Tier (if applicable)

13. Copy and fill remaining root files: `WORKFLOW.md`, `CODE_OF_CONDUCT.md`, `LICENSE.md`, `EVALS.md`, `DOCUMENTATION-OVERVIEW.md`
14. Create `.github/` directory and copy issue/PR templates
15. Copy and fill AI agent files: `CLAUDE.md`, `WINDSURF.md`, etc.
16. Run Three Pillars checklist on all files
17. Commit: `"docs: complete full-tier documentation"`

---

## 8. Tier Scaling

| Signal | MVP | Core | Full |
|--------|-----|------|------|
| Solo developer | ✅ | — | — |
| Multiple developers or agents | — | ✅ | ✅ |
| Complex dependency chains | — | — | ✅ |
| Duration < 1 month | ✅ | — | — |
| Duration 1–6 months | — | ✅ | — |
| Duration > 6 months | — | — | ✅ |
| Formal handoff protocols needed | — | ✅ | ✅ |
| Compliance or audit requirements | — | — | ✅ |
| Multiple AI tools in use | — | ✅ | ✅ |

**Upgrade triggers**:
- MVP → Core: CHANGELOG exceeds 30 events, or >1 agent working concurrently
- Core → Full: >3 concurrent agents, complex dependency queries needed, or >6 months duration

---

## 9. Quality Standards

### Documentation Health Checks

Run at the start of every session:
- [ ] `AGENTS.md` exists and has not been modified in this session
- [ ] `CHANGELOG.md` last event matches `.memory/graph.md` event horizon
- [ ] `.memory/context.md` is current (event horizon matches CHANGELOG)
- [ ] No `{{PLACEHOLDER}}` strings remain in any file
- [ ] No broken links (all referenced files exist)

### Per-File Standards

| Standard | Applies To |
|----------|-----------|
| Max 150 lines | README.md |
| Max 60 lines | AI tool files (CLAUDE.md, WINDSURF.md, etc.) |
| Append-only | CHANGELOG.md |
| Never edit directly | .memory/graph.md, .memory/context.md |
| Immutable during execution | AGENTS.md |
| No curriculum language | AGENTS.md (no "learn", "study", "practice") |
| No undefined placeholders | All files |
| **Right tool for the job** | Use skills when available, spawn subagents for parallel tasks, scripts for mechanical checks, LLM judgment only for reasoning |

### Validation Checklist (Three Pillars)

Before declaring any task complete:

**AUTOMATING**
- [ ] Structure validator run — 0 errors (sections present, naming conventions, tier structure)
- [ ] Skills and subagents used correctly (parallel tasks spawned, right tool for each job)
- [ ] Placeholder scanner run — 0 `{{PLACEHOLDER}}` strings remaining in any file
- [ ] Link checker run — 0 broken links, all referenced files exist
- [ ] Linter / formatter run — 0 style errors
- [ ] All automated checks exited with 0 errors

**TESTING**
- [ ] All code examples tested and runnable
- [ ] Setup instructions verified end-to-end
- [ ] All internal links resolve

**DOCUMENTING**
- [ ] CHANGELOG.md has event for this change
- [ ] All affected docs updated to match implementation
- [ ] Memory layers (graph.md, context.md) regenerated

---

## 10. How the Files Connect

Understanding the relationship between files prevents confusion about what to read and what to update.

### Information Flow

```text
Human / External Request
    │
    ▼
AGENTS.md  ◄── Read first. Defines what agents can and cannot do.
    │
    ▼
.memory/context.md  ◄── Read second. "What is happening right now?"
    │                     (ephemeral — regenerated from L1 + L2)
    ▼
CHANGELOG.md  ◄── Source of truth. "What happened and when?"
    │                (append-only event log)
    ▼
.memory/graph.md  ◄── Derived from CHANGELOG. "How do entities relate?"
    │
    ▼
Execute Task  ──► Update affected files ──► Append event to CHANGELOG
    │
    ▼
Shutdown: Materialize graph ──► Regenerate context ──► Commit ──► Die
```

### What Each File Answers

| Question | Answer Source |
|----------|--------------|
| "What can agents do and not do?" | `AGENTS.md` |
| "What is this project?" | `README.md` |
| "What changed and when?" | `CHANGELOG.md` |
| "What's left to do?" | `TODO.md` |
| "How do I set up and run this?" | `QUICKSTART.md` |
| "How do I contribute?" | `CONTRIBUTING.md` |
| "How do I report a vulnerability?" | `SECURITY.md` |
| "What does the architecture look like?" | `docs/SYSTEM-MAP.md` |
| "Is this prompt safe to execute?" | `docs/PROMPT-VALIDATION.md` |
| "What matters right now?" | `.memory/context.md` |
| "How do entities relate?" | `.memory/graph.md` |
| "What's the branching/release process?" | `WORKFLOW.md` |
| "Is the output good enough?" | `EVALS.md` |
| "Where is all the documentation?" | `DOCUMENTATION-OVERVIEW.md` |
| "How do I use [specific AI tool]?" | `CLAUDE.md`, `WINDSURF.md`, etc. |

### File Dependency Graph

Files are layered by trust and derivation. Higher files never depend on lower ones.

```text
              ┌─────────────┐
              │  AGENTS.md  │  L0 — Constitution (immutable at runtime)
              └──────┬──────┘
                     │ governs
              ┌──────▼──────┐
              │ CHANGELOG.md│  L1 — Event log (append-only, source of truth)
              └──┬───────┬──┘
      materializes│       │derives
          ┌───────▼──┐ ┌──▼──────────┐
          │ graph.md │ │ context.md  │  L2/L3 — Derived views
          └──────────┘ └─────────────┘

    ┌──────────────────────────────────────────────┐
    │  Standalone files — updated by event trigger  │
    │  README · QUICKSTART · CONTRIBUTING · SECURITY│
    │  SYSTEM-MAP · TODO · WORKFLOW · EVALS         │
    └──────────────────────────────────────────────┘
```

### Update Cascade

When a change occurs, the documentation parity table (§5) determines which files need updating. The cascade always flows:

1. **Do the work** — code, config, architecture, whatever changed
2. **Append event** to `CHANGELOG.md` (L1)
3. **Update affected files** per the parity table (README, SYSTEM-MAP, QUICKSTART, etc.)
4. **Materialize** new event into `.memory/graph.md` (L2)
5. **Regenerate** `.memory/context.md` from L1 + L2 (L3)
6. **Commit** all changes as one atomic transaction

---

_Templates for each file listed above are in the `templates/` directory._  
_See `QUICK-REFERENCE.md` for a one-page agent cheat sheet._
