# Full Comparison: Documentation Blueprint and Current System — With Bidirectional Improvements

**Purpose**: (1) Full comparison of the Documentation Blueprint to the current repository; (2) how the current system can improve the blueprint; (3) how the blueprint can improve the current system.  
**Audience**: Maintainers of the blueprint, repo contributors, and adopters of either.  
**See also**: `_documentation-blueprint/DOCUMENTATION-BLUEPRINT.md`, `CURRENT-REPOSITORY-STATE.md`, `docs/DOCUMENTATION-BLUEPRINT-VS-CURRENT-SETUP.md` (shorter gap list).

---

## Part I — Full Comparison

### I.1 Blueprint Tier Model

The Documentation Blueprint defines three tiers of required files:

| Tier | Purpose | Root files | docs/ | .memory/ | Other |
|------|---------|------------|-------|----------|--------|
| **MVP** | Minimum viable | AGENTS.md, CHANGELOG.md, README.md | — | context.md | — |
| **Core** | Standard project | + TODO.md, QUICKSTART.md, CONTRIBUTING.md, SECURITY.md | PROMPT-VALIDATION.md, SYSTEM-MAP.md | + graph.md | — |
| **Full** | Enterprise / multi-agent | + WORKFLOW.md, DOCUMENTATION-OVERVIEW.md, CODE_OF_CONDUCT.md, LICENSE.md, EVALS.md | + api/, adr/ | (same) | .github/ (PR/issue templates, CODEOWNERS) |

**AI agent files** (Core/Full): One file per tool (CLAUDE.md, CURSOR.md, WINDSURF.md, etc.), each ≤60 lines, linking to AGENTS.md for all behavioral rules.

**Design principles** (blueprint): Constitution over checklists (AGENTS.md = law); event-sourced truth (CHANGELOG = source of truth); one-way flow L1→L2→L3; stateless agents; documentation parity; git as database; tier-appropriate complexity.

---

### I.2 Current Repository vs Blueprint (File-Level)

#### Root

| Blueprint | Current | Notes |
|-----------|---------|--------|
| AGENTS.md | ✅ | Present, canonical rules |
| CHANGELOG.md | ✅ | Uses `## Event Log` (blueprint says `## Events`) |
| README.md | ✅ | Present |
| TODO.md | ✅ | Present |
| QUICKSTART.md | ❌ | Only in _documentation-blueprint/, not at root |
| CONTRIBUTING.md | ❌ | Missing |
| SECURITY.md | ❌ | Missing |
| WORKFLOW.md | ❌ | Full tier; not present |
| DOCUMENTATION-OVERVIEW.md | ⚠️ | Repo uses **docs/INDEX.md** as doc index |
| CODE_OF_CONDUCT.md | ❌ | Full tier; not present |
| LICENSE.md / LICENSE | ❌ | Full tier; not checked |
| EVALS.md | ❌ | Full tier; not present |
| AGENTIC-ASSETS-FRAMEWORK.md | — | **Extra**: seven template types, not in blueprint |
| CURRENT-REPOSITORY-STATE.md | — | **Extra**: repo inventory |

#### AI / Rule files

| Blueprint | Current | Notes |
|-----------|---------|--------|
| AGENTS.md | ✅ | Single constitution |
| CLAUDE.md ≤60 lines | ⚠️ | Present but long (~39KB); blueprint suggests ≤60 |
| CURSOR.md | ✅ | Present, thinner |
| WINDSURF.md | ✅ | Present, thinner |

#### Memory (L1–L3)

| Layer | Blueprint | Current | Notes |
|-------|-----------|---------|--------|
| L0 | AGENTS.md | ✅ | Immutable at runtime |
| L1 | CHANGELOG.md | ✅ | Append-only; section name "Event Log" |
| L2 | .memory/graph.md | ✅ | **Stale**: horizon evt-001, CHANGELOG at evt-011 |
| L3 | .memory/context.md | ✅ | Horizon evt-011, matches CHANGELOG |

#### docs/

| Blueprint | Current | Notes |
|-----------|---------|--------|
| docs/PROMPT-VALIDATION.md | — | Repo has **docs/protocols/PROMPT-VALIDATION-PROTOCOL.md** (protocol type, installable via skill) |
| docs/SYSTEM-MAP.md | ❌ | Missing; architecture spread across framework, CURRENT-REPOSITORY-STATE, INDEX |
| docs/api/ | ❌ | Full tier; not present |
| docs/adr/ | ❌ | Full tier; not present |
| docs/INDEX.md | — | **Extra**: central doc index (blueprint Full has root DOCUMENTATION-OVERVIEW.md) |
| docs/protocols/ | — | **Extra**: MEMORY-SYSTEM-PROTOCOL.md, PROMPT-VALIDATION-PROTOCOL.md |
| docs/memory-system/ | — | **Extra**: memory docs, scripts, templates |
| docs/guides/, core/, templates/, etc. | — | **Extra**: rich docs structure |

#### .github/ (Full tier)

| Blueprint | Current |
|-----------|---------|
| PULL_REQUEST_TEMPLATE.md, CODEOWNERS, ISSUE_TEMPLATE/* | ❌ Not present (templates exist in _documentation-blueprint/templates/github/) |

#### .agents/skills/ and _documentation-blueprint/

Not in the blueprint file inventory. Current repo has nine skills and the blueprint folder (DOCUMENTATION-BLUEPRINT.md, QUICK-REFERENCE.md, QUICKSTART.md, templates/).

---

### I.3 Alignment Summary

- **MVP**: Met (AGENTS, CHANGELOG, README, .memory/context).
- **Core**: Partially met. Missing: root QUICKSTART, CONTRIBUTING, SECURITY; docs/SYSTEM-MAP.md. Prompt validation covered by docs/protocols/ protocol; graph.md stale.
- **Full**: Not aimed for; several Full-tier items absent. docs/INDEX.md acts as doc overview.

---

## Part II — How the Current System Can Improve the Documentation Blueprint

These are concrete ways the **current repository’s practices and structure** could strengthen the Documentation Blueprint (for future blueprint versions or for projects that adopt both).

### II.1 Introduce “Protocols” as a First-Class Concept

**Current system**: Process documents (e.g. prompt validation, memory) live in **docs/protocols/** as named protocols (PROMPT-VALIDATION-PROTOCOL.md, MEMORY-SYSTEM-PROTOCOL.md). They are **installed and maintained by protocol skills** (prompt-validation-setup, memory-system-setup). Rules reference them by path and do not duplicate their content.

**Blueprint improvement**: In §3 (Required File Inventory), add an optional **Protocols** category:

- **Location**: `docs/protocols/`.
- **Naming**: e.g. `PROMPT-VALIDATION-PROTOCOL.md`, `MEMORY-SYSTEM-PROTOCOL.md`.
- **Installation**: Via “protocol skills” or a setup step; not necessarily created by hand.
- **Relationship**: Core tier could specify “docs/PROMPT-VALIDATION.md **or** docs/protocols/PROMPT-VALIDATION-PROTOCOL.md (when using protocol skills).” This allows both the single-file pattern (docs/PROMPT-VALIDATION.md) and the protocol pattern (docs/protocols/ + skills).

**Benefit**: Blueprint supports installable, versionable process docs and aligns with template ecosystems that distinguish “protocols” from generic docs.

---

### II.2 Allow docs/INDEX.md as Alternative to Root DOCUMENTATION-OVERVIEW.md

**Current system**: The main documentation index is **docs/INDEX.md** (Quick Reference table, Core Documentation, Guides, Protocols, etc.). Root does not have DOCUMENTATION-OVERVIEW.md.

**Blueprint improvement**: In Full tier (§3), state that the “documentation overview” may live either as:

- **Root**: `DOCUMENTATION-OVERVIEW.md`, or  
- **docs**: `docs/INDEX.md` (or similar), with a one-line pointer from root or README.

**Benefit**: Repos that centralize docs under `docs/` can use a single index there without duplicating a root overview.

---

### II.3 Reference a “Template Types” or “Ecosystem” Framework

**Current system**: **AGENTIC-ASSETS-FRAMEWORK.md** defines seven template types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols). Rules (AGENTS.md, CLAUDE.md, etc.) are one type; Protocols are another. Skills and protocol skills are first-class.

**Blueprint improvement**: In §1 or §3, add a short “Ecosystem alignment” note:

- Projects may adopt a **template-type framework** (e.g. Rules, Protocols, Skills, Blueprints, Tasks, Recipes, Subagents). The blueprint’s required files map onto that (e.g. Rules = AGENTS.md + tool files; Protocols = docs/protocols/). Reference an external framework doc when present (e.g. AGENTIC-ASSETS-FRAMEWORK.md).

**Benefit**: Blueprint stays generic but interoperates with multi-type template systems.

---

### II.4 Event Log Section Name and Event Format

**Current system**: CHANGELOG uses **`## Event Log`** and events like `### evt-NNN | date | agent | type` with **Scope**, **Summary**, **Details**, **Refs**, **Tags**. Same idea as blueprint; section heading differs.

**Blueprint improvement**: In §4 (Memory) and §6 (Section Specifications), allow either:

- `## Events` or `## Event Log` for the changelog section that contains events.

Optionally reference “evt-NNN” and the Ref/Tags pattern as a recommended format so blueprint and current practice stay aligned.

**Benefit**: One blueprint fits repos that use “Event Log” and evt-NNN without renaming.

---

### II.5 Staleness Check and Graph Materialization

**Current system**: **.memory/context.md** includes an “Event horizon” line and instructs agents to compare it to the last event in CHANGELOG; if they differ or context is missing, **regenerate** context (and graph) from the event log. Memory protocol and rules-setup/memory-system-setup document this.

**Blueprint improvement**: In §4 (Memory Architecture) and §5 (Agent Rules), add an explicit **staleness rule**:

- On boot, compare “event horizon” in .memory/context.md (and .memory/graph.md if present) to the last event ID in CHANGELOG. If they differ or the file is missing, **regenerate** the derived layer(s) from L1 before proceeding. Never edit graph.md or context.md backward to match an older event.

**Benefit**: Blueprint encodes the same recovery rule many implementations already use.

---

### II.6 Repository State / Inventory Document

**Current system**: **CURRENT-REPOSITORY-STATE.md** is a single “what exists now” inventory: root files, directory tree, what’s active vs archived, integration points. It is updated when structure or implementation status changes.

**Blueprint improvement**: In Core or Full tier, add an optional **repository state / inventory** doc (e.g. `CURRENT-REPOSITORY-STATE.md` or `REPOSITORY-STATE.md`):

- Purpose: Snapshot of current layout, active vs archived areas, and where to find things.  
- Update trigger: When directories, key files, or “what’s in use” changes.

**Benefit**: New contributors and agents get one place to see current layout and status without reading the whole blueprint.

---

### II.7 Skills and “Protocol Skills” in AUTOMATING

**Current system**: AGENTS.md and framework say “use skills when available” and “protocol skills install/maintain protocol files.” Prompt validation is applied before every task (4 checks); full detail lives in the protocol; skills do the install.

**Blueprint improvement**: In §2 (Three Pillars — AUTOMATING), already “Use skills when available. Spawn subagents for parallel tasks.” Extend with:

- When the project uses **protocol skills** (e.g. prompt-validation-setup, memory-system-setup), agents should use them to install or update protocol files in docs/protocols/ (or equivalent). Pre-task validation (e.g. 4 checks) can be summarized in Rules and linked to the full protocol.

**Benefit**: Blueprint explicitly supports skill-driven protocol installation and the “thin rule + full protocol” pattern.

---

### II.8 AI Tool File Length: Allow Documented Exceptions

**Current system**: CLAUDE.md is long (~39KB); CURSOR.md and WINDSURF.md are short. Behavioral content lives in AGENTS.md; tool files add tool-specific context and commands.

**Blueprint improvement**: Keep “≤60 lines per AI file” as the default, and add:

- **Exception**: A project may designate one or more AI files as “extended reference” (e.g. CLAUDE.md) and document that in the blueprint or in AGENTS.md. Other tool files (CURSOR.md, WINDSURF.md) stay thin and point to AGENTS.md.

**Benefit**: Blueprint stays strict by default but allows one extended tool file where useful.

---

## Part III — How the Documentation Blueprint Can Improve the Current System

These are concrete ways **adopting the Documentation Blueprint’s requirements and practices** could improve the current repository.

### III.1 Add Core-Tier Root Files: QUICKSTART, CONTRIBUTING, SECURITY

**Blueprint**: Core tier requires QUICKSTART.md, CONTRIBUTING.md, SECURITY.md at root.

**Current gap**: None of these exist at repo root (QUICKSTART exists only inside _documentation-blueprint/).

**Improvement**:

- **QUICKSTART.md** (root): Prerequisites (e.g. Python 3, Node if needed), clone/setup, validate (e.g. JSON, optional scripts), first steps (e.g. run a skill, read AGENTS.md). Copy/adapt from _documentation-blueprint/QUICKSTART.md.
- **CONTRIBUTING.md**: How to contribute (branching, commits, PRs), development setup, Three Pillars requirement for contributors, link to AGENTS.md and docs/INDEX.md. Use _documentation-blueprint/templates/CONTRIBUTING.md.tpl.md as base.
- **SECURITY.md**: Supported versions (e.g. “this repo’s docs and skills”), how to report vulnerabilities (private channel), response timeline, what to include in a report. Use _documentation-blueprint/templates/SECURITY.md.tpl.md as base.

**Benefit**: New contributors and agents get a clear path to run, contribute, and report security issues.

---

### III.2 Add docs/SYSTEM-MAP.md

**Blueprint**: Core tier requires docs/SYSTEM-MAP.md with system overview, component inventory, data flow, dependency map, decision log (links to CHANGELOG).

**Current gap**: No single SYSTEM-MAP; architecture is in AGENTIC-ASSETS-FRAMEWORK.md, CURRENT-REPOSITORY-STATE.md, INDEX.md.

**Improvement**: Add **docs/SYSTEM-MAP.md** (from _documentation-blueprint/templates/SYSTEM-MAP.md.tpl.md) and fill it with:

- **Overview**: Unified AI dev ecosystem; seven template types; Rules + Protocols + Skills active; rest archived.
- **Components**: .agents/skills (nine skills), docs/ (INDEX, protocols, memory-system, guides, …), .memory/ (graph, context), root (AGENTS, CHANGELOG, README, rule files), _documentation-blueprint/, _complete_archive/.
- **Data flow**: L0→L1→L2→L3; event log → graph → context; Rules reference Protocols; skills invoked by triggers.
- **Dependencies**: CHANGELOG → graph/context; AGENTS.md references protocols and template framework.
- **Decision log**: Link to selected CHANGELOG events (e.g. evt-006 Protocols, evt-007 skill-setup rename).

**Benefit**: One place for “how the repo is structured and how data flows,” matching blueprint Core.

---

### III.3 Formalize Prompt Validation Location (Pointer or Alias)

**Blueprint**: Core tier expects docs/PROMPT-VALIDATION.md. Current repo uses docs/protocols/PROMPT-VALIDATION-PROTOCOL.md.

**Improvement**: Choose one:

- **Option A**: Add **docs/PROMPT-VALIDATION.md** (≤1 page) that states: “Prompt validation is defined in **docs/protocols/PROMPT-VALIDATION-PROTOCOL.md**. Install it in a new project with the **prompt-validation-setup** skill. Before every task, agents run the 4 checks summarized in AGENTS.md.”
- **Option B**: In docs/INDEX.md and SYSTEM-MAP (once added), state clearly that the canonical prompt-validation doc is docs/protocols/PROMPT-VALIDATION-PROTOCOL.md and that Rules reference it. Do not add a separate docs/PROMPT-VALIDATION.md.

**Benefit**: Blueprint readers know where “PROMPT-VALIDATION” lives; no duplication of protocol content.

---

### III.4 Keep .memory/graph.md Materialized and Document the Rule

**Blueprint**: L2 (graph.md) is materialized from L1 only; never edited directly. Recovery: trust L1 → rebuild L2 → rebuild L3.

**Current gap**: .memory/graph.md event horizon is evt-001; CHANGELOG is at evt-011. Graph was not updated when events were appended.

**Improvement**:

- **Process**: After appending events to CHANGELOG, materialize new events into .memory/graph.md (nodes/edges/meta, event horizon = last evt), then regenerate .memory/context.md. Document this in AGENTS.md “After every task” and in the memory protocol.
- **One-time**: Regenerate .memory/graph.md from CHANGELOG (evt-001 through evt-011) so horizon matches. Use memory-system scripts if available (e.g. validate-memory, or a small script that updates graph from event log).
- **Ongoing**: Enforce “graph horizon = last CHANGELOG event” in the memory protocol and in agent shutdown steps.

**Benefit**: L2 is always consistent with L1; recovery and staleness checks work as in the blueprint.

---

### III.5 Adopt Blueprint’s DOCUMENTING Table in AGENTS.md

**Blueprint**: §2 (DOCUMENTING) and §5 (Documentation Parity Checklist) give a **change-type → required updates** table (e.g. new feature → README, SYSTEM-MAP, CHANGELOG; API change → API reference, CHANGELOG, QUICKSTART if affected).

**Current**: AGENTS.md has a “Three Pillars — DOCUMENTING” and a change-type table; it may not mirror the blueprint’s table exactly.

**Improvement**: Ensure AGENTS.md’s DOCUMENTING section includes (or references) a table that covers:

- New feature/module → README, SYSTEM-MAP (or CURRENT-REPOSITORY-STATE), CHANGELOG  
- New protocol or skill → CHANGELOG, docs/INDEX, protocol/skill docs  
- New rule file → AGENTIC-ASSETS-FRAMEWORK, Key References in all rule files  
- Architecture/behavioral change → SYSTEM-MAP, AGENTS.md if behavioral, CHANGELOG  

Add rows for “New protocol,” “New skill,” “Repository structure change” if missing.

**Benefit**: Agents and humans have a single, blueprint-aligned checklist for what to update per change type.

---

### III.6 Tier Scaling and Optional Full-Tier Items

**Blueprint**: §8 defines when to use MVP vs Core vs Full (solo vs multi-agent, duration, handoffs, compliance). Full tier adds WORKFLOW.md, DOCUMENTATION-OVERVIEW.md, CODE_OF_CONDUCT.md, LICENSE.md, EVALS.md, .github/, docs/api/, docs/adr/.

**Improvement** (optional):

- **Decide tier**: State in README or CURRENT-REPOSITORY-STATE that this repo targets “MVP + Core” (or “partial Full”) and list which Full-tier items are intentionally omitted.
- **Selective Full**: If useful, add only some Full items, e.g.:  
  - **WORKFLOW.md**: Branching, release, commit convention, CI (if any).  
  - **.github/**: Install PR and issue templates from _documentation-blueprint/templates/github/ for consistency.  
  - **CODE_OF_CONDUCT.md** / **LICENSE.md**: If the repo is public or wants to formalize conduct/licensing.

**Benefit**: Clear tier choice and optional Full elements without adopting the entire Full set.

---

### III.7 Section Specifications and Quality Standards

**Blueprint**: §6 specifies required sections per file (e.g. README: title, tagline, what it does, quick start, key features, links; AGENTS: identity, Do/Don’t, naming, workflows, Three Pillars, memory, prompt validation).

**Improvement**: Periodically audit root and key docs against blueprint §6:

- README: length (e.g. ≤150 lines), required sections.  
- AGENTS.md: required sections present, no tutorial content.  
- CHANGELOG: append-only, event format, section name (Event Log vs Events).  
- .memory/context.md: required sections (Active Mission, Current Sprint, Constraints, Blockers, Recent Changes, Dependencies, Next Actions).  
- .memory/graph.md: Nodes, Edges, Meta; event horizon.

Use the result as a checklist in CONTRIBUTING or in a docs-health script.

**Benefit**: Documentation stays aligned with a clear, shared standard.

---

### III.8 Boot and Shutdown Sequences

**Blueprint**: §5 defines Boot (read AGENTS → context → check staleness → graph → verify → execute) and Shutdown (append CHANGELOG → materialize graph → regenerate context → commit → handoff if needed → die).

**Current**: AGENTS.md and memory protocol already describe load order and staleness; shutdown may not explicitly say “materialize graph then regenerate context.”

**Improvement**: In AGENTS.md (and memory protocol if present), make the **shutdown sequence** explicit and ordered:

1. Append event(s) to CHANGELOG.md.  
2. Materialize new events into .memory/graph.md (event horizon = last evt).  
3. Regenerate .memory/context.md from L1 + L2.  
4. Commit all changes.  
5. If handoff: write handoff event; otherwise terminate.

**Benefit**: Same as blueprint: no ambiguity on order and no backward edits to L2/L3.

---

## Part IV — Summary Tables

### IV.1 Current system → Blueprint (improvements to blueprint)

| # | Suggestion |
|---|------------|
| 1 | Add **Protocols** (docs/protocols/, protocol skills) as optional first-class category in file inventory. |
| 2 | Allow **docs/INDEX.md** as alternative to root DOCUMENTATION-OVERVIEW.md for Full tier. |
| 3 | Add **ecosystem/template-types** note (e.g. Rules, Protocols, Skills) and optional reference to framework docs. |
| 4 | Allow **`## Event Log`** and **evt-NNN** format in CHANGELOG section name and event structure. |
| 5 | Add explicit **staleness rule**: regenerate L2/L3 when event horizon ≠ last CHANGELOG event. |
| 6 | Add optional **repository state / inventory** doc (e.g. CURRENT-REPOSITORY-STATE.md) in Core/Full. |
| 7 | In AUTOMATING, reference **protocol skills** for installing/maintaining protocol files. |
| 8 | Allow **documented exception** for one “extended reference” AI file (e.g. CLAUDE.md) beyond 60 lines. |

### IV.2 Blueprint → Current system (improvements to repo)

| # | Suggestion |
|---|------------|
| 1 | Add **QUICKSTART.md**, **CONTRIBUTING.md**, **SECURITY.md** at root (Core tier). |
| 2 | Add **docs/SYSTEM-MAP.md** (overview, components, data flow, dependencies, decision log). |
| 3 | Formalize **prompt validation** location: pointer doc at docs/PROMPT-VALIDATION.md or clear statement in INDEX/SYSTEM-MAP. |
| 4 | **Materialize .memory/graph.md** from CHANGELOG and keep it updated; document rule in protocol and AGENTS. |
| 5 | Align **DOCUMENTING** change-type table in AGENTS.md with blueprint and add protocol/skill/structure rows. |
| 6 | State **tier** (MVP + Core) and optionally add selected Full-tier items (WORKFLOW, .github, CODE_OF_CONDUCT, LICENSE). |
| 7 | Audit **section specs** (§6) and **quality standards** (§9) for key files; add checklist or script. |
| 8 | Make **shutdown sequence** explicit (append → materialize graph → regenerate context → commit). |

---

*Document generated 2026-02-27. Update when the blueprint or repo structure changes.*
