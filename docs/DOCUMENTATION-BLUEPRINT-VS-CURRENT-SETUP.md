# Documentation Blueprint vs Current Setup

**Purpose**: Compare `_documentation-blueprint/DOCUMENTATION-BLUEPRINT.md` (required file inventory and tiers) to the current repository.  
**Generated**: 2026-02-27  
**See also**: `_documentation-blueprint/DOCUMENTATION-BLUEPRINT.md`, `CURRENT-REPOSITORY-STATE.md`

---

## 1. Blueprint Tier Summary

The Documentation Blueprint defines three tiers:

| Tier | Purpose | Key additions |
|------|---------|----------------|
| **MVP** | Minimum viable | AGENTS.md, CHANGELOG.md, README.md, .memory/context.md |
| **Core** | Standard project | + TODO.md, QUICKSTART.md, CONTRIBUTING.md, SECURITY.md, .memory/graph.md, docs/PROMPT-VALIDATION.md, docs/SYSTEM-MAP.md |
| **Full** | Enterprise / multi-agent | + WORKFLOW.md, DOCUMENTATION-OVERVIEW.md, CODE_OF_CONDUCT.md, LICENSE.md, EVALS.md, docs/api/, docs/adr/, .github/ (PR/issue templates, CODEOWNERS) |

AI agent files (Core/Full): AGENTS.md + one short file per tool (CLAUDE.md, CURSOR.md, WINDSURF.md, etc.), each ≤60 lines, linking to AGENTS.md.

---

## 2. Current Setup vs Blueprint

### 2.1 Root-Level Files

| Blueprint requirement | Location | Status |
|-----------------------|----------|--------|
| **AGENTS.md** | Root | ✅ Present |
| **CHANGELOG.md** | Root | ✅ Present (uses `## Event Log`; blueprint says `## Events`) |
| **README.md** | Root | ✅ Present |
| **TODO.md** | Root (Core+) | ✅ Present |
| **QUICKSTART.md** | Root (Core+) | ⚠️ **Missing at root** — exists only in `_documentation-blueprint/QUICKSTART.md` |
| **CONTRIBUTING.md** | Root (Core+) | ❌ **Missing** |
| **SECURITY.md** | Root (Core+) | ❌ **Missing** |
| **WORKFLOW.md** | Root (Full) | ❌ Missing (Full tier) |
| **DOCUMENTATION-OVERVIEW.md** | Root (Full) | ⚠️ **Different**: repo has `docs/INDEX.md` as docs index, not root DOCUMENTATION-OVERVIEW.md |
| **CODE_OF_CONDUCT.md** | Root (Full) | ❌ Missing (Full tier) |
| **LICENSE.md** | Root (Full) | ❌ Missing (Full tier; repo may have LICENSE without .md) |
| **EVALS.md** | Root (Full) | ❌ Missing (Full tier) |

### 2.2 AI Agent / Rule Files

| Blueprint | Current | Status |
|-----------|---------|--------|
| AGENTS.md (constitution) | ✅ | Present |
| CLAUDE.md (≤60 lines) | ✅ | Present (CLAUDE.md is ~39KB — exceeds 60-line guideline) |
| CURSOR.md | ✅ | Present |
| WINDSURF.md | ✅ | Present |

Blueprint says each AI file should be ≤60 lines and link to AGENTS.md for all behavioral rules. CLAUDE.md is much longer; CURSOR.md and WINDSURF.md are thinner.

### 2.3 Memory (L1–L3)

| Blueprint | Current | Status |
|-----------|---------|--------|
| **CHANGELOG.md** (L1 event log) | ✅ | Present, append-only, Event Log section |
| **.memory/graph.md** (L2) | ✅ | Present (event horizon in graph is **evt-001**; CHANGELOG is at **evt-010** — graph is stale) |
| **.memory/context.md** (L3) | ✅ | Present (event horizon evt-010, matches CHANGELOG) |

**Gap**: `.memory/graph.md` has not been materialized from events evt-002–evt-010; event horizon still evt-001.

### 2.4 docs/

| Blueprint | Current | Status |
|-----------|---------|--------|
| **docs/PROMPT-VALIDATION.md** | — | ⚠️ **Different path**: repo has **docs/protocols/PROMPT-VALIDATION-PROTOCOL.md** (protocol type). Functionally equivalent; installable via prompt-validation-setup skill. |
| **docs/SYSTEM-MAP.md** | — | ❌ **Missing** — no docs/SYSTEM-MAP.md (only template in _documentation-blueprint/templates/) |
| **docs/api/** | Full tier | ❌ Not present |
| **docs/adr/** | Full tier | ❌ Not present |

Current docs structure: INDEX.md, protocols/, memory-system/, guides/, core/, templates/, examples/, technical/, universal/. No single SYSTEM-MAP.md; architecture is described in AGENTIC-ASSETS-FRAMEWORK.md, CURRENT-REPOSITORY-STATE.md, and INDEX.md.

### 2.5 .github/ (Full tier)

| Blueprint | Current | Status |
|-----------|---------|--------|
| .github/PULL_REQUEST_TEMPLATE.md | — | ❌ Not present |
| .github/CODEOWNERS | — | ❌ Not present |
| .github/ISSUE_TEMPLATE/config.yml | — | ❌ Not present |
| .github/ISSUE_TEMPLATE/bug_report.md | — | ❌ Not present |
| .github/ISSUE_TEMPLATE/feature_request.md | — | ❌ Not present |

Templates exist in `_documentation-blueprint/templates/github/` but have not been installed at repo root.

---

## 3. What Exists Beyond the Blueprint

The repo adds several things the blueprint does not list:

- **AGENTIC-ASSETS-FRAMEWORK.md** — Framework for seven template types (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols).
- **CURRENT-REPOSITORY-STATE.md** — Repository inventory and directory overview.
- **CURSOR.md, WINDSURF.md** — Present (blueprint allows them; CURSOR.md is tool entry).
- **docs/protocols/** — Protocol documents (PROMPT-VALIDATION-PROTOCOL.md, MEMORY-SYSTEM-PROTOCOL.md); blueprint assumes docs/PROMPT-VALIDATION.md.
- **docs/INDEX.md** — Documentation index (blueprint Full tier has root DOCUMENTATION-OVERVIEW.md).
- **docs/** — guides/, core/, memory-system/, templates/, examples/, technical/, universal/, SUGGESTIONS-FOR-NEW-TEMPLATES.md, TEMPLATES-SYSTEM-OVERVIEW.md, etc.
- **.agents/skills/** — Nine skills (setup and protocol skills).
- **_documentation-blueprint/** — The blueprint itself plus QUICK-REFERENCE.md, QUICKSTART.md, and templates/ (22 files).

---

## 4. Tier Assessment

- **MVP**: Satisfied (AGENTS.md, CHANGELOG.md, README.md, .memory/context.md).
- **Core**: Partially satisfied. Missing at root: QUICKSTART.md, CONTRIBUTING.md, SECURITY.md. Missing in docs: SYSTEM-MAP.md. Prompt validation is covered by docs/protocols/PROMPT-VALIDATION-PROTOCOL.md (different path/name). .memory/graph.md exists but is stale.
- **Full**: Not targeted. WORKFLOW.md, DOCUMENTATION-OVERVIEW.md (or equivalent), CODE_OF_CONDUCT.md, LICENSE.md, EVALS.md, docs/api/, docs/adr/, .github/ are not present; docs/INDEX.md serves as the doc index.

---

## 5. Recommendations

### 5.1 Align with Core tier (if desired)

1. **Add at root** (from _documentation-blueprint/templates/ or QUICKSTART.md):
   - **QUICKSTART.md** — Copy from `_documentation-blueprint/QUICKSTART.md` and adapt to this repo (prerequisites, install, first run, common errors).
   - **CONTRIBUTING.md** — From templates/CONTRIBUTING.md.tpl.md; how to contribute, branch/commit, PR process, Three Pillars.
   - **SECURITY.md** — From templates/SECURITY.md.tpl.md; supported versions, how to report vulnerabilities, response timeline.

2. **Add under docs/**:
   - **docs/SYSTEM-MAP.md** — From _documentation-blueprint/templates/SYSTEM-MAP.md.tpl.md; fill with system overview, components (.agents/skills, docs, .memory, rule files, protocols), data flow, dependencies. Optionally add a short note that prompt validation lives at docs/protocols/PROMPT-VALIDATION-PROTOCOL.md (and link from SYSTEM-MAP or from a one-line docs/PROMPT-VALIDATION.md that points to the protocol).

3. **Prompt validation**: Either add **docs/PROMPT-VALIDATION.md** as a short pointer to `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` (and to the prompt-validation-setup skill), or document in SYSTEM-MAP/INDEX that the canonical prompt-validation doc is the protocol.

4. **Materialize .memory/graph.md** — Regenerate graph from CHANGELOG.md so event horizon matches latest event (evt-010). Keep graph.md updated when appending events (per memory protocol).

### 5.2 Optional (Full tier or consistency)

- **DOCUMENTATION-OVERVIEW.md at root** — If you want strict Full tier: add root DOCUMENTATION-OVERVIEW.md (e.g. from template) and either keep docs/INDEX.md as the docs-hub view or merge roles (e.g. INDEX points to root overview).
- **.github/** — Install PR and issue templates from _documentation-blueprint/templates/github/ if you want GitHub workflow alignment.
- **AI file length** — Trim CLAUDE.md to ≤60 lines for tool-specific onboarding and link to AGENTS.md for full rules, or document an exception (e.g. “CLAUDE.md is extended reference”) in the blueprint or AGENTS.md.

### 5.3 Keep as-is (and document)

- Treat this repo as **MVP + partial Core**, with **docs/protocols/** and **docs/INDEX.md** as intentional variants of the blueprint’s docs/PROMPT-VALIDATION.md and root DOCUMENTATION-OVERVIEW.md.
- Add a short note in README or in _documentation-blueprint/QUICK-REFERENCE.md: “This repo follows the documentation blueprint at MVP and partially at Core; prompt validation and doc index live under docs/protocols/ and docs/INDEX.md.”

---

## 6. Quick Checklist (Core Tier)

| Item | Done |
|------|------|
| AGENTS.md | ✅ |
| CHANGELOG.md | ✅ |
| README.md | ✅ |
| .memory/context.md | ✅ |
| .memory/graph.md | ✅ (content present; **stale** — regenerate) |
| TODO.md | ✅ |
| QUICKSTART.md at root | ❌ |
| CONTRIBUTING.md | ❌ |
| SECURITY.md | ❌ |
| docs/PROMPT-VALIDATION.md or equivalent | ⚠️ docs/protocols/PROMPT-VALIDATION-PROTOCOL.md |
| docs/SYSTEM-MAP.md | ❌ |
| AI files (AGENTS + CLAUDE, CURSOR, WINDSURF) | ✅ |

---

*Comparison generated 2026-02-27. Update this doc when the blueprint or repo structure changes.*
