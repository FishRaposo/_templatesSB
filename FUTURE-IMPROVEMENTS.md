# Future Improvements Backlog

This document captures future improvements identified as valuable during the ongoing audit/consolidation of the Universal Template System.

It is intentionally:

- **Implementation-oriented** (what to change, not just “nice ideas”)
- **Prioritized** (P0 = unblockers, P3 = optional)
- **Focused on system integrity** (consistency, validation, consolidation, documentation accuracy)

---

## P0 — Repo health (unblockers)

- **Make the repo parse/validate cleanly**
  Ensure `python -m compileall scripts tests -q` succeeds so CI and local validation can be trusted.

- **Repair or archive structurally broken scripts**
  Some scripts contain embedded non-Python content and cannot be “incrementally fixed” safely. Example: `scripts/generate_comprehensive_testing.py` appears to contain raw JS/TS blocks inside the module body.

- **Eliminate merge-conflict remnants and corrupted generated files**
  Add a guardrail step to validation that fails if conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`) exist anywhere in tracked files.

---

## P1 — Consolidation & naming (reduce ambiguity)

- **Choose one naming convention for Python entrypoints**
  The repo currently mixes:
  - Hyphenated CLI scripts (`setup-project.py`, `validate-templates.py`)
  - Importable module-style scripts (`generate_reference_projects.py`, `validate_templates.py`)

  Decide on a canonical convention and provide wrappers if needed.

- **Consolidate duplicate/near-duplicate scripts and keep a single canonical path**
  Notable duplicates discovered:
  - `scripts/generate-reference-projects.py` vs `scripts/generate_reference_projects.py` (archived the hyphenated one)
  - `scripts/generate_missing_tier_templates.py` vs `scripts/generate_missing_tier_templates_fixed.py` (archived the non-fixed one)
  - `scripts/setup-project.py` vs `scripts/setup-project-simple.py`

  Future improvement: keep one canonical implementation and archive the others with a clear replacement mapping.

- **Fix importability mismatches caused by hyphenated filenames**
  Example pattern: scripts importing `setup_project` while the main entrypoint is `setup-project.py`.
  Future improvement: expose an importable module (e.g. `setup_project.py`) and keep the CLI wrapper as thin as possible.

---

## P1 — Task invariants system follow-ups (contract coverage)

- **Expand invariant coverage across the task library**
  Today, invariants exist as a system but coverage is sparse. Future improvement:
  - Add invariants for each task (even minimal “must emit event X / must return key Y”).
  - Decide whether missing invariants should be warn/fail by tier.

- **Standardize invariant linking from `tasks/task-index.yaml`**
  The optional `invariant:` field exists; future improvement is to roll it out consistently and ensure it is the single source of truth for which invariants apply.

- **Document and version the trace format**
  Create a short, authoritative spec for `artifacts/task-trace.jsonl`:
  - Required fields
  - Event types
  - Examples per stack
  - Compatibility guarantees

- **Add stack-neutral trace probes/templates**
  Provide minimal “trace emitters” per stack so runtime enforcement is feasible outside Python-only flows.

- **CI integration**
  Run invariant static validation (and optionally enforcement against a synthetic trace) as part of the full validation pipeline.

---

## P2 — Archive governance (make `_archive/` safe and useful)

- **Decide how `_archive/` should be tracked and validated**
  Current `.gitignore` rules include `_archive/`. If we expect to move files there and keep them in-repo, we should either:
  - Remove/relax the ignore rule, or
  - Keep a tracked “index” file and an explicit allowlist.

- **Create an authoritative archive map**
  Add `_archive/ARCHIVE-MAP.md` containing:
  - What was archived
  - Why it was archived
  - The replacement path (if any)
  - Last known good usage

- **Add validation for archive references**
  Future improvement: fail validation if docs/scripts reference archived paths without an explicit compatibility shim.

---

## P2 — Validation pipeline hardening

- **Add a “repo hygiene” validation stage**
  In addition to template structure/content checks:
  - Compile-check Python (`compileall`)
  - Detect conflict markers
  - Detect duplicate-script naming collisions (hyphen vs underscore)

- **Reduce duplication between `scripts/` and `tests/validation/` validators**
  There are multiple validation entrypoints with overlapping responsibilities.
  Future improvement: clarify:
  - What is a library module?
  - What is a CLI entrypoint?
  - What is only used in CI?

- **Provide JSON Schema for YAML files and wire it to the repo**
  IDEs can misclassify `tasks/task-index.yaml` under unrelated schemas.
  Future improvement: ship a schema and map it via repo settings so linting is meaningful.

---

## P3 — Documentation accuracy & automation

- **Make docs self-healing where possible**
  Several docs contain counts/claims (number of tasks, number of templates, script lists) that drift.
  Future improvement: generate those sections (or at least validate them) from the filesystem.

- **Unify “official commands” across README/SYSTEM-MAP/WARP/CLAUDE docs**
  Example mismatch to eliminate:
  - `validate-templates.py` vs `validate_templates.py`

- **Add a single “source of truth” index for entrypoints**
  A small document listing:
  - Supported commands
  - Canonical script path
  - Deprecated aliases

---

## P3 — Reference project generation improvements

✅ **COMPLETED** — Created 3 production-ready reference projects:
- `saas-api/` - FastAPI backend with auth, billing, webhooks
- `data-pipeline/` - Python ETL framework with extractors, transformers, loaders  
- `web-dashboard/` - Next.js 14 with data tables, charts, React Query hooks

- **Single canonical generator entrypoint**
  Ensure docs and scripts all point to the same generator.

- **Enforce stack alias compatibility in docs**
  For example: `nextjs → next`, `agnostic → generic`.

---

## P3 — Testing improvements

- **Replace fragile auto-generated unit tests with minimal smoke tests**
  Auto-generated tests can become syntactically corrupted and block CI.
  Future improvement:
  - Keep a small curated test suite
  - Generate tests only as a starting point and require review before committing

- **Avoid toolchain-dependent template validation in CI**
  Prefer content-based checks or optional checks that degrade to warnings when external tools aren’t installed.

---

## Open questions (need decisions)

- **Canonical naming**
  Should the repo standardize on hyphenated CLI filenames or importable module filenames (underscore), and how should wrappers be structured?

- **Archive tracking policy**
  Should `_archive/` be a first-class tracked directory (recommended if it’s part of the system), or a local-only holding area?

- **Invariant enforcement strictness**
  Should missing invariants be allowed (warn) in MVP but fail in core/enterprise by default?
