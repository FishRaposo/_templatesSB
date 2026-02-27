# Three Pillars Protocol

_Every task must satisfy all three pillars_

## Overview

A task is **not complete** until all three pillars are satisfied:

1. ✅ **AUTOMATING** — Content validates against structural rules; prefer scripts over manual steps (if something can be done with a script, especially a reusable one, use it)
2. ✅ **TESTING** — Verification passes, examples are runnable
3. ✅ **DOCUMENTING** — This AGENTS.md and related docs are updated

Skipping any pillar = incomplete work.

---

## Pillar 1: AUTOMATING

**Principle:** Prefer scripts over manual steps. If a task can be done with a script (especially a reusable one in `scripts/`), use the script instead of doing it manually.

After every content change, verify:

### SKILL.md Validation

- [ ] Only `name` and `description` in frontmatter (no curriculum fields)
- [ ] No version, tags, or category fields
- [ ] Action-oriented language (not "learn" but "apply")
- [ ] Multi-language examples (JS/Python/Go minimum)

### config.json Validation

- [ ] Valid JSON
- [ ] `"tools": []` (always empty for language-agnostic)
- [ ] Appropriate triggers and patterns
- [ ] Examples are accurate

### Structure Validation

- [ ] Directory structure matches project conventions (e.g. `skills/<skill-name>/` with SKILL.md, config.json, README.md)
- [ ] Naming conventions followed (kebab-case, etc.)
- [ ] README.md under 80 lines
- [ ] Reference files have `<!-- Generated from... -->` headers when applicable

### Code Example Validation

- [ ] Before/after format uses ❌/✅
- [ ] Code is syntactically correct
- [ ] Examples are runnable
- [ ] Multi-language coverage

---

## Pillar 2: TESTING

After every content change, verify:

### New Skills

- [ ] Skill can be invoked with trigger keywords from config.json
- [ ] SKILL.md instructions are clear and complete
- [ ] Examples work as described

### New Reference Files

- [ ] Code snippets are syntactically correct
- [ ] Multi-language coverage (JS/Python/Go)
- [ ] Outputs match expected results

### New Tasks

- [ ] Tasks produce outputs convertible to standalone reference files
- [ ] Raw outputs saved to `task-outputs/`
- [ ] Outputs are complete and accurate

### Changed Examples

- [ ] Before/after examples are accurate
- [ ] ❌/✅ format used consistently
- [ ] No syntax errors

### Cross-References

- [ ] All file paths in PACK.md, QUICK_REFERENCE.md, INDEX.md exist
- [ ] No broken links
- [ ] Cross-links resolve correctly

---

## Pillar 3: DOCUMENTING

After completing any task, check whether documentation updates are needed:

| Change Type | Update These Files |
|-------------|-------------------|
| New standalone skill (in `skills/`) | AGENTS.md (Key References / Skills), README if present |
| New skill in existing pack | Pack's PACK.md, QUICK_REFERENCE.md, reference-files/INDEX.md (when project uses packs) |
| New reference file | Pack's reference-files/INDEX.md (when project uses packs) |
| New top-level file | AGENTS.md (Project Structure) |
| Changed conventions | AGENTS.md (Do/Don't) |
| New file type or naming convention | AGENTS.md (File Types and Conventions) |
| New key file role | AGENTS.md (Key File Roles table) |
| Changed workflow step | AGENTS.md (Workflows section) |

### How to Update

1. After completing primary task, review what changed
2. Update relevant section(s) in the same commit
3. Keep updates minimal and factual — match existing style
4. Do not rewrite sections unrelated to your change

---

## Integration with Other Protocols

### With Prompt Validation

- **BEFORE starting:** Validate prompt using `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` (or PROMPT-VALIDATION-PROTOCOL.md at project root if present)
- **DURING:** Follow Three Pillars as you work
- **AFTER:** Verify all three pillars satisfied before declaring complete

### With Memory System

- **L1 (Event Log):** Log pillar completion in CHANGELOG.md
- **L2 (Knowledge Graph):** Track which skills/packs pass all pillars
- **L3 (Narrative):** Include pillar status in context.md

### With Sub-Agent Pattern

When spawning sub-agents, include Three Pillars in task description:

```
Task: "Create skill for X"
Requirements:
1. AUTOMATING: Follow SKILL.md template, config.json rules
2. TESTING: Provide working examples, verify triggers
3. DOCUMENTING: Update PACK.md and INDEX.md
```

---

## Common Failures

### Partial Completion (2/3 Pillars)

**Scenario:** Skill created and tested, but docs not updated.

**Problem:** Future agents don't know skill exists. Broken cross-references.

**Fix:** Always do documentation pass before finishing.

### False Automation

**Scenario:** Content "looks right" but doesn't validate.

**Example:** Added `version` field to SKILL.md frontmatter (curriculum artifact).

**Fix:** Run AUTOMATING checklist explicitly.

### Untested Examples

**Scenario:** Examples copied from somewhere, never run.

**Problem:** Syntax errors, wrong outputs, broken trust.

**Fix:** Always run examples, verify outputs match.

---

## Self-Check Before Declaring Complete

Ask yourself:

1. **AUTOMATING:** Would a linter for our conventions pass this? Did I use scripts instead of manual steps where possible?
2. **TESTING:** Have I actually run the examples I provided?
3. **DOCUMENTING:** If someone looks for this later, will they find it?

If all three are YES → task is complete.

---

*See also: `../AGENTS.md` (Three Pillars section)*
