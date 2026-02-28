# AGENTS.md Setup Skill

This skill helps you **create** or **edit** **AGENTS.md** — the **primary rule file** for a project. AGENTS.md is the canonical, tool-agnostic source for how agents must behave; other rule files (CLAUDE.md, CURSOR.md, WINDSURF.md) can point to it.

## When to use

- Create AGENTS.md from scratch with all core sections (Overview, Commands, Testing, Three Pillars, Prompt Validation, Boundaries, Key References, etc.)
- Edit existing AGENTS.md (add sections, refine commands, strengthen Three Pillars or Prompt Validation)
- Audit AGENTS.md for missing or weak sections

Use the **project's AGENTS.md** as the reference for structure and principles. For the full four rule files (AGENTS.md + CLAUDE.md, CURSOR.md, WINDSURF.md), use **rules-setup**.

## Core principles (included in AGENTS.md)

- **Three Pillars** — AUTOMATING (prefer scripts), TESTING, DOCUMENTING (with change-type table)
- **Prompt Validation** — 4 checks before every task; link to full protocol (do not duplicate)
- **Boundaries** — Always / Ask first / Never; Safety and Permissions
- **Prefer scripts** — Use scripts in `scripts/` over manual steps
- **Key References** — Framework, rule files, protocols, skills; **When Stuck** — where to look

## Related skills

- **rules-setup** — Full Rules template type (four rule files)
- **prompt-validation-setup** — Install Prompt Validation Protocol so AGENTS.md can link to it
- **memory-system-setup** — Set up memory system so AGENTS.md can reference Memory System Protocol

## Reference

- Project's `AGENTS.md` at project root
- `AGENTIC-ASSETS-FRAMEWORK.md` → Rules
- `.agents/skills/rules-setup/` for full rule-file generation
