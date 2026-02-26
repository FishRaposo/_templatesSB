# Skills Repository

A curated collection of AI agent skill packs organized by domain. **766 skills** across **60 planned packs**, **14 categories**.

All content is Markdown + JSON — no application code, no build system. Target audience: AI coding agents (Claude, Copilot, Cursor, Windsurf, Codex, etc.).

## Structure

```
_templates/
├── AGENTS.md                         ← AI agent operating instructions (Three Pillars enforced)
├── SKILLS_MASTER_LIST.md             ← Single source of truth: 766 skills, 60 packs, 14 categories
├── AGENT_SKILLS_GUIDE.md             ← Comprehensive guide to building agent skills
├── ARCHIVE_INDEX.md                  ← Index of archived source material
├── skill-packs/
│   ├── HOW_TO_CREATE_SKILL_PACKS.md  ← Step-by-step pack creation guide
│   ├── TASKS-TEMPLATE.md             ← Template for writing verification tasks
│   ├── 1-programming-core/           ← Pack 1: 12 skills, 19 reference files (COMPLETED)
│   └── 2-code-quality/               ← Pack 2: 12 skills, 18 reference files (COMPLETED)
├── skill-builder/                    ← Standalone skill: creating/editing/converting AI agent skills
├── generating-agents-md/             ← Standalone skill: generating AGENTS.md with Three Pillars
└── _complete_archive/                ← Previous repo content preserved for reference
    └── ARCHIVE-DOCUMENTATION-INDEX.md
```

## Completed Packs

| Pack | Skills | Reference Files | Focus |
|------|--------|----------------|-------|
| **1-programming-core** | 12 | 19 | Algorithms, data structures, recursion, FP, metaprogramming |
| **2-code-quality** | 12 | 18 | Clean code, refactoring, error handling, testing, migration |

## Standalone Skills

| Skill | Purpose |
|-------|---------|
| **skill-builder** | Create, edit, and convert AI agent skills across platforms |
| **generating-agents-md** | Generate and audit AGENTS.md files with Three Pillars enforcement |

## Three Pillars Framework

Every task in this repo must satisfy all three:

1. **AUTOMATING** — Content validates against structural rules
2. **TESTING** — Examples are runnable, cross-references resolve
3. **DOCUMENTING** — AGENTS.md and related docs updated if changes affect them

## Quick Start

- **Create a new skill pack**: Start with `skill-packs/HOW_TO_CREATE_SKILL_PACKS.md`, use Pack 1 as reference
- **Create a skill**: See `AGENT_SKILLS_GUIDE.md` for design principles
- **Find a skill**: Search `SKILLS_MASTER_LIST.md` by category
- **Generate an AGENTS.md**: Use the `generating-agents-md/` skill
- **Find archive material**: See `ARCHIVE_INDEX.md` or `_complete_archive/ARCHIVE-DOCUMENTATION-INDEX.md`

---

*Repository Reset: 2026-02-01 14:30:05*
*All content preserved in archive*
*Last Updated: 2026-02-07*
