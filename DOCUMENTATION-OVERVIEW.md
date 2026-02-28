# Documentation Overview — Unified AI Development Ecosystem

_Index of all documentation in this project_

**Last updated**: 2026-02-28 (evt-001)

---

## Root-Level Documents

| Document | Purpose | Audience | Tier |
|----------|---------|----------|------|
| [AGENTS.md](AGENTS.md) | Behavioral rules for AI agents | AI agents | All |
| [CHANGELOG.md](CHANGELOG.md) | Event log and change history | All | All |
| [README.md](README.md) | Project introduction and quick start | All | All |
| [TODO.md](TODO.md) | Task tracker | Contributors | Core+ |
| [QUICKSTART.md](QUICKSTART.md) | Setup and first-run guide | New users | Core+ |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines | Contributors | Core+ |
| [SECURITY.md](SECURITY.md) | Security policy | All | Core+ |
| [WORKFLOW.md](WORKFLOW.md) | Branching and release process | Contributors | Full |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards | All | Full |
| [LICENSE.md](LICENSE.md) | License terms | All | Full |
| [EVALS.md](EVALS.md) | Quality benchmarks | Reviewers | Full |

---

## docs/ Directory

| Document | Purpose |
|----------|---------|
| [SYSTEM-MAP.md](docs/SYSTEM-MAP.md) | Architecture overview |
| [PROMPT-VALIDATION.md](docs/PROMPT-VALIDATION.md) | Prompt validation protocol |

---

## Memory System

| File | Layer | Purpose |
|------|-------|---------|
| [.memory/graph.md](.memory/graph.md) | L2 | Knowledge graph |
| [.memory/context.md](.memory/context.md) | L3 | Current narrative |

---

## AI Agent Files

| File | Purpose |
|------|---------|
| [AGENTS.md](AGENTS.md) | Canonical rules (all agents read this) |
| CLAUDE.md | Claude-specific hints (if present) |
| CURSOR.md | Cursor-specific hints (if present) |
| WINDSURF.md | Windsurf-specific hints (if present) |

Each AI-specific file is ≤60 lines and links to AGENTS.md for behavioral rules.

---

## Documentation Health Checklist

- [ ] All files have no unfilled placeholders
- [ ] All internal links resolve
- [ ] CHANGELOG.md is up to date
- [ ] README.md reflects current project state
- [ ] SYSTEM-MAP.md reflects current architecture

---

_Update this file when adding or removing documentation._
