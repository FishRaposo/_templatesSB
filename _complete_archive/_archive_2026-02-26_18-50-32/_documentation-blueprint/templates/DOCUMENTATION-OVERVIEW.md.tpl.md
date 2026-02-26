# Documentation Overview — {{PROJECT_NAME}}

_Complete index of all project documentation — keep this current_

**Last updated**: {{DATE}} (evt-NNN)

---

## Root-Level Documents

| Document | Purpose | Audience | Tier |
|----------|---------|----------|------|
| [AGENTS.md](../AGENTS.md) | Behavioral core for AI agents | AI agents | All |
| [CHANGELOG.md](../CHANGELOG.md) | Event log — all decisions and changes | Agents, maintainers | All |
| [README.md](../README.md) | Project gateway and quick start | All | All |
| [TODO.md](../TODO.md) | Active task tracker | Agents, contributors | Core+ |
| [QUICKSTART.md](../QUICKSTART.md) | Detailed setup guide | New contributors | Core+ |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Contribution guidelines | Contributors | Core+ |
| [SECURITY.md](../SECURITY.md) | Security policy and reporting | Security researchers | Core+ |
| [WORKFLOW.md](../WORKFLOW.md) | Branching and release process | Maintainers | Full |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Community standards | All | Full |
| [EVALS.md](../EVALS.md) | Quality benchmarks and evaluation rubric | Agents, reviewers | Full |
| [LICENSE.md](../LICENSE.md) | License terms | All | Full |

## docs/ Directory

| Document | Purpose | Audience | Tier |
|----------|---------|----------|------|
| [docs/SYSTEM-MAP.md](SYSTEM-MAP.md) | Architecture overview and component inventory | Agents, developers | Core+ |
| [docs/PROMPT-VALIDATION.md](PROMPT-VALIDATION.md) | Prompt validation protocol | AI agents | Core+ |

## Memory System

| File | Purpose | Mutability |
|------|---------|-----------|
| [.memory/graph.md](../.memory/graph.md) | Knowledge graph — entities and relationships | Materialize from CHANGELOG only |
| [.memory/context.md](../.memory/context.md) | Current narrative — trajectory and active tasks | Regenerate every session |

## AI Agent Files

| File | Tool | Purpose |
|------|------|---------|
| [CLAUDE.md](../CLAUDE.md) | Claude | Tool-specific onboarding | 
| [WINDSURF.md](../WINDSURF.md) | Windsurf/Cascade | Tool-specific onboarding |
| [CURSOR.md](../CURSOR.md) | Cursor | Tool-specific onboarding |
| [COPILOT.md](../COPILOT.md) | GitHub Copilot | Tool-specific onboarding |

_Add or remove rows as AI tools are added/removed from the project._

## API Reference (if applicable)

| Document | Endpoint Group | Last Updated |
|----------|---------------|-------------|
| [docs/api/{{API_GROUP_1}}.md](api/{{API_GROUP_1}}.md) | {{API_GROUP_1_DESCRIPTION}} | {{DATE}} |

_Remove this section if the project has no API documentation._

## Architecture Decision Records (if applicable)

| ADR | Decision | Status | Date |
|-----|----------|--------|------|
| [docs/adr/001-{{ADR_1_TITLE}}.md](adr/001-{{ADR_1_TITLE}}.md) | {{ADR_1_DECISION}} | Accepted | {{DATE}} |

_Remove this section if the project does not use ADRs. Otherwise, also see `decision` events in CHANGELOG.md._

---

## Documentation Health

Run at the start of every session:

- [ ] All files listed above exist
- [ ] No `{{PLACEHOLDER}}` strings remain in any file
- [ ] CHANGELOG.md event horizon matches `.memory/graph.md`
- [ ] This file reflects the current set of documents (add/remove rows as needed)

---

_Update this file when any document is added, removed, or renamed. Log as a `modify` event in CHANGELOG.md._
