# Documentation Blueprint — Quick Reference

_One-page agent cheat sheet_

---

## Agent Cheat Sheet

```
BOOT:     Read AGENTS.md → Read context.md → Check staleness → Query graph.md → Verify constraints
EXECUTE:  Work within boundaries → Append events to CHANGELOG.md
SHUTDOWN: Append → Materialize → Regenerate → Commit → Handoff → Die
RECOVER:  Trust L1 → Rebuild L2 → Rebuild L3 → Resume
```

## File Trust Order

```
AGENTS.md  >  CHANGELOG.md  >  .memory/graph.md  >  .memory/context.md
(immutable)   (source of truth)  (derived)              (ephemeral)
```

## Three Pillars — Must All Pass Before Done

| Pillar | Check |
|--------|-------|
| **AUTOMATING** | **MUST use scripts** — if a script can check it, the script checks it. Existing → standard tools → write new → manual only as last resort |
| **TESTING** | Code examples run · setup instructions verified · links resolve |
| **DOCUMENTING** | CHANGELOG has event · affected docs updated · memory layers regenerated |

## Tier Selection

| Project Type | Use Tier |
|-------------|----------|
| Solo, prototype, < 1 month | **MVP** |
| Team, real project, 1–6 months | **Core** |
| Multi-agent, enterprise, 6+ months | **Full** |

**Upgrade triggers**: MVP → Core when changelog hits 30 events or >1 agent. Core → Full when >3 agents or >6 months.

## Required Files by Tier

| File | MVP | Core | Full |
|------|-----|------|------|
| `AGENTS.md` | ✅ | ✅ | ✅ |
| `CHANGELOG.md` | ✅ | ✅ | ✅ |
| `README.md` | ✅ | ✅ | ✅ |
| `.memory/context.md` | ✅ | ✅ | ✅ |
| `TODO.md` | | ✅ | ✅ |
| `QUICKSTART.md` | | ✅ | ✅ |
| `CONTRIBUTING.md` | | ✅ | ✅ |
| `SECURITY.md` | | ✅ | ✅ |
| `.memory/graph.md` | | ✅ | ✅ |
| `docs/SYSTEM-MAP.md` | | ✅ | ✅ |
| `docs/PROMPT-VALIDATION.md` | | ✅ | ✅ |
| `WORKFLOW.md` | | | ✅ |
| `CODE_OF_CONDUCT.md` | | | ✅ |
| `LICENSE.md` | | | ✅ |
| `EVALS.md` | | | ✅ |
| `.github/` templates | | | ✅ |
| AI tool files (CLAUDE.md, etc.) | | ✅ | ✅ |

## CHANGELOG Event Format

```markdown
### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type

**Scope**: area
**Summary**: one-line description

**Details**:
- key: value

**Refs**: evt-XXX
**Tags**: tag1, tag2
```

Event types: `decision` `create` `modify` `delete` `test` `fix` `dependency` `blocker` `milestone` `escalation` `handoff`

## Handoff Event

```markdown
### evt-NNN | YYYY-MM-DD HH:MM | from-agent | handoff

**Scope**: module
**Summary**: Handing off X to Y because Z

**Details**:
- From agent: name
- To agent: name
- Invariants: must not violate these
- Boundaries: scope limits
- Artifacts: evt-NNN, evt-NNN
```

## Documentation Parity — What to Update

| Change | Update |
|--------|--------|
| New feature | README, SYSTEM-MAP, CHANGELOG |
| API change | API docs, CHANGELOG, QUICKSTART |
| Dependency | CONTRIBUTING, QUICKSTART, CHANGELOG |
| Security fix | SECURITY, CHANGELOG |
| Architecture | SYSTEM-MAP, AGENTS if behavioral, CHANGELOG |

## When In Doubt

1. **Read the event log** — it is the only truth
2. **Rebuild, don't repair** — regenerate derived layers from upstream
3. **Append, don't edit** — wrong? append a corrective event
4. **Escalate, don't guess** — if constraints are unclear, ask a human

---

_Full specification: `DOCUMENTATION-BLUEPRINT.md`_  
_Templates: `templates/` directory_
