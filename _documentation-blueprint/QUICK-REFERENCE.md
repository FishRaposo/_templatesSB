# Documentation Blueprint — Quick Reference

_One-page agent cheat sheet_

---

## CLI Commands

```bash
# Scaffold new project
python scaffold.py --interactive
python scaffold.py --name "Project" --tier core --stack python

# Validate
python validate.py .

# List files for tier
python scaffold.py --list-files core
```

## Agent Lifecycle

```
BOOT:     Read AGENTS.md → Read context.md → Check staleness → Query graph.md → Verify
EXECUTE:  Work within boundaries → Append events to CHANGELOG.md
SHUTDOWN: Append → Materialize → Regenerate → Commit → Die
RECOVER:  Trust L1 → Rebuild L2 → Rebuild L3 → Resume
```

## File Trust Order

```
AGENTS.md  >  CHANGELOG.md  >  .memory/graph.md  >  .memory/context.md
(immutable)   (source of truth)  (derived)              (ephemeral)
```

## Three Pillars

| Pillar | Check |
|--------|-------|
| **AUTOMATING** | Scripts for all mechanical checks. Existing → standard tools → write new → manual last |
| **TESTING** | Code examples run · setup verified · links resolve |
| **DOCUMENTING** | CHANGELOG has event · docs updated · memory regenerated |

## Tiers

| Tier | Files | Use When |
|------|-------|----------|
| **MVP** | 4 | Solo, prototype, < 1 month |
| **Core** | 11 | Team, 1–6 months |
| **Full** | 21+ | Enterprise, multi-agent, > 6 months |

## Files by Tier

| File | MVP | Core | Full |
|------|:---:|:----:|:----:|
| AGENTS.md | ✅ | ✅ | ✅ |
| CHANGELOG.md | ✅ | ✅ | ✅ |
| README.md | ✅ | ✅ | ✅ |
| .memory/context.md | ✅ | ✅ | ✅ |
| TODO.md | | ✅ | ✅ |
| QUICKSTART.md | | ✅ | ✅ |
| CONTRIBUTING.md | | ✅ | ✅ |
| SECURITY.md | | ✅ | ✅ |
| .memory/graph.md | | ✅ | ✅ |
| docs/SYSTEM-MAP.md | | ✅ | ✅ |
| docs/PROMPT-VALIDATION.md | | ✅ | ✅ |
| WORKFLOW.md | | | ✅ |
| CODE_OF_CONDUCT.md | | | ✅ |
| LICENSE.md | | | ✅ |
| EVALS.md | | | ✅ |
| DOCUMENTATION-OVERVIEW.md | | | ✅ |
| .github/* | | | ✅ |

## Event Format

```markdown
### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type

**Scope**: area
**Summary**: one-line description

**Details**:
- key: value

**Refs**: evt-XXX
**Tags**: tag1, tag2
```

Types: `decision` `create` `modify` `delete` `test` `fix` `dependency` `blocker` `milestone` `escalation` `handoff`

## Documentation Parity

| Change | Update |
|--------|--------|
| New feature | README, SYSTEM-MAP, CHANGELOG |
| API change | API docs, CHANGELOG, QUICKSTART |
| Dependency | CONTRIBUTING, QUICKSTART, CHANGELOG |
| Security | SECURITY, CHANGELOG |
| Architecture | SYSTEM-MAP, AGENTS, CHANGELOG |

## When In Doubt

1. **Read the event log** — it is the only truth
2. **Rebuild, don't repair** — regenerate derived layers
3. **Append, don't edit** — wrong? append corrective event
4. **Escalate, don't guess** — unclear? ask human

---

## For AI Agents

**Start with `AI-ENTRYPOINT.md`** for step-by-step instructions.

Full spec: `DOCUMENTATION-BLUEPRINT.md`
