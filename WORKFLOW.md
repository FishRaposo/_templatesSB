# Development Workflow — _templatesSB

_Branching strategy, release process, and conventions._

---

## Branching Strategy

```
main          ← stable, protected
feature/name  ← new features (branch from main)
fix/name      ← bug fixes (branch from main)
docs/name     ← documentation-only changes
```

**Rules**:

- Prefer short-lived branches; merge after validation and doc updates.
- Commit with conventional messages; reference CHANGELOG event in PR or footer when relevant.
- No force-push to main unless agreed.

---

## Development Cycle

### Starting Work

```bash
git checkout main
git pull origin main
git checkout -b feature/my-feature
```

### During Development

- Append decisions and changes to **CHANGELOG.md** (## Event Log) as you go.
- Run JSON validation on changed `config.json`: `python -m json.tool <file>`.
- Satisfy **Three Pillars** (AUTOMATING, TESTING, DOCUMENTING) before marking done.

### Pull Request

1. Push branch and open PR against `main`.
2. Ensure CHANGELOG has an event for the change set.
3. Update docs (README, docs/INDEX.md, SYSTEM-MAP.md, or AGENTS.md per change type — see AGENTS.md DOCUMENTING table).
4. After review, merge (squash or merge per preference).

---

## Commit Message Convention

```
type(scope): short description (≤72 chars)

types: feat | fix | docs | style | refactor | test | chore
```

Examples:

- `docs(skills): add QUICKSTART and CONTRIBUTING`
- `fix(memory): regenerate graph to evt-012`

Optional footer: `CHANGELOG evt-NNN`.

---

## Release / Tagging

- Tag releases on `main` when appropriate: `vMAJOR.MINOR.PATCH`.
- CHANGELOG milestone events can mark releases; no separate release branch required for doc-only repo.

---

## CI / Automation

| Check | When | Command |
|-------|------|---------|
| JSON validation | On change to .agents/skills | `find .agents/skills -name "config.json" -exec python -m json.tool {} \;` |
| Memory validation | When .memory/ or CHANGELOG changes | `python docs/memory-system/scripts/validate-memory.py` (when present) |

---

_For contribution guidelines: [CONTRIBUTING.md](../CONTRIBUTING.md)_  
_For architecture: [docs/SYSTEM-MAP.md](SYSTEM-MAP.md)_
