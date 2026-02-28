# Quickstart — _templatesSB

Get the repository, validate the setup, and start using the template system and skills.

---

## Prerequisites

| Requirement | Check |
|-------------|-------|
| Git | `git --version` |
| Python 3 | `python --version` or `python3 --version` (for JSON validation, optional scripts) |
| Text editor / AI IDE | Cursor, VS Code, Windsurf, or similar |

---

## Clone and Open

```bash
git clone https://github.com/YOUR_ORG/_templatesSB.git
cd _templatesSB
```

(Replace with your actual repo URL if different.)

---

## First Run — Verify Setup

### 1. Validate JSON (skills config)

```bash
# From repo root
python -m json.tool .agents/skills/skill-setup/config.json
```

Or validate all JSON under `.agents/skills/`:

```bash
find .agents/skills -name "config.json" -exec python -m json.tool {} \; > /dev/null
```

Exit code 0 = valid.

### 2. Read the rules

- **AGENTS.md** — Canonical behavioral rules (start here).
- **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md** — Tool-specific entry points; all point to AGENTS.md.

### 3. Check memory (optional)

If using the memory system:

- `.memory/context.md` — Current trajectory; event horizon should match last event in CHANGELOG.md (section `## Event Log`).
- If stale or missing, regenerate from CHANGELOG per `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md`.

---

## What Success Looks Like

- You can open AGENTS.md and see the Three Pillars, template types, and memory protocol.
- You can list skills: `ls .agents/skills` — nine skills (memory-system-setup, rules-setup, skill-setup, blueprints-setup, tasks-setup, recipes-setup, subagents-setup, prompt-validation-setup, protocol-setup).
- JSON validation passes for all `config.json` under `.agents/skills/`.

---

## Common Errors

| Error | Cause | Fix |
|-------|--------|-----|
| `python: command not found` | Python not installed or not on PATH | Install Python 3 or use `python3`; JSON check is optional. |
| `No such file: .agents/skills/...` | Wrong directory | Run from repo root (where AGENTS.md and .agents/ live). |
| JSON parse error | Corrupt or invalid config.json | Restore from git or fix syntax; ensure no trailing commas, valid quotes. |

---

## Next Steps

1. **Use a skill** — Open `.agents/skills/skill-setup/SKILL.md` or `.agents/skills/rules-setup/SKILL.md` when creating skills or rules.
2. **Install protocols** — Use `.agents/skills/prompt-validation-setup/` or `.agents/skills/memory-system-setup/` to install protocol files into a project's `docs/protocols/`.
3. **Docs index** — See `docs/INDEX.md` for the full documentation map.

---

_For full documentation baseline: `_documentation-blueprint/DOCUMENTATION-BLUEPRINT.md`_  
_For repository state: `CURRENT-REPOSITORY-STATE.md`_
