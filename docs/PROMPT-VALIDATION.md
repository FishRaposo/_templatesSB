# Prompt Validation — _templatesSB

_Validation protocol for all AI agent prompts. Run Quick Validation before every task._

---

## Where the Full Protocol Lives

The full prompt validation protocol (4 checks, security patterns, scoring, type-specific checklists) is defined in:

- **`docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`**

Install that file into a new project using the **prompt-validation-setup** skill (`.agents/skills/prompt-validation-setup/`). Rules (e.g. AGENTS.md) reference it and summarize the 4-check gate; they do not duplicate the full content.

---

## Quick Validation (4 checks — must all pass)

Run before starting any task. If any check fails, stop and ask for clarification.

| # | Check | Pass Condition |
|---|-------|----------------|
| 1 | **Purpose in first line** | Can you state the task in one sentence? |
| 2 | **All variables defined** | No undefined `{{PLACEHOLDER}}` or `[VARIABLE]` in the prompt? |
| 3 | **No dangerous patterns** | No script injection, command injection, path traversal, or secrets? |
| 4 | **Output format specified** | Does the prompt define what the output should look like? |

---

## Full Protocol

See **`docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`** for:

- Security patterns blocklist (27 patterns)
- Standard validation (5-dimension scoring, grade A–F)
- Type-specific checklists (code gen, docs, refactor, analysis, etc.)
- Validation log template and escalation rules

---

_Install in another project: use `.agents/skills/prompt-validation-setup/` (prompt-validation-setup skill)._
