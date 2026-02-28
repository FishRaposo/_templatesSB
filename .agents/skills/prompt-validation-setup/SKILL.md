---
name: prompt-validation-setup
description: Use this skill when installing or maintaining the Prompt Validation Protocol in a project. This includes creating docs/protocols/, placing PROMPT-VALIDATION-PROTOCOL.md, and ensuring Rules (e.g. AGENTS.md) reference it. Fits the seven-template-types framework (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols).
---

# Prompt Validation Setup Skill

This skill is the **protocol skill** for the **Prompt Validation Protocol** — a **Protocol** template (one of seven template types). It installs and maintains the protocol document in `docs/protocols/` and ensures Rules (e.g. AGENTS.md) reference it with a minimal gate (4 checks). Use **protocol-setup** to create or audit the Protocols template type in general; use this skill to install or maintain this specific protocol.

## Core Approach

The Prompt Validation Protocol is a **Protocol** template: a standalone process document that defines how agents must validate user prompts before execution. Rules (AGENTS.md) reference it by path and summarize the minimal gate (4 checks). This skill **installs** the protocol file; use **rules-setup** to generate or update the full Rules including the "Prompt Validation — Before Every Task" section.

**Protocol location**: `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` (recommended). Alternative: project root `PROMPT-VALIDATION-PROTOCOL.md` for minimal setups.

## Step-by-Step Instructions

### 1. Ensure docs/protocols/ exists

From the project root:

```bash
mkdir -p docs/protocols
```

On Windows (PowerShell):

```powershell
New-Item -ItemType Directory -Force -Path docs/protocols
```

### 2. Install the protocol file

Copy the protocol template from this skill into the project.

- **Source**: This skill's `templates/PROMPT-VALIDATION-PROTOCOL.md` (e.g. `.agents/skills/prompt-validation-setup/templates/PROMPT-VALIDATION-PROTOCOL.md` in the repo, or the equivalent path when the skill is installed under `~/.cursor/skills/` or `.cursor/skills/`).
- **Destination**: `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` in the project.

If the skill is in the same repo:

```bash
cp .agents/skills/prompt-validation-setup/templates/PROMPT-VALIDATION-PROTOCOL.md docs/protocols/PROMPT-VALIDATION-PROTOCOL.md
```

If the project does not have the skill locally, create `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` with the full protocol content (validation levels, 4 quick checks, security patterns, standard validation, checklists, type-specific checks, integration with Three Pillars). Use the protocol from this repo's `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` or from the rules-setup skill's embedded appendix as the reference.

### 3. Ensure Rules reference the protocol

AGENTS.md (and optionally other rule files) should include a **Prompt Validation — Before Every Task** section that:

1. States that all agents must validate user prompts before execution.
2. Lists the 4 must-pass checks (purpose in first line, all variables defined, no dangerous patterns, output format specified).
3. Points to `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` (or the project's actual path) for the full process.

If AGENTS.md does not yet have this section, add it or use the **rules-setup** skill to generate/update the full Rules. Do not duplicate the full protocol text in AGENTS.md; link to the protocol file.

**Example reference block for AGENTS.md:**

```markdown
## Prompt Validation — Before Every Task

**All agents MUST validate user prompts before execution.** Use `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` for the full process. As a minimum, run these **4 checks** before starting:

1. **Purpose in first line** — Can you state what the prompt wants in one sentence?
2. **All variables defined** — Are all `{{`, `[`, `{` placeholders defined or defaulted?
3. **No dangerous patterns** — No `eval`, `exec`, `rm -rf`, `DROP TABLE`, `sudo`, secrets, or other blocked patterns (see protocol).
4. **Output format specified** — Does the prompt say what the output should look like?

If **any** check fails, ask for clarification before proceeding. For full validation levels, security patterns, and scoring, see `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`.
```

### 4. Validate

- Confirm `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` exists and is readable.
- Confirm AGENTS.md (or the canonical rule file) contains the reference section and correct path to the protocol.

## Best Practices

- Prefer `docs/protocols/` over project root for the protocol file so all protocols live in one place.
- After installing, run the 4 checks yourself on the next few prompts to reinforce the habit.
- When updating the protocol (e.g. new security patterns), update the file in `docs/protocols/` and leave the brief reference in AGENTS.md unchanged unless the path or checks change.

## Validation Checklist

- [ ] `docs/protocols/` exists
- [ ] `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` exists and contains the full protocol (validation levels, 4 checks, security patterns, etc.) — this is the **Protocol** template for prompt validation
- [ ] AGENTS.md (or canonical rule file) includes "Prompt Validation — Before Every Task" with 4 checks and path to the protocol
- [ ] Path in AGENTS.md matches actual protocol location (e.g. `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`)

## Related Skills

- **rules-setup** — Creates and maintains the Rules template type (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md). Use rules-setup to add or refresh the Prompt Validation reference section in AGENTS.md when generating or auditing Rules.
- **protocol-setup** — Create or audit the Protocols template type (docs/protocols/, protocol skills, references from Rules). This skill (prompt-validation-setup) is the protocol skill for the Prompt Validation Protocol.
- **memory-system-setup** — Protocol skill for the Memory System Protocol (MEMORY-SYSTEM-PROTOCOL.md); same pattern as this skill.
