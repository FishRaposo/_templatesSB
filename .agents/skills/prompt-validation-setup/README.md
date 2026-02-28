# Prompt Validation Setup Skill

**Purpose**: Install and maintain the **Prompt Validation Protocol** (a **Protocol** template) in a project.

**When to use**: When you want to add the prompt validation process to a new or existing repo so agents validate user prompts before execution. Protocols are one of seven template types; this skill installs the protocol file and ensures Rules reference it.

## What This Skill Does

1. Ensures `docs/protocols/` exists.
2. Copies (or creates) `PROMPT-VALIDATION-PROTOCOL.md` into `docs/protocols/`.
3. Ensures AGENTS.md (or the canonical rule file) has a "Prompt Validation — Before Every Task" section that points to the protocol and lists the 4 must-pass checks.

## Quick Start

- **Install protocol file**: Copy `.agents/skills/prompt-validation-setup/templates/PROMPT-VALIDATION-PROTOCOL.md` to `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`.
- **Reference in Rules**: Add the brief "Prompt Validation — Before Every Task" block to AGENTS.md (see SKILL.md Step 3). Use **rules-setup** if you need to generate or audit the full Rules.

## Related

- **Protocols**: `docs/protocols/` — Process definitions (see AGENTIC-ASSETS-FRAMEWORK.md).
- **Rules**: AGENTS.md references the protocol; **rules-setup** skill maintains the four rule files and the prompt validation reference.
- **Full protocol**: Content is in `templates/PROMPT-VALIDATION-PROTOCOL.md` in this skill and in the project's `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md` after install.
