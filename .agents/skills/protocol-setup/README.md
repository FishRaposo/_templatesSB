# Protocol Setup Skill

**Purpose**: Create and maintain **Protocols** — the template type for process definitions (e.g. prompt validation, memory).

**When to use**: When you need to add a protocol document, create a protocol skill to install it, or audit `docs/protocols/` and Rules references. Protocols are one of seven template types; they live in `docs/protocols/` and are referenced by Rules (AGENTS.md).

## What This Skill Does

1. Ensures `docs/protocols/` exists and protocol documents follow the framework.
2. Guides adding or editing a protocol (naming, content, link from Rules).
3. Guides creating a **protocol skill** (e.g. prompt-validation-setup) so a protocol can be installed in new projects.
4. Audits protocol files and AGENTS.md references.

## Quick Start

- **Add a protocol**: Create `docs/protocols/<NAME>-PROTOCOL.md`; add a short reference section in AGENTS.md that points to it (use rules-setup for full Rules).
- **Install a protocol**: Use the matching protocol skill (e.g. `.agents/skills/prompt-validation-setup/` for Prompt Validation).
- **Create a protocol skill**: Add `.agents/skills/<name>-setup/` with SKILL.md, config.json, and `templates/<PROTOCOL>.md`; see prompt-validation-setup as reference.

## Related

- **Framework**: AGENTIC-ASSETS-FRAMEWORK.md → Protocols
- **Example protocol skill**: `.agents/skills/prompt-validation-setup/`
- **Rules**: AGENTS.md references protocols; **rules-setup** maintains the reference section
