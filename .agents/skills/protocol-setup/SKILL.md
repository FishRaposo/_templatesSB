---
name: protocol-setup
description: Use this skill when creating, editing, or auditing Protocols — the template type that defines how processes are run (validation, memory, safety, etc.). This includes docs/protocols/ layout, protocol documents (e.g. PROMPT-VALIDATION-PROTOCOL.md), protocol skills that install them, and referencing protocols from Rules (AGENTS.md). Fits the seven-template-types framework (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols).
---

# Protocol Setup Skill

This skill creates and maintains **Protocols**: the template type that defines **how processes are run** (e.g. validation, memory, safety). Protocols are Markdown artifacts in `docs/protocols/` (or project root for minimal setups). **Protocol skills** (e.g. prompt-validation-setup) install and maintain specific protocol files in a project.

## Your Role

Help users **create** and **modify** Protocols through:

1. **Creating New Protocols** — Add `docs/protocols/` if missing, create a new protocol document (e.g. `PROCESS-NAME-PROTOCOL.md`) with purpose, steps, and checklists; optionally create a protocol skill under `.agents/skills/<name>-setup/` to install it
2. **Editing Existing Protocols** — Update a protocol document’s content or add a new protocol skill (SKILL.md, config.json, templates) to install/maintain it
3. **Auditing Protocols** — Check that `docs/protocols/` exists, protocol documents are complete, Rules reference them by path (with minimal gate only), and protocol skills have correct templates and install target

When invoked, produce or update protocol files and Rules references. Do not duplicate full protocol text in AGENTS.md—link to the protocol.

## Core Approach

Protocols answer **"How is [process] defined and where do I find it?"** They are Markdown artifacts under `docs/protocols/`. Each protocol is a single source of truth for a process (e.g. prompt validation, memory lifecycle). **Protocol skills** (e.g. prompt-validation-setup) install and maintain protocol files in a project; Rules (AGENTS.md) reference protocols by path and summarize the minimal gate (e.g. 4 checks). Do not duplicate full protocol content in Rules—link to the protocol.

## Step-by-Step Instructions

### 1. Ensure docs/protocols/ exists

```
project/
├── docs/
│   └── protocols/           # All protocol documents
│       ├── PROMPT-VALIDATION-PROTOCOL.md
│       └── MEMORY-SYSTEM-PROTOCOL.md
└── ...
```

Create the directory if missing: `mkdir -p docs/protocols` (or `New-Item -ItemType Directory -Force -Path docs/protocols` on Windows).

### 2. Add or edit the protocol document

- **Naming**: `PROTOCOL-NAME-PROTOCOL.md` or `PROTOCOL-NAME.md` (e.g. `PROMPT-VALIDATION-PROTOCOL.md`, `MEMORY-SYSTEM-PROTOCOL.md`).
- **Content**: Purpose, mandatory steps, checklists, security patterns (if applicable), integration with other template types (e.g. Three Pillars). Keep one document per process.
- **Format**: Markdown; optional YAML frontmatter for metadata. Reference the framework (`AGENTIC-ASSETS-FRAMEWORK.md` at project root, when present) → Protocols.

### 3. Reference from Rules (AGENTS.md)

Rules should not duplicate the full protocol. Add a short section that:

1. States that agents must follow the process (e.g. "validate prompts before execution").
2. Lists the minimal gate (e.g. 4 must-pass checks for prompt validation).
3. Points to `docs/protocols/PROTOCOL-NAME-PROTOCOL.md` (or the project's actual path) for the full process.

Use **rules-setup** when generating or updating the full Rules; ensure the path in AGENTS.md matches where the protocol file lives.

### 4. Create a protocol skill (when installing a protocol in new projects)

To make a protocol **installable**, add a **protocol skill** under `.agents/skills/<protocol-name>-setup/` (e.g. `prompt-validation-setup`):

- **SKILL.md**: Steps to create `docs/protocols/`, copy or create the protocol file, and ensure Rules reference it.
- **templates/**: Include a copy of the protocol (e.g. `templates/PROMPT-VALIDATION-PROTOCOL.md`) so the skill can install it into any project.
- **config.json**: Triggers (e.g. "install prompt validation", "setup prompt validation protocol").

See `.agents/skills/prompt-validation-setup/` as the reference implementation. Protocol skills are for **one** protocol each; this skill (protocol-setup) is for creating or auditing the Protocols template type in general.

### 5. Validate

- [ ] `docs/protocols/` exists (or protocol at project root if minimal).
- [ ] Protocol document exists and is complete (purpose, steps, checklists).
- [ ] AGENTS.md (or canonical rule file) references the protocol by correct path and includes the minimal gate.
- [ ] If the protocol is installable, a corresponding protocol skill exists under `.agents/skills/<name>-setup/`.

## Editing Protocols

When modifying an existing protocol or its integration:

- **Protocol document** — Update purpose, mandatory steps, checklists, or security patterns; keep one document per process
- **AGENTS.md reference** — Ensure the path to the protocol is correct and the minimal gate (e.g. 4 checks) is still accurate; do not paste full protocol text into Rules
- **Protocol skill** — If the protocol is installable, update the skill’s SKILL.md, config.json, or `templates/` so the installed file and Rules reference stay correct

Use **rules-setup** when changing the full Rules content; use this skill for the protocol document and protocol-skill layout.

## Best Practices

- One protocol document per process; keep Rules thin (link + minimal gate).
- Prefer `docs/protocols/` over project root for consistency.
- When adding a new process (e.g. security review, deployment checklist), add a new protocol file and a protocol skill if projects should install it from a template.

## Validation Checklist

- [ ] `docs/protocols/` exists
- [ ] Each protocol file has a clear purpose and mandatory steps
- [ ] Rules reference protocols by path; no full protocol text duplicated in AGENTS.md
- [ ] Protocol skills (when used) have SKILL.md, config.json, and template(s); install target is `docs/protocols/`

## Related Skills

- **rules-setup** — When adding or updating AGENTS.md or rule files that reference protocols
- **prompt-validation-setup** — Example protocol skill; installs Prompt Validation Protocol
- **memory-system-setup** — References MEMORY-SYSTEM-PROTOCOL.md; use when the protocol is memory-related
- **skill-setup** — When creating a new protocol skill (SKILL.md, config.json, templates)

## Supporting Files

- **Framework and Protocols section:** `AGENTIC-ASSETS-FRAMEWORK.md` at project root (when present)
- **Example protocol skills:** `.agents/skills/prompt-validation-setup/` (installs PROMPT-VALIDATION-PROTOCOL.md); `.agents/skills/memory-system-setup/` (installs MEMORY-SYSTEM-PROTOCOL.md and sets up memory layout)
- **Existing protocols:** `docs/protocols/` in the project (e.g. PROMPT-VALIDATION-PROTOCOL.md, MEMORY-SYSTEM-PROTOCOL.md)
