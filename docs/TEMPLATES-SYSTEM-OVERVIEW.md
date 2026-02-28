# Templates System — Full Overview

**Purpose**: Single-document overview of all seven template types in the unified AI development ecosystem.  
**Audience**: Contributors, agents, and adopters.  
**See also**: `AGENTIC-ASSETS-FRAMEWORK.md` (detailed definitions, examples, YAML samples), `AGENTS.md` (canonical rules).

---

## 1. What “Templates” Means

**“Templates”** refers collectively to **all seven template types**—the complete reusable system:

| # | Type        | One-line definition                                      |
|---|-------------|----------------------------------------------------------|
| 1 | **Rules**   | How agents must behave (tool- and audience-specific)      |
| 2 | **Blueprints** | What to build (product archetypes)                    |
| 3 | **Tasks**   | How to implement a feature (implementation units)        |
| 4 | **Recipes** | Feature combinations (bundles of Tasks + Skills)         |
| 5 | **Subagents** | Who does the work (configured sub-agents)              |
| 6 | **Skills**  | How to do it well (capabilities, best practices)         |
| 7 | **Protocols** | How processes are defined (repeatable procedures)      |

Rules and Protocols are always in play when the project uses them; Skills are invoked on demand. Blueprints, Tasks, Recipes, and Subagents are used when the project adopts those types (e.g. blueprint-driven generation, recipe bundles, dedicated subagents).

---

## 2. The Seven Types in Detail

### 1. Rules — How Agents Must Behave

- **Purpose**: Constrain behavior so agents and subagents behave consistently across tools (Cursor, Claude, Windsurf, etc.). One canonical source (e.g. AGENTS.md) plus tool-specific entry points.
- **Format**: Markdown (optionally YAML frontmatter).
- **Location**: Project root; for Cursor, also `.cursor/rules/`. **Naming**: Root rule files use **ALL CAPS** (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md).
- **Key files**: **AGENTS.md** (canonical), **CLAUDE.md**, **CURSOR.md**, **WINDSURF.md** (tool entries), `.cursor/rules/*.md` (scope-specific).
- **When to use**: Every project using this framework. Prefer one AGENTS.md and thin tool-specific files that point to it.
- **Question answered**: *“What must agents do or avoid, and how is this project set up for this tool?”*

---

### 2. Blueprints — What to Build

- **Purpose**: Define product archetypes and drive automated project generation (stacks, tiers, required tasks).
- **Format**: YAML (machine-readable) + Markdown (human-readable).
- **Location**: `blueprints/`.
- **Key files**: `blueprint.meta.yaml`, `BLUEPRINT.md`, `overlays/{stack}/*.tpl.{ext}`.
- **When to use**: When defining a product pattern that will drive project generation.
- **Question answered**: *“What should I build?”*

*(In this repo, Blueprints are defined in the framework; implementations are archived.)*

---

### 3. Tasks — How to Implement a Feature

- **Purpose**: Deliver complete feature implementations (code, config, docs) across stacks and complexity tiers.
- **Format**: Code (Python/JS/etc.) + Jinja2 templates + YAML config + Markdown docs.
- **Location**: `tasks/`.
- **Key files**: `task-index.yaml`, per-task `TASK.md`, `config.yaml`, `universal/`, `stacks/{stack}/`.
- **When to use**: When implementing a specific feature within a blueprint- or recipe-driven project.
- **Question answered**: *“How do I implement [feature]?”*

*(In this repo, Tasks are defined in the framework; implementations are archived.)*

---

### 4. Recipes — Feature Combinations

- **Purpose**: Pre-configured bundles of Tasks + Skills for common scenarios (e.g. e-commerce, SaaS starter).
- **Format**: YAML (configuration) + Markdown (documentation).
- **Location**: `recipes/`.
- **Key files**: `recipe.yaml`, `RECIPE.md`, optional `examples/`.
- **When to use**: When you need a complete feature set for a scenario without picking each Task manually.
- **Question answered**: *“What features do I need for [scenario]?”*

*(In this repo, Recipes are defined in the framework; implementations are archived.)*

---

### 5. Subagents — Who Does the Work

- **Purpose**: Pre-configured sub-agents with curated skills, compatible blueprints/recipes, and workflows (e.g. code review, testing).
- **Format**: YAML (configuration) + Markdown (documentation).
- **Location**: `subagents/`.
- **Key files**: `subagent.yaml`, `SUBAGENT.md`, `workflows/`.
- **When to use**: When you need a specialized sub-agent for a domain or repetitive workflow.
- **Question answered**: *“Which subagent should I use for [task]?”*

*(In this repo, Subagents are defined in the framework; implementations are archived.)*

---

### 6. Skills — How to Do It Well

- **Purpose**: Reusable instruction packages that teach best practices and capabilities; invoked via trigger keywords.
- **Format**: Markdown (SKILL.md) + JSON (config.json).
- **Location**: `.agents/skills/` (this repo); also `~/.cursor/skills/` or `.cursor/skills/` for Cursor.
- **Key files**: `SKILL.md` (YAML frontmatter + steps + examples), `config.json` (triggers, examples), `README.md`, optional `_examples/`.
- **When to use**: When you need to teach an agent a specific capability that can be invoked on demand.
- **Question answered**: *“How do I do [capability] well?”*

**Current skills in this repo**: memory-system-setup, rules-setup, skill-setup, blueprints-setup, tasks-setup, recipes-setup, subagents-setup, prompt-validation-setup, protocol-setup.

---

### 7. Protocols — How Processes Are Defined

- **Purpose**: Single source of truth for repeatable procedures (e.g. prompt validation, memory lifecycle). Rules and agents reference them by path; **protocol skills** install and maintain the files.
- **Format**: Markdown (optionally YAML frontmatter).
- **Location**: `docs/protocols/`. **Naming**: e.g. `PROMPT-VALIDATION-PROTOCOL.md`, `MEMORY-SYSTEM-PROTOCOL.md`.
- **Key files**: **PROMPT-VALIDATION-PROTOCOL.md** (installed by prompt-validation-setup), **MEMORY-SYSTEM-PROTOCOL.md** (installed by memory-system-setup).
- **When to use**: When defining a repeatable process that agents must follow and that deserves one versionable document. Use a protocol skill to install it in a new project.
- **Question answered**: *“How is [process] defined and where do I find it?”*

---

## 3. How They Relate

- **Rules** are loaded at agent/subagent boot. They reference **Protocols** (e.g. `docs/protocols/PROMPT-VALIDATION-PROTOCOL.md`) for process definitions.
- **Subagents** run within Rules and use **Skills**; they may apply **Recipes** and **Blueprints**.
- **Recipes** bundle **Tasks** and **Skills**; **Blueprints** define products and reference tasks.
- **Tasks** are the implementation units; they can use **Skills** for best practices.
- **Protocol skills** (e.g. prompt-validation-setup, memory-system-setup) install and maintain **Protocol** files; they do not replace Rules.

```
Rules (AGENTS.md, etc.) ──► reference ──► Protocols (docs/protocols/)
        │
        └── constrain Subagents and agents
                    │
                    └── Subagents use Skills (and optionally Recipes/Blueprints/Tasks)
```

---

## 4. Comparison at a Glance

| Aspect   | Rules   | Blueprints | Tasks   | Recipes  | Subagents | Skills  | Protocols   |
|----------|---------|------------|---------|----------|-----------|---------|-------------|
| **Question** | What must agents do/avoid? | What to build? | How to implement? | What features? | Who does it? | How to do well? | How is process defined? |
| **Purpose** | Constrain behavior | Define products | Implement features | Bundle features | Deploy workers | Teach capabilities | Define processes |
| **Format** | Markdown | YAML + MD | Code + Config | YAML + MD | YAML + MD | MD + JSON | Markdown |
| **Scope** | Project / file | Product | Single feature | Feature set | Domain worker | Capability | Process |
| **Location** | Root, .cursor/rules/ | `blueprints/` | `tasks/` | `recipes/` | `subagents/` | `.agents/skills/` | `docs/protocols/` |

---

## 5. File Layout (Idealized)

```
<project root>
├── AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md   # Rules
├── .cursor/rules/*.md                             # Rules (Cursor)
├── docs/protocols/                                # Protocols
│   ├── PROMPT-VALIDATION-PROTOCOL.md
│   └── MEMORY-SYSTEM-PROTOCOL.md
├── blueprints/                                    # Blueprints (when adopted)
├── tasks/                                         # Tasks (when adopted)
├── recipes/                                       # Recipes (when adopted)
├── subagents/                                     # Subagents (when adopted)
├── .agents/skills/                                # Skills
│   ├── memory-system-setup/
│   ├── rules-setup/
│   ├── skill-setup/
│   ├── blueprints-setup/
│   ├── tasks-setup/
│   ├── recipes-setup/
│   ├── subagents-setup/
│   ├── prompt-validation-setup/
│   └── protocol-setup/
└── scripts/                                       # Automation (when present)
```

---

## 6. Implementation Status in This Repo

- **Active**: **Rules** (four rule files), **Protocols** (`docs/protocols/`), **Skills** (nine under `.agents/skills/`).
- **Archived / framework-only**: Blueprints, Tasks, Recipes, Subagents (structure and definitions in `AGENTIC-ASSETS-FRAMEWORK.md`; implementations in `_complete_archive/` or not present).

---

## 7. Quick Reference by Need

- **“I need agents to behave consistently”** → Rules (AGENTS.md + tool-specific files).
- **“I need to define what we’re building”** → Blueprints.
- **“I need to implement one feature”** → Tasks.
- **“I need a full feature set for a scenario”** → Recipes.
- **“I need a dedicated worker for a domain”** → Subagents.
- **“I need to teach a capability”** → Skills.
- **“I need a defined process (e.g. validation, memory)”** → Protocols (+ protocol skills to install them).

---

*For full detail, examples, and YAML snippets see `AGENTIC-ASSETS-FRAMEWORK.md`. For behavioral constraints and commands see `AGENTS.md`.*
