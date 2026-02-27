---
name: memory-system-setup
description: Use this skill when setting up the event-sourced memory system in a new project. This includes choosing tier (MVP/Core/Full), creating the file layout (CHANGELOG.md at root, .memory/ for graph and context), initializing the 4-layer architecture from templates or via the initialization script, and integrating the Memory System Protocol into AGENTS.md.
---

# Memory System Setup

Sets up an event-sourced memory system in a new project so AI agents can operate as stateless workers on shared, immutable state. Pure markdown — no JSON, no runtime required. For ongoing use (regeneration, archival), follow the project's Memory System Protocol or `memory-system/README.md`.

## Core Approach

Four layers separate **behavior**, **history**, **structure**, and **trajectory**. This skill performs **initial setup** only.

```
L0: AGENTS.md         → Behavioral Core (immutable during execution)
L1: CHANGELOG.md      → Event Log (root, append-only, source of truth)
L2: .memory/graph.md  → Knowledge Graph (materialized from L1)
L3: .memory/context.md → Narrative (derived from L1 + L2, ephemeral)
```

**Data flows one way:** L1 → L2 → L3. Never backward. After setup, agents boot from these files, execute, append events, and terminate.

## Step-by-Step Instructions

### 1. Choose tier

| Signal | MVP | Core | Full |
|--------|-----|------|------|
| Solo developer, &lt; 1 month | ✅ | | |
| Multiple agents/developers, 1–6 months | | ✅ | |
| Complex dependencies, 6+ months, need "what blocks what?" | | | ✅ |

| Tier | Files to create |
|------|-----------------|
| **MVP** | `CHANGELOG.md` (root) only |
| **Core** | `CHANGELOG.md` + `.memory/context.md` |
| **Full** | `CHANGELOG.md` + `TODO.md` + `.memory/graph.md` + `.memory/context.md` |

### 2. Create the file layout

```
project/
├── AGENTS.md              ← Layer 0 (add Memory System section in step 6)
├── CHANGELOG.md           ← Layer 1 (append-only)
├── TODO.md                ← Full tier only
├── .memory/
│   ├── graph.md           ← Full tier
│   └── context.md         ← Core/Full tier
└── ...
```

Create `.memory/` if using Core or Full. Either:

- **Option A (script)**: From project root run: `python memory-system/scripts/initialize-memory.py <project_name> [mvp|core|full]`. Requires the memory-system folder at project root (e.g. submodule or copied).  
- **Option B (manual)**: Copy from this skill's `memory-system-setup/templates/` (e.g. `~/.cursor/skills/memory-system-setup/memory-system-setup/templates/` or project-local `memory-system/memory-system-setup/memory-system-setup/templates/`): MVP → `changelog.md` → `CHANGELOG.md`; Core → also copy `context.md` → `.memory/context.md`; Full → also copy `graph.md` → `.memory/graph.md`.

### 3. Initialize CHANGELOG.md (Layer 1)

Copy `memory-system-setup/templates/changelog.md` to project root as `CHANGELOG.md`. Update the initial event with project name, description, and tier. Event format: heading `### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type` with **Scope**, **Summary**, **Details**, **Refs**, **Tags**. See `./event-format-and-types.md` for the full template, event types, and append rules.

### 4. Initialize .memory/context.md (Layer 3 — Core/Full tier)

Copy `memory-system-setup/templates/context.md` to `.memory/context.md`. Fill **Active Mission**, **Current Sprint**, **Active Constraints**. The event horizon in `context.md` should match the last event in `CHANGELOG.md`; agents will regenerate this at session start per the protocol.

### 5. Initialize .memory/graph.md (Layer 2 — Full tier only)

Copy `memory-system-setup/templates/graph.md` to `.memory/graph.md`. After setup, agents materialize the graph from new events per `./event-format-and-types.md`.

### 6. Initialize TODO.md (Full tier only)

Create `TODO.md` at project root with sections: **In Progress**, **Up Next**, **Completed**, **Backlog**. Every completed task should have a corresponding event in `CHANGELOG.md`.

### 7. Integrate into AGENTS.md

Add a Memory System Protocol section to the project's AGENTS.md. Use the exact markdown in `./agents-integration-snippet.md`.

### 8. Validate (optional)

From project root run: `python memory-system/scripts/validate-memory.py` (or `--project-root PATH`). Fix any reported errors before considering setup complete.

## Best Practices

- Start with MVP; add Core or Full when the project needs shared context or dependency tracking
- Do not gitignore `.memory/` — it is shared state
- Ensure the first event in `CHANGELOG.md` describes the project and chosen tier
- After setup, agents follow the protocol in AGENTS.md for appending events, regenerating context, and (when needed) archiving

## Validation Checklist

- [ ] `CHANGELOG.md` exists at project root with `## Event Log` and sequential event IDs
- [ ] Events use heading format: `### evt-NNN | YYYY-MM-DD HH:MM | agent | type`
- [ ] Every event has **Scope** and **Summary**
- [ ] `.memory/` exists and is not gitignored (Core/Full)
- [ ] `.memory/graph.md` present (Full); `.memory/context.md` present (Core/Full)
- [ ] `.memory/context.md` Event horizon matches last event in `CHANGELOG.md` (Core/Full)
- [ ] `TODO.md` exists at root (Full)
- [ ] AGENTS.md includes the Memory System Protocol section from `agents-integration-snippet.md`
- [ ] (Optional) `python memory-system/scripts/validate-memory.py` passes

## Troubleshooting

**Templates not found** — Templates live under the skill's `memory-system-setup/` subfolder (e.g. `memory-system/memory-system-setup/memory-system-setup/templates/`). If the skill is installed globally, use the path reported by the platform (e.g. `~/.cursor/skills/memory-system-setup/memory-system-setup/templates/`).

**AGENTS.md section missing** — Paste the contents of `./agents-integration-snippet.md` into AGENTS.md.

**Ongoing operations** — For context regeneration, archival when CHANGELOG exceeds ~50 events, or multi-agent conflicts, follow the project's Memory System Protocol or `memory-system/README.md`; those are outside this setup skill.

## Related Skills

- **rules-setup** — When creating or auditing AGENTS.md with memory system integration (add the Memory System Protocol section)
- **skill-builder** — When creating AI agent skills that operate within or reference the memory system

## Supporting Files

- **Archive:** When the project has an archive, a memory system reference (e.g. PROJECT-MEMORY-SYSTEM-REFERENCE.md) may exist there; do not modify archive files
- **Event format, types, materialization:** `./event-format-and-types.md`
- **AGENTS.md integration snippet:** `./agents-integration-snippet.md`
- **Protocol and ongoing use:** The project's `memory-system/README.md` when present, or the Memory System Protocol section in the project's AGENTS.md
- **Worked example (8 events through all layers):** `./_examples/worked-example.md`
- **Automation:** `memory-system/scripts/initialize-memory.py` (setup), `memory-system/scripts/validate-memory.py` (validation)
