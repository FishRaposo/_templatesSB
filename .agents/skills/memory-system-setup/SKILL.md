---
name: memory-system-setup
description: Use this skill when setting up the event-sourced memory system in a new project. This is the **protocol skill** for the Memory System Protocol (Protocols template type). It installs docs/protocols/MEMORY-SYSTEM-PROTOCOL.md, creates the file layout (CHANGELOG.md at root, .memory/ for graph and context), initializes the 4-layer architecture from templates or via script, and integrates the protocol reference into AGENTS.md. Fits the seven-template-types framework (Rules, Blueprints, Tasks, Recipes, Subagents, Skills, Protocols).
---

# Memory System Setup

This skill is the **protocol skill** for the **Memory System Protocol** — a **Protocol** template that defines the event-sourced memory lifecycle. Protocols are one of seven template types; they live in `docs/protocols/` and are referenced by Rules (AGENTS.md). This skill **installs** the protocol file and sets up the memory system (CHANGELOG, .memory/, AGENTS.md integration). For ongoing use (regeneration, archival), follow the project's `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` or the Memory System section in AGENTS.md.

## Core Approach

Four layers separate **behavior**, **history**, **structure**, and **trajectory**. This skill performs **initial setup** only.

```
L0: AGENTS.md         → Behavioral Core (immutable during execution)
L1: CHANGELOG.md      → Event Log (root, append-only, source of truth)
L2: .memory/graph.md  → Knowledge Graph (materialized from L1)
L3: .memory/context.md → Narrative (derived from L1 + L2, ephemeral)
```

**Data flows one way:** L1 → L2 → L3. Never backward. After setup, agents boot from these files, execute, append events, and terminate. The full process is defined in **docs/protocols/MEMORY-SYSTEM-PROTOCOL.md** (the Protocol template); this skill installs that protocol and the file layout.

## Step-by-Step Instructions

### 1. Ensure docs/protocols/ exists and install the protocol document

Create `docs/protocols/` if missing. Copy the Memory System Protocol from this skill's `templates/MEMORY-SYSTEM-PROTOCOL.md` to `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` in the project so the process is defined as a **Protocol** template (see protocol-setup for the Protocols type).

- **Source**: `.agents/skills/memory-system-setup/templates/MEMORY-SYSTEM-PROTOCOL.md` (or the equivalent path when the skill is installed under `~/.cursor/skills/` or `.cursor/skills/`).
- **Destination**: `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md`.

Example (from project root, when the skill is in-repo):

```bash
mkdir -p docs/protocols
cp .agents/skills/memory-system-setup/templates/MEMORY-SYSTEM-PROTOCOL.md docs/protocols/MEMORY-SYSTEM-PROTOCOL.md
```

Rules (AGENTS.md) will reference this protocol by path; do not duplicate the full protocol text in AGENTS.md.

### 2. Choose tier

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

### 3. Create the file layout

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

### 4. Initialize CHANGELOG.md (Layer 1)

Copy `memory-system-setup/templates/changelog.md` to project root as `CHANGELOG.md`. Update the initial event with project name, description, and tier. Event format: heading `### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type` with **Scope**, **Summary**, **Details**, **Refs**, **Tags**. See `./event-format-and-types.md` for the full template, event types, and append rules.

### 5. Initialize .memory/context.md (Layer 3 — Core/Full tier)

Copy `memory-system-setup/templates/context.md` to `.memory/context.md`. Fill **Active Mission**, **Current Sprint**, **Active Constraints**. The event horizon in `context.md` should match the last event in `CHANGELOG.md`; agents will regenerate this at session start per the protocol.

### 6. Initialize .memory/graph.md (Layer 2 — Full tier only)

Copy `memory-system-setup/templates/graph.md` to `.memory/graph.md`. After setup, agents materialize the graph from new events per `./event-format-and-types.md`.

### 7. Initialize TODO.md (Full tier only)

Create `TODO.md` at project root with sections: **In Progress**, **Up Next**, **Completed**, **Backlog**. Every completed task should have a corresponding event in `CHANGELOG.md`.

### 8. Integrate into AGENTS.md

Add a Memory System Protocol section to the project's AGENTS.md. Use the exact markdown in `./agents-integration-snippet.md`. That snippet includes the **load-memory** sequence (read context, check staleness, regenerate if needed) and a reference to `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` so agents boot consistently across rule files (AGENTS.md, CLAUDE.md, CURSOR.md, WINDSURF.md). Do not duplicate the full protocol—link to the protocol file.

### 9. Validate (optional)

From project root run: `python memory-system/scripts/validate-memory.py` (or `--project-root PATH`). Fix any reported errors before considering setup complete.

### 10. After setup — retrieval and tools (optional)

Once the memory system is running, agents can use the retrieval scripts (when `docs/memory-system/scripts/` or `memory-system/scripts/` is available):

- **Resolve event by ID:** `python docs/memory-system/scripts/get_event.py evt-001` or `1` — full event text from CHANGELOG or archive.
- **Search:** `python docs/memory-system/scripts/search_events.py [QUERY] [--type TYPE] [--scope SCOPE] [--tag TAG]` — compact index; add `--timeline evt-NNN --context N` for timeline; then use `get_event.py` for full text (progressive disclosure).
- **Relevant at boot:** `python docs/memory-system/scripts/relevant_events.py [QUERY] [--scope SCOPE] [--tag TAG] --limit N` — compact index for session start (default limit 5).
- **Summarize range:** `python docs/memory-system/scripts/summarize_events.py --last N` or `--start evt-XXX --end evt-YYY`.
- **Suggest event:** `python docs/memory-system/scripts/suggest_event.py --from-git` or `--from-stdin` — draft event for approval; paste into CHANGELOG after review.
- **Web viewer:** `python docs/memory-system/scripts/generate_memory_viewer.py [--output .memory/memory-viewer.html]` — static HTML with Event Log (evt-ID anchors), graph, context. Events tagged `private` or `sensitive` are excluded from search/summary/viewer by default; see protocol §15 (Privacy convention).

See `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` §15 Retrieval and Tools and `docs/memory-system/README.md` (Retrieval and Tools) for full usage.

## Best Practices

- Start with MVP; add Core or Full when the project needs shared context or dependency tracking
- Do not gitignore `.memory/` — it is shared state
- Ensure the first event in `CHANGELOG.md` describes the project and chosen tier
- After setup, agents follow the protocol in AGENTS.md for appending events, regenerating context, and (when needed) archiving

## Validation Checklist

- [ ] `docs/protocols/` exists and `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` exists (Protocol template installed)
- [ ] `CHANGELOG.md` exists at project root with `## Event Log` and sequential event IDs
- [ ] Events use heading format: `### evt-NNN | YYYY-MM-DD HH:MM | agent | type`
- [ ] Every event has **Scope** and **Summary**
- [ ] `.memory/` exists and is not gitignored (Core/Full)
- [ ] `.memory/graph.md` present (Full); `.memory/context.md` present (Core/Full)
- [ ] `.memory/context.md` Event horizon matches last event in `CHANGELOG.md` (Core/Full)
- [ ] `TODO.md` exists at root (Full)
- [ ] AGENTS.md includes the Memory System Protocol section from `agents-integration-snippet.md` (references `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md`)
- [ ] (Optional) `python memory-system/scripts/validate-memory.py` passes

## Troubleshooting

**Templates not found** — Templates live under the skill's `memory-system-setup/` subfolder (e.g. `memory-system/memory-system-setup/memory-system-setup/templates/`). If the skill is installed globally, use the path reported by the platform (e.g. `~/.cursor/skills/memory-system-setup/memory-system-setup/templates/`).

**AGENTS.md section missing** — Paste the contents of `./agents-integration-snippet.md` into AGENTS.md. That snippet includes the boot sequence and staleness check so agents load memory properly.

**Ongoing operations** — For context regeneration, archival when CHANGELOG exceeds ~50 events, or multi-agent conflicts, follow the project's Memory System Protocol or `memory-system/README.md`; those are outside this setup skill.

## Related Skills

- **protocol-setup** — Create or audit the Protocols template type (docs/protocols/, protocol skills). This skill (memory-system-setup) is the protocol skill for the Memory System Protocol.
- **rules-setup** — When creating or auditing AGENTS.md with memory system integration (add the Memory System Protocol section and link to docs/protocols/MEMORY-SYSTEM-PROTOCOL.md)
- **skill-setup** — When creating AI agent skills that operate within or reference the memory system

## Supporting Files

- **Protocol document (Protocols template type):** `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` — the Protocol template; install from this skill's `templates/MEMORY-SYSTEM-PROTOCOL.md` when setting up a new project. See protocol-setup for the Protocols template type.
- **Archive:** When the project has an archive, a memory system reference (e.g. PROJECT-MEMORY-SYSTEM-REFERENCE.md) may exist there; do not modify archive files
- **Event format, types, materialization:** `./event-format-and-types.md`
- **AGENTS.md integration snippet:** `./agents-integration-snippet.md` — includes load-memory steps, staleness check, and reference to docs/protocols/MEMORY-SYSTEM-PROTOCOL.md so agents boot correctly
- **Protocol and ongoing use:** The project's `docs/protocols/MEMORY-SYSTEM-PROTOCOL.md` (or memory-system/README.md when present), or the Memory System Protocol section in the project's AGENTS.md
- **Worked example (8 events through all layers):** `./_examples/worked-example.md` (under memory-system-setup/ when present)
- **Automation:** `memory-system/scripts/initialize-memory.py` (setup), `memory-system/scripts/validate-memory.py` (validation). **Retrieval (after setup):** `get_event.py`, `search_events.py`, `relevant_events.py`, `summarize_events.py`, `suggest_event.py`, `generate_memory_viewer.py` — see protocol §15 and memory-system README (Retrieval and Tools).
