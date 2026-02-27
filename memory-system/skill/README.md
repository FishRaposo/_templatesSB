# Memory System Skill

**Self-contained skill for deploying event-sourced memory systems to any project.**

## Quick Install

Copy this entire `skill/` folder to your project:

```bash
# Option 1: Copy folder
cp -r memory-system/skill/ your-project/memory-system-skill/

# Option 2: Install as submodule
git submodule add https://github.com/your-repo/memory-system.git your-project/memory-system-skill
```

Then point your AI agent at `memory-system-skill/SKILL.md`.

---

## What This Skill Does

When triggered, an AI agent will:

1. **Assess tier** — Determine MVP, Core, or Full based on project signals
2. **Create file layout** — Deploy the appropriate templates
3. **Initialize layers** — Set up CHANGELOG.md, graph.md, context.md as needed
4. **Integrate into AGENTS.md** — Add the Memory System Protocol section
5. **Handle archival** — Manage changelog growth over time

---

## Skill Structure

```
skill/
├── README.md                     # This file — installation guide
├── SKILL.md                      # Complete step-by-step instructions
├── config.json                   # Skill triggers and configuration
├── install.sh                    # Linux/macOS installer
├── install.ps1                   # Windows installer
└── memory-system/                # Memory system files
    ├── templates/                # Deployable files
    │   ├── changelog.md          # → deploys as CHANGELOG.md
    │   ├── graph.md              # → deploys as .memory/graph.md
    │   ├── context.md            # → deploys as .memory/context.md
    │   ├── context.md.tpl.md     # Jinja2 with variables
    │   └── graph.md.tpl.md       # Jinja2 with variables
    └── _examples/                # Usage examples
        └── worked-example.md     # 8 events through all 4 layers
```

---

## Usage Examples

### Deploy to New Project
```
"Set up a memory system for this project"
```

### Upgrade Existing Project
```
"Upgrade this project to full-tier memory system"
```

### Troubleshoot Issues
```
"Regenerate context.md — it's stale"
"Audit the memory system for consistency"
```

### Archive Events
```
"Archive old events from changelog.md"
```

---

## Triggers

The skill activates on keywords like:
- "memory system", "event log", "agent memory", "changelog"
- "set up memory system", "initialize changelog", "regenerate context"
- Patterns: `set.*up.*memory.*system`, `deploy.*memory.*system`, `regenerate.*context`

---

## Requirements

- **Permissions**: `file_read`, `file_write`
- **Tools**: None (pure markdown implementation)
- **Compatible with**: Claude, Roo, Cascade, Generic agents

---

## Deployment Tiers

| Signal | MVP | Core | Full |
|--------|-----|------|------|
| Solo developer, < 1 month | ✅ | | |
| Multiple agents, 1-6 months | | ✅ | |
| Complex dependencies, 6+ months | | | ✅ |

---

## Related Documentation

- `SKILL.md` — Complete implementation instructions
- `memory-system/_examples/worked-example.md` — 8 events flowing through all layers
- For full protocol documentation: See the parent `memory-system/README.md`
