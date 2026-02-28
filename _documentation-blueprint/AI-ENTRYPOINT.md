# AI-ENTRYPOINT.md — Documentation Blueprint

_For AI agents: Read this file, execute the steps, and the project will have complete documentation._

---

## Purpose

This blueprint scaffolds complete documentation for any software project in under 2 minutes. Works for **new projects** (from scratch) and **existing projects** (adding documentation incrementally).

---

## Quick Decision

| Scenario | Command |
|----------|---------|
| New project | `python scaffold.py --name "MyProject" --tier core --stack python` |
| Existing project | `python scaffold.py --existing --tier core` |
| Detect best tier | `python scaffold.py --detect-tier` |

---

## Prerequisites

- Python 3.8+
- Working directory: `_documentation-blueprint/`
- Run all commands from that directory

---

## For NEW Projects

```bash
# Minimal (uses defaults)
python scaffold.py --name "MyProject" --stack python

# Full specification
python scaffold.py --name "MyProject" --description "A REST API for..." --tagline "Fast API" --tier core --stack python --output ./my-project

# Dry run first (see what would be created)
python scaffold.py --name "MyProject" --tier core --stack python --dry-run
```

### Available Options

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--name` | text | required | Project name |
| `--tier` | mvp, core, full | core | Documentation tier |
| `--stack` | python, node, go, generic | generic | Tech stack |
| `--description` | text | - | 2-3 sentence description |
| `--tagline` | text | - | One-line tagline |
| `--repo-url` | URL | - | Git repository URL |
| `--output` | path | current dir | Output directory |
| `--config` | path | - | Load from YAML file |

### Tier Selection Guide

| Tier | Files | Use When |
|------|-------|----------|
| **MVP** | 4 | Solo developer, prototype, < 1 month |
| **Core** | 11 | Team project, 1–6 months, multiple developers |
| **Full** | 20+ | Enterprise, multi-agent, > 6 months, compliance |

---

## For EXISTING Projects

```bash
# Add documentation to existing project (non-destructive)
python scaffold.py --existing --tier core --stack python --output /path/to/project

# Detect best tier first
python scaffold.py --detect-tier --output /path/to/project
```

The `--existing` flag:
- Skips files that already exist
- Only creates missing documentation
- Safe to run multiple times

---

## Detect Tier Automatically

```bash
python scaffold.py --detect-tier --output /path/to/project
```

Analyzes: git history age, file count, existing docs complexity, team size indicators.

---

## Validate After Setup

```bash
# Basic validation
python validate.py /path/to/project

# Strict (also checks for unfilled {{FILL_ME:...}} markers)
python validate.py /path/to/project --strict
```

### Validation Checklist

```
[ ] All required files exist (per tier)
[ ] No unfilled core placeholders ({{PROJECT_NAME}}, etc.)
[ ] All required sections present
[ ] Internal links resolve
[ ] File naming conventions followed
```

---

## Fill Placeholders

After scaffolding, search for unfilled markers:

```bash
# Find all placeholders
grep -r "{{FILL_ME" /path/to/project

# Replace manually or re-run with more config
```

---

## Common Workflows

### Workflow 1: New Project from Scratch

```bash
cd _documentation-blueprint
python scaffold.py \
  --name "MyAPI" \
  --description "A REST API for task management" \
  --tagline "Task management API" \
  --tier core \
  --stack python \
  --output ../my-api

cd ../my-api
# Fill any {{FILL_ME:...}} markers
python validate.py .
git init
git add . && git commit -m "docs: initialize documentation"
```

### Workflow 2: Add Docs to Existing Project

```bash
cd _documentation-blueprint
python scaffold.py --detect-tier --output /path/to/existing-project
# Reads recommended tier from output

python scaffold.py --existing --tier core --stack python --output /path/to/existing-project
python validate.py /path/to/existing-project
```

### Workflow 3: Using Config File

```bash
# Create project.yaml (see project.yaml.example)
cp project.yaml.example my-project.yaml
# Edit my-project.yaml with your values

python scaffold.py --config my-project.yaml --output ../my-project
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Project name is required" | Use `--name` flag or `--config` with project.yaml |
| "Invalid tier" | Must be: mvp, core, or full |
| "Invalid stack" | Must be: python, node, go, or generic |
| "Existing files detected" | Use `--force` to overwrite, or `--existing` to skip |
| Validation errors | Fill {{FILL_ME:...}} markers, then re-run validate.py |

---

## Output Structure

After running scaffold, you'll have:

```
project/
├── AGENTS.md              ← Behavioral rules (required)
├── CHANGELOG.md           ← Event log (required)
├── README.md              ← Project gateway
├── TODO.md                ← Task tracker [Core+]
├── QUICKSTART.md          ← Setup guide [Core+]
├── CONTRIBUTING.md        ← Contribution guidelines [Core+]
├── SECURITY.md            ← Security policy [Core+]
├── .memory/
│   ├── graph.md           ← Knowledge graph [Core+]
│   └── context.md         ← Current narrative
└── docs/
    ├── SYSTEM-MAP.md      ← Architecture [Core+]
    └── PROMPT-VALIDATION.md [Core+]
```

---

## Next Steps

1. Run scaffold command
2. Fill any `{{FILL_ME:...}}` markers
3. Run `python validate.py .` to verify
4. Commit: `git add . && git commit -m "docs: initialize documentation"`

---

**For full specification**: See `DOCUMENTATION-BLUEPRINT.md`  
**Quick reference**: See `QUICK-REFERENCE.md`
