# Documentation Blueprint

_Canonical documentation baseline for any software project with AI agent collaboration._

**Version**: 4.0

---

## Quick Start

> **For AI agents**: Start with `AI-ENTRYPOINT.md` — it provides step-by-step instructions for both new and existing projects.

```bash
# Interactive mode (recommended)
python scaffold.py --interactive

# From config file
python scaffold.py --config project.yaml

# With CLI flags
python scaffold.py --name "MyProject" --tier core --stack python

# Validate output
python validate.py ./my-project
```

---

## CLI Reference

### scaffold.py

Generate documentation for a new project.

```bash
python scaffold.py [OPTIONS]

Options:
  --name TEXT           Project name
  --tier [mvp|core|full]  Documentation tier (default: core)
  --stack TEXT          Tech stack (python, node, go, generic)
  --config PATH         Load values from YAML config
  --output PATH         Output directory (default: current dir)
  --dry-run             Show what would be created without writing
  --force, -f           Allow overwriting existing files
  --interactive, -i     Prompt for missing required values
  --list-files TIER     List files that would be created for tier
```

### validate.py

Validate scaffolded documentation.

```bash
python validate.py [PATH]

Options:
  --strict    Also check for {{FILL_ME:...}} markers
```

Checks:
1. Required files exist per tier
2. No unfilled core placeholders
3. Required sections present
4. Internal links resolve
5. File naming conventions

---

## Tiers

| Tier | Files | Use When |
|------|-------|----------|
| **MVP** | 4 | Solo developer, prototype, < 1 month |
| **Core** | 11 | Team project, 1–6 months, multiple developers |
| **Full** | 20+ | Enterprise, multi-agent, > 6 months, compliance |

**Upgrade triggers**:
- MVP → Core: CHANGELOG exceeds 30 events, or >1 agent working
- Core → Full: >3 agents, complex dependencies, or >6 months

### Files by Tier

| File | MVP | Core | Full |
|------|:---:|:----:|:----:|
| AGENTS.md | ✅ | ✅ | ✅ |
| CHANGELOG.md | ✅ | ✅ | ✅ |
| README.md | ✅ | ✅ | ✅ |
| .memory/context.md | ✅ | ✅ | ✅ |
| TODO.md | | ✅ | ✅ |
| QUICKSTART.md | | ✅ | ✅ |
| CONTRIBUTING.md | | ✅ | ✅ |
| SECURITY.md | | ✅ | ✅ |
| .memory/graph.md | | ✅ | ✅ |
| docs/SYSTEM-MAP.md | | ✅ | ✅ |
| docs/PROMPT-VALIDATION.md | | ✅ | ✅ |
| WORKFLOW.md | | | ✅ |
| CODE_OF_CONDUCT.md | | | ✅ |
| LICENSE.md | | | ✅ |
| EVALS.md | | | ✅ |
| DOCUMENTATION-OVERVIEW.md | | | ✅ |
| .github/* | | | ✅ |
| AI tool files | | | ✅ |

---

## Stack Profiles

Stack profiles provide default commands and prerequisites. Create or edit `stacks/{stack}.yaml`.

### Python

```yaml
name: Python
primary_language: Python
commands:
  install: "pip install -r requirements.txt"
  run: "python main.py"
  test: "pytest"
  lint: "ruff check ."
  build: "python -m build"
local_url: "http://localhost:8000"
prerequisites:
  - name: Python
    version: "3.11+"
    check: "python --version"
```

### Node.js

```yaml
name: Node.js
primary_language: TypeScript
commands:
  install: "npm install"
  run: "npm run dev"
  test: "npm test"
  lint: "npm run lint"
  build: "npm run build"
local_url: "http://localhost:3000"
prerequisites:
  - name: Node.js
    version: "20+"
    check: "node --version"
```

### Go

```yaml
name: Go
primary_language: Go
commands:
  install: "go mod download"
  run: "go run ./cmd/server"
  test: "go test ./..."
  lint: "golangci-lint run"
  build: "go build ./..."
local_url: "http://localhost:8080"
prerequisites:
  - name: Go
    version: "1.21+"
    check: "go version"
```

---

## Configuration

Create `project.yaml` to configure scaffolding:

```yaml
project:
  name: "MyProject"
  description: "A brief description of what this project does."
  tagline: "One-line tagline"
  repo_url: "https://github.com/user/repo"
  tier: core
  stack: python

license:
  name: "MIT"

# Optional: override stack defaults
commands:
  install: ""
  run: ""
  test: ""
  lint: ""

# Optional: shown in README
features:
  - "Feature 1"
  - "Feature 2"
  - "Feature 3"

# Optional: AI tool files to generate
ai_tools:
  - claude
  - cursor
```

---

## Placeholders

### Core (required)

| Placeholder | Source | Example |
|-------------|--------|---------|
| `PROJECT_NAME` | config.project.name | "MyProject" |
| `PROJECT_DESCRIPTION` | config.project.description | "A REST API..." |
| `PROJECT_TAGLINE` | config.project.tagline | "Fast API builder" |
| `REPO_URL` | config.project.repo_url | "https://github.com/..." |
| `TIER` | config.project.tier | "core" |
| `STACK` | config.project.stack | "python" |
| `LICENSE_NAME` | config.license.name | "MIT" |

### Commands (from stack or config)

| Placeholder | Source |
|-------------|--------|
| `INSTALL_COMMAND` | config.commands.install or stack default |
| `RUN_COMMAND` | config.commands.run or stack default |
| `TEST_COMMAND` | config.commands.test or stack default |
| `LINT_COMMAND` | config.commands.lint or stack default |
| `BUILD_COMMAND` | config.commands.build or stack default |
| `LOCAL_URL` | stack.local_url |

### Auto-filled

| Placeholder | Value |
|-------------|-------|
| `DATE` | YYYY-MM-DD |
| `TIME` | HH:MM |
| `YEAR` | YYYY |
| `AGENT` | "scaffold" |

### Optional (become FILL_ME markers if not set)

| Placeholder | Used In |
|-------------|---------|
| `FEATURE_1`, `FEATURE_2`, `FEATURE_3` | README.md |
| `TECH_1`, `TECH_2`, `TECH_3` | README.md |
| `PREREQ_1`, `PREREQ_1_VERSION`, etc. | QUICKSTART.md, CONTRIBUTING.md |
| `STYLE_RULE_1`, `STYLE_RULE_2`, `STYLE_RULE_3` | CONTRIBUTING.md |
| `SECURITY_EMAIL` | SECURITY.md, CODE_OF_CONDUCT.md |

---

## Three Pillars

A task is **not complete** until all three pillars pass:

### 1. AUTOMATING

Run scripts for everything that can be mechanically verified.

**Priority**: (1) Existing project scripts → (2) Standard tools (grep, find, markdownlint) → (3) Write new script → (4) Manual only as last resort

- [ ] Placeholder scanner: `grep -r '{{' .` returns 0 matches
- [ ] Link checker: no broken internal links
- [ ] Linter: 0 style errors
- [ ] All checks exit 0

### 2. TESTING

- [ ] All code examples are runnable
- [ ] Setup instructions verified end-to-end
- [ ] All internal links resolve

### 3. DOCUMENTING

| Change Type | Update These |
|-------------|--------------|
| New feature | README.md, SYSTEM-MAP.md, CHANGELOG.md |
| API change | API docs, CHANGELOG.md, QUICKSTART.md |
| Dependency | CONTRIBUTING.md, QUICKSTART.md, CHANGELOG.md |
| Security | SECURITY.md, CHANGELOG.md |
| Architecture | SYSTEM-MAP.md, AGENTS.md if behavioral, CHANGELOG.md |

---

## Memory System

Four-layer architecture for agent state:

```
┌──────────────────────────────────────────────────────────┐
│  L3: NARRATIVE  (.memory/context.md)                     │
│  "What matters right now" — ephemeral, rebuilt from L1+L2│
├──────────────────────────────────────────────────────────┤
│  L2: KNOWLEDGE GRAPH  (.memory/graph.md)                 │
│  Entities + relations — materialized from L1 only        │
├──────────────────────────────────────────────────────────┤
│  L1: EVENT LOG  (CHANGELOG.md)                           │
│  Source of truth — append-only, immutable once committed │
├──────────────────────────────────────────────────────────┤
│  L0: BEHAVIORAL CORE  (AGENTS.md)                        │
│  Constitution — immutable during execution               │
└──────────────────────────────────────────────────────────┘
```

**Trust order**: L0 > L1 > L2 > L3

### Event Format

```markdown
### evt-NNN | YYYY-MM-DD HH:MM | agent-name | type

**Scope**: area affected
**Summary**: one-line description

**Details**:
- key: value

**Refs**: evt-XXX
**Tags**: tag1, tag2
```

**Event types**: `decision` `create` `modify` `delete` `test` `fix` `dependency` `blocker` `milestone` `escalation` `handoff`

---

## Agent Lifecycle

### Boot Sequence

```
1. READ    AGENTS.md              → Load constraints
2. READ    .memory/context.md     → Load trajectory
3. CHECK   Staleness              → Regenerate if stale
4. READ    .memory/graph.md       → Query neighborhood [Core+]
5. VERIFY  Constraints            → Confirm in bounds
6. EXECUTE Task
```

### Shutdown Sequence

```
1. APPEND        All changes to CHANGELOG.md
2. MATERIALIZE   New events into .memory/graph.md [Core+]
3. REGENERATE    .memory/context.md
4. COMMIT        All changes in one git commit
5. DIE           Purge all local/working memory
```

---

## File Specifications

### AGENTS.md

Required sections: project identity · Do/Don't · file naming · workflow · Three Pillars · memory system · prompt validation

### CHANGELOG.md

Required sections: event format · Events section (append-only)

### README.md

Required sections: title + tagline · what it does · quick start · features · links  
Max 150 lines.

### TODO.md

Required sections: Active · In Progress · Blocked · Done

### QUICKSTART.md

Required sections: prerequisites · installation · first run · common errors

### CONTRIBUTING.md

Required sections: bug reporting · feature requests · development setup · PR process

### SECURITY.md

Required sections: supported versions · vulnerability reporting · response timeline

### docs/SYSTEM-MAP.md

Required sections: system overview · component inventory · data flow · dependencies

### .memory/graph.md

Required sections: Nodes table · Edges table · Meta  
Never edit directly — materialize from CHANGELOG.md.

### .memory/context.md

Required sections: Active Mission · Active Tasks · Constraints · Blockers · Recent Changes · Next Actions  
Regenerate every session.

---

## Directory Structure

```
project/
├── AGENTS.md
├── CHANGELOG.md
├── README.md
├── TODO.md
├── QUICKSTART.md
├── CONTRIBUTING.md
├── SECURITY.md
├── WORKFLOW.md
├── CODE_OF_CONDUCT.md
├── LICENSE.md
├── EVALS.md
├── DOCUMENTATION-OVERVIEW.md
├── .memory/
│   ├── graph.md
│   └── context.md
├── docs/
│   ├── SYSTEM-MAP.md
│   └── PROMPT-VALIDATION.md
└── .github/
    ├── PULL_REQUEST_TEMPLATE.md
    ├── CODEOWNERS
    └── ISSUE_TEMPLATE/
```

---

## What Each File Answers

| Question | File |
|----------|------|
| What can agents do? | AGENTS.md |
| What is this project? | README.md |
| What changed and when? | CHANGELOG.md |
| What's left to do? | TODO.md |
| How do I set up? | QUICKSTART.md |
| How do I contribute? | CONTRIBUTING.md |
| How do I report a vulnerability? | SECURITY.md |
| What's the architecture? | docs/SYSTEM-MAP.md |
| Is this prompt safe? | docs/PROMPT-VALIDATION.md |
| What matters right now? | .memory/context.md |
| How do entities relate? | .memory/graph.md |
| What's the release process? | WORKFLOW.md |
| Is output good enough? | EVALS.md |
| Where is all documentation? | DOCUMENTATION-OVERVIEW.md |

---

_Templates: `templates/` directory_  
_Stack profiles: `stacks/` directory_  
_Config example: `project.yaml.example`_

## Related Files

| File | Purpose |
|------|---------|
| `AI-ENTRYPOINT.md` | **Start here for AI agents** — step-by-step instructions |
| `QUICKSTART.md` | Quick start guide for humans |
| `QUICK-REFERENCE.md` | One-page cheat sheet |
