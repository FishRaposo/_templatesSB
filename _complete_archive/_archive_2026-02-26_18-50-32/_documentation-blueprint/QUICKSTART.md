# Quickstart — Documentation Blueprint

_Set up a new project with complete documentation in under 20 minutes._

---

## Prerequisites

| Requirement | Check |
|-------------|-------|
| Git installed | `git --version` |
| Text editor | VS Code, Cursor, Windsurf, or similar |
| Your project tier decided | MVP (solo, prototype) · Core (team) · Full (enterprise) |

---

## Phase 1: Foundation (5 minutes)

Copy the blueprint templates to your project root and fill placeholders.

```bash
# Navigate to your project directory
cd /path/to/your/project

# Copy core templates
cp /path/to/_documentation-blueprint/templates/AGENTS.md.tpl.md AGENTS.md
cp /path/to/_documentation-blueprint/templates/CHANGELOG.md.tpl.md CHANGELOG.md
cp /path/to/_documentation-blueprint/templates/README.md.tpl.md README.md
```

### Fill Placeholders

Edit each file and replace all `{{PLACEHOLDER}}` values:

**AGENTS.md** — Required fields:
- `{{PROJECT_NAME}}` — Your project name
- `{{PROJECT_DESCRIPTION}}` — 2-3 sentences
- `{{REPO_URL}}` — Git repository URL
- `{{PRIMARY_LANGUAGE}}` — e.g., Python, TypeScript, Go
- `{{TIER}}` — MVP, Core, or Full
- `{{LINT_COMMAND}}` — e.g., `npm run lint`, `ruff check .`

**CHANGELOG.md** — Required fields:
- `{{DATE}}` — Today's date (YYYY-MM-DD)
- `{{TIME}}` — Current time (HH:MM)
- `{{AGENT}}` — Your name or "human"
- `{{PROJECT_NAME}}` — Your project name
- `{{TIER}}` — MVP, Core, or Full
- `{{STACK}}` — Your tech stack

**README.md** — Required fields:
- `{{PROJECT_NAME}}` — Your project name
- `{{PROJECT_TAGLINE}}` — One-line description
- `{{PROJECT_DESCRIPTION_2_3_SENTENCES}}` — What it does
- `{{REPO_URL}}` — Git repository URL
- `{{INSTALL_COMMAND}}` — How to install dependencies
- `{{RUN_COMMAND}}` — How to run the project
- `{{LOCAL_URL}}` — e.g., http://localhost:3000
- `{{FEATURE_1}}`, `{{FEATURE_2}}`, `{{FEATURE_3}}` — Key features
- `{{TECH_1}}`, `{{TECH_2}}`, `{{TECH_3}}` — Tech stack
- `{{LICENSE_NAME}}` — e.g., MIT, Apache-2.0

### Commit Phase 1

```bash
git add AGENTS.md CHANGELOG.md README.md
git commit -m "docs: initialize documentation foundation"
```

---

## Phase 2: Memory Setup (3 minutes)

Create the memory system for event-sourced state tracking.

```bash
# Create memory directory
mkdir .memory

# Copy memory templates
cp /path/to/_documentation-blueprint/templates/memory/graph.md.tpl.md .memory/graph.md
cp /path/to/_documentation-blueprint/templates/memory/context.md.tpl.md .memory/context.md
```

### Fill Placeholders

**.memory/graph.md** — Required fields:
- `{{PROJECT_NAME}}` — Your project name
- `{{TIER}}` — MVP, Core, or Full
- `{{COMPONENT_1}}`, `{{COMPONENT_2}}` — Your project components
- `{{COMPONENT_1_PATH}}`, `{{COMPONENT_2_PATH}}` — File paths
- `{{COMPONENT_1_OWNER}}`, `{{COMPONENT_2_OWNER}}` — Owners
- `{{DATE}}` — Today's date
- `{{NODE_COUNT}}` — Number of rows in Nodes table
- `{{EDGE_COUNT}}` — Number of rows in Edges table

**.memory/context.md** — Required fields:
- `{{PROJECT_NAME}}` — Your project name
- `{{DATE}}`, `{{TIME}}` — Current date/time
- `{{SESSION_DESCRIPTION}}` — What you're working on now
- `{{ACTIVE_MISSION_PARAGRAPH}}` — Current goal
- `{{TASK_1}}`, `{{TASK_2}}` — Active tasks
- `{{CONSTRAINT_1}}`, `{{CONSTRAINT_2}}` — Current constraints
- `{{DEPENDENCY_1}}`, `{{DEPENDENCY_2}}` — Dependencies
- `{{NEXT_ACTION_1}}`, `{{NEXT_ACTION_2}}`, `{{NEXT_ACTION_3}}` — Next steps

### Commit Phase 2

```bash
git add .memory/
git commit -m "docs: initialize memory system"
```

---

## Phase 3: Core Documentation (8 minutes)

Add the standard documentation files for Core tier and above.

```bash
# Copy core templates
cp /path/to/_documentation-blueprint/templates/TODO.md.tpl.md TODO.md
cp /path/to/_documentation-blueprint/templates/QUICKSTART.md.tpl.md QUICKSTART.md
cp /path/to/_documentation-blueprint/templates/CONTRIBUTING.md.tpl.md CONTRIBUTING.md
cp /path/to/_documentation-blueprint/templates/SECURITY.md.tpl.md SECURITY.md

# Create docs directory
mkdir docs

# Copy docs templates
cp /path/to/_documentation-blueprint/templates/SYSTEM-MAP.md.tpl.md docs/SYSTEM-MAP.md
cp /path/to/_documentation-blueprint/templates/PROMPT-VALIDATION.md.tpl.md docs/PROMPT-VALIDATION.md
```

### Fill Placeholders

**TODO.md** — Required fields:
- `{{TASK_1}}`, `{{TASK_2}}`, `{{TASK_3}}` — Initial tasks
- `{{TASK_IN_PROGRESS}}` — Task you're working on now
- `{{BLOCKED_TASK}}` — Any blocked task (or remove if none)
- `{{BLOCKER_DESCRIPTION}}` — What's blocking it
- `{{DATE}}` — Today's date

**QUICKSTART.md** — Required fields:
- `{{PROJECT_NAME}}` — Your project name
- `{{PREREQ_1}}`, `{{PREREQ_2}}`, `{{PREREQ_3}}` — Prerequisites
- `{{PREREQ_1_VERSION}}`, etc. — Version requirements
- `{{PREREQ_1_INSTALL_URL}}`, etc. — Install links
- `{{PREREQ_1_CHECK_COMMAND}}`, etc. — Verification commands
- `{{REPO_URL}}` — Git repository URL
- `{{INSTALL_COMMAND}}` — Install dependencies
- `{{ENV_EXAMPLE_FILE}}`, `{{ENV_FILE}}` — Environment files (remove if not needed)
- `{{ENV_VAR_1}}`, `{{ENV_VAR_2}}` — Environment variables
- `{{INIT_COMMAND}}` — Initialization (remove if not needed)
- `{{RUN_COMMAND}}` — How to run
- `{{EXPECTED_OUTPUT}}` — What you should see
- `{{LOCAL_URL}}` — Local URL
- `{{CLI_VERIFY_COMMAND}}` — Alternative verification
- `{{TEST_COMMAND}}`, `{{TEST_SINGLE_COMMAND}}` — Test commands
- `{{ERROR_1}}`, `{{ERROR_2}}` — Common errors
- `{{ERROR_1_CAUSE}}`, `{{ERROR_1_FIX}}` — Error causes and fixes
- `{{ISSUES_URL}}` — Issue tracker URL

**CONTRIBUTING.md** — Required fields:
- `{{ISSUES_URL}}` — Issue tracker URL
- `{{PREREQ_1}}`, `{{PREREQ_2}}`, `{{PREREQ_3}}` — Development prerequisites
- `{{PREREQ_1_VERSION}}`, etc. — Version requirements
- `{{REPO_URL}}` — Git repository URL
- `{{INSTALL_COMMAND}}` — Install dependencies
- `{{TEST_COMMAND}}` — Test command
- `{{STYLE_RULE_1}}`, `{{STYLE_RULE_2}}`, `{{STYLE_RULE_3}}` — Code style rules
- `{{LINT_COMMAND}}` — Lint command
- `{{CONTACT_METHOD}}` — Contact method
- `{{DISCUSSIONS_URL}}` — Discussions URL

**SECURITY.md** — Required fields:
- `{{PROJECT_NAME}}` — Your project name
- `{{VERSION_LATEST}}`, `{{VERSION_PREVIOUS}}`, `{{VERSION_MIN}}` — Supported versions
- `{{SECURITY_EMAIL}}` — Security email
- `{{SECURITY_ADVISORIES_URL}}` — GitHub Security Advisories URL
- `{{ALTERNATIVE_CHANNEL}}`, `{{ALTERNATIVE_CHANNEL_DETAILS}}` — Alternative reporting
- `{{DISCLOSURE_DELAY}}` — Disclosure delay (e.g., 7 days)
- `{{SECURITY_BEST_PRACTICE_1}}`, `{{SECURITY_BEST_PRACTICE_2}}` — Best practices

**docs/SYSTEM-MAP.md** — Required fields:
- `{{PROJECT_NAME}}` — Your project name
- `{{DATE}}` — Today's date
- `{{ASCII_OR_MERMAID_DIAGRAM}}` — Architecture diagram
- `{{CLIENT}}`, `{{API}}`, `{{DB}}`, `{{CACHE}}` — Component names
- `{{COMPONENT_1}}`, etc. — Component details
- `{{COMPONENT_1_PURPOSE}}`, etc. — Component purposes
- `{{COMPONENT_1_PATH}}`, etc. — Component paths
- `{{COMPONENT_1_OWNER}}`, etc. — Component owners
- `{{DATA_FLOW_DESCRIPTION}}` — Data flow description
- `{{STEP_1}}`, `{{STEP_2}}`, `{{STEP_3}}` — Data flow steps
- `{{DEP_1}}`, `{{DEP_2}}` — External dependencies
- `{{DEP_1_VERSION}}`, etc. — Dependency versions
- `{{DEP_1_PURPOSE}}`, etc. — Dependency purposes
- `{{DEP_1_RISK}}`, etc. — Dependency risks
- `{{COMPONENT_A}}`, `{{COMPONENT_B}}`, `{{COMPONENT_C}}` — Internal dependencies
- `{{DECISION_1}}`, `{{DECISION_2}}` — Architecture decisions
- `{{DECISION_1_RATIONALE}}`, etc. — Decision rationales
- `{{BOUNDARY_1}}`, `{{BOUNDARY_2}}`, `{{BOUNDARY_3}}` — System boundaries

**docs/PROMPT-VALIDATION.md** — No placeholders — copy as-is.

### Commit Phase 3

```bash
git add TODO.md QUICKSTART.md CONTRIBUTING.md SECURITY.md docs/
git commit -m "docs: add core documentation"
```

---

## Phase 4: Full Tier (Optional, 5 minutes)

Only if you're using the Full tier. Skip for MVP and Core.

```bash
# Copy Full tier templates
cp /path/to/_documentation-blueprint/templates/WORKFLOW.md.tpl.md WORKFLOW.md
cp /path/to/_documentation-blueprint/templates/CODE_OF_CONDUCT.md.tpl.md CODE_OF_CONDUCT.md
cp /path/to/_documentation-blueprint/templates/LICENSE.md.tpl.md LICENSE.md
cp /path/to/_documentation-blueprint/templates/EVALS.md.tpl.md EVALS.md
cp /path/to/_documentation-blueprint/templates/DOCUMENTATION-OVERVIEW.md.tpl.md DOCUMENTATION-OVERVIEW.md

# Create GitHub directory
mkdir -p .github/ISSUE_TEMPLATE

# Copy GitHub templates
cp /path/to/_documentation-blueprint/templates/github/PULL_REQUEST_TEMPLATE.md .github/
cp /path/to/_documentation-blueprint/templates/github/bug_report.md .github/ISSUE_TEMPLATE/
cp /path/to/_documentation-blueprint/templates/github/feature_request.md .github/ISSUE_TEMPLATE/
cp /path/to/_documentation-blueprint/templates/github/config.yml .github/ISSUE_TEMPLATE/
cp /path/to/_documentation-blueprint/templates/github/CODEOWNERS .github/
```

### Fill Placeholders

**WORKFLOW.md** — Required fields:
- `{{FEATURE_NAME}}` — Example feature name
- `{{TEST_COMMAND}}` — Test command
- `{{DEFAULT_REVIEWERS}}` — Default reviewers
- `{{REQUIRED_APPROVALS}}` — Required approvals
- `{{VERSION}}` — Version number
- `{{VERSION_FILE}}` — Version file path
- `{{BUILD_COMMAND}}` — Build command
- `{{DEPLOY_COMMAND}}` — Deploy command

**CODE_OF_CONDUCT.md** — Required fields:
- `{{PROJECT_NAME}}` — Your project name
- `{{CONTACT_EMAIL}}` — Contact email

**LICENSE.md** — Required fields:
- `{{PROJECT_NAME}}` — Your project name
- `{{LICENSE_NAME}}` — License name
- `{{SPDX_ID}}` — SPDX identifier
- `{{FULL_LICENSE_TEXT}}` — Full license text
- `{{YEAR}}` — Copyright year
- `{{COPYRIGHT_HOLDER}}` — Copyright holder

**EVALS.md** — Required fields:
- `{{PROJECT_NAME}}` — Your project name
- `{{MIN_COVERAGE}}`, `{{TARGET_COVERAGE}}` — Coverage targets
- `{{COVERAGE_COMMAND}}` — Coverage command
- `{{BUILD_COMMAND}}` — Build command
- `{{LINT_COMMAND}}` — Lint command
- `{{BENCHMARK_1}}`, `{{BENCHMARK_2}}` — Benchmark tasks
- `{{BENCHMARK_1_DESCRIPTION}}`, etc. — Benchmark descriptions
- `{{BENCHMARK_1_EXPECTED}}`, etc. — Expected results
- `{{DATE}}` — Date
- `{{BASELINE_TEST_COUNT}}` — Baseline test count
- `{{BASELINE_COVERAGE}}` — Baseline coverage
- `{{BASELINE_BUILD_TIME}}` — Baseline build time

**DOCUMENTATION-OVERVIEW.md** — Required fields:
- `{{PROJECT_NAME}}` — Your project name
- `{{DATE}}` — Today's date
- `{{API_GROUP_1}}`, `{{API_GROUP_1_DESCRIPTION}}` — API groups (remove if no API)
- `{{ADR_1_TITLE}}`, `{{ADR_1_DECISION}}` — ADRs (remove if not using ADRs)

**.github/config.yml** — Required fields:
- `{{SECURITY_REPORTING_URL}}` — Security reporting URL
- `{{DISCUSSIONS_URL}}` — Discussions URL

**.github/CODEOWNERS** — Required fields:
- `{{DEFAULT_OWNER}}` — Default owner
- `{{DOCS_OWNER}}` — Docs owner
- `{{PROJECT_LEAD}}` — Project lead
- `{{DEVOPS_OWNER}}` — DevOps owner

### Commit Phase 4

```bash
git add WORKFLOW.md CODE_OF_CONDUCT.md LICENSE.md EVALS.md DOCUMENTATION-OVERVIEW.md .github/
git commit -m "docs: complete full-tier documentation"
```

---

## AI Tool Files (Optional, 2 minutes each)

If you're using AI tools, create one file per tool from the AI-TOOL template.

```bash
# Example for Claude
cp /path/to/_documentation-blueprint/templates/AI-TOOL.md.tpl.md CLAUDE.md
```

### Fill Placeholders

Each AI tool file requires:
- `{{AI_TOOL_NAME}}` — Tool name (e.g., Claude, Windsurf)
- `{{AI_TOOL_LAUNCH_INSTRUCTIONS}}` — How to launch
- `{{AI_TOOL_LAUNCH_COMMAND}}` — Launch command
- `{{TOOL_1}}`, `{{TOOL_2}}` — Available tools
- `{{TOOL_1_PURPOSE}}`, `{{TOOL_2_PURPOSE}}` — Tool purposes
- `{{STACK}}` — Your tech stack
- `{{STACK_HINT}}` — Stack-specific hints
- `{{ENTRY_POINT}}` — Entry point
- `{{TEST_COMMAND}}` — Test command
- `{{LINT_COMMAND}}` — Lint command
- `{{AI_TOOL_SPECIFIC_NOTES}}` — Tool-specific notes

Max 60 lines per file. All behavioral rules are in AGENTS.md.

---

## Verification Checklist

After completing all phases for your tier:

### MVP Tier (4 files)
- [ ] `AGENTS.md` exists and has no placeholders
- [ ] `CHANGELOG.md` has evt-001
- [ ] `README.md` is complete
- [ ] `.memory/context.md` exists

### Core Tier (12 files)
- [ ] All MVP tier files complete
- [ ] `TODO.md` has initial tasks
- [ ] `QUICKSTART.md` has setup instructions
- [ ] `CONTRIBUTING.md` has contribution guidelines
- [ ] `SECURITY.md` has security policy
- [ ] `docs/SYSTEM-MAP.md` has architecture diagram
- [ ] `docs/PROMPT-VALIDATION.md` exists
- [ ] `.memory/graph.md` has initial nodes

### Full Tier (22+ files)
- [ ] All Core tier files complete
- [ ] `WORKFLOW.md` has branching strategy
- [ ] `CODE_OF_CONDUCT.md` exists
- [ ] `LICENSE.md` has license text
- [ ] `EVALS.md` has quality criteria
- [ ] `DOCUMENTATION-OVERVIEW.md` lists all docs
- [ ] `.github/` templates exist
- [ ] AI tool files (if applicable)

---

## Next Steps

1. **Start coding** — Your documentation foundation is ready
2. **Follow AGENTS.md** — All behavioral rules are defined there
3. **Append events** — Every decision goes into CHANGELOG.md
4. **Update docs** — Keep README, SYSTEM-MAP, and QUICKSTART current
5. **Regenerate memory** — Update graph.md and context.md after changes

---

**For details**: See `DOCUMENTATION-BLUEPRINT.md`  
**For reference**: See `QUICK-REFERENCE.md`  
**For templates**: See `templates/` directory
