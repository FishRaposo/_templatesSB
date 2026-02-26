# Archive Documentation Index

**Purpose**: Comprehensive index of all instructions, templates, and blueprints related to documentation found in `_complete_archive/`. Use this as a reference when building new skills, packs, or project documentation.

**Archive Date**: 2026-02-01  
**Indexed**: 2026-02-07  
**Total Files Cataloged**: 80+

## Recent Archive Updates

### 2026-02-26 Complete Repository Archive
- **Archive Location**: `_archive_2026-02-26_18-50-32/`
- **Documentation**: `ARCHIVE-2026-02-26.md`
- **Content**: Complete repository state with 1,600+ files and directories
- **Reason**: Full repository reset for fresh start
- **Key Components**: Skills repository, agent framework, template system, memory system, validation framework

---

## Quick Reference — What's Where

| Need | Go To | Section |
|------|-------|---------|
| Generate project docs from scratch | `_templates-main/DOCUMENTATION-BLUEPRINT.tpl.md` | [Documentation Blueprint](#1-documentation-blueprint) |
| Set up AI agent instructions | `_templates-main/docs/universal/AGENTS.tpl.md` | [Agent System Templates](#3-multi-agent-system-templates) |
| Create tool-specific guides | `_templates-main/docs/universal/CLAUDE.tpl.md` etc. | [Tool-Specific Templates](#4-tool-specific-ai-guide-templates) |
| Add a new blueprint/stack/task | `_templates-main/ADD-NEW-*.md` | [System Extension Guides](#6-system-extension-guides) |
| Set up API docs | `_templates-main/docs/examples/API-DOCUMENTATION.tpl.md` | [Example Templates](#5-example--reference-templates) |
| Maintain docs automatically | `_templates-main/docs/technical/DOCUMENTATION-MAINTENANCE.tpl.md` | [Technical Templates](#7-technical-documentation-templates) |
| Understand the template system | `_templates-main/TEMPLATE-SYSTEM-GUIDE.md` | [System Architecture](#8-system-architecture-documentation) |
| Full validation system reference | `PROMPT-VALIDATION-SYSTEM-REFERENCE.md` | [Comprehensive reference doc](#13-validation--reports) |
| Memory, context, state tracking | `PROJECT-MEMORY-SYSTEM-REFERENCE.md` | [Memory system reference](#13-validation--reports) |
| Create skills (older format) | `agent-skills-main/AGENTS.md` | [Agent Skills Archive](#9-agent-skills-archive) |
| Skill quality standards | `_supporting-files/UNIVERSAL_SKILL_STANDARDS.md` | [Supporting Files](#10-supporting-files) |

---

## 1. Documentation Blueprint

**The most comprehensive file in the archive — a complete documentation system for any project.**

### `_templates-main/DOCUMENTATION-BLUEPRINT.tpl.md` (601 lines, 25 KB)

**Features:**
- **Three Pillars Framework**: Scripting, Testing, Documenting — automatic documentation updates mandatory for every code change
- **18 required documentation files** with detailed specs for each:
  1. `README.md` — project gateway
  2. `CHANGELOG.md` — version history (Keep a Changelog format)
  3. `CONTEXT.md` — project philosophy and "why" behind decisions
  4. `TODO.md` — development roadmap
  5. `WORKFLOW.md` — user workflows and navigation paths
  6. `AGENTS.md` — AI development guide with Three Pillars
  7. `[LEAD_DEVELOPER].md` — quick reference for lead dev
  8. `EVALS.md` — evaluation criteria and success metrics
  9. `docs/ARCHITECTURE.md` — system architecture with module registry and ADRs
  10. `docs/PROJECT-SETUP.md` — development environment setup
  11. `docs/DEVELOPMENT-GUIDELINES.md` — coding standards with mandatory commenting
  12. `docs/TESTING-STRATEGY.md` — 7-layer testing strategy (85%+ coverage)
  13. `docs/DEPLOYMENT-GUIDE.md` — deployment procedures
  14. `docs/API-REFERENCE.md` — technical API documentation
  15. `docs/USER-MANUAL.md` — end-user guide
  16. `docs/INDEX.md` — navigation hub
  17. `docs/TEST-REQUIREMENTS.md` — mandatory test documentation
  18. `FEATURES.md` — feature matrix and capability tracking
- **Extended docs**: legal (ToS, Privacy), security, maintenance, QA checklists
- **GitHub community health files**: PR template, CODEOWNERS, issue templates
- **Complete file structure template** for project scaffolding
- **4-phase implementation workflow** (Foundation → Technical → User/Community → Maintenance)
- **Quality standards**: content, formatting, and maintenance checklists
- **Documentation parity enforcement**: code changes incomplete without doc updates

**Reuse potential**: ★★★★★ — Directly applicable as a documentation checklist for any project. The file list and required sections can seed AGENTS.md "Do" rules.

---

## 2. Universal AI Guide Templates

### `_templates-main/docs/universal/AI-GUIDE.tpl.md` (496 lines, 20 KB)

**Features:**
- Complete AI development assistant onboarding guide
- **Project identity template**: name, type, language, framework, status placeholders
- **10-step development approach**: read first, ask questions, follow patterns, test, document, mandatory comments, modular design, template privacy, Three Pillars validation, validation script
- **AI capability matrix**: what the agent can/should help with
- **Three Pillars validation integration** with `.\scripts\ai-workflow.ps1`

**Reuse potential**: ★★★★☆ — Good template for "AI onboarding" sections in AGENTS.md files.

### `_templates-main/docs/universal/INTEGRATION-GUIDE.tpl.md` (327 lines, 12 KB)

**Features:**
- **Template access hierarchy** — 3 priority levels for what AI should read first
- **Three Pillars workflow**: scripting → testing → documenting pipeline
- Links templates to specific development tasks

**Reuse potential**: ★★★☆☆ — Useful for multi-doc projects where agents need reading order guidance.

---

## 3. Multi-Agent System Templates

### `_templates-main/docs/universal/AGENTS.tpl.md` (332 lines, 11 KB)

**Features:**
- **Five-agent role system**: Architect, Builder, Refactorer, Doc Manager, Tester
- Each agent has: responsibilities, forbidden actions, reasoning loop, handoff conditions
- **Strict role boundaries** — agents are modes, not separate models
- **Doc Manager agent** specifically maintains documentation-code parity
- **Deterministic handoff protocol** between agents

**Reuse potential**: ★★★★★ — The five-agent pattern is directly reusable for complex project AGENTS.md files.

### `_templates-main/docs/universal/AGENT-ORCHESTRATION.tpl.md` (278 lines, 6 KB)

**Features:**
- **6-phase assembly line**: Architect → Builder → Tester → Doc Manager → Validator → Merge
- Entry/exit conditions for each phase
- Handoff artifact specifications
- Deterministic phase ordering

**Reuse potential**: ★★★★☆ — Useful pattern for projects needing structured multi-step agent workflows.

### `_templates-main/docs/universal/AGENT-DELEGATION-MATRIX.tpl.md` (194 lines, 7 KB)

**Features:**
- **14-row delegation matrix**: situation → primary agent → delegates to → trigger conditions
- Role authority boundaries (who can do what)
- Delegation protocol (6 steps)
- Escalation paths

**Reuse potential**: ★★★☆☆ — Reference for designing agent coordination in complex projects.

### `_templates-main/docs/universal/AGENT-MEMORY-RULES.tpl.md` (334 lines, 10 KB)

**Features:**
- **3 memory types**: Local (task-scoped), Handoff (inter-agent), Shared (persistent)
- Handoff memory YAML schemas for each agent transition
- **Cross-role contamination prevention** — memory purged on handoff
- Clean handoff token specifications

**Reuse potential**: ★★★☆☆ — Reference for designing agent context management.

### `_templates-main/docs/universal/AGENT-FAILURE-MODES.tpl.md` (389 lines, 12 KB)

**Features:**
- **Failure modes with detection code**: role drift, scope creep, infinite loops, hallucination
- Python detection functions for each failure type
- Recovery protocols (abort, reset, retry, escalate)
- Prevention strategies

**Reuse potential**: ★★★☆☆ — Defensive patterns for AGENTS.md boundary enforcement.

### `_templates-main/docs/universal/AGENT-SAFETY-FILTERS.tpl.md` (542 lines, 17 KB)

**Features:**
- **Multi-layered safety system**: scope enforcement, tier constraints, complexity budgets
- Python implementation code for each filter
- Enforcement actions (block, escalate, log, reset)
- Real-time monitoring patterns

**Reuse potential**: ★★★☆☆ — Safety boundary patterns reusable in AGENTS.md "Never" sections.

### `_templates-main/docs/universal/EXECUTION-ENGINE.tpl.md` (1018 lines, 34 KB)

**Features:**
- **WorkItem data model** with YAML schema (scope, intent, artifacts, audit trail)
- State machine for task lifecycle (pending → running → blocked → done → failed)
- Agent-agnostic execution orchestration
- Comprehensive retry and recovery logic

**Reuse potential**: ★★☆☆☆ — Advanced reference for complex agentic workflows.

---

## 4. Tool-Specific AI Guide Templates

All in `_templates-main/docs/universal/` unless noted. These are fill-in-the-blank templates for configuring specific AI tools on a project.

| File | Size | Features |
|------|------|----------|
| **`CLAUDE.tpl.md`** | 37 KB (1123 lines) | Full Claude Code guide: project overview, essential commands, architecture, state management, DB layer, UI layer, testing strategy, error handling, dev tasks, platform notes, integrations, debugging tips, pre-commit checklist, critical policies |
| **`WARP.tpl.md`** | 16 KB (375 lines) | Warp AI + Agent Mode: reading order, role expectations, recommended prompts, workflow patterns, security/safety, command reference, prompt engineering tips |

**Root-level tool guides** (in `_templates-main/`):

| File | Size | Features |
|------|------|----------|
| **`CLAUDE.md`** | 39 KB | Production-ready Claude guide (not template — full content for the template system itself) |
| **`WARP.md`** | 31 KB | Production-ready Warp guide for the template system |
| **`COPILOT.md`** | 5 KB | GitHub Copilot configuration |
| **`CURSOR.md`** | 4 KB | Cursor IDE configuration |
| **`GEMINI.md`** | 6 KB | Google Gemini configuration |
| **`AIDER.md`** | 2 KB | Aider CLI configuration |
| **`CODEX.md`** | 2 KB | OpenAI Codex configuration |
| **`CODY.md`** | 2 KB | Sourcegraph Cody configuration |
| **`WINDSURF.md`** | 3 KB | Windsurf/Cascade configuration |
| **`AGENTS.md`** | 22 KB | Multi-agent coordination guide (v3.2, production content) |

**Reuse potential**: ★★★★★ — The `CLAUDE.tpl.md` is a gold-standard template for any tool-specific AI guide. Can be adapted for new tools.

---

## 5. Example & Reference Templates

All in `_templates-main/docs/examples/`:

| File | Size | Features |
|------|------|----------|
| **`API-DOCUMENTATION.tpl.md`** | 17 KB (725 lines) | REST/GraphQL/SDK documentation template with OpenAPI 3.0 structure, endpoint docs, auth, code examples, error handling |
| **`FRAMEWORK-PATTERNS.tpl.md`** | 42 KB (1438 lines) | Architecture patterns, design patterns by stack (MVC, MVVM, Clean Architecture), framework-specific conventions |
| **`MIGRATION-GUIDE.tpl.md`** | 24 KB (809 lines) | Platform/framework/architecture/database/language migration template with phases, success criteria, rollback plans |
| **`PROJECT-ROADMAP.tpl.md`** | 7 KB (219 lines) | TODO.md template with completed features, launch tasks, milestones, version planning |
| **`TESTING-EXAMPLES.tpl.md`** | 57 KB | Technology-specific test implementations across Flutter, React, Node.js, Python, Go |
| **`GITIGNORE-EXAMPLES.tpl.md`** | 9 KB | Curated .gitignore patterns by stack |
| **`README.tpl.md`** | 6 KB | README template for the examples directory itself |

**Reuse potential**: ★★★★☆ — API docs and migration templates are directly reusable. Framework patterns is a reference goldmine.

---

## 6. System Extension Guides

How to add new components to the template system. In `_templates-main/`:

| File | Size | Features |
|------|------|----------|
| **`ADD-NEW-BLUEPRINT-TEMPLATE.md`** | 14 KB (507 lines) | Directory structure, `blueprint.meta.yaml` schema, overlay structure per stack (flutter, python, node, go, react, etc.), validation checklist |
| **`ADD-NEW-STACK-TEMPLATE.md`** | 12 KB (435 lines) | Stack directory structure (`base/code/`, `base/docs/`, `base/tests/`), required doc templates per stack, reference project generation for 3 tiers |
| **`ADD-NEW-TASK-TEMPLATE.md`** | 17 KB (700 lines) | Task directory structure (`universal/` + `stacks/`), `meta.yaml` schema, universal + stack-specific template patterns |

**Reuse potential**: ★★★☆☆ — Structural patterns reusable when designing any template/scaffolding system.

---

## 7. Technical Documentation Templates

All in `_templates-main/docs/technical/`:

### Documentation Maintenance
| File | Size | Features |
|------|------|----------|
| **`DOCUMENTATION-MAINTENANCE.tpl.md`** | 6 KB (220 lines) | **Self-updating documentation system**: automatic update checklists by change type (bug fix, feature, refactor, deprecation, security), 4-step update workflow, daily/weekly/monthly/quarterly maintenance schedule, quality metrics, maintenance log |

### Prompt Validation
| File | Size | Features |
|------|------|----------|
| **`PROMPT-VALIDATION.tpl.md`** | 4 KB | Full prompt validation system |
| **`PROMPT-VALIDATION-QUICK.tpl.md`** | 1 KB | Quick validation checklist |

### Tier System
| File | Size | Features |
|------|------|----------|
| **`TIER-GUIDE.tpl.md`** | 23 KB (734 lines) | Three-tier documentation system (MVP → Core → Enterprise) with requirements per tier, LLM cost considerations, time estimates |
| **`TIER-MAPPING.tpl.md`** | 20 KB | Tier-to-requirements mapping tables |
| **`TIER-SELECTION.tpl.md`** | 10 KB | Decision tree for tier selection |

### Platform Engineering (Code Quality)
| File | Size | Features |
|------|------|----------|
| **`AGENTIC-REFACTOR-PLAYBOOK.tpl.md`** | 13 KB | Multi-agent refactoring playbook |
| **`CODE-DIFF-REASONER.tpl.md`** | 9 KB | AI-powered code diff analysis |
| **`CODE-GENERATION-TEMPLATES.tpl.md`** | 11 KB | Code generation template patterns |
| **`DIFF-VALIDATOR.tpl.md`** | 9 KB | Diff safety validation |
| **`HOTSPOT-RADAR.tpl.md`** | 12 KB | Code hotspot detection |
| **`MERGE-SAFETY-CHECKLIST.tpl.md`** | 9 KB | Pre-merge safety checklist |
| **`MIGRATION-ENGINE.tpl.md`** | 8 KB | Migration execution engine |
| **`REFACTOR-SAFETY-DASHBOARD.tpl.md`** | 7 KB | Refactoring safety monitoring |
| **`REFACTOR-SIMULATION-ENGINE.tpl.md`** | 7 KB | Refactor impact simulation |
| **`VALIDATION-PROTOCOL-v2.tpl.md`** | 8 KB | Validation protocol v2 |

### Other Templates
| File | Size | Features |
|------|------|----------|
| **`TOOL-CALL-LIMITS.tpl.md`** | 8 KB | AI tool call budget management |
| **`README.tpl.md`** | 3 KB | Technical docs directory README |

**Reuse potential**: ★★★★☆ — `DOCUMENTATION-MAINTENANCE.tpl.md` directly informs self-updating AGENTS.md. Tier system is useful for scaling documentation per project maturity.

---

## 8. System Architecture Documentation

In `_templates-main/`:

| File | Size | Features |
|------|------|----------|
| **`TEMPLATE-SYSTEM-GUIDE.md`** | 16 KB (598 lines) | Complete system architecture: blueprint-driven design, task-based organization, tier system mechanics, component relationships |
| **`SYSTEM-MAP.md`** | 54 KB (1237 lines) | Full system inventory: 47 tasks, 746 templates, 12 stacks, validation commands, file structure, maintenance guide |
| **`LLM-ENTRYPOINT.md`** | 8 KB (220 lines) | Primary LLM entry point: 3-file reading order, template categories table, 5-phase project generation workflow |
| **`LLM-GUIDE.md`** | 8 KB (263 lines) | Autonomous project generation: single-command setup, agentic behavior enforcement, documentation parity rules |
| **`AGENTIC-RULES.md`** | 6 KB (271 lines) | **Mandatory rules for AI agents**: validate before commit, never break templates, documentation parity, task-based architecture, naming conventions |
| **`QUICKSTART.md`** | 5 KB | Quick start guide for the template system |
| **`CONTRIBUTING.md`** | 5 KB | Contributor guidelines |
| **`FUTURE-IMPROVEMENTS.md`** | 7 KB | Planned system enhancements |
| **`README.md`** | 15 KB | Template system overview |

**Reuse potential**: ★★★☆☆ — `AGENTIC-RULES.md` patterns directly reusable for AGENTS.md boundary sections. `LLM-ENTRYPOINT.md` is a good model for "When Stuck" sections.

---

## 9. Agent Skills Archive

### `agent-skills-main/` — Original Skills Repository

| File | Size | Features |
|------|------|----------|
| **`AGENTS.md`** | 3 KB (111 lines) | Skills creation guide: directory structure, naming conventions, SKILL.md format, script requirements, context efficiency best practices, zip packaging, installation methods |
| **`README.md`** | 5 KB (148 lines) | 3 available skills: `react-best-practices` (40+ rules), `web-design-guidelines` (100+ rules), `react-native-guidelines` (16 rules) |
| **`CLAUDE.md`** | 0 bytes | Empty pointer file |

**Skills available:**
- `skills/react-best-practices/` — React/Next.js performance optimization (Vercel Engineering rules)
- `skills/web-design-guidelines/` — UI audit (accessibility, performance, UX — 100+ rules)
- `skills/react-native-skills/` — React Native best practices (16 rules)
- `skills/composition-patterns/` — Component composition patterns
- `skills/claude.ai/` — Claude.ai-specific skills

**Reuse potential**: ★★★★☆ — The `AGENTS.md` here is a concise, effective model for skill creation guides. The actual skills contain reusable audit checklists.

---

## 10. Supporting Files

### `_supporting-files/` — Skills Database & Reports

| File | Size | Features |
|------|------|----------|
| **`UNIVERSAL_SKILL_STANDARDS.md`** | 12 KB (470 lines) | Skill architecture (progressive disclosure), directory structure, SKILL.md format, config.json schema, platform paths, best practices |
| **`COMPREHENSIVE_SKILLS_INVENTORY.md`** | 51 KB | Complete inventory of all 1,456 skills |
| **`SKILLS_THEMATIC_PACKS.md`** | 40 KB | Skills organized by thematic packs |
| **`SKILLS_TRACKING_CHECKLIST.md`** | 16 KB | Quality tracking for skills |
| **`skills_database.json`** | 757 KB | Machine-readable skills database |
| **`skills_database_final.json`** | 678 KB | Final cleaned skills database |

**Reports** (historical, read-only):
- `duplicate_skills_report.md` (84 KB) — Identified duplicate skills
- `skills_comparison_report_v2.md` (48 KB) — Skills comparison analysis
- `sections_addition_report.md` (40 KB) — Sections added to skills
- `section_names_fix_report.md` (38 KB) — Section naming fixes
- `skills_comparison_report.md` (25 KB) — Earlier comparison
- `quality_improvement_report.md` (8 KB) — Quality improvements
- Various fix/validation reports

**Reuse potential**: ★★★☆☆ — `UNIVERSAL_SKILL_STANDARDS.md` is directly relevant to current skill creation. The JSON databases could be queried for skill metadata.

---

## 11. Blueprint Definitions

### `_templates-main/blueprints/`

| Blueprint | BLUEPRINT.md | meta.yaml | Features |
|-----------|-------------|-----------|----------|
| **`default-project/`** | 7 KB | 8 KB | **Most important** — mandatory documentation + repo hygiene baseline applied to ALL generated projects. 66 templates in generic overlay. |
| **`mins/`** | 7 KB | 2 KB | Mobile inventory app blueprint with Flutter focus |
| **`saas-api/`** | 2 KB | 1 KB | SaaS API service blueprint |
| **`web-dashboard/`** | 2 KB | 1 KB | Web dashboard blueprint |
| **`data-pipeline/`** | 1 KB | 1 KB | Data pipeline blueprint |

**Reuse potential**: ★★★★☆ — `default-project` blueprint defines the documentation baseline that every generated project gets. Study its overlay structure for understanding documentation scaffolding.

---

## 12. Misc Templates

### `_templates-main/docs/templates/`

| File | Size | Features |
|------|------|----------|
| **`README.tpl.md`** | 1 KB | README template for docs directory |
| **`SUBDIRECTORY-INDEX.tpl.md`** | 3 KB (167 lines) | **Auto-generated directory index template** with Handlebars-style placeholders: file categories, alphabetical listing, dependency graph, recent changes |

### `_templates-main/features/`

| File | Size | Features |
|------|------|----------|
| **`FEATURE-SCHEMA.md`** | 443 bytes | Feature definition schema |
| **`feature-schema.yaml`** | 1 KB | Machine-readable feature schema |

### `_templates-main/workflows/`

| File | Size | Features |
|------|------|----------|
| **`WORKFLOW-SCHEMA.md`** | 433 bytes | Workflow definition schema |
| **`workflow-schema.yaml`** | 2 KB | Machine-readable workflow schema |

### `_templates-main/template_schema/`

| File | Size | Features |
|------|------|----------|
| **`template_schema.json`** | 10 KB | JSON schema for template validation |
| **`schema.py`** | 6 KB | Python schema implementation |

---

## 13. Validation & Reports

### `PROMPT-VALIDATION-SYSTEM-REFERENCE.md` (this archive, root level)

**Comprehensive reference document** covering the entire validation system — all 8 Python scripts (~3,785 lines), 4 documentation templates (~914 lines), and 3 analysis reports (~559 lines). Covers prompt validation, tier compliance, self-healing protocols, diff inspection, template structure validation, test compliance, feature parity, and code quality checks. Includes architecture diagrams, CLI usage, and relevance mapping to the current Three Pillars Framework.

### `PROJECT-MEMORY-SYSTEM-REFERENCE.md` (this archive, root level)

**Comprehensive reference document** covering the entire memory, context, and state tracking system — 13 source files across agent memory rules, execution engine, project context/changelog/roadmap/workflow/eval templates, AI quickstart automation, tool call limits, documentation blueprint, and agent documentation status. Covers 4-level state persistence (agent memory → pipeline state → project state → system state), multi-agent handoff protocols, WorkItem pipeline state machine, and the full documentation baseline deployed to every generated project.

### `_templates-main/` (root)

| File | Size | Features |
|------|------|----------|
| **`COMPREHENSIVE_TEST_VALIDATION_REPORT.md`** | 10 KB | Full test suite validation results |
| **`COMPREHENSIVE_VALIDATION_REPORT.md`** | 7 KB | System-wide validation results |
| **`AGENT_DOCS_VERIFICATION_REPORT.md`** | 4 KB | Agent documentation verification |
| **`AGENT_DOCUMENTATION_STATUS.md`** | 4 KB | Agent doc completion status |
| **`FINAL_STACK_IMPLEMENTATION_STATUS.md`** | 9 KB | Stack implementation completeness |
| **`stack-implementation-gaps.md`** | 4 KB | Missing stack implementations |
| **`stack-validation-matrix.md`** | 3 KB | Stack validation results |
| **`task-validation-matrix.md`** | 3 KB | Task validation results |
| **`test-coverage-matrix.md`** | 5 KB | Test coverage across stacks |
| **`reports/FINAL-TEST-SUITE-COMPLETION-REPORT.md`** | 13 KB | Final test suite report |

---

## 14. Scripts (Documentation-Related)

In `_templates-main/scripts/`:

| Script | Size | Purpose |
|--------|------|---------|
| **`sync_documentation.py`** | 13 KB | Synchronize documentation across the system |
| **`fix_documentation_links.py`** | 7 KB | Fix broken documentation links |
| **`add-header-comments.py`** | 3 KB | Add header comments to template files |
| **`validate-templates.py`** | 29 KB | Comprehensive template validation |
| **`validate_blueprints.py`** | 12 KB | Blueprint structure validation |
| **`prompt_validator.py`** | 17 KB | AI prompt validation |

---

## Cross-Reference: Key Patterns Worth Extracting

### For Building AGENTS.md Files
1. **Three Pillars Framework** → `DOCUMENTATION-BLUEPRINT.tpl.md` lines 36-56
2. **Three-tier boundaries** → `AGENTIC-RULES.md`
3. **Five-agent role system** → `docs/universal/AGENTS.tpl.md`
4. **Documentation parity enforcement** → `docs/technical/DOCUMENTATION-MAINTENANCE.tpl.md`
5. **Self-updating checklists by change type** → `DOCUMENTATION-MAINTENANCE.tpl.md` lines 16-63

### For Building Skills
1. **Skill format** → `agent-skills-main/AGENTS.md` lines 29-68
2. **Progressive disclosure** → `_supporting-files/UNIVERSAL_SKILL_STANDARDS.md` lines 41-57
3. **Context efficiency** → `agent-skills-main/AGENTS.md` lines 70-78

### For Project Scaffolding
1. **Complete file structure** → `DOCUMENTATION-BLUEPRINT.tpl.md` lines 432-472
2. **Blueprint system** → `ADD-NEW-BLUEPRINT-TEMPLATE.md`
3. **Stack templates** → `ADD-NEW-STACK-TEMPLATE.md`
4. **Subdirectory indexes** → `docs/templates/SUBDIRECTORY-INDEX.tpl.md`

### For Testing Documentation
1. **7-layer testing strategy** → `docs/universal/TESTING-STRATEGY.tpl.md`
2. **Technology-specific examples** → `docs/examples/TESTING-EXAMPLES.tpl.md`
3. **Test requirements template** → `DOCUMENTATION-BLUEPRINT.tpl.md` lines 358-381

---

*This index is read-only reference material. Do not modify files in `_complete_archive/`.*
