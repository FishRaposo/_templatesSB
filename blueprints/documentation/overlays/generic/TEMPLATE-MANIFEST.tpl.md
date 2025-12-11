# Documentation Blueprint - Template Manifest

> Complete inventory and organization of all templates in the documentation blueprint

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Total Templates**: {{TOTAL_TEMPLATES}}  
**Blueprint Version**: {{BLUEPRINT_VERSION}}

---

## 📁 Template Organization

### Root Folder - LLM Entry Points & Big Picture Files
These are the primary files that AI agents and developers encounter first.

| File | Purpose | Size | Notes |
|------|---------|------|-------|
| `AGENTS.md` | **PRIMARY LLM ENTRYPOINT** - Developer guide with AI operating standards | 18KB | Enhanced with archive content (MCP Tools, Script-First) |
| `CLAUDE.md` | **PRIMARY LLM ENTRYPOINT** - Claude quick reference | 5KB | Essential for Claude Code users |
| `AI-QUICK-START.md` | AI agent setup guide (6KB) | 6KB | Created from archive blueprint |
| `QUICKSTART-AI.md` | Comprehensive AI quickstart (42KB) | 42KB | Full version from archive |
| `README.md` | Project overview | 435B | Basic project description |
| `CONTEXT.md` | Philosophy & architecture decisions | 3KB | Project context and principles |
| `INDEX.md` | Project navigation | 8KB | Complete file index |
| `SYSTEM-MAP.md` | System architecture overview | 6KB | Visual system representation |
| `DOCUMENTATION.md` | Documentation navigation | 5KB | Guide to all documentation |
| `QUICKSTART.md` | Quick start for users | 2KB | User-focused quickstart |
| `WORKFLOW.md` | User workflows | 6KB | Development workflows |
| `CONTRIBUTING.md` | Contribution guide | 5KB | How to contribute |
| `CHANGELOG.md` | Version history | 3KB | Change tracking |
| `TODO.md` | Task tracking | 6KB | Project tasks |
| `EVALS.md` | Testing/evaluation guide | 8KB | Evaluation criteria |
| `tier-index.yaml` | Tier configuration | 16KB | MVP/Core/Enterprise tiers |

### Subdirectories

#### `agents/` - Individual AI Agent Guides
Specialized guides for different AI coding assistants.

| File | Agent | Purpose |
|------|-------|---------|
| `README.md` | - | Overview of all agent guides |
| `COPILOT.md` | GitHub Copilot | Integration guide |
| `GEMINI.md` | Google Gemini | Gemini/Duet AI guide |
| `CURSOR.md` | Cursor AI | Cursor IDE assistant |
| `CODY.md` | Sourcegraph Cody | Cody code assistant |
| `AIDER.md` | Aider | CLI assistant guide |
| `CODEX.md` | OpenAI Codex | Codex API integration |
| `WINDSURF.md` | Windsurf/Codeium | Windsurf assistant |
| `WARP.md` | Warp Terminal | AI terminal guide |

#### `blueprints/` - Blueprint System Documentation
Internal documentation for the blueprint system itself.

| File | Purpose |
|------|---------|
| `README.md` | Blueprint system overview |
| `BLUEPRINT-COMPILER.md` | Blueprint compilation system |
| `BLUEPRINT-MAPPING.md` | Blueprint mapping documentation |
| `CHANGELOG-GENERATOR.md` | Automated changelog generation |
| `SYSTEM-INTEGRATION.md` | System integration documentation |
| `TIERED-TEMPLATES.md` | Tiered template system |
| `VALIDATION.md` | Validation protocols |

#### `docs/` - Technical Documentation
Technical and process documentation.

| File | Purpose |
|------|---------|
| `README.md` | Technical docs overview |
| `PROMPT-VALIDATION.md` | **MANDATORY** - Prompt validation system |
| `PROMPT-VALIDATION-QUICK.md` | Quick validation checklist |
| `DOCUMENTATION-MAINTENANCE.md` | **MANDATORY** - Documentation maintenance workflow |
| `TOOL-CALL-LIMITS.md` | Tool call optimization guide |
| `TIER-GUIDE.md` | Tier system guidance |
| `TIER-MAPPING.md` | Tier mapping documentation |
| `TIER-SELECTION.md` | Tier selection algorithm |
| `platform-engineering/` | Platform engineering docs (11 files) |

#### `examples/` - Code Examples and Patterns
Reusable examples and patterns.

| File | Purpose |
|------|---------|
| `README.md` | Examples overview |
| `API-DOCUMENTATION.md` | API documentation examples |
| `FRAMEWORK-PATTERNS.md` | Framework patterns |
| `GITIGNORE-EXAMPLES.md` | .gitignore examples |
| `MIGRATION-GUIDE.md` | Migration examples |
| `PROJECT-ROADMAP.md` | Roadmap examples |
| `TESTING-EXAMPLES.md` | Testing examples |

#### `scripts/` - Automation Scripts
Utility scripts for automation.

| File | Type | Purpose |
|------|------|---------|
| `README.md` | - | Scripts documentation |
| `install.sh` | Shell | Installation script |
| `self_heal.py` | Python | Self-healing system |
| `tier_config.py` | Python | Tier configuration |
| `validate_docs.py` | Python | Documentation validation |
| `validate_template_versions.py` | Python | Version validation |
| `validation_protocol_v2.py` | Python | Validation protocol |

#### `templates/` - Reusable Meta-Templates
Templates for creating other templates.

| File | Purpose |
|------|---------|
| `README.md` | Meta-templates overview |
| `SUBDIRECTORY-INDEX.md` | Index for directories with 5+ files |

#### `universal/` - Universal Agent Templates
Templates that can be used across any project.

| File | Purpose | Note |
|------|---------|------|
| `README.md` | Universal templates overview | Different from root files |
| `AGENT-DELEGATION-MATRIX.md` | Delegation patterns | Universal template |
| `AGENT-FAILURE-MODES.md` | Failure handling | Universal template |
| `AGENT-MEMORY-RULES.md` | Memory management | Universal template |
| `AGENT-ORCHESTRATION.md` | Orchestration patterns | Universal template |
| `AGENT-SAFETY-FILTERS.md` | Safety protocols | Universal template |
| `AGENTS.md` | Generic agent guide | Universal template |
| `AI-GUIDE.md` | General AI guide | Universal template |
| `CLAUDE.md` | Generic Claude guide | Universal template |
| `DOCUMENTATION-BLUEPRINT.md` | Generic blueprint | Universal template |
| `EXECUTION-ENGINE.md` | Execution patterns | Universal template |
| `INTEGRATION-GUIDE.md` | Integration patterns | Universal template |
| `TESTING-STRATEGY.md` | Testing patterns | Universal template |
| `WARP.md` | Generic Warp guide | Universal template |
| `.gitignore` | Git ignore template | Universal template |

#### `.github/` - GitHub Actions
CI/CD workflows.

| File | Purpose |
|------|---------|
| `template-validation.yml` | Template validation workflow |

---

## 🔄 Template Relationships

### Hierarchy
```
Root (LLM Entry Points)
├── agents/ (Specific AI guides)
├── blueprints/ (System docs)
├── docs/ (Technical docs)
├── examples/ (Code examples)
├── scripts/ (Automation)
├── templates/ (Meta-templates)
├── universal/ (Universal templates)
└── .github/ (CI/CD)
```

### Key Distinctions
- **Root files**: Project-specific, primary entry points
- **Universal files**: Generic templates for any project
- **Individual agent guides**: In `agents/`, not root
- **Blueprint system docs**: In `blueprints/`, for maintainers

---

## 📊 Statistics

| Category | Count |
|----------|-------|
| Root files | 16 |
| agents/ | 9 |
| blueprints/ | 7 |
| docs/ | 19 (including platform-engineering/) |
| examples/ | 7 |
| scripts/ | 7 |
| templates/ | 2 |
| universal/ | 15 |
| .github/ | 1 |
| **Total** | **83** |

---

## 🎯 Usage Guidelines

### For AI Agents
1. Start with `AGENTS.md` (root) - primary guide
2. Use `CLAUDE.md` (root) for quick reference
3. Refer to `AI-QUICK-START.md` for setup
4. Use `universal/` templates for generic patterns

### For Developers
1. Read `README.md` for overview
2. Check `CONTEXT.md` for philosophy
3. Use `INDEX.md` for navigation
4. Refer to appropriate agent guide in `agents/`

### For Maintainers
1. Use `blueprints/` for system documentation
2. Run `scripts/` for automation
3. Update `tier-index.yaml` for tier changes
4. Use `.github/` for CI/CD

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Maintained by**: {{MAINTAINER}}

---

*This manifest ensures all templates are accounted for and their purposes are clear.*
