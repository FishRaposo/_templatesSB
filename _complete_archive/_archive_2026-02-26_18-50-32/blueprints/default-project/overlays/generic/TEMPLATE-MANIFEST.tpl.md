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
| `LLM-ENTRYPOINT.md` | **PRIMARY STARTING POINT** - For all AI agents | 7KB | System navigation guide |
| `AGENTS.md` | **PRIMARY LLM ENTRYPOINT** - Developer guide with AI operating standards | 18KB | Enhanced with archive content (MCP Tools, Script-First) |
| `CLAUDE.md` | **PRIMARY LLM ENTRYPOINT** - Claude quick reference | 5KB | Essential for Claude Code users |
| `AI-QUICK-START.md` | AI agent setup guide (6KB) | 6KB | Created from archive blueprint |
| `QUICKSTART-AI.md` | Comprehensive AI quickstart (42KB) | 42KB | Full version from archive |
| **Individual AI Agent Guides** | | | **System Documentation** |
| `AIDER.md` | Aider CLI assistant guide | 2KB | For Aider users |
| `CODEX.md` | OpenAI Codex integration guide | 2KB | For Codex API users |
| `CODY.md` | Sourcegraph Cody guide | 2KB | For Cody users |
| `COPILOT.md` | GitHub Copilot integration guide | 5KB | For Copilot users |
| `CURSOR.md` | Cursor IDE assistant guide | 4KB | For Cursor users |
| `GEMINI.md` | Google Gemini/Duet AI guide | 6KB | For Gemini users |
| `WARP.md` | Warp AI terminal guide | 32KB | For Warp terminal users |
| `WINDSURF.md` | Windsurf/Codeium assistant guide | 3KB | For Windsurf users |
| **Project Files** | | | **Templates to Copy** |
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

#### `templates/` - Reusable Meta-Templates
Templates for creating other templates.

| File | Purpose |
|------|---------|
| `README.md` | Meta-templates overview |
| `SUBDIRECTORY-INDEX.md` | Index for directories with 5+ files |

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
└── .github/ (CI/CD)
```

### Key Distinctions
- **Root files**: Project-specific, primary entry points
- **Individual agent guides**: In `agents/`, not root

---

## 📊 Statistics

| Category | Count |
|----------|-------|
| Root files | 16 |
| agents/ | 9 |
| .github/ | 1 |
| **Total** | **26** |

---

## 🎯 Usage Guidelines

### For AI Agents
1. Start with `AGENTS.md` (root) - primary guide
2. Use `CLAUDE.md` (root) for quick reference
3. Refer to `AI-QUICK-START.md` for setup

### For Developers
1. Read `README.md` for overview
2. Check `CONTEXT.md` for philosophy
3. Use `INDEX.md` for navigation
4. Refer to appropriate agent guide in `agents/`

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Maintained by**: {{MAINTAINER}}

---

*This manifest ensures all templates are accounted for and their purposes are clear.*
