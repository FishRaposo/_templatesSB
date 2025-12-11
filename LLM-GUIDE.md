# LLM-GUIDE.md - Autonomous Project Generation Guide

**Purpose**: This is the primary entry point for LLM agents to understand and use the Universal Template System for autonomous project generation.

**Target**: All LLM coding agents (Claude, Copilot, Gemini, Cursor, Cody, Aider, GPT, Windsurf, etc.)

**Version**: 1.0  
**Last Updated**: 2025-12-11

---

## 🤖 AUTONOMOUS MODE - START HERE

### Single Command Project Generation

```bash
python scripts/setup-project.py --auto --name "ProjectName" --description "Your project description"
```

**That's it.** The system will:
1. Analyze your description
2. Select the appropriate blueprint
3. Choose optimal stacks and tiers
4. Generate a complete, ready-to-run project

---

## 📋 SYSTEM OVERVIEW

| Metric | Value |
|--------|-------|
| **Tasks** | 47 production-ready tasks |
| **Templates** | 672 validated template files |
| **Stacks** | 12 technology stacks |
| **Tiers** | 3 complexity levels |
| **Blueprints** | 2 (mins, documentation) |
| **Status** | Production Ready ✅ |

---

## 🎯 AGENTIC BEHAVIOR ENFORCEMENT

### Required Practices

When working with this repository, LLM agents MUST:

1. **Always validate before commits**:
   ```bash
   python scripts/validate-templates.py --full
   ```

2. **Follow the task-based architecture**:
   - Each feature maps to a task in `tasks/`
   - Use `task-index.yaml` for task definitions
   - Universal templates + stack-specific implementations

3. **Maintain documentation parity**:
   - Update docs when changing code
   - Keep agent guides synchronized
   - Follow the documentation blueprint

4. **Use blueprint-driven development**:
   - Start with blueprint selection
   - Apply stack-specific overlays
   - Follow tier complexity guidelines

### Testing Requirements

| Tier | Coverage | Test Types |
|------|----------|------------|
| MVP | Basic | Unit tests |
| Core | 70%+ | Unit + Integration |
| Enterprise | 90%+ | Full suite + Security |

---

## 🏗️ ARCHITECTURE AT A GLANCE

```
_templates/
├── blueprints/          # Product archetypes
│   ├── mins/            # Minimalist app blueprint
│   └── documentation/   # Documentation standards
├── tasks/               # 47 functional task templates
│   └── task-index.yaml  # Master task definitions
├── stacks/              # 12 technology implementations
├── tiers/               # MVP/Core/Enterprise complexity
├── scripts/             # Validation and build tools
└── [AGENT].md           # Agent-specific guides
```

---

## 📦 TASK CATEGORIES

### Web & API (6 tasks)
`web-scraping`, `rest-api-service`, `graphql-api`, `web-dashboard`, `landing-page`, `public-api-gateway`

### Auth & Billing (5 tasks)
`auth-basic`, `auth-oauth`, `user-profile-management`, `billing-stripe`, `team-workspaces`

### Background Work (5 tasks)
`job-queue`, `scheduled-tasks`, `notification-center`, `webhook-consumer`, `file-processing-pipeline`

### Data & ML (7 tasks)
`etl-pipeline`, `analytics-event-pipeline`, `data-exploration-report`, `forecasting-engine`, `segmentation-clustering`, `ab-test-analysis`, `embedding-index`

### SEO & Growth (6 tasks)
`seo-keyword-research`, `seo-onpage-auditor`, `seo-rank-tracker`, `content-brief-generator`, `email-campaign-engine`, `link-monitoring`

### Product & SaaS (5 tasks)
`crud-module`, `admin-panel`, `feature-flags`, `multitenancy`, `audit-logging`

### DevOps & Quality (5 tasks)
`healthchecks-telemetry`, `ci-template`, `error-reporting`, `config-management`, `canary-release`

### AI-Specific (4 tasks)
`llm-prompt-router`, `rag-pipeline`, `agentic-workflow`, `code-refactor-agent`

### Meta/Tooling (4 tasks)
`project-bootstrap`, `docs-site`, `sample-data-generator`, `testing`

---

## 🔧 TECHNOLOGY STACKS

| Stack | Type | Primary Use |
|-------|------|-------------|
| **Python** | Backend | APIs, Data Science, ML |
| **Node.js** | Backend | APIs, Microservices |
| **Go** | Backend | High-performance services |
| **TypeScript** | Backend | Type-safe backends |
| **Flutter** | Mobile | Cross-platform mobile apps |
| **React Native** | Mobile | Cross-platform mobile |
| **React** | Frontend | Web applications |
| **Next.js** | Full-stack | SSR web applications |
| **SQL** | Database | Schema, migrations |
| **R** | Analytics | Data analysis, statistics |
| **Rust** | Systems | Performance-critical code |
| **Generic** | Any | Technology-agnostic |

---

## 🚀 WORKFLOW PATTERNS

### Pattern 1: New Project Generation
```bash
# Autonomous mode (recommended)
python scripts/setup-project.py --auto --name "MyApp" --description "E-commerce platform with auth"

# Manual mode
python scripts/setup-project.py --manual-stack python --manual-tier core --name "MyAPI"
```

### Pattern 2: Adding Features to Existing Project
1. Identify needed tasks from categories above
2. Reference `tasks/[task-name]/` for templates
3. Apply stack-specific templates from `stacks/[stack]/`
4. Follow tier guidelines for complexity

### Pattern 3: Maintenance and Updates
```bash
# Validate changes
python scripts/validate-templates.py --full

# Check specific validators
python scripts/validate_stacks.py
python scripts/validate_tasks.py
python scripts/validate_blueprints.py
```

---

## 📝 BEST PRACTICES FOR LLM AGENTS

### Code Generation
- Use templates from `tasks/` as starting points
- Apply stack-specific patterns from `stacks/[stack]/`
- Include proper error handling from `ERROR-HANDLING.tpl.*`
- Follow framework patterns from `FRAMEWORK-PATTERNS-*.tpl.md`

### Documentation
- Always include README.md in generated projects
- Follow documentation blueprint standards
- Include API documentation for services
- Add inline comments for complex logic

### Testing
- Use test templates from `stacks/[stack]/base/tests/`
- Follow testing patterns for the tier level
- Include integration tests for API endpoints
- Add performance tests for Enterprise tier

### Security
- Apply security patterns from templates
- Include authentication where needed
- Add input validation
- Follow security guidelines in `ARCHITECTURE-*.tpl.md`

---

## 🔄 CONTINUOUS IMPROVEMENT

When working on this template system:

1. **Fix issues as you find them** - Don't leave broken links or invalid templates
2. **Update documentation** - Keep all guides current
3. **Maintain consistency** - Follow established patterns
4. **Validate thoroughly** - Run all validators before committing
5. **Test generated projects** - Ensure templates produce working code

---

## 📚 AGENT-SPECIFIC GUIDES

Each agent has a dedicated guide with optimized instructions:

| Agent | File | Focus |
|-------|------|-------|
| Claude | `CLAUDE.md` | Comprehensive coding |
| GitHub Copilot | `COPILOT.md` | Code completion |
| Google Gemini | `GEMINI.md` | Code assist |
| Cursor | `CURSOR.md` | AI-first editor |
| Sourcegraph Cody | `CODY.md` | Code intelligence |
| Aider | `AIDER.md` | CLI pair programming |
| OpenAI GPT | `CODEX.md` | Code generation |
| Windsurf | `WINDSURF.md` | Codeium editor |
| Warp | `WARP.md` | Terminal workflows |
| Multi-Agent | `AGENTS.md` | Coordination |

---

## ✅ QUICK VALIDATION CHECKLIST

Before any commit, verify:

- [ ] `python scripts/validate-templates.py --full` passes
- [ ] Documentation is updated
- [ ] Tests are included (if applicable)
- [ ] No broken links in markdown
- [ ] Template placeholders are correct
- [ ] Code follows stack-specific patterns

---

## 🎯 SUCCESS METRICS

A well-functioning template system should achieve:

- **0 validation errors** - All templates valid
- **0 warnings** - Clean validation output
- **100% documentation coverage** - Every component documented
- **Working generated projects** - Templates produce runnable code
- **Consistent patterns** - Same approach across all stacks

---

**The Universal Template System is designed for plug-and-play development.**

**Start with autonomous mode. Customize as needed. Always validate.**

**Status**: PRODUCTION READY ✅
