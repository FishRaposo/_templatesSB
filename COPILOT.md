# COPILOT.md - Universal Template System Guide for GitHub Copilot

**Purpose**: This file provides complete guidance to GitHub Copilot (including Copilot Chat, Copilot Workspace, and Copilot Coding Agent) when working with code in this repository.

**Version**: 1.0  
**AI Integration**: Comprehensive - includes architecture, patterns, commands, testing, and autonomous workflows  
**Last Updated**: 2025-12-11

---

## 🎯 Project Overview

**Universal Template System**: A comprehensive blueprint-driven template system for automated project analysis, building, and gap identification.

- **Version**: 3.2
- **Status**: Production Ready with Blueprint System
- **Primary Language**: Python 3.8+
- **Architecture**: Blueprint-Driven with Task-Based Analysis Pipeline
- **Total Tasks**: 47 production tasks
- **Template Files**: 667 validated templates

---

## ⚡ Essential Commands

```bash
# Blueprint-driven project setup (RECOMMENDED)
python scripts/setup-project.py --auto --name "MyProject" --description "project description"

# Validate template system
python scripts/validate-templates.py --full

# Run all validators
python scripts/validate_stacks.py
python scripts/validate_tasks.py
python scripts/validate_blueprints.py

# Analyze project requirements
python scripts/analyze_and_build.py --description "Real-time chat app" --build
```

---

## 🏗️ Directory Structure

```
_templates/
├── 📁 blueprints/               # Product archetype definitions
│   └── mins/                    # MINS blueprint with overlays
├── 📁 tasks/                    # 47 task templates
│   ├── 📄 task-index.yaml       # Unified task definitions
│   └── 📁 [task-name]/          # Individual tasks with universal/stacks
├── 📁 scripts/                  # Analysis and validation tools
├── 📁 stacks/                   # 12 technology stack templates
├── 📁 tiers/                    # MVP, Core, Enterprise templates
└── 📁 reference-projects/       # Generated reference implementations
```

---

## 📋 Task Categories (47 Tasks)

| Category | Count | Examples |
|----------|-------|----------|
| Web & API | 6 | web-scraping, rest-api-service, graphql-api |
| Auth, Users & Billing | 5 | auth-basic, billing-stripe, user-profile-management |
| Background Work | 5 | job-queue, scheduled-tasks, notification-center |
| Data, Analytics & ML | 7 | etl-pipeline, forecasting-engine, embedding-index |
| SEO / Growth | 6 | seo-keyword-research, content-brief-generator |
| Product & SaaS | 5 | crud-module, admin-panel, multitenancy |
| DevOps & Quality | 5 | ci-template, healthchecks-telemetry, error-reporting |
| AI-Specific | 4 | llm-prompt-router, rag-pipeline, agentic-workflow |
| Meta / Tooling | 4 | project-bootstrap, docs-site, testing |

---

## 🔧 Technology Stacks (12 Stacks)

- **Backend**: Python, Node.js, Go, TypeScript
- **Frontend**: React, Next.js
- **Mobile**: Flutter, React Native
- **Data**: SQL, R
- **Utility**: Generic, Agnostic

---

## ✅ Validation Commands

```bash
# Full template validation (ALWAYS run before commits)
python scripts/validate-templates.py --full

# Stack-specific validation
python scripts/validate_stacks.py --detailed

# Task validation
python scripts/validate_tasks.py --detailed

# Blueprint validation
python scripts/validate_blueprints.py --detailed
```

---

## 🎯 Copilot-Specific Guidelines

### When Making Changes

1. **Always run validation** after modifications:
   ```bash
   python scripts/validate-templates.py --full
   ```

2. **Follow template structure**:
   - Universal templates in `tasks/[task]/universal/`
   - Stack-specific in `tasks/[task]/stacks/[stack]/`

3. **Maintain consistency**:
   - Use existing naming conventions
   - Include header comments in all templates
   - Add template placeholders ({{PROJECT_NAME}}, etc.)

4. **Check task-index.yaml** for task definitions and file mappings

### File Naming Conventions

- Templates: `*.tpl.{ext}` (e.g., `config.tpl.py`, `service.tpl.go`)
- Documentation: `*.tpl.md` or `*.md`
- Configuration: `*.yaml` or `*.yml`

---

## 📚 Related Documentation

| File | Purpose |
|------|---------|
| [QUICKSTART.md](./QUICKSTART.md) | Quick start guide |
| [SYSTEM-MAP.md](./SYSTEM-MAP.md) | Complete architecture |
| [README.md](./README.md) | Main documentation |
| [AGENTS.md](./AGENTS.md) | Multi-agent coordination |
| [CLAUDE.md](./CLAUDE.md) | Claude-specific guide |

---

## 🚀 Quick Reference

```yaml
# System Status
tasks: 47
templates: 667
stacks: 12
tiers: 3 (MVP, Core, Enterprise)
blueprints: 1 (mins)
validation: EXCELLENT (0 errors)
status: PRODUCTION READY ✅
```

**For comprehensive details, see [SYSTEM-MAP.md](./SYSTEM-MAP.md)**
