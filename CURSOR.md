# CURSOR.md - Universal Template System Guide for Cursor AI

**Purpose**: This file provides complete guidance to Cursor AI when working with code in this repository. It ensures AI follows project-specific patterns and standards.

**Version**: 1.0  
**AI Integration**: Comprehensive - architecture, patterns, commands, testing, autonomous workflows  
**Last Updated**: 2025-12-11

---

## 🎯 Project Overview

**Universal Template System**: A blueprint-driven template system for automated project analysis, building, and gap identification.

| Attribute | Value |
|-----------|-------|
| Version | 3.2 |
| Status | Production Ready |
| Language | Python 3.8+ |
| Tasks | 47 production tasks |
| Templates | 667 validated files |
| Stacks | 12 technology stacks |

---

## ⚡ Essential Commands

```bash
# Autonomous project generation (RECOMMENDED)
python scripts/setup-project.py --auto --name "MyProject" --description "project description"

# Manual setup
python scripts/setup-project.py --manual-stack flutter --manual-tier mvp --name "MyApp"

# Validation (run before commits)
python scripts/validate-templates.py --full

# Full validation suite
python scripts/validate_stacks.py && python scripts/validate_tasks.py && python scripts/validate_blueprints.py
```

---

## 🏗️ Architecture

```
_templates/
├── blueprints/          # Product archetypes (MINS blueprint)
├── tasks/               # 47 task templates with universal/stack implementations
├── scripts/             # Analysis, building, validation tools
├── stacks/              # 12 technology stack templates
├── tiers/               # MVP, Core, Enterprise complexity levels
└── reference-projects/  # Generated reference implementations
```

### Key Files
- `tasks/task-index.yaml` - All task definitions and file mappings
- `blueprints/mins/blueprint.meta.yaml` - Blueprint configuration
- `scripts/validate-templates.py` - Main validation script

---

## 📋 47 Tasks in 9 Categories

| Category | Tasks |
|----------|-------|
| Web & API | web-scraping, rest-api-service, graphql-api, web-dashboard, landing-page, public-api-gateway |
| Auth & Billing | auth-basic, auth-oauth, user-profile-management, billing-stripe, team-workspaces |
| Background Work | job-queue, scheduled-tasks, notification-center, webhook-consumer, file-processing-pipeline |
| Data & ML | etl-pipeline, analytics-event-pipeline, data-exploration-report, forecasting-engine, segmentation-clustering, ab-test-analysis, embedding-index |
| SEO & Growth | seo-keyword-research, seo-onpage-auditor, seo-rank-tracker, content-brief-generator, email-campaign-engine, link-monitoring |
| Product & SaaS | crud-module, admin-panel, feature-flags, multitenancy, audit-logging |
| DevOps | healthchecks-telemetry, ci-template, error-reporting, config-management, canary-release |
| AI-Specific | llm-prompt-router, rag-pipeline, agentic-workflow, code-refactor-agent |
| Meta/Tooling | project-bootstrap, docs-site, sample-data-generator, testing |

---

## 🔧 12 Technology Stacks

**Backend**: Python, Node.js, Go, TypeScript  
**Frontend**: React, Next.js  
**Mobile**: Flutter, React Native  
**Data**: SQL, R  
**Utility**: Generic, Rust

---

## ✅ Validation

```bash
# Always run before making changes
python scripts/validate-templates.py --full

# Expected output:
# Total Files: 667
# Errors: 0
# Warnings: 0
# All templates validated successfully.
```

---

## 🎯 Cursor-Specific Tips

1. **Use Cmd+K** to generate code following template patterns
2. **Reference task-index.yaml** when creating new functionality
3. **Check stacks/[stack]/README.md** for stack-specific patterns
4. **Run validation** after any template modifications
5. **Follow naming conventions**: `*.tpl.{ext}` for templates

---

## 📚 Documentation

- [QUICKSTART.md](./QUICKSTART.md) - Quick start
- [SYSTEM-MAP.md](./SYSTEM-MAP.md) - Full architecture
- [README.md](./README.md) - Main docs
- [AGENTS.md](./AGENTS.md) - Multi-agent guide

**Status**: PRODUCTION READY ✅
