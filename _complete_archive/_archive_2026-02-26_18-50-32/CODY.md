# CODY.md - Universal Template System Guide for Sourcegraph Cody

**Purpose**: This file provides complete guidance to Sourcegraph Cody when working with code in this repository.

**Version**: 1.0  
**Last Updated**: 2025-12-11

---

## 🎯 Project Overview

**Universal Template System**: Blueprint-driven template system for automated project generation.

- **Tasks**: 47 production tasks across 9 categories
- **Templates**: 667 validated template files
- **Stacks**: 12 technology stacks (Python, Node, Go, Flutter, React, etc.)
- **Tiers**: 3 complexity levels (MVP, Core, Enterprise)

---

## ⚡ Quick Commands

```bash
# Generate project
python scripts/setup-project.py --auto --name "Project" --description "description"

# Validate templates
python scripts/validate-templates.py --full

# Run all validators
python scripts/validate_stacks.py
python scripts/validate_tasks.py  
python scripts/validate_blueprints.py
```

---

## 🏗️ Key Directories

| Directory | Purpose |
|-----------|---------|
| `blueprints/` | Product archetypes with overlays |
| `tasks/` | 47 task templates |
| `scripts/` | Validation and build tools |
| `stacks/` | 12 stack-specific templates |
| `tiers/` | MVP/Core/Enterprise templates |

---

## 📋 Task Categories

1. **Web & API** (6): web-scraping, rest-api-service, graphql-api...
2. **Auth & Billing** (5): auth-basic, billing-stripe...
3. **Background Work** (5): job-queue, notification-center...
4. **Data & ML** (7): etl-pipeline, forecasting-engine...
5. **SEO & Growth** (6): seo-keyword-research...
6. **Product & SaaS** (5): crud-module, admin-panel...
7. **DevOps** (5): ci-template, healthchecks-telemetry...
8. **AI-Specific** (4): llm-prompt-router, rag-pipeline...
9. **Meta/Tooling** (4): project-bootstrap, testing...

---

## 🔧 Key Files

- `tasks/task-index.yaml` - Task definitions
- `blueprints/mins/blueprint.meta.yaml` - Blueprint config
- `scripts/validate-templates.py` - Main validator

---

## ✅ Before Committing

```bash
python scripts/validate-templates.py --full
# Expected: 667 files, 0 errors, 0 warnings
```

---

## 📚 More Documentation

- [SYSTEM-MAP.md](./SYSTEM-MAP.md) - Complete architecture
- [QUICKSTART.md](./QUICKSTART.md) - Getting started
- [README.md](./README.md) - Main documentation

**Status**: PRODUCTION READY ✅
