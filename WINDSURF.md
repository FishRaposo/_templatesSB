# WINDSURF.md - Universal Template System Guide for Windsurf (Codeium)

**Purpose**: Guidance for Windsurf/Codeium AI when working with this repository.

**Version**: 1.0  
**Last Updated**: 2025-12-11

---

## 🎯 Project Overview

**Universal Template System**: Blueprint-driven template system for automated project generation.

- **47 Tasks** across 9 categories
- **667 Templates** validated
- **12 Stacks** supported
- **3 Tiers**: MVP, Core, Enterprise

---

## ⚡ Essential Commands

```bash
# Autonomous project generation
python scripts/setup-project.py --auto --name "MyProject" --description "project description"

# Template validation (run before commits)
python scripts/validate-templates.py --full

# Full validation suite
python scripts/validate_stacks.py
python scripts/validate_tasks.py
python scripts/validate_blueprints.py
```

---

## 🏗️ Directory Structure

```
_templates/
├── blueprints/mins/     # MINS blueprint with overlays
├── tasks/               # 47 task templates
│   └── task-index.yaml  # Task definitions
├── scripts/             # Validation & build tools
├── stacks/              # 12 technology stacks
├── tiers/               # MVP/Core/Enterprise
└── reference-projects/  # Generated examples
```

---

## 📋 Task Categories (47 Total)

| Category | Count | Key Tasks |
|----------|-------|-----------|
| Web & API | 6 | rest-api-service, graphql-api |
| Auth & Billing | 5 | auth-basic, billing-stripe |
| Background | 5 | job-queue, notification-center |
| Data & ML | 7 | etl-pipeline, embedding-index |
| SEO & Growth | 6 | seo-keyword-research |
| Product | 5 | crud-module, admin-panel |
| DevOps | 5 | ci-template, healthchecks-telemetry |
| AI-Specific | 4 | rag-pipeline, agentic-workflow |
| Tooling | 4 | project-bootstrap, testing |

---

## 🔧 Technology Stacks

**Backend**: Python, Node.js, Go, TypeScript  
**Frontend**: React, Next.js  
**Mobile**: Flutter, React Native  
**Data**: SQL, R  
**Other**: Generic, Rust

---

## ✅ Before Committing

```bash
python scripts/validate-templates.py --full
# Must show: 667 files, 0 errors, 0 warnings
```

---

## 🎯 Windsurf Tips

1. Use Cascade for multi-file changes following template patterns
2. Reference `task-index.yaml` for task structure
3. Check stack READMEs for conventions
4. Run validation after modifications

---

## 📚 Documentation

- [SYSTEM-MAP.md](./SYSTEM-MAP.md) - Complete architecture
- [QUICKSTART.md](./QUICKSTART.md) - Getting started
- [README.md](./README.md) - Main documentation

**Status**: PRODUCTION READY ✅
