# CODEX.md - Universal Template System Guide for OpenAI Codex/GPT

**Purpose**: Guidance for OpenAI Codex, GPT-4, and ChatGPT when working with this repository.

**Version**: 1.0  
**Last Updated**: 2025-12-11

---

## 🎯 System Summary

**Universal Template System** - Blueprint-driven template generation system.

| Metric | Value |
|--------|-------|
| Tasks | 47 |
| Templates | 667 |
| Stacks | 12 |
| Tiers | 3 |
| Status | Production Ready ✅ |

---

## ⚡ Commands

```bash
# Generate project
python scripts/setup-project.py --auto --name "Project" --description "desc"

# Validate
python scripts/validate-templates.py --full
python scripts/validate_stacks.py
python scripts/validate_tasks.py
python scripts/validate_blueprints.py
```

---

## 🏗️ Structure

```
_templates/
├── blueprints/     # Product archetypes
├── tasks/          # 47 task templates
├── scripts/        # Tools
├── stacks/         # 12 tech stacks
└── tiers/          # MVP/Core/Enterprise
```

---

## 📋 Task Categories

- **Web & API** (6): APIs, dashboards, scraping
- **Auth & Billing** (5): Authentication, payments
- **Background** (5): Jobs, notifications
- **Data & ML** (7): Pipelines, analytics
- **SEO & Growth** (6): SEO, content
- **Product** (5): CRUD, admin panels
- **DevOps** (5): CI/CD, monitoring
- **AI** (4): LLM, RAG, agents
- **Tooling** (4): Bootstrap, docs, testing

---

## 🔧 Stacks

Python, Node.js, Go, TypeScript, React, Next.js, Flutter, React Native, SQL, R, Generic, Rust

---

## ✅ Validation

```bash
# Run before any commit
python scripts/validate-templates.py --full
# Expected: 667 files, 0 errors
```

---

## 📚 Key Files

- `tasks/task-index.yaml` - Task definitions
- `blueprints/mins/blueprint.meta.yaml` - Blueprint config
- `SYSTEM-MAP.md` - Full architecture

**Status**: PRODUCTION READY ✅
