# GEMINI.md - Universal Template System AI Guide

**Purpose**: This file provides complete guidance to Google Gemini (including Gemini Code Assist) when working with code in this repository. It's a mandatory reference document that ensures AI follows project-specific patterns and standards.

**Version**: 1.0  
**AI Integration**: Comprehensive - includes architecture, patterns, commands, testing, and autonomous workflows  
**Last Updated**: 2025-12-11

---

## 🎯 Project Overview

**Universal Template System**: A comprehensive blueprint-driven template system for automated project analysis, building, and gap identification.

- **Version**: 3.2
- **Status**: Production Ready with Blueprint System
- **Primary Language**: Python 3.8+
- **Key Framework(s)**: YAML configuration, Jinja2 templates, pathlib for cross-platform compatibility, Blueprint resolution engine
- **Architecture**: Blueprint-Driven with Task-Based Analysis Pipeline

---

## ⚡ Essential Commands

### Development & Analysis

```bash
# Blueprint-driven project setup (RECOMMENDED)
python scripts/setup-project.py  # Interactive blueprint-first setup

# Autonomous project generation
python scripts/setup-project.py --auto --name "MyProject" --description "project description"

# Analyze and build any project
python scripts/analyze_and_build.py --description "Real-time chat app with auth" --build

# Validate template system
python scripts/validate-templates.py --full
```

### Validation Commands

```bash
# Full validation suite
python scripts/validate-templates.py --full
python scripts/validate_stacks.py
python scripts/validate_tasks.py
python scripts/validate_blueprints.py
```

---

## 🏗️ System Architecture

### Directory Structure

```
_templates/
├── 📁 blueprints/               # Product archetype definitions
│   ├── mins/                    # MINS blueprint example
│   │   ├── 📄 BLUEPRINT.md      # Human-readable blueprint documentation
│   │   ├── 📄 blueprint.meta.yaml # Machine-readable blueprint metadata
│   │   └── 📁 overlays/         # Stack-specific template extensions
├── 📁 tasks/                    # 47 task templates with universal/stack implementations
│   ├── 📄 task-index.yaml       # Unified task definitions and file mappings
│   └── 📁 [task-name]/          # Individual task directories
├── 📁 scripts/                  # Analysis, building, and blueprint tools
├── 📁 tiers/                    # Tier-specific templates (MVP, Core, Enterprise)
├── 📁 stacks/                   # Technology stack specific templates
└── 📁 reference-projects/       # Generated reference implementations
```

### Key Architectural Principles

1. **Blueprint-Driven Development**: Product archetypes drive stack, tier, and task selection
2. **Task-Based Organization**: All functionality organized around 47 production tasks
3. **Universal + Stack-Specific**: Universal patterns with stack-specific optimizations
4. **Tiered Complexity**: MVP, Core, and Enterprise tiers for different project needs
5. **Automated Analysis**: AI-powered task detection and gap analysis

---

## 📋 Task Categories

The 47 tasks are organized into 9 virtual categories:

| Category | Tasks | Description |
|----------|-------|-------------|
| **Web & API** | 6 | Web scraping, APIs, dashboards |
| **Auth, Users & Billing** | 5 | Authentication, user management, payments |
| **Background Work & Automation** | 5 | Jobs, scheduling, notifications |
| **Data, Analytics & ML** | 7 | Data processing, analytics, machine learning |
| **SEO / Growth / Content** | 6 | SEO optimization, content generation |
| **Product & SaaS** | 5 | SaaS features, product management |
| **DevOps, Reliability & Quality** | 5 | DevOps automation, monitoring |
| **AI-Specific** | 4 | AI/LLM applications, intelligent automation |
| **Meta / Tooling** | 4 | Project scaffolding, documentation, testing |

---

## 🔧 Technology Stacks

| Stack | Language | Use Cases | Support |
|-------|----------|-----------|---------|
| **Python** | Python | APIs, Data Science, ML | ✅ Full |
| **Node.js** | JavaScript | Backend APIs, Microservices | ✅ Full |
| **Go** | Go | High-performance services | ✅ Full |
| **Flutter** | Dart | Cross-platform mobile apps | ✅ Full |
| **React** | JavaScript/JSX | Frontend web applications | ✅ Full |
| **Next.js** | JavaScript/JSX | Full-stack web applications | ✅ Full |
| **TypeScript** | TypeScript | Type-safe backends | ✅ Full |
| **SQL** | SQL | Database schemas, migrations | ✅ Full |
| **R** | R | Data analysis, statistics | ✅ Full |

---

## ✅ Validation & Quality

### Current System Status
- **Total Tasks**: 47 ✅
- **Template Files**: 667 ✅
- **Validation Status**: EXCELLENT (0 issues) ✅
- **All Stacks**: 12 validated ✅
- **Blueprint System**: Operational ✅

### Running Validation

```bash
# Comprehensive validation
python scripts/validate-templates.py --full

# Individual validators
python scripts/validate_stacks.py
python scripts/validate_tasks.py
python scripts/validate_blueprints.py
```

---

## 📚 Related Documentation

- **[QUICKSTART.md](./QUICKSTART.md)** - Quick start guide
- **[SYSTEM-MAP.md](./SYSTEM-MAP.md)** - Complete system architecture
- **[README.md](./README.md)** - Main project documentation
- **[AGENTS.md](./AGENTS.md)** - Multi-agent coordination guide

---

## 🎯 Gemini-Specific Guidelines

When working with this repository:

1. **Use the autonomous workflow** for project generation
2. **Reference task-index.yaml** for available functionality
3. **Check validation scripts** before making changes
4. **Follow the blueprint-driven approach** for new features
5. **Maintain template structure** consistency across stacks

**System Health**: PRODUCTION READY ✅
