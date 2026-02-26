# Complete Archive Index & Feature Reference

**Purpose**: Quick-reference index of everything in `_complete_archive/` — designed to accelerate new skill creation.  
**Archive Date**: 2026-02-01  
**Generated**: 2026-02-06  
**Updated**: 2026-02-07

> **Current master list**: [`SKILLS_MASTER_LIST.md`](SKILLS_MASTER_LIST.md) (766 skills, 60 packs, 14 categories, 0 duplicates)  
> **Pack creation guide**: [`skill-packs/HOW_TO_CREATE_SKILL_PACKS.md`](skill-packs/HOW_TO_CREATE_SKILL_PACKS.md)  
> **Completed pack**: [`skill-packs/1-programming-core/`](skill-packs/1-programming-core/PACK.md) (12 skills, 19 reference files)

---

## Table of Contents

1. [Archive Structure Overview](#1-archive-structure-overview)
2. [Reference Skill Implementations (Gold Standard)](#2-reference-skill-implementations-gold-standard)
3. [Skill Format & Standards](#3-skill-format--standards)
4. [Comprehensive Skills Inventory (1,014 skills)](#4-comprehensive-skills-inventory-1014-skills)
5. [Thematic Packs (20 packs, 1,014 skills)](#5-thematic-packs-20-packs-1014-skills)
6. [Templates System (_templates-main)](#6-templates-system-_templates-main)
7. [Existing Skill Packs (41 packs, ~1,456 skills — CORRUPTED)](#7-existing-skill-packs-41-packs--corrupted)
8. [Supporting Files & Reports](#8-supporting-files--reports)
9. [Archive & Historical Data](#9-archive--historical-data)
10. [Feature Catalog by Domain](#10-feature-catalog-by-domain)
11. [Quick-Reference for Creating New Skills](#11-quick-reference-for-creating-new-skills)

---

## 1. Archive Structure Overview

```
_complete_archive/
├── README.md                          # Archive overview
├── agent-skills-main/                 # ★ GOLD STANDARD: Vercel's reference skills
│   ├── AGENTS.md / CLAUDE.md          # Agent-specific instructions
│   ├── packages/                      # Packaged skill builds
│   └── skills/                        # 5 production-quality skills
├── skill-packs/                       # 41 numbered packs (~1,456 skills) — CORRUPTED names
│   ├── 01–27: Angular (Components, Services, Forms, Routing, Testing, Perf, Advanced, Core)
│   ├── 28–31: React Forms A–D
│   ├── 32–36: Business Intelligence A–E
│   ├── 37–38: Development Tools
│   ├── 39: Debugging
│   └── 40–41: JavaScript +
├── _supporting-files/                 # Planning docs, inventories, databases, reports
│   ├── COMPREHENSIVE_SKILLS_INVENTORY.md   # Full 1,014-skill catalog
│   ├── SKILLS_THEMATIC_PACKS.md            # 20 thematic packs with dependencies
│   ├── UNIVERSAL_SKILL_STANDARDS.md        # Skill format specification
│   ├── SKILLS_TRACKING_CHECKLIST.md        # Progress tracking
│   ├── skills_database.json                # Machine-readable skill DB
│   ├── skills_database_final.json          # Final version of skill DB
│   └── (16 fix/validation/comparison reports)
├── _templates-main/                   # Universal Template System (746 templates)
│   ├── Agent guides: CLAUDE.md, CURSOR.md, COPILOT.md, WINDSURF.md, etc.
│   ├── blueprints/                    # 5 project blueprints
│   ├── features/                      # Feature implementations
│   ├── scripts/                       # Python automation scripts
│   ├── stacks/                        # 12 technology stack templates
│   ├── tasks/                         # 47 production tasks
│   ├── tiers/                         # MVP / Core / Enterprise templates
│   └── workflows/                     # Workflow templates (12 stacks)
├── _archive/                          # Historical reorganization data
│   ├── backups/                       # 6 backup snapshots
│   ├── data/                          # CSVs, JSONs
│   ├── old-structures/                # Previous pack organizations
│   ├── plans/                         # Implementation plans
│   └── reports/                       # Organization reports
├── archive/                           # Master list versions (V3 variants)
│   └── skills-v3/                     # V3 skill implementations
├── agent-skills-main.zip              # ZIP of agent-skills-main
├── _templates-main.zip                # ZIP of _templates-main
└── skill-builder-main.zip             # ZIP of skill-builder tool
```

---

## 2. Reference Skill Implementations (Gold Standard)

**Location**: `_complete_archive/agent-skills-main/skills/`  
**Source**: Vercel Labs (agentskills.io format)

These are the **highest-quality examples** to follow when creating new skills:

| Skill | Description | Files |
|-------|-------------|-------|
| **react-best-practices** | 57 rules across 8 priority categories for React/Next.js perf | SKILL.md, AGENTS.md, metadata.json, rules/ |
| **web-design-guidelines** | 100+ rules for accessibility, performance, UX audit | SKILL.md |
| **react-native-skills** | 16 rules across 7 sections for RN/Expo | SKILL.md, AGENTS.md, metadata.json, rules/ |
| **composition-patterns** | Compound components, state lifting, internal composition | SKILL.md, AGENTS.md, metadata.json, rules/ |
| **vercel-deploy-claimable** | Auto-deploy to Vercel from Claude conversations | SKILL.md, scripts/ |

### Reference Skill Anatomy

```
skills/{skill-name}/
├── SKILL.md           # Required — frontmatter + instructions
├── AGENTS.md          # Optional — full compiled rules for agents
├── README.md          # Optional — human-readable docs
├── metadata.json      # Optional — version, author, references
├── rules/             # Optional — individual rule files
│   ├── {prefix}-{rule-name}.md
│   └── ...
└── scripts/           # Optional — automation helpers
```

### Reference SKILL.md Format (from react-best-practices)

```yaml
---
name: skill-name-here
description: >
  Specific, actionable description of WHEN to use this skill.
  Triggers on tasks involving X, Y, or Z.
license: MIT
metadata:
  author: org-name
  version: "1.0.0"
---
```

Followed by: title, "When to Apply" section, rule categories table, quick reference per category, and "How to Use" instructions.

---

## 3. Skill Format & Standards

**Location**: `_complete_archive/_supporting-files/UNIVERSAL_SKILL_STANDARDS.md`

### Key Specifications

- **Frontmatter**: `name` (1–64 chars, lowercase + hyphens) + `description` (1–1024 chars)
- **Name rules**: No leading/trailing/consecutive hyphens; must match directory name
- **Description**: Specific and actionable — tell the agent *when* to use it
- **Progressive disclosure**: L1 (discovery/metadata) → L2 (full instructions) → L3 (bundled resources)
- **Override priority**: Project mode-specific > Project generic > Global mode-specific > Global generic

### Required Sections in SKILL.md

1. **Frontmatter** (name + description)
2. **Title** (# heading)
3. **When to Apply / Activation Conditions**
4. **Prerequisites**
5. **Implementation Steps**
6. **Code Templates**
7. **Common Issues**
8. **Integration** (related skills)
9. **Resources**

### Directory Locations

```
~/.agent/skills/              # Global skills
{project}/.agent/skills/      # Project skills (override global)
~/.agent/skills-{mode}/       # Mode-specific skills
```

---

## 4. Comprehensive Skills Inventory (1,014 skills)

**Location**: `_complete_archive/_supporting-files/COMPREHENSIVE_SKILLS_INVENTORY.md`

### Category Summary

| Category Group | Categories | Total Skills |
|----------------|-----------|-------------|
| **Core Development Phases** | Foundation, Essentials, Operations, Advanced, Specialized | 125 |
| **Technology-Specific** | Framework (25), Platform (20), Emerging (22) | 67 |
| **AI & ML** | AI/ML & Agentic Systems | 18 |
| **Security & Ops** | Security (20), SRE (15), DevSecOps (12) | 47 |
| **Dev Specializations** | Mobile (15), Data Eng (18), Testing (18), Architecture (15), Frontend (15), Backend (15) | 96 |
| **Developer Tools** | DevEx (12), Code Quality (10), Docs (10), PM (10) | 42 |
| **Infrastructure** | Cloud (15), API (12), Database (15), Network (12), Perf (12), Integration (10) | 76 |
| **Business Domains** | E-commerce (12), Comms (10), SEO (8), Users (8), Content (10), Reporting (10), Fintech (10), Healthcare (8), Gaming (10) | 86 |
| **Education** | E-Learning | 10 |
| **Emerging Domains** | IoT (10), Blockchain (12), AR/VR (8), Robotics (10) | 40 |
| **Future Tech** | Sustainability (8), Quantum (6) | 14 |
| **Other** | Localization (8), Compliance (10), Low-Code (8) | 26 |
| **Archive-Sourced** | Tasks (50), Agents (5), Blueprints (4), Workflows (3), Stacks (14), Tiers (3), Utilities (3) | 82 |

### Core Development Phases (detailed)

**Phase 1 — Foundation (15)**: project-setup, environment-setup, package-management, git-workflow, cli-tools, code-structure, debugging, error-handling, logging, configuration, testing-fundamentals, documentation-fundamentals, code-quality, performance-basics, security-fundamentals

**Phase 2 — Development Essentials (25)**: api-development, database-development, authentication, session-management, file-handling, validation, service-layer, component-development, feature-development, state-management, routing, form-handling, ui-components, data-structures, algorithms, design-patterns, ci-cd-pipeline, security-hardening, + 7 more

**Phase 3 — Operations & Deployment (20)**: containerization, infrastructure-as-code, monitoring-logging, load-balancing, auto-scaling, disaster-recovery, orchestration, serverless, cloud-services, compliance, + 10 more

**Phase 4 — Advanced Features (35)**: real-time-communication, search-engine, content-management, payment-processing, messaging, file-storage, internationalization, push-notifications, machine-learning, graphql, microservices, event-driven, caching, rate-limiting, data-warehouse, recommendation-system, workflow-engine, multi-tenancy, offline-support, progressive-web-app, analytics, + 14 more

**Phase 5 — Specialized & Meta (30)**: code-generation, testing-automation, documentation-generation, api-design, system-design, architecture-patterns, code-review, refactoring, legacy-migration, ai-integration, automation, business-intelligence, feature-flags, observability, + 16 more

---

## 5. Thematic Packs (20 packs, 1,014 skills)

**Location**: `_complete_archive/_supporting-files/SKILLS_THEMATIC_PACKS.md`

| # | Pack Name | Skills | Dependencies | Est. Time |
|---|-----------|--------|--------------|-----------|
| 1 | **Project Foundation** | 15 | None | 2 weeks |
| 2 | **Development Core** | 25 | Pack 1 | 3 weeks |
| 3 | **Operations & Deployment** | 20 | Pack 1, 2 | 3 weeks |
| 4 | **Cloud & DevOps** | 15 | Pack 3 | 2 weeks |
| 5 | **Data Engineering** | 18 | Pack 1, 2 | 3 weeks |
| 6 | **Analytics & Business Intelligence** | 15 | Pack 5 | 2 weeks |
| 7 | **Frontend Foundation** | 15 | Pack 1, 2 | 3 weeks |
| 8 | **Full Stack Web** | 15 | Pack 7 | 3 weeks |
| 9 | **Mobile Foundation** | 15 | Pack 1, 2 | 3 weeks |
| 10 | **AI & Machine Learning** | 18 | Pack 5 | 4 weeks |
| 11 | **Security** | 20 | Pack 3 | 3 weeks |
| 12 | **Testing & Quality** | 18 | Pack 2 | 3 weeks |
| 13 | **Emerging Technologies** | 22 | Pack 4, 10 | 4 weeks |
| 14 | **Architecture & Design** | 15 | Pack 2, 4 | 3 weeks |
| 15 | **E-commerce & Business** | 15 | Pack 8, 6 | 3 weeks |
| 16 | **Content & Media** | 15 | Pack 8, 5 | 3 weeks |
| 17 | **API & Integration** | 15 | Pack 2, 3 | 3 weeks |
| 18 | **Workflow Automation** | 15 | Pack 17 | 3 weeks |
| 19 | **Developer Tools** | 15 | Pack 1 | 2 weeks |
| 20 | **Utilities & Helpers** | 15 | Pack 2 | 2 weeks |

### Specialized Domain Skills (not in numbered packs)

| Domain | Skills |
|--------|--------|
| **React Ecosystem** | react-hooks, react-router, redux-toolkit, zustand, tanstack-query, swr, mobx (8) |
| **Vue Ecosystem** | vue-composition, vue-router, pinia, nuxt-pages, nuxt-server-middleware, svelte-stores (6) |
| **Other Frameworks** | angular-services, nextjs-app-router, remix-routes, astro-components, sveltekit-endpoints, solid-js, qwik, recoil (10) |
| **Cloud Platforms** | aws-lambda, aws-s3, azure-functions, gcp-cloud-functions, vercel-deploy, + 6 more (11) |
| **DevOps Tools** | kubernetes, docker, terraform, ansible, helm, prometheus, grafana, jenkins (9) |
| **Gaming & Real-Time** | game-engine, physics-simulation, multiplayer, matchmaking, leaderboards (15) |
| **Fintech & Banking** | payment-gateway, fraud-detection, digital-wallet, trading-platform, AML (15) |
| **Healthcare** | EMR-integration, telemedicine, medical-imaging, HIPAA, clinical-workflows (15) |
| **Education** | LMS, virtual-classroom, assessment-engine, adaptive-learning, certification (15) |
| **IoT & Embedded** | device-management, MQTT, edge-computing, firmware-updates, mesh-networks (15) |
| **Blockchain & Web3** | smart-contracts, DApps, DeFi, NFTs, DAOs, crypto-wallets (15) |
| **AR/VR & Metaverse** | AR/VR dev, 3D modeling, spatial-computing, WebXR, avatars (15) |
| **Robotics** | robot-control, path-planning, sensor-fusion, swarm-robotics, autonomous-vehicles (15) |
| **Sustainability** | energy-monitoring, carbon-tracking, green-computing, smart-grid (15) |
| **Quantum** | quantum-algorithms, quantum-crypto, quantum-ML, quantum-programming (15) |

### Implementation Phases

| Phase | Packs | Duration | Skills |
|-------|-------|----------|--------|
| 1: Foundation | 1–2 | 5 weeks | 40 |
| 2: Infrastructure | 3–4 | 5 weeks | 35 |
| 3: Data | 5–6 | 5 weeks | 33 |
| 4: Web & Mobile | 7–9 | 9 weeks | 45 |
| 5: AI & Security | 10–12 | 10 weeks | 53 |
| 6: Advanced | 13–14 | 7 weeks | 37 |
| 7: Domain | 15–16 | 6 weeks | 30 |
| 8: Integration | 17–18 | 6 weeks | 30 |
| 9: Tools | 19–20 | 4 weeks | 30 |
| 10: Specialization | Domain packs | 45 weeks | 450+ |

### Pack Dependency Chain

```
Foundation(1) → Development Core(2) → Operations(3) → Cloud/DevOps(4)
                                    → Frontend(7) → Full Stack(8) → E-commerce(15)
                                    → Data Eng(5) → Analytics(6)
                                                  → AI/ML(10) → Emerging(13)
                                    → Testing(12)
                                    → Architecture(14)
                                    → API/Integration(17) → Workflow(18)
               → Mobile(9)
               → Dev Tools(19)
               → Utilities(20)
               → Security(11)
```

---

## 6. Templates System (_templates-main)

**Location**: `_complete_archive/_templates-main/`

### Architecture

- **Hybrid system**: Task-Based (functionality) + Tier-Based (complexity) + Stack-Based (technology)
- **47 production tasks** across 9 development categories
- **746 validated templates** total
- **12 technology stacks**: Python, Node, TypeScript, Go, Flutter, React, React Native, Next.js, SQL, R, Generic, Agnostic
- **3 tiers**: MVP (rapid dev), Core (production), Enterprise (scale)

### 9 Task Categories (47 tasks)

| Category | Tasks |
|----------|-------|
| **Web & API** | web-scraping, rest-api-service, graphql-api, web-dashboard, landing-page, public-api-gateway |
| **Auth, Users & Billing** | auth-basic, auth-oauth, user-profile-management, billing-stripe, team-workspaces |
| **Background Work** | job-queue, scheduled-tasks, notification-center, webhook-consumer, file-processing-pipeline |
| **Data, Analytics & ML** | etl-pipeline, analytics-event-pipeline, data-exploration-report, forecasting-engine, segmentation-clustering, ab-test-analysis, embedding-index |
| **SEO / Growth / Content** | seo-keyword-research, seo-onpage-auditor, seo-rank-tracker, content-brief-generator, email-campaign-engine, link-monitoring |
| **Product & SaaS** | crud-module, admin-panel, feature-flags, multitenancy, audit-logging |
| **DevOps & Reliability** | healthchecks-telemetry, ci-template, error-reporting, config-management, canary-release |
| **AI-Specific** | llm-prompt-router, rag-pipeline, agentic-workflow, code-refactor-agent |
| **Meta / Tooling** | project-bootstrap, docs-site, sample-data-generator |

### 5 Project Blueprints

| Blueprint | Purpose |
|-----------|---------|
| **default-project** | Generic project scaffolding |
| **data-pipeline** | Data processing project |
| **saas-api** | SaaS backend API |
| **web-dashboard** | Admin/analytics dashboard |
| **mins** | Minimal project |

### Agent-Specific Guides

Files for: CLAUDE.md, CURSOR.md, COPILOT.md, WINDSURF.md, GEMINI.md, AIDER.md, CODEX.md, CODY.md, WARP.md

### Automation Scripts

- `analyze_and_build.py` — Analyze description → detect tasks → build project
- `validate-templates.py` — Full template validation suite
- `detect_project_tasks.py` — NLP-based task detection
- `list_tasks_by_category.py` — Browse/search tasks

### Workflow Templates

Per-stack workflow orchestrators and tests for all 12 stacks in: `workflows/stacks/{flutter,go,nextjs,node,python,r,react,react_native,rust,sql,typescript}/`

---

## 7. Existing Skill Packs (41 packs — CORRUPTED)

**Location**: `_complete_archive/skill-packs/`  
**Status**: ⚠️ Directory names corrupted by scripting bug (`args-0-Value-ToUpper-` prefix pattern)

| Range | Theme |
|-------|-------|
| 01–27 | Angular (Components, Services, Forms, Routing, Testing, Performance, Advanced, Core ×20) |
| 28–31 | React Forms A–D |
| 32–36 | Business Intelligence A–E |
| 37–38 | Development Tools |
| 39 | Debugging |
| 40 | JavaScript |
| 41+ | (at least 1 more) |

**Skill format inside packs**: Each skill is a directory with a `SKILL.md` file containing frontmatter + basic template content. Quality is **low** — generic placeholder implementations, duplicated frontmatter blocks, no specific code or detailed rules.

**Recommendation**: Use the thematic packs plan (Section 5) and the reference implementations (Section 2) to recreate skills from scratch rather than reusing these.

---

## 8. Supporting Files & Reports

**Location**: `_complete_archive/_supporting-files/`

### Key Reference Files

| File | Description |
|------|-------------|
| `COMPREHENSIVE_SKILLS_INVENTORY.md` | Full 1,014-skill catalog with categories, implementations, gaps |
| `SKILLS_THEMATIC_PACKS.md` | 20 thematic packs with skills, dependencies, implementation phases |
| `UNIVERSAL_SKILL_STANDARDS.md` | Complete skill format specification (agentskills.io based) |
| `SKILLS_TRACKING_CHECKLIST.md` | Progress tracking for skill implementation |
| `skills_database.json` | Machine-readable skill database |
| `skills_database_final.json` | Final version of skill database |

### QA & Validation Reports

| File | Content |
|------|---------|
| `comprehensive_fix_report.md` | Comprehensive fix results |
| `corrupted_frontmatter_fix_report.md` | Frontmatter corruption fixes |
| `duplicate_skills_report.md` | Duplicate skill analysis |
| `duplicates_final_resolution_report.md` | Final duplicate resolution |
| `final_validation_report.md` | Final validation results |
| `missing_skills_creation_report.md` | Missing skill creation results |
| `pack_analysis_report.md` | Pack organization analysis |
| `pack_optimization_report.md` | Pack optimization results |
| `quality_improvement_report.md` | Quality improvement results |
| `skills_quality_report.md` | Overall quality assessment |

---

## 9. Archive & Historical Data

### _archive/ (reorganization history)

| Path | Content |
|------|---------|
| `backups/` | 6 backup snapshots from reorganization efforts |
| `data/` | `skills_database.csv`, `skills_comparison.csv`, `duplicate_resolutions.json` |
| `old-structures/` | Previous pack organizations (10-per-pack, split, renumbered, etc.) |
| `plans/` | Implementation plans |
| `reports/` | `ARCHIVE_MAP.md`, `DOCUMENTATION_INDEX.md`, organization reports |

### archive/ (master list versions)

| File | Content |
|------|---------|
| `ALL_SKILLS_MASTER_LIST_V3_REDESIGNED.md` | V3 redesigned master list |
| `ALL_SKILLS_MASTER_LIST_V3_VARIABLE.md` | V3 variable version |
| `ALL_SKILLS_MASTER_LIST_V3_VARIABLE_EXTENDED.md` | V3 extended version |
| `skill-packs-redesign-dd441b.md` | Pack redesign notes |
| `skills-v3/` | V3 skill implementations |

---

## 10. Feature Catalog by Domain

### A. Core Software Engineering

| Feature Area | Skills Available | Key Skills |
|-------------|-----------------|------------|
| **Project Setup** | 15 | project-setup, environment-setup, package-management, git-workflow |
| **Code Quality** | 10 | code-review, linting, formatting, static-analysis, coverage, refactoring |
| **Testing** | 18 | unit, integration, e2e, performance, load, security, visual, contract, mutation |
| **Architecture** | 15 | DDD, clean-arch, hexagonal, CQRS, saga, modular-monolith, vertical-slice |
| **Design Patterns** | 15+ | SOLID, dependency-injection, repository-pattern, event-driven, middleware |
| **Documentation** | 10 | API docs, code docs, architecture docs, tutorials, runbooks, changelogs |
| **DevEx** | 12 | CLI dev, developer-portal, SDK, onboarding, scaffolding, monorepo, versioning |

### B. Web Development

| Feature Area | Skills Available | Key Skills |
|-------------|-----------------|------------|
| **Frontend** | 15 | responsive-design, CSS architecture, animations, accessibility, web-components |
| **React** | 8+ | hooks, router, Redux, Zustand, TanStack Query, SWR, MobX |
| **Vue** | 6 | composition-api, router, Pinia, Nuxt |
| **Full Stack** | 15 | REST APIs, GraphQL, real-time, auth flows, file uploads, payments, search, CMS |
| **Performance** | 12 | bundling, lazy-loading, code-splitting, service-workers, image-optimization |
| **SEO** | 8 | keyword-research, on-page audit, rank-tracking, content-strategy |

### C. Backend & Infrastructure

| Feature Area | Skills Available | Key Skills |
|-------------|-----------------|------------|
| **Backend** | 15 | async, concurrency, message-queues, background-jobs, middleware, DI |
| **API** | 12 | REST design, GraphQL schema, gRPC, OpenAPI, versioning, rate-limiting |
| **Database** | 15 | SQL optimization, NoSQL, indexing, normalization, migration, replication |
| **Cloud** | 15 | cloud-architecture, multi-cloud, migration, cost, networking, compliance |
| **DevOps** | 20 | containers, K8s, CI/CD, IaC, monitoring, alerting, scaling, incident-response |
| **Networking** | 12 | TCP/IP, DNS, SSL, VPN, firewalls, reverse-proxy, CDN, DDoS |

### D. Data & AI

| Feature Area | Skills Available | Key Skills |
|-------------|-----------------|------------|
| **Data Engineering** | 18 | ETL, streaming, batch, partitioning, governance, lineage, dbt, Spark, Airflow |
| **Analytics** | 15 | data-analysis, visualization, dashboards, BI, KPI-tracking, forecasting |
| **AI/ML** | 18 | model-training, deployment, TensorFlow, PyTorch, NLP, computer-vision, deep-learning |
| **Agentic AI** | 18 | RAG, multi-agent, embeddings, semantic-search, LangChain, LLM eval, guardrails |
| **MLOps** | 5+ | MLflow, feature-stores, model-versioning, model-monitoring |

### E. Security

| Feature Area | Skills Available | Key Skills |
|-------------|-----------------|------------|
| **AppSec** | 20 | threat-modeling, secure-coding, OWASP, encryption, identity, access-control |
| **DevSecOps** | 12 | shift-left, container-scanning, secrets-detection, policy-as-code |
| **Compliance** | 10 | GDPR, HIPAA, SOC2, PCI-DSS, audit-trails, consent-management |

### F. Mobile

| Feature Area | Skills Available | Key Skills |
|-------------|-----------------|------------|
| **Cross-Platform** | 15 | React Native, Flutter, Ionic, navigation, offline, push, deep-linking |
| **Platform** | 4 | iOS/Swift, Android/Kotlin, app-store-deployment |

### G. Industry Verticals

| Domain | Skills | Examples |
|--------|--------|----------|
| **E-commerce** | 15 | product-catalog, cart, checkout, payments, inventory, shipping, tax |
| **Fintech** | 15 | payment-gateway, fraud-detection, digital-wallet, trading, AML, credit-scoring |
| **Healthcare** | 15 | EMR, telemedicine, medical-imaging, HIPAA, clinical-workflows, genomics |
| **Education** | 15 | LMS, virtual-classroom, assessment, adaptive-learning, certification |
| **Gaming** | 15 | game-engine, physics, multiplayer, matchmaking, leaderboards, monetization |

### H. Emerging Tech

| Domain | Skills | Examples |
|--------|--------|----------|
| **IoT** | 15 | device-management, MQTT, edge-computing, firmware, mesh-networks |
| **Blockchain** | 15 | smart-contracts, DApps, DeFi, NFTs, DAOs, cross-chain |
| **AR/VR** | 15 | AR/VR dev, 3D modeling, spatial-computing, WebXR, haptics |
| **Robotics** | 15 | robot-control, path-planning, sensor-fusion, swarm, autonomous-vehicles |
| **Quantum** | 15 | quantum-algorithms, quantum-crypto, quantum-ML, quantum-programming |
| **Sustainability** | 15 | energy-monitoring, carbon-tracking, green-computing, smart-grid |

---

## 11. Quick-Reference for Creating New Skills

### Step-by-Step Skill Creation Checklist

1. **Choose skill name** — lowercase, hyphens only, 1–64 chars (e.g., `api-rate-limiting`)
2. **Write description** — specific, actionable, 1–1024 chars
3. **Create directory**: `{skill-name}/SKILL.md`
4. **Write frontmatter**:
   ```yaml
   ---
   name: {skill-name}
   description: {When to use this skill — be specific}
   ---
   ```
5. **Write content** following the required sections (see Section 3)
6. **Optionally add**: `rules/`, `scripts/`, `templates/`, `resources/`, `metadata.json`

### Quality Checklist (from reference skills)

- [ ] Description tells agent exactly WHEN to activate
- [ ] Rules/guidelines organized by priority (CRITICAL → LOW)
- [ ] Each rule has a unique prefix-based ID (e.g., `async-parallel`)
- [ ] Code examples show incorrect vs. correct patterns
- [ ] Categories organized in a quick-reference table
- [ ] Related skills documented for integration

### Where to Find Source Material

| Need | Look Here |
|------|-----------|
| **Current skills master list** | [`SKILLS_MASTER_LIST.md`](../SKILLS_MASTER_LIST.md) (766 unique skills, 60 packs, 14 categories) |
| **Pack creation guide** | [`skill-packs/HOW_TO_CREATE_SKILL_PACKS.md`](../skill-packs/HOW_TO_CREATE_SKILL_PACKS.md) |
| **Task template** | [`skill-packs/TASKS-TEMPLATE.md`](../skill-packs/TASKS-TEMPLATE.md) |
| **Reference implementation** | [`skill-packs/1-programming-core/`](../skill-packs/1-programming-core/PACK.md) |
| **Skill name + description ideas** | `_supporting-files/COMPREHENSIVE_SKILLS_INVENTORY.md` |
| **Pack grouping + dependencies** | `_supporting-files/SKILLS_THEMATIC_PACKS.md` |
| **Format specification** | `_supporting-files/UNIVERSAL_SKILL_STANDARDS.md` |
| **High-quality SKILL.md examples** | `agent-skills-main/skills/react-best-practices/SKILL.md` |
| **Rule file examples** | `agent-skills-main/skills/react-best-practices/rules/` |
| **metadata.json example** | `agent-skills-main/skills/react-best-practices/metadata.json` |
| **Task templates (code)** | `_templates-main/tasks/{task-name}/` |
| **Stack-specific patterns** | `_templates-main/stacks/{stack}/` |
| **Blueprint examples** | `_templates-main/blueprints/{blueprint}/` |
| **Machine-readable DB** | `_supporting-files/skills_database_final.json` |

### Key Principles (from UNIVERSAL_SKILL_STANDARDS)

1. **General first** — create the general skill before framework-specific ones
2. **Composition** — skills should compose with other skills
3. **Extensibility** — skills should be extensible for new frameworks/platforms
4. **Consistency** — use consistent patterns across all skills
5. **Documentation** — each skill should document its relationships

---

*This index references materials archived on 2026-02-01. All archive paths are relative to `_complete_archive/`.*  
*Current operational files: [`SKILLS_MASTER_LIST.md`](SKILLS_MASTER_LIST.md), [`skill-packs/`](skill-packs/)*
