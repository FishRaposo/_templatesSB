# TIER-MAPPING.md - Template Mapping by Tier

**Purpose**: Shows which templates belong to each tier and how they map from the universal collection to project-specific files.  
**Version**: 1.0  
**Last Updated**: 2025-12-09  
**Source**: Generated from `tier-index.yaml` (machine-readable source of truth)  

---

## 🎯 Tier Overview Matrix

| File | MVP | CORE | FULL | Description |
|------|-----|------|------|-------------|
| **README.md** | ✅ Required | ✅ Required | ✅ Required | Project purpose, features, stack, quickstart |
| **ARCHITECTURE.md** | ✅ Required | ✅ Required | ✅ Required | High-level architecture, folder structure, data flow |
| **TODO.md** | ✅ Required | ✅ Required | ✅ Required | Action items and phase progress |
| **WORKFLOWS.md** | ✅ Required | ✅ Required | ✅ Required | Developer and AI workflows, commands, automation |
| **TESTING.md** | ✅ Required | ✅ Required | ✅ Required | Testing plan (varying detail by tier) |
| **.gitignore** | ✅ Required | ✅ Required | ✅ Required | Ignored files per tech stack |
| **API-DESIGN.md** | ✅ Recommended | ❌ Not included | ❌ Not included | Brief endpoint list for API projects |
| **UI-FLOW.md** | ✅ Recommended | ❌ Not included | ❌ Not included | Screen list and user flow diagram |
| **TESTING-EXAMPLES.md** | ❌ Not included | ✅ Required | ✅ Required | Tech-specific examples for testing strategy |
| **DOCUMENTATION-BLUEPRINT.md** | ❌ Not included | ✅ Required | ✅ Required | Template for generating documentation OS |
| **API-DOCUMENTATION.md** | ❌ Not included | ✅ Required | ✅ Required | Endpoints, schemas, request/response patterns |
| **FRAMEWORK-PATTERNS.md** | ❌ Not included | ✅ Required | ✅ Required | Tech-specific architecture patterns and conventions |
| **PROJECT-ROADMAP.md** | ❌ Not included | ✅ Required | ✅ Required | Phases, milestones, features, timeline |
| **universal/INTEGRATION-GUIDE.md** | ❌ Not included | ✅ Required | ✅ Required | How to integrate templates into projects |
| **AGENTS.md** | ❌ Not included | ✅ Required | ✅ Required | Agents' roles, workflows, responsibilities |
| **QUICKSTART-AI.md** | ❌ Not included | ✅ Required | ✅ Required | AI-specific bootstrapping and onboarding |
| **MIGRATION-GUIDE.md** | ❌ Not included | ✅ Required | ✅ Required | How to migrate major changes safely |
| **TESTING-STRATEGY.md** | ❌ Not included | ❌ Not included | ✅ Required | Universal multi-layer testing doctrine |
| **DEPLOYMENT.md** | ❌ Not included | ❌ Not included | ✅ Required | Build, ship, release, and environment strategy |
| **SECURITY.md** | ❌ Not included | ❌ Not included | ✅ Required | Threat model, authentication, permissions |
| **DATA-MODEL.md** | ❌ Not included | ❌ Not included | ✅ Required | Schemas, relationships, invariants |
| **ANALYTICS.md** | ❌ Not included | ✅ Recommended | ✅ Required | Tracking, events, KPIs |
| **CONFIGURATION.md** | ❌ Not included | ✅ Recommended | ✅ Required | Environment variables, secrets handling |
| **LOCAL-DEV.md** | ❌ Not included | ✅ Recommended | ✅ Required | Developer onboarding and environment setup |
| **CI-CD.md** | ❌ Not included | ❌ Not included | ✅ Required | Automation pipelines, code quality, gating |

---

## 🚀 MVP TIER - Template Mapping

### Required Files (6)

| Source Template | Target File | Purpose | MVP Variation |
|-----------------|-------------|---------|---------------|
| `universal/README.md` | `./README.md` | Project overview | Brief - problem, features, quick run (3-5 commands) |
| (Create new) | `./ARCHITECTURE.md` | System design | Minimal - 1-2 pages: stack, folders, basic flow |
| `examples/PROJECT-ROADMAP.md` | `./TODO.md` | Task tracking | Simple checklist - 3-5 core features |
| (Create new) | `./WORKFLOWS.md` | Process documentation | Brief - build, run, test commands |
| `universal/TESTING-STRATEGY.md` | `./TESTING.md` | Testing strategy | Basic - what will be tested later, smoke tests |
| `examples/GITIGNORE-EXAMPLES.md` | `./.gitignore` | Version control | Tech-specific minimal version |

### Recommended Files (2)

| Source Template | Target File | Purpose | When to Include |
|-----------------|-------------|---------|-----------------|
| `examples/API-DOCUMENTATION.md` | `./API-DESIGN.md` | API overview | If it's a backend/API project |
| (Create new) | `./UI-FLOW.md` | UI/UX overview | If it's a mobile/web app |

**Total Files**: 4-7 files  
**Setup Time**: 15-30 minutes  
**Coverage Target**: 0-20% (smoke tests only)

---

## 🏗️ CORE TIER - Template Mapping

### Required Files (17)

| Source Template | Target File | Purpose | CORE Variation |
|-----------------|-------------|---------|----------------|
| `universal/README.md` | `./README.md` | Project overview | Standard - full overview with architecture summary |
| (Create new) | `./ARCHITECTURE.md` | System design | Standard - detailed architecture with patterns |
| `examples/PROJECT-ROADMAP.md` | `./TODO.md` | Task tracking | Structured - phase-based with milestones |
| (Create new) | `./WORKFLOWS.md` | Process documentation | Standard - development and deployment workflows |
| `universal/TESTING-STRATEGY.md` | `./TESTING.md` | Testing strategy | Full - all layers defined, 85%+ coverage requirements |
| `examples/GITIGNORE-EXAMPLES.md` | `./.gitignore` | Version control | Comprehensive tech-specific version |
| `examples/TESTING-EXAMPLES.md` | `./TESTING-EXAMPLES.md` | Test examples | Tech-specific patterns for implemented stack |
| `universal/DOCUMENTATION-BLUEPRINT.md` | `./DOCUMENTATION-BLUEPRINT.md` | Documentation structure | Project-specific version (5-10 key files) |
| `examples/API-DOCUMENTATION.md` | `./API-DOCUMENTATION.md` | API documentation | Complete endpoints, schemas, error handling |
| `examples/FRAMEWORK-PATTERNS.md` | `./FRAMEWORK-PATTERNS.md` | Architecture patterns | Tech-specific architecture rules |
| `examples/PROJECT-ROADMAP.md` | `./PROJECT-ROADMAP.md` | Project planning | Phase 1+2 with milestones |
| `universal/INTEGRATION-GUIDE.md` | `./INTEGRATION-GUIDE.md` | Template usage | Standard integration guide |
| `universal/AGENTS.md` | `./AGENTS.md` | AI configuration | Final version with project specifics |
| `QUICKSTART-AI.md` | `./QUICKSTART-AI.md` | AI setup | Customized to project |
| `examples/MIGRATION-GUIDE.md` | `./MIGRATION-GUIDE.md` | Migration procedures | Basic structure (even if empty) |

### Recommended Files (3)

| Source Template | Target File | Purpose | When to Include |
|-----------------|-------------|---------|-----------------|
| `examples/PROJECT-ROADMAP.md` | `./ANALYTICS.md` | Analytics strategy | For projects needing tracking |
| `examples/PROJECT-ROADMAP.md` | `./CONFIGURATION.md` | Configuration | Multi-environment setup needed |
| `examples/PROJECT-ROADMAP.md` | `./LOCAL-DEV.md` | Developer setup | Team onboarding required |

**Total Files**: 15-25 files  
**Setup Time**: 2-4 hours  
**Coverage Target**: 85%+ overall (90%+ unit, 80%+ component, 70%+ integration)

---

## 🏢 FULL TIER - Template Mapping

### Required Files (24)

| Source Template | Target File | Purpose | FULL Variation |
|-----------------|-------------|---------|----------------|
| `universal/README.md` | `./README.md` | Project overview | Comprehensive - complete project documentation |
| (Create new) | `./ARCHITECTURE.md` | System design | In-depth - complete system design with ADRs |
| `examples/PROJECT-ROADMAP.md` | `./TODO.md` | Task tracking | Comprehensive - multi-phase with dependencies |
| (Create new) | `./WORKFLOWS.md` | Process documentation | Complete - all workflows including governance |
| `universal/TESTING-STRATEGY.md` | `./TESTING.md` | Testing strategy | Comprehensive - complete testing doctrine |
| `examples/GITIGNORE-EXAMPLES.md` | `./.gitignore` | Version control | Enterprise gitignore with security exclusions |
| `examples/TESTING-EXAMPLES.md` | `./TESTING-EXAMPLES.md` | Test examples | Complete examples for all supported stacks |
| `universal/DOCUMENTATION-BLUEPRINT.md` | `./DOCUMENTATION-BLUEPRINT.md` | Documentation structure | Complete blueprint (all 20 files) |
| `examples/API-DOCUMENTATION.md` | `./API-DOCUMENTATION.md` | API documentation | Comprehensive - auth, rate limiting, examples |
| `examples/FRAMEWORK-PATTERNS.md` | `./FRAMEWORK-PATTERNS.md` | Architecture patterns | Complete patterns with decision records |
| `examples/PROJECT-ROADMAP.md` | `./PROJECT-ROADMAP.md` | Project planning | Phase 1-4 with dependencies |
| `universal/INTEGRATION-GUIDE.md` | `./INTEGRATION-GUIDE.md` | Template usage | Complete guide with advanced workflows |
| `universal/AGENTS.md` | `./AGENTS.md` | AI configuration | Comprehensive with multi-agent support |
| `QUICKSTART-AI.md` | `./QUICKSTART-AI.md` | AI setup | Complete with enterprise features |
| `examples/MIGRATION-GUIDE.md` | `./MIGRATION-GUIDE.md` | Migration procedures | Complete with real examples and scripts |
| `universal/TESTING-STRATEGY.md` | `./TESTING-STRATEGY.md` | Testing doctrine | In-depth - all 7 test layers with examples |
| `examples/PROJECT-ROADMAP.md` | `./DEPLOYMENT.md` | Deployment strategy | Complete deployment strategy |
| `examples/PROJECT-ROADMAP.md` | `./SECURITY.md` | Security documentation | Comprehensive security documentation |
| `examples/PROJECT-ROADMAP.md` | `./DATA-MODEL.md` | Data architecture | Complete data model documentation |
| `examples/PROJECT-ROADMAP.md` | `./ANALYTICS.md` | Analytics strategy | Complete analytics implementation |
| `examples/PROJECT-ROADMAP.md` | `./CONFIGURATION.md` | Configuration management | Complete configuration management |
| `examples/PROJECT-ROADMAP.md` | `./LOCAL-DEV.md` | Developer setup | Comprehensive developer setup |
| `examples/PROJECT-ROADMAP.md` | `./CI-CD.md` | CI/CD pipeline | Complete CI/CD pipeline |

**Total Files**: 30-50 files  
**Setup Time**: 1-2 days  
**Coverage Target**: 95%+ overall (90%+ unit, 85%+ integration, 80%+ E2E)

---

## 📋 Template Source Mapping

### Universal Templates (`universal/`)

| Template | Used In MVP | Used In CORE | Used In FULL | Target Variations |
|----------|-------------|--------------|--------------|-------------------|
| `README.md` | ✅ | ✅ | ✅ | MVP→brief, CORE→standard, FULL→comprehensive |
| `TESTING-STRATEGY.md` | ✅ (as TESTING.md) | ✅ (as TESTING.md) | ✅ (both TESTING.md + TESTING-STRATEGY.md) | MVP→basic, CORE→full, FULL→comprehensive |
| `DOCUMENTATION-BLUEPRINT.md` | ❌ | ✅ | ✅ | CORE→project-specific, FULL→complete |
| `universal/INTEGRATION-GUIDE.md` | ❌ | ✅ | ✅ | CORE→standard, FULL→complete |
| `AGENTS.md` | ❌ | ✅ | ✅ | CORE→project-specific, FULL→comprehensive |
| `QUICKSTART-AI.md` | ❌ | ✅ | ✅ | CORE→customized, FULL→enterprise |
| `WORKFLOWS.md` | ❌ (create new) | ❌ (create new) | ✅ | MVP→brief, CORE→standard, FULL→complete |

### Example Templates (`examples/`)

| Template | Used In MVP | Used In CORE | Used In FULL | Target Variations |
|----------|-------------|--------------|--------------|-------------------|
| `PROJECT-ROADMAP.md` | ✅ (as TODO.md) | ✅ (TODO.md + PROJECT-ROADMAP.md) | ✅ (TODO.md + PROJECT-ROADMAP.md) | MVP→checklist, CORE→phases 1-2, FULL→phases 1-4 |
| `TESTING-EXAMPLES.md` | ❌ | ✅ | ✅ | CORE→tech-specific, FULL→complete |
| `API-DOCUMENTATION.md` | ✅ (as API-DESIGN.md) | ✅ | ✅ | MVP→brief, CORE→complete, FULL→comprehensive |
| `FRAMEWORK-PATTERNS.md` | ❌ | ✅ | ✅ | CORE→tech-specific, FULL→complete with ADRs |
| `GITIGNORE-EXAMPLES.md` | ✅ | ✅ | ✅ | MVP→minimal, CORE→comprehensive, FULL→enterprise |
| `MIGRATION-GUIDE.md` | ❌ | ✅ | ✅ | CORE→basic structure, FULL→complete with scripts |

### Generated Files (No Template)

| File | Created In MVP | Created In CORE | Created In FULL | Purpose |
|------|----------------|-----------------|-----------------|---------|
| `ARCHITECTURE.md` | ✅ | ✅ | ✅ | System architecture (tier-specific complexity) |
| `TODO.md` | ✅ | ✅ | ✅ | Task tracking (from PROJECT-ROADMAP.md template) |
| `WORKFLOWS.md` | ✅ | ✅ | ✅ | Process documentation (tier-specific detail) |
| `API-DESIGN.md` | ✅ (optional) | ❌ | ❌ | Simple API overview for MVP |
| `UI-FLOW.md` | ✅ (optional) | ❌ | ❌ | UI/UX flow for MVP mobile/web |
| `DEPLOYMENT.md` | ❌ | ❌ | ✅ | Deployment strategy (enterprise) |
| `SECURITY.md` | ❌ | ❌ | ✅ | Security documentation (enterprise) |
| `DATA-MODEL.md` | ❌ | ❌ | ✅ | Data model documentation (enterprise) |
| `ANALYTICS.md` | ❌ | ✅ (optional) | ✅ | Analytics strategy |
| `CONFIGURATION.md` | ❌ | ✅ (optional) | ✅ | Configuration management |
| `LOCAL-DEV.md` | ❌ | ✅ (optional) | ✅ | Developer onboarding |
| `CI-CD.md` | ❌ | ❌ | ✅ | CI/CD pipeline (enterprise) |

---

## 🤖 AI Agent Usage Instructions

### Tier Selection Process

1. **Analyze Project Context**
   - Team size, timeline, complexity, production requirements
   - Use decision framework from docs/TIER-GUIDE.md

2. **Select Appropriate Tier**
   - Default to CORE for most real projects
   - Use MVP for experiments and prototypes
   - Use FULL for enterprise and long-term projects

3. **Map Templates to Files**
   - Use this mapping to copy from `_templates/` to project root
   - Customize placeholders based on detected project context
   - Follow tier-specific variations for content depth

4. **Validate Completeness**
   - Check all required files exist
   - Verify recommended files included where appropriate
   - Ensure ignored files are not present
   - Use `tier-index.yaml` for automated validation

### File Generation Rules

- **Copy Directly**: Templates that map 1:1 (e.g., `universal/README.md` → `./README.md`)
- **Adapt Content**: Templates with tier variations (e.g., testing documentation)
- **Generate New**: Files without templates (e.g., `ARCHITECTURE.md`, `WORKFLOWS.md`)
- **Conditional Include**: Recommended files based on project type
- **Skip Entirely**: Files not in tier's required/recommended lists

---

**Version**: 1.0  
**Last Updated**: 2025-12-09  
**Source of Truth**: `tier-index.yaml`  
**Next Review**: Quarterly or when adding new templates  

---

*This mapping provides AI agents with precise instructions for selecting and copying the appropriate templates based on project tier requirements.*

## 📊 Template Inventory by Tier

### MVP Tier (4-7 files)

```
📄 README.md (MVP version)
📄 TODO.md (checklist format)
📄 TESTING.md (MVP plan)
📄 ARCHITECTURE.md (basic)
📄 .gitignore (minimal)
📄 API-DESIGN.md (optional)
📄 UI-FLOW.md (optional)
🧪 test/smoke_test.* (0-3 files)
```

**Total**: 4-7 documentation files + 0-3 test files

### CORE Tier (15-25 files)

```
📄 README.md (full)
📄 TODO.md / PROJECT-ROADMAP.md (Phase 1+2)
📄 CONTRIBUTING.md
📁 docs/
  📄 TESTING.md (full)
  📄 TESTING-EXAMPLES.md
  📄 DOCUMENTATION-BLUEPRINT.md
  📄 ARCHITECTURE.md (complete)
  📄 API-DOCUMENTATION.md (if applicable)
  📄 FRAMEWORK-PATTERNS.md
  📄 PROJECT-ROADMAP.md
  📄 universal/INTEGRATION-GUIDE.md
  📄 MIGRATION-GUIDE.md
📄 AGENTS.md
📄 QUICKSTART-AI.md
📁 scripts/
  📄 ai-workflow.ps1
  📄 test-coverage.ps1
  📄 build-all.ps1
  📄 generate-docs.ps1
  📄 check-quality.ps1
📁 .github/workflows/
  📄 ci.yml
🧪 test/unit/ (90%+ coverage)
🧪 test/component/ (80%+ coverage)
🧪 test/integration/ (70%+ coverage)
🧪 test/feature/ (all features)
```

**Total**: 15-25 documentation files + 10-20 test files

### FULL Tier (30-50 files)

```
📄 README.md (comprehensive)
📄 TODO.md / PROJECT-ROADMAP.md (Phases 1-4)
📄 CONTRIBUTING.md
📄 CODE_OF_CONDUCT.md
📄 CHANGELOG.md
📁 docs/
  📄 TESTING.md (all 7 layers)
  📄 TESTING-EXAMPLES.md (complete)
  📄 DOCUMENTATION-BLUEPRINT.md (all 20 files)
  📄 ARCHITECTURE.md (with ADRs)
  📄 API-DOCUMENTATION.md (complete)
  📄 FRAMEWORK-PATTERNS.md (with ADRs)
  📄 PROJECT-ROADMAP.md (Phases 1-4)
  📄 MIGRATION-GUIDE.md (with scripts)
  📄 DEPLOYMENT.md
  📄 SECURITY.md
  📄 DATA-MODEL.md
  📄 WORKFLOWS.md (detailed)
  📄 ONBOARDING.md
  📄 ANALYTICS.md
  📄 FEATURE-FLAGS.md
  📄 PERFORMANCE.md
  📄 MONITORING.md
  📄 ERROR-HANDLING.md
  📄 CONFIGURATION.md
📄 AGENTS.md
📄 QUICKSTART-AI.md
📁 scripts/
  📄 ai-workflow.ps1
  📄 test-coverage.ps1
  📄 build-all.ps1
  📄 generate-docs.ps1
  📄 check-quality.ps1
  📄 deploy.ps1
📁 .github/workflows/
  📄 ci.yml (complete)
  📄 cd.yml
🧪 test/unit/ (90%+)
🧪 test/component/ (80%+)
🧪 test/integration/ (70%+)
🧪 test/feature/ (100%)
🧪 test/workflow/ (all workflows)
🧪 test/system/ (E2E)
🧪 test/e2e/ (cross-platform)
🧪 test/performance/ (latency, throughput)
🧪 test/security/ (OWASP)
🧪 test/load/ (scalability)
```

**Total**: 30-50 documentation files + 20-40 test files

---

## 🎯 AI Implementation Commands by Tier

### MVP Setup

```bash
# AI Command
"Set up MVP tier for a Flutter prototype"

# AI Actions:
1. Copy: README.md, TODO.md, TESTING.md, .gitignore
2. Create: ARCHITECTURE.md (basic)
3. Create: smoke test (optional)
4. Generate: 4-7 files total
5. Report: "MVP setup complete - [X] files created"
```

### CORE Setup

```bash
# AI Command
"Set up CORE tier for a React/Node.js SaaS"

# AI Actions:
1. Copy all MVP templates
2. Copy: TESTING-EXAMPLES.md, DOCUMENTATION-BLUEPRINT.md
3. Copy: API-DOCUMENTATION.md, FRAMEWORK-PATTERNS.md
4. Copy: PROJECT-ROADMAP.md, universal/INTEGRATION-GUIDE.md
5. Copy: AGENTS.md, QUICKSTART-AI.md, MIGRATION-GUIDE.md
6. Create: CONTRIBUTING.md
7. Create: All scripts in scripts/
8. Create: .github/workflows/ci.yml
9. Generate: Test suite (unit 90%, component 80%, integration 70%)
10. Validate: .\scripts\ai-workflow.ps1
11. Report: "CORE setup complete - [X] files, [Y]% coverage"
```

### FULL Setup

```bash
# AI Command
"Set up FULL tier for enterprise Flutter SaaS"

# AI Actions:
1. Copy all MVP and CORE templates
2. Generate: ALL 20 blueprint files
3. Expand: API-DOCUMENTATION.md (complete)
4. Expand: PROJECT-ROADMAP.md (Phases 1-4)
5. Create: DEPLOYMENT.md, SECURITY.md, DATA-MODEL.md
6. Create: WORKFLOWS.md, ONBOARDING.md, ANALYTICS.md
7. Create: FEATURE-FLAGS.md, PERFORMANCE.md
8. Create: MONITORING.md, ERROR-HANDLING.md
9. Create: CODE_OF_CONDUCT.md, CHANGELOG.md
10. Implement: Complete test suite (all 7 layers)
11. Set up: Full CI/CD pipeline
12. Validate: Full validation suite
13. Report: "FULL setup complete - [X] files, [Y]% coverage, enterprise-ready"
```

---

## ✅ Quick Tier Decision Checklist

### Choose MVP if:
- [ ] You're prototyping or learning
- [ ] Project will be archived soon (< 1 month)
- [ ] No real users (just testing)
- [ ] Solo development, no collaboration

### Choose CORE if:
- [ ] ✅ **90% of projects fall here**
- [ ] Real users will use it (10-1000)
- [ ] You need to maintain it (1-2 years)
- [ ] Might have collaborators (1-3 developers)
- [ ] It's for a client
- [ ] It's a SaaS/product

### Choose FULL if:
- [ ] Enterprise or large-scale
- [ ] Team collaboration required (3+ developers)
- [ ] Long-term maintenance expected (2+ years)
- [ ] Complex architecture
- [ ] Multiple integrations
- [ ] Compliance/audit requirements
- [ ] It's a Krei project

---

## 🎊 Summary

| Aspect | MVP Tier | CORE Tier ⭐ | FULL Tier |
|--------|----------|--------------|-----------|
| **Purpose** | Prototype | Production Baseline | Enterprise |
| **When** | < 1 month | 1-6 months | 6+ months |
| **Team** | Solo | 1-3 devs | 3+ devs |
| **Users** | Personal | Real users (10-1000) | Scale (1000+) |
| **Files** | 4-7 | 15-25 | 30-50 |
| **Setup Time** | 15-30 min | 2-4 hours | 1-2 days |
| **Coverage** | 0-20% | **85%+** | **85%+ strict** |
| **AI Cost** | Low | Medium | High |

**⭐ CORE tier is the recommended default for 90% of projects**

**Reference**: See **docs/TIER-GUIDE.md** for complete framework details

---

**Last Updated**: 2025-12-09
**Framework Version**: 1.0
**Status**: Production Ready 🎊
