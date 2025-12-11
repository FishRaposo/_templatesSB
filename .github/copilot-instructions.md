# Universal Template System - Copilot Instructions

## Project Overview

The Universal Template System is a **blueprint-driven, task-based template system** for automated project analysis, building, and gap identification. It enables autonomous project generation with 1.00 resolution confidence through a sophisticated architecture combining product archetypes (blueprints), technology stacks, complexity tiers, and functional tasks.

### Key Capabilities
- **Autonomous Project Generation**: Single-command project setup with blueprint-driven architecture
- **46 Production Tasks**: Organized across 9 development categories
- **12 Technology Stacks**: Python, Go, Node, React, Next.js, Flutter, React Native, TypeScript, R, SQL, Rust, Generic
- **3 Complexity Tiers**: MVP (50-200 lines), Core (200-500 lines), Enterprise (500-1000+ lines)
- **655 Validated Templates**: Universal + stack-specific implementations with 0 validation errors
- **Multi-Agent System**: 5 operational personas for coordinated development

---

## Technology Stack

### Supported Stacks
- **Backend**: Python (FastAPI, SQLAlchemy), Node.js (Express), Go (standard library)
- **Frontend**: React, Next.js (full-stack), TypeScript
- **Mobile**: Flutter (Dart), React Native
- **Data**: Python (Pandas, NumPy), R (tidyverse, ggplot2), SQL (database-agnostic)
- **Emerging**: Rust (systems programming)
- **Generic**: Language-agnostic utilities

### Primary Languages
- Python 3.8+ (data science, backend)
- JavaScript/TypeScript (web, backend)
- Go 1.18+ (backend services)
- Dart/Flutter (mobile)
- R (data analytics)
- SQL (database)

---

## Project Structure

### Root Directory
```
_templates/
├── blueprints/          # Product archetype definitions
│   └── mins/            # MINS blueprint (Minimalist Sustainable Monetization)
│       ├── BLUEPRINT.md # Human-readable documentation
│       ├── blueprint.meta.yaml # Machine-readable metadata
│       └── overlays/    # Stack-specific template extensions
├── tasks/               # 46 task templates (flat structure)
│   ├── task-index.yaml  # Unified task definitions
│   ├── auth-basic/      # Example: Authentication task
│   │   ├── universal/   # Universal templates
│   │   └── stacks/      # Stack-specific implementations
│   └── [45 more tasks]  # Complete task library
├── stacks/              # Technology stack templates
│   ├── python/          # Python-specific templates
│   ├── flutter/         # Flutter-specific templates
│   └── [10 more stacks] # Additional stack templates
├── tiers/               # Tier-specific templates
│   ├── mvp/             # MVP tier templates
│   ├── core/            # Core tier templates
│   └── enterprise/      # Enterprise tier templates
├── scripts/             # Automation and analysis tools
│   ├── setup-project.py # Blueprint-driven project setup
│   ├── validate-templates.py # Template validation
│   ├── analyze_and_build.py # Project analysis pipeline
│   └── [40+ scripts]    # Additional automation tools
├── tests/               # Test infrastructure
└── reference-projects/  # Generated reference implementations
```

### Task Categories (Virtual Organization)
1. **Web & API** (6 tasks): web-scraping, rest-api-service, graphql-api, web-dashboard, landing-page, public-api-gateway
2. **Auth, Users & Billing** (5 tasks): auth-basic, billing-stripe, user-profile-management, team-workspaces, oauth-flow
3. **Background Work & Automation** (5 tasks): job-queue, scheduled-tasks, notification-center, email-system, webhook-processor
4. **Data, Analytics & ML** (7 tasks): etl-pipeline, forecasting-engine, embedding-index, analytics-event-pipeline, segmentation-clustering, feature-engineering, recommendation-engine
5. **SEO / Growth / Content** (6 tasks): seo-keyword-research, sitemap-generator, content-brief-generator, ab-testing, lead-capture, landing-page
6. **Product & SaaS** (5 tasks): crud-module, admin-panel, multitenancy, feature-flags, audit-logging
7. **DevOps, Reliability & Quality** (5 tasks): healthchecks-telemetry, ci-template, error-reporting, rate-limiter, env-config-manager
8. **AI-Specific** (4 tasks): llm-prompt-router, rag-pipeline, agentic-workflow, code-refactor-agent
9. **Meta / Tooling** (3 tasks): project-bootstrap, docs-site, sample-data-generator

---

## Coding Guidelines

### Template Development Standards

#### File Naming Conventions
- **Task templates**: Lowercase with hyphens (e.g., `auth-basic`, `web-scraping`)
- **Stack templates**: Lowercase stack name directories (e.g., `python/`, `flutter/`)
- **Tier templates**: Lowercase tier names (e.g., `mvp/`, `core/`, `enterprise/`)
- **Template files**: Use `.tpl` extension or framework-specific extensions
- **Blueprint files**: `blueprint.meta.yaml` (machine-readable), `BLUEPRINT.md` (human-readable)

#### Template Structure Requirements
- **Universal templates**: Place in `tasks/{task-name}/universal/` directory
- **Stack-specific templates**: Place in `tasks/{task-name}/stacks/{stack-name}/` directory
- **Blueprint overlays**: Place in `blueprints/{blueprint-name}/overlays/{stack-name}/` directory
- **Tier templates**: Organized by tier in `tiers/{tier-name}/{stack-name}/` structure

#### Code Style Per Stack
- **Python**: Follow PEP 8, use type hints, FastAPI for APIs, SQLAlchemy for databases
- **Go**: Follow standard Go conventions, use interfaces, standard library first
- **Node.js**: Use Express, TypeScript preferred, async/await patterns
- **Flutter**: Widget composition, state management (Provider/Riverpod), material design
- **React**: Functional components, hooks, prop-types or TypeScript
- **SQL**: Database-agnostic patterns, migration support, indexing best practices

#### Documentation Requirements
- **Every template must have**: Clear purpose, usage instructions, example usage
- **Blueprint files must include**: Constraints, recommended stacks/tiers, task requirements
- **Script documentation**: Docstrings for functions, command-line help text
- **README files**: Present in all major directories and generated projects

### Validation Standards

#### Template Validation
- **Always run before committing**: `python scripts/validate-templates.py --full`
- **Expected output**: "All 655 templates validated successfully (0 errors)"
- **Validation checks**: Syntax, structure, mappings, integration, metadata
- **Blueprint validation**: Included in comprehensive validation

#### Quality Gates
- Template validation success rate: **100%**
- Documentation-template parity: **100%**
- Cross-stack compatibility: **100%**
- Integration test coverage: **95%+**

---

## Development Workflows

### Autonomous Project Generation
```bash
# Single-command autonomous setup (recommended)
python scripts/setup-project.py --auto --name "ProjectName" --description "project description"

# Manual stack and tier selection
python scripts/setup-project.py --manual-stack python --manual-tier core --name "MyAPI"

# Blueprint-specific setup
python scripts/setup-project.py --blueprint mins --name "MyApp"
```

### Template Validation
```bash
# Comprehensive validation (CRITICAL - run before committing)
python scripts/validate-templates.py --full

# Module-specific validation
python scripts/validate-templates.py --structure  # Directory structure
python scripts/validate-templates.py --content    # Template content
python scripts/validate-templates.py --mappings   # File mappings

# Blueprint validation
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"
```

### Task Analysis and Building
```bash
# Analyze project requirements
python scripts/analyze_and_build.py --description "E-commerce platform with auth" --build

# Task detection only
python scripts/detect_project_tasks.py --description "Project requirements"

# List available tasks by category
python scripts/list_tasks_by_category.py --summary

# Generate reference projects
python scripts/generate-reference-projects.py
```

### Testing Generated Projects
```bash
# Navigate to generated project
cd reference-projects/{tier}/{stack}-reference/

# Run stack-specific tests
# Python: pytest
# Node: npm test
# Go: go test ./...
# Flutter: flutter test
```

---

## Multi-Agent System

### Agent Personas (AGENTS.md)
The system uses 5 operational personas for coordinated development:

1. **Architect Agent**: Master reasoner, constraint setter, blueprint design
2. **Builder Agent**: Template constructor and implementer
3. **Refactorer Agent**: Structural improvement specialist
4. **Doc Manager Agent**: Documentation-template parity guardian
5. **Tester Agent**: Validation and quality gatekeeper

### Agent Handoff Protocol
- **Architect → Builder**: Architectural specification → Implementation
- **Builder → Tester**: New template → Validation
- **Tester → Doc Manager**: Validated template → Documentation
- **Doc Manager → Refactorer**: Documentation parity → Improvements
- **Refactorer → Tester**: Refactored template → Re-validation

### Quality Enforcement
- Templates require architectural approval before implementation
- All templates must pass validation before merge
- Documentation must be synchronized with templates
- Breaking changes require migration paths
- Security vulnerabilities must be addressed immediately

---

## Blueprint-Driven Architecture

### What are Blueprints?
Blueprints are **product archetypes** that define application patterns, constraints, and requirements. They operate as system primitives with the same rigor as stacks/tiers/tasks.

### Blueprint Resolution Algorithm (7 Steps)
1. Blueprint selection from description
2. Extract stack constraints from blueprint
3. Apply tier defaults from blueprint
4. Identify required tasks from blueprint
5. Generate intermediate representation
6. Validate resolution confidence (target: 1.00)
7. Output project configuration

### Blueprint Components
- **blueprint.meta.yaml**: Machine-readable metadata (stacks, tiers, tasks, constraints)
- **BLUEPRINT.md**: Human-readable documentation (purpose, architecture, guidelines)
- **overlays/**: Stack-specific template extensions that supplement base templates

### Using Blueprints
```bash
# Automatic blueprint detection
python scripts/setup-project.py --auto --description "minimalist mobile app"
# → Detects 'mins' blueprint, selects flutter/python, generates project

# Manual blueprint selection
python scripts/setup-project.py --blueprint mins --name "MyApp"

# List available blueprints
python scripts/list_blueprints.py
```

---

## Common Development Patterns

### Adding New Templates
1. **Identify task category**: Determine which of the 9 categories the task belongs to
2. **Create task directory**: `tasks/{task-name}/`
3. **Add universal templates**: Place in `tasks/{task-name}/universal/`
4. **Add stack-specific templates**: Place in `tasks/{task-name}/stacks/{stack}/`
5. **Update task-index.yaml**: Add task definition and file mappings
6. **Validate**: Run `python scripts/validate-templates.py --full`
7. **Document**: Update README and relevant documentation

### Adding New Stacks
1. **Create stack directory**: `stacks/{stack-name}/`
2. **Add stack templates**: Create stack-specific template files
3. **Update stack configuration**: Add to `scripts/stack_config.py`
4. **Create tier templates**: Add MVP, Core, Enterprise templates
5. **Validate**: Ensure all templates pass validation
6. **Document**: Add stack to documentation

### Adding New Blueprints
1. **Create blueprint directory**: `blueprints/{blueprint-name}/`
2. **Define metadata**: Create `blueprint.meta.yaml` with constraints
3. **Write documentation**: Create `BLUEPRINT.md` with guidelines
4. **Add overlays**: Create stack-specific overlays in `overlays/{stack}/`
5. **Validate**: Run blueprint validation
6. **Test**: Generate projects using the new blueprint

### Refactoring Templates
1. **Run analysis**: Identify improvement opportunities
2. **Plan changes**: Ensure backward compatibility
3. **Update templates**: Make structural improvements
4. **Update documentation**: Sync with template changes
5. **Validate**: Run comprehensive validation
6. **Test**: Verify generated projects still work

---

## Important Constraints

### DO NOT
- ❌ Break template validation (must maintain 100% validation rate)
- ❌ Create templates without architectural approval
- ❌ Skip documentation updates for template changes
- ❌ Introduce breaking changes without migration paths
- ❌ Add security vulnerabilities
- ❌ Modify task-index.yaml without validation
- ❌ Change directory structure without system-wide updates
- ❌ Remove or modify working templates unnecessarily

### ALWAYS
- ✅ Run `python scripts/validate-templates.py --full` before committing
- ✅ Maintain documentation-template parity
- ✅ Follow multi-agent coordination protocols
- ✅ Ensure cross-stack compatibility
- ✅ Test generated projects after template changes
- ✅ Update task-index.yaml for new tasks
- ✅ Follow tier-specific complexity guidelines
- ✅ Validate blueprint constraints

### PREFER
- 🎯 Universal templates over stack-specific when possible
- 🎯 Existing patterns over new implementations
- 🎯 Minimal changes over extensive refactoring
- 🎯 Blueprint-driven setup over manual configuration
- 🎯 Automated validation over manual checks
- 🎯 Standard library over external dependencies

---

## Key Resources

### Essential Documentation
- **[README.md](./README.md)**: System overview and quick start
- **[AGENTS.md](./AGENTS.md)**: Multi-agent coordination guide
- **[CLAUDE.md](./CLAUDE.md)**: Primary LLM agent guide
- **[QUICKSTART.md](./QUICKSTART.md)**: Hands-on project exploration
- **[SYSTEM-MAP.md](./SYSTEM-MAP.md)**: Complete architecture documentation

### Development Guides
- **[ADD-NEW-TASK-TEMPLATE.md](./ADD-NEW-TASK-TEMPLATE.md)**: Adding new tasks
- **[ADD-NEW-STACK-TEMPLATE.md](./ADD-NEW-STACK-TEMPLATE.md)**: Adding new stacks
- **[ADD-NEW-BLUEPRINT-TEMPLATE.md](./ADD-NEW-BLUEPRINT-TEMPLATE.md)**: Adding new blueprints

### Critical Commands
```bash
# Validate entire system (RUN BEFORE COMMITTING)
python scripts/validate-templates.py --full

# Generate autonomous project
python scripts/setup-project.py --auto --name "Project" --description "description"

# List all tasks by category
python scripts/list_tasks_by_category.py --summary

# Analyze project requirements
python scripts/analyze_and_build.py --description "requirements" --build
```

---

## Performance Expectations

### Template Validation
- **Speed**: ~2-3 seconds for full validation
- **Success rate**: 100% (0 errors)
- **Coverage**: 655 templates across all stacks

### Project Generation
- **Autonomous mode**: 5-10 seconds
- **Manual mode**: 3-5 seconds
- **Resolution confidence**: 1.00 (target)
- **Output**: Compilation-ready projects

### Quality Metrics
- Template validation: **100%**
- Cross-stack compatibility: **100%**
- Documentation accuracy: **100%**
- Integration test coverage: **95%+**

---

## Security Considerations

### Template Security
- Validate all template inputs
- Avoid hardcoded credentials
- Use environment variables for secrets
- Follow stack-specific security best practices
- Run security scanning on generated projects

### Blueprint Constraints
- Enforce blueprint-defined security requirements
- Validate overlay templates for security issues
- Check for common vulnerabilities in templates
- Follow tier-specific security guidelines

---

## Troubleshooting

### Validation Failures
```bash
# Run detailed validation
python scripts/validate-templates.py --full --detailed

# Check specific module
python scripts/validate-templates.py --structure
python scripts/validate-templates.py --content
```

### Project Generation Issues
```bash
# Enable debug mode
python scripts/setup-project.py --auto --name "Test" --description "test" --debug

# Check blueprint resolution
python -c "from scripts.blueprint_resolver import resolve_blueprint; print(resolve_blueprint('description'))"
```

### Template Issues
```bash
# Validate specific task
python scripts/validate_tasks.py

# Check stack templates
python scripts/validate_stacks.py

# Validate blueprints
python scripts/validate_blueprints.py
```

---

## Version Information

- **System Version**: 4.0
- **Total Tasks**: 46 production tasks
- **Total Templates**: 655 validated templates
- **Validation Status**: EXCELLENT (0 errors)
- **Blueprint Support**: v3.2
- **Multi-Agent System**: v3.2

---

**Last Updated**: December 2025  
**Maintained By**: Universal Template System Team  
**License**: See repository root
