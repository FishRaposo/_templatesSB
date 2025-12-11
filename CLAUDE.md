## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Essential Commands](#essential-commands)
- [Architecture Overview](#architecture-overview)
- [State Management / Data Flow](#state-management--data-flow)
- [Database / Data Access Layer](#database--data-access-layer)
- [UI / Presentation Layer](#ui--presentation-layer)
- [Testing Strategy (MANDATORY)](#testing-strategy-mandatory)
- [Error Handling](#error-handling)
- [Common Development Tasks](#common-development-tasks)
- [Platform-Specific Notes](#platform-specific-notes)
- [Third-Party Integrations](#third-party-integrations)
- [Important Documentation Files](#important-documentation-files)
- [Debugging Tips](#debugging-tips)
- [Key Design Decisions](#key-design-decisions)
- [Pre-Commit Checklist (MANDATORY)](##pre-commit-checklist-mandatory)
- [Quick Reference: Common Commands](#quick-reference-common-commands)
- [When in Doubt](#when-in-doubt)
- [Critical Policies (Non-Negotiable)](##critical-policies-non-negotiable)

---

# CLAUDE.md - Universal Template System AI Guide

**Purpose**: This file provides complete guidance to Claude Code (claude.ai/code) when working with code in this repository. It's a mandatory reference document that ensures AI follows project-specific patterns and standards.

**Version**: 3.2  
**AI Integration**: Comprehensive - includes architecture, patterns, commands, testing, and autonomous workflows

---

## 📖 How to Use This Guide

This guide is designed to be a **comprehensive reference** for Claude Code to understand the Universal Template System architecture, development practices, and project-specific patterns.

**Key Principles**:
- Include **concrete examples** from the actual codebase
- Provide **exact file paths** that AI should reference
- Document **project-specific patterns** that differ from generic best practices
- Include **coverage requirements** and other quality gates
- Show **real code examples** from the project (not generic pseudocode)
- Keep it comprehensive but organized for quick reference

---

## 🎯 Project Overview

**Universal Template System**: A comprehensive blueprint-driven template system for automated project analysis, building, and gap identification.

- **Version**: 3.1
- **Status**: Production Ready with Blueprint System
- **Primary Language**: Python 3.8+
- **Key Framework(s)**: YAML configuration, Jinja2 templates, pathlib for cross-platform compatibility, Blueprint resolution engine
- **Architecture**: Blueprint-Driven with Task-Based Analysis Pipeline
- **Last Updated**: 2025-12-11

---

## ⚡ Essential Commands

### Development & Analysis

```bash
# Blueprint-driven project setup (NEW - RECOMMENDED)
python scripts/setup-project.py  # Interactive blueprint-first setup

# Analyze and build any project (legacy)
python scripts/analyze_and_build.py --description "Real-time chat app with auth" --build

# Analysis only (no building)
python scripts/analyze_and_build.py --description "E-commerce platform" --no-build

# Interactive mode
python scripts/analyze_and_build.py --interactive

# Detect tasks for project
python scripts/detect_project_tasks.py --description "API service" --output tasks.json

# Generate reference projects
python scripts/generate_reference_projects.py

# Validate template system
python scripts/validate-templates.py --full --detailed
```

### Blueprint System Commands

```bash
# 🚀 AUTONOMOUS PROJECT GENERATION (LLM Primary Entry Point)
python scripts/setup-project.py --auto --name "MyProject" --description "project description"

# Blueprint validation and management
python -c "from scripts.blueprint_config import get_available_blueprints; print(get_available_blueprints())"
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"

# Blueprint resolution testing
python -c "from scripts.blueprint_resolver import BlueprintResolver, ProjectSpecification; resolver = BlueprintResolver(); spec = ProjectSpecification(name='Test', blueprint='mins', stacks={'frontend': 'flutter'}); ir = resolver.resolve(spec); print(f'Blueprint: {ir.blueprint}, Confidence: {ir.metadata[\"resolution_confidence\"]:.2f}')"

# List available blueprints
python -c "from scripts.blueprint_config import get_blueprint_summary; print(get_blueprint_summary('mins'))"
```

### Template System Validation

```bash
# Comprehensive validation (CRITICAL - never skip)
python scripts/validate-templates.py --full --detailed

# Individual validation modules
python scripts/validate_templates.py --structure      # Directory structure
python scripts/validate_templates.py --content        # Template syntax & content
python scripts/validate_templates.py --mappings       # File mapping accuracy
python scripts/validate_templates.py --integration    # System compatibility
python scripts/validate_templates.py --blueprints     # Blueprint validation (NEW)

# Generate validation report
python scripts/validate_templates.py --full --report health-report.json

# Blueprint-specific validation
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"
python -c "from scripts.blueprint_config import get_available_blueprints; print(get_available_blueprints())"
```

### Template Development

```bash
# List tasks by category
python scripts/list_tasks_by_category.py --summary
python scripts/list_tasks_by_category.py --details
python scripts/list_tasks_by_category.py --search "scraping"

# Setup new project with templates
python scripts/setup-project.py

# Generate missing templates (if needed)
python scripts/generate_missing_stacks.py
python scripts/generate_missing_tier_templates_fixed.py
```

### Code Quality & Linting

```bash
# Validate Python code
python -m py_compile scripts/*.py
python -m flake8 scripts/ --max-line-length=100

# Check YAML syntax
python -c "import yaml; yaml.safe_load(open('tasks/task-index.yaml'))"

# Validate template file structure
python scripts/validate-templates.py --structure
```

---

## 🏗️ Architecture Overview

### High-Level Structure

The Universal Template System uses a **blueprint-driven architecture** with task-based analysis and automated building capabilities. The system is organized around product archetypes (blueprints) that drive stack, tier, and task selection, with 47 production tasks across 9 development categories, and 667+ template files providing universal and stack-specific implementations.

### Directory Structure

```
_templates/
├── 📁 blueprints/               # NEW: Product archetype definitions
│   ├── mins/                    # MINS blueprint example
│   │   ├── 📄 BLUEPRINT.md      # Human-readable blueprint documentation
│   │   ├── 📄 blueprint.meta.yaml # Machine-readable blueprint metadata
│   │   └── 📁 overlays/         # Stack-specific template extensions
│   │       ├── flutter/         # Flutter overlay templates
│   │       ├── python/          # Python overlay templates
│   │       └── [other stacks]/
│   └── [more blueprints...]     # Additional product archetypes
├── 📁 tasks/                    # 47 task templates with universal/stack implementations
│   ├── 📄 task-index.yaml       # Unified task definitions and file mappings
│   ├── 📁 web-scraping/         # Example task structure
│   │   ├── 📁 universal/        # Universal templates (apply to all stacks)
│   │   └── 📁 stacks/           # Stack-specific implementations
│   └── 📁 [45 more tasks...]   # Complete task library
├── 📁 scripts/                  # Analysis, building, and blueprint tools
│   ├── 🔍 analyze_and_build.py  # Legacy end-to-end analysis and building pipeline
│   ├── 🎯 detect_project_tasks.py # Task detection and gap analysis
│   ├── 🛠️ resolve_project.py    # Project building and scaffolding
│   ├── 🏗️ blueprint_config.py   # NEW: Blueprint metadata management
│   ├── 🏗️ blueprint_resolver.py # NEW: 7-step blueprint resolution algorithm
│   ├── ⚙️ setup-project.py      # UPDATED: Blueprint-first project setup
│   └── ✅ validate_templates.py # UPDATED: Includes blueprint validation
├── 📁 tiers/                    # Tier-specific templates (MVP, Core, Enterprise)
│   ├── mvp/                     # Minimal viable product templates
│   ├── core/                    # Production-ready templates
│   └── enterprise/              # Enterprise-grade templates
├── 📁 stacks/                   # Technology stack specific templates
│   ├── flutter/                 # Flutter mobile app templates
│   ├── go/                      # Go backend templates
│   ├── node/                    # Node.js templates
│   ├── python/                  # Python templates
│   ├── react/                   # React web templates
│   ├── react_native/            # React Native mobile templates
│   ├── next/                    # Next.js full-stack templates
│   ├── r/                       # R data analysis templates
│   └── sql/                     # SQL database templates
├── 📁 reference-projects/       # Generated reference implementations
│   ├── mvp/                     # MVP tier reference projects
│   ├── core/                    # Core tier reference projects
│   └── enterprise/              # Enterprise tier reference projects
├── 📁 docs/                     # Documentation and guides
├── 📁 examples/                 # Reference implementations and patterns
└── 📁 backups/                  # Consolidated legacy files
```

### Key Architectural Principles

1. **Blueprint-Driven Development**: Product archetypes drive stack, tier, and task selection as system primitives
2. **Task-Based Organization**: All functionality organized around 47 production tasks
3. **Universal + Stack-Specific**: Universal patterns with stack-specific optimizations and blueprint overlays
4. **Tiered Complexity**: MVP, Core, and Enterprise tiers for different project needs
5. **Automated Analysis**: AI-powered task detection and gap analysis
6. **Template Validation**: Comprehensive validation ensuring system integrity including blueprint validation
7. **Resolution Algorithm**: 7-step blueprint resolution producing intermediate representations
8. **System Primitive Formalization**: Blueprints operate with same rigor as stacks/tiers/tasks

---

## 🚀 Autonomous Workflow (Primary LLM Entry Point)

### LLM Configuration Metadata
```yaml
# LLM:CONFIGURATION - Stack, tier, and command mappings
stacks:
  - flutter: {tier: [mvp, core, enterprise], type: mobile, files: "main.dart, widget_test.dart, README.md"}
  - react_native: {tier: [mvp, core, enterprise], type: mobile, files: "App.jsx, App.test.jsx, README.md"}
  - react: {tier: [mvp, core, enterprise], type: web, files: "App.jsx, App.test.jsx, README.md"}
  - node: {tier: [mvp, core, enterprise], type: backend, files: "app.js, app.test.js, README.md"}
  - go: {tier: [mvp, core, enterprise], type: backend, files: "main.go, main_test.go, README.md"}
  - python: {tier: [mvp, core, enterprise], type: data-science, files: "app.py, test_main.py, README.md"}
  - r: {tier: [mvp, core], type: data-analytics, files: "main.R, tests/testthat.R, README.md"}
  - sql: {tier: [mvp, core], type: database, files: "schema.sql, queries.sql, README.md"}

tiers:
  mvp: {complexity: "50-200 lines", time: "15-30 min", team: "1-2 people", features: "basic"}
  core: {complexity: "200-500 lines", time: "2-4 hours", team: "3-10 people", features: "production"}
  enterprise: {complexity: "500-1000+ lines", time: "1-2 days", team: "10+ people", features: "security"}

commands:
  explore: "cd reference-projects/{tier}/{stack}-reference/"
  setup: "python scripts/setup-project.py --manual-stack {stack} --manual-tier {tier}"
  validate: "ls reference-projects/{tier}/{stack}-reference/"
  test: {"go": "go test ./...", "node": "npm test", "python": "pytest", "flutter": "flutter test", "react": "npm test", "r": "Rscript -e 'testthat::test_dir()'", "sql": "psql -f schema.sql"}
```

### Single-Command Project Generation
The blueprint system enables fully autonomous project generation through a unified command that achieves 1.00 resolution confidence:

```bash
python scripts/setup-project.py --auto --name "MyProject" --description "project description"
```

### Enhanced MINS Blueprint Capabilities
The unified MINS blueprint now includes comprehensive Flutter monetization overlays:

- **Complete IAP Service**: Mobile in-app purchases with desktop license validation
- **Conditional UI Pattern**: AdBannerSlot hidden for premium users (`if (!purchaseState.isPremium)`)
- **Monetization-Aware Navigation**: App shell with premium status integration
- **Production-Ready State Management**: Riverpod integration with purchase state

### Autonomous Workflow Results
```
🤖 Autonomous Mode Activated
🏗️  Blueprint: mins
📊 Resolution Confidence: 1.00
🔧 Stacks: flutter, python
📈 Tiers: {'flutter': 'mvp', 'python': 'core'}
📋 Tasks: 5 total
✅ Project structure generated with complete overlays
```

### Blueprint System Architecture
- **Single Source of Truth**: `blueprints/mins/` with enhanced overlays
- **Comprehensive Overlays**: 6 Flutter files including nested directory structure
- **Production Validation**: Autonomous workflow generates compilation-ready projects

---

## 🔄 State Management / Data Flow

### Blueprint-First Analysis Pipeline Flow

```python
# NEW: Blueprint-driven flow in scripts/setup-project.py
1. Blueprint Selection → Stack Constraints → Tier Defaults → Task Requirements
2. Resolution Algorithm → Intermediate Representation → Project Generation
3. Output: Ready-to-use project with blueprint-driven architecture

# Legacy flow in scripts/analyze_and_build.py
1. User Input → Task Detection → Stack Recommendation → Tier Assessment
2. Gap Analysis → Build Configuration → Template Generation → Validation
3. Output: Ready-to-use project with appropriate templates
```

### Blueprint Resolution System

```python
# Located in: scripts/blueprint_resolver.py
class BlueprintResolver:
    def resolve(self, project_spec: ProjectSpecification) -> IntermediateRepresentation:
        # 1. Load blueprint metadata
        # 2. Resolve stacks (required, recommended, supported)
        # 3. Resolve tiers (apply defaults, allow overrides)
        # 4. Resolve tasks (required, recommended, optional)
        # 5. Produce intermediate representation
        # 6. Validation and confidence scoring
        # 7. Return IR for project generation
```

### Task Index System

```yaml
# Located in: tasks/task-index.yaml
tasks:
  web-scraping:
    category: "web-api"
    description: "Scrape pages, parse HTML/JSON, store results"
    templates:
      universal: ["scraping-service.tpl.py", "data-parser.tpl.py"]
      stacks:
        python: ["python-scraping.tpl.py", "beautifulsoup-wrapper.tpl.py"]
        node: ["node-scraping.tpl.js", "cheerio-wrapper.tpl.js"]
    dependencies: ["http-client", "data-storage"]
    tier_support: ["mvp", "core", "enterprise"]
```

### Template Resolution Process

```python
# Template resolution logic
def resolve_template(task, stack, tier):
    # 1. Check for stack-specific template
    stack_template = f"tasks/{task}/stacks/{stack}/{task}-{tier}.tpl.{ext}"
    if exists(stack_template):
        return stack_template
    
    # 2. Fall back to universal template
    universal_template = f"tasks/{task}/universal/{task}-universal.tpl.{ext}"
    return universal_template
```

---

## 🗄️ Database / Data Access Layer

### Blueprint Metadata Structure

The "database" of the blueprint system includes both the existing `task-index.yaml` and new blueprint metadata:

```yaml
# Located in: blueprints/mins/blueprint.meta.yaml
blueprint:
  id: "mins"
  version: "1.0.0"
  name: "MINS – Minimalist Income Niche SaaS"
  category: "micro_saas"
  type: "app"
  description: "A single-purpose freemium mobile app pattern"
  
  stacks:
    required: ["flutter"]
    recommended: ["python"]
    supported: ["node", "go"]
  
  tier_defaults:
    flutter: "mvp"
    python: "core"
    node: "core"
    go: "mvp"
  
  tasks:
    required: ["auth-basic", "crud-module", "analytics-event-pipeline"]
    recommended: ["notification-center", "billing-stripe"]
    optional: ["seo-keyword-research", "web-scraping", "email-campaign-engine"]
  
  constraints:
    single_primary_feature: true
    monetization:
      model: ["one_time", "freemium"]
    offline_first: true
    platforms: ["android", "ios"]
  
  overlays:
    flutter:
      - "overlays/flutter/code/app-structure.tpl.dart"
      - "overlays/flutter/code/monetization-hooks.tpl.dart"
  
  llm_hints:
    architectural_keywords: ["minimalist", "single-purpose", "mobile-first"]
    monetization_focus: "freemium mobile app patterns"
    constraint_enforcement: "single feature focus"
```

### Task Index Structure

The "database" of the template system is the `task-index.yaml` file:

```yaml
# tasks/task-index.yaml - Master configuration
system_info:
  version: "3.0"
  total_tasks: 46
  supported_stacks: 9
  template_files: 93

categories:
  web-api:
    description: "Web scraping, APIs, dashboards"
    tasks: ["web-scraping", "rest-api-service", "graphql-api", "web-dashboard", "landing-page", "public-api-gateway"]
  
  auth-users-billing:
    description: "Authentication, user management, payments"
    tasks: ["auth-basic", "auth-oauth", "user-profile-management", "billing-stripe", "team-workspaces"]
```

### Template Metadata

```yaml
# Template metadata structure
template_metadata:
  name: "web-scraping"
  stack: "python"
  tier: "core"
  files:
    - path: "lib/scraping/scraper.py"
      template: "tasks/web-scraping/stacks/python/python-scraping.tpl.py"
    - path: "lib/scraping/parser.py"
      template: "tasks/web-scraping/universal/data-parser.tpl.py"
  dependencies:
    - "http-client"
    - "data-storage"
  validation_required: true
```

---

## 🎨 UI / Presentation Layer

### Template File Organization

Templates use a consistent presentation structure:

```python
# Template file pattern
"""
# {Template Name} Template ({Tier} Tier - {Stack})

## Purpose
Provides {tier-specific} {stack} code structure for {task} projects.

## Usage
This template should be used for:
- {specific use cases}
- {project types}

## Structure
```{language}
{template code with placeholders}
```

## Features
- {feature list}
- {tier-specific capabilities}
"""

# Template code with Jinja2-style placeholders
def {{function_name}}({{parameters}}):
    """{{function_description}}"""
    # {{implementation}}
    pass
```

### Tier-Specific Template Patterns

```python
# MVP Tier Template - Minimal features
mvp_web_scraping = """
import requests
from bs4 import BeautifulSoup

class SimpleScraper:
    def scrape_page(self, url):
        response = requests.get(url)
        return BeautifulSoup(response.content, 'html.parser')
"""

# Enterprise Tier Template - Advanced features
enterprise_web_scraping = """
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from typing import List, Dict, Optional
import logging
import time

class EnterpriseScraper:
    def __init__(self, config: ScraperConfig):
        self.config = config
        self.session = None
        self.logger = logging.getLogger(__name__)
    
    async def scrape_with_retry(self, url: str, max_retries: int = 3) -> Optional[Dict]:
        for attempt in range(max_retries):
            try:
                return await self._scrape_page(url)
            except Exception as e:
                self.logger.warning(f"Attempt {attempt + 1} failed for {url}: {e}")
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
"""
```

---

## 🧪 Testing Strategy (MANDATORY)

### Test Organization

Located in: `tests/validation/` directory

```
tests/
├── validation/
│   ├── validate_templates.py      # Main validation script
│   ├── test_structure.py          # Directory structure validation
│   ├── test_content.py            # Template content validation
│   ├── test_mappings.py           # File mapping accuracy
│   └── test_integration.py        # System integration tests
└── test_data/
    ├── valid_templates/           # Known good templates
    └── invalid_templates/         # Test cases for error handling
```

### Validation Test Template

```python
# tests/validation/test_content.py
def test_template_syntax():
    """Test that all templates have valid syntax"""
    for template_file in get_all_template_files():
        content = read_template(template_file)
        
        # Check for valid placeholder syntax
        assert '{{' in content or '{%' in content, f"Template {template_file} has no placeholders"
        
        # Check for required sections
        assert '## Purpose' in content, f"Template {template_file} missing Purpose section"
        assert '## Usage' in content, f"Template {template_file} missing Usage section"
        
        # Validate placeholder format
        placeholders = extract_placeholders(content)
        for placeholder in placeholders:
            assert is_valid_placeholder(placeholder), f"Invalid placeholder {placeholder} in {template_file}"

def test_stack_compatibility():
    """Test that stack-specific templates are compatible"""
    for stack in SUPPORTED_STACKS:
        stack_templates = get_templates_for_stack(stack)
        for template in stack_templates:
            assert has_stack_specific_code(template), f"Template {template} lacks {stack} specific code"
```

### Running Tests

```bash
# All tests (MUST PASS before committing)
python scripts/validate-templates.py --full

# Individual validation modules (legacy script for granular options)
python scripts/validate-templates.py --structure
python scripts/validate-templates.py --content
python scripts/validate-templates.py --mappings
python scripts/validate-templates.py --integration

# Generate detailed report
python scripts/validate-templates.py --full --detailed --report validation_report.json

# Test specific task
python scripts/validate-templates.py --task web-scraping
```

**Coverage Requirements (ENFORCED)**:
- Template syntax validation: 100%
- File mapping accuracy: 100%
- Cross-stack compatibility: 95%
- Integration testing: 90%

---

## 🔍 Error Handling

### Exception Hierarchy

```python
# scripts/shared/template_exceptions.py

class TemplateSystemError(Exception):
    """Base exception for template system errors"""
    pass

class TemplateNotFoundError(TemplateSystemError):
    def __init__(self, template_path: str):
        self.template_path = template_path
        super().__init__(f"Template not found: {template_path}")

class InvalidTemplateError(TemplateSystemError):
    def __init__(self, template_path: str, issue: str):
        self.template_path = template_path
        self.issue = issue
        super().__init__(f"Invalid template {template_path}: {issue}")

class StackCompatibilityError(TemplateSystemError):
    def __init__(self, stack: str, template: str):
        self.stack = stack
        self.template = template
        super().__init__(f"Template {template} not compatible with stack {stack}")
```

### Logging Utility

```python
# scripts/shared/logger.py

import logging
from pathlib import Path

class TemplateLogger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.setup_logger()
    
    def setup_logger(self):
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '[%(levelname)s] %(name)s: %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def template_processed(self, template_path: str, stack: str):
        self.logger.info(f"✅ Processed template: {template_path} for {stack}")
    
    def validation_failed(self, template_path: str, error: str):
        self.logger.error(f"❌ Validation failed for {template_path}: {error}")
    
    def gap_detected(self, task: str, stack: str):
        self.logger.warning(f"⚠️  Gap detected: {task} missing for {stack}")
```

---

## 🎯 Common Development Tasks

### Task 1: Adding a New Blueprint (NEW)

1. **Create blueprint directory** following blueprint structure:
   ```
   blueprints/my-blueprint/
   ├── BLUEPRINT.md                    # Human-readable documentation
   ├── blueprint.meta.yaml            # Machine-readable metadata
   └── overlays/                       # Stack-specific template extensions
       ├── flutter/
       │   ├── app-structure.tpl.dart
       │   └── [overlay templates...]
       ├── python/
       └── [other stacks...]
   ```

2. **Create blueprint.meta.yaml** with required schema:
   ```yaml
   blueprint:
     id: "my-blueprint"
     version: "1.0.0"
     name: "My Blueprint Name"
     category: "appropriate-category"
     type: "app"
     stacks:
       required: ["flutter"]
       recommended: ["python"]
       supported: ["node", "go"]
     tier_defaults:
       flutter: "mvp"
       python: "core"
     tasks:
       required: ["auth-basic", "crud-module"]
       recommended: ["analytics-event-pipeline"]
       optional: ["notification-center"]
   ```

3. **Create overlay templates** for stack-specific extensions

4. **Test blueprint resolution**:
   ```python
   from scripts.blueprint_resolver import BlueprintResolver, ProjectSpecification
   resolver = BlueprintResolver()
   spec = ProjectSpecification(name='Test', blueprint='my-blueprint', stacks={'frontend': 'flutter'})
   ir = resolver.resolve(spec)
   print(f'Resolution confidence: {ir.metadata["resolution_confidence"]:.2f}')
   ```

5. **Validate blueprint**: `python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('my-blueprint'))"`

6. **Update documentation** and integration guides

### Task 2: Adding a New Task

1. **Create task directory** following task structure:
   ```
   tasks/my-new-task/
   ├── universal/
   │   ├── my-new-task-universal.tpl.py
   │   └── my-new-task-config.tpl.yaml
   └── stacks/
       ├── python/
       │   └── my-new-task-python.tpl.py
       ├── node/
       │   └── my-new-task-node.tpl.js
       └── [other stacks...]
   ```

2. **Update task-index.yaml**:
   ```yaml
   tasks:
     my-new-task:
       category: "appropriate-category"
       description: "Description of the new task"
       templates:
         universal: ["my-new-task-universal.tpl.py"]
         stacks:
           python: ["my-new-task-python.tpl.py"]
           node: ["my-new-task-node.tpl.js"]
       dependencies: ["existing-task1", "existing-task2"]
       tier_support: ["mvp", "core", "enterprise"]
   ```

3. **Create tier-specific templates** in `tiers/` directory

4. **Add validation tests** for the new task

5. **Update documentation** and examples

6. **Run validation**: `python scripts/validate-templates.py --full`

### Task 3: Blueprint-Driven Project Setup (NEW RECOMMENDED WORKFLOW)

1. **Run blueprint-first setup**:
   ```bash
   python scripts/setup-project.py
   ```

2. **Select blueprint** from available options (e.g., MINS)

3. **Configure stacks** based on blueprint constraints:
   - Required stacks are automatically selected
   - Recommended stacks are suggested but optional
   - Supported stacks are available as options

4. **Configure tiers** using blueprint defaults:
   - Blueprint provides tier defaults for each stack
   - User can override defaults if needed

5. **Select optional tasks** from blueprint recommendations

6. **Generate project** using resolved intermediate representation

### Task 4: Legacy Project Setup (BACKUP WORKFLOW)

1. **Run manual setup** (skip blueprint selection):
   ```bash
   python scripts/setup-project.py --manual
   ```

2. **Select stacks** manually without blueprint constraints

3. **Select tiers** manually without blueprint defaults

4. **Select tasks** manually without blueprint recommendations

5. **Generate project** using traditional configuration

### Task 5: Adding Support for a New Stack

1. **Create stack directory**: `stacks/new-stack/`

2. **Create base templates**:
   ```
   stacks/new-stack/base/
   ├── code/
   ├── docs/
   └── tests/
   ```

3. **Add stack-specific implementations** for each task

4. **Update STACKS list** in all scripts

5. **Generate reference projects** for the new stack

6. **Validate cross-stack compatibility**

### Task 6: Updating Template Content

1. **Identify templates to update** using grep or validation tools

2. **Update template content** maintaining placeholder consistency

3. **Test template rendering** with sample data

4. **Update affected documentation**

5. **Run full validation suite**

6. **Regenerate reference projects** if needed

### Task 7: Blueprint Gap Analysis and Resolution

1. **Run blueprint gap analysis**:
   ```bash
   python -c "
   from scripts.blueprint_config import get_available_blueprints, get_blueprint_summary
   for blueprint in get_available_blueprints():
       print(f'Blueprint: {blueprint}')
       summary = get_blueprint_summary(blueprint)
       print(f'Stacks: {summary.get(\"stacks\", {})}')
       print(f'Tasks: {summary.get(\"tasks\", {})}')
   "
   ```

2. **Review blueprint coverage** for missing stacks or tasks

3. **Create missing overlay templates** for supported stacks

4. **Add missing task configurations** to blueprint metadata

5. **Validate updated blueprints** and test resolution

6. **Update blueprint documentation** with new capabilities

---

## 📱 Platform-Specific Notes

### Platform 1: Windows

- **Python Version**: 3.8+ (recommended 3.11)
- **Key Dependencies**: pyyaml, jinja2, pathlib
- **Shell Commands**: Use PowerShell syntax in documentation
- **Path Handling**: Use pathlib for cross-platform compatibility
- **Line Endings**: Git autocrlf should be configured

### Platform 2: macOS/Linux

- **Python Version**: 3.8+ (system python or pyenv)
- **Package Manager**: pip or conda
- **Shell Commands**: Bash syntax in documentation
- **Permissions**: May need chmod +x for scripts
- **Dependencies**: System packages for some stacks (e.g., build-essential)

### Platform 3: Docker

- **Base Image**: python:3.11-slim for validation scripts
- **Volume Mounting**: Mount `_templates` directory as working directory
- **Environment Variables**: Set PYTHONPATH and template directories
- **Build Context**: Include necessary template files

---

## 🔗 Third-Party Integrations

### Integration 1: YAML Configuration

- **Purpose**: Task definitions, template metadata, system configuration
- **Configuration**: `tasks/task-index.yaml`, stack configs
- **Usage Example**:
  ```python
  import yaml
  with open('tasks/task-index.yaml', 'r') as f:
      config = yaml.safe_load(f)
  ```

### Integration 2: Jinja2 Templates

- **Purpose**: Template rendering with placeholders
- **Package**: jinja2
- **Usage Pattern**:
  ```python
  from jinja2 import Template
  template = Template(open(template_file).read())
  rendered = template.render(variables=context)
  ```

### Integration 3: Pathlib for Cross-Platform

- **Purpose**: File system operations across platforms
- **Usage Pattern**:
  ```python
  from pathlib import Path
  template_path = Path('tasks') / task_name / 'universal' / f'{task_name}.tpl.py'
  ```

---

## 📖 Important Documentation Files

| File | Purpose | When to Update |
|------|---------|----------------|
| README.md | System overview and quick start | Major version changes |
| tasks/task-index.yaml | Master task configuration | When adding/modifying tasks |
| docs/TASKS-GUIDE.md | Detailed task documentation | Task system changes |
| AGENTS.md | Multi-agent system guide | Agent workflow changes |
| CLAUDE.md | AI development guide | Architecture changes |
| docs/TEMPLATE-BEST-PRACTICES.md | Template creation standards | Pattern changes |

---

## 🐛 Debugging Tips

### Debug Scenario 1: Template Validation Failures

```bash
# Enable verbose validation output
python scripts/validate-templates.py --full --detailed

# Check specific template
python scripts/validate-templates.py --template web-scraping

# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('tasks/task-index.yaml'))"

# Check file permissions
ls -la tasks/stacks/python/
```

### Debug Scenario 2: Task Detection Issues

```bash
# Debug task detection with verbose output
python scripts/detect_project_tasks.py --description "test project" --debug

# Check task index loading
python -c "
import yaml
with open('tasks/task-index.yaml') as f:
    config = yaml.safe_load(f)
    print(f'Loaded {len(config[\"tasks\"])} tasks')
"

# Test analysis pipeline
python scripts/analyze_and_build.py --description "simple web app" --dry-run
```

### Debug Scenario 3: Template Generation Problems

```bash
# Check template file existence
find tasks/ -name "*.tpl.*" | head -10

# Validate template syntax
python -c "
import jinja2
template = jinja2.Template(open('tasks/web-scraping/universal/scraping-service.tpl.py').read())
print('Template syntax valid')
"

# Test stack-specific resolution
python -c "
from scripts.shared.template_resolver import resolve_template
print(resolve_template('web-scraping', 'python', 'core'))
"
```

---

## 🔑 Key Design Decisions

1. **Blueprint-Driven Architecture**: Product archetypes (blueprints) drive stack, tier, and task selection as system primitives
2. **Task-Based Organization**: Organized around 47 production tasks rather than technology stacks
3. **Universal + Stack-Specific**: Universal patterns with stack optimizations and blueprint overlays for maximum reusability
4. **Tiered Complexity**: MVP/Core/Enterprise tiers match project maturity levels
5. **YAML Configuration**: Human-readable task definitions and blueprint metadata
6. **Automated Validation**: Comprehensive validation ensures system integrity including blueprint validation
7. **Cross-Platform Support**: Pathlib and platform-agnostic scripts
8. **Template Generation**: Automated reference project generation for validation
9. **Resolution Algorithm**: 7-step blueprint resolution producing intermediate representations
10. **System Primitive Formalization**: Blueprints operate with same rigor as stacks/tiers/tasks
11. **Backward Compatibility**: Legacy setup flow preserved alongside blueprint-first approach
12. **Overlay System**: Stack-specific template extensions modify base templates per blueprint

---

## ✅ Pre-Commit Checklist (MANDATORY)

1. **Run Full Validation**: `python scripts/validate-templates.py --full`
2. **Check Task Index**: Verify YAML syntax and completeness
3. **Validate Blueprints**: `python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"`
4. **Test Blueprint Resolution**: `python -c "from scripts.blueprint_resolver import BlueprintResolver; print('Blueprint resolver works')"`
5. **Test Template Generation**: `python scripts/generate_reference_projects.py`
6. **Update Documentation**: Ensure all changes are documented
7. **Verify Cross-Stack**: Test template compatibility across all stacks
8. **Check Blueprint Integration**: Test blueprint-first setup flow
9. **Verify File Mappings**: Ensure all templates are properly indexed
10. **Run Analysis Pipeline**: Test with sample project descriptions

---

## ⚡ Quick Reference: Common Commands

```bash
# Essential commands (memorize these)
python scripts/setup-project.py                    # Blueprint-first setup (NEW)
python scripts/validate-templates.py --full        # Comprehensive validation
python scripts/generate_reference_projects.py      # Generate reference projects

# Blueprint commands (NEW)
python -c "from scripts.blueprint_config import get_available_blueprints; print(get_available_blueprints())"
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"

# Development workflow
python scripts/list_tasks_by_category.py --search "keyword"
python scripts/detect_project_tasks.py --description "project" --output analysis.json
python scripts/validate_templates.py --task specific-task

# System maintenance
python scripts/validate_templates.py --full --report health.json
find tasks/ -name "*.tpl.*" | wc -l  # Count templates
find blueprints/ -name "*.yaml" | wc -l  # Count blueprints
```

---

## 🤔 When in Doubt

1. **Validation Issues**: Run `python scripts/validate-templates.py --full --detailed`
2. **Blueprint Questions**: Check `blueprints/mins/BLUEPRINT.md` and `blueprints/mins/blueprint.meta.yaml` for examples
3. **Template Questions**: Check `docs/TASKS-GUIDE.md` and existing template examples
4. **Architecture Decisions**: Review this file and `README.md`
5. **System Status**: Check the validation report and task index
6. **Blueprint Resolution**: Test with `python -c "from scripts.blueprint_resolver import BlueprintResolver; print('Works')"`
7. **Development Help**: Use `--help` flags on all scripts

---

## 🚨 Critical Policies (Non-Negotiable)

1. **All Templates Must Pass Validation**: No exceptions, no workarounds
2. **All Blueprints Must Pass Validation**: Blueprint validation is mandatory for system integrity
3. **Task Index Must Be Updated**: Every template change requires index updates
4. **Documentation Must Match Code**: Templates and documentation must stay synchronized
5. **Cross-Stack Compatibility**: New features must work across all supported stacks
6. **Backward Compatibility**: Template changes must not break existing projects
7. **Blueprint System Primitive**: Blueprints must be treated with same rigor as stacks/tiers/tasks
8. **Test Coverage**: All new functionality must include validation tests
9. **File Naming**: Strict adherence to established naming conventions
10. **Resolution Confidence**: Blueprint resolution must achieve high confidence scores

---

**Remember**: This is a production template system used by automated tools. The blueprint system is now a core system primitive that fundamentally changes how projects are set up. Consistency, validation, and documentation are not optional - they are mandatory for system reliability.
