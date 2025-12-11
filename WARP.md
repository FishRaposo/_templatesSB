# WARP.md - Universal Template System Terminal Guide

**Purpose**: Comprehensive Warp terminal configuration and workflow guide for the Universal Template System development environment.
**Version**: 3.2  
**Terminal Integration**: Optimized for Warp's AI-powered features, block-based workflows, and autonomous project generation with Blueprint System support.

---

## 🏗️ System Overview

### High-Level Structure

The Universal Template System uses a **blueprint-driven architecture** with task-based analysis and automated building capabilities. The system is organized around product archetypes (blueprints) that drive stack, tier, and task selection, with 46 production tasks across 9 development categories, and 93+ template files providing universal and stack-specific implementations.

### Directory Structure

```
_templates/
├── 📁 blueprints/               # Product archetype definitions
│   ├── mins/                    # MINS blueprint example
│   │   ├── 📄 BLUEPRINT.md      # Human-readable blueprint documentation
│   │   ├── 📄 blueprint.meta.yaml # Machine-readable blueprint metadata
│   │   └── 📁 overlays/         # Stack-specific template extensions
│   │       ├── flutter/         # Flutter overlay templates
│   │       ├── python/          # Python overlay templates
│   │       └── [other stacks]/
│   └── [more blueprints...]     # Additional product archetypes
├── 📁 tasks/                    # 46 task templates with universal/stack implementations
│   ├── 📄 task-index.yaml       # Unified task definitions and file mappings
│   ├── 📁 web-scraping/         # Example task structure
│   │   ├── 📁 universal/        # Universal templates (apply to all stacks)
│   │   └── 📁 stacks/           # Stack-specific implementations
│   └── 📁 [45 more tasks...]   # Complete task library
├── 📁 scripts/                  # Analysis, building, and blueprint tools
│   ├── 🔍 analyze_and_build.py  # Legacy end-to-end analysis and building pipeline
│   ├── 🎯 detect_project_tasks.py # Task detection and gap analysis
│   ├── 🛠️ resolve_project.py    # Project building and scaffolding
│   ├── 🏗️ blueprint_config.py   # Blueprint metadata management
│   ├── 🏗️ blueprint_resolver.py # 7-step blueprint resolution algorithm
│   ├── ⚙️ setup-project.py      # Blueprint-first project setup
│   └── ✅ validate_templates.py # Includes blueprint validation
├── 📁 tiers/                    # Tier-specific templates (MVP, Core, Enterprise)
├── 📁 stacks/                   # Technology stack specific templates
└── 📁 reference-projects/       # Generated reference implementations
```

### Key Architectural Principles

1. **Blueprint-Driven Development**: Product archetypes drive stack, tier, and task selection as system primitives
2. **Task-Based Organization**: All functionality organized around 46 production tasks
3. **Universal + Stack-Specific**: Universal patterns with stack-specific optimizations and blueprint overlays
4. **Tiered Complexity**: MVP, Core, and Enterprise tiers for different project needs
5. **Automated Analysis**: AI-powered task detection and gap analysis
6. **Template Validation**: Comprehensive validation ensuring system integrity including blueprint validation
7. **Resolution Algorithm**: 7-step blueprint resolution producing intermediate representations
8. **System Primitive Formalization**: Blueprints operate with same rigor as stacks/tiers/tasks

---

## 🚀 Autonomous Workflow

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

---

## 📋 Essential Commands

### Autonomous Workflow
```bash
# Generate project automatically (recommended)
python scripts/setup-project.py --auto --name "ProjectName" --description "project description"

# Manual stack and tier selection
python scripts/setup-project.py --manual-stack flutter --manual-tier mvp --name "MyApp"

# Validate template system
python scripts/validate-templates.py --full
```

### Template System Validation
```bash
# Comprehensive validation (CRITICAL - never skip)
python scripts/validate-templates.py --full

# Blueprint-specific validation
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"
```

### Template Development
```bash
# List tasks by category
python scripts/list_tasks_by_category.py --summary

# Setup new project with templates
python scripts/setup-project.py
```

---

## 🚀 Quick Start for Warp Users

### Essential Warp Setup

```bash
# Clone and setup the Universal Template System
git clone <repository-url>
cd _templates

# Install Python dependencies
pip install -r requirements.txt

# Setup Warp-specific environment
export PYTHONPATH="$PWD:$PYTHONPATH"
export TEMPLATE_SYSTEM_ROOT="$PWD"
```

### Warp Block Commands

```bash
# 🚀 AUTONOMOUS PROJECT GENERATION (Primary Warp Block - LLM Entry Point)
python scripts/setup-project.py --auto --name "MyProject" --description "project description"

# Blueprint-Driven Setup Block (Interactive Alternative)
python scripts/setup-project.py

# Blueprint Management Block
python -c "from scripts.blueprint_config import get_available_blueprints; print(get_available_blueprints())"
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"

# System Validation Block
python scripts/validate-templates.py --full --detailed

# Project Analysis Block (Legacy)
python scripts/analyze_and_build.py --description "your project description" --build

# Task Exploration Block
python scripts/list_tasks_by_category.py --details

# Blueprint Management Block (NEW)
python -c "from scripts.blueprint_config import get_available_blueprints; print(get_available_blueprints())"
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"
```

---

## 🎯 Warp-Specific Workflows

### Workflow 1: Blueprint-Driven System Exploration (NEW)

```bash
# Block 1: Blueprint System Overview
echo "🏗️  Blueprint-Driven Template System Status"
echo "============================================"
python -c "from scripts.blueprint_config import get_available_blueprints; print(f'Available Blueprints: {get_available_blueprints()}')"

# Block 2: Blueprint Details
echo "📋 Blueprint Details and Capabilities"
echo "======================================"
python -c "from scripts.blueprint_config import get_blueprint_summary; print(get_blueprint_summary('mins'))"

# Block 3: Template Validation
echo "✅ System Validation (Including Blueprints)"
echo "=========================================="
python scripts/validate-templates.py --full --detailed
```

### Workflow 2: Blueprint-First Project Setup (NEW RECOMMENDED)

```bash
# Block 1: Interactive Blueprint Selection
echo "🎯 Blueprint-Driven Project Setup"
echo "================================="
python scripts/setup-project.py

# Block 2: Blueprint Resolution Testing
echo "🔍 Blueprint Resolution Testing"
echo "==============================="
python -c "
from scripts.blueprint_resolver import BlueprintResolver, ProjectSpecification
resolver = BlueprintResolver()
spec = ProjectSpecification(name='TestProject', blueprint='mins', stacks={'frontend': 'flutter'})
ir = resolver.resolve(spec)
print(f'Resolution confidence: {ir.metadata[\"resolution_confidence\"]:.2f}')
print(f'Resolved stacks: {ir.stacks}')
print(f'Resolved tiers: {ir.tiers}')
"

# Block 3: Blueprint Validation
echo "✅ Blueprint Validation"
echo "======================"
python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))"
```

### Workflow 3: Legacy Template System Exploration

```bash
# Block 1: System Overview
echo "🏗️  Universal Template System Status"
echo "======================================"
python scripts/list_tasks_by_category.py --summary

# Block 2: Available Tasks
echo "📋 Available Tasks by Category"
echo "=============================="
python scripts/list_tasks_by_category.py --category web-api --details

# Block 3: Template Validation
echo "✅ System Validation"
echo "===================="
python tests/validation/validate_templates.py --structure
```

### Workflow 4: Legacy Project Analysis Pipeline

```bash
# Block 1: Project Description Analysis
echo "🔍 Analyzing Project Requirements..."
python scripts/detect_project_tasks.py --description "Real-time chat application with authentication" --output analysis.json

# Block 2: Gap Detection
echo "📊 Identifying Template Gaps..."
python scripts/analyze_and_build.py --description "Real-time chat application with authentication" --no-build --output gap-analysis

# Block 3: Template Generation
echo "🛠️  Generating Project Templates..."
python scripts/resolve_project.py --config analysis.json --output my-chat-app
```

### Workflow 3: Template Development

```bash
# Block 1: Create New Task Structure
echo "📁 Creating Task Structure..."
mkdir -p tasks/my-new-task/{universal,stacks/{python,node,go,flutter}}

# Block 2: Template Validation
echo "✅ Validating New Templates..."
python scripts/validate-templates.py --task my-new-task --detailed

# Block 3: System Integration
echo "🔗 Updating System Integration..."
python scripts/generate_reference_projects.py --filter my-new-task
```

---

## ⚡ Warp Command Shortcuts

### Custom Warp Commands

Add these to your Warp configuration for the Universal Template System:

```yaml
# Warp Configuration (~/.warp/themes/commands.yaml)
commands:
  - name: "validate-templates"
    description: "Validate all template system components including blueprints"
    command: "python scripts/validate-templates.py --full"
    
  - name: "setup-project"
    description: "Blueprint-driven project setup (NEW - RECOMMENDED)"
    command: "python scripts/setup-project.py"
    
  - name: "analyze-project"
    description: "Analyze project and generate templates (legacy)"
    command: "python scripts/analyze_and_build.py --description \"{{project_description}}\" --build"
    
  - name: "list-tasks"
    description: "List available tasks by category"
    command: "python scripts/list_tasks_by_category.py --details"
    
  - name: "list-blueprints"
    description: "List available blueprints (NEW)"
    command: "python -c \"from scripts.blueprint_config import get_available_blueprints; print(get_available_blueprints())\""
    
  - name: "validate-blueprint"
    description: "Validate specific blueprint (NEW)"
    command: "python -c \"from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('{{blueprint_id}}'))\""
    
  - name: "test-blueprint-resolution"
    description: "Test blueprint resolution algorithm (NEW)"
    command: "python -c \"from scripts.blueprint_resolver import BlueprintResolver, ProjectSpecification; resolver = BlueprintResolver(); spec = ProjectSpecification(name='Test', blueprint='{{blueprint_id}}', stacks={'frontend': '{{stack}}'}); ir = resolver.resolve(spec); print(f'Confidence: {ir.metadata[\\\"resolution_confidence\\\"]:.2f}')\""
    
  - name: "generate-reference"
    description: "Generate reference projects"
    command: "python scripts/generate_reference_projects.py"
```

### Warp Input Blocks

```bash
# Interactive Project Analysis
read -p "Enter project description: " project_desc
python scripts/analyze_and_build.py --description "$project_desc" --build

# Stack Selection
echo "Available stacks: flutter, go, node, python, react, react_native, next, r, sql, generic, typescript"
read -p "Select stack: " selected_stack
python scripts/setup-project.py --stack "$selected_stack"

# Task Category Selection
echo "Categories: web-api, auth-users-billing, background-work, data-analytics, seo-growth, product-saas, devops, ai-specific, meta-tooling"
read -p "Select category: " category
python scripts/list_tasks_by_category.py --category "$category" --details
```

---

## 🎨 Warp Theme Integration

### Template System Theme Colors

```css
/* Universal Template System Warp Theme */
:root {
  --template-primary: #2563eb;
  --template-secondary: #7c3aed;
  --template-success: #16a34a;
  --template-warning: #f59e0b;
  --template-error: #dc2626;
  --template-info: #0891b2;
}

/* Syntax highlighting for template files */
.template-placeholder {
  color: var(--template-secondary);
  font-weight: bold;
}

.template-code {
  color: var(--template-primary);
  background: rgba(37, 99, 235, 0.1);
}
```

### Custom Warp Prompts

```bash
# Template System Development Prompt
export PS1="\[\033[38;5;27m\]🏗️  Template System\[\033[0m\] \[\033[38;5;39m\]\w\[\033[0m\] \$ "

# Project Analysis Prompt
export PS1="\[\033[38;5;34m\]🔍 Analysis Mode\[\033[0m\] \[\033[38;5;39m\]\w\[\033[0m\] \$ "

# Template Validation Prompt
export PS1="\[\033[38;5;28m\]✅ Validation Mode\[\033[0m\] \[\033[38;5;39m\]\w\[\033[0m\] \$ "
```

---

## 📊 Warp Dashboard Integration

### System Status Dashboard

```bash
# Create a Warp dashboard block for system status
echo "🏗️  Universal Template System Dashboard"
echo "========================================"
echo ""
echo "📊 System Statistics:"
echo "- Total Tasks: $(grep -c 'tasks:' tasks/task-index.yaml)"
echo "- Supported Stacks: $(grep -o 'stacks:' tasks/task-index.yaml | wc -l)"
echo "- Template Files: $(find tasks/ -name '*.tpl.*' | wc -l)"
echo ""
echo "🔍 Recent Activity:"
echo "- Last Validation: $(date)"
echo "- Template Updates: $(git log --oneline --since="1 week ago" | wc -l) commits"
echo ""
echo "✅ System Health:"
python tests/validation/validate_templates.py --structure | tail -1
```

### Development Workflow Dashboard

```bash
# Development progress tracking
echo "🛠️  Development Workflow Status"
echo "==============================="
echo ""
echo "Current Tasks in Progress:"
git status --porcelain | grep -E "(tasks/|scripts/)" | wc -l | xargs echo "- Modified files:"
echo ""
echo "Validation Results:"
if python tests/validation/validate_templates.py --structure > /dev/null 2>&1; then
    echo "✅ All templates valid"
else
    echo "❌ Template validation issues detected"
fi
echo ""
echo "Recent Commits:"
git log --oneline -5
```

---

## 🔧 Warp-Specific Tools Integration

### Warp AI Integration

```bash
# Warp AI prompts for template system development
echo "🤖 Warp AI Prompts for Template Development:"
echo "============================================"
echo ""
echo "Template Creation:"
echo "Create a new task template for [feature] with universal and stack-specific implementations"
echo ""
echo "Gap Analysis:"
echo "Analyze the current template system and identify missing templates for [technology stack]"
echo ""
echo "Validation:"
echo "Review and validate the following template for syntax and best practices: [template content]"
echo ""
echo "Documentation:"
echo "Generate comprehensive documentation for the [task] template including usage examples"
```

### Warp Block Templates

```bash
# Template Analysis Block Template
cat << 'EOF' > ~/.warp/blocks/template-analysis.warp
# Template Analysis Block
echo "🔍 Template Analysis: $1"
echo "========================"
python scripts/analyze_and_build.py --description "$1" --no-build
echo ""
echo "📊 Gap Analysis:"
python scripts/detect_project_tasks.py --description "$1" --output gaps.json
cat gaps.json
EOF

# Template Validation Block Template
cat << 'EOF' > ~/.warp/blocks/template-validation.warp
# Template Validation Block
echo "✅ Template System Validation"
echo "============================="
python scripts/validate-templates.py --full --detailed
echo ""
echo "📋 Validation Summary:"
python tests/validation/validate_templates.py --structure
EOF

# Reference Project Generation Block
cat << 'EOF' > ~/.warp/blocks/reference-project.warp
# Reference Project Generation
echo "🏗️  Generating Reference Projects"
echo "=================================="
python scripts/generate_reference_projects.py
echo ""
echo "📊 Generated Projects:"
find reference-projects/ -type d -name "*-reference" | sort
EOF
```

---

## 🎯 Warp-Specific Aliases

### Productivity Aliases

```bash
# Add to ~/.bashrc or ~/.zshrc for Warp
alias ts-validate="python scripts/validate-templates.py --full"
alias ts-setup="python scripts/setup-project.py"                    # NEW: Blueprint-first setup
alias ts-analyze="python scripts/analyze_and_build.py"
alias ts-tasks="python scripts/list_tasks_by_category.py --details"
alias ts-generate="python scripts/generate_reference_projects.py"
alias ts-status="echo '🏗️  Template System Status' && python tests/validation/validate_templates.py --structure"

# Blueprint-specific aliases (NEW)
alias ts-blueprints="python -c \"from scripts.blueprint_config import get_available_blueprints; print(get_available_blueprints())\""
alias ts-blueprint-info="python -c \"from scripts.blueprint_config import get_blueprint_summary; print(get_blueprint_summary('mins'))\""
alias ts-blueprint-validate="python -c \"from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('mins'))\""
alias ts-blueprint-test="python -c \"from scripts.blueprint_resolver import BlueprintResolver; print('Blueprint resolver working')\""

# Stack-specific aliases
alias ts-python="python scripts/setup-project.py --stack python"
alias ts-node="python scripts/setup-project.py --stack node"
alias ts-go="python scripts/setup-project.py --stack go"
alias ts-flutter="python scripts/setup-project.py --stack flutter"
alias ts-react="python scripts/setup-project.py --stack react"
alias ts-next="python scripts/setup-project.py --stack next"

# Development workflow aliases
alias ts-dev="echo '🛠️  Development Mode' && export PS1='\[\033[38;5;27m\]🏗️  Dev\[\033[0m\] \w \$ '"
alias ts-validate="echo '✅ Validation Mode' && export PS1='\[\033[38;5;28m\]✅ Valid\[\033[0m\] \w \$ '"
alias ts-analyze="echo '🔍 Analysis Mode' && export PS1='\[\033[38;5;34m\]🔍 Analysis\[\033[0m\] \w \$ '"
alias ts-blueprint="echo '🏗️  Blueprint Mode' && export PS1='\[\033[38;5;93m\]🏗️  Blueprint\[\033[0m\] \w \$ '"
```

### Warp-Specific Functions

```bash
# Interactive template system functions
ts_explore() {
    echo "🔍 Exploring Template System..."
    echo "Available categories:"
    python scripts/list_tasks_by_category.py --summary
    echo ""
    read -p "Enter category to explore: " category
    python scripts/list_tasks_by_category.py --category "$category" --details
}

ts_create_project() {
    echo "🏗️  Creating New Project..."
    echo "1. Blueprint-driven (Recommended)"
    echo "2. Legacy manual setup"
    read -p "Choose setup method (1/2): " method
    
    if [ "$method" = "1" ]; then
        python scripts/setup-project.py
    else
        read -p "Enter project description: " description
        read -p "Enter stack (python/node/go/flutter/react/next): " stack
        read -p "Enter tier (mvp/core/enterprise): " tier
        
        python scripts/analyze_and_build.py --description "$description" --stack "$stack" --tier "$tier" --build
    fi
}

ts_blueprint_explore() {
    echo "🏗️  Exploring Blueprints..."
    echo "Available blueprints:"
    python -c "from scripts.blueprint_config import get_available_blueprints; print(get_available_blueprints())"
    echo ""
    read -p "Enter blueprint to explore: " blueprint
    python -c "from scripts.blueprint_config import get_blueprint_summary; print(get_blueprint_summary('$blueprint'))"
}

ts_validate_task() {
    echo "✅ Validating Task: $1"
    python scripts/validate_templates.py --task "$1" --detailed
}

ts_validate_blueprint() {
    echo "✅ Validating Blueprint: $1"
    python -c "from scripts.blueprint_config import validate_blueprint; print(validate_blueprint('$1'))"
}

ts_search_templates() {
    echo "🔍 Searching Templates: $1"
    find tasks/ -name "*.tpl.*" -exec grep -l "$1" {} \; | sort
}

ts_test_blueprint_resolution() {
    echo "🧪 Testing Blueprint Resolution: $1"
    python -c "
from scripts.blueprint_resolver import BlueprintResolver, ProjectSpecification
resolver = BlueprintResolver()
spec = ProjectSpecification(name='Test', blueprint='$1', stacks={'frontend': 'flutter'})
ir = resolver.resolve(spec)
print(f'Blueprint: {ir.metadata[\"blueprint\"]}')
print(f'Confidence: {ir.metadata[\"resolution_confidence\"]:.2f}')
print(f'Stacks: {ir.stacks}')
print(f'Tiers: {ir.tiers}')
print(f'Tasks: {len(ir.tasks[\"all\"])} total')
"
}
```

---

## 📱 Warp Mobile Integration

### Remote Development Setup

```bash
# Warp mobile SSH configuration for template system development
echo "🔧 Warp Mobile SSH Setup"
echo "========================"
echo ""
echo "Add this to your Warp mobile SSH config:"
echo ""
echo "Host template-system"
echo "    HostName your-server.com"
echo "    User your-username"
echo "    IdentityFile ~/.ssh/template-system-key"
echo "    RemoteCommand cd ~/projects/_templates && bash --login"
echo "    RequestTTY yes"
echo ""
echo "Then connect with: ssh template-system"
```

### Cloud Development Environment

```bash
# Warp cloud development setup
echo "☁️  Cloud Development Setup"
echo "==========================="
echo ""
echo "Docker development container:"
echo "docker run -it -v \$(pwd):/workspace python:3.11 bash"
echo ""
echo "Once in container:"
echo "cd /workspace"
echo "pip install -r requirements.txt"
echo "export PYTHONPATH=/workspace"
echo "python tests/validation/validate_templates.py --full"
```

---

## 🎨 Warp Customization

### Custom Warp Themes

```yaml
# Universal Template System Theme for Warp
# Save as: ~/.warp/themes/template-system.yaml
name: "Universal Template System"
colors:
  primary: "#2563eb"
  secondary: "#7c3aed"
  success: "#16a34a"
  warning: "#f59e0b"
  error: "#dc2626"
  info: "#0891b2"
  
syntax:
  keyword: "#7c3aed"
  string: "#16a34a"
  comment: "#6b7280"
  variable: "#2563eb"
  function: "#0891b2"
  
background:
  default: "#ffffff"
  selection: "#e0e7ff"
  
cursor:
  color: "#2563eb"
  style: "block"
```

### Warp Font Configuration

```yaml
# Recommended font settings for template development
font:
  family: "JetBrains Mono"
  size: 14
  weight: "regular"
  ligatures: true
  
# Template-specific font highlighting
font_highlights:
  template_placeholders:
    color: "#7c3aed"
    weight: "bold"
  template_code:
    color: "#2563eb"
    background: "#e0e7ff"
```

---

## 🔍 Warp Debugging Integration

### Debug Workflows

```bash
# Template debugging workflow in Warp
echo "🐛 Template Debugging Workflow"
echo "=============================="
echo ""
echo "1. Syntax Validation:"
python -m py_compile scripts/*.py
echo ""
echo "2. YAML Validation:"
python -c "import yaml; yaml.safe_load(open('tasks/task-index.yaml'))"
echo ""
echo "3. Template Syntax Check:"
find tasks/ -name "*.tpl.*" -exec echo "Checking {}" \; -exec python -c "
import jinja2
try:
    jinja2.Template(open('{}').read())
    print('✅ Valid')
except Exception as e:
    print(f'❌ Error: {e}')
" \;
echo ""
echo "4. File Structure Validation:"
python tests/validation/validate_templates.py --structure
```

### Performance Monitoring

```bash
# Warp performance monitoring for template operations
echo "⚡ Performance Monitoring"
echo "=========================="
echo ""
echo "Template generation performance:"
time python scripts/generate_reference_projects.py
echo ""
echo "Validation performance:"
time python tests/validation/validate_templates.py --full
echo ""
echo "Task detection performance:"
time python scripts/detect_project_tasks.py --description "test project"
```

---

## 📚 Warp Learning Resources

### Interactive Tutorial Blocks

```bash
# Warp interactive tutorial for template system
echo "🎓 Universal Template System Tutorial"
echo "======================================"
echo ""
echo "Step 1: Explore the system"
python scripts/list_tasks_by_category.py --summary
echo ""
echo "Step 2: Analyze a sample project"
python scripts/analyze_and_build.py --description "simple web API" --no-build
echo ""
echo "Step 3: Validate the system"
python tests/validation/validate_templates.py --structure
echo ""
echo "Step 4: Generate reference projects"
python scripts/generate_reference_projects.py
echo ""
echo "Tutorial complete! 🎉"
```

### Command Reference Cards

```bash
# Warp command reference for template system
echo "📋 Quick Command Reference"
echo "=========================="
echo ""
echo "Core Commands:"
echo "  ts-setup         - Blueprint-driven project setup (NEW - RECOMMENDED)"
echo "  ts-validate      - Validate all templates including blueprints"
echo "  ts-analyze       - Analyze project requirements (legacy)"
echo "  ts-tasks         - List available tasks"
echo "  ts-generate      - Generate reference projects"
echo ""
echo "Blueprint Commands (NEW):"
echo "  ts-blueprints    - List available blueprints"
echo "  ts-blueprint-info - Show blueprint details"
echo "  ts-blueprint-validate - Validate blueprint"
echo "  ts-blueprint-test - Test blueprint resolution"
echo ""
echo "Stack Commands:"
echo "  ts-python        - Setup Python project"
echo "  ts-node          - Setup Node.js project"
echo "  ts-go            - Setup Go project"
echo "  ts-flutter       - Setup Flutter project"
echo "  ts-react         - Setup React project"
echo "  ts-next          - Setup Next.js project"
echo ""
echo "Utility Commands:"
echo "  ts-explore       - Interactive exploration"
echo "  ts-create        - Interactive project creation"
echo "  ts-search        - Search templates"
```

---

## 🚀 Advanced Warp Features

### Multi-Session Workflows

```bash
# Warp multi-session workflow for template development
echo "🔄 Multi-Session Development Workflow"
echo "======================================"
echo ""
echo "Session 1: Template Creation"
echo "- Create task structure"
echo "- Write template files"
echo "- Update task-index.yaml"
echo ""
echo "Session 2: Validation"
echo "- Run validation suite"
echo "- Fix any issues"
echo "- Test template generation"
echo ""
echo "Session 3: Integration"
echo "- Update documentation"
echo "- Generate reference projects"
echo "- Test end-to-end workflow"
echo ""
echo "Session 4: Deployment"
echo "- Commit changes"
echo "- Update version"
echo "- Deploy to production"
```

### Warp AI Collaboration

```bash
# Warp AI collaboration for template development
echo "🤖 AI-Assisted Template Development"
echo "===================================="
echo ""
echo "AI Prompts for Template System:"
echo ""
echo "1. Template Creation:"
echo "\"Create a universal template for [feature] with proper placeholder syntax and tier-specific variations\""
echo ""
echo "2. Gap Analysis:"
echo "\"Analyze the Universal Template System and identify missing templates for [technology] stack\""
echo ""
echo "3. Optimization:"
echo "\"Review the following template and suggest optimizations for better performance and maintainability\""
echo ""
echo "4. Documentation:"
echo "\"Generate comprehensive documentation for the [task] template including usage examples and best practices\""
```

---

## 🎯 Best Practices for Warp Users

### Workflow Optimization

1. **Use Warp Blocks**: Organize related commands into reusable blocks, especially for blueprint workflows
2. **Custom Commands**: Create Warp commands for frequent operations, including blueprint management
3. **AI Integration**: Leverage Warp's AI features for blueprint-driven template generation
4. **Themes**: Use the template system theme for visual consistency
5. **Aliases**: Set up aliases for common template system and blueprint operations

### Performance Tips

1. **Parallel Validation**: Use Warp's multi-session capabilities for parallel validation
2. **Background Tasks**: Run long-running template generation in background sessions
3. **Caching**: Warp caches command results - use this for expensive operations like blueprint resolution
4. **History**: Utilize Warp's command history for repetitive template and blueprint operations

### Security Considerations

1. **Environment Variables**: Use Warp's secure environment variable storage
2. **SSH Keys**: Manage SSH keys through Warp's secure storage
3. **API Keys**: Store API keys in Warp's encrypted storage
4. **Audit Trail**: Warp maintains command history for audit purposes

---

**Remember**: Warp is designed for modern development workflows. Leverage its AI features, block-based organization, and cross-platform capabilities to maximize your productivity with the Universal Template System. The combination of Warp's advanced terminal features and the template system's blueprint-driven capabilities creates a powerful development environment that prioritizes product archetypes over technology stacks.
