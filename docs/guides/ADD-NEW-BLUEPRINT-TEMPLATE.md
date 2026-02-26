# New Blueprint Template

**Purpose**: Complete template for adding new blueprints to the Universal Template System
**Version**: 4.0
**Target**: Production-ready blueprint integration with autonomous workflow support

---

## 🏗️ Required Directory Structure

Create the following directory structure for your new blueprint:

```
blueprints/{blueprint_name}/
├── 📄 BLUEPRINT.md                 # Human-readable blueprint documentation
├── 📄 blueprint.meta.yaml          # Machine-readable blueprint metadata
└── 📁 overlays/                    # Stack-specific template extensions
    ├── 📁 flutter/                 # Flutter overlay templates
    │   ├── 📁 lib/                  # Main overlay files
    │   │   ├── 📄 main.tpl.dart     # Entry point with blueprint integration
    │   │   ├── 📄 app-structure.tpl.dart  # Blueprint-specific app structure
    │   │   └── 📁 [feature modules]  # Blueprint feature overlays
    │   └── 📁 services/             # Service overlays
    │       └── 📁 [blueprint services]  # Blueprint-specific services
    ├── 📁 python/                  # Python overlay templates
    ├── 📁 node/                    # Node.js overlay templates
    ├── 📁 go/                      # Go overlay templates
    ├── 📁 react/                   # React overlay templates
    ├── 📁 react_native/            # React Native overlay templates
    ├── 📁 r/                       # R overlay templates
    └── 📁 sql/                     # SQL overlay templates
```

---

## 📋 Essential Files Template

### 1. Blueprint Metadata (blueprint.meta.yaml)

```yaml
# Blueprint Metadata Configuration
id: {blueprint_name}
version: 1
name: "{Human Readable Blueprint Name}"
category: "{blueprint_category}"

description: >
  {Comprehensive blueprint description explaining the product archetype,
  target use cases, and key characteristics}

# What kind of thing this is
type: "app"                     # "app" | "pipeline" | "api" | "agent_system" | "dashboard"

# Which stacks this blueprint is designed for
stacks:
  required:
    - {primary_stack}            # MUST be present (e.g., flutter, python)
  recommended:
    - {secondary_stack}          # optional but preferred (e.g., python for backend)
  supported:
    - {additional_stack_1}
    - {additional_stack_2}

# Tier recommendations
tier_defaults:
  overall: core                  # default if user doesn't specify
  frontend: mvp                  # e.g. mobile UI can be lighter tier
  backend: core

# Which tasks this blueprint expects
tasks:
  required:                      # always enabled if available
    - {required_task_1}
    - {required_task_2}
    - {required_task_3}
  recommended:                   # auto-on, user can disable
    - {recommended_task_1}
    - {recommended_task_2}
  optional:                       # shown in UI as extra checkboxes
    - {optional_task_1}
    - {optional_task_2}

# Constraints / invariants this blueprint enforces
constraints:
  {constraint_1}: true
  {constraint_2}: {value}
  {constraint_3}:
    - {option_1}
    - {option_2}

# Which templates/overlays to apply on top of base stack templates
overlays:
  {stack_name}:
    enabled: true
    mode: "extend"                # "extend" | "override"
    apply_to:
      - "{target_directory_1}"
      - "{target_directory_2}"

# Hooks for the compiler/agents
hooks:
  pre_scaffold:
    - "scripts/blueprints/{blueprint_name}/pre_scaffold.py"
  post_scaffold:
    - "scripts/blueprints/{blueprint_name}/post_scaffold.py"

# LLM hints
llm:
  prompt_preamble: |
    {LLM prompt preamble for guiding AI generation}
  architectural_keywords:
    - "{keyword_1}"
    - "{keyword_2}"
    - "{keyword_3}"
```

### 2. Blueprint Documentation (BLUEPRINT.md)

```markdown
# {Blueprint Name}

**Version**: 1.0  
**Category**: {blueprint_category}  
**Type**: {blueprint_type}

{One-sentence blueprint description}

---

## 🎯 **Product Archetype**

### **Core Philosophy**
{Detailed explanation of the blueprint's philosophy and approach}

### **Key Characteristics**
- **Characteristic 1**: {Description}
- **Characteristic 2**: {Description}
- **Characteristic 3**: {Description}
- **Characteristic 4**: {Description}
- **Characteristic 5**: {Description}

### **Target Use Cases**
- {Use case 1}
- {Use case 2}
- {Use case 3}
- {Use case 4}
- {Use case 5}

---

## 🏗️ **Architecture Patterns**

### **Primary Architecture**
```
{Architecture diagram or description}
```

### **Key Components**
1. **{Component 1}**: {Description and purpose}
2. **{Component 2}**: {Description and purpose}
3. **{Component 3}**: {Description and purpose}

### **Design Principles**
- **Principle 1**: {Description}
- **Principle 2**: {Description}
- **Principle 3**: {Description}

---

## 📊 **Technical Stack**

### **Required Stacks**
- **{Primary Stack}**: {Reason for requirement}
- **{Secondary Stack}**: {Reason for requirement}

### **Supported Stacks**
- **{Additional Stack 1}**: {Integration notes}
- **{Additional Stack 2}**: {Integration notes}

### **Tier Recommendations**
- **MVP**: {MVP-specific considerations}
- **Core**: {Core-tier features}
- **Enterprise**: {Enterprise enhancements}

---

## 🔧 **Implementation Patterns**

### **Core Implementation**
{Detailed implementation guidance}

### **Stack-Specific Patterns**

#### Flutter Implementation
{Flutter-specific implementation details}

#### Python Implementation
{Python-specific implementation details}

#### Node.js Implementation
{Node.js-specific implementation details}

---

## 📋 **Task Integration**

### **Required Tasks**
- **{Task 1}**: {Integration purpose}
- **{Task 2}**: {Integration purpose}
- **{Task 3}**: {Integration purpose}

### **Recommended Tasks**
- **{Task 4}**: {Integration purpose}
- **{Task 5}**: {Integration purpose}

### **Optional Tasks**
- **{Task 6}**: {Integration purpose}
- **{Task 7}**: {Integration purpose}

---

## 🚀 **Quick Start**

```bash
# Generate project with {blueprint_name} blueprint
python scripts/setup-project.py --auto --name "MyProject" --description "project with {blueprint_name}"

# Manual blueprint selection
python scripts/setup-project.py --manual-blueprint {blueprint_name} --name "MyProject"
```

---

## 📚 **Documentation**

- [Blueprint Metadata](./blueprint.meta.yaml)
- [Overlay Templates](./overlays/)
- [System Integration](../SYSTEM-MAP.md)

---

**See [SYSTEM-MAP.md](../SYSTEM-MAP.md) for complete system architecture**
```

### 3. Stack Overlay Templates

For each supported stack, create overlay templates:

#### Flutter Overlay Template (main.tpl.dart)
```dart
// Universal Template System - {Blueprint Name} Blueprint
// Generated: {date}
// Purpose: {Blueprint Name} Flutter overlay
// Tier: blueprint
// Stack: flutter
// Category: overlay

/// {Blueprint Name} Blueprint - Flutter Implementation
/// 
/// {Blueprint description for Flutter}
/// 
/// CONFIDENTIAL - INTERNAL USE ONLY
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/config/app_config.dart';
import '../core/theme/app_theme.dart';
import '../features/{feature}/presentation/{feature}_page.dart';

/// Main entry point with {blueprint_name} integration
class {{PROJECT_NAME}}App extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return MaterialApp(
      title: '{{PROJECT_NAME}}',
      theme: AppTheme.primary,
      home: {{BLUEPRINT_SHELL}}(),
    );
  }
}

/// {Blueprint Name} specific app shell
class {{BLUEPRINT_SHELL}} extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      appBar: AppBar(
        title: Text('{{PROJECT_NAME}}'),
      ),
      body: {{MAIN_FEATURE_WIDGET}}(),
      bottomNavigationBar: {{BLUEPRINT_NAVIGATION}}(),
    );
  }
}
```

#### Python Overlay Template (main.tpl.py)
```python
# Universal Template System - {Blueprint Name} Blueprint
# Generated: {date}
# Purpose: {Blueprint Name} Python overlay
# Tier: blueprint
# Stack: python
# Category: overlay

"""{Blueprint Name} Blueprint - Python Implementation"""

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .features.{feature} import router as {feature}_router

app = FastAPI(
    title="{{PROJECT_NAME}}",
    description="{Blueprint description}",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include blueprint-specific routers
app.include_router({feature}_router, prefix="/api/v1/{feature}")

@app.get("/")
async def root():
    return {"message": "{{PROJECT_NAME}} - {Blueprint Name} API"}
```

---

## 🔧 Integration Steps

### 1. Create Directory Structure
```bash
mkdir -p blueprints/{blueprint_name}/overlays/{flutter,python,node,go,react,react_native,r,sql}
mkdir -p blueprints/{blueprint_name}/overlays/flutter/{lib,services}
```

### 2. Create Blueprint Metadata
- Create blueprint.meta.yaml with complete configuration
- Define stack requirements and constraints
- Specify task dependencies and recommendations
- Configure overlay mappings

### 3. Create Blueprint Documentation
- Create BLUEPRINT.md with comprehensive documentation
- Include architecture patterns and implementation guidance
- Document stack-specific considerations
- Add quick start instructions

### 4. Create Stack Overlays
- Implement overlay templates for each supported stack
- Follow stack-specific conventions and patterns
- Ensure blueprint integration points are clear
- Add blueprint-specific features and services

### 5. Create Hook Scripts (Optional)
```bash
mkdir -p scripts/blueprints/{blueprint_name}
# Create pre_scaffold.py and post_scaffold.py if needed
```

### 6. Update System Integration
- Add blueprint to blueprint resolver
- Update validation scripts
- Test autonomous workflow integration

### 7. Validate Integration
```bash
# Run comprehensive validation
python scripts/validate-templates.py --full

# Test blueprint generation
python scripts/setup-project.py --manual-blueprint {blueprint_name} --name "TestProject"

# Validate generated project
cd TestProject/
# Follow project-specific instructions
```

---

## 📊 System Integration

### Blueprint Resolver Integration
Your blueprint must integrate with the 7-step blueprint resolution algorithm:

1. **Blueprint Selection**: User selects or auto-detects blueprint
2. **Stack Constraints**: Apply blueprint stack requirements
3. **Tier Defaults**: Apply blueprint tier recommendations
4. **Task Requirements**: Include blueprint required tasks
5. **Resolution Algorithm**: Generate intermediate representation
6. **Overlay Application**: Apply stack-specific overlays
7. **Project Generation**: Generate final project structure

### Validation Requirements
- Blueprint metadata must be valid YAML
- All required overlays must exist
- Stack constraints must be satisfiable
- Task dependencies must be resolvable
- Generated projects must compile and run

---

## 📊 Validation Checklist

- [ ] Directory structure created correctly
- [ ] blueprint.meta.yaml with complete metadata
- [ ] BLUEPRINT.md with comprehensive documentation
- [ ] Stack overlays created for all supported stacks
- [ ] Hook scripts implemented (if required)
- [ ] Blueprint resolver integration complete
- [ ] Validation script passes (0 errors)
- [ ] Blueprint generation works correctly
- [ ] Generated projects compile and run
- [ ] Autonomous workflow integration tested

---

## 🎯 Success Metrics

Your new blueprint is complete when:
- ✅ Blueprint metadata is valid and complete
- ✅ Documentation is comprehensive and clear
- ✅ Stack overlays implemented for all supported stacks
- ✅ Integration with blueprint resolver works
- ✅ Validation passes with 0 errors
- ✅ Autonomous workflow generates working projects
- ✅ Generated projects follow blueprint patterns

---

## 📚 Blueprint Categories

Choose from existing blueprint categories or create new ones:

### Existing Categories
- **micro_saas**: Single-purpose SaaS applications
- **enterprise**: Large-scale business applications
- **mobile_first**: Mobile-centric applications
- **data_pipeline**: Data processing and analytics
- **api_service**: API-centric services
- **dashboard**: Analytics and monitoring dashboards

### Creating New Categories
If creating a new blueprint category:
1. Ensure clear differentiation from existing categories
2. Provide compelling use cases and examples
3. Document architectural patterns specific to the category

---

## 🔧 Advanced Features

### Conditional Overlays
```yaml
overlays:
  flutter:
    enabled: true
    condition: "tier == 'enterprise'"  # Only apply for enterprise tier
    mode: "extend"
    apply_to:
      - "lib/enterprise/"
```

### Dynamic Configuration
```yaml
llm:
  prompt_preamble: |
    Dynamic prompt based on user input: {{USER_DESCRIPTION}}
  conditional_keywords:
    enterprise: ["scalability", "security", "compliance"]
    mvp: ["simplicity", "speed", "core"]
```

### Hook Script Examples
```python
# scripts/blueprints/{blueprint_name}/pre_scaffold.py
def pre_scaffold(config):
    """Run before project generation"""
    # Validate blueprint-specific requirements
    # Generate additional configuration
    # Prepare custom templates
    pass

# scripts/blueprints/{blueprint_name}/post_scaffold.py
def post_scaffold(project_path):
    """Run after project generation"""
    # Apply post-processing
    # Generate additional files
    # Setup development environment
    pass
```

---

**See [CLAUDE.md](./CLAUDE.md), [AGENTS.md](./AGENTS.md), and [WARP.md](./WARP.md) for complete system documentation**
