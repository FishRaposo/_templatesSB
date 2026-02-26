# New Task Template

**Purpose**: Complete template for adding new tasks to the Universal Template System
**Version**: 4.0
**Target**: Production-ready task integration with full stack support

---

## 🏗️ Required Directory Structure

Create the following directory structure for your new task:

```
tasks/{task_name}/
├── 📄 meta.yaml                    # Task metadata and configuration
├── 📁 universal/                   # Universal templates (apply to all stacks)
│   ├── 📁 code/                    # Universal code templates
│   │   ├── 📄 CONFIG.tpl.yaml      # Task configuration template
│   │   ├── 📄 {TASK}-SKELETON.tpl.md  # Main task implementation
│   │   └── 📄 [additional code templates]
│   ├── 📁 docs/                    # Universal documentation
│   │   └── 📄 README.tpl.md        # Task documentation
│   └── 📁 tests/                   # Universal test templates
│       └── 📄 {TASK}-TESTS.tpl.md  # Test patterns
└── 📁 stacks/                      # Stack-specific implementations
    ├── 📁 flutter/                 # Flutter-specific templates
    ├── 📁 python/                  # Python-specific templates
    ├── 📁 node/                    # Node.js-specific templates
    ├── 📁 go/                      # Go-specific templates
    ├── 📁 react/                   # React-specific templates
    ├── 📁 react_native/            # React Native templates
    ├── 📁 r/                       # R-specific templates
    └── 📁 sql/                     # SQL-specific templates
```

---

## 📋 Essential Files Template

### 1. Task Metadata (meta.yaml)

```yaml
# Task Metadata Configuration
task_name: "{task_name}"
display_name: "{Human Readable Task Name}"
description: "{Comprehensive task description}"
category: "{virtual_category}"
version: "1.0.0"

# Task Configuration
requires_database: false
requires_auth: false
requires_api: false
complexity: "basic|intermediate|advanced"

# Supported Stacks
supported_stacks:
  - flutter
  - python
  - node
  - go
  - react
  - react_native
  - r
  - sql

# Dependencies
task_dependencies: []
optional_dependencies: []

# File Mappings (automatically generated)
file_mappings:
  universal:
    - "tasks/{task_name}/universal/code/CONFIG.tpl.yaml"
    - "tasks/{task_name}/universal/code/{TASK}-SKELETON.tpl.md"
    - "tasks/{task_name}/universal/docs/README.tpl.md"
    - "tasks/{task_name}/universal/tests/{TASK}-TESTS.tpl.md"
  stacks:
    flutter: ["tasks/{task_name}/stacks/flutter/*.dart"]
    python: ["tasks/{task_name}/stacks/python/*.py"]
    node: ["tasks/{task_name}/stacks/node/*.js"]
    go: ["tasks/{task_name}/stacks/go/*.go"]
    react: ["tasks/{task_name}/stacks/react/*.jsx"]
    react_native: ["tasks/{task_name}/stacks/react_native/*.jsx"]
    r: ["tasks/{task_name}/stacks/r/*.R"]
    sql: ["tasks/{task_name}/stacks/sql/*.sql"]
```

### 2. Universal Code Templates

#### CONFIG.tpl.yaml Template
```yaml
# Universal Template System - {Task Name} Task
# Generated: {date}
# Purpose: Task configuration template
# Tier: universal
# Stack: all
# Category: configuration

---
# {Task Name} Configuration
task_name: "{task_name}"
enabled: true

# Task Settings
{task_name}_config:
  # Basic configuration
  enabled: true
  debug_mode: false
  
  # Performance settings
  timeout: 30
  retry_attempts: 3
  
  # Feature flags
  {{FEATURE_FLAGS}}
  
  # Custom settings
  {{CUSTOM_SETTINGS}}

# Integration Points
integrations:
  database:
    enabled: {{REQUIRES_DATABASE}}
    type: "{{DATABASE_TYPE}}"
  auth:
    enabled: {{REQUIRES_AUTH}}
    provider: "{{AUTH_PROVIDER}}"
  api:
    enabled: {{REQUIRES_API}}
    version: "{{API_VERSION}}"

# Stack-Specific Configuration
stack_config:
  flutter:
    package_name: "{{FLUTTER_PACKAGE_NAME}}"
    min_sdk_version: "{{FLUTTER_MIN_SDK}}"
  python:
    package_name: "{{PYTHON_PACKAGE_NAME}}"
    min_python_version: "{{PYTHON_MIN_VERSION}}"
  node:
    package_name: "{{NODE_PACKAGE_NAME}}"
    min_node_version: "{{NODE_MIN_VERSION}}"
  go:
    module_name: "{{GO_MODULE_NAME}}"
    min_go_version: "{{GO_MIN_VERSION}}"
```

#### Main Task Skeleton Template
```markdown
# Universal Template System - {Task Name} Task
# Generated: {date}
# Purpose: {Task description}
# Tier: universal
# Stack: all
# Category: implementation

---

# {Task Name} Implementation

## Overview
{Comprehensive overview of the task implementation}

## Core Components
- **Component 1**: Description and implementation
- **Component 2**: Description and implementation
- **Component 3**: Description and implementation

## Implementation Pattern
```{{LANGUAGE}}
// Main task implementation
class {{TASK_CLASS_NAME}} {
  constructor(config) {
    this.config = config;
    this.{{COMPONENT_NAME}} = new {{COMPONENT_CLASS}}();
  }
  
  async execute() {
    // Main task logic
    try {
      const result = await this.{{MAIN_METHOD}}();
      return result;
    } catch (error) {
      this.handleError(error);
    }
  }
  
  {{ADDITIONAL_METHODS}}
}
```

## Stack-Specific Considerations
- **Flutter**: {{FLUTTER_SPECIFIC}}
- **Python**: {{PYTHON_SPECIFIC}}
- **Node.js**: {{NODE_SPECIFIC}}
- **Go**: {{GO_SPECIFIC}}

## Integration Points
- Database: {{DATABASE_INTEGRATION}}
- Authentication: {{AUTH_INTEGRATION}}
- API: {{API_INTEGRATION}}

---

**See [SYSTEM-MAP.md](../SYSTEM-MAP.md) for complete system architecture**
```

### 3. Universal Documentation Template

#### README.tpl.md Template
```markdown
# Universal Template System - {Task Name} Task
# Generated: {date}
# Purpose: Task documentation template
# Tier: universal
# Stack: all
# Category: documentation

---

# {Task Name}

**Purpose**: {Task purpose and primary use cases}
**Category**: {virtual_category}
**Complexity**: {complexity}
**Supported Stacks**: flutter, python, node, go, react, react_native, r, sql

## 🚀 Quick Start

```bash
# Generate project with {task_name} task
python scripts/setup-project.py --auto --name "MyProject" --description "project with {task_name}"

# Manual task selection
python scripts/setup-project.py --manual-task {task_name} --manual-stack {stack} --name "MyProject"
```

## 📋 Task Overview

{Detailed task description explaining what this task accomplishes}

### Key Features
- **Feature 1**: Description
- **Feature 2**: Description
- **Feature 3**: Description

### Use Cases
- **Use Case 1**: Description
- **Use Case 2**: Description
- **Use Case 3**: Description

## 🏗️ Implementation

### Core Components
1. **{{COMPONENT_1}}**: {{COMPONENT_1_DESCRIPTION}}
2. **{{COMPONENT_2}}**: {{COMPONENT_2_DESCRIPTION}}
3. **{{COMPONENT_3}}**: {{COMPONENT_3_DESCRIPTION}}

### Configuration
```yaml
{task_name}:
  enabled: true
  {{CONFIGURATION_OPTIONS}}
```

## 🔧 Stack-Specific Implementation

### Flutter
{{FLUTTER_IMPLEMENTATION_DETAILS}}

### Python
{{PYTHON_IMPLEMENTATION_DETAILS}}

### Node.js
{{NODE_IMPLEMENTATION_DETAILS}}

### Go
{{GO_IMPLEMENTATION_DETAILS}}

## 🧪 Testing

{{TESTING_STRATEGIES}}

## 📚 Documentation

- [Implementation Guide](./code/{TASK}-SKELETON.tpl.md)
- [Configuration Guide](./code/CONFIG.tpl.yaml)
- [Testing Guide](./tests/{TASK}-TESTS.tpl.md)

## 🔗 Dependencies

{{TASK_DEPENDENCIES}}

## 🚀 Integration

{Integration instructions with other tasks and system components}

---

**See [SYSTEM-MAP.md](../SYSTEM-MAP.md) for complete system architecture**
```

### 4. Universal Test Template

#### {TASK}-TESTS.tpl.md Template
```markdown
# Universal Template System - {Task Name} Task
# Generated: {date}
# Purpose: Task testing template
# Tier: universal
# Stack: all
# Category: testing

---

# {Task Name} Testing Strategy

## Testing Approach
{Comprehensive testing strategy for the task}

## Test Categories

### Unit Tests
{{UNIT_TEST_DESCRIPTION}}

### Integration Tests
{{INTEGRATION_TEST_DESCRIPTION}}

### End-to-End Tests
{{E2E_TEST_DESCRIPTION}}

## Stack-Specific Testing

### Flutter Testing
```dart
// Example test structure
void main() {
  group('{Task Name} Tests', () {
    test('should initialize correctly', () {
      // Test implementation
    });
    
    test('should handle edge cases', () {
      // Test implementation
    });
  });
}
```

### Python Testing
```python
# Example test structure
import pytest
from {module} import {TaskClass}

class Test{TaskName}:
    def test_initialization(self):
        # Test implementation
        pass
    
    def test_main_functionality(self):
        # Test implementation
        pass
```

### Node.js Testing
```javascript
// Example test structure
const { TaskClass } = require('../src/{module}');

describe('{Task Name}', () => {
  test('should initialize correctly', () => {
    // Test implementation
  });
  
  test('should handle main functionality', () => {
    // Test implementation
  });
});
```

## Test Data
{{TEST_DATA_STRATEGY}}

## Mock Strategy
{{MOCK_STRATEGY}}

## Coverage Requirements
- Unit Tests: > 80%
- Integration Tests: Core workflows
- E2E Tests: Critical paths

---

**See [SYSTEM-MAP.md](../SYSTEM-MAP.md) for complete system architecture**
```

### 5. Stack-Specific Implementation Templates

For each supported stack, create stack-specific implementations:

#### Flutter Stack Template
```dart
// Universal Template System - {Task Name} Task
// Generated: {date}
// Purpose: Flutter implementation
// Tier: stack-specific
// Stack: flutter
// Category: implementation

/// {Task Name} Flutter Implementation
/// 
/// CONFIDENTIAL - INTERNAL USE ONLY
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Flutter-specific {task name} implementation
class {{TASK_NAME_FLUTTER}} extends ConsumerWidget {
  final {{TASK_NAME}}Config config;
  
  const {{TASK_NAME_FLUTTER}}({
    Key? key,
    required this.config,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Container(
      child: {{MAIN_WIDGET_IMPLEMENTATION}},
    );
  }
}

/// Flutter-specific configuration
class {{TASK_NAME}}Config {
  final bool enabled;
  final {{ADDITIONAL_CONFIG_FIELDS}};
  
  const {{TASK_NAME}}Config({
    required this.enabled,
    {{ADDITIONAL_CONFIG_PARAMETERS}},
  });
}

/// Flutter-specific service
class {{TASK_NAME}}Service {
  final {{TASK_NAME}}Config config;
  
  {{TASK_NAME}}Service(this.config);
  
  Future<{{RETURN_TYPE}}> execute{{TASK_NAME}}() async {
    // Flutter-specific implementation
    {{FLUTTER_IMPLEMENTATION}};
  }
}
```

#### Python Stack Template
```python
# Universal Template System - {Task Name} Task
# Generated: {date}
# Purpose: Python implementation
# Tier: stack-specific
# Stack: python
# Category: implementation

"""{Task Name} Python Implementation"""

from typing import Dict, Any, Optional
import asyncio
import logging

logger = logging.getLogger(__name__)

class {{TaskNamePython}}:
    """Python-specific {task name} implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', True)
        {{ADDITIONAL_INIT_CODE}}
    
    async def execute_{{task_name}}(self) -> Dict[str, Any]:
        """Execute the {task name} task"""
        try:
            # Python-specific implementation
            result = await self._{{main_method}}()
            return result
        except Exception as e:
            logger.error(f"Error in {task_name}: {e}")
            raise
    
    async def _{{main_method}}(self) -> Dict[str, Any]:
        """Main implementation method"""
        {{PYTHON_IMPLEMENTATION}}
        pass
    
    def _validate_config(self) -> bool:
        """Validate configuration"""
        {{VALIDATION_CODE}}
        return True
```

#### Node.js Stack Template
```javascript
// Universal Template System - {Task Name} Task
// Generated: {date}
// Purpose: Node.js implementation
// Tier: stack-specific
// Stack: node
// Category: implementation

/**
 * {Task Name} Node.js Implementation
 */

const EventEmitter = require('events');

class {{TaskNameNode}} extends EventEmitter {
  constructor(config) {
    super();
    this.config = config;
    this.enabled = config.enabled || true;
    {{ADDITIONAL_INIT_CODE}}
  }
  
  async execute{{TaskName}}() {
    try {
      // Node.js-specific implementation
      const result = await this._{{mainMethod}}();
      this.emit('success', result);
      return result;
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }
  
  async _{{mainMethod}}() {
    // Main implementation method
    {{NODE_IMPLEMENTATION}}
  }
  
  _validateConfig() {
    // Configuration validation
    {{VALIDATION_CODE}}
    return true;
  }
}

module.exports = {{TaskNameNode}};
```

---

## 🔧 Integration Steps

### 1. Create Directory Structure
```bash
mkdir -p tasks/{task_name}/templates/{universal,stacks}
mkdir -p tasks/{task_name}/templates/universal/{code,docs,tests}
mkdir -p tasks/{task_name}/templates/stacks/{flutter,python,node,go,react,react_native,r,sql}
```

### 2. Create Universal Templates
- Create meta.yaml with task metadata
- Create universal code templates (CONFIG, main skeleton)
- Create universal documentation (README)
- Create universal test templates

### 3. Create Stack-Specific Templates
- Implement stack-specific versions for each supported stack
- Follow stack-specific conventions and patterns
- Ensure consistency with existing stack implementations

### 4. Update Task Index
- Add task to task-index.yaml
- Include in appropriate virtual category
- Add file mappings for all templates
- Define dependencies and relationships

### 5. Validate Integration
```bash
# Run comprehensive validation
python scripts/validate-templates.py --full

# Test task generation
python scripts/setup-project.py --manual-task {task_name} --manual-stack {stack} --name "TestProject"

# Validate generated project
cd TestProject/
# Follow project-specific instructions
```

---

## 📊 Task Index Integration

### Adding to task-index.yaml

1. **Add to Virtual Category**:
```yaml
virtual_categories:
  {category_name}:
    display_name: "{Category Display Name}"
    description: "{Category description}"
    tasks:
    - {task_name}
```

2. **Add Task Definition**:
```yaml
tasks:
  {task_name}:
    display_name: "{Human Readable Task Name}"
    description: "{Task description}"
    category: "{virtual_category}"
    complexity: "basic|intermediate|advanced"
    supported_stacks: ["flutter", "python", "node", "go", "react", "react_native", "r", "sql"]
    dependencies: []
    optional_dependencies: []
```

3. **Add File Mappings**:
```yaml
file_mappings:
  {task_name}:
    universal:
      - "tasks/{task_name}/templates/universal/code/CONFIG.tpl.yaml"
      - "tasks/{task_name}/templates/universal/code/{TASK}-SKELETON.tpl.md"
      - "tasks/{task_name}/templates/universal/docs/README.tpl.md"
      - "tasks/{task_name}/templates/universal/tests/{TASK}-TESTS.tpl.md"
    stacks:
      flutter: ["tasks/{task_name}/templates/stacks/flutter/*.dart"]
      python: ["tasks/{task_name}/templates/stacks/python/*.py"]
      node: ["tasks/{task_name}/templates/stacks/node/*.js"]
      go: ["tasks/{task_name}/templates/stacks/go/*.go"]
      react: ["tasks/{task_name}/templates/stacks/react/*.jsx"]
      react_native: ["tasks/{task_name}/templates/stacks/react_native/*.jsx"]
      r: ["tasks/{task_name}/templates/stacks/r/*.R"]
      sql: ["tasks/{task_name}/templates/stacks/sql/*.sql"]
```

---

## 📊 Validation Checklist

- [ ] Directory structure created correctly
- [ ] meta.yaml with complete metadata
- [ ] Universal templates created (4 minimum)
- [ ] Stack-specific implementations for all supported stacks
- [ ] Task added to task-index.yaml
- [ ] File mappings configured correctly
- [ ] Dependencies defined in task index
- [ ] Validation script passes (0 errors)
- [ ] Task generation works for all stacks
- [ ] Documentation is comprehensive
- [ ] Test templates included

---

## 🎯 Success Metrics

Your new task is complete when:
- ✅ All universal templates created with proper headers
- ✅ Stack-specific implementations for all supported stacks
- ✅ Task index integration complete
- ✅ Validation passes with 0 errors
- ✅ Task generation works correctly
- ✅ Documentation is comprehensive
- ✅ Test templates included for all stacks

---

## 📚 Virtual Categories

Choose from existing virtual categories or create new ones:

### Existing Categories
- **web-api**: Web scraping, APIs, dashboards
- **auth-users-billing**: Authentication, users, payments
- **background-automation**: Jobs, scheduling, workflows
- **data-analytics-ml**: Data processing, analytics, ML
- **content-marketing**: Content generation, SEO, campaigns
- **devops-infrastructure**: CI/CD, monitoring, deployment
- **business-operations**: Admin panels, reports, management

### Creating New Categories
If creating a new virtual category:
1. Add to virtual_categories section
2. Include display_name and description
3. Add at least 2-3 tasks to establish the category

---

**See [CLAUDE.md](./CLAUDE.md), [AGENTS.md](./AGENTS.md), and [WARP.md](./WARP.md) for complete system documentation**
