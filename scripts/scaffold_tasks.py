#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Task Scaffolding Script for {{PROJECT_NAME}} Template System
Generates directory structure and basic templates for all 46 tasks.

Usage: python scripts/scaffold_tasks.py [--task TASK_NAME] [--category CATEGORY_NAME]
"""

import os
import sys
import yaml
import shutil
from pathlib import Path
from typing import Dict, List, Any
import argparse

# Add templates directory to path
SCRIPT_DIR = Path(__file__).parent
TEMPLATES_DIR = SCRIPT_DIR.parent
TASKS_DIR = TEMPLATES_DIR / "tasks"

def load_task_index() -> Dict[str, Any]:
    """Load the expanded task index."""
    index_file = TASKS_DIR / "expanded-task-index.yaml"
    if not index_file.exists():
        raise FileNotFoundError(f"Task index not found: {index_file}")
    
    with open(index_file, 'r') as f:
        return yaml.safe_load(f)

def create_task_directory(task_name: str, task_data: Dict[str, Any]) -> Path:
    """Create the complete directory structure for a task."""
    task_dir = TASKS_DIR / task_name
    
    # Create main directories
    directories = [
        task_dir / "universal" / "code",
        task_dir / "universal" / "tests", 
        task_dir / "universal" / "docs",
    ]
    
    # Create stack-specific directories for allowed stacks
    for stack in task_data.get('allowed_stacks', []):
        if stack not in ['all', 'agnostic']:  # Skip special stack types
            stack_dirs = [
                task_dir / "stacks" / stack / "base" / "code",
                task_dir / "stacks" / stack / "base" / "tests",
                task_dir / "stacks" / stack / "base" / "docs",
            ]
            directories.extend(stack_dirs)
    
    # Create all directories
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    
    return task_dir

def create_meta_yaml(task_name: str, task_data: Dict[str, Any], task_dir: Path):
    """Create the task metadata file."""
    meta_content = {
        'name': task_name,
        'description': task_data.get('description', ''),
        'version': '1.0.0',
        'created': '{{DATE}}',
        'author': '{{AUTHOR}}',
        'categories': task_data.get('categories', []),
        'compatibility': {
            'default_stacks': task_data.get('default_stacks', []),
            'allowed_stacks': task_data.get('allowed_stacks', []),
            'recommended_tiers': task_data.get('recommended_tier', {})
        },
        'features': [
            f"Core {task_name.replace('-', ' ')} functionality",
            "Configurable settings and options",
            "Comprehensive error handling",
            "Integration with {{PROJECT_NAME}} architecture"
        ],
        'dependencies': {
            'universal': ['logging', 'configuration'],
            **{stack: [] for stack in task_data.get('allowed_stacks', []) if stack not in ['all', 'agnostic']}
        }
    }
    
    meta_file = task_dir / "meta.yaml"
    with open(meta_file, 'w', encoding='utf-8') as f:
        yaml.dump(meta_content, f, default_flow_style=False, indent=2)

def create_universal_service_skeleton(task_name: str, task_data: Dict[str, Any], task_dir: Path):
    """Create the universal service skeleton template."""
    service_name = ''.join(word.capitalize() for word in task_name.split('-'))
    
    content = f"""# {service_name} Service Skeleton

## Purpose
{task_data.get('description', 'Service for ' + task_name.replace('-', ' '))}

## Interface
```{{{{EXTENSION}}}}
// Universal interface for {task_name} service
interface {service_name}Service {{
    // Core methods that all implementations should provide
    async execute(input: InputType): Promise<OutputType>;
    async validate(input: InputType): Promise<boolean>;
    async getStatus(): Promise<ServiceStatus>;
}}
```

## Implementation Requirements
All stack-specific implementations must provide:
- [ ] Core service class implementing the interface
- [ ] Error handling and logging
- [ ] Configuration management
- [ ] Health check endpoints
- [ ] Input validation and sanitization

## Stack-Specific Considerations
- **Python**: Use async/await patterns, implement with FastAPI/Flask
- **Go**: Use goroutines for concurrency, implement with net/http
- **Node.js**: Use Promises/async-await, implement with Express
- **React/Next.js**: Use hooks and modern patterns
- **Flutter**: Use async/await and provider patterns

## Variables Available
- `{{{{PROJECT_NAME}}}}`: Project name
- `{{{{TASK_NAME}}}}`: Task name ({task_name})
- `{{{{STACK}}}}`: Target stack
- `{{{{TIER}}}}`: Target tier
- `{{{{EXTENSION}}}}`: File extension for target stack

## Configuration
The service expects configuration in `config/{task_name}.yaml`:

```yaml
{task_name}:
  enabled: true
  timeout: 30
  retry_attempts: 3
  # Stack-specific settings will be added here
```
"""
    
    skeleton_file = task_dir / "universal" / "code" / f"{task_name.upper()}-SKELETON.tpl.md"
    with open(skeleton_file, 'w', encoding='utf-8') as f:
        f.write(content)

def create_config_template(task_name: str, task_data: Dict[str, Any], task_dir: Path):
    """Create the configuration template."""
    content = f"""# {task_name.replace('-', ' ').title()} Configuration
# Generated for {{{{PROJECT_NAME}}}} using {{{{STACK}}}} stack

# Service Configuration
service:
  name: "{{{{PROJECT_NAME}}}}-{task_name}"
  version: "1.0.0"
  enabled: true

# Task-Specific Settings
{task_name}:
  # Core configuration options
  timeout: 30
  retry_attempts: 3
  retry_delay: 1
  
  # Performance Settings
  max_concurrent: 10
  batch_size: 100
  
  # Stack-Specific Defaults
  {{% if STACK == "python" %}}
  framework: "fastapi"
  {{% elif STACK == "go" %}}
  framework: "net/http"
  {{% elif STACK == "node" %}}
  framework: "express"
  {{% elif STACK == "nextjs" %}}
  framework: "next.js"
  {{% elif STACK == "react" %}}
  framework: "react"
  {{% elif STACK == "flutter" %}}
  framework: "flutter"
  {{% endif %}}

# Logging Configuration
logging:
  level: "info"
  format: "json"
  
# Monitoring
monitoring:
  enabled: true
  metrics_port: 9090
  health_check: "/health"

# Security
security:
  auth_required: false
  rate_limit: 100
  cors_enabled: true
"""
    
    config_file = task_dir / "universal" / "code" / "CONFIG.tpl.yaml"
    with open(config_file, 'w', encoding='utf-8') as f:
        f.write(content)

def create_test_strategy(task_name: str, task_data: Dict[str, Any], task_dir: Path):
    """Create the test strategy template."""
    service_name = ''.join(word.capitalize() for word in task_name.split('-'))
    
    content = f"""# {task_name.replace('-', ' ').title()} Testing Strategy

## Testing Approach
Comprehensive testing strategy for {task_name} functionality across all tiers.

## Test Categories

### MVP Tier Tests
- [ ] Basic functionality tests
- [ ] Input validation tests
- [ ] Error handling tests
- [ ] Configuration loading tests

### Core Tier Tests (MVP +)
- [ ] Integration tests
- [ ] Performance tests
- [ ] Security tests
- [ ] Error recovery tests

### Full Tier Tests (Core +)
- [ ] Load testing
- [ ] Failover testing
- [ ] Compliance tests
- [ ] End-to-end tests

## Stack-Specific Testing

### Python Tests
```python
# Test structure using pytest
class Test{service_name}:
    async def test_basic_functionality(self):
        # Test core service functionality
        pass
    
    async def test_error_handling(self):
        # Test error scenarios
        pass
    
    async def test_configuration(self):
        # Test configuration loading
        pass
```

### Go Tests
```go
// Test structure using testing package
func Test{service_name}Service(t *testing.T) {{
    // Test core service functionality
}}

func Test{service_name}Configuration(t *testing.T) {{
    // Test configuration loading
}}
```

### Node.js Tests
```javascript
// Test structure using Jest
describe('{service_name}Service', () => {{
    test('basic functionality', async () => {{
        // Test core service functionality
    }});
    
    test('error handling', async () => {{
        // Test error scenarios
    }});
}});
```

### React/Next.js Tests
```javascript
// Test structure using React Testing Library
import {{ render, screen }} from '@testing-library/react';
import {{{service_name}Component}} from './{{{service_name}Component}}';

describe('{service_name}Component', () => {{
    test('renders correctly', () => {{
        render(<{{{service_name}Component}} />);
        // Test component rendering
    }});
}});
```

## Test Data Management
- Use fixtures for consistent test data
- Mock external dependencies
- Clean up test artifacts after runs
- Validate configuration loading

## Coverage Requirements
- **MVP**: 70% minimum coverage
- **Core**: 85% minimum coverage  
- **Full**: 95% minimum coverage

## Test Execution
```bash
# Run tests for different stacks
{{% if STACK == "python" %}}
pytest tests/{task_name}/
{{% elif STACK == "go" %}}
go test ./{task_name}/...
{{% elif STACK == "node" %}}
npm test -- tests/{task_name}/
{{% elif STACK == "nextjs" %}}
npm test -- tests/{task_name}/
{{% elif STACK == "flutter" %}}
flutter test test/{task_name}/
{{% endif %}}
```
"""
    
    test_file = task_dir / "universal" / "tests" / "TEST-STRATEGY.tpl.md"
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(content)

def create_documentation(task_name: str, task_data: Dict[str, Any], task_dir: Path):
    """Create the task overview documentation."""
    content = f"""# {task_name.replace('-', ' ').title()} Overview

## Purpose
{task_data.get('description', 'Comprehensive task for ' + task_name.replace('-', ' '))}

## Features
- **Core Functionality**: {task_data.get('description', 'Primary task functionality')}
- **Configuration**: Flexible configuration options
- **Monitoring**: Built-in health checks and metrics
- **Error Handling**: Comprehensive error management
- **Integration**: Seamless integration with {{{{PROJECT_NAME}}}} architecture

## Categories
{', '.join(task_data.get('categories', []))}

## Usage Examples

### Basic Usage
```{{{{EXTENSION}}}}
// Example of basic task usage
const result = await {task_name.replace('-', '')}Service.execute(input);
```

### Advanced Configuration
```yaml
# Advanced configuration example
{task_name}:
  advanced_setting: true
  custom_option: "value"
  performance:
    max_workers: 20
    batch_size: 500
```

## Supported Stacks
**Default Stacks**: {', '.join(task_data.get('default_stacks', []))}
**All Supported Stacks**: {', '.join(task_data.get('allowed_stacks', []))}

## Tier Recommendations
{chr(10).join([f'- **{tier}**: {desc}' for tier, desc in task_data.get('recommended_tier', {}).items()])}

## Stack-Specific Notes

### Python Implementation
- Uses async/await patterns with FastAPI/Flask
- Includes comprehensive type hints
- Follows PEP 8 coding standards
- Integrates with Python ecosystem (pytest, black, etc.)

### Go Implementation
- Uses goroutines for concurrent operations
- Follows Go idioms and best practices
- Includes comprehensive error handling
- Integrates with Go testing framework

### Node.js Implementation
- Uses modern ES6+ features
- Includes TypeScript definitions
- Follows Node.js best practices
- Integrates with npm ecosystem

### React/Next.js Implementation
- Uses modern React patterns (hooks, context)
- Includes TypeScript support
- Follows React best practices
- Integrates with Next.js when applicable

### Flutter Implementation
- Uses modern Flutter patterns
- Includes proper state management
- Follows Flutter best practices
- Integrates with Flutter testing framework

## Integration Points
- **Service Integration**: How it integrates with main application
- **Configuration**: How to configure the task
- **Monitoring**: How to monitor task performance
- **Error Handling**: How errors are handled and reported

## Configuration
The task uses configuration from `config/{task_name}.yaml`:

```yaml
{task_name}:
  enabled: true
  timeout: 30
  retry_attempts: 3
  # Additional stack-specific settings
```

## Monitoring and Observability
- Health check endpoint at `/health`
- Metrics available at `/metrics`
- Structured logging with correlation IDs
- Performance monitoring and alerting

## Troubleshooting
- **Common Issue 1**: Check configuration file syntax
- **Common Issue 2**: Verify stack-specific dependencies
- **Performance Issues**: Adjust concurrency settings
- **Integration Issues**: Check API endpoints and authentication

## Migration Guide
If upgrading between tiers:
- **MVP → Core**: Add integration tests and monitoring
- **Core → Full**: Add advanced security and compliance features
- Configuration changes are backward compatible
- Data migration handled automatically

## Dependencies
- **Universal**: logging, configuration management
{chr(10).join([f'- **{stack}**: Stack-specific dependencies' for stack in task_data.get('allowed_stacks', []) if stack not in ['all', 'agnostic']])}

## Best Practices
- Follow stack-specific coding conventions
- Use appropriate error handling patterns
- Implement proper logging and monitoring
- Write comprehensive tests
- Document configuration options
- Handle edge cases gracefully

## Related Tasks
{chr(10).join([f'- **{dep}**: Prerequisite task' for dep in task_data.get('dependencies', [])])}
"""
    
    docs_file = task_dir / "universal" / "docs" / "OVERVIEW.tpl.md"
    with open(docs_file, 'w', encoding='utf-8') as f:
        f.write(content)

def create_stack_implementation(task_name: str, stack: str, task_dir: Path):
    """Create basic stack-specific implementation."""
    service_name = ''.join(word.capitalize() for word in task_name.split('-'))
    
    # Stack-specific file extensions and patterns
    stack_configs = {
        'python': {'ext': 'py', 'import': 'import logging'},
        'go': {'ext': 'go', 'import': 'import "log"'},
        'node': {'ext': 'js', 'import': 'const logger = require(\'./logger\');'},
        'react': {'ext': 'jsx', 'import': 'import React from \'react\';'},
        'nextjs': {'ext': 'tsx', 'import': 'import React from \'react\';'},
        'flutter': {'ext': 'dart', 'import': 'import \'package:flutter/material.dart\';'},
        'sql': {'ext': 'sql', 'import': '-- SQL Implementation'},
        'r': {'ext': 'R', 'import': '# R Implementation'}
    }
    
    config = stack_configs.get(stack, stack_configs['python'])
    
    # Create basic service implementation
    if stack in ['python', 'go', 'node']:
        service_content = f"""# {service_name} Service for {stack.title()}
# Generated for {{{{PROJECT_NAME}}}}

{config['import']}

class {service_name}Service:
    \"\"\"{service_name} service implementation for {{{{PROJECT_NAME}}}}.\"\"\"
    
    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.timeout = config.get('timeout', 30)
    
    async def execute(self, input_data: dict) -> dict:
        \"\"\"Execute the {task_name} service.
        
        Args:
            input_data: Input data for the service
            
        Returns:
            Result of the service execution
        \"\"\"
        # TODO: Implement {task_name} logic here
        return {{"status": "success", "data": input_data}}
    
    async def validate(self, input_data: dict) -> bool:
        \"\"\"Validate input data.
        
        Args:
            input_data: Input data to validate
            
        Returns:
            True if valid, False otherwise
        \"\"\"
        # TODO: Implement validation logic
        return True
    
    async def get_status(self) -> dict:
        \"\"\"Get service status.
        
        Returns:
            Service status information
        \"\"\"
        return {{
            "status": "healthy",
            "service": "{{{{PROJECT_NAME}}}}-{task_name}",
            "enabled": self.enabled,
            "stack": "{stack}"
        }}
"""
        
        service_file = task_dir / "stacks" / stack / "base" / "code" / f"{task_name.replace('-', '_')}_service.tpl.{config['ext']}"
        with open(service_file, 'w', encoding='utf-8') as f:
            f.write(service_content)
    
    elif stack in ['react', 'nextjs']:
        component_content = f"""import React, {{ useState, useEffect }} from 'react';

interface {service_name}Props {{
  config?: any;
  onStatusChange?: (status: any) => void;
}}

const {service_name}Component: React.FC<{service_name}Props> = ({{ config, onStatusChange }}) => {{
  const [status, setStatus] = useState('loading');
  const [data, setData] = useState(null);

  useEffect(() => {{
    // Initialize {task_name} service
    const initializeService = async () => {{
      try {{
        // TODO: Implement service initialization
        setStatus('ready');
      }} catch (error) {{
        setStatus('error');
        console.error('Failed to initialize {task_name}:', error);
      }}
    }};

    initializeService();
  }}, [config]);

  const handleExecute = async () => {{
    // TODO: Implement service execution
    console.log('Executing {task_name}...');
  }};

  return (
    <div className="{task_name}-component">
      <h3>{service_name}</h3>
      <p>Status: {{status}}</p>
      <button onClick={{handleExecute}} disabled={{status !== 'ready'}}>
        Execute {task_name.replace('-', ' ')}
      </button>
    </div>
  );
}};

export default {service_name}Component;
"""
        
        component_file = task_dir / "stacks" / stack / "base" / "code" / f"{task_name.replace('-', '_')}_component.tpl.{config['ext']}"
        with open(component_file, 'w', encoding='utf-8') as f:
            f.write(component_content)

def scaffold_task(task_name: str, task_data: Dict[str, Any]) -> bool:
    """Scaffold a single task with all templates."""
    try:
        print(f"Scaffolding task: {task_name}")
        
        # Create directory structure
        task_dir = create_task_directory(task_name, task_data)
        print(f"  Created directory: {task_dir}")
        
        # Create metadata
        create_meta_yaml(task_name, task_data, task_dir)
        print(f"  Created metadata: meta.yaml")
        
        # Create universal templates
        create_universal_service_skeleton(task_name, task_data, task_dir)
        create_config_template(task_name, task_data, task_dir)
        create_test_strategy(task_name, task_data, task_dir)
        create_documentation(task_name, task_data, task_dir)
        print(f"  Created universal templates")
        
        # Create stack-specific implementations
        for stack in task_data.get('allowed_stacks', []):
            if stack not in ['all', 'agnostic']:
                create_stack_implementation(task_name, stack, task_dir)
        print(f"  Created stack implementations for: {', '.join(task_data.get('allowed_stacks', []))}")
        
        return True
        
    except Exception as e:
        print(f"Error scaffolding {task_name}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Scaffold tasks for {{PROJECT_NAME}} template system')
    parser.add_argument('--task', help='Scaffold specific task only')
    parser.add_argument('--category', help='Scaffold tasks from specific category')
    parser.add_argument('--list', action='store_true', help='List all available tasks and categories')
    
    args = parser.parse_args()
    
    try:
        task_index = load_task_index()
        tasks = task_index.get('tasks', {})
        
        if args.list:
            print("Available tasks by category:")
            categories = {}
            for task_name, task_data in tasks.items():
                for category in task_data.get('categories', []):
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(task_name)
            
            for category, task_list in categories.items():
                print(f"\n{category}:")
                for task in sorted(task_list):
                    stacks = tasks[task].get('allowed_stacks', [])
                    print(f"  - {task} (stacks: {', '.join(stacks)})")
            return
        
        # Filter tasks based on arguments
        if args.task:
            if args.task not in tasks:
                print(f"Task '{args.task}' not found")
                return
            filtered_tasks = {args.task: tasks[args.task]}
        elif args.category:
            filtered_tasks = {
                name: data for name, data in tasks.items()
                if args.category in data.get('categories', [])
            }
            if not filtered_tasks:
                print(f"No tasks found in category '{args.category}'")
                return
        else:
            filtered_tasks = tasks
        
        print(f"Scaffolding {len(filtered_tasks)} tasks...")
        
        success_count = 0
        for task_name, task_data in filtered_tasks.items():
            if scaffold_task(task_name, task_data):
                success_count += 1
        
        print(f"\nCompleted: {success_count}/{len(filtered_tasks)} tasks scaffolded successfully")
        
        if success_count == len(filtered_tasks):
            print("All tasks scaffolded successfully!")
            print("\nNext steps:")
            print("1. Review generated templates")
            print("2. Implement stack-specific logic")
            print("3. Update main task-index.yaml")
            print("4. Test with resolver")
        else:
            print("Some tasks failed to scaffold. Check errors above.")
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
