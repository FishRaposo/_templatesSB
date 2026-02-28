# Converting Agent Configurations to Universal Skills

This guide provides detailed instructions for converting existing agent configurations from various formats to the universal Agent Skills format.

## Overview

Different AI agent platforms use various configuration formats. This guide helps you convert:
- Claude sub-agents to skills
- Roo Code configurations to skills
- Custom agent configurations to skills
- Legacy formats to universal skills

## Pre-Conversion Checklist

Before starting conversion:

1. **Backup Original Configuration**
   ```bash
   cp -r ~/.claude/agents ~/.claude/agents.backup
   cp -r ~/.roo/config ~/.roo/config.backup
   ```

2. **Identify Target Platforms**
   - Which platforms will use this skill?
   - What features are required?
   - Are there platform-specific limitations?

3. **Document Current Functionality**
   - What does the configuration do?
   - What tools/permissions does it need?
   - What are the inputs and outputs?

## Converting Claude Sub-Agents

### Understanding Claude Sub-Agents

Claude sub-agents are defined in YAML files:

```yaml
---
name: code-reviewer
description: Reviews code quality, checks security and best practices
model: sonnet
tools: [file_read, file_write, execute]
---

You are an expert code reviewer focusing on:
- Code quality and maintainability
- Security vulnerabilities
- Performance issues
```

### Conversion Steps

#### Step 1: Extract Core Information
```yaml
# From sub-agent
name: code-reviewer
description: Reviews code quality, checks security and best practices
model: sonnet
tools: [file_read, file_write, execute]
```

#### Step 2: Transform to Skill Format
```yaml
# To skill frontmatter
---
name: code-reviewer
description: Use this skill when you need comprehensive code review including quality checks, security analysis, and best practices verification
version: "1.0.0"
tags: ["code-review", "security", "quality"]
category: "development"

# Agent support
agent_support:
  claude:
    min_version: "3.0"
    model_preference: "sonnet"
    tools: ["file_read", "file_write", "execute"]
  generic:
    required_features: ["file_access", "code_execution"]
---
```

#### Step 3: Enhance Instructions
```markdown
# Code Reviewer

You are an expert code reviewer with deep expertise in:

## Review Areas

### 1. Code Quality
- Maintainability and readability
- Adherence to coding standards
- Code organization and structure
- Documentation quality

### 2. Security Analysis
- Common vulnerabilities (OWASP Top 10)
- Input validation and sanitization
- Authentication and authorization
- Data protection and encryption

### 3. Performance Optimization
- Algorithm efficiency
- Resource usage
- Scalability considerations
- Bottleneck identification

## Review Process

1. **Initial Assessment**
   ```bash
   # Scan the codebase
   find . -name "*.py" -o -name "*.js" | head -20
   ```

2. **Detailed Analysis**
   - Review each file systematically
   - Check for common issues
   - Document findings

3. **Report Generation**
   - Prioritize issues by severity
   - Provide actionable recommendations
   - Include code examples for fixes

## Usage Examples

### Example 1: Full Repository Review
**Input**: "Review this entire codebase for security issues"
**Approach**: 
1. Scan all files
2. Focus on authentication and data handling
3. Generate security report

### Example 2: Specific File Review
**Input**: "Review this pull request for code quality"
**Approach**:
1. Check changed files only
2. Focus on maintainability
3. Suggest improvements
```

#### Step 4: Create Supporting Structure
```
code-reviewer/
├── SKILL.md
├── config.json
├── scripts/
│   ├── security-scan.js
│   └── quality-check.py
├── templates/
│   └── security-report.md
└── _examples/
    └── review-output.md
```

## Converting Roo Code Configurations

### Understanding Roo Code Format

Roo Code uses various configuration approaches:

```json
{
  "name": "data-processor",
  "mode": "code",
  "tools": ["read_file", "write_file", "bash"],
  "instructions": "Process data files using Python scripts"
}
```

### Conversion Process

#### Step 1: Parse Existing Config
```python
# parse-roo-config.py
import json

def parse_roo_config(config_path):
    with open(config_path) as f:
        config = json.load(f)
    
    return {
        'name': config.get('name'),
        'description': generate_description(config),
        'mode': config.get('mode'),
        'tools': config.get('tools', []),
        'instructions': config.get('instructions', '')
    }

def generate_description(config):
    # Generate a proper description from config
    mode = config.get('mode', 'generic')
    tools = config.get('tools', [])
    
    if mode == 'code':
        return f"Use this skill for code-related tasks including {', '.join(tools)}"
    else:
        return f"Use this skill for {mode} tasks"
```

#### Step 2: Create Universal Skill
```yaml
---
name: data-processor
description: Use this skill when processing data files with Python scripts, including CSV parsing, JSON transformation, and data validation
version: "1.0.0"
category: "data-processing"

agent_support:
  roo:
    mode: "code"
    tools: ["read_file", "write_file", "bash"]
  generic:
    required_features: ["file_access", "code_execution"]
---
```

## Converting Custom Agent Configurations

### Common Custom Formats

#### Format 1: JSON-based
```json
{
  "skillName": "email-sender",
  "description": "Send emails via SMTP",
  "apiEndpoint": "/api/send-email",
  "permissions": ["network", "smtp"],
  "settings": {
    "smtpHost": "smtp.example.com",
    "smtpPort": 587
  }
}
```

#### Format 2: YAML-based
```yaml
skill:
  name: file-converter
  purpose: Convert between file formats
  runtime: python
  dependencies:
    - pandas
    - openpyxl
  config:
    input_formats: [csv, xlsx, json]
    output_formats: [csv, json, xml]
```

### Universal Conversion Script

```python
#!/usr/bin/env python3
# convert-to-skill.py

import yaml
import json
import argparse
from pathlib import Path

class ConfigConverter:
    def __init__(self, source_format):
        self.source_format = source_format
    
    def convert_json_config(self, config_path):
        """Convert JSON-based config to skill"""
        with open(config_path) as f:
            config = json.load(f)
        
        skill = {
            'name': config.get('skillName', config.get('name', 'unnamed-skill')),
            'description': self.enhance_description(config.get('description', '')),
            'version': '1.0.0',
            'agent_support': {
                'custom': {
                    'api_endpoint': config.get('apiEndpoint'),
                    'settings': config.get('settings', {})
                }
            },
            'permissions': self.map_permissions(config.get('permissions', []))
        }
        
        return skill
    
    def convert_yaml_config(self, config_path):
        """Convert YAML-based config to skill"""
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        skill_config = config.get('skill', {})
        
        skill = {
            'name': skill_config.get('name', 'unnamed-skill'),
            'description': self.enhance_description(skill_config.get('purpose', '')),
            'version': '1.0.0',
            'dependencies': {
                skill_config.get('runtime', 'python'): skill_config.get('dependencies', [])
            },
            'config': skill_config.get('config', {})
        }
        
        return skill
    
    def enhance_description(self, base_desc):
        """Make description more specific and actionable"""
        if not base_desc or base_desc == 'Process data':
            return "Use this skill when you need to process and transform data files"
        
        # Add action words if missing
        if not any(word in base_desc.lower() for word in ['use', 'when', 'process']):
            base_desc = f"Use this skill to {base_desc.lower()}"
        
        return base_desc
    
    def map_permissions(self, permissions):
        """Map custom permissions to universal format"""
        permission_map = {
            'network': {'network': {'outbound': True}},
            'smtp': {'network': {'outbound': True}, 'external_apis': ['smtp']},
            'file_system': {'file_system': {'read': True, 'write': True}},
            'execute': {'code_execution': {'python': True, 'shell': True}}
        }
        
        universal_perms = {
            'file_system': {'read': False, 'write': False, 'execute': False},
            'network': {'outbound': False, 'inbound': False},
            'code_execution': {'python': False, 'javascript': False, 'shell': False},
            'external_apis': []
        }
        
        for perm in permissions:
            if perm in permission_map:
                self.merge_permissions(universal_perms, permission_map[perm])
        
        return universal_perms
    
    def merge_permissions(self, target, source):
        """Merge permission dictionaries"""
        for key, value in source.items():
            if isinstance(value, dict):
                target[key].update(value)
            else:
                target[key] = value
    
    def generate_skill_file(self, skill_data, output_path):
        """Generate complete SKILL.md file"""
        
        # Generate frontmatter
        frontmatter = yaml.dump(skill_data, default_flow_style=False)
        
        # Generate content template
        content = f"""---
{frontmatter}---

# {skill_data['name'].title().replace('-', ' ')}

{self.generate_content(skill_data)}

## Usage Examples

### Example 1: Basic Usage
**Input**: "Process this data file"
**Approach**: Use default settings

### Example 2: Advanced Usage
**Input**: "Process with custom configuration"
**Approach**: Modify settings as needed

## Configuration

See `config.json` for configuration options.

## Troubleshooting

Common issues and solutions...
"""
        
        with open(output_path, 'w') as f:
            f.write(content)
    
    def generate_content(self, skill_data):
        """Generate skill content based on configuration"""
        content_parts = [
            "This skill provides automated processing capabilities.",
            "",
            "## Core Functionality",
            ""
        ]
        
        # Add specific content based on dependencies
        deps = skill_data.get('dependencies', {})
        if 'python' in deps and deps['python']:
            content_parts.append("### Python Dependencies")
            content_parts.append(f"Required packages: {', '.join(deps['python'])}")
            content_parts.append("")
        
        # Add configuration section
        if 'config' in skill_data:
            content_parts.append("## Configuration")
            content_parts.append("The skill supports the following configuration options:")
            for key, value in skill_data['config'].items():
                content_parts.append(f"- `{key}`: {value}")
            content_parts.append("")
        
        return "\n".join(content_parts)

def main():
    parser = argparse.ArgumentParser(description='Convert agent configs to universal skills')
    parser.add_argument('input', help='Input configuration file')
    parser.add_argument('output', help='Output SKILL.md file')
    parser.add_argument('--format', choices=['json', 'yaml', 'auto'], default='auto',
                       help='Input format')
    
    args = parser.parse_args()
    
    # Detect format if auto
    if args.format == 'auto':
        if args.input.endswith('.json'):
            args.format = 'json'
        elif args.input.endswith(('.yml', '.yaml')):
            args.format = 'yaml'
        else:
            print("Error: Cannot detect format, please specify --format")
            return
    
    converter = ConfigConverter(args.format)
    
    if args.format == 'json':
        skill_data = converter.convert_json_config(args.input)
    else:
        skill_data = converter.convert_yaml_config(args.input)
    
    converter.generate_skill_file(skill_data, args.output)
    print(f"Skill created: {args.output}")

if __name__ == "__main__":
    main()
```

## Migration Strategies

### Strategy 1: Direct Conversion
Best for simple configurations with clear mappings.

1. Extract core functionality
2. Map to universal format
3. Test on target platforms
4. Iterate based on feedback

### Strategy 2: Progressive Enhancement
Best for complex configurations.

1. Create basic skill first
2. Add features incrementally
3. Maintain backward compatibility
4. Document migration path

### Strategy 3: Parallel Operation
Best for critical systems.

1. Keep original running
2. Create skill version
3. Test thoroughly
4. Switch when ready

## Post-Conversion Tasks

### Validation
```bash
# Validate skill structure
python validate-skill.py new-skill/SKILL.md

# Test on platforms
claude --test-skill new-skill
roo --test-skill new-skill
```

### Documentation
- Update README files
- Create migration guide
- Document differences
- Provide examples

### Testing
- Unit tests for scripts
- Integration tests
- Platform-specific tests
- Performance tests

## Common Conversion Patterns

### Pattern 1: Tool-Based Config → Skill
```yaml
# From
tools: [read_file, write_file, execute]

# To
permissions:
  file_system: {read: true, write: true}
  code_execution: {python: true, shell: true}
```

### Pattern 2: Model Specification → Skill
```yaml
# From
model: sonnet

# To
agent_support:
  claude:
    model_preference: "sonnet"
```

### Pattern 3: Simple Description → Enhanced
```yaml
# From
description: "Process files"

# To
description: "Use this skill when you need to process and transform files, including format conversion, data extraction, and validation"
```

## Troubleshooting Common Issues

### Issue: Skill Not Loading
**Cause**: Name mismatch or invalid frontmatter
**Solution**: 
```bash
# Check directory name matches skill name
ls -la skill-directory/

# Validate YAML
python -c "import yaml; yaml.safe_load(open('SKILL.md').read().split('---')[1])"
```

### Issue: Missing Features
**Cause**: Platform-specific features not mapped
**Solution**: Add fallback mechanisms in config.json

### Issue: Permission Errors
**Cause**: Incorrect permission mapping
**Solution**: Review and update permissions section

## Best Practices

1. **Preserve Functionality**: Ensure converted skills do the same thing
2. **Enhance Where Possible**: Add features and improvements during conversion
3. **Document Changes**: Keep clear records of what was changed
4. **Test Thoroughly**: Validate on all target platforms
5. **Get Feedback**: Have users test converted skills

## Automation Tools

### Batch Conversion Script
```bash
#!/bin/bash
# convert-all.sh

for config in ~/.claude/agents/*.md; do
    skill_name=$(basename "$config" .md)
    mkdir -p ~/.claude/skills/$skill_name
    python convert-to-skill.py "$config" ~/.claude/skills/$skill_name/SKILL.md
done
```

### Validation Pipeline
```yaml
# .github/workflows/validate-skills.yml
name: Validate Skills
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Validate all skills
        run: python validate-all-skills.py
```

This guide provides a comprehensive approach to converting various agent configurations to the universal skill format, ensuring compatibility and maintainability across platforms.
