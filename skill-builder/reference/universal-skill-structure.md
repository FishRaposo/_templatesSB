# Universal Skill Structure Guide

This document provides detailed guidelines for structuring skills that work across different AI agent platforms.

## Core Directory Structure

### Minimum Viable Skill
```
skill-name/
└── SKILL.md
```

### Recommended Structure
```
skill-name/
├── SKILL.md              # Required: Main skill definition
├── config.json           # Optional: Agent-specific configuration
├── README.md            # Optional: Skill documentation
├── scripts/             # Optional: Executable scripts
│   ├── setup.py        # Installation/dependency setup
│   ├── run.py          # Main execution script
│   └── utils.py        # Utility functions
├── templates/           # Optional: Template files
│   ├── output.md       # Output format template
│   └── email.md        # Email template
├── _examples/          # Optional: Example usage (this repo; elsewhere: examples/)
│   ├── basic.md        # Basic usage example
│   └── advanced.md     # Advanced usage example
├── tests/              # Optional: Test cases
│   ├── test_skill.py   # Unit tests
│   └── integration.md  # Integration test cases
└── docs/               # Optional: Additional documentation
    ├── api.md          # API documentation
    └── troubleshooting.md
```

## File Specifications

### SKILL.md (Required)
The main skill definition file containing:
- YAML frontmatter with metadata
- Skill instructions and methodology
- Usage examples
- Best practices

**Requirements:**
- Must be valid markdown
- Frontmatter must include `name` and `description`
- Name must match directory name exactly
- Description should be 1-1024 characters

### config.json (Optional)
Agent-specific configuration file:
```json
{
  "agent_support": {
    "claude": {"min_version": "3.0", "max_version": null},
    "roo": {"min_version": "1.0", "max_version": null},
    "custom": {"api_endpoint": "https://api.example.com"}
  },
  "dependencies": {
    "python": ["requests", "pyyaml"],
    "node": ["axios", "lodash"],
    "system": ["curl", "jq"]
  },
  "permissions": {
    "file_system": true,
    "network": false,
    "execute_code": true
  },
  "triggers": {
    "keywords": ["pdf", "extract", "parse"],
    "file_types": [".pdf", ".docx"],
    "patterns": ["extract.*from.*pdf"]
  },
  "execution": {
    "timeout": 30,
    "retry_count": 3,
    "fallback_skill": "generic-file-processor"
  }
}
```

### README.md (Optional)
Human-readable documentation including:
- Skill overview and purpose
- Installation instructions
- Usage examples
- Contribution guidelines
- License information

### Scripts Directory
Optional executable scripts that the skill can invoke:

**Python Scripts (Recommended):**
```python
#!/usr/bin/env python3
"""Script description"""
import sys
import json

def main():
    # Script logic here
    pass

if __name__ == "__main__":
    main()
```

**Shell Scripts:**
```bash
#!/bin/bash
# Script description
set -e  # Exit on error

# Script logic here
```

**Node.js Scripts:**
```javascript
#!/usr/bin/env node
/* Script description */
import fs from 'fs';

// Script logic here
```

### Templates Directory
Reusable template files for generating output:
- Markdown templates
- JSON templates
- Email templates
- Code templates

### Examples Directory
Sample inputs and outputs:
- Basic usage examples
- Edge cases
- Common scenarios
- Expected outputs

### Tests Directory
Test files for validation:
- Unit tests for scripts
- Integration tests
- Mock data for testing
- Validation scripts

## Naming Conventions

### Directory and File Names
- Use lowercase letters, numbers, and hyphens
- No spaces or special characters
- Be descriptive but concise
- Use kebab-case for multi-word names

**Examples:**
- ✅ `pdf-processor`
- ✅ `api-docs-generator`
- ✅ `data-analyzer`
- ❌ `PDF Processor`
- ❌ `skill#1`
- ❌ `my_skill`

### Script Names
- Use descriptive names that indicate function
- Include extension appropriate for language
- Prefix with action verbs when appropriate

**Examples:**
- ✅ `extract-data.py`
- ✅ `generate-report.js`
- ✅ `validate-input.sh`
- ❌ `script.py`
- ❌ `temp.js`

## File Organization Best Practices

### Group Related Files
```
skill-name/
├── scripts/
│   ├── data/           # Data processing scripts
│   │   ├── extract.py
│   │   └── transform.py
│   └── output/         # Output generation scripts
│       ├── generate.py
│       └── format.py
│   └── universal-paths/
│       └── paths.md
├── core/
│   ├── SKILL.md
│   └── config.json
├── processors/
│   ├── input/
│   └── output/
├── templates/
│   ├── reports/
│   └── emails/
└── tests/
    ├── unit/
    └── integration/
```

## Cross-Platform Considerations

### Path Handling
- Use forward slashes for relative paths
- Avoid absolute paths when possible
- Use path.join() or Path objects in code

### File Permissions
- Ensure scripts are executable
- Set appropriate read/write permissions
- Consider Windows file permission differences

### Character Encoding
- Use UTF-8 encoding for all text files
- Specify encoding in script headers
- Handle encoding errors gracefully

## Resource Management

### Large Files
- Consider splitting large resources
- Use compression for text files
- Document size requirements

### Binary Files
- Document binary file requirements
- Provide alternatives when possible
- Include checksums for verification

### External Dependencies
- List all dependencies in config.json
- Provide installation instructions
- Include version requirements

## Version Control

### .gitignore Recommendations
```
# Python
__pycache__/
*.pyc
*.pyo
.env

# Node.js
node_modules/
npm-debug.log*

# OS
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/

# Temporary files
*.tmp
*.temp
```

### Commit Guidelines
- Commit SKILL.md changes with descriptive messages
- Include test updates with feature changes
- Tag releases for stable versions
- Document breaking changes

This structure ensures your skills are organized, maintainable, and compatible across different AI agent platforms.
