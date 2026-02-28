# Skill Structure and Format Guide

This document provides a comprehensive reference for the proper structure and formatting of AI agent skills.

## Core File Structure

### Minimal Required Structure
```
skill-name/
└── SKILL.md
```

### Recommended Complete Structure
```
skill-name/
├── SKILL.md                   # Required: Main skill definition
├── config.json                # Optional: Configuration
├── README.md                  # Optional: Documentation
├── package.json               # Optional: Node.js dependencies
├── requirements.txt           # Optional: Python dependencies
├── scripts/                   # Optional: Executable scripts
│   ├── main.js               # Main execution script
│   ├── utils.js              # Utility functions
│   └── setup.sh              # Setup script
├── templates/                 # Optional: Template files
│   ├── output.md             # Output template
│   └── report.html           # HTML report template
├── examples/                 # Optional: Usage examples (examples/ or _examples/ per convention)
│   ├── basic.md              # Basic example
│   └── advanced.md           # Advanced example
├── tests/                     # Optional: Test files
│   ├── test_skill.js         # Unit tests
│   └── integration.md        # Integration tests
├── docs/                      # Optional: Additional docs
│   ├── api.md                # API documentation
│   └── troubleshooting.md    # Troubleshooting guide
└── resources/                 # Optional: Static resources
    ├── images/               # Image files
    └── data/                 # Data files
```

## SKILL.md Format Specification

### Frontmatter Requirements

#### Minimum Frontmatter
```yaml
---
name: skill-name
description: Specific description of when to use this skill
---
```

#### Complete Frontmatter Example
```yaml
---
name: skill-name
description: Use this skill when [specific situation]. This includes [concrete use cases].
version: "1.0.0"
author: "Author Name <email@example.com>"
tags: ["tag1", "tag2", "tag3"]
category: "development"
license: "MIT"
repository: "https://github.com/user/skill"
homepage: "https://skill-website.com"
keywords: ["keyword1", "keyword2"]
created_at: "2024-01-01"
updated_at: "2024-01-15"

# Agent compatibility
agent_support:
  claude:
    min_version: "3.0"
    max_version: null
  roo:
    min_version: "1.0"
    max_version: "2.0"
  generic:
    required_features: ["file_access"]

# Dependencies
dependencies:
  python: ["requests>=2.25.0"]
  node: ["axios", "lodash"]
  system: ["curl", "jq"]

# Permissions
permissions:
  file_system: true
  network: false
  execute_code: true

# Execution parameters
timeout: 30
retry_count: 3
memory_limit: "512MB"
---
```

### Content Structure Template

```markdown
---
# Frontmatter
---

# [Skill Name]

[Brief one-paragraph overview of what this skill does and its primary purpose]

## Quick Start

[3-4 step quick start guide for immediate use]

1. **Step One**: [Action description]
2. **Step Two**: [Action description]
3. **Step Three**: [Action description]

## Core Methodology

[Explain the fundamental approach and philosophy behind this skill]

### Key Principles
- [Principle 1]
- [Principle 2]
- [Principle 3]

## Step-by-Step Instructions

### 1. [First Major Step]

[Detailed instructions for the first step]

**Requirements** (e.g. environment or context needed):
- [Requirement 1]
- [Requirement 2]

**Actions**:
- [Specific action 1]
- [Specific action 2]

**Validation**:
- [How to verify completion]

### 2. [Second Major Step]

[Continue with detailed instructions...]

### 3. [Third Major Step]

[Continue with detailed instructions...]

## Command Reference

### Essential Commands
```bash
# Command 1
command-name --option value

# Command 2
another-command --flag
```

### Script Examples
```javascript
// Node.js example
import { module } from 'package';

const result = await module.function();
console.log(result);
```

```python
# Python example
import library

result = library.function()
print(result)
```

## Usage Examples

### Example 1: [Use Case Name]

**Scenario**: [Description of the scenario]

**User Query**: "Example user input"

**Execution**:
1. [Step 1 with actual commands]
2. [Step 2 with actual commands]
3. [Step 3 with actual commands]

**Expected Output**: [Description of expected result]

### Example 2: [Another Use Case]

[Continue with examples...]

## Configuration Options

### Basic Configuration
```json
{
  "option1": "value1",
  "option2": "value2"
}
```

### Advanced Configuration
[Description of advanced options]

## Troubleshooting

### Common Issues

#### Issue: [Problem Name]
**Symptoms**: [What the user sees]
**Causes**: [Why it happens]
**Solutions**:
1. [Solution 1]
2. [Solution 2]

#### Issue: [Another Problem]
[Continue with issues...]

## Best Practices

- [Best practice 1]
- [Best practice 2]
- [Best practice 3]

## References

- [Link to relevant documentation]
- [Link to related resources]
- [Link to examples]

## Supporting Files

- See `./scripts/` for [description]
- See `./templates/` for [description]
- See `./_examples/` for [description]
```

## Configuration Files

### config.json Format
```json
{
  "universal": {
    "version": "1.0",
    "timeout": 30,
    "retry_count": 3
  },
  "agent_specific": {
    "claude": {
      "temperature": 0.7,
      "max_tokens": 4000,
      "tools": ["file_read", "file_write", "execute"]
    },
    "roo": {
      "mode": "code",
      "auto_approve": false
    },
    "generic": {
      "api_version": "1.0",
      "capabilities": ["file_access"]
    }
  },
  "dependencies": {
    "python": {
      "required": ["requests>=2.25.0"],
      "optional": ["pandas"]
    },
    "node": {
      "required": ["axios"],
      "optional": ["lodash"]
    },
    "system": {
      "required": ["curl"],
      "optional": ["jq"]
    }
  },
  "permissions": {
    "file_system": {
      "read": true,
      "write": true,
      "execute": false
    },
    "network": {
      "outbound": false,
      "inbound": false
    },
    "code_execution": {
      "python": true,
      "javascript": false,
      "shell": false
    }
  },
  "triggers": {
    "keywords": ["keyword1", "keyword2"],
    "file_types": [".txt", ".json"],
    "patterns": ["pattern1", "pattern2"]
  },
  "execution": {
    "timeout": 30,
    "retry_count": 3,
    "memory_limit": "512MB",
    "max_file_size": "100MB"
  }
}
```

### package.json (for Node.js skills)
```json
{
  "name": "skill-name",
  "version": "1.0.0",
  "description": "Skill description",
  "type": "module",
  "main": "scripts/main.js",
  "scripts": {
    "start": "node scripts/main.js",
    "test": "node scripts/test.js",
    "setup": "node scripts/setup.js"
  },
  "dependencies": {
    "axios": "^1.6.0",
    "commander": "^11.0.0"
  },
  "devDependencies": {
    "jest": "^29.7.0"
  },
  "bin": {
    "skill-command": "scripts/main.js"
  },
  "keywords": ["ai", "skill"],
  "author": "Author Name",
  "license": "MIT"
}
```

### requirements.txt (for Python skills)
```txt
requests>=2.25.0
pyyaml>=5.4.0
click>=8.0.0
pandas>=1.3.0  # Optional: for data processing
```

## Script Organization

### Entry Point Script (scripts/main.js)
```javascript
#!/usr/bin/env node

import { program } from 'commander';
import { processFile } from './utils.js';
import { ConfigManager } from './config.js';

// Parse command line arguments
program
  .name('skill-command')
  .description('Skill description')
  .option('-i, --input <file>', 'Input file')
  .option('-o, --output <file>', 'Output file')
  .option('-c, --config <file>', 'Config file', './config.json')
  .action(async (options) => {
    try {
      const config = await ConfigManager.load(options.config);
      const result = await processFile(options.input, config);
      
      if (options.output) {
        await writeFile(options.output, result);
        console.log(`Output written to ${options.output}`);
      } else {
        console.log(result);
      }
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program.parse();
```

### Utility Functions (scripts/utils.js)
```javascript
import fs from 'fs/promises';
import path from 'path';

export async function readFile(filePath) {
  try {
    return await fs.readFile(filePath, 'utf-8');
  } catch (error) {
    throw new Error(`Failed to read file: ${error.message}`);
  }
}

export async function writeFile(filePath, content) {
  try {
    await fs.writeFile(filePath, content, 'utf-8');
  } catch (error) {
    throw new Error(`Failed to write file: ${error.message}`);
  }
}

export function validateInput(input) {
  if (!input || input.trim() === '') {
    throw new Error('Input cannot be empty');
  }
  return input.trim();
}
```

## Template Files

### Output Template (templates/output.md)
```markdown
# Skill Output Report

Generated on: {{date}}
Processed by: {{skill-name}}

## Summary
- Total items processed: {{total}}
- Success: {{success}}
- Failed: {{failed}}

## Details
{{#each items}}
### {{this.name}}
- Status: {{this.status}}
- Result: {{this.result}}
{{/each}}

## Recommendations
{{recommendations}}
```

### Email Template (templates/email.md)
```markdown
To: {{recipient}}
Subject: {{subject}}

Dear {{name}},

{{message}}

Best regards,
{{sender}}
```

## Test Files

### Unit Test (tests/test_skill.js)
```javascript
import assert from 'assert';
import { processFile } from '../scripts/utils.js';

describe('Skill Tests', () => {
  it('should process valid input', async () => {
    const input = 'test input';
    const result = await processFile(input);
    assert.ok(result);
  });

  it('should handle errors gracefully', async () => {
    try {
      await processFile(null);
      assert.fail('Should have thrown an error');
    } catch (error) {
      assert.ok(error.message);
    }
  });
});
```

### Integration Test (tests/integration.md)
```markdown
# Integration Test Cases

## Test Case 1: Basic Functionality
**Input**: "Test input"
**Expected**: "Expected output"
**Command**: `node scripts/main.js --input test.txt`

## Test Case 2: Error Handling
**Input**: Invalid input
**Expected**: Error message
**Command**: `node scripts/main.js --input invalid.txt`
```

## Documentation Files

### README.md
```markdown
# Skill Name

Brief description of the skill.

## Installation

1. Clone or download the skill
2. Install dependencies:
   ```bash
   npm install  # For Node.js skills
   pip install -r requirements.txt  # For Python skills
   ```

## Usage

```bash
# Basic usage
skill-command --input file.txt

# With options
skill-command --input file.txt --output result.json --config config.json
```

## Configuration

See `config.json` for configuration options.

## Examples

See `_examples/` directory for usage examples.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT
```

### API Documentation (docs/api.md)
```markdown
# API Documentation

## Functions

### processFile(input, options)

Processes the input file according to skill logic.

**Parameters:**
- `input` (string): Input file path or content
- `options` (object): Configuration options

**Returns:**
- Promise<string>: Processed output

**Example:**
```javascript
const result = await processFile('input.txt', { format: 'json' });
```
```

## Naming Conventions

### Files and Directories
- Use kebab-case for all files and directories
- Names should be descriptive but concise
- Maximum 64 characters for skill directory name

**Examples:**
- ✅ `pdf-text-extractor`
- ✅ `api-docs-generator`
- ✅ `data-analyzer`
- ❌ `PDFTextExtractor`
- ❌ `skill_v1`
- ❌ `very-long-skill-name-that-exceeds-limit`

### Scripts
- Use descriptive names with action verbs
- Include file extensions appropriate for language

**Examples:**
- ✅ `extract-data.js`
- ✅ `generate-report.py`
- ✅ `validate-input.sh`
- ❌ `script.js`
- ❌ `temp.py`

## Formatting Guidelines

### Markdown Formatting
- Use ATX style headers (# ## ###)
- Include blank line before headers
- Use fenced code blocks with language hints
- Use bullet lists for itemized information
- Use numbered lists for sequences

### Code Formatting
```javascript
// Use 2 space indentation
import { module } from 'package';

function functionName(param1, param2) {
  if (condition) {
    return result;
  }
}
```

### YAML Formatting
```yaml
# Use 2 space indentation
key1: value1
key2:
  nested1: value2
  nested2: value3
array:
  - item1
  - item2
```

## Validation Checklist

### Structure Validation
- [ ] Directory name matches frontmatter name
- [ ] SKILL.md exists in root
- [ ] All referenced files exist
- [ ] Scripts have execute permissions
- [ ] Dependencies are documented

### Content Validation
- [ ] Frontmatter is valid YAML
- [ ] Required fields are present
- [ ] Description is specific and actionable
- [ ] Instructions are clear and complete
- [ ] Examples are provided

### Format Validation
- [ ] Markdown syntax is correct
- [ ] Code blocks have language hints
- [ ] Links are valid
- [ ] Images have alt text
- [ ] Tables are properly formatted

Following this structure and format guide ensures your skills are well-organized, maintainable, and compatible across different AI agent platforms.
