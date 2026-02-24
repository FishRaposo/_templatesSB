# Comprehensive Guide to Building Agent Skills

## Table of Contents
1. [Overview](#overview)
2. [Why Use Skills](#why-use-skills)
3. [Skills vs Other Customization Methods](#skills-vs-other-customization-methods)
4. [Understanding How Skills Work](#understanding-how-skills-work)
5. [Universal Skill Architecture](#universal-skill-architecture)
6. [Creating Your First Skill](#creating-your-first-skill)
7. [Directory Structure](#directory-structure)
8. [Skill Specification](#skill-specification)
9. [Agent-Specific Configurations](#agent-specific-configurations)
10. [Best Practices](#best-practices)
11. [Advanced Features](#advanced-features)
12. [Testing & Validation](#testing--validation)
13. [Troubleshooting](#troubleshooting)
14. [Examples](#examples)
15. [Cross-Platform Compatibility](#cross-platform-compatibility)

## Overview

Agent Skills are reusable instruction packages that enable AI agents to perform specialized tasks with expertise. This guide provides a universal approach to creating skills that work across different AI agent platforms and implementations.

### What Are Skills?
Skills are self-contained packages that include:
- **Instructions**: Detailed guidance for specific tasks
- **Resources**: Scripts, templates, and reference files
- **Metadata**: Information for skill discovery and matching
- **Configuration**: Agent-specific settings and parameters

### Key Benefits
- **Task-Specific Expertise**: Package detailed instructions for specialized workflows
- **Bundled Resources**: Include helper scripts, templates, or reference files
- **Mode Targeting**: Create skills that activate only in specific contexts
- **Team Sharing**: Version-control skills for consistent team workflows
- **Efficient Loading**: Skills remain dormant until activated, keeping the base prompt focused
- **Cross-Platform Portability**: Skills can be shared across different agent implementations

## Why Use Skills

### When to Use Skills
- For specialized workflows (data processing, documentation generation, code migration)
- When you need to bundle scripts or templates with instructions
- For expertise that should only load when relevant
- When creating reusable workflows across projects

### Skills Solve These Problems
- Custom instructions apply broadly - skills are task-specific
- Can't package assets with custom instructions - skills can bundle files
- System prompt bloat - skills load only when needed

## Skills vs Other Customization Methods

| Method | Best For | Scope | When to Use |
|--------|----------|-------|-------------|
| **Skills** | Specialized workflows with bundled resources | Task-specific | "Generate API docs following OpenAPI spec" |
| **Custom Instructions** | General rules and preferences | Global | "Always use TypeScript strict mode" |
| **Slash Commands** | Quick commands that return content | On-demand | `/init` for project setup |

## Understanding How Skills Work

Skills use a three-level progressive disclosure architecture:

### Level 1: Discovery
- Agent reads each `SKILL.md` file
- Parses frontmatter for `name` and `description` only
- Metadata stored for matching - full content not in memory

### Level 2: Instructions
- When a request matches a skill's description
- Agent loads the full `SKILL.md` instructions into context
- Uses `read_file` tool to access content

### Level 3: Resources
- Prompt indicates access to bundled files
- No separate resource manifest needed
- Files discovered on-demand when referenced

## Creating Your First Skill

### Step 1: Choose a Location

**Global Skills** (available in all projects):
```bash
# Linux/macOS
~/.agent/skills/{skill-name}/SKILL.md
# Or depending on agent:
~/.roo/skills/{skill-name}/SKILL.md
~/.claude/skills/{skill-name}/SKILL.md
~/.ai/skills/{skill-name}/SKILL.md

# Windows
%USERPROFILE%\.agent\skills\{skill-name}\SKILL.md
# Or depending on agent:
%USERPROFILE%\.roo\skills\{skill-name}\SKILL.md
%USERPROFILE%\.claude\skills\{skill-name}\SKILL.md
%USERPROFILE%\.ai\skills\{skill-name}\SKILL.md
```

**Project Skills** (specific to current workspace):
```bash
<project-root>/.agent/skills/{skill-name}/SKILL.md
# Or depending on agent:
<project-root>/.roo/skills/{skill-name}/SKILL.md
<project-root>/.claude/skills/{skill-name}/SKILL.md
<project-root>/.ai/skills/{skill-name}/SKILL.md
```

**Note**: The exact path may vary depending on your agent implementation. Check your agent's documentation for the specific path.

### Step 2: Create Directory and File

```bash
# Example: PDF processing skill
mkdir -p ~/.agent/skills/pdf-processing
# Or for specific agents:
mkdir -p ~/.roo/skills/pdf-processing
mkdir -p ~/.claude/skills/pdf-processing

touch ~/.agent/skills/pdf-processing/SKILL.md
# Or:
touch ~/.roo/skills/pdf-processing/SKILL.md
touch ~/.claude/skills/pdf-processing/SKILL.md
```

### Step 3: Write the SKILL.md File

The file requires YAML frontmatter with `name` and `description`:

```markdown
---
name: pdf-processing
description: Extract text and tables from PDF files using Python libraries
---

# PDF Processing Instructions

When the user requests PDF processing:

1. Check if PyPDF2 or pdfplumber is installed
2. For text extraction, use pdfplumber for better table detection
3. For simple text-only PDFs, PyPDF2 is sufficient
4. Always handle encoding errors gracefully
5. Offer to save extracted content to a file

## Code Template

[Your detailed code patterns here]

## Common Issues

- **Encrypted PDFs**: Explain they require password parameter
- **Scanned PDFs**: Recommend OCR tools like pytesseract
- **Large files**: Suggest page-by-page processing
```

### Step 4: Test the Skill

Ask the agent something matching the description:
```
"Can you help me extract tables from this PDF file?"
```

The agent should recognize the request, load the skill, and follow its instructions.

## Universal Skill Architecture

### Core Components
Every skill should follow this universal structure:

```
skill-directory/
├── SKILL.md              # Required: Main skill definition
├── config.json           # Optional: Agent-specific configuration
├── README.md            # Optional: Skill documentation
├── scripts/             # Optional: Executable scripts
│   ├── setup.py        # Installation script
│   └── run.py          # Main execution script
├── templates/           # Optional: Template files
│   └── template.md     # Output templates
├── examples/           # Optional: Example usage
│   └── example.md     # Example inputs/outputs
└── tests/              # Optional: Test cases
    └── test_skill.py  # Unit tests
```

### Minimum Viable Skill
The simplest skill requires only:
1. A directory with a valid name
2. A `SKILL.md` file with proper frontmatter

### Enhanced Skill Features
For more sophisticated skills, include:
- **Configuration files** for agent-specific settings
- **Setup scripts** for dependency installation
- **Test cases** for validation
- **Documentation** for users and contributors

## Directory Structure

### Basic Structure
```
~/.agent/skills/                    # Global skills
├── pdf-processing/
│   ├── SKILL.md                  # Required
│   ├── config.json               # Agent-specific config
│   ├── extract.py                # Optional: bundled scripts
│   └── templates/                # Optional: related files
│       └── output-template.md
└── api-docs-generator/
    └── SKILL.md

.agent/skills/                      # Project skills (override global)
└── custom-pdf-workflow/
    └── SKILL.md
```

### Context-Specific Skills
```
~/.agent/skills-code/               # Only in Code context
└── refactoring-patterns/
    └── SKILL.md

.agent/skills-architect/            # Only in Architect context
└── system-design-templates/
    └── SKILL.md

~/.agent/skills-{context}/          # Any specific context
```

**Note**: The exact directory naming may vary by agent. Some agents use:
- `skills-{mode}` (Roo Code)
- `skills-{context}` (Generic)
- `{mode}-skills` (Alternative pattern)
Check your agent's documentation for the specific pattern.

## Skill Specification

### Required Fields

#### Frontmatter
```yaml
---
name: skill-name                  # Required: 1-64 chars
description: Specific description # Required: 1-1024 chars
version: "1.0.0"                # Optional: Semantic version
author: "Your Name"              # Optional: Skill author
tags: ["tag1", "tag2"]          # Optional: Search tags
category: "development"          # Optional: Skill category
---
```

#### Extended Frontmatter (Optional)
```yaml
---
name: skill-name
description: Specific description
version: "1.0.0"
author: "Your Name"
tags: ["tag1", "tag2"]
category: "development"

# Agent-specific configuration
agent_support:
  claude: {"min_version": "3.0", "max_version": null}
  roo: {"min_version": "1.0", "max_version": null}
  custom: {"api_endpoint": "https://api.example.com"}

# Dependencies
dependencies:
  python: ["PyPDF2", "pdfplumber"]
  node: ["pdf-parse"]
  system: ["pdftotext"]

# Permissions required
permissions:
  file_system: true
  network: false
  execute_code: true

# Metadata
created_at: "2024-01-01"
updated_at: "2024-01-15"
license: "MIT"
repository: "https://github.com/user/skill"
---
```

#### Naming Rules
- `name` must exactly match the directory name
- Names: 1-64 characters, lowercase letters/numbers/hyphens only
- No leading/trailing hyphens
- No consecutive hyphens (e.g., `my--skill` is invalid)
- Description must be specific and tell the agent when to use the skill

### Override Priority

When skills with the same name exist in multiple locations, the general priority is:
1. Project context-specific (`.agent/skills-code/my-skill/`)
2. Project generic (`.agent/skills/my-skill/`)
3. Global context-specific (`~/.agent/skills-code/my-skill/`)
4. Global generic (`~/.agent/skills/my-skill/`)

**Note**: Priority order may vary by agent implementation. Some agents may:
- Prioritize context over project location
- Use different naming patterns
- Support additional override levels

Check your agent's documentation for the specific priority rules.

## Agent-Specific Configurations

### Configuration File (config.json)
```json
{
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
    "custom": {
      "api_key_env": "CUSTOM_API_KEY",
      "endpoint": "/v1/skills/execute"
    }
  },
  "triggers": {
    "keywords": ["pdf", "extract", "parse"],
    "file_types": [".pdf"],
    "patterns": ["extract.*from.*pdf"]
  },
  "execution": {
    "timeout": 30,
    "retry_count": 3,
    "fallback_skill": "generic-file-processor"
  }
}
```

### Agent Compatibility Matrix
| Feature | Claude | Roo Code | Custom Agents | Notes |
|---------|--------|----------|---------------|-------|
| Mode-specific skills | ✓ | ✓ | Variable | Check implementation |
| Symlink support | ✓ | ✓ | Variable | File system dependent |
| Config.json | ✓ | ✓ | ✓ | Universal support |
| Version constraints | ✓ | ✓ | Optional | Agent-specific |
| Permission system | ✓ | ✓ | Variable | Security feature |

## Best Practices

### Writing Effective Descriptions
- **Be specific**: "Extract text and tables from PDF files using Python libraries"
- **Avoid vague**: "Handle files"
- **Include key technologies**: Mention libraries, frameworks, or methods
- **Specify the task**: Clearly state what the skill accomplishes

### Organizing Skills
- Group related files in subdirectories
- Use descriptive names for bundled resources
- Keep skills focused on a single task or domain
- Document dependencies in the skill

### Security Considerations
- Only use skills from trusted sources
- Skills can execute code - review before installing
- Be cautious with skills that access external APIs
- Validate input handling in bundled scripts

## Testing & Validation

### Unit Testing
Create test files in the `tests/` directory:

```python
# tests/test_skill.py
import unittest
import json
import os

class TestSkill(unittest.TestCase):
    def setUp(self):
        self.skill_dir = os.path.dirname(os.path.dirname(__file__))
        with open(os.path.join(self.skill_dir, 'SKILL.md'), 'r') as f:
            self.skill_content = f.read()
    
    def test_frontmatter_exists(self):
        self.assertIn('---', self.skill_content)
        self.assertIn('name:', self.skill_content)
        self.assertIn('description:', self.skill_content)
    
    def test_name_matches_directory(self):
        import yaml
        frontmatter = yaml.safe_load(self.skill_content.split('---')[1])
        dir_name = os.path.basename(self.skill_dir)
        self.assertEqual(frontmatter['name'], dir_name)
    
    def test_config_valid(self):
        config_path = os.path.join(self.skill_dir, 'config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
            self.assertIsInstance(config, dict)

if __name__ == '__main__':
    unittest.main()
```

### Integration Testing
Test the skill with sample inputs:

```markdown
<!-- tests/integration_test.md -->
# Integration Test Cases

## Test Case 1: Basic PDF Processing
**Input**: "Extract text from this PDF file"
**Expected**: Skill loads and processes PDF

## Test Case 2: Table Extraction
**Input**: "Can you extract tables from this document?"
**Expected**: Skill uses table-specific logic

## Test Case 3: Error Handling
**Input**: "Process this corrupted PDF"
**Expected**: Graceful error handling
```

### Validation Checklist
- [ ] Frontmatter is valid YAML
- [ ] Name matches directory name
- [ ] Description is specific and clear
- [ ] All referenced files exist
- [ ] Scripts have proper permissions
- [ ] Dependencies are documented
- [ ] Tests pass successfully
- [ ] Documentation is complete

## Advanced Features

### Symlink Support
Share skill libraries across projects:
```bash
# Share a skill library across projects
ln -s /shared/company-skills ~/.roo/skills/company-standards
```

The skill name comes from the symlink name, not the target.

### Composable Skills
- Skills can stack together
- Agent automatically identifies needed skills
- Skills can reference each other
- Use complementary skills for complex workflows

### Portable Format
- Skills use the same format across all Claude products
- Build once, use across:
  - Claude apps
  - Claude Code
  - Claude Developer Platform (API)

## Troubleshooting

### Skill Isn't Loading

**Symptom**: Agent doesn't use your skill even for matching requests

**Common Causes & Fixes**:

1. **Name Mismatch**
   - Frontmatter `name` must exactly match directory name
   - Check for typos or case differences

2. **Invalid Frontmatter**
   - Both `name` and `description` are required
   - Ensure valid YAML syntax
   - Check for missing hyphens or quotes

3. **Naming Rule Violations**
   - No consecutive hyphens
   - No leading/trailing hyphens
   - Only lowercase letters, numbers, and hyphens

4. **Custom System Prompt**
   - File-based custom prompts replace the standard system prompt
   - Skills won't be available with custom system prompts

### Skill Not Discovering

**Symptom**: Skill not found after creation

**Solutions**:
- Restart the agent to reindex skills
- Check file permissions
- Verify directory structure
- Ensure SKILL.md is in the correct location

## Examples

### Example 1: PDF Processing Skill
```markdown
---
name: pdf-processing
description: Extract text and tables from PDF files using Python libraries
---

# PDF Processing Instructions

When processing PDF files:

1. **Check Dependencies**
   ```python
   import PyPDF2
   import pdfplumber
   ```

2. **Choose the Right Tool**
   - Use `pdfplumber` for documents with tables
   - Use `PyPDF2` for simple text extraction
   - Consider `PyMuPDF` for image-heavy PDFs

3. **Handle Common Issues**
   - Encrypted PDFs: Request password
   - Scanned documents: Suggest OCR
   - Large files: Process page by page

4. **Output Options**
   - Plain text (.txt)
   - Structured data (JSON for tables)
   - Markdown format
```

### Example 2: API Documentation Generator
```markdown
---
name: api-docs-generator
description: Generate comprehensive API documentation from OpenAPI specifications
---

# API Documentation Generator

## Workflow

1. **Parse OpenAPI Spec**
   - Validate YAML/JSON syntax
   - Extract endpoints, models, schemas
   - Identify authentication methods

2. **Generate Documentation Structure**
   ```
   docs/
   ├── introduction.md
   ├── authentication.md
   ├── endpoints/
   │   ├── users.md
   │   └── posts.md
   └── models.md
   ```

3. **Create Endpoint Documentation**
   - HTTP method and path
   - Parameters (path, query, header)
   - Request body schema
   - Response schemas
   - Error codes

4. **Include Code Examples**
   - cURL commands
   - JavaScript fetch
   - Python requests

## Templates

Use bundled templates in `templates/` directory:
- `endpoint.md.j2` - Single endpoint template
- `model.md.j2` - Data model template
- `intro.md.j2` - Introduction template
```

### Example 3: Code Refactoring Patterns
```markdown
---
name: refactoring-patterns
description: Apply automated refactoring patterns to improve code quality and maintainability
---

# Code Refactoring Patterns

## Common Patterns

### 1. Extract Method
- Identify long methods (>20 lines)
- Extract cohesive code blocks
- Use descriptive method names
- Preserve original behavior

### 2. Replace Magic Numbers
- Find hardcoded numeric literals
- Create named constants
- Group related constants
- Use enums for related values

### 3. Simplify Conditional Expressions
- Replace nested ifs with guard clauses
- Extract complex conditions to methods
- Use polymorphism instead of type checks

## Automation Scripts

Use `scripts/` directory:
- `extract_method.py` - Automated method extraction
- `find_magic_numbers.py` - Detect magic numbers
- `complexity_analyzer.py` - Measure cyclomatic complexity

## Before/After Examples

See `examples/` directory for:
- Real-world refactoring cases
- Performance comparisons
- Readability improvements
```

### Cross-Agent Compatibility

To ensure skills work across different agents:

1. **Use Universal Paths**
   ```yaml
   # In config.json
   {
     "paths": {
       "global_skills": "~/.agent/skills",
       "project_skills": "{project_root}/.agent/skills"
     }
   }
   ```

2. **Agent-Agnostic Instructions**
   ```markdown
   ## Universal Instructions
   
   This skill works with any AI agent that supports:
   - File reading capabilities
   - Code execution
   - Markdown processing
   
   ### Agent-Specific Notes
   - **Claude**: Uses native file tools
   - **Roo Code**: May require code mode
   - **Custom Agents**: Ensure file system access
   ```

3. **Fallback Mechanisms**
   ```yaml
   # config.json
   {
     "fallbacks": {
       "no_file_access": "Provide manual instructions",
       "no_code_execution": "Generate code for user to run",
       "missing_dependency": "Show installation command"
     }
   }
   ```

## Cross-Platform Compatibility

### Operating System Considerations

**Windows**
- Use `%USERPROFILE%` instead of `~`
- Handle path separators (`\` vs `/`)
- Consider file permissions

**Linux/macOS**
- Use `~` for home directory
- Handle symlink creation
- Respect file permissions

**Universal Solutions**
```python
# Python example for cross-platform paths
import os
from pathlib import Path

# Get home directory universally
home = Path.home()
skills_dir = home / ".agent" / "skills"

# Handle both forward and back slashes
skills_dir = Path(os.path.expanduser("~/.agent/skills"))
```

### Agent Implementation Differences

| Aspect | Claude | Roo Code | Generic Agents |
|--------|--------|----------|---------------|
| Skill Path | `~/.claude/skills` | `~/.roo/skills` | Variable |
| Context Support | ✓ | ✓ | Variable |
| Config Format | JSON | JSON | Variable |
| File Tools | Native | Custom | Variable |

### Best Practices for Compatibility

1. **Always provide a config.json**
2. **Include setup instructions for multiple agents**
3. **Use relative paths within skills**
4. **Document agent-specific requirements**
5. **Test on multiple platforms when possible**
6. **Provide fallback options for missing features**

## Resources

### Universal Documentation
- [Agent Skills Standard](https://agentskills.io/)
- [Skill Architecture Guide](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
- [Cross-Platform Development](https://example.com/cross-platform-skills)

### Agent-Specific Documentation
- [Claude Skills Documentation](https://docs.claude.com/en/api/skills-guide)
- [Roo Code Skills Documentation](https://docs.roocode.com/features/skills)
- [Custom Agent Integration Guide](https://example.com/custom-agent-guide)

### Community Resources
- [Skills Registry](https://github.com/agentskills/registry)
- [Community Examples](https://github.com/agentskills/examples)
- [Discussion Forum](https://github.com/agentskills/discussions)

### Development Tools
- [Skill Validator](https://github.com/agentskills/validator)
- [Template Generator](https://github.com/agentskills/generator)
- [Testing Framework](https://github.com/agentskills/test-framework)

## Conclusion

Skills provide a powerful way to package expertise and make AI agents more effective at specialized tasks. By following this guide, you can create reusable, efficient skills that enhance productivity across projects and teams.

Remember to:
- Keep skills focused and specific
- Write clear, descriptive metadata
- Bundle relevant resources
- Test thoroughly before sharing
- Consider security implications

Start building your skills library today and transform how your organization works with AI agents!
