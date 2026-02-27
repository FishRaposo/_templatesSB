# Skill Metadata Requirements

This document details the metadata requirements and standards for universal AI agent skills.

## Frontmatter Specification

### Required Fields

#### name
- **Type**: String
- **Format**: 1-64 characters
- **Allowed Characters**: Lowercase letters, numbers, hyphens
- **Rules**:
  - Must exactly match the directory name
  - No leading or trailing hyphens
  - No consecutive hyphens
  - Cannot be empty

**Examples:**
```yaml
name: pdf-processor        # ✅ Valid
name: api-docs-generator   # ✅ Valid
name: my-skill             # ✅ Valid
name: Skill-Name           # ❌ Invalid (uppercase)
name: my--skill            # ❌ Invalid (consecutive hyphens)
name: -skill-name          # ❌ Invalid (leading hyphen)
name: skill-name-          # ❌ Invalid (trailing hyphen)
```

#### description
- **Type**: String
- **Length**: 1-1024 characters
- **Purpose**: Describe when to invoke the skill
- **Requirements**:
  - Must be specific and actionable
  - Should include trigger keywords
  - Must describe the skill's purpose

**Examples:**
```yaml
description: Extract text and tables from PDF files using Python libraries  # ✅ Good
description: Generate REST API documentation from OpenAPI 3.0 specifications  # ✅ Good
description: Help with files  # ❌ Too vague
description: This skill processes documents  # ❌ Not actionable
```

### Optional Fields

#### version
- **Type**: String
- **Format**: Semantic versioning (X.Y.Z)
- **Example**: `"1.2.3"`

#### author
- **Type**: String
- **Format**: Free text
- **Example**: `"John Doe <john@example.com>"`

#### tags
- **Type**: Array of strings
- **Purpose**: Categorization and search
- **Example**: `["pdf", "text-extraction", "python"]`

#### category
- **Type**: String
- **Common Values**:
  - `development`
  - `data-processing`
  - `documentation`
  - `analysis`
  - `automation`
  - `utility`

#### license
- **Type**: String
- **Example**: `"MIT"`, `"Apache-2.0"`, `"GPL-3.0"`

#### repository
- **Type**: String (URL)
- **Example**: `"https://github.com/user/skill-name"`

#### homepage
- **Type**: String (URL)
- **Example**: `"https://skill-website.com"`

#### keywords
- **Type**: Array of strings
- **Purpose**: Alternative to tags for some platforms
- **Example**: `["pdf", "extract", "parser", "document"]`

### Extended Metadata Fields

#### agent_support
Defines compatibility with different agents:
```yaml
agent_support:
  claude:
    min_version: "3.0"
    max_version: null
    features: ["file_tools", "code_execution"]
  roo:
    min_version: "1.0"
    max_version: "2.0"
    modes: ["code", "architect"]
  generic:
    required_features: ["file_access", "text_processing"]
    optional_features: ["network_access"]
```

#### dependencies
Lists required dependencies:
```yaml
dependencies:
  python:
    - "requests>=2.25.0"
    - "pyyaml>=5.4.0"
    - "pdfplumber<1.0.0"
  node:
    - "axios": "^0.24.0"
    - "lodash": "4.17.21"
  system:
    - "curl"
    - "jq"
    - "pdftotext"
  optional:
    python: ["opencv-python"]  # Optional feature dependencies
```

#### permissions
Specifies required permissions:
```yaml
permissions:
  file_system:
    read: true
    write: true
    execute: false
  network:
    outbound: false
    inbound: false
  code_execution:
    python: true
    javascript: false
    shell: false
  external_apis:
    - "https://api.github.com"
    - "https://api.openai.com"
```

#### execution
Execution parameters:
```yaml
execution:
  timeout: 30          # Timeout in seconds
  retry_count: 3       # Number of retries on failure
  memory_limit: "512MB" # Memory limit
  cpu_limit: "1"       # CPU limit
  max_file_size: "100MB" # Max file size to process
```

#### triggers
Automatic invocation triggers:
```yaml
triggers:
  keywords:
    - "pdf"
    - "extract"
    - "parse"
  file_types:
    - ".pdf"
    - ".docx"
  patterns:
    - "extract.*from.*pdf"
    - "parse.*document"
  contexts:
    - "document_processing"
    - "data_extraction"
```

#### compatibility
Compatibility information:
```yaml
compatibility:
  platforms:
    - "linux"
    - "macos"
    - "windows"
  architectures:
    - "x86_64"
    - "arm64"
  agents:
    - "claude"
    - "roo"
    - "generic"
```

## Complete Frontmatter Example

```yaml
---
name: pdf-text-extractor
description: Extract text content from PDF files using Python libraries, supporting encrypted PDFs and batch processing
version: "2.1.0"
author: "Jane Smith <jane@example.com>"
tags: ["pdf", "text-extraction", "python", "batch-processing"]
category: "data-processing"
license: "MIT"
repository: "https://github.com/jane/pdf-text-extractor"
homepage: "https://pdf-extractor.example.com"

# Agent compatibility
agent_support:
  claude:
    min_version: "3.0"
    features: ["file_tools", "code_execution"]
  roo:
    min_version: "1.0"
    modes: ["code"]
  generic:
    required_features: ["file_access", "text_processing"]

# Dependencies
dependencies:
  python:
    - "pdfplumber>=0.7.0"
    - "PyPDF2>=2.0.0"
    - "click>=8.0.0"
  system:
    - "python3"

# Permissions
permissions:
  file_system:
    read: true
    write: true
  network: false
  code_execution:
    python: true

# Execution parameters
execution:
  timeout: 60
  retry_count: 3
  memory_limit: "1GB"
  max_file_size: "500MB"

# Triggers
triggers:
  keywords:
    - "extract text from pdf"
    - "pdf text extraction"
    - "parse pdf"
  file_types:
    - ".pdf"
  patterns:
    - "extract.*text.*pdf"
    - "pdf.*text.*extract"

# Compatibility
compatibility:
  platforms:
    - "linux"
    - "macos"
    - "windows"
  agents:
    - "claude"
    - "roo"
    - "generic"

# Metadata
created_at: "2024-01-01"
updated_at: "2024-01-15"
---
```

## Validation Rules

### Name Validation
```python
import re

def validate_skill_name(name):
    """Validate skill name according to specifications"""
    pattern = r'^[a-z0-9]+(-[a-z0-9]+)*$'
    
    if not 1 <= len(name) <= 64:
        raise ValueError("Name must be 1-64 characters")
    
    if not re.match(pattern, name):
        raise ValueError(
            "Name must contain only lowercase letters, numbers, and hyphens. "
            "No leading/trailing/consecutive hyphens."
        )
    
    return True
```

### Description Validation
```python
def validate_description(description):
    """Validate skill description"""
    if not 1 <= len(description) <= 1024:
        raise ValueError("Description must be 1-1024 characters")
    
    # Check for vague phrases
    vague_phrases = [
        "help with",
        "process files",
        "handle data",
        "work with"
    ]
    
    desc_lower = description.lower()
    for phrase in vague_phrases:
        if phrase in desc_lower:
            raise ValueError(
                f"Description is too vague. Avoid phrase: '{phrase}'"
            )
    
    return True
```

### Frontmatter Validation
```python
import yaml
from pathlib import Path

def validate_skill_frontmatter(skill_path):
    """Validate complete skill frontmatter"""
    skill_file = Path(skill_path) / "SKILL.md"
    
    if not skill_file.exists():
        raise FileNotFoundError("SKILL.md not found")
    
    content = skill_file.read_text()
    
    # Extract frontmatter
    if not content.startswith('---'):
        raise ValueError("SKILL.md must start with frontmatter")
    
    try:
        parts = content.split('---', 2)
        frontmatter = yaml.safe_load(parts[1])
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in frontmatter: {e}")
    
    # Validate required fields
    required_fields = ['name', 'description']
    for field in required_fields:
        if field not in frontmatter:
            raise ValueError(f"Required field missing: {field}")
    
    # Validate name matches directory
    dir_name = Path(skill_path).name
    if frontmatter['name'] != dir_name:
        raise ValueError(
            f"Name '{frontmatter['name']}' does not match directory '{dir_name}'"
        )
    
    # Validate individual fields
    validate_skill_name(frontmatter['name'])
    validate_description(frontmatter['description'])
    
    return True
```

## Platform-Specific Extensions

### Claude Extensions
```yaml
# Claude-specific metadata
claude:
  model_preference: "claude-3-sonnet"
  temperature: 0.7
  max_tokens: 4000
  tools: ["file_read", "file_write", "execute"]
```

### Roo Code Extensions
```yaml
# Roo Code specific metadata
roo:
  mode: "code"
  auto_approve: false
  priority: 1
  shortcut: "pdf"
```

### Custom Agent Extensions
```yaml
# Custom agent metadata
custom:
  api_version: "v2"
  endpoint: "/skills/pdf-extractor"
  auth_required: true
  rate_limit: 100
```

## Metadata Best Practices

1. **Be Specific**: Descriptions should clearly indicate when to use the skill
2. **Version Consistency**: Update version numbers with each release
3. **Dependency Clarity**: Specify exact versions when possible
4. **Permission Minimization**: Only request necessary permissions
5. **Documentation**: Include all relevant metadata for better discovery
6. **Validation**: Always validate metadata before publishing

## Common Metadata Errors

### Errors to Avoid
```yaml
# ❌ Common mistakes
---
name: MySkill        # Uppercase letters
description: Help    # Too vague
version: 1.0         # Not a string
tags: pdf            # Should be array
---

# ✅ Correct format
---
name: my-skill
description: Extract text from PDF files using Python libraries
version: "1.0.0"
tags: ["pdf", "extraction"]
---
```

### Validation Checklist
- [ ] Name is 1-64 characters, lowercase, numbers, hyphens only
- [ ] Name matches directory name exactly
- [ ] Description is 1-1024 characters and specific
- [ ] All required fields are present
- [ ] YAML syntax is valid
- [ ] Optional fields use correct data types
- [ ] Version follows semantic versioning
- [ ] Dependencies specify versions when possible
- [ ] Permissions are minimized
- [ ] Platform-specific fields are correctly formatted

Following these metadata requirements ensures your skills are properly discovered, validated, and compatible across different AI agent platforms.
