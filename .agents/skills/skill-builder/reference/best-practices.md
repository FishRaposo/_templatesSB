# Universal Skill Best Practices

This document outlines comprehensive best practices for creating effective, maintainable, and cross-platform compatible AI agent skills.

## Design Principles

### 1. Single Responsibility
Each skill should focus on one specific task or domain.

**Good:**
```yaml
name: pdf-text-extractor
description: Extract text content from PDF files using Python libraries
```

**Avoid:**
```yaml
name: document-processor
description: Process PDFs, Word docs, images, videos, and audio files
```

### 2. Clear Invocation Triggers
The description should clearly indicate when to use the skill.

**Good:**
```yaml
description: Generate REST API documentation from OpenAPI 3.0 specifications
```

**Poor:**
```yaml
description: Help with documentation
```

### 3. Progressive Disclosure
Structure information from general to specific.

```markdown
# Skill Overview
Brief description of purpose

## Quick Start
3-4 steps to get started

## Detailed Instructions
Comprehensive guidance

## Advanced Features
Optional capabilities
```

## Frontmatter Best Practices

### Required Fields
```yaml
---
name: skill-name              # Must match directory name
description: Specific description of when to use this skill
---
```

### Recommended Optional Fields
```yaml
---
name: skill-name
description: Use this skill when [specific situation]
version: "1.0.0"              # Semantic versioning
author: "Your Name"
tags: ["category", "keywords"]
category: "development"
license: "MIT"
repository: "https://github.com/user/skill"
---
```

### Extended Metadata
```yaml
---
# ... basic fields ...

# Agent compatibility
agent_support:
  claude: {min_version: "3.0", max_version: null}
  roo: {min_version: "1.0", max_version: null}
  generic: {required_features: ["file_access"]}

# Dependencies
dependencies:
  python: ["requests>=2.25.0", "pyyaml"]
  node: ["axios", "lodash"]
  system: ["curl", "jq"]

# Security and permissions
permissions:
  file_system: true
  network: false
  execute_code: true
  external_apis: []

# Execution parameters
timeout: 30
retry_count: 3
memory_limit: "512MB"
---
```

## Content Organization

### Structure Template
```markdown
---
# Frontmatter
---

# [Skill Name]

Brief one-paragraph overview

## Quick Start
1. Step one
2. Step two
3. Step three

## Core Methodology
Explanation of the approach

## Step-by-Step Instructions

### 1. Preparation
- Action item
- Another item

### 2. Execution
- Detailed steps
- Code examples

### 3. Validation
- Verification steps
- Success criteria

## Examples
Real-world usage scenarios

## Troubleshooting
Common issues and solutions

## References
Links and resources
```

### Writing Guidelines

#### Use Active Voice
```
✅ Do: "Extract text using the pdfplumber library"
❌ Don't: "Text can be extracted using the pdfplumber library"
```

#### Be Specific and Actionable
```
✅ Do: "Run `pip install pdfplumber` to install the required library"
❌ Don't: "Make sure you have the necessary libraries installed"
```

#### Provide Complete Commands
```
✅ Do: ```bash
pip install pdfplumber PyPDF2
python extract_pdf.py input.pdf output.txt
```
❌ Don't: "Install the libraries and run the script"
```

## Cross-Platform Compatibility

### Universal Paths
```python
# Good: Cross-platform path handling
from pathlib import Path

skill_dir = Path(__file__).parent
template_file = skill_dir / "templates" / "output.md"

# Bad: Hard-coded paths
template_file = "/usr/local/share/skill/templates/output.md"
```

### Configuration Management
```json
{
  "universal": {
    "timeout": 30,
    "retry_count": 3
  },
  "platform_specific": {
    "claude": {"temperature": 0.7},
    "roo": {"mode": "code"},
    "generic": {"api_version": "1.0"}
  }
}
```

### Feature Detection
```python
def get_available_tools():
    """Detect available tools and adapt accordingly"""
    tools = {
        "file_read": False,
        "execute": False,
        "network": False
    }
    
    # Test for tool availability
    try:
        test_file_operation()
        tools["file_read"] = True
    except:
        pass
    
    return tools
```

## Performance Optimization

### Keep Skills Focused
- **Target**: Under 500 lines for SKILL.md
- Split complex skills into multiple focused skills
- Use references for detailed information

### Efficient Resource Loading
```markdown
## Resources
- See `./scripts/processor.py` for data processing logic
- See `./templates/report.md` for output format
- See `./_examples/` for usage examples
```

### Lazy Loading Patterns
```python
def load_resource(resource_name):
    """Load resources only when needed"""
    resource_path = Path(__file__).parent / "resources" / resource_name
    if resource_path.exists():
        return resource_path.read_text()
    return None
```

## Security Considerations

### Input Validation
```python
def validate_input(user_input):
    """Validate user input before processing"""
    # Check for malicious patterns
    dangerous_patterns = ["rm -rf", "sudo", "eval("]
    for pattern in dangerous_patterns:
        if pattern in user_input:
            raise ValueError("Potentially dangerous input detected")
    return True
```

### Permission Minimization
```yaml
permissions:
  file_system: true          # Only if needed
  network: false             # Default to false
  execute_code: true         # Only if necessary
  external_apis: []          # List specific APIs
```

### Safe Script Execution
```python
import subprocess
import shlex

def safe_execute(command):
    """Safely execute commands with proper escaping"""
    # Parse command safely
    args = shlex.split(command)
    
    # Execute with limited privileges
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=30,
        check=True
    )
    return result.stdout
```

## Testing and Validation

### Unit Tests Structure
```python
# tests/test_skill.py
import unittest
import json
import yaml
from pathlib import Path

class TestSkill(unittest.TestCase):
    def setUp(self):
        self.skill_dir = Path(__file__).parent.parent
        self.skill_file = self.skill_dir / "SKILL.md"
        
    def test_frontmatter_valid(self):
        """Test that frontmatter is valid YAML"""
        content = self.skill_file.read_text()
        frontmatter = content.split('---')[1]
        yaml.safe_load(frontmatter)  # Will raise if invalid
        
    def test_name_matches_directory(self):
        """Test skill name matches directory name"""
        content = self.skill_file.read_text()
        frontmatter = yaml.safe_load(content.split('---')[1])
        dir_name = self.skill_dir.name
        self.assertEqual(frontmatter['name'], dir_name)
        
    def test_description_specificity(self):
        """Test description is specific enough"""
        content = self.skill_file.read_text()
        frontmatter = yaml.safe_load(content.split('---')[1])
        description = frontmatter.get('description', '')
        self.assertGreater(len(description), 50)
        self.assertNotIn('help with', description.lower())
```

### Integration Tests
```markdown
# tests/integration.md
## Test Case 1: Basic Functionality
**Input**: "Extract text from sample.pdf"
**Expected Steps**:
1. Check for pdfplumber installation
2. Load and process PDF
3. Save extracted text
**Output**: Text file with extracted content

## Test Case 2: Error Handling
**Input**: "Process non-existent.pdf"
**Expected**: Graceful error message with suggestions
```

### Validation Checklist
- [ ] Frontmatter is valid YAML
- [ ] Name matches directory exactly
- [ ] Description is specific and actionable
- [ ] All referenced files exist
- [ ] Scripts have proper error handling
- [ ] Dependencies are clearly documented
- [ ] Security considerations are addressed
- [ ] Cross-platform compatibility tested
- [ ] Performance within acceptable limits
- [ ] Documentation is complete and clear

## Documentation Standards

### README.md Template
```markdown
# Skill Name

Brief description of the skill's purpose.

## Installation
1. Clone or download the skill
2. Place in appropriate skills directory
3. Install dependencies

## Usage
Example of how to use the skill

## Configuration
Available configuration options

## Troubleshooting
Common issues and solutions

## Contributing
Guidelines for contributors

## License
License information
```

### Inline Documentation
```python
def extract_pdf_text(pdf_path, output_path):
    """
    Extract text from PDF file and save to output file.
    
    Args:
        pdf_path (str): Path to input PDF file
        output_path (str): Path to save extracted text
        
    Returns:
        bool: True if successful, False otherwise
        
    Raises:
        FileNotFoundError: If PDF file doesn't exist
        PermissionError: If unable to write output file
    """
    pass
```

## Version Management

### Semantic Versioning
```yaml
version: "2.1.3"
# MAJOR.MINOR.PATCH
# MAJOR: Breaking changes
# MINOR: New features (backward compatible)
# PATCH: Bug fixes
```

### Changelog Format
```markdown
# Changelog

## [2.1.3] - 2024-01-15
### Fixed
- Fixed encoding issue with non-ASCII PDFs
- Improved error messages

## [2.1.0] - 2024-01-10
### Added
- Support for password-protected PDFs
- New output format option

### Changed
- Updated default timeout to 60 seconds
```

## Community Guidelines

### Contributing
1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request
5. Provide clear description

### Code Review Checklist
- [ ] Code follows style guidelines
- [ ] Tests are included and passing
- [ ] Documentation is updated
- [ ] Breaking changes are documented
- [ ] Security implications considered

### Issue Reporting
- Use descriptive titles
- Provide reproduction steps
- Include environment details
- Attach relevant files

Following these best practices ensures your skills are reliable, maintainable, and valuable to the community.
