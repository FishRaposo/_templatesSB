# Editing Skills Guide

This guide provides comprehensive instructions for editing and maintaining existing AI agent skills to improve their effectiveness, compatibility, and maintainability.

## When to Edit Skills

### Common Reasons for Editing
1. **Bug Fixes**: Correcting errors in instructions or scripts
2. **Performance Optimization**: Improving speed or resource usage
3. **Cross-Platform Compatibility**: Adding support for new platforms
4. **Feature Enhancements**: Adding new capabilities
5. **Dependency Updates**: Updating to newer library versions
6. **Security Improvements**: Addressing vulnerabilities
7. **Documentation Updates**: Improving clarity and completeness

### Signs a Skill Needs Editing
- Users report inconsistent behavior
- Skill fails to load or execute
- Dependencies are outdated
- Platform compatibility issues
- Performance degradation
- Security vulnerabilities identified

## Editing Workflow

### 1. Assessment Phase

#### Review Current State
```bash
# Examine skill structure
ls -la skill-directory/

# Check frontmatter validity
head -20 SKILL.md

# Validate YAML
python -c "import yaml; yaml.safe_load(open('SKILL.md').read().split('---')[1])"
```

#### Identify Issues
- Read user feedback or bug reports
- Test skill functionality
- Check compatibility with target platforms
- Review dependencies for updates

#### Plan Changes
- List specific improvements needed
- Prioritize by impact and effort
- Consider backward compatibility
- Document the rationale

### 2. Backup Phase

#### Create Backup
```bash
# Create backup before editing
cp -r skill-directory skill-directory.backup.$(date +%Y%m%d)

# Or use version control
git add .
git commit -m "Backup before editing - $(date)"
git tag -a "v$(date +%Y%m%d)-backup" -m "Pre-edit backup"
```

#### Document Current State
```markdown
# Edit Log - [Date]
## Current State
- Version: [current version]
- Known Issues: [list issues]
- Last Tested: [date/platforms]

## Planned Changes
1. [Change 1]
2. [Change 2]
3. [Change 3]
```

### 3. Implementation Phase

#### Edit Frontmatter
```yaml
# Before editing
---
name: pdf-processor
description: Process PDF files
version: "1.0.0"
---

# After editing
---
name: pdf-processor
description: Extract text and tables from PDF files using Python libraries, supporting batch processing and encrypted documents
version: "1.2.0"
tags: ["pdf", "extraction", "batch", "encryption"]
updated_at: "2024-01-15"
---
```

#### Update Instructions
```markdown
## Before
When processing PDFs, use the pdfplumber library.

## After
When processing PDF files:

1. **Check Dependencies**
   ```bash
   pip install pdfplumber PyPDF2
   ```

2. **Handle Different PDF Types**
   - For text-based PDFs: Use pdfplumber
   - For scanned PDFs: Recommend OCR tools
   - For encrypted PDFs: Request password

3. **Batch Processing Support**
   ```python
   def process_multiple_pdfs(file_list):
       for pdf_file in file_list:
           extract_text(pdf_file)
   ```
```

#### Update Scripts
```python
# Before
import PyPDF2

def extract_text(pdf_path):
    # Simple extraction
    pass

# After
import PyPDF2
import pdfplumber
from pathlib import Path

def extract_text(pdf_path, password=None):
    """Enhanced extraction with error handling"""
    try:
        # Try pdfplumber first (better table support)
        with pdfplumber.open(pdf_path, password=password) as pdf:
            text = ""
            for page in pdf.pages:
                text += page.extract_text() or ""
        return text
    except Exception as e:
        # Fallback to PyPDF2
        return fallback_extraction(pdf_path, password)
```

### 4. Testing Phase

#### Unit Tests
```python
# tests/test_edited_skill.py
import unittest
import tempfile
import os
from skill_module import extract_text

class TestEditedSkill(unittest.TestCase):
    def setUp(self):
        self.test_pdf = "test_files/sample.pdf"
        
    def test_basic_extraction(self):
        result = extract_text(self.test_pdf)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)
        
    def test_encrypted_pdf(self):
        result = extract_text("encrypted.pdf", password="test")
        self.assertIsNotNone(result)
        
    def test_error_handling(self):
        with self.assertRaises(FileNotFoundError):
            extract_text("nonexistent.pdf")
```

#### Integration Tests
```markdown
## Test Scenarios

### Scenario 1: Basic PDF Processing
**Input**: "Extract text from document.pdf"
**Expected**: Text extracted successfully
**Platforms**: Claude, Roo Code, Generic

### Scenario 2: Batch Processing
**Input**: "Process all PDFs in the /docs folder"
**Expected**: All PDFs processed with progress updates
**Platforms**: Claude, Roo Code

### Scenario 3: Error Recovery
**Input**: "Extract from corrupted.pdf"
**Expected**: Graceful error with suggestions
**Platforms**: All
```

#### Cross-Platform Testing
```bash
# Test on different platforms
# Claude
claude --skill pdf-processor "test input"

# Roo Code
roo code --skill pdf-processor "test input"

# Generic agent
generic-agent --skill pdf-processor "test input"
```

### 5. Documentation Updates

#### Update Version History
```markdown
# Changelog

## [1.2.0] - 2024-01-15
### Added
- Support for encrypted PDFs
- Batch processing capability
- Better error handling

### Changed
- Updated dependencies (pdfplumber 0.7.0)
- Improved text extraction algorithm

### Fixed
- Issue with table extraction
- Memory leak with large files
```

#### Update README
```markdown
# PDF Processor Skill

## What's New in v1.2.0
- ✨ Encrypted PDF support
- ✨ Batch processing
- 🐛 Fixed table extraction issues

## Installation
```bash
pip install pdfplumber>=0.7.0 PyPDF2>=2.0.0
```

## Usage
See _examples/ directory for detailed usage examples.
```

## Common Editing Tasks

### Updating Dependencies
```yaml
# config.json - Before
{
  "dependencies": {
    "python": ["pdfplumber==0.5.0", "PyPDF2==1.26.0"]
  }
}

# config.json - After
{
  "dependencies": {
    "python": ["pdfplumber>=0.7.0,<1.0.0", "PyPDF2>=2.0.0"]
  }
}
```

### Adding Platform Support
```yaml
# Add new platform to agent_support
agent_support:
  claude: {...}
  roo: {...}
  new_agent:
    min_version: "1.0"
    required_features: ["file_access"]
```

### Improving Description
```yaml
# Before
description: Process PDF files

# After
description: Extract text and tables from PDF files using Python libraries, with support for encrypted documents, batch processing, and multiple output formats
```

### Optimizing Performance
```python
# Before - Loads entire file into memory
def process_large_pdf(pdf_path):
    with open(pdf_path, 'rb') as f:
        data = f.read()
    return process_data(data)

# After - Processes in chunks
def process_large_pdf(pdf_path, chunk_size=1024):
    with open(pdf_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield process_chunk(chunk)
```

## Advanced Editing Techniques

### Modularization
For complex skills, split into modules:
```
skill-directory/
├── SKILL.md
├── core/
│   ├── __init__.py
│   ├── extractor.py
│   └── processor.py
├── utils/
│   ├── __init__.py
│   └── helpers.py
└── tests/
```

### Configuration-Driven Behavior
```json
{
  "settings": {
    "default_output_format": "text",
    "max_file_size": "100MB",
    "parallel_processing": true,
    "retry_attempts": 3
  },
  "presets": {
    "fast": {"quality": "low", "speed": "high"},
    "quality": {"quality": "high", "speed": "low"}
  }
}
```

### Plugin Architecture
```python
# plugins/base.py
class ProcessorPlugin:
    def process(self, data):
        raise NotImplementedError

# plugins/pdf_processor.py
class PDFProcessor(ProcessorPlugin):
    def process(self, pdf_data):
        # PDF-specific processing
        pass

# Main skill logic
def load_processor(file_type):
    plugin_map = {
        'pdf': PDFProcessor,
        'docx': DocxProcessor
    }
    return plugin_map[file_type]()
```

## Quality Assurance

### Code Review Checklist
- [ ] Changes align with skill's purpose
- [ ] Backward compatibility maintained
- [ ] Error handling is robust
- [ ] Documentation is updated
- [ ] Tests cover new functionality
- [ ] Performance is not degraded
- [ ] Security implications considered
- [ ] Cross-platform compatibility verified

### Automated Validation
```python
# validate_skill.py
import yaml
import json
from pathlib import Path

def validate_skill(skill_path):
    """Automated skill validation"""
    errors = []
    warnings = []
    
    # Check structure
    required_files = ['SKILL.md']
    for file in required_files:
        if not (skill_path / file).exists():
            errors.append(f"Missing required file: {file}")
    
    # Validate frontmatter
    try:
        with open(skill_path / 'SKILL.md') as f:
            frontmatter = yaml.safe_load(f.read().split('---')[1])
    except Exception as e:
        errors.append(f"Invalid frontmatter: {e}")
    
    # Check config.json if present
    if (skill_path / 'config.json').exists():
        try:
            with open(skill_path / 'config.json') as f:
                json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid config.json: {e}")
    
    return errors, warnings
```

## Rollback Procedures

### Quick Rollback
```bash
# Restore from backup
rm -rf skill-directory
mv skill-directory.backup.20240115 skill-directory
```

### Git Rollback
```bash
# Reset to previous commit
git reset --hard HEAD~1

# Or checkout specific tag
git checkout v1.1.0
```

### Partial Rollback
```bash
# Restore specific file
git checkout HEAD~1 -- SKILL.md

# Or from backup
cp skill-directory.backup.20240115/SKILL.md skill-directory/
```

## Publishing Updates

### Version Bumping
```yaml
# Patch version (bug fixes)
version: "1.0.1"

# Minor version (new features)
version: "1.1.0"

# Major version (breaking changes)
version: "2.0.0"
```

### Release Notes Template
```markdown
# Release v[Version]

## Highlights
- [Major feature 1]
- [Major feature 2]

## Changes
### Added
- [New feature 1]
- [New feature 2]

### Changed
- [Modified feature 1]
- [Updated dependency 1]

### Fixed
- [Bug fix 1]
- [Bug fix 2]

### Breaking Changes
- [Breaking change 1]
- Migration instructions: [link]

## Upgrade Instructions
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Compatibility
- Requires: [Agent] v[minimum version]
- Compatible with: [Platform list]
```

## Best Practices Summary

1. **Always backup before editing**
2. **Test changes thoroughly**
3. **Update documentation with code**
4. **Maintain backward compatibility**
5. **Use semantic versioning**
6. **Document all changes**
7. **Validate before publishing**
8. **Monitor feedback after release**

Following this guide ensures your skill edits are systematic, tested, and well-documented, maintaining quality and reliability across updates.
