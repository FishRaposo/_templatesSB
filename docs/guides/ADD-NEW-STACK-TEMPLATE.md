# New Tech Stack Template

**Purpose**: Complete template for adding new technology stacks to the Universal Template System
**Version**: 4.0
**Target**: Production-ready stack integration with full parity

---

## 🏗️ Required Directory Structure

Create the following directory structure for your new stack:

```
stacks/{stack_name}/
├── 📄 README.md                    # Stack overview and integration guide
├── 📄 requirements.txt.tpl         # Stack-specific dependencies (if applicable)
└── 📁 base/                        # Base templates for all tiers
    ├── 📁 code/                    # Core utility templates
    │   ├── config-management.tpl.{ext}
    │   ├── data-validation.tpl.{ext}
    │   ├── error-handling.tpl.{ext}
    │   ├── http-client.tpl.{ext}
    │   ├── logging-utilities.tpl.{ext}
    │   └── testing-utilities.tpl.{ext}
    ├── 📁 docs/                    # Documentation templates
    │   ├── ARCHITECTURE-{stack_name}.tpl.md
    │   ├── CI-EXAMPLES-{stack_name}.tpl.md
    │   ├── ERROR-HANDLING.tpl.md
    │   ├── FRAMEWORK-PATTERNS-{stack_name}.tpl.md
    │   ├── PACKAGE-MANAGEMENT.tpl.md
    │   ├── PERFORMANCE.tpl.md
    │   ├── PROJECT-STRUCTURE.tpl.md
    │   ├── README.tpl.md
    │   └── TESTING-EXAMPLES-{stack_name}.tpl.md
    └── 📁 tests/                   # Test infrastructure templates
        ├── integration-tests.tpl.{ext}
        └── test-base-scaffold.tpl.{ext}

reference-projects/
├── 📁 mvp/mvp-{stack_name}-reference/    # MVP tier reference project
├── 📁 core/core-{stack_name}-reference/  # Core tier reference project
└── 📁 enterprise/enterprise-{stack_name}-reference/  # Enterprise tier reference project
```

---

## 📋 Essential Files Template

### 1. Stack README.md Template

```markdown
# {Stack Name} Templates

**Purpose**: {Stack description and primary use cases}
**Version**: {version}
**Language**: {programming language}
**Framework**: {framework version}

## 🚀 Quick Start

```bash
# Generate {stack_name} project
python scripts/setup-project.py --manual-stack {stack_name} --manual-tier mvp --name "MyProject"

# Validate {stack_name} templates
python scripts/validate-templates.py --full
```

## 📁 File Structure

- `base/code/` - Core utility templates
- `base/docs/` - Documentation templates  
- `base/tests/` - Test infrastructure templates
- `reference-projects/` - Complete reference implementations

## 🎯 Supported Tiers

- **MVP**: Basic functionality with minimal dependencies
- **Core**: Production-ready with comprehensive features
- **Enterprise**: Advanced features with security and scalability

## 📚 Documentation

- [ARCHITECTURE-{stack_name}](./base/docs/ARCHITECTURE-{stack_name}.tpl.md) - System architecture
- [FRAMEWORK-PATTERNS-{stack_name}](./base/docs/FRAMEWORK-PATTERNS-{stack_name}.tpl.md) - Best practices
- [TESTING-EXAMPLES-{stack_name}](./base/docs/TESTING-EXAMPLES-{stack_name}.tpl.md) - Testing strategies

## 🔧 Integration

The {stack_name} stack integrates with:
- Universal templates from `tiers/` directory
- Blueprint overlays from `blueprints/` directory
- Cross-stack utilities from `stacks/generic/`

## 📊 Validation

Run comprehensive validation:
```bash
python scripts/validate-templates.py --full
```

Expected: 0 errors, minimal warnings

---

**See [SYSTEM-MAP.md](../SYSTEM-MAP.md) for complete system architecture**
```

### 2. Base Code Templates

Each code template must include:

```{language}
# Universal Template System - {Stack Name} Stack
# Generated: {date}
# Purpose: {template purpose}
# Tier: base
# Stack: {stack_name}
# Category: utilities

/// {Template description}
/// 
/// CONFIDENTIAL - INTERNAL USE ONLY
library;

// Import statements
import '{package}';

// Template implementation with placeholders
class {{CLASS_NAME}} {
  // Implementation with {{PLACEHOLDER}} patterns
}
```

#### Required Code Templates:

1. **config-management.tpl.{ext}**
   - Environment variable handling
   - Configuration file loading
   - Runtime configuration management

2. **data-validation.tpl.{ext}**
   - Input validation utilities
   - Data transformation helpers
   - Validation error handling

3. **error-handling.tpl.{ext}**
   - Custom exception classes
   - Error logging utilities
   - Error recovery patterns

4. **http-client.tpl.{ext}**
   - HTTP client wrapper
   - Request/response handling
   - API integration utilities

5. **logging-utilities.tpl.{ext}**
   - Structured logging setup
   - Log level management
   - Output formatting

6. **testing-utilities.tpl.{ext}**
   - Test helper functions
   - Mock utilities
   - Test data generators

### 3. Documentation Templates

Each documentation template must include:

```markdown
# Universal Template System - {Stack Name} Stack
# Generated: {date}
# Purpose: {template purpose}
# Tier: base
# Stack: {stack_name}
# Category: documentation

---

# {Document Title}

## Overview
{Comprehensive overview of the topic}

## Implementation
{Implementation details and examples}

## Best Practices
{Stack-specific best practices}

## Integration
{How this integrates with the Universal Template System}

---

**See [SYSTEM-MAP.md](../SYSTEM-MAP.md) for complete system architecture**
```

#### Required Documentation Templates:

1. **ARCHITECTURE-{stack_name}.tpl.md**
   - System architecture overview
   - Component relationships
   - Design patterns

2. **CI-EXAMPLES-{stack_name}.tpl.md**
   - Continuous integration setup
   - Build pipeline examples
   - Deployment configurations

3. **FRAMEWORK-PATTERNS-{stack_name}.tpl.md**
   - Framework-specific patterns
   - Common implementation approaches
   - Code organization

4. **TESTING-EXAMPLES-{stack_name}.tpl.md**
   - Testing strategies
   - Test framework setup
   - Example test cases

### 4. Test Templates

#### Required Test Templates:

1. **integration-tests.tpl.{ext}**
   ```{language}
   # Universal Template System - {Stack Name} Stack
   # Generated: {date}
   # Purpose: Integration test utilities
   # Tier: base
   # Stack: {stack_name}
   # Category: testing

   /// Integration test utilities for {stack_name}
   /// 
   /// CONFIDENTIAL - INTERNAL USE ONLY
   library;

   import 'package:test/test.dart';

   class {{TEST_CLASS_NAME}} {
     // Integration test implementations
   }
   ```

2. **test-base-scaffold.tpl.{ext}**
   ```{language}
   # Universal Template System - {Stack Name} Stack
   # Generated: {date}
   # Purpose: Base test scaffold
   # Tier: base
   # Stack: {stack_name}
   # Category: testing

   /// Base test scaffold for {stack_name} projects
   /// 
   /// CONFIDENTIAL - INTERNAL USE ONLY
   library;

   import 'package:test/test.dart';

   void main() {
     group('{{PROJECT_NAME}} Tests', () {
       // Test setup and teardown
     });
   }
   ```

---

## 🏗️ Reference Project Templates

Create three reference projects with complete implementations:

### MVP Reference Project Structure
```
mvp/mvp-{stack_name}-reference/
├── 📄 main.{ext}                    # Entry point
├── 📄 config.{ext}                  # Configuration
├── 📄 README.md                     # Project documentation
└── 📄 test_main.{ext}               # Basic tests
```

### Core Reference Project Structure
```
core/core-{stack_name}-reference/
├── 📁 src/                          # Source code
│   ├── 📄 main.{ext}
│   ├── 📄 config.{ext}
│   ├── 📄 utils.{ext}
│   └── 📁 [feature modules]
├── 📁 tests/                        # Test suite
│   ├── 📄 unit/
│   ├── 📄 integration/
│   └── 📄 test_main.{ext}
├── 📄 pubspec.yaml / package.json   # Dependencies
└── 📄 README.md                     # Documentation
```

### Enterprise Reference Project Structure
```
enterprise/enterprise-{stack_name}-reference/
├── 📁 src/                          # Source code
├── 📁 tests/                        # Comprehensive test suite
├── 📁 docs/                         # Documentation
├── 📁 scripts/                      # Build/deployment scripts
├── 📄 dockerfile / Dockerfile       # Container configuration
├── 📄 pubspec.yaml / package.json   # Dependencies
└── 📄 README.md                     # Documentation
```

---

## 🏗️ Blueprint Overlay Integration

New stacks must support blueprint overlays for enhanced functionality:

### Overlay Directory Structure
```
blueprints/{blueprint_name}/overlays/{stack_name}/
├── 📁 lib/                          # Main overlay files
│   ├── 📄 main.tpl.{ext}            # Entry point with blueprint integration
│   ├── 📄 app-structure.tpl.{ext}   # Blueprint-specific app structure
│   └── 📁 [feature modules]         # Blueprint feature overlays
└── 📁 services/                     # Service overlays
    └── 📁 [blueprint services]      # Blueprint-specific services
```

### Overlay Implementation Pattern
```{language}
# Universal Template System - {Stack Name} Stack
# Generated: {date}
# Purpose: {Blueprint Name} blueprint overlay
# Tier: base
# Stack: {stack_name}
# Category: overlay

/// {Blueprint Name} Blueprint - {Stack Name} Implementation
/// 
/// {Blueprint description for {stack_name}}
/// 
/// CONFIDENTIAL - INTERNAL USE ONLY
library;

import 'package:{stack_name}/{framework}.dart';
import '../core/config/app_config.dart';

/// Main entry point with {blueprint_name} integration
class {{PROJECT_NAME}}App extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '{{PROJECT_NAME}}',
      theme: AppTheme.primary,
      home: {{BLUEPRINT_SHELL}}(),
    );
  }
}
```

### Required Blueprint Overlays
For each blueprint (e.g., MINS), create:
1. **Main overlay** - Entry point with blueprint integration
2. **App structure** - Blueprint-specific navigation and layout
3. **Feature modules** - Blueprint feature implementations
4. **Service overlays** - Blueprint-specific services

---

## 🔧 Integration Steps

### 1. Create Directory Structure
```bash
mkdir -p stacks/{stack_name}/base/{code,docs,tests}
mkdir -p reference-projects/{mvp,core,enterprise}/{tier}-{stack_name}-reference
```

### 2. Create Base Templates
- Copy and adapt templates from existing stack
- Replace language-specific patterns
- Update placeholders and imports

### 3. Create Reference Projects
- Implement complete working examples
- Include all tier-specific features
- Add comprehensive documentation

### 4. Update System Files
- Add stack to `tier-index.yaml`
- Update validation scripts
- Update documentation references

### 5. Validate Integration
```bash
# Run comprehensive validation
python scripts/validate-templates.py --full

# Test project generation
python scripts/setup-project.py --manual-stack {stack_name} --manual-tier mvp --name "TestProject"

# Validate generated project
cd TestProject/
# Follow project-specific instructions
```

---

## 📊 Validation Checklist

- [ ] All base templates created with proper headers
- [ ] Reference projects compile and run
- [ ] Documentation is complete and accurate
- [ ] Integration with universal templates works
- [ ] Validation script passes (0 errors)
- [ ] Project generation works correctly
- [ ] All tiers (MVP, Core, Enterprise) functional
- [ ] Cross-stack compatibility verified

---

## 🎯 Success Metrics

Your new stack is complete when:
- ✅ All 18 base templates created (6 code, 9 docs, 3 tests)
- ✅ 3 reference projects implemented and working
- ✅ Validation passes with 0 errors
- ✅ Project generation works for all tiers
- ✅ Documentation is comprehensive
- ✅ Integration with blueprint system works

---

**See [CLAUDE.md](./CLAUDE.md), [AGENTS.md](./AGENTS.md), and [WARP.md](./WARP.md) for complete system documentation**
