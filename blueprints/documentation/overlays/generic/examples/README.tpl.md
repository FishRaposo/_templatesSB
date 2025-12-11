# Example Templates

**Purpose**: Technology-specific templates to be copied and customized for individual projects. These are reference implementations, not static documentation.

---

## 📋 File Inventory

| File | Size | Purpose | Target Files |
|------|------|---------|--------------|
| **API-DOCUMENTATION.md** | 17KB | 📡 Complete API documentation template | `./API-DOCUMENTATION.md` |
| **FRAMEWORK-PATTERNS.md** | 44KB | 🏗️ Architecture patterns and conventions | `./FRAMEWORK-PATTERNS.md` |
| **GITIGNORE-EXAMPLES.md** | 9KB | 🚫 Version control ignore patterns | `./.gitignore` |
| **MIGRATION-GUIDE.md** | 24KB | 🚀 Safe migration strategies and procedures | `./MIGRATION-GUIDE.md` |
| **PROJECT-ROADMAP.md** | 7KB | 🗺️ Project planning and milestone tracking | `./PROJECT-ROADMAP.md` |
| **TESTING-EXAMPLES.md** | 59KB | 🧪 Tech-specific testing patterns and examples | `./TESTING-EXAMPLES.md` |

---

## 🎯 Template Usage

### **How to Use These Templates**
1. **Copy** the appropriate template to your project root
2. **Customize** with your project-specific details
3. **Adapt** patterns to match your technology stack
4. **Validate** with `scripts/validate_docs.py`

### **Template Mapping by Tier**

| Tier | Templates Used | Target Files | Purpose |
|------|----------------|--------------|---------|
| **MVP** | API-DOCUMENTATION.md → API-DESIGN.md | Brief endpoint list | Simple API documentation |
| **CORE** | All 6 templates | Full implementation | Production-ready documentation |
| **FULL** | All 6 templates + extensions | Enterprise versions | Complete with advanced features |

---

## 📚 Template Details

### **API-DOCUMENTATION.md**
- **Purpose**: Complete API documentation with OpenAPI/Swagger
- **Content**: Endpoints, schemas, request/response patterns, authentication
- **Customization**: Replace placeholder APIs with your actual endpoints
- **Tier Variations**: 
  - MVP: Brief API-DESIGN.md
  - CORE: Full API-DOCUMENTATION.md
  - FULL: Complete with examples and rate limiting

### **FRAMEWORK-PATTERNS.md**
- **Purpose**: Technology-specific architecture patterns and conventions
- **Content**: Design patterns, coding standards, best practices
- **Customization**: Adapt patterns to your specific framework (React, Node.js, Django, etc.)
- **Integration**: Works with docs/TIER-GUIDE.md for framework selection

### **TESTING-EXAMPLES.md**
- **Purpose**: Comprehensive testing patterns and copy-paste examples
- **Content**: Unit tests, integration tests, E2E tests, performance tests
- **Customization**: Examples for multiple testing frameworks and languages
- **Coverage**: Supports 85%+ (CORE) and 95%+ (FULL) coverage targets

### **PROJECT-ROADMAP.md**
- **Purpose**: Project planning, milestones, and timeline management
- **Content**: Phases, features, dependencies, release planning
- **Customization**: Adapt phases to your project scope and timeline
- **Tier Variations**:
  - MVP: Phase 1 only (basic features)
  - CORE: Phases 1-2 (production features)
  - FULL: Phases 1-4 (enterprise roadmap)

### **MIGRATION-GUIDE.md**
- **Purpose**: Safe procedures for major changes and migrations
- **Content**: Database migrations, API changes, framework upgrades
- **Customization**: Add migration scripts specific to your stack
- **Integration**: Works with docs/platform-engineering/MIGRATION-ENGINE.md

### **GITIGNORE-EXAMPLES.md**
- **Purpose**: Comprehensive .gitignore patterns for various technologies
- **Content**: Language-specific, framework-specific, tool-specific patterns
- **Customization**: Select relevant sections for your tech stack
- **Target**: Copy to `./.gitignore` in project root

---

## 🔗 Integration Points

### **With Tier System**
- **docs/TIER-MAPPING.md** defines which templates to copy per tier
- **docs/TIER-SELECTION.md** determines complexity level
- **Integration with QUICKSTART-AI.md** - Automated template copying process

### **With Validation System**
- **scripts/validate_docs.py** validates copied templates
- **docs/platform-engineering/VALIDATION-PROTOCOL-v2.md** ensures consistency
- **tier-index.yaml** defines required files per tier

### **With AI Agents**
- Templates provide **copy-paste examples** for AI learning
- **FRAMEWORK-PATTERNS.md** guides AI architecture decisions
- **TESTING-EXAMPLES.md** provides test generation patterns

---

## 🚀 Quick Start

### **For New Projects**
```bash
# AI Command
"Set up CORE tier for a React/Node.js SaaS"

# Manual Setup
1. Read docs/TIER-GUIDE.md to understand requirements
2. Reference docs/TIER-MAPPING.md for file list
3. Copy templates from examples/ to project root
4. Customize with project-specific details
5. Run scripts/validate_docs.py for verification
```

### **For Technology Stack**
```bash
# React Project
cp examples/API-DOCUMENTATION.md ./API-DOCUMENTATION.md
cp examples/FRAMEWORK-PATTERNS.md ./FRAMEWORK-PATTERNS.md
cp examples/TESTING-EXAMPLES.md ./TESTING-EXAMPLES.md

# Customize each file for React-specific patterns
```

---

## 📋 Customization Guidelines

### **Do Customize**
- Replace placeholder content with your actual project details
- Adapt patterns to match your specific technology stack
- Add sections relevant to your project domain
- Update examples to match your coding style

### **Don't Remove**
- Core structure and section organization
- Integration points with tier system
- Cross-references to other templates
- Validation checklist items

---

## 🔧 Maintenance

### **When to Update**
- New technology patterns discovered
- Framework best practices evolve
- Testing approaches improve
- Security requirements change

### **How to Update**
1. Update template in examples/ folder
2. Test with sample projects
3. Update docs/TIER-MAPPING.md if needed
4. Validate with scripts/validate_docs.py

---

**Last Updated**: 2025-12-09  
**Template Version**: 2.0  
**Status**: Production Ready 🎊
