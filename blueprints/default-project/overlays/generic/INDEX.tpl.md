# {{PROJECT_NAME}} - Project Index

> ⚠️ **MANDATORY** for projects with 20+ files: Complete navigation index for {{PROJECT_NAME}}

## 📑 Quick Navigation

### Getting Started
- [README.md](README.md) - Project overview and quick start
- [CONTEXT.md](CONTEXT.md) - Project philosophy and context
- [CHANGELOG.md](CHANGELOG.md) - Recent changes and version history

### Development Guide
- [AGENTS.md](AGENTS.md) - Developer implementation guide
- [CLAUDE.md](CLAUDE.md) - Claude developer quick reference
- [WORKFLOW.md](WORKFLOW.md) - User workflows and processes
- [EVALS.md](EVALS.md) - Testing and evaluation framework

### Documentation
- [DOCUMENTATION.md](DOCUMENTATION.md) - Documentation navigation guide
- [DOCUMENTATION-OVERVIEW.md](DOCUMENTATION-OVERVIEW.md) - Overview of all documentation
- [DOCUMENTATION-BLUEPRINT.md](DOCUMENTATION-BLUEPRINT.md) - Documentation templates and guidelines

### Tasks and Planning
- [TODO.md](TODO.md) - Pending features and improvements
- [docs/PROMPT-VALIDATION.md](docs/PROMPT-VALIDATION.md) - ⚠️ MANDATORY: Prompt validation system
- [docs/PROMPT-VALIDATION-QUICK.md](docs/PROMPT-VALIDATION-QUICK.md) - Quick 5-minute validation
- [docs/DOCUMENTATION-MAINTENANCE.md](docs/DOCUMENTATION-MAINTENANCE.md) - ⚠️ MANDATORY: Documentation maintenance

## 📁 Directory Structure

```
{{PROJECT_NAME}}/
├── 📄 README.md                    # Project overview
├── 📄 CONTEXT.md                   # Project philosophy
├── 📄 AGENTS.md                    # Developer guide
├── 📄 CLAUDE.md                    # Claude quick reference
├── 📄 WORKFLOW.md                  # User workflows
├── 📄 CHANGELOG.md                 # Version history
├── 📄 TODO.md                      # Task list
├── 📄 DOCUMENTATION.md             # Documentation guide
├── 📄 DOCUMENTATION-OVERVIEW.md    # Documentation overview
├── 📄 DOCUMENTATION-BLUEPRINT.md   # Documentation templates
├── 📄 EVALS.md                     # Testing guide
├── 📄 INDEX.md                     # This file
│
├── 📁 {{SOURCE_DIR}}/              # Source code
│   ├── 📁 {{CORE_DIR}}/            # Core functionality
│   │   ├── 📄 [main_module].{{EXT}}
│   │   ├── 📄 [config].{{EXT}}
│   │   └── 📄 [utilities].{{EXT}}
│   ├── 📁 {{FEATURES_DIR}}/        # Feature modules
│   │   ├── 📁 [feature_1]/
│   │   ├── 📁 [feature_2]/
│   │   └── 📁 [feature_3]/
│   └── 📁 {{INTERFACES_DIR}}/      # External interfaces
│       ├── 📄 [api].{{EXT}}
│       └── 📄 [cli].{{EXT}}
│
├── 📁 {{TEST_DIR}}/                # Test files
│   ├── 📁 unit/                    # Unit tests
│   ├── 📁 integration/             # Integration tests
│   ├── 📁 e2e/                     # End-to-end tests
│   └── 📁 fixtures/                # Test data
│
├── 📁 docs/                        # Documentation
│   ├── 📄 PROMPT-VALIDATION.md     # Prompt validation
│   ├── 📄 PROMPT-VALIDATION-QUICK.md # Quick validation
│   ├── 📄 DOCUMENTATION-MAINTENANCE.md # Maintenance guide
│   ├── 📁 api/                     # API documentation
│   ├── 📁 guides/                  # User guides
│   └── 📁 examples/                # Code examples
│
├── 📁 scripts/                     # Utility scripts
│   ├── 📄 [build_script].{{EXT}}
│   ├── 📄 [test_script].{{EXT}}
│   └── 📄 [deploy_script].{{EXT}}
│
├── 📁 config/                      # Configuration
│   ├── 📄 [development_config].{{EXT}}
│   ├── 📄 [production_config].{{EXT}}
│   └── 📄 [test_config].{{EXT}}
│
├── 📄 {{PACKAGE_FILE}}             # Package configuration
├── 📄 {{LOCK_FILE}}                # Dependency lock file
├── 📄 {{IGNORE_FILE}}              # Ignore patterns
└── 📄 {{LICENSE_FILE}}             # License information
```

## 🔍 File Finder

### By Purpose
{{#each FILE_CATEGORIES}}
#### {{category}}
{{#each files}}
- [{{filename}}]({{path}}) - {{description}}
{{/each}}
{{/each}}

### By File Type
{{#each FILE_TYPES}}
#### {{type}} Files
{{#each files}}
- [{{name}}]({{path}})
{{/each}}
{{/each}}

### By Module
{{#each MODULES}}
#### {{module_name}}
- **Main**: [{{main_file}}]({{main_path}})
- **Tests**: [{{test_file}}]({{test_path}})
- **Docs**: [{{doc_file}}]({{doc_path}})
- **Config**: [{{config_file}}]({{config_path}})
{{/each}}

## 🏷️ Tag Index

### Features
{{#each FEATURE_TAGS}}
#{{tag}}
- [{{feature_1}}]({{path_1}})
- [{{feature_2}}]({{path_2}})
{{/each}}

### Technologies
{{#each TECH_TAGS}}
#{{tag}}
- [{{component_1}}]({{path_1}})
- [{{component_2}}]({{path_2}})
{{/each}}

### Documentation Types
#api-docs - API documentation files
#guides - User and developer guides
#templates - Template files
#config - Configuration files
#tests - Test files and documentation

## 📊 Project Statistics

### File Counts
- Total Files: {{TOTAL_FILES}}
- Source Files: {{SOURCE_FILES}}
- Test Files: {{TEST_FILES}}
- Documentation Files: {{DOC_FILES}}
- Configuration Files: {{CONFIG_FILES}}

### Code Metrics
- Lines of Code: {{LOC_COUNT}}
- Test Coverage: {{COVERAGE_PERCENTAGE}}%
- Documentation Coverage: {{DOC_COVERAGE_PERCENTAGE}}%

### Last Updated
- Project: {{PROJECT_LAST_UPDATED}}
- Documentation: {{DOC_LAST_UPDATED}}
- Tests: {{TESTS_LAST_UPDATED}}

## 🔗 Quick Links

### External Resources
- [Repository]({{REPOSITORY_URL}})
- [Issue Tracker]({{ISSUE_TRACKER_URL}})
- [CI/CD Pipeline]({{CI_CD_URL}})
- [Documentation Site]({{DOCS_SITE_URL}})

### Internal Tools
- [Build Script]({{BUILD_SCRIPT_PATH}})
- [Test Runner]({{TEST_RUNNER_PATH}})
- [Linter]({{LINTER_PATH}})
- [Formatter]({{FORMATTER_PATH}})

## 🚀 Quick Start Checklist

### For New Developers
- [ ] Read [README.md](README.md)
- [ ] Set up development environment
- [ ] Run initial tests
- [ ] Review [CONTEXT.md](CONTEXT.md)
- [ ] Check [TODO.md](TODO.md) for tasks

### For Contributors
- [ ] Read [AGENTS.md](AGENTS.md)
- [ ] Set up git hooks
- [ ] Understand [WORKFLOW.md](WORKFLOW.md)
- [ ] Review [EVALS.md](EVALS.md)
- [ ] Check contribution guidelines

### For Maintainers
- [ ] Review [docs/DOCUMENTATION-MAINTENANCE.md](docs/DOCUMENTATION-MAINTENANCE.md)
- [ ] Check release process
- [ ] Monitor CI/CD
- [ ] Review issues and PRs
- [ ] Update documentation

## 📝 Index Maintenance

### When to Update
- New files are added
- Major restructuring occurs
- New features are implemented
- Documentation is reorganized

### Update Process
1. Add new files to appropriate sections
2. Update directory structure diagram
3. Refresh statistics
4. Check all links
5. Update last modified date

### Automation
```bash
# Generate index automatically
./scripts/generate-index.sh

# Validate index links
./scripts/validate-index.sh

# Update statistics
./scripts/update-stats.sh
```

---

## 🔍 Search Tips

### Finding Files
- Use browser search (Ctrl+F) for file names
- Check directory structure for location
- Look in relevant sections by purpose
- Use tags to narrow down results

### Understanding Relationships
- Check file dependencies in documentation
- Look at import/export statements
- Review test files for usage examples
- Check configuration for connections

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Total Files Indexed**: {{TOTAL_FILES}}  
**Index Version**: {{INDEX_VERSION}}

---

*This index is mandatory for projects with 20+ files. Keep it updated to ensure project navigability and maintainability.*
