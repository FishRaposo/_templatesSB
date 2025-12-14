# {{PROJECT_NAME}} - Claude Developer Guide

> Quick reference for developers using Claude Code with {{PROJECT_NAME}}

## 🚀 Quick Start

### Project Setup
```bash
# Clone and setup
git clone {{REPOSITORY_URL}}
cd {{PROJECT_NAME}}
{{SETUP_COMMANDS}}

# Start development
{{DEV_START_COMMAND}}
```

### Key Commands
```bash
# Run tests
{{TEST_COMMAND}}

# Build project
{{BUILD_COMMAND}}

# Run linter
{{LINT_COMMAND}}

# Start server
{{SERVER_COMMAND}}
```

## 📁 Project Structure

```
{{PROJECT_NAME}}/
├── {{SOURCE_DIR}}/          # Main source code
│   ├── {{CORE_DIR}}/        # Core functionality
│   ├── {{UTILS_DIR}}/       # Utilities
│   └── {{CONFIG_DIR}}/      # Configuration
├── {{TEST_DIR}}/            # Test files
├── docs/                    # Documentation
├── scripts/                 # Build and utility scripts
└── {{CONFIG_FILES}}         # Project configuration
```

## 🎯 Development Workflow

### 1. Feature Development
```bash
# Create feature branch
git checkout -b feature/feature-name

# Make changes
# ... edit files ...

# Run tests
{{TEST_COMMAND}}

# Commit with conventional commits
git commit -m "feat: add new feature"

# Push and create PR
git push origin feature/feature-name
```

### 2. Bug Fixing
```bash
# Create bugfix branch
git checkout -b fix/bug-description

# Debug with
{{DEBUG_COMMAND}}

# Fix and test
{{TEST_COMMAND}}

# Commit
git commit -m "fix: resolve specific issue"
```

### 3. Code Review Process
- All changes require PR review
- Must pass all automated checks
- Update documentation if needed
- Include test coverage for new code

## 🔧 Common Tasks

### Adding New Module
1. Create directory in `{{SOURCE_DIR}}/`
2. Add main module file
3. Create test file in `{{TEST_DIR}}/`
4. Update index/exports
5. Add documentation

### Updating Configuration
- Edit files in `{{CONFIG_DIR}}/`
- Test with different environments
- Update `.env.example` if needed
- Document changes

### Running Tests
```bash
# All tests
{{TEST_COMMAND}}

# Specific test file
{{TEST_COMMAND}} {{TEST_DIR}}/specific_test.{{EXT}}

# With coverage
{{COVERAGE_COMMAND}}

# Watch mode
{{WATCH_COMMAND}}
```

## 📝 Code Style

### Formatting
- Use {{FORMATTING_TOOL}}
- Configure in `.{{FORMATTING_CONFIG}}`
- Run on commit: `{{FORMAT_COMMAND}}`

### Linting
- Use {{LINTING_TOOL}}
- Rules in `.{{LINTING_CONFIG}}`
- Fix with: `{{LINT_FIX_COMMAND}}`

### Commit Messages
Follow conventional commits:
- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation
- `style:` - Formatting
- `refactor:` - Code refactoring
- `test:` - Test changes
- `chore:` - Maintenance

## 🐛 Debugging

### Common Issues
{{#each COMMON_ISSUES}}
#### {{title}}
- **Symptom**: {{symptom}}
- **Solution**: {{solution}}
- **Prevention**: {{prevention}}
{{/each}}

### Debug Tools
- {{DEBUG_TOOL_1}} - {{DEBUG_TOOL_1_DESC}}
- {{DEBUG_TOOL_2}} - {{DEBUG_TOOL_2_DESC}}
- {{DEBUG_TOOL_3}} - {{DEBUG_TOOL_3_DESC}}

### Logging
```bash
# Enable debug logging
{{DEBUG_LOG_COMMAND}}

# View logs
{{LOG_VIEW_COMMAND}}
```

## 🚀 Deployment

### Build for Production
```bash
# Clean build
{{CLEAN_COMMAND}}

# Build
{{BUILD_COMMAND}}

# Package
{{PACKAGE_COMMAND}}
```

### Environment Setup
- Development: `.env.development`
- Testing: `.env.test`
- Production: `.env.production`

### Deploy Commands
{{#each DEPLOY_COMMANDS}}
- **{{environment}}**: `{{command}}`
{{/each}}

## 📚 Key Documentation

- [CONTEXT.md](CONTEXT.md) - Project philosophy
- [AGENTS.md](AGENTS.md) - Implementation guide
- [WORKFLOW.md](WORKFLOW.md) - User workflows
- [EVALS.md](EVALS.md) - Testing guide
- [CHANGELOG.md](CHANGELOG.md) - Version history

## 🔍 Claude-Specific Tips

### Effective Prompts
1. Be specific about file locations
2. Include error messages in prompts
3. Reference relevant documentation
4. Use context from recent changes

### Common Claude Tasks
```bash
# "Add error handling to {{SOURCE_DIR}}/{{MODULE}}"
# "Update tests for {{FEATURE}}"
# "Refactor {{FUNCTION}} for better performance"
# "Add documentation to {{API_ENDPOINT}}"
```

### Best Practices
- Always run tests after Claude changes
- Review generated code before committing
- Ask Claude to explain complex changes
- Use Claude for documentation updates

## 📋 Quick Reference

### File Extensions
- Source: `{{SOURCE_EXT}}`
- Test: `{{TEST_EXT}}`
- Config: `{{CONFIG_EXT}}`
- Docs: `.md`

### Important Files
- Main: `{{MAIN_FILE}}`
- Config: `{{CONFIG_FILE}}`
- Package: `{{PACKAGE_FILE}}`
- README: `README.md`

### Environment Variables
```bash
{{#each ENV_VARS}}
export {{name}}="{{value}}"
{{/each}}
```

---

## 🆘 Getting Help

1. Check [CONTEXT.md](CONTEXT.md) for design decisions
2. Review [WORKFLOW.md](WORKFLOW.md) for processes
3. Search existing issues in {{ISSUE_TRACKER}}
4. Ask in {{COMMUNITY_CHANNEL}}

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Version**: {{PROJECT_VERSION}}

---

*This guide is specifically for developers using Claude Code with {{PROJECT_NAME}}. For general documentation, see the other files in this repository.*
