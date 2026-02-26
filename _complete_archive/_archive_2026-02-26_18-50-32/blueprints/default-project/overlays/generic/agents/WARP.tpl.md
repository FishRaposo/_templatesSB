# {{PROJECT_NAME}} - Warp Terminal Guide

> Quick reference for developers using Warp AI with {{PROJECT_NAME}}

## 🚀 Getting Started

### Installation
1. Download [Warp](https://www.warp.dev)
2. Install and launch
3. Enable AI features in settings

### Basic Usage
- `Cmd+Shift+.` - Open AI command search
- Type natural language commands
- Use AI to generate shell commands

## 🎯 {{PROJECT_NAME}} Integration

### Common {{PROJECT_NAME}} Commands
{{#each PROJECT_COMMANDS}}
- "{{description}}"
  ```bash
  {{command}}
  ```
{{/each}}

### AI Prompt Examples
- "How do I run tests in {{PROJECT_NAME}}?"
- "Show me the build process for {{PROJECT_NAME}}"
- "Generate a commit message for these changes"
- "Help me debug this {{PROJECT_NAME}} error"

## 📝 Best Practices

1. Use Warp's workflow features for {{PROJECT_NAME}}
2. Save common commands as workflows
3. Leverage AI for complex shell operations
4. Use block selection for multi-line commands

## 🎯 {{PROJECT_NAME}} Workflows

### Development Workflow
```bash
# Warp workflow for development
git checkout -b feature/new-feature
{{DEV_SERVER_COMMAND}}
{{TEST_COMMAND}}
git add .
git commit -m "feat: add new feature"
```

### Deployment Workflow
```bash
# Warp workflow for deployment
{{BUILD_COMMAND}}
{{DEPLOY_COMMAND}}
{{HEALTH_CHECK_COMMAND}}
```

---

**Last Updated**: {{LAST_UPDATED_DATE}}
