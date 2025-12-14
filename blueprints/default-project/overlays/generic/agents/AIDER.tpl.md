# {{PROJECT_NAME}} - Aider CLI Guide

> Quick reference for developers using Aider with {{PROJECT_NAME}}

## 🚀 Getting Started

### Installation
```bash
# Install Aider
pip install aider-chat

# Or with pipx
pipx install aider-chat
```

### Basic Usage
```bash
# Start Aider in {{PROJECT_NAME}}
cd {{PROJECT_NAME}}
aider

# Add specific files
aider {{SOURCE_DIR}}/{{MAIN_FILE}}
```

## 🎯 {{PROJECT_NAME}} Integration

### Project Setup
```bash
# Configure for {{PROJECT_NAME}}
aider --model {{AI_MODEL}} --format {{FORMAT_TYPE}}
```

### Common Commands
{{#each AIDER_COMMANDS}}
- `/{{command}}` - {{description}}
{{/each}}

## 📝 Best Practices

1. Use `.aiderignore` for sensitive files
2. Configure model for {{LANGUAGE}} development
3. Use `/diff` to review changes
4. Commit frequently with Aider's help

## 🎯 Configuration

```bash
# .aider.conf.yml
model: {{AI_MODEL}}
format: {{FORMAT_TYPE}}
input-history-file: .aider.input.history
chat-history-file: .aider.chat.history
```

---

**Last Updated**: {{LAST_UPDATED_DATE}}
