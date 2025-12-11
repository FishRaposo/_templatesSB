# {{PROJECT_NAME}} - Cursor AI Guide

> Quick reference for developers using Cursor AI with {{PROJECT_NAME}}

## 🚀 Getting Started

### Installation
1. Download [Cursor AI](https://cursor.sh)
2. Install and launch
3. Open {{PROJECT_NAME}} in Cursor

### Basic Usage
- `Cmd+K` (Mac) / `Ctrl+K` (Windows/Linux) - AI chat
- `Cmd+L` (Mac) / `Ctrl+L` (Windows/Linux) - Inline edit
- `Tab` to accept suggestions

## 🎯 {{PROJECT_NAME}} Integration

### Project Context
Cursor understands:
- {{LANGUAGE}} language specifics
- {{FRAMEWORK}} framework patterns
- Project structure in {{SOURCE_DIR}}/
- Configuration in {{CONFIG_FILES}}

### Effective Prompts
{{#each CURSOR_PROMPTS}}
- {{prompt}}
{{/each}}

## 🔧 Configuration

```json
{
  "cursor.model": "{{CURSOR_MODEL}}",
  "cursor.temperature": {{TEMPERATURE}},
  "cursor.enableInline": true,
  "cursor.contextSize": {{CONTEXT_SIZE}}
}
```

## 📝 Best Practices

1. Use file-specific context
2. Reference existing patterns
3. Generate with testing in mind
4. Follow {{PROJECT_NAME}} conventions

## 🎯 Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd+K` | AI chat |
| `Cmd+L` | Inline edit |
| `Cmd+Shift+P` | Command palette |

---

**Last Updated**: {{LAST_UPDATED_DATE}}
