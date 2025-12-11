# {{PROJECT_NAME}} - Windsurf/Codeium Guide

> Quick reference for developers using Windsurf (Codeium) with {{PROJECT_NAME}}

## 🚀 Getting Started

### Installation
1. Install [Windsurf](https://windsurf.ai) or Codeium extension
2. Sign in with your account
3. Enable for {{PROJECT_NAME}}

### Basic Usage
- `Ctrl+I` - Open AI chat
- `Ctrl+Enter` - Accept inline suggestion
- Use natural language to generate code

## 🎯 {{PROJECT_NAME}} Integration

### Context Understanding
Windsurf understands:
- {{LANGUAGE}} syntax and patterns
- {{FRAMEWORK}} conventions
- Project structure
- Import/export relationships

### Effective Prompts
{{#each WINDSURF_PROMPTS}}
- "{{prompt}}"
{{/each}}

## 📝 Best Practices

1. Provide clear context about {{PROJECT_NAME}}
2. Reference existing code patterns
3. Generate with {{PROJECT_NAME}} conventions
4. Test generated code thoroughly

## 🎯 Configuration

```json
{
  "windsurf.model": "{{MODEL_NAME}}",
  "windsurf.enableInline": true,
  "windsurf.contextLines": {{CONTEXT_LINES}}
}
```

---

**Last Updated**: {{LAST_UPDATED_DATE}}
