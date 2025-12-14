# {{PROJECT_NAME}} - Google Gemini Guide

> Quick reference for developers using Google Gemini (formerly Duet AI) with {{PROJECT_NAME}}

## 🚀 Getting Started

### Installation
1. Install [Gemini Code Assist](https://cloud.google.com/ai/generator) extension
2. Connect to your Google Cloud project
3. Enable Gemini for {{PROJECT_NAME}}

### Basic Usage
- Start coding to receive AI suggestions
- Use `Ctrl+Space` to trigger suggestions
- Press `Tab` to accept inline suggestions

## 🎯 Project-Specific Integration

### {{PROJECT_NAME}} Context
Gemini understands:
- {{FRAMEWORK}} framework patterns
- {{LANGUAGE}} language conventions
- Project structure in {{SOURCE_DIR}}/
- Test patterns in {{TEST_DIR}}/

### Code Generation Prompts
{{#each GEMINI_PROMPTS}}
#### {{category}}
```
{{prompt}}
```
{{/each}}

## 📝 Effective Prompting

### For {{PROJECT_NAME}}
- "Generate a {{COMPONENT_TYPE}} with {{FEATURES}}"
- "Create {{TEST_TYPE}} tests for {{MODULE}}"
- "Implement {{PATTERN_NAME}} pattern"
- "Add {{FEATURE_NAME}} to existing code"

### Prompt Templates
{{#each PROMPT_TEMPLATES}}
```text
{{template}}
```
{{/each}}

## 🔧 Configuration

### IDE Settings
```json
{
  "gemini.enabled": true,
  "gemini.model": "{{GEMINI_MODEL}}",
  "gemini.temperature": {{TEMPERATURE}},
  "gemini.maxTokens": {{MAX_TOKENS}}
}
```

### Google Cloud Setup
```bash
# Set up authentication
gcloud auth application-default login
gcloud config set project {{PROJECT_ID}}

# Enable Gemini API
gcloud services enable generativeai.googleapis.com
```

## 🎨 Best Practices

### Code Quality
- Review all generated code
- Ensure compliance with {{PROJECT_NAME}} standards
- Add appropriate error handling
- Include necessary comments

### Performance
- Generate code in chunks
- Use specific, focused prompts
- Leverage context from open files
- Iterate on complex generations

## 🚨 Common Issues

### Authentication
- **Problem**: API key errors
- **Solution**: Check gcloud authentication
- **Problem**: Project access denied
- **Solution**: Verify IAM permissions

### Code Quality
- **Problem**: Generic suggestions
- **Solution**: Provide more context
- **Problem**: Outdated patterns
- **Solution**: Reference recent examples

## 📊 Advanced Features

### Multi-file Generation
- Generate related files together
- Maintain consistency across modules
- Use project-wide context

### Code Refactoring
- Select code and request refactoring
- Specify refactoring patterns
- Apply {{PROJECT_NAME}} conventions

## 🔍 Code Examples

### {{EXAMPLE_1_TITLE}}
```{{LANGUAGE}}
// Prompt: {{EXAMPLE_1_PROMPT}}
{{EXAMPLE_1_CODE}}
```

### {{EXAMPLE_2_TITLE}}
```{{LANGUAGE}}
// Prompt: {{EXAMPLE_2_PROMPT}}
{{EXAMPLE_2_CODE}}
```

## 📚 Integration Features

### Documentation Generation
- Generate API documentation
- Create code examples
- Add inline documentation

### Test Generation
- Unit tests with {{TESTING_FRAMEWORK}}
- Integration test scenarios
- Mock data generation

## 🎯 Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Space` | Trigger suggestion |
| `Ctrl+Enter` | Generate full code |
| `Alt+/` | Quick actions menu |
| `Ctrl+Shift+G` | Gemini chat |

## 📝 {{PROJECT_NAME}} Tips

1. **Use file-specific context** by opening relevant files
2. **Reference project patterns** in prompts
3. **Leverage Google Cloud integration** for cloud features
4. **Generate with testing in mind**
5. **Follow {{PROJECT_NAME}} naming conventions**

## 🔗 Resources

- [Google Gemini Documentation](https://cloud.google.com/ai/generator)
- [Gemini API Reference](https://ai.google.dev/docs)
- [{{PROJECT_NAME}} Documentation](../DOCUMENTATION.md)

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Gemini Version**: {{GEMINI_VERSION}}

---

*Optimize your development workflow with Google Gemini in {{PROJECT_NAME}} using these guidelines and best practices.*
