<!--
File: ERROR-HANDLING.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Rust Error Handling - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Rust

## Recommended approach

- Use `thiserror` for structured, typed errors.
- Use `anyhow` for application boundaries when you need rich context.
- Avoid panics in production paths.
