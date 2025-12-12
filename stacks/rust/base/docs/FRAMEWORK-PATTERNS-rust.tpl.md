<!--
File: FRAMEWORK-PATTERNS-rust.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Rust Framework Patterns - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Rust

## Patterns

- Use `src/lib.rs` for reusable application logic and keep `src/main.rs` thin.
- Prefer explicit module boundaries (`mod`, `pub mod`) over deep nesting.
- Use `Result<T, E>` consistently and centralize error types.

## Recommended crates

- `tokio` for async runtime
- `thiserror` + `anyhow` for error modeling
- `tracing` + `tracing-subscriber` for structured logs
- `serde` for (de)serialization

## Tier expectations

- **MVP**: minimal modules, minimal dependencies.
- **Core**: config module, error module, structured logging.
- **Enterprise**: observability, security boundaries, stronger validation.
