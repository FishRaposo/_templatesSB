<!--
File: ARCHITECTURE-rust.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Rust Architecture - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Rust

## Goals

- Clear module boundaries
- Testable units with minimal global state
- Explicit error handling

## Suggested layering

- `routes/`: transport layer (HTTP, CLI)
- `services/`: business logic
- `core/`: shared utilities (error/logging/config)

## Dependency direction

- `routes` depends on `services`
- `services` depends on `core`
- `core` should not depend on application layers
