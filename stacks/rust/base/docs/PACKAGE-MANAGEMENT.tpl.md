<!--
File: PACKAGE-MANAGEMENT.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Rust Package Management - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Rust

## Cargo basics

- Dependencies live in `Cargo.toml`
- Use `cargo build`, `cargo run`, `cargo test`

## Feature flags

Use Cargo features to gate optional integrations.

```toml
[features]
default = []
metrics = []
```
