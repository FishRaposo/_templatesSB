<!--
File: PERFORMANCE.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Rust Performance - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Rust

## Build profiles

```bash
cargo build --release
```

## Profiling

- Prefer measuring before optimizing.
- Consider flamegraphs for hotspots.
