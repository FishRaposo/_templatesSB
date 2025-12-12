<!--
File: CI-EXAMPLES-rust.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Rust CI Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Rust

## GitHub Actions

```yaml
name: Rust CI
on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo fmt --check
      - run: cargo clippy -- -D warnings
      - run: cargo test
```
