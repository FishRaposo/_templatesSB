<!--
File: TESTING-EXAMPLES-rust.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Rust Testing Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Rust

## Commands

```bash
cargo test
cargo test -- --nocapture
```

## Unit tests (in-module)

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn adds_numbers() {
        assert_eq!(2 + 2, 4);
    }
}
```

## Integration tests (tests/)

```rust
// tests/smoke_test.rs
#[test]
fn smoke_test() {
    assert!(true);
}
```

## Notes

- Keep tests deterministic.
- Prefer testing public APIs rather than private implementation details.
