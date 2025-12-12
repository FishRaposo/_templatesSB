<!--
File: ARCHITECTURE-rust.tpl.md
Purpose: Architectural guidelines for Rust projects
Generated for: {{PROJECT_NAME}}
-->

# Architecture Guide: {{PROJECT_NAME}}

## Core Philosophy
This project follows a **Hexagonal (Ports and Adapters)** architecture pattern, leveraging Rust's type system to enforce boundaries.
The goal is to decouple the core business logic from external concerns like databases, APIs, and UIs.

## Directory Structure
```
src/
├── domain/       # Core business logic (Pure Rust, no I/O)
│   ├── models/   # Domain structures
│   └── errors.rs # Domain-level errors
├── ports/        # Interfaces (Traits) definitions
│   ├── inbound/  # API definitions (e.g., Service traits)
│   └── outbound/ # Repository/Adapter traits
├── adapters/     # Implementation of ports
│   ├── http/     # Web controllers (Axum/Actix)
│   ├── db/       # Database implementations (Sqlx/Diesel)
│   └── external/ # 3rd party APIs
└── config/       # Configuration loading
```

## Key Patterns
- **Newtype Pattern**: Use tuple structs for strong typing (e.g., `pub struct UserId(Uuid);`).
- **Error Handling**: Use `thiserror` for library/domain errors and `anyhow` for application/handler errors.
- **Dependency Injection**: Pass traits (e.g., `Arc<dyn UserRepository>`) to service constructors.
- **Async Runtime**: Use `tokio` as the default runtime.

## Testing Strategy
- **Unit Tests**: Co-located in the same file `mod tests`. Pure business logic testing.
- **Integration Tests**: In `tests/` directory. Test interaction with database/API.
- **Property Tests**: Use `proptest` for invariant checking.
