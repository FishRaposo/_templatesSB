[package]
name = "{{PROJECT_NAME}}"
version = "0.1.0"
edition = "2021"
authors = ["[[.Author]]"]
description = "{{PROJECT_DESCRIPTION}}"
license = "MIT OR Apache-2.0"
repository = "https://github.com/yourorg/{{PROJECT_NAME}}"
readme = "README.md"
keywords = ["backend", "api", "service"]
categories = ["web-programming", "network-programming"]

[dependencies]
# Web framework
actix-web = "4.0"
tokio = { version = "1.0", features = ["full"] }

# Configuration
config = "0.13"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Logging and tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tracing-actix-web = "0.7"

# Error handling
thiserror = "1.0"
anyhow = "1.0"

# Database (PostgreSQL)
sqlx = { version = "0.6", features = ["postgres", "runtime-tokio-native-tls", "macros", "chrono", "json"] }

# Async utilities
futures = "0.3"
async-trait = "0.1"

# Validation
validator = { version = "0.16", features = ["derive"] }

# Environment variables
dotenvy = "0.15"

# UUID generation
uuid = { version = "1.0", features = ["v4", "serde"] }

# Time handling
chrono = { version = "0.4", features = ["serde"] }

# JSON Web Tokens
jsonwebtoken = "8.0"

# Password hashing
bcrypt = "0.13"

# HTTP client
reqwest = { version = "0.11", features = ["json"] }

# Caching
redis = { version = "0.22", features = ["tokio-comp"] }

# Metrics
metrics = "0.20"
metrics-exporter-prometheus = "0.11"

# Health checks
actix-web-httpauth = "0.8"

# API documentation
utoipa = { version = "3.0", features = ["actix_extras", "chrono", "uuid"] }
utoipa-swagger-ui = { version = "3.0", features = ["actix-web"] }

# Testing
mockall = "0.11"
test-case = "2.0"

[dev-dependencies]
# Test utilities
mockito = "1.0"
serial_test = "1.0"

# Test data generation
fake = "2.0"

# Async test utilities
tokio-test = "0.4"

[features]
default = ["logging", "metrics", "swagger"]
logging = ["tracing-subscriber/env-filter"]
metrics = ["metrics-exporter-prometheus"]
swagger = ["utoipa-swagger-ui"]

[profile.dev]
opt-level = 0
debug = true
debug-assertions = true
overflow-checks = true
lto = false
panic = "unwind"
incremental = true
codegen-units = 256
rpath = false

[profile.release]
opt-level = 3
debug = false
debug-assertions = false
overflow-checks = false
lto = true
panic = "unwind"
incremental = false
codegen-units = 1
rpath = false

[profile.test]
opt-level = 0
debug = true
debug-assertions = true
overflow-checks = true
lto = false
panic = "unwind"
incremental = true
codegen-units = 256
rpath = false

[workspace]
members = [
    ".",
    # Add workspace members here if needed
]

# Build configuration
[package.metadata]
# Docker build configuration
docker = { 
    image = "rust:1.60",
    command = "cargo build --release",
    target = "x86_64-unknown-linux-gnu"
}

# CI/CD configuration
[package.metadata.ci]
# GitHub Actions configuration
github = { 
    runs-on = "ubuntu-latest",
    steps = [
        "uses: actions/checkout@v2",
        "uses: actions-rs/toolchain@v1",
        "run: cargo test",
        "run: cargo build --release"
    ]
}

# Deployment configuration
[package.metadata.deploy]
# Kubernetes deployment configuration
kubernetes = { 
    replicas = 3,
    ports = [8080],
    resources = { 
        requests = { cpu = "100m", memory = "128Mi" },
        limits = { cpu = "500m", memory = "512Mi" }
    }
}

# Documentation
[package.metadata.docs]
# Documentation generation configuration
docsrs = { 
    features = ["all"],
    targets = ["x86_64-unknown-linux-gnu"]
}

# Benchmarking
[[bench]]
name = "performance"
harness = false

[dependencies.criterion]
version = "0.4"
features = ["html_reports"]

# Example configuration
# Uncomment and modify as needed for your project

# [package.metadata.manifest]
# authors = ["Your Name <your.email@example.com>"]
# description = "A comprehensive Rust backend service"
# homepage = "https://example.com/{{PROJECT_NAME}}"
# documentation = "https://docs.rs/{{PROJECT_NAME}}"
# repository = "https://github.com/yourorg/{{PROJECT_NAME}}"
# readme = "README.md"
# license = "MIT OR Apache-2.0"
# keywords = ["backend", "api", "service", "rust"]
# categories = ["web-programming", "network-programming", "asynchronous"]

# [badges]
# maintenance = { status = "actively-developed" }

# [lib]
# name = "{{PROJECT_NAME}}"
# path = "src/lib.rs"
# crate-type = ["cdylib", "rlib"]

# [[bin]]
# name = "{{PROJECT_NAME}}"
# path = "src/main.rs"

# [target.'cfg(target_arch = "wasm32")'.dependencies]
# wasm-bindgen = "0.2"

# [target.'cfg(target_os = "linux")'.dependencies]
# linux-specific dependencies

# [target.'cfg(target_os = "windows")'.dependencies]
# windows-specific dependencies

# [target.'cfg(target_os = "macos")'.dependencies]
# macos-specific dependencies