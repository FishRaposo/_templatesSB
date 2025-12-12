<!--
File: PROJECT-STRUCTURE.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# {{PROJECT_NAME}} - Rust Project Structure

**Tier**: {{TIER}} | **Stack**: Rust

## 🦀 Canonical Rust Project Structure

### **MVP Tier (Single Binary)**
```
{{PROJECT_NAME}}/
├── Cargo.toml
├── src/
│   └── main.rs
└── README.md
```

### **Core Tier (Library + Binary + Modules)**
```
{{PROJECT_NAME}}/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config.rs
│   ├── error.rs
│   ├── services/
│   │   └── mod.rs
│   └── routes/
│       └── mod.rs
├── tests/
│   └── smoke_test.rs
└── README.md
```

### **Enterprise Tier (Layered + Observability + Security)**
```
{{PROJECT_NAME}}/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config/
│   │   └── mod.rs
│   ├── core/
│   │   ├── error.rs
│   │   └── logging.rs
│   ├── security/
│   │   └── mod.rs
│   ├── routes/
│   │   └── mod.rs
│   └── services/
│       └── mod.rs
├── tests/
│   ├── smoke_test.rs
│   └── api_test.rs
└── README.md
```
