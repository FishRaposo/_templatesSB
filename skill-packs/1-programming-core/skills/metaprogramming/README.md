# Metaprogramming Skill

Write code that manipulates or generates other code — proxies, decorators, reflection, code generation, and template systems.

## Quick Start

Invoke this skill when you need to:
- Intercept property access with proxies (JS) or `__getattr__` (Python)
- Add cross-cutting behavior with decorators (timing, logging, retry)
- Inspect objects at runtime via reflection
- Generate code from templates or AST transforms

## Example Usage

```
User: I want to add timing to every method in this class without modifying each one

Agent: I'll show you a decorator approach — in Python use @timed,
in JS use a Proxy that wraps all method calls with timing...
```

## Languages

Examples in JavaScript, Python, Go, and Rust. See `../PACK.md` for the **Language Adaptation Guide** (C#, Java, Kotlin, Swift, etc.).

## Resources

- See `./_examples/basic-examples.md` for proxies, reflection, decorators

## Related Skills

- **abstraction** - Metaprogramming creates abstractions
- **functional-paradigm** - Metaprogramming in functional style
- **modularity** - Generate and compose modular components
