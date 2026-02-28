# Flutter state management choices

Quick guide for choosing the right state management approach.

## Decision matrix

| Criteria | Provider | Bloc | Riverpod | GetX |
|----------|----------|------|----------|------|
| Learning curve | Low | Medium | Medium | Low |
| Boilerplate | Minimal | High | Medium | Minimal |
| Testability | Good | Excellent | Excellent | Fair |
| Scalability | Medium | High | High | Low |
| Debugging | Good | Excellent (BlocObserver) | Good (DevTools) | Limited |

## When to use each

### Provider
- Simple to medium apps (1-5 screens with shared state)
- Quick prototypes that may grow
- Teams new to Flutter state management
- Example: Todo app, settings page, simple CRUD

### Bloc
- Large apps with complex state transitions
- Event-driven architectures
- Teams that want predictable, testable state changes
- Example: E-commerce checkout flow, multi-step forms

### Riverpod
- Complex apps with heavy business logic
- Apps needing compile-time safety
- Projects requiring excellent testability
- Example: Finance apps, dashboards, data-heavy UIs

### GetX
- Rapid prototyping only
- Small internal tools with short lifespan
- Not recommended for long-term production apps

## Quick setup commands

```bash
# Provider
flutter pub add provider

# Bloc
flutter pub add flutter_bloc

# Riverpod
flutter pub add flutter_riverpod

# GetX (use with caution)
flutter pub add get
```