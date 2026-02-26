# Code Quality Review Skill

This skill helps you measure and improve code through structured review checklists and automated analysis.

## Quick Start

Invoke this skill when you need to:
- Conduct a thorough code review
- Create a review checklist or PR template
- Set up automated quality gates in CI
- Give constructive review feedback
- Self-review before requesting review

## Example Usage

### Basic Example
```
User: Review this function for quality issues

Agent: I'll check correctness, design, naming, error handling,
security, and test coverage using a structured checklist...
```

## Review Focus Areas

| Area | Human Review | Automate |
|------|-------------|----------|
| Correctness & logic | ✅ | Partially (tests) |
| Design & architecture | ✅ | ❌ |
| Security | ✅ | Partially (scanners) |
| Formatting & style | ❌ | ✅ (prettier, eslint) |
| Test coverage | Partially | ✅ (coverage tools) |

## Related Skills

- **clean-code** - Standards being checked during review
- **code-metrics** - Quantitative quality data
- **code-standards** - Automated rules that reduce review burden
