# Legacy Code Migration Skill

This skill helps you migrate legacy code safely with strangler fig, characterization tests, and incremental rewrites.

## Quick Start

Invoke this skill when you need to:
- Modernize a legacy system without a big-bang rewrite
- Write characterization tests for untested code
- Apply the strangler fig pattern
- Run old and new systems in parallel for verification
- Plan a phased migration with feature flags

## Example Usage

### Basic Example
```
User: How do I start migrating this old module?

Agent: I'll help you write characterization tests first, then create
a new interface, wrap the legacy behind an adapter, and migrate
one method at a time...
```

## Migration Phases

| Phase | What Happens | Risk |
|-------|-------------|------|
| 1. Characterize | Write tests capturing current behavior | None |
| 2. Wrap | Legacy adapter behind new interface | Low |
| 3. Shadow | Compare old and new for all traffic | Low |
| 4. Canary | Serve new to 5% of traffic | Medium |
| 5. Rollout | Gradually increase to 100% | Medium |
| 6. Cleanup | Remove legacy code | Low |

## Related Skills

- **technical-debt** - Prioritize what to migrate first
- **code-refactoring** - Safely restructure during migration
- **error-handling** - Implement proper error handling in new system
