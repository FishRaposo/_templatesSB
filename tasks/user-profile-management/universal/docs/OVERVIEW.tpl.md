<!--
File: OVERVIEW.tpl.md
Purpose: Template for user-profile-management implementation
Template Version: 1.0
-->

# User Profile Management Overview

## Purpose
Profile CRUD, avatars, preferences, settings pages.

## Features
- **Core Functionality**: Profile CRUD, avatars, preferences, settings pages.
- **Configuration**: Flexible configuration options
- **Monitoring**: Built-in health checks and metrics
- **Error Handling**: Comprehensive error management
- **Integration**: Seamless integration with {{PROJECT_NAME}} architecture

## Categories
users, frontend, crud

## Usage Examples

### Basic Usage
```{{EXTENSION}}
// Example of basic task usage
const result = await userprofilemanagementService.execute(input);
```

### Advanced Configuration
```yaml
# Advanced configuration example
user-profile-management:
  advanced_setting: true
  custom_option: "value"
  performance:
    max_workers: 20
    batch_size: 500
```

## Supported Stacks
**Default Stacks**: react, nextjs
**All Supported Stacks**: react, nextjs, flutter, node, python

## Tier Recommendations
- **basic-profile**: mvp
- **production-profile**: core

## Stack-Specific Notes

### Python Implementation
- Uses async/await patterns with FastAPI/Flask
- Includes comprehensive type hints
- Follows PEP 8 coding standards
- Integrates with Python ecosystem (pytest, black, etc.)

### Go Implementation
- Uses goroutines for concurrent operations
- Follows Go idioms and best practices
- Includes comprehensive error handling
- Integrates with Go testing framework

### Node.js Implementation
- Uses modern ES6+ features
- Includes TypeScript definitions
- Follows Node.js best practices
- Integrates with npm ecosystem

### React/Next.js Implementation
- Uses modern React patterns (hooks, context)
- Includes TypeScript support
- Follows React best practices
- Integrates with Next.js when applicable

### Flutter Implementation
- Uses modern Flutter patterns
- Includes proper state management
- Follows Flutter best practices
- Integrates with Flutter testing framework

## Integration Points
- **Service Integration**: How it integrates with main application
- **Configuration**: How to configure the task
- **Monitoring**: How to monitor task performance
- **Error Handling**: How errors are handled and reported

## Configuration
The task uses configuration from `config/user-profile-management.yaml`:

```yaml
user-profile-management:
  enabled: true
  timeout: 30
  retry_attempts: 3
  # Additional stack-specific settings
```

## Monitoring and Observability
- Health check endpoint at `/health`
- Metrics available at `/metrics`
- Structured logging with correlation IDs
- Performance monitoring and alerting

## Troubleshooting
- **Common Issue 1**: Check configuration file syntax
- **Common Issue 2**: Verify stack-specific dependencies
- **Performance Issues**: Adjust concurrency settings
- **Integration Issues**: Check API endpoints and authentication

## Migration Guide
If upgrading between tiers:
- **MVP → Core**: Add integration tests and monitoring
- **Core → Full**: Add advanced security and compliance features
- Configuration changes are backward compatible
- Data migration handled automatically

## Dependencies
- **Universal**: logging, configuration management
- **react**: Stack-specific dependencies
- **nextjs**: Stack-specific dependencies
- **flutter**: Stack-specific dependencies
- **node**: Stack-specific dependencies
- **python**: Stack-specific dependencies

## Best Practices
- Follow stack-specific coding conventions
- Use appropriate error handling patterns
- Implement proper logging and monitoring
- Write comprehensive tests
- Document configuration options
- Handle edge cases gracefully

## Related Tasks

