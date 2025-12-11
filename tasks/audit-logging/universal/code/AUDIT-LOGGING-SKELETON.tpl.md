<!--
File: AUDIT-LOGGING-SKELETON.tpl.md
Purpose: Template for audit-logging implementation
Template Version: 1.0
-->

# AuditLogging Service Skeleton

## Purpose
Who did what, when, on which object, with replayable logs.

## Interface
```{{EXTENSION}}
// Universal interface for audit-logging service
interface AuditLoggingService {
    // Core methods that all implementations should provide
    async execute(input: InputType): Promise<OutputType>;
    async validate(input: InputType): Promise<boolean>;
    async getStatus(): Promise<ServiceStatus>;
}
```

## Implementation Requirements
All stack-specific implementations must provide:
- [ ] Core service class implementing the interface
- [ ] Error handling and logging
- [ ] Configuration management
- [ ] Health check endpoints
- [ ] Input validation and sanitization

## Stack-Specific Considerations
- **Python**: Use async/await patterns, implement with FastAPI/Flask
- **Go**: Use goroutines for concurrency, implement with net/http
- **Node.js**: Use Promises/async-await, implement with Express
- **React/Next.js**: Use hooks and modern patterns
- **Flutter**: Use async/await and provider patterns

## Variables Available
- `{{PROJECT_NAME}}`: Project name
- `{{TASK_NAME}}`: Task name (audit-logging)
- `{{STACK}}`: Target stack
- `{{TIER}}`: Target tier
- `{{EXTENSION}}`: File extension for target stack

## Configuration
The service expects configuration in `config/audit-logging.yaml`:

```yaml
audit-logging:
  enabled: true
  timeout: 30
  retry_attempts: 3
  # Stack-specific settings will be added here
```
