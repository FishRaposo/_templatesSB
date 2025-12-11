# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: unknown template utilities
# Tier: base
# Stack: unknown
# Category: utilities

# RestApiService Service Skeleton

## Purpose
Standard CRUD API with auth, validation, pagination, rate limits.

## Interface
```{{EXTENSION}}
// Universal interface for rest-api-service service
interface RestApiServiceService {
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
- `{{TASK_NAME}}`: Task name (rest-api-service)
- `{{STACK}}`: Target stack
- `{{TIER}}`: Target tier
- `{{EXTENSION}}`: File extension for target stack

## Configuration
The service expects configuration in `config/rest-api-service.yaml`:

```yaml
rest-api-service:
  enabled: true
  timeout: 30
  retry_attempts: 3
  # Stack-specific settings will be added here
```
