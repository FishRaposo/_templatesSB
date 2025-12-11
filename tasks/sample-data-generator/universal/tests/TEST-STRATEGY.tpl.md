<!--
File: TEST-STRATEGY.tpl.md
Purpose: Template for sample-data-generator implementation
Template Version: 1.0
-->

# Sample Data Generator Testing Strategy

## Testing Approach
Comprehensive testing strategy for sample-data-generator functionality across all tiers.

## Test Categories

### MVP Tier Tests
- [ ] Basic functionality tests
- [ ] Input validation tests
- [ ] Error handling tests
- [ ] Configuration loading tests

### Core Tier Tests (MVP +)
- [ ] Integration tests
- [ ] Performance tests
- [ ] Security tests
- [ ] Error recovery tests

### Full Tier Tests (Core +)
- [ ] Load testing
- [ ] Failover testing
- [ ] Compliance tests
- [ ] End-to-end tests

## Stack-Specific Testing

### Python Tests
```python
# Test structure using pytest
class TestSampleDataGenerator:
    async def test_basic_functionality(self):
        # Test core service functionality
        pass
    
    async def test_error_handling(self):
        # Test error scenarios
        pass
    
    async def test_configuration(self):
        # Test configuration loading
        pass
```

### Go Tests
```go
// Test structure using testing package
func TestSampleDataGeneratorService(t *testing.T) {
    // Test core service functionality
}

func TestSampleDataGeneratorConfiguration(t *testing.T) {
    // Test configuration loading
}
```

### Node.js Tests
```javascript
// Test structure using Jest
describe('SampleDataGeneratorService', () => {
    test('basic functionality', async () => {
        // Test core service functionality
    });
    
    test('error handling', async () => {
        // Test error scenarios
    });
});
```

### React/Next.js Tests
```javascript
// Test structure using React Testing Library
import { render, screen } from '@testing-library/react';
import {SampleDataGeneratorComponent} from './{SampleDataGeneratorComponent}';

describe('SampleDataGeneratorComponent', () => {
    test('renders correctly', () => {
        render(<{SampleDataGeneratorComponent} />);
        // Test component rendering
    });
});
```

## Test Data Management
- Use fixtures for consistent test data
- Mock external dependencies
- Clean up test artifacts after runs
- Validate configuration loading

## Coverage Requirements
- **MVP**: 70% minimum coverage
- **Core**: 85% minimum coverage  
- **Full**: 95% minimum coverage

## Test Execution
```bash
# Run tests for different stacks
{% if STACK == "python" %}
pytest tests/sample-data-generator/
{% elif STACK == "go" %}
go test ./sample-data-generator/...
{% elif STACK == "node" %}
npm test -- tests/sample-data-generator/
{% elif STACK == "nextjs" %}
npm test -- tests/sample-data-generator/
{% elif STACK == "flutter" %}
flutter test test/sample-data-generator/
{% endif %}
```
