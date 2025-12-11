<!--
File: TEST-STRATEGY.tpl.md
Purpose: Template for embedding-index implementation
Template Version: 1.0
-->

# Embedding Index Testing Strategy

## Testing Approach
Comprehensive testing strategy for embedding-index functionality across all tiers.

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
class TestEmbeddingIndex:
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
func TestEmbeddingIndexService(t *testing.T) {
    // Test core service functionality
}

func TestEmbeddingIndexConfiguration(t *testing.T) {
    // Test configuration loading
}
```

### Node.js Tests
```javascript
// Test structure using Jest
describe('EmbeddingIndexService', () => {
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
import {EmbeddingIndexComponent} from './{EmbeddingIndexComponent}';

describe('EmbeddingIndexComponent', () => {
    test('renders correctly', () => {
        render(<{EmbeddingIndexComponent} />);
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
pytest tests/embedding-index/
{% elif STACK == "go" %}
go test ./embedding-index/...
{% elif STACK == "node" %}
npm test -- tests/embedding-index/
{% elif STACK == "nextjs" %}
npm test -- tests/embedding-index/
{% elif STACK == "flutter" %}
flutter test test/embedding-index/
{% endif %}
```
