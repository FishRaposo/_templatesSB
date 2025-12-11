<!--
File: unit-tests.tpl.md
Purpose: Comprehensive unit testing template for generic/technology-agnostic projects
Template Version: 1.0
-->

# ----------------------------------------------------------------------------- 
# FILE: unit-tests.tpl.md
# PURPOSE: Comprehensive unit testing for generic/technology-agnostic projects
# USAGE: Technology-agnostic unit testing principles and patterns
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Unit Testing Suite - Generic Implementation

## Overview

This comprehensive unit testing suite provides technology-agnostic testing patterns applicable to any programming language or framework. It covers fundamental testing principles, design pattern testing, and universal testing strategies that work across all technology stacks.

## Core Testing Principles

### 1. Universal Testing Philosophy

#### Test Pyramid Foundation
- **Unit Tests**: Fast, isolated, focused on single components
- **Integration Tests**: Component interactions and external dependencies
- **System Tests**: End-to-end workflows and user scenarios
- **Acceptance Tests**: Business requirements validation

#### Language-Agnostic Testing Concepts
- **Arrange-Act-Assert (AAA)**: Universal test structure pattern
- **Given-When-Then**: Behavior-driven development approach
- **Test Doubles**: Mocks, stubs, fakes, spies for isolation
- **Test Data Builders**: Consistent test data generation
- **Property-Based Testing**: Generate test cases automatically

### 2. Design Pattern Testing

#### MVC Pattern Testing
```pseudocode
// Model Testing
class ModelTest:
    function test_model_validation():
        // Test business logic validation
        assert model.validate(invalid_data) == false
        assert model.validate(valid_data) == true
    
    function test_model_state_transitions():
        // Test state machine logic
        model.transition_to("pending")
        assert model.state == "pending"
        
        model.transition_to("approved")
        assert model.state == "approved"

// View Testing  
class ViewTest:
    function test_view_rendering():
        // Test UI component rendering
        view_data = { "title": "Test", "items": [] }
        rendered = view.render(view_data)
        assert rendered.contains("Test")
        assert rendered.contains("items-container")
    
    function test_view_event_handling():
        // Test user interaction handling
        view.simulate_click("submit-button")
        assert controller.received_event("submit")

// Controller Testing
class ControllerTest:
    function test_controller_request_handling():
        // Test request processing
        request = create_request("POST", "/users", user_data)
        response = controller.handle(request)
        assert response.status == 201
        assert response.data["id"] != null
    
    function test_controller_validation():
        // Test input validation
        invalid_request = create_request("POST", "/users", {})
        response = controller.handle(invalid_request)
        assert response.status == 400
        assert response.errors.length > 0
```

#### Repository Pattern Testing
```pseudocode
class RepositoryTest:
    function test_repository_create():
        // Test entity creation
        entity_data = { "name": "Test Entity", "value": 100 }
        entity = repository.create(entity_data)
        
        assert entity.id != null
        assert entity.name == entity_data.name
        assert entity.created_at != null
    
    function test_repository_find_by_id():
        // Test entity retrieval
        existing_entity = repository.create({ "name": "Existing" })
        found_entity = repository.find_by_id(existing_entity.id)
        
        assert found_entity != null
        assert found_entity.id == existing_entity.id
        assert found_entity.name == existing_entity.name
    
    function test_repository_update():
        // Test entity updates
        entity = repository.create({ "name": "Original", "value": 50 })
        updated_entity = repository.update(entity.id, { "value": 75 })
        
        assert updated_entity.value == 75
        assert updated_entity.name == "Original"  // Unchanged field
        assert updated_entity.updated_at > entity.updated_at
    
    function test_repository_delete():
        // Test entity deletion
        entity = repository.create({ "name": "To Delete" })
        delete_result = repository.delete(entity.id)
        
        assert delete_result == true
        assert repository.find_by_id(entity.id) == null
    
    function test_repository_query_methods():
        // Test complex queries
        repository.create({ "name": "Active", "status": "active" })
        repository.create({ "name": "Inactive", "status": "inactive" })
        repository.create({ "name": "Another Active", "status": "active" })
        
        active_entities = repository.find_by_status("active")
        assert active_entities.length == 2
        
        all_entities = repository.find_all()
        assert all_entities.length == 3
```

#### Strategy Pattern Testing
```pseudocode
class StrategyPatternTest:
    function test_strategy_selection():
        // Test strategy selection logic
        context = Context()
        
        context.set_strategy("fast")
        assert context.strategy instanceof FastStrategy
        
        context.set_strategy("accurate")
        assert context.strategy instanceof AccurateStrategy
    
    function test_strategy_execution():
        // Test different strategy implementations
        data = [1, 2, 3, 4, 5]
        
        fast_strategy = FastStrategy()
        fast_result = fast_strategy.process(data)
        assert fast_result.time < 1000  // Fast execution
        
        accurate_strategy = AccurateStrategy()
        accurate_result = accurate_strategy.process(data)
        assert accurate_result.accuracy > 0.95  // High accuracy
    
    function test_strategy_consistency():
        // Test that strategies produce consistent results
        data = load_test_data()
        
        strategies = [FastStrategy(), AccurateStrategy(), BalancedStrategy()]
        results = []
        
        for strategy in strategies:
            result = strategy.process(data)
            results.append(result)
        
        # All strategies should process the same data
        assert results.length == strategies.length
        for result in results:
            assert result.input_checksum == data.checksum
```

### 3. Universal Testing Patterns

#### Test Data Management
```pseudocode
class TestDataManager:
    function create_valid_user(overrides=None):
        default_data = {
            "username": "testuser_" + generate_id(),
            "email": "test_" + generate_id() + "@example.com",
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User",
            "roles": ["user"],
            "is_active": true,
            "created_at": current_timestamp()
        }
        return merge(default_data, overrides or {})
    
    function create_invalid_user_data(type="missing_required"):
        if type == "missing_required":
            return { "email": "test@example.com" }  # Missing username
        elif type == "invalid_email":
            return {
                "username": "testuser",
                "email": "invalid-email-format"
            }
        elif type == "weak_password":
            return {
                "username": "testuser",
                "email": "test@example.com",
                "password": "123"  # Too weak
            }
    
    function create_boundary_test_data():
        return {
            "empty_string": "",
            "max_length": "a" * 255,
            "unicode_chars": "测试用户🚀",
            "special_chars": "!@#$%^&*()",
            "null_value": null,
            "very_large_number": 999999999999999,
            "very_small_number": -999999999999999
        }

class BoundaryValueTest:
    function test_string_length_boundaries():
        # Test minimum length (0)
        result1 = validator.validate_username("")
        assert result1.is_valid == false
        
        # Test minimum valid length (1)
        result2 = validator.validate_username("a")
        assert result2.is_valid == true
        
        # Test maximum valid length
        max_length_username = "a" * 50
        result3 = validator.validate_username(max_length_username)
        assert result3.is_valid == true
        
        # Test maximum length + 1
        too_long_username = "a" * 51
        result4 = validator.validate_username(too_long_username)
        assert result4.is_valid == false
```

#### Error Handling Testing
```pseudocode
class ErrorHandlingTest:
    function test_exception_handling():
        # Test specific exception types
        with assert_raises(ValidationError):
            service.process_invalid_data()
        
        with assert_raises(NotFoundError):
            repository.find_by_id("nonexistent")
        
        with assert_raises(PermissionError):
            service.access_restricted_resource()
    
    function test_error_message_quality():
        # Test that errors provide helpful messages
        try:
            validator.validate_email("invalid")
            assert false, "Should have raised ValidationError"
        except ValidationError as e:
            assert "email" in e.message.lower()
            assert "invalid" in e.message.lower()
            assert e.suggestion != null  # Should provide fix suggestion
    
    function test_error_recovery():
        # Test graceful error recovery
        result = service.process_with_recovery(invalid_data)
        
        # Should return error result instead of throwing
        assert result.success == false
        assert result.error != null
        assert result.recovery_action == "used_default_values"
```

### 4. Technology-Agnostic Test Categories

#### Algorithm Testing
```pseudocode
class AlgorithmTest:
    function test_sorting_algorithm():
        # Test with various data sets
        test_cases = [
            { "input": [], "expected": [] },
            { "input": [1], "expected": [1] },
            { "input": [3, 1, 4, 1, 5], "expected": [1, 1, 3, 4, 5] },
            { "input": [5, 4, 3, 2, 1], "expected": [1, 2, 3, 4, 5] },
            { "input": [1, 2, 3, 4, 5], "expected": [1, 2, 3, 4, 5] }
        ]
        
        for test_case in test_cases:
            result = sorting_algorithm.sort(test_case.input)
            assert arrays_equal(result, test_case.expected)
    
    function test_search_algorithm():
        data = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
        
        # Test existing elements
        for i, value in enumerate(data):
            result = search_algorithm.search(data, value)
            assert result == i
        
        # Test non-existing elements
        assert search_algorithm.search(data, 0) == -1
        assert search_algorithm.search(data, 20) == -1
        assert search_algorithm.search(data, 6) == -1
    
    function test_algorithm_performance():
        large_dataset = generate_dataset(size=10000)
        
        start_time = current_time()
        result = algorithm.process(large_dataset)
        end_time = current_time()
        
        # Verify correctness
        assert result.is_valid == true
        
        # Verify performance (technology-agnostic)
        execution_time = end_time - start_time
        assert execution_time < 1000  # Less than 1 second
        
        # Verify complexity (approximate)
        expected_time_ratio = estimate_complexity(algorithm, [100, 1000, 10000])
        assert execution_time_ratio < expected_time_ratio * 1.5  # Allow 50% tolerance
```

#### Data Structure Testing
```pseudocode
class DataStructureTest:
    function test_stack_implementation():
        stack = Stack()
        
        # Test empty stack
        assert stack.is_empty() == true
        assert stack.size() == 0
        
        # Test push operations
        stack.push("first")
        stack.push("second")
        stack.push("third")
        
        assert stack.size() == 3
        assert stack.is_empty() == false
        
        # Test pop operations
        assert stack.pop() == "third"
        assert stack.pop() == "second"
        assert stack.size() == 1
        
        # Test peek
        assert stack.peek() == "first"
        assert stack.size() == 1  # Size shouldn't change
    
    function test_queue_implementation():
        queue = Queue()
        
        # Test enqueue
        queue.enqueue("first")
        queue.enqueue("second")
        queue.enqueue("third")
        
        assert queue.size() == 3
        assert queue.is_empty() == false
        
        # Test dequeue (FIFO)
        assert queue.dequeue() == "first"
        assert queue.dequeue() == "second"
        assert queue.size() == 1
        
        # Test front
        assert queue.front() == "third"
        assert queue.size() == 1
    
    function test_hash_table_implementation():
        hash_table = HashTable(size=10)
        
        # Test insertion and retrieval
        hash_table.put("key1", "value1")
        hash_table.put("key2", "value2")
        hash_table.put("key3", "value3")
        
        assert hash_table.get("key1") == "value1"
        assert hash_table.get("key2") == "value2"
        assert hash_table.get("key3") == "value3"
        assert hash_table.get("nonexistent") == null
        
        # Test update
        hash_table.put("key1", "updated_value1")
        assert hash_table.get("key1") == "updated_value1"
        
        # Test deletion
        hash_table.remove("key2")
        assert hash_table.get("key2") == null
        assert hash_table.size() == 2
```

#### Configuration Testing
```pseudocode
class ConfigurationTest:
    function test_configuration_loading():
        # Test loading from different sources
        config = ConfigurationLoader.load([
            "config/default.json",
            "config/development.json",
            "config/local.json"
        ])
        
        # Verify configuration structure
        assert config.database != null
        assert config.server != null
        assert config.logging != null
        
        # Verify configuration values
        assert config.server.port > 0
        assert config.server.port < 65536
        assert config.database.connection_timeout > 0
    
    function test_configuration_validation():
        # Test required fields
        invalid_config = { "server": { "host": "localhost" } }  # Missing port
        
        with assert_raises(ConfigurationError):
            ConfigurationValidator.validate(invalid_config)
        
        # Test valid configuration
        valid_config = {
            "server": { "host": "localhost", "port": 8080 },
            "database": { "url": "memory://test" }
        }
        
        result = ConfigurationValidator.validate(valid_config)
        assert result.is_valid == true
    
    function test_configuration_override():
        # Test environment variable override
        set_environment("SERVER_PORT", "9090")
        
        config = ConfigurationLoader.load(["config/default.json"])
        assert config.server.port == 9090  # Overridden from env
        
        # Clean up
        unset_environment("SERVER_PORT")
```

### 5. Universal Test Organization

#### Test Directory Structure
```
tests/
├── unit/                    # Unit tests
│   ├── models/             # Model/domain tests
│   ├── services/           # Business logic tests
│   ├── utils/              # Utility function tests
│   └── algorithms/         # Algorithm tests
├── integration/            # Integration tests
│   ├── database/          # Database integration tests
│   ├── api/               # API integration tests
│   └── external/          # External service tests
├── fixtures/              # Test data and fixtures
├── helpers/               # Test utilities and helpers
└── config/                # Test configuration
```

#### Test Naming Conventions
```pseudocode
# Universal naming patterns
test_<component>_<action>_<expected_result>()
test_<component>_<scenario>_<expected_behavior>()
test_<component>_<input_type>_<expected_output>()

# Examples
test_user_service_create_user_success()
test_user_service_create_user_duplicate_email()
test_user_service_create_user_invalid_input()
test_calculator_divide_by_zero_throws_exception()
test_calculator_divide_positive_numbers_returns_quotient()
test_validator_validate_email_invalid_format_returns_false()
```

#### Test Data Management
```pseudocode
class TestDataRepository:
    function load_test_data(category):
        # Load test data from files
        data_file = f"tests/fixtures/{category}.json"
        return load_json_file(data_file)
    
    function generate_test_data(template, count=10):
        # Generate random test data based on template
        generated_data = []
        for i in range(count):
            data_item = template.copy()
            data_item["id"] = generate_uuid()
            data_item["timestamp"] = current_timestamp()
            data_item["random_suffix"] = generate_random_string(8)
            generated_data.append(data_item)
        
        return generated_data
    
    function create_test_scenarios():
        # Define common test scenarios
        return {
            "empty": {},
            "minimal": { "required_field": "value" },
            "typical": { 
                "required_field": "value",
                "optional_field": "optional_value",
                "status": "active"
            },
            "complete": {
                "required_field": "value",
                "optional_field": "optional_value",
                "additional_field": "additional_value",
                "metadata": { "key": "value" },
                "tags": ["tag1", "tag2"]
            },
            "edge_case": {
                "required_field": "a" * 1000,  # Very long string
                "special_chars": "!@#$%^&*()",
                "unicode": "测试用户🚀",
                "boundary_values": [0, 1, -1, 999999]
            }
        }
```

## Implementation Guidelines

### 1. Test Independence
- Each test should be independent and isolated
- Tests should not depend on execution order
- Use setup and teardown methods for test preparation
- Clean up resources after each test

### 2. Test Readability
- Use descriptive test names that explain the scenario
- Keep test methods focused and concise
- Use meaningful variable names
- Include comments for complex logic

### 3. Test Reliability
- Tests should be deterministic and repeatable
- Avoid timing-dependent tests when possible
- Use appropriate timeouts for operations
- Handle flaky external dependencies with retries

### 4. Test Performance
- Unit tests should execute quickly (< 1 second per test)
- Use in-memory implementations when possible
- Mock external dependencies appropriately
- Parallelize independent tests

### 5. Test Coverage
- Aim for high code coverage (> 80%)
- Focus on critical business logic
- Test both happy path and error scenarios
- Include boundary value testing

## Technology-Specific Adaptations

### Adaptation Guidelines
1. **Identify Testing Framework**: Choose appropriate testing framework for your technology
2. **Implement Test Doubles**: Use mocking libraries specific to your stack
3. **Configure Test Environment**: Set up testing configuration for your technology
4. **Integrate with Build System**: Add test execution to your build process
5. **Set Up Continuous Testing**: Configure automated test execution

### Framework Examples
- **JavaScript/TypeScript**: Jest, Mocha, Jasmine
- **Python**: pytest, unittest, nose
- **Java**: JUnit, TestNG, Spock
- **C#**: NUnit, xUnit, MSTest
- **Go**: testing package, testify
- **Ruby**: RSpec, Minitest
- **PHP**: PHPUnit, Codeception

## Continuous Integration Integration

### CI/CD Pipeline Testing
```yaml
# Universal CI test configuration
test_stages:
  - unit_tests:
      parallel: true
      coverage: true
      fail_fast: true
  
  - integration_tests:
      requires: unit_tests
      services: [database, redis]
      parallel: true
  
  - system_tests:
      requires: integration_tests
      environment: staging
      parallel: false
  
  - performance_tests:
      requires: system_tests
      threshold: 5%  # Max performance degradation
```

This comprehensive unit testing suite provides a solid foundation for testing any technology stack while maintaining technology-agnostic principles and universal testing patterns.