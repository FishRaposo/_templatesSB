"""
File: basic-tests-python.tpl.py
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
"""

# Basic Python Testing Template
# Purpose: MVP-level testing template with unit and component tests for Python applications
# Usage: Copy to tests/ directory and customize for your Python project
# Stack: Python (.py)
# Tier: MVP (Minimal Viable Product)

## Purpose

MVP-level Python testing template providing essential unit and component tests for basic application functionality. Focuses on testing core business logic, utilities, and simple integration points with minimal setup and fast execution.

## Usage

```bash
# Copy to your Python project
cp _templates/tiers/mvp/tests/basic-tests-python.tpl.py tests/test_basic.py

# Install dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/test_basic.py -v

# Run with coverage
pytest tests/test_basic.py --cov=your_app --cov-report=html
```

## Structure

```python
# tests/test_basic.py
# Project: [[.ProjectName]]
# Author: [[.Author]]
# Version: [[.Version]]
import pytest
from unittest.mock import Mock, patch
from datetime import datetime
from your_app.main import Calculator, UserValidator, DataProcessor

"""
MVP Python Test Suite

This test suite follows the MVP testing philosophy:
- Focus on core business logic and essential functionality
- Fast execution with minimal setup and mocking
- No complex integration testing or database operations
- Educational comments to teach Python testing patterns

MVP Testing Approach:
- Unit tests for pure business logic and utilities
- Component tests for class methods and functions
- No database integration tests (added in Core tier)
- No performance or async tests (added in Enterprise tier)

Key Python Testing Patterns:
- pytest: Testing framework with powerful fixtures and assertions
- unittest.mock: Mocking framework for isolating units under test
- parametrize: Multiple test cases with different inputs
- fixtures: Reusable test setup and teardown
- assertions: Clear, readable test expectations
"""

class TestCalculator:
    """
    Unit tests for calculator business logic
    
    Demonstrates testing pure utility functions and mathematical operations.
    MVP approach: Basic arithmetic, no complex calculations or error handling.
    """
    
    def test_add_two_numbers(self):
        """
        Test basic addition functionality
        
        Simple method test to demonstrate pytest syntax.
        MVP: Basic operations, no error handling or validation.
        """
        calc = Calculator()
        result = calc.add(2, 3)
        assert result == 5
    
    def test_subtract_two_numbers(self):
        """
        Test basic subtraction functionality
        
        Demonstrates testing subtraction with edge cases.
        MVP: Basic operations, no floating point precision handling.
        """
        calc = Calculator()
        result = calc.subtract(10, 3)
        assert result == 7
    
    def test_multiply_two_numbers(self):
        """Test basic multiplication functionality"""
        calc = Calculator()
        result = calc.multiply(4, 5)
        assert result == 20
    
    def test_divide_two_numbers(self):
        """Test basic division functionality"""
        calc = Calculator()
        result = calc.divide(20, 4)
        assert result == 5.0
    
    def test_divide_by_zero_raises_error(self):
        """Test division by zero handling"""
        calc = Calculator()
        with pytest.raises(ValueError, match="Cannot divide by zero"):
            calc.divide(10, 0)

class TestUserValidator:
    """Unit tests for user validation logic"""
    
    def test_valid_email_passes(self):
        """Test valid email validation"""
        validator = UserValidator()
        assert validator.is_valid_email("test@example.com") is True
    
    def test_invalid_email_fails(self):
        """Test invalid email validation"""
        validator = UserValidator()
        invalid_emails = ["test@", "@example.com", "test.example.com", ""]
        for email in invalid_emails:
            assert validator.is_valid_email(email) is False
    
    def test_valid_password_passes(self):
        """Test valid password validation"""
        validator = UserValidator()
        assert validator.is_valid_password("SecurePass123!") is True
    
    def test_weak_password_fails(self):
        """Test weak password validation"""
        validator = UserValidator()
        weak_passwords = ["123", "password", "Pass", ""]
        for password in weak_passwords:
            assert validator.is_valid_password(password) is False
    
    def test_user_age_validation(self):
        """Test age validation logic"""
        validator = UserValidator()
        assert validator.is_valid_age(25) is True
        assert validator.is_valid_age(17) is False
        assert validator.is_valid_age(150) is False

class TestDataProcessor:
    """Unit tests for data processing logic"""
    
    def test_process_empty_list(self):
        """Test processing empty data"""
        processor = DataProcessor()
        result = processor.process_list([])
        assert result == []
    
    def test_process_list_with_numbers(self):
        """Test processing numeric list"""
        processor = DataProcessor()
        data = [1, 2, 3, 4, 5]
        result = processor.process_list(data)
        assert result == [2, 4, 6, 8, 10]  # Assuming doubling logic
    
    def test_process_list_with_strings(self):
        """Test processing string list"""
        processor = DataProcessor()
        data = ["hello", "world"]
        result = processor.process_list(data)
        assert result == ["HELLO", "WORLD"]  # Assuming uppercase logic
    
    def test_filter_valid_data(self):
        """Test data filtering logic"""
        processor = DataProcessor()
        data = [1, None, 3, "", 5, 0]
        result = processor.filter_valid_data(data)
        assert result == [1, 3, 5]

class TestIntegration:
    """Basic integration tests"""
    
    @patch('your_app.main.external_api_call')
    def test_api_integration_with_mock(self, mock_api):
        """Test API integration with mocked external service"""
        mock_api.return_value = {"status": "success", "data": "test"}
        
        processor = DataProcessor()
        result = processor.fetch_external_data()
        
        assert result["status"] == "success"
        mock_api.assert_called_once()
    
    def test_database_integration(self):
        """Test database integration with in-memory database"""
        # This would typically use an in-memory SQLite or test database
        processor = DataProcessor()
        
        # Mock database operations
        with patch('your_app.main.database_connection') as mock_db:
            mock_db.execute.return_value = [{"id": 1, "name": "test"}]
            
            result = processor.get_data_from_db()
            assert len(result) == 1
            assert result[0]["name"] == "test"

class TestUtilities:
    """Tests for utility functions"""
    
    def test_date_formatting(self):
        """Test date formatting utility"""
        from your_app.utils import format_date
        
        test_date = datetime(2023, 12, 25)
        result = format_date(test_date)
        assert result == "2023-12-25"
    
    def test_string_manipulation(self):
        """Test string manipulation utilities"""
        from your_app.utils import capitalize_words, clean_whitespace
        
        assert capitalize_words("hello world") == "Hello World"
        assert clean_whitespace("  hello   world  ") == "hello world"
    
    def test_file_operations(self):
        """Test file operation utilities"""
        from your_app.utils import read_config, validate_file_path
        
        # Mock file operations
        with patch('builtins.open', mock_open(read_data='{"key": "value"}')):
            with patch('os.path.exists', return_value=True):
                config = read_config("config.json")
                assert config["key"] == "value"
                assert validate_file_path("config.json") is True

# Test Fixtures and Helpers
@pytest.fixture
def sample_user_data():
    """Fixture providing sample user data for tests"""
    return {
        "id": 1,
        "name": "Test User",
        "email": "test@example.com",
        "age": 25,
        "created_at": datetime.now()
    }

@pytest.fixture
def sample_product_data():
    """Fixture providing sample product data for tests"""
    return [
        {"id": 1, "name": "Product 1", "price": 10.99},
        {"id": 2, "name": "Product 2", "price": 20.50},
        {"id": 3, "name": "Product 3", "price": 15.75}
    ]

class TestWithFixtures:
    """Tests using fixtures for data setup"""
    
    def test_user_data_processing(self, sample_user_data):
        """Test processing user data with fixture"""
        processor = DataProcessor()
        result = processor.process_user(sample_user_data)
        
        assert result["id"] == sample_user_data["id"]
        assert result["processed"] is True
    
    def test_product_calculations(self, sample_product_data):
        """Test product calculations with fixture"""
        processor = DataProcessor()
        total = processor.calculate_total_price(sample_product_data)
        
        expected_total = 10.99 + 20.50 + 15.75
        assert abs(total - expected_total) < 0.01

# Mock Data Factory
class MockDataFactory:
    """Factory for creating test data"""
    
    @staticmethod
    def create_user(**overrides):
        """Create mock user data with optional overrides"""
        default_user = {
            "id": 1,
            "name": "Test User",
            "email": "test@example.com",
            "age": 25,
            "active": True
        }
        default_user.update(overrides)
        return default_user
    
    @staticmethod
    def create_product(**overrides):
        """Create mock product data with optional overrides"""
        default_product = {
            "id": 1,
            "name": "Test Product",
            "price": 10.99,
            "in_stock": True,
            "category": "electronics"
        }
        default_product.update(overrides)
        return default_product
    
    @staticmethod
    def create_order(user_id, products=None):
        """Create mock order data"""
        if products is None:
            products = [MockDataFactory.create_product()]
        
        return {
            "id": 1,
            "user_id": user_id,
            "products": products,
            "total": sum(p["price"] for p in products),
            "status": "pending"
        }

# Test Configuration
class TestConfig:
    """Test configuration and constants"""
    
    TIMEOUT_SECONDS = 5
    MAX_RETRIES = 3
    TEST_DATABASE_URL = "sqlite:///:memory:"
    TEST_API_BASE_URL = "http://localhost:8000/api"

# Custom Assertions and Helpers
def assert_valid_response(response):
    """Custom assertion for valid API responses"""
    assert "status" in response
    assert "data" in response
    assert response["status"] in ["success", "error"]

def assert_user_data_valid(user_data):
    """Custom assertion for valid user data"""
    required_fields = ["id", "name", "email", "age"]
    for field in required_fields:
        assert field in user_data, f"Missing required field: {field}"
    assert isinstance(user_data["age"], int)
    assert 18 <= user_data["age"] <= 120

if __name__ == "__main__":
    # Run tests when script is executed directly
    pytest.main([__file__, "-v"])
```

## Guidelines

### Test Organization
- **Unit Tests**: Test individual functions and classes in isolation
- **Integration Tests**: Test component interactions with mocked dependencies
- **Fixtures**: Use pytest fixtures for reusable test data
- **Keep Tests Fast**: MVP tests should run in under 30 seconds

### Test Structure
- Use descriptive test method names
- Group related tests in classes
- Use `pytest.raises()` for exception testing
- Mock external dependencies with `unittest.mock`

### Testing Best Practices
- Test one thing per test
- Use arrange-act-assert pattern
- Test both happy path and error cases
- Use meaningful assertions

### Coverage Requirements
- **Unit Tests**: 80%+ coverage for business logic
- **Integration Tests**: 60%+ coverage for external interactions
- **Overall**: 75%+ minimum for MVP

## Required Dependencies

Add to `requirements.txt` or `pyproject.toml`:

```txt
pytest>=7.4.0
pytest-cov>=4.1.0
pytest-mock>=3.11.1
```

## What's Included

- **Unit Tests**: Business logic, utilities, data validation
- **Integration Tests**: API and database integration with mocks
- **Test Fixtures**: Reusable test data setup
- **Mock Data Factory**: Sample data generation
- **Custom Assertions**: Domain-specific validation helpers

## What's NOT Included

- End-to-end tests with real external services
- Performance and load tests
- Database migration tests
- Web framework specific tests (Flask, Django, etc.)

---

**Template Version**: 1.0 (MVP)  
**Last Updated**: 2025-12-10  
**Stack**: Python  
**Tier**: MVP  
**Framework**: pytest
