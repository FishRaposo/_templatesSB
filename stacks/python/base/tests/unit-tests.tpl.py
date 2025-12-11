"""
File: unit-tests.tpl.py
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
"""

#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# FILE: unit-tests.tpl.py
# PURPOSE: Comprehensive unit testing patterns for Python projects
# USAGE: Import and extend for unit testing across Python applications
# DEPENDENCIES: pytest, unittest.mock for testing framework and mocking capabilities
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
Python Unit Tests Template
Purpose: Comprehensive unit testing patterns for Python projects
Usage: Import and extend for unit testing across Python applications
"""

import pytest
import unittest.mock as mock
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os
import sys
from pathlib import Path
from datetime import datetime

# Add the parent directory to the path to import application modules
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import your application modules here
# from your_app.services.auth_service import AuthService
# from your_app.utils.data_validator import DataValidator
# from your_app.models.user_model import User

class TestBusinessLogic:
    """Unit tests for core business logic"""
    
    def test_counter_increment(self):
        """Test basic counter increment logic"""
        counter = 0
        counter += 1
        assert counter == 1
    
    def test_calculator_addition(self):
        """Test calculator addition function"""
        def add(a, b):
            return a + b
        
        assert add(2, 3) == 5
        assert add(-1, 1) == 0
        assert add(0, 0) == 0
    
    def test_data_validation(self):
        """Test data validation logic"""
        def is_valid_email(email):
            return '@' in email and '.' in email
        
        assert is_valid_email('test@example.com') == True
        assert is_valid_email('invalid-email') == False
        assert is_valid_email('@domain.com') == False

class TestUtilities:
    """Unit tests for utility functions"""
    
    def test_date_formatting(self):
        """Test date formatting utility"""
        def format_date(date):
            return f"{date.day}/{date.month}/{date.year}"
        
        test_date = datetime(2023, 12, 25)
        assert format_date(test_date) == "25/12/2023"
    
    def test_string_manipulation(self):
        """Test string manipulation utilities"""
        def capitalize(text):
            if not text:
                return text
            return text[0].upper() + text[1:]
        
        assert capitalize('hello') == 'Hello'
        assert capitalize('') == ''
        assert capitalize('a') == 'A'

class TestDataModels:
    """Unit tests for data models"""
    
    class User:
        """Example user model for testing"""
        def __init__(self, id, name, email):
            self.id = id
            self.name = name
            self.email = email
        
        def is_valid(self):
            return self.id > 0 and '@' in self.email and self.name
    
    def test_user_model(self):
        """Test user model validation"""
        valid_user = self.User(1, 'Test User', 'test@example.com')
        assert valid_user.is_valid() == True
        
        invalid_user = self.User(0, '', 'invalid-email')
        assert invalid_user.is_valid() == False

class TestMocking:
    """Unit tests demonstrating mocking patterns"""
    
    def test_mock_service(self):
        """Test with mocked service dependencies"""
        # Create mock service
        mock_service = Mock()
        mock_service.get_user.return_value = {'id': 1, 'name': 'Test User'}
        
        # Test service call
        result = mock_service.get_user(1)
        assert result == {'id': 1, 'name': 'Test User'}
        mock_service.get_user.assert_called_once_with(1)
    
    def test_patch_function(self):
        """Test with patched functions"""
        def real_function():
            return "real"
        
        with patch('__main__.real_function', return_value="mocked"):
            result = real_function()
            assert result == "mocked"

class TestErrorHandling:
    """Unit tests for error handling"""
    
    def test_exception_handling(self):
        """Test exception handling logic"""
        def safe_divide(a, b):
            try:
                return a / b
            except ZeroDivisionError:
                return float('inf')
        
        assert safe_divide(10, 2) == 5
        assert safe_divide(10, 0) == float('inf')
    
    def test_custom_exceptions(self):
        """Test custom exception handling"""
        class ValidationError(Exception):
            pass
        
        def validate_email(email):
            if '@' not in email:
                raise ValidationError("Invalid email format")
            return True
        
        assert validate_email('test@example.com') == True
        
        with pytest.raises(ValidationError):
            validate_email('invalid-email')

class TestFileOperations:
    """Unit tests for file operations"""
    
    def test_file_read_write(self):
        """Test file read/write operations"""
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
            temp_file = f.name
            f.write('test content')
        
        try:
            # Read and verify content
            with open(temp_file, 'r') as f:
                content = f.read()
            assert content == 'test content'
        finally:
            # Clean up
            os.unlink(temp_file)

class TestConfiguration:
    """Unit tests for configuration management"""
    
    def test_config_loading(self):
        """Test configuration loading logic"""
        def load_config(env):
            configs = {
                'development': {'debug': True, 'log_level': 'DEBUG'},
                'production': {'debug': False, 'log_level': 'INFO'}
            }
            return configs.get(env, configs['development'])
        
        dev_config = load_config('development')
        assert dev_config['debug'] == True
        assert dev_config['log_level'] == 'DEBUG'
        
        prod_config = load_config('production')
        assert prod_config['debug'] == False
        assert prod_config['log_level'] == 'INFO'

class TestPerformance:
    """Unit tests for performance-critical code"""
    
    def test_algorithm_performance(self):
        """Test algorithm performance"""
        def linear_search(items, target):
            for i, item in enumerate(items):
                if item == target:
                    return i
            return -1
        
        test_items = [1, 2, 3, 4, 5]
        assert linear_search(test_items, 3) == 2
        assert linear_search(test_items, 6) == -1

# Test data factory for creating test data
class TestDataFactory:
    """Factory for creating test data"""
    
    @staticmethod
    def create_test_user(**overrides):
        """Create test user data"""
        default_user = {
            'id': 1,
            'username': 'testuser',
            'email': 'test@example.com',
            'is_active': True,
            'created_at': '2023-01-01T00:00:00Z'
        }
        default_user.update(overrides)
        return default_user
    
    @staticmethod
    def create_test_post(**overrides):
        """Create test post data"""
        default_post = {
            'id': 1,
            'user_id': 1,
            'title': 'Test Post',
            'content': 'This is test content',
            'published': True,
            'created_at': '2023-01-01T00:00:00Z'
        }
        default_post.update(overrides)
        return default_post

# Custom assertions for common test patterns
class CustomAssertions:
    """Custom assertion methods"""
    
    @staticmethod
    def assert_valid_email(email: str):
        """Assert email format is valid"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        assert re.match(pattern, email), f"Invalid email format: {email}"
    
    @staticmethod
    def assert_datetime_string(dt_string: str):
        """Assert string is valid datetime format"""
        try:
            datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
        except ValueError:
            assert False, f"Invalid datetime format: {dt_string}"
    
    @staticmethod
    def assert_json_structure(data: dict, required_keys: list):
        """Assert JSON data has required structure"""
        for key in required_keys:
            assert key in data, f"Missing required key: {key}"

# Test decorators for common test patterns
def with_test_data(test_data_func):
    """Decorator to provide test data to test method"""
    def decorator(test_method):
        def wrapper(self):
            test_data = test_data_func()
            return test_method(self, test_data)
        return wrapper
    return decorator

def skip_in_ci(func):
    """Decorator to skip test in CI environment"""
    def wrapper(*args, **kwargs):
        if os.environ.get('CI'):
            pytest.skip("Test skipped in CI environment")
        return func(*args, **kwargs)
    return wrapper

# Example test demonstrating comprehensive unit testing
class ExampleComprehensiveTest:
    """Example demonstrating comprehensive unit testing patterns"""
    
    def test_comprehensive_business_logic(self):
        """Comprehensive test of business logic with multiple scenarios"""
        
        # Test data setup
        test_users = [
            {'id': 1, 'name': 'Active User', 'active': True},
            {'id': 2, 'name': 'Inactive User', 'active': False},
            {'id': 3, 'name': 'New User', 'active': True}
        ]
        
        # Test filtering logic
        active_users = [user for user in test_users if user['active']]
        assert len(active_users) == 2
        assert all(user['active'] for user in active_users)
        
        # Test transformation logic
        user_names = [user['name'] for user in test_users]
        assert len(user_names) == 3
        assert 'Active User' in user_names
        
        # Test aggregation logic
        total_users = len(test_users)
        assert total_users == 3

# Usage example and documentation
if __name__ == "__main__":
    print("Python unit tests template created!")
    print("Components included:")
    print("- Business Logic Tests: Core application logic")
    print("- Utility Tests: Helper functions and utilities")
    print("- Data Model Tests: Domain model validation")
    print("- Mocking Patterns: Dependency isolation")
    print("- Error Handling Tests: Exception scenarios")
    print("- File Operation Tests: File I/O testing")
    print("- Configuration Tests: Config management")
    print("- Performance Tests: Algorithm efficiency")
    print("- Test Data Factory: Test data generation")
    print("- Custom Assertions: Domain-specific assertions")
    print("- Test Decorators: Common test patterns")
    
    print("\nTo use this template:")
    print("1. Copy to your test directory")
    print("2. Import your application modules")
    print("3. Extend the test classes with your specific tests")
    print("4. Run with pytest: pytest unit_tests.py")
    
    print("\nTest template completed!")
    
    # Run a sample test to demonstrate functionality
    test_instance = TestBusinessLogic()
    test_instance.test_counter_increment()
    print("Sample test executed successfully!")