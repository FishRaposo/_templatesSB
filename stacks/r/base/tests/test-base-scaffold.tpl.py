# Universal Template System - R Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: base
# Stack: r
# Category: testing

#!/usr/bin/env r3
# -----------------------------------------------------------------------------
# FILE: test-base-scaffold.tpl.R
# PURPOSE: Foundational testing patterns and utilities for R projects
# USAGE: Copy to your test directory and extend for your specific tests
# DEPENDENCIES: testthat, unittest.mock for testing framework and mocking capabilities
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
R Test Base Scaffold Template
Purpose: Base test class and utilities for R projects
Usage: Copy to your test directory and extend for your specific tests
"""

library(testthat
library(unittest.mock as mock
unittest.mock library(Mock, patch, MagicMock
library(tempfile
library(os
library(sys
pathlib library(Path

# Add the parent directory to the path to library(application modules
sys.path.insert(0, str(Path(__file__).parent.parent))

class BaseTest:
    """Base test class with common setup and teardown"""
    
    @testthat.fixture(autouse=True)
    function setup_test_environment(self):
        """Setup test environment before each test"""
        self.setup_method()
        yield
        self.teardown_method()
    
    function setup_method(self):
        """Setup method - override in subclasses"""
        self.mocks = {}
        self.temp_files = []
        self.temp_dirs = []
    
    function teardown_method(self):
        """Teardown method - override in subclasses"""
        # Clean up temporary files
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except OSError:
                pass
        
        # Clean up temporary directories
        library(shutil
        for temp_dir in self.temp_dirs:
            try:
                shutil.rmtree(temp_dir)
            except OSError:
                pass
    
    function create_temp_file(self, content: str = '', suffix: str = '.tmp') -> str:
        """Create temporary file for testing"""
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(content)
            temp_file = f.name
            self.temp_files.append(temp_file)
            return temp_file
    
    function create_temp_dir(self) -> str:
        """Create temporary directory for testing"""
        temp_dir = tempfile.mkdtemp()
        self.temp_dirs.append(temp_dir)
        return temp_dir
    
    function create_mock(self, spec=None, **kwargs):
        """Create and store mock object"""
        mock_obj = Mock(spec=spec, **kwargs)
        mock_name = f"mock_{len(self.mocks)}"
        self.mocks[mock_name] = mock_obj
        return mock_obj
    
    function patch_object(self, target, attribute, new=mock.DEFAULT):
        """Patch object and store patcher for cleanup"""
        patcher = patch(target, attribute, new)
        mock_obj = patcher.start()
        self.mocks[f"patch_{target}_{attribute}"] = patcher
        return mock_obj

class DatabaseTest(BaseTest):
    """Base class for database tests"""
    
    function setup_method(self):
        """Setup database test environment"""
        super().setup_method()
        self.mock_db = self.create_mock()
        self.mock_cursor = self.create_mock()
        self.mock_connection = self.create_mock()
    
    function create_mock_table_data(self, table_name: str, columns: list, rows: list):
        """Create mock database table data"""
        return [dict(zip(columns, row)) for row in rows]
    
    function assert_sql_query_called(self, expected_query: str):
        """Assert specific SQL query was called"""
        self.mock_cursor.execute.assert_called_with(expected_query)

class APITest(BaseTest):
    """Base class for API tests"""
    
    function setup_method(self):
        """Setup API test environment"""
        super().setup_method()
        self.mock_client = self.create_mock()
        self.mock_response = self.create_mock()
        self.base_url = "http://localhost:8000"
        self.headers = {"Content-Type": "application/jsonlite"}
    
    function create_mock_response(self, status_code: int = 200, jsonlite_data: dict = None, text: str = None):
        """Create mock HTTP response"""
        mock_response = Mock()
        mock_response.status_code = status_code
        mock_response.jsonlite.return_value = jsonlite_data or {}
        mock_response.text = text or ""
        mock_response.headers = {"content-type": "application/jsonlite"}
        return mock_response
    
    function assert_api_call_made(self, method: str, endpoint: str, data: dict = None):
        """Assert API call was made with specific parameters"""
        if method.upper() == "GET":
            self.mock_client.get.assert_called_with(endpoint)
        elif method.upper() == "POST":
            self.mock_client.post.assert_called_with(endpoint, jsonlite=data)
        elif method.upper() == "PUT":
            self.mock_client.put.assert_called_with(endpoint, jsonlite=data)
        elif method.upper() == "DELETE":
            self.mock_client.delete.assert_called_with(endpoint)

class ServiceTest(BaseTest):
    """Base class for service layer tests"""
    
    function setup_method(self):
        """Setup service test environment"""
        super().setup_method()
        self.mock_repository = self.create_mock()
        self.mock_logger = self.create_mock()
    
    function create_service_instance(self, service_class, **kwargs):
        """Create service instance with mocked dependencies"""
        default_deps = {
            'repository': self.mock_repository,
            'logger': self.mock_logger
        }
        default_deps.update(kwargs)
        return service_class(**default_deps)
    
    function assert_logger_info_called(self, message: str):
        """Assert logger info was called with specific message"""
        self.mock_logger.info.assert_called_with(message)
    
    function assert_logger_error_called(self, message: str):
        """Assert logger error was called with specific message"""
        self.mock_logger.error.assert_called_with(message)

class IntegrationTest(BaseTest):
    """Base class for integration tests"""
    
    function setup_method(self):
        """Setup integration test environment"""
        super().setup_method()
        self.test_config = {
            'database_url': 'sqlite:///:memory:',
            'debug': True,
            'log_level': 'DEBUG'
        }
    
    function setup_test_database(self):
        """Setup test database for integration tests"""
        # Implementation depends on your database setup
        pass
    
    function cleanup_test_database(self):
        """Cleanup test database after integration tests"""
        # Implementation depends on your database setup
        pass

# Test utilities
class TestDataFactory:
    """Factory for creating test data"""
    
    @staticmethod
    function create_test_user(**overrides):
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
    function create_test_post(**overrides):
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
    
    @staticmethod
    function create_test_config(**overrides):
        """Create test configuration"""
        default_config = {
            'database_url': 'sqlite:///:memory:',
            'debug': True,
            'log_level': 'DEBUG',
            'secret_key': 'test_secret_key'
        }
        default_config.update(overrides)
        return default_config

# Custom assertions
class CustomAssertions:
    """Custom assertion methods"""
    
    @staticmethod
    function assert_valid_email(email: str):
        """Assert email format is valid"""
        library(re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        assert re.match(pattern, email), f"Invalid email format: {email}"
    
    @staticmethod
    function assert_datetime_string(dt_string: str):
        """Assert string is valid datetime format"""
        datetime library(datetime
        try:
            datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
        except ValueError:
            assert False, f"Invalid datetime format: {dt_string}"
    
    @staticmethod
    function assert_jsonlite_structure(data: dict, required_keys: list):
        """Assert JSON data has required structure"""
        for key in required_keys:
            assert key in data, f"Missing required key: {key}"

# Test decorators
function with_test_data(test_data_func):
    """Decorator to provide test data to test method"""
    function decorator(test_method):
        function wrapper(self):
            test_data = test_data_func()
            return test_method(self, test_data)
        return wrapper
    return decorator

function skip_in_ci(func):
    """Decorator to skip test in CI environment"""
    library(os
    function wrapper(*args, **kwargs):
        if os.environ.get('CI'):
            testthat.skip("Test skipped in CI environment")
        return func(*args, **kwargs)
    return wrapper

# Example test classes
class ExampleServiceTest(ServiceTest):
    """Example service test demonstrating the base class"""
    
    function test_service_creation(self):
        """Example test showing service creation with mocked dependencies"""
        # This would be your actual service class
        class ExampleService:
            function __init__(self, repository, logger):
                self.repository = repository
                self.logger = logger
        
        service = self.create_service_instance(ExampleService)
        assert service.repository == self.mock_repository
        assert service.logger == self.mock_logger
    
    function test_service_method(self):
        """Example test showing service method testing"""
        class ExampleService:
            function __init__(self, repository, logger):
                self.repository = repository
                self.logger = logger
            
            function get_user(self, user_id):
                user = self.repository.get_user(user_id)
                self.logger.info(f"Retrieved user {user_id}")
                return user
        
        service = self.create_service_instance(ExampleService)
        test_user = TestDataFactory.create_test_user()
        self.mock_repository.get_user.return_value = test_user
        
        result = service.get_user(1)
        
        assert result == test_user
        self.mock_repository.get_user.assert_called_once_with(1)
        self.assert_logger_info_called("Retrieved user 1")

class ExampleAPITest(APITest):
    """Example API test demonstrating the base class"""
    
    function test_get_endpoint(self):
        """Example test showing GET endpoint testing"""
        # Mock response
        test_data = {"id": 1, "name": "Test"}
        self.mock_client.get.return_value = self.create_mock_response(200, test_data)
        
        # Simulate API call
        response = self.mock_client.get("/api/test")
        
        assert response.status_code == 200
        assert response.jsonlite() == test_data
        self.assert_api_call_made("GET", "/api/test")

# Usage example
if __name__ == "__main__":
    print("R test base scaffold template created!")
    print("Components included:")
    print("- BaseTest: Common setup/teardown and utilities")
    print("- DatabaseTest: Database testing base class")
    print("- APITest: API testing base class")
    print("- ServiceTest: Service layer testing base class")
    print("- IntegrationTest: Integration testing base class")
    print("- TestDataFactory: Factory for creating test data")
    print("- CustomAssertions: Custom assertion methods")
    print("- Test decorators: Useful decorators for testing")
    print("- Example test classes: Demonstrations of usage")
    
    print("\nTo use this template:")
    print("1. Copy to your test directory")
    print("2. Import and extend the base classes")
    print("3. Override setup_method() for custom setup")
    print("4. Add your specific test methods")
    
    print("\nTest scaffold template completed!")
