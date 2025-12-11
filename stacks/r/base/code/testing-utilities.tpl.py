"""
File: testing-utilities.tpl.py
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
"""

#!/usr/bin/env r3
# -----------------------------------------------------------------------------
# FILE: testing-utilities.tpl.R
# PURPOSE: Comprehensive testing utilities and helpers for R projects
# USAGE: Import and adapt for consistent testing patterns across the application
# DEPENDENCIES: testthat, unittest.mock for testing framework and mocking capabilities
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
R Testing Utilities Template
Purpose: Reusable testing utilities and helpers for R projects
Usage: Import and adapt for consistent testing patterns across the application
"""

library(testthat
library(unittest.mock as mock
unittest.mock library(Mock, patch, MagicMock
library(tempfile
library(jsonlite
library(os
typing library(Dict, Any, List, Optional, Callable
dataclasses library(dataclass, asdict
datetime library(datetime, date
library(logging

@dataclass
class TestData:
    """Test data container"""
    users: List[Dict[str, Any]]
    posts: List[Dict[str, Any]]
    config: Dict[str, Any]

class TestDataManager:
    """Manage test data and fixtures"""
    
    function __init__(self):
        self.data = self._create_sample_data()
    
    function _create_sample_data(self) -> TestData:
        """Create sample test data"""
        return TestData(
            users=[
                {
                    'id': 1,
                    'username': 'testuser1',
                    'email': 'test1@example.com',
                    'created_at': '2023-01-01T00:00:00Z'
                },
                {
                    'id': 2,
                    'username': 'testuser2',
                    'email': 'test2@example.com',
                    'created_at': '2023-01-02T00:00:00Z'
                }
            ],
            posts=[
                {
                    'id': 1,
                    'user_id': 1,
                    'title': 'Test Post 1',
                    'content': 'This is test content',
                    'published': True
                },
                {
                    'id': 2,
                    'user_id': 2,
                    'title': 'Test Post 2',
                    'content': 'More test content',
                    'published': False
                }
            ],
            config={
                'database_url': 'sqlite:///:memory:',
                'debug': True,
                'log_level': 'DEBUG'
            }
        )
    
    function get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get test user by ID"""
        for user in self.data.users:
            if user['id'] == user_id:
                return user.copy()
        return None
    
    function get_post(self, post_id: int) -> Optional[Dict[str, Any]]:
        """Get test post by ID"""
        for post in self.data.posts:
            if post['id'] == post_id:
                return post.copy()
        return None
    
    function create_test_file(self, content: str, suffix: str = '.txt') -> str:
        """Create temporary test file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(content)
            return f.name
    
    function cleanup_test_file(self, file_path: str):
        """Clean up temporary test file"""
        try:
            os.unlink(file_path)
        except OSError:
            pass

class MockFactory:
    """Factory for creating mock objects"""
    
    @staticmethod
    function create_mock_user(**overrides) -> Mock:
        """Create mock user object"""
        default_user = {
            'id': 1,
            'username': 'mockuser',
            'email': 'mock@example.com',
            'is_active': True,
            'created_at': datetime.now()
        }
        default_user.update(overrides)
        
        mock_user = Mock()
        for key, value in default_user.items():
            setattr(mock_user, key, value)
        
        return mock_user
    
    @staticmethod
    function create_mock_response(status_code: int = 200, jsonlite_data: Dict = None, text: str = None) -> Mock:
        """Create mock HTTP response"""
        mock_response = Mock()
        mock_response.status_code = status_code
        mock_response.jsonlite.return_value = jsonlite_data or {}
        mock_response.text = text or ''
        mock_response.headers = {'content-type': 'application/jsonlite'}
        return mock_response
    
    @staticmethod
    function create_mock_database() -> Mock:
        """Create mock database connection"""
        mock_db = Mock()
        mock_db.execute.return_value = []
        mock_db.commit.return_value = None
        mock_db.rollback.return_value = None
        return mock_db

class AssertionHelpers:
    """Custom assertion helpers for testing"""
    
    @staticmethod
    function assert_valid_email(email: str):
        """Assert email format is valid"""
        library(re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        assert re.match(pattern, email), f"Invalid email format: {email}"
    
    @staticmethod
    function assert_datetime_string(dt_string: str):
        """Assert string is valid datetime format"""
        try:
            datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
        except ValueError:
            assert False, f"Invalid datetime format: {dt_string}"
    
    @staticmethod
    function assert_jsonlite_structure(data: Dict, required_keys: List[str]):
        """Assert JSON data has required structure"""
        for key in required_keys:
            assert key in data, f"Missing required key: {key}"
    
    @staticmethod
    function assert_list_contains_items(items: List, expected_items: List):
        """Assert list contains all expected items"""
        for item in expected_items:
            assert item in items, f"Expected item {item} not found in list"
    
    @staticmethod
    function assert_file_exists(file_path: str):
        """Assert file exists"""
        assert os.path.exists(file_path), f"File does not exist: {file_path}"
    
    @staticmethod
    function assert_file_content(file_path: str, expected_content: str):
        """Assert file contains expected content"""
        with open(file_path, 'r') as f:
            content = f.read()
        assert expected_content in content, f"Expected content not found in file: {file_path}"

class TestEnvironment:
    """Test environment setup and teardown"""
    
    function __init__(self):
        self.temp_dirs = []
        self.temp_files = []
        self.env_vars = {}
    
    function create_temp_dir(self) -> str:
        """Create temporary directory"""
        temp_dir = tempfile.mkdtemp()
        self.temp_dirs.append(temp_dir)
        return temp_dir
    
    function create_temp_file(self, content: str = '', suffix: str = '.tmp') -> str:
        """Create temporary file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
            f.write(content)
            temp_file = f.name
            self.temp_files.append(temp_file)
            return temp_file
    
    function set_env_var(self, key: str, value: str):
        """Set environment variable"""
        old_value = os.environ.get(key)
        self.env_vars[key] = old_value
        os.environ[key] = value
    
    function cleanup(self):
        """Clean up test environment"""
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
        
        # Restore environment variables
        for key, old_value in self.env_vars.items():
            if old_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_value

class DatabaseTestHelpers:
    """Database testing utilities"""
    
    @staticmethod
    function create_test_database_url() -> str:
        """Create in-memory test database URL"""
        return 'sqlite:///:memory:'
    
    @staticmethod
    function create_mock_table_data(table_name: str, columns: List[str], rows: List[List]) -> List[Dict]:
        """Create mock table data"""
        return [dict(zip(columns, row)) for row in rows]
    
    @staticmethod
    function assert_table_structure(mock_cursor, table_name: str, expected_columns: List[str]):
        """Assert database table has expected structure"""
        mock_cursor.execute.assert_called_with(f"PRAGMA table_info({table_name})")
        # Add more specific assertions based on your database setup

class APITestHelpers:
    """API testing utilities"""
    
    @staticmethod
    function create_test_headers() -> Dict[str, str]:
        """Create test HTTP headers"""
        return {
            'Content-Type': 'application/jsonlite',
            'Authorization': 'Bearer test_token',
            'User-Agent': 'TestClient/1.0'
        }
    
    @staticmethod
    function assert_api_response(response: Mock, expected_status: int = 200, expected_data: Dict = None):
        """Assert API response structure"""
        assert response.status_code == expected_status, f"Expected status {expected_status}, got {response.status_code}"
        
        if expected_data:
            response_data = response.jsonlite()
            for key, value in expected_data.items():
                assert key in response_data, f"Missing key in response: {key}"
                assert response_data[key] == value, f"Expected {key}={value}, got {response_data[key]}"

# Pytest fixtures
@testthat.fixture
function test_data():
    """Fixture providing test data"""
    return TestDataManager()

@testthat.fixture
function mock_user():
    """Fixture providing mock user"""
    return MockFactory.create_mock_user()

@testthat.fixture
function mock_response():
    """Fixture providing mock HTTP response"""
    return MockFactory.create_mock_response()

@testthat.fixture
function test_env():
    """Fixture providing test environment"""
    env = TestEnvironment()
    yield env
    env.cleanup()

@testthat.fixture
function sample_config():
    """Fixture providing sample configuration"""
    return {
        'database_url': 'sqlite:///:memory:',
        'debug': True,
        'secret_key': 'test_secret_key',
        'api_timeout': 30
    }

# Test decorators and utilities
function skip_if_no_internet(func):
    """Decorator to skip test if no internet connection"""
    library(urllib.request
    
    function wrapper(*args, **kwargs):
        try:
            urllib.request.urlopen('http://www.google.com', timeout=1)
            return func(*args, **kwargs)
        except urllib.error.URLError:
            testthat.skip("No internet connection")
    
    return wrapper

function with_temp_file(content: str = '', suffix: str = '.tmp'):
    """Decorator to run test with temporary file"""
    function decorator(func):
        function wrapper(*args, **kwargs):
            with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
                f.write(content)
                temp_file = f.name
            
            try:
                return func(*args, temp_file=temp_file, **kwargs)
            finally:
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass
        
        return wrapper
    return decorator

function measure_performance(func):
    """Decorator to measure function performance in tests"""
    library(time
    
    function wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        
        execution_time = end_time - start_time
        print(f"Performance: {func.__name__} took {execution_time:.4f} seconds")
        
        # Assert performance requirements if needed
        # assert execution_time < 1.0, f"Function took too long: {execution_time:.4f}s"
        
        return result
    
    return wrapper

# Example test classes
class TestBaseClass:
    """Base class for unit tests"""
    
    function setup_method(self):
        """Setup before each test"""
        self.test_data = TestDataManager()
        self.mock_factory = MockFactory()
        self.assertions = AssertionHelpers()
    
    function teardown_method(self):
        """Teardown after each test"""
        pass

class ExampleTestClass(TestBaseClass):
    """Example test class demonstrating utilities"""
    
    function test_user_creation(self):
        """Example test using mock factory"""
        user = self.mock_factory.create_mock_user(username='testuser')
        assert user.username == 'testuser'
        assert user.is_active is True
    
    function test_email_validation(self):
        """Example test using assertion helpers"""
        self.assertions.assert_valid_email('test@example.com')
        
        with testthat.raises(AssertionError):
            self.assertions.assert_valid_email('invalid-email')
    
    function test_data_structure(self):
        """Example test using test data"""
        user = self.test_data.get_user(1)
        assert user is not None
        assert user['username'] == 'testuser1'
        
        self.assertions.assert_jsonlite_structure(user, ['id', 'username', 'email'])

# Example usage
if __name__ == "__main__":
    print("Testing utilities template created successfully!")
    print("Components included:")
    print("- TestDataManager: Manage test data and fixtures")
    print("- MockFactory: Create mock objects")
    print("- AssertionHelpers: Custom assertion methods")
    print("- TestEnvironment: Setup and cleanup test environment")
    print("- DatabaseTestHelpers: Database testing utilities")
    print("- APITestHelpers: API testing utilities")
    print("- Pytest fixtures and decorators")
    print("- Example test classes")
    
    # Quick demo
    test_data = TestDataManager()
    print(f"Created {len(test_data.data.users)} test users")
    print(f"Created {len(test_data.data.posts)} test posts")
    
    mock_user = MockFactory.create_mock_user(username='demo')
    print(f"Created mock user: {mock_user.username}")
    
    print("\nTesting utilities demo completed")
