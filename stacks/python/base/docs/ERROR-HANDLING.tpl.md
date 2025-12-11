<!--
File: ERROR-HANDLING.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Error Handling Guide - Python

This guide covers comprehensive error handling strategies, exception management, and error recovery patterns for Python applications.

## 🚨 Python Error Handling Overview

Python provides robust error handling through exceptions, context managers, and error propagation mechanisms. Proper error handling ensures application stability and maintainability.

## 📊 Error Categories

### Built-in Exception Types
- **Exception**: Base class for all exceptions
- **ValueError**: Invalid value or argument
- **TypeError**: Operation on inappropriate type
- **KeyError**: Dictionary key not found
- **IndexError**: Sequence index out of range
- **AttributeError**: Attribute not found on object
- **ImportError**: Module import failure
- **ConnectionError**: Network connection issues
- **TimeoutError**: Operation timeout
- **FileNotFoundError**: File not found

### Custom Exception Hierarchy
```python
class BaseAppException(Exception):
    """Base exception for all application errors"""
    def __init__(self, message: str, error_code: str = None, context: dict = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        self.timestamp = datetime.utcnow()
    
    def __str__(self):
        return f"{self.__class__.__name__}: {self.message}"
    
    def to_dict(self):
        return {
            'type': self.__class__.__name__,
            'message': self.message,
            'error_code': self.error_code,
            'context': self.context,
            'timestamp': self.timestamp.isoformat()
        }

class ValidationException(BaseAppException):
    """Data validation errors"""
    pass

class BusinessException(BaseAppException):
    """Business logic errors"""
    pass

class SystemException(BaseAppException):
    """System-level errors"""
    pass

class NetworkException(BaseAppException):
    """Network-related errors"""
    pass

class DatabaseException(BaseAppException):
    """Database operation errors"""
    pass
```

## 🔍 Error Detection & Patterns

### Exception Handling Patterns

#### Before: Poor Error Handling
```python
# BAD: Bare except clause and silent failures
def process_user_data_bad(user_data):
    try:
        name = user_data['name']
        age = user_data['age']
        email = user_data['email']
        
        if age < 18:
            return False
        
        # Process data
        return True
    except:
        # Silent failure - no logging or error handling
        return False
```

#### After: Comprehensive Error Handling
```python
# GOOD: Specific exception handling with proper logging
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

def process_user_data_good(user_data: Dict[str, Any]) -> bool:
    """
    Process user data with comprehensive error handling
    
    Args:
        user_data: Dictionary containing user information
        
    Returns:
        bool: True if processing successful
        
    Raises:
        ValidationException: If data validation fails
        BusinessException: If business rules are violated
    """
    try:
        # Validate required fields
        required_fields = ['name', 'age', 'email']
        missing_fields = [field for field in required_fields if field not in user_data]
        
        if missing_fields:
            raise ValidationException(
                f"Missing required fields: {', '.join(missing_fields)}",
                error_code="MISSING_FIELDS",
                context={'missing_fields': missing_fields}
            )
        
        name = user_data['name']
        age = user_data['age']
        email = user_data['email']
        
        # Validate data types
        if not isinstance(name, str) or not name.strip():
            raise ValidationException(
                "Name must be a non-empty string",
                error_code="INVALID_NAME",
                context={'name': name}
            )
        
        if not isinstance(age, int) or age < 0:
            raise ValidationException(
                "Age must be a non-negative integer",
                error_code="INVALID_AGE",
                context={'age': age}
            )
        
        # Business logic validation
        if age < 18:
            raise BusinessException(
                "User must be at least 18 years old",
                error_code="AGE_RESTRICTION",
                context={'age': age}
            )
        
        # Process data
        user_record = create_user_record(name, age, email)
        logger.info(f"Successfully processed user: {name}")
        
        return True
        
    except ValidationException as e:
        logger.warning(f"Validation error: {e.message}", extra=e.context)
        raise
    except BusinessException as e:
        logger.warning(f"Business rule violation: {e.message}", extra=e.context)
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing user data: {str(e)}", 
                    exc_info=True, extra={'user_data': user_data})
        raise SystemException(
            "Failed to process user data",
            error_code="PROCESSING_ERROR",
            context={'original_error': str(e), 'user_data': user_data}
        ) from e

def create_user_record(name: str, age: int, email: str) -> Dict[str, Any]:
    """Create user record with validation"""
    return {
        'name': name.strip(),
        'age': age,
        'email': email.lower(),
        'created_at': datetime.utcnow()
    }
```

### Context Manager Error Handling

#### Before: Manual Resource Management
```python
# BAD: Manual resource cleanup
def process_file_bad(filepath):
    try:
        file = open(filepath, 'r')
        content = file.read()
        # Process content
        return content.upper()
    except Exception as e:
        # File might not be closed if error occurs
        print(f"Error: {e}")
        return None
    finally:
        file.close()  # Might fail if file was never opened
```

#### After: Context Manager Error Handling
```python
# GOOD: Using context managers for proper resource management
from contextlib import contextmanager
import os

@contextmanager
def file_processor(filepath: str, mode: str = 'r'):
    """Context manager for file processing with error handling"""
    file = None
    try:
        # Validate file exists before opening
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        file = open(filepath, mode)
        logger.info(f"Opened file: {filepath}")
        yield file
        
    except PermissionError:
        logger.error(f"Permission denied accessing file: {filepath}")
        raise
    except Exception as e:
        logger.error(f"Error processing file {filepath}: {str(e)}")
        raise SystemException(
            f"Failed to process file: {filepath}",
            error_code="FILE_PROCESSING_ERROR",
            context={'filepath': filepath, 'original_error': str(e)}
        ) from e
    finally:
        if file:
            file.close()
            logger.info(f"Closed file: {filepath}")

def process_file_good(filepath: str) -> str:
    """Process file with proper error handling and resource management"""
    try:
        with file_processor(filepath) as file:
            content = file.read()
            processed_content = content.upper()
            
            # Validate content
            if not processed_content.strip():
                raise ValidationException(
                    "File is empty or contains only whitespace",
                    error_code="EMPTY_FILE",
                    context={'filepath': filepath}
                )
            
            return processed_content
            
    except FileNotFoundError as e:
        logger.warning(f"File not found: {filepath}")
        raise
    except ValidationException as e:
        logger.warning(f"Content validation failed: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing file: {str(e)}")
        raise

# Usage
try:
    result = process_file_good('data.txt')
    print(result)
except FileNotFoundError:
    print("Please check if the file exists")
except ValidationException as e:
    print(f"Validation error: {e.message}")
except SystemException as e:
    print(f"System error: {e.message}")
```

## ⚡ Asynchronous Error Handling

### Async/Await Error Patterns

#### Before: Poor Async Error Handling
```python
# BAD: Not handling async errors properly
import asyncio

async def fetch_data_bad(url):
    response = await asyncio.get_event_loop().run_in_executor(
        None, lambda: requests.get(url)
    )
    data = response.json()  # Might fail if response is not valid JSON
    return data

async def main_bad():
    tasks = [fetch_data_bad(url) for url in urls]
    results = await asyncio.gather(*tasks)  # One failure cancels all
    return results
```

#### After: Comprehensive Async Error Handling
```python
# GOOD: Proper async error handling with individual task management
import asyncio
import aiohttp
from typing import List, Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)

async def fetch_data_good(url: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
    """
    Fetch data from URL with comprehensive error handling
    
    Args:
        url: URL to fetch data from
        session: aiohttp session for making requests
        
    Returns:
        Dict: Parsed JSON data
        
    Raises:
        NetworkException: If network request fails
        ValidationException: If response data is invalid
    """
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
            # Check HTTP status
            if response.status == 404:
                raise NetworkException(
                    f"Resource not found: {url}",
                    error_code="NOT_FOUND",
                    context={'url': url, 'status': response.status}
                )
            elif response.status >= 400:
                raise NetworkException(
                    f"HTTP error {response.status}: {url}",
                    error_code="HTTP_ERROR",
                    context={'url': url, 'status': response.status}
                )
            
            # Parse JSON with error handling
            try:
                data = await response.json()
            except aiohttp.ContentTypeError as e:
                raise ValidationException(
                    f"Invalid JSON response from {url}",
                    error_code="INVALID_JSON",
                    context={'url': url, 'content_type': response.headers.get('content-type')}
                ) from e
            
            # Validate response data
            if not isinstance(data, dict):
                raise ValidationException(
                    f"Expected dict response, got {type(data).__name__}",
                    error_code="INVALID_RESPONSE_TYPE",
                    context={'url': url, 'response_type': type(data).__name__}
                )
            
            logger.info(f"Successfully fetched data from {url}")
            return data
            
    except asyncio.TimeoutError:
        raise NetworkException(
            f"Request timeout for {url}",
            error_code="TIMEOUT",
            context={'url': url, 'timeout': 30}
        )
    except aiohttp.ClientConnectorError as e:
        raise NetworkException(
            f"Connection error for {url}: {str(e)}",
            error_code="CONNECTION_ERROR",
            context={'url': url, 'original_error': str(e)}
        ) from e
    except Exception as e:
        raise SystemException(
            f"Unexpected error fetching data from {url}",
            error_code="FETCH_ERROR",
            context={'url': url, 'original_error': str(e)}
        ) from e

async def fetch_multiple_data(urls: List[str]) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Fetch data from multiple URLs with individual error handling
    
    Args:
        urls: List of URLs to fetch
        
    Returns:
        List of tuples containing (url, data) for successful requests
    """
    connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
    timeout = aiohttp.ClientTimeout(total=60)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Create tasks for all URLs
        tasks = [fetch_data_good(url, session) for url in urls]
        
        # Wait for all tasks with individual error handling
        results = []
        for i, task in enumerate(asyncio.as_completed(tasks)):
            try:
                data = await task
                results.append((urls[i], data))
            except NetworkException as e:
                logger.warning(f"Network error for {urls[i]}: {e.message}")
                # Continue with other URLs instead of failing completely
            except ValidationException as e:
                logger.warning(f"Validation error for {urls[i]}: {e.message}")
            except SystemException as e:
                logger.error(f"System error for {urls[i]}: {e.message}")
        
        return results

# Usage example
async def main_good():
    urls = [
        'https://api.example.com/users',
        'https://api.example.com/products',
        'https://api.example.com/orders'
    ]
    
    try:
        results = await fetch_multiple_data(urls)
        print(f"Successfully fetched {len(results)} out of {len(urls)} URLs")
        
        for url, data in results:
            print(f"{url}: {len(data)} items")
            
    except Exception as e:
        logger.error(f"Fatal error in main: {str(e)}")
        raise
```

## 🛡️ Error Recovery & Retry Mechanisms

### Retry Pattern with Exponential Backoff

#### Before: No Retry Logic
```python
# BAD: No retry mechanism
def unstable_operation():
    # This operation might fail temporarily
    result = external_api_call()
    return result
```

#### After: Comprehensive Retry Strategy
```python
# GOOD: Retry mechanism with exponential backoff and circuit breaker
import time
import random
from typing import Callable, Any, Optional
from functools import wraps
import logging

logger = logging.getLogger(__name__)

class RetryConfig:
    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True
    ):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
    
    def call(self, func: Callable, *args, **kwargs):
        if self.state == 'OPEN':
            if self._should_attempt_reset():
                self.state = 'HALF_OPEN'
            else:
                raise NetworkException(
                    "Circuit breaker is OPEN",
                    error_code="CIRCUIT_BREAKER_OPEN"
                )
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise
    
    def _should_attempt_reset(self) -> bool:
        return (self.last_failure_time and 
                time.time() - self.last_failure_time > self.timeout)
    
    def _on_success(self):
        self.failure_count = 0
        self.state = 'CLOSED'
    
    def _on_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = 'OPEN'

def retry_with_backoff(
    config: Optional[RetryConfig] = None,
    retry_on: Optional[tuple] = None,
    circuit_breaker: Optional[CircuitBreaker] = None
):
    """
    Decorator for retrying functions with exponential backoff
    
    Args:
        config: Retry configuration
        retry_on: Tuple of exception types to retry on
        circuit_breaker: Circuit breaker instance
    """
    if config is None:
        config = RetryConfig()
    
    if retry_on is None:
        retry_on = (NetworkException, TimeoutError)
    
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(config.max_attempts):
                try:
                    if circuit_breaker:
                        return circuit_breaker.call(func, *args, **kwargs)
                    else:
                        return func(*args, **kwargs)
                        
                except retry_on as e:
                    last_exception = e
                    
                    if attempt == config.max_attempts - 1:
                        logger.error(
                            f"Function {func.__name__} failed after {config.max_attempts} attempts"
                        )
                        raise
                    
                    delay = _calculate_delay(attempt, config)
                    logger.warning(
                        f"Attempt {attempt + 1} failed for {func.__name__}: {str(e)}. "
                        f"Retrying in {delay:.2f} seconds"
                    )
                    time.sleep(delay)
                    
                except Exception as e:
                    # Don't retry on non-retryable exceptions
                    logger.error(f"Non-retryable error in {func.__name__}: {str(e)}")
                    raise
            
            # This should never be reached
            raise last_exception
        
        return wrapper
    return decorator

def _calculate_delay(attempt: int, config: RetryConfig) -> float:
    """Calculate delay with exponential backoff and optional jitter"""
    delay = config.base_delay * (config.exponential_base ** attempt)
    delay = min(delay, config.max_delay)
    
    if config.jitter:
        # Add random jitter to prevent thundering herd
        jitter_range = delay * 0.1
        delay += random.uniform(-jitter_range, jitter_range)
    
    return max(0, delay)

# Usage examples
circuit_breaker = CircuitBreaker(failure_threshold=3, timeout=30.0)

@retry_with_backoff(
    config=RetryConfig(max_attempts=5, base_delay=1.0, max_delay=30.0),
    retry_on=(NetworkException, TimeoutError, ConnectionError),
    circuit_breaker=circuit_breaker
)
def call_external_api(data: dict) -> dict:
    """Call external API with retry and circuit breaker"""
    response = requests.post(
        'https://api.example.com/data',
        json=data,
        timeout=30
    )
    response.raise_for_status()
    return response.json()

# Alternative usage without decorator
def unstable_operation_with_retry():
    config = RetryConfig(max_attempts=3, base_delay=2.0)
    
    for attempt in range(config.max_attempts):
        try:
            result = external_api_call()
            return result
        except NetworkException as e:
            if attempt == config.max_attempts - 1:
                raise
            
            delay = _calculate_delay(attempt, config)
            time.sleep(delay)
```

## 📝 Error Logging & Monitoring

### Comprehensive Error Logging System

#### Before: Basic Logging
```python
# BAD: Basic error logging without context
import logging

logging.basicConfig(level=logging.INFO)

def process_data(data):
    try:
        result = complex_operation(data)
        return result
    except Exception as e:
        logging.error(f"Error: {e}")
        return None
```

#### After: Structured Logging with Context
```python
# GOOD: Comprehensive logging system with structured data
import logging
import json
import traceback
from typing import Dict, Any, Optional
from datetime import datetime
import uuid

class StructuredLogger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.setup_logger()
    
    def setup_logger(self):
        """Setup logger with structured formatting"""
        handler = logging.StreamHandler()
        formatter = StructuredFormatter()
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        severity: str = "ERROR"
    ):
        """Log error with structured context"""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': severity,
            'error_type': error.__class__.__name__,
            'error_message': str(error),
            'traceback': traceback.format_exc(),
            'context': context or {},
            'request_id': getattr(self, '_request_id', None)
        }
        
        self.logger.error(json.dumps(log_data, default=str))
    
    def log_info(self, message: str, context: Optional[Dict[str, Any]] = None):
        """Log info message with context"""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': 'INFO',
            'message': message,
            'context': context or {},
            'request_id': getattr(self, '_request_id', None)
        }
        
        self.logger.info(json.dumps(log_data, default=str))
    
    def set_request_id(self, request_id: str):
        """Set request ID for correlation"""
        self._request_id = request_id

class StructuredFormatter(logging.Formatter):
    def format(self, record):
        try:
            log_data = json.loads(record.getMessage())
            return json.dumps(log_data, default=str)
        except (json.JSONDecodeError, AttributeError):
            # Fallback for non-JSON messages
            return record.getMessage()

# Error monitoring service
class ErrorMonitor:
    def __init__(self):
        self.error_counts = {}
        self.error_rates = {}
        self.logger = StructuredLogger(__name__)
    
    def record_error(self, error: Exception, context: Dict[str, Any] = None):
        """Record error for monitoring"""
        error_type = error.__class__.__name__
        
        # Update counts
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        
        # Log with context
        self.logger.log_error(error, context)
        
        # Check for error rate thresholds
        self._check_error_thresholds(error_type)
    
    def _check_error_thresholds(self, error_type: str):
        """Check if error rate exceeds thresholds"""
        count = self.error_counts[error_type]
        
        if count > 10:  # Alert if more than 10 errors of same type
            self.logger.log_info(
                f"High error rate detected for {error_type}",
                {'error_count': count, 'error_type': error_type}
            )
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics"""
        return {
            'total_errors': sum(self.error_counts.values()),
            'error_counts': self.error_counts,
            'error_types': list(self.error_counts.keys())
        }

# Usage example
class DataService:
    def __init__(self):
        self.logger = StructuredLogger(__name__)
        self.monitor = ErrorMonitor()
    
    def process_request(self, request_data: Dict[str, Any], request_id: str = None):
        """Process request with comprehensive error handling"""
        if request_id:
            self.logger.set_request_id(request_id)
        
        try:
            # Validate request
            self._validate_request(request_data)
            
            # Process data
            result = self._process_data(request_data)
            
            self.logger.log_info(
                "Request processed successfully",
                {'request_id': request_id, 'result_size': len(result)}
            )
            
            return result
            
        except ValidationException as e:
            self.monitor.record_error(e, {
                'request_id': request_id,
                'request_data': request_data
            })
            raise
            
        except BusinessException as e:
            self.monitor.record_error(e, {
                'request_id': request_id,
                'business_rule': e.error_code
            })
            raise
            
        except Exception as e:
            self.monitor.record_error(e, {
                'request_id': request_id,
                'unexpected_error': True
            })
            raise SystemException(
                "Unexpected error processing request",
                error_code="PROCESSING_ERROR",
                context={'request_id': request_id}
            ) from e
    
    def _validate_request(self, data: Dict[str, Any]):
        """Validate request data"""
        if not data:
            raise ValidationException(
                "Request data cannot be empty",
                error_code="EMPTY_REQUEST"
            )
    
    def _process_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process data - might raise various exceptions"""
        # Simulate processing
        return {'processed': True, 'data': data}

# Usage
service = DataService()
request_id = str(uuid.uuid4())

try:
    result = service.process_request({'test': 'data'}, request_id)
except ValidationException as e:
    print(f"Validation failed: {e.message}")
except SystemException as e:
    print(f"System error: {e.message}")
```

## 🔄 Error Recovery Strategies

### Graceful Degradation Pattern

#### Before: All-or-Nothing Approach
```python
# BAD: Complete failure on partial issues
def generate_report(data):
    # If any part fails, entire report fails
    summary = generate_summary(data)
    charts = generate_charts(data)
    tables = generate_tables(data)
    
    return {
        'summary': summary,
        'charts': charts,
        'tables': tables
    }
```

#### After: Graceful Degradation with Fallbacks
```python
# GOOD: Graceful degradation with fallbacks
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.logger = StructuredLogger(__name__)
    
    def generate_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate report with graceful degradation
        Returns partial report if some components fail
        """
        report = {'status': 'partial', 'components': {}}
        
        # Generate summary with fallback
        try:
            summary = self._generate_summary(data)
            report['summary'] = summary
            report['components']['summary'] = 'success'
        except Exception as e:
            self.logger.log_error(e, {'component': 'summary'})
            report['summary'] = self._get_fallback_summary(data)
            report['components']['summary'] = 'fallback'
        
        # Generate charts with fallback
        try:
            charts = self._generate_charts(data)
            report['charts'] = charts
            report['components']['charts'] = 'success'
        except Exception as e:
            self.logger.log_error(e, {'component': 'charts'})
            report['charts'] = self._get_fallback_charts()
            report['components']['charts'] = 'fallback'
        
        # Generate tables with fallback
        try:
            tables = self._generate_tables(data)
            report['tables'] = tables
            report['components']['tables'] = 'success'
        except Exception as e:
            self.logger.log_error(e, {'component': 'tables'})
            report['tables'] = self._get_fallback_tables(data)
            report['components']['tables'] = 'fallback'
        
        # Determine overall status
        if all(status == 'success' for status in report['components'].values()):
            report['status'] = 'complete'
        elif any(status == 'success' for status in report['components'].values()):
            report['status'] = 'partial'
        else:
            report['status'] = 'failed'
        
        return report
    
    def _generate_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary - might fail"""
        if not data.get('records'):
            raise ValidationException("No records found in data")
        
        records = data['records']
        return {
            'total_records': len(records),
            'average_value': sum(r.get('value', 0) for r in records) / len(records),
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def _generate_charts(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate charts - might fail"""
        # Simulate chart generation
        return [{'type': 'bar', 'data': data.get('records', [])}]
    
    def _generate_tables(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate tables - might fail"""
        # Simulate table generation
        return [{'type': 'summary', 'rows': data.get('records', [])}]
    
    def _get_fallback_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback summary when generation fails"""
        return {
            'total_records': len(data.get('records', [])),
            'status': 'fallback_summary',
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def _get_fallback_charts(self) -> List[Dict[str, Any]]:
        """Fallback charts when generation fails"""
        return [{'type': 'placeholder', 'message': 'Chart generation failed'}]
    
    def _get_fallback_tables(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fallback tables when generation fails"""
        return [{'type': 'simple', 'message': f'Table contains {len(data.get("records", []))} records'}]

# Usage
generator = ReportGenerator()
try:
    report = generator.generate_report({'records': [{'value': 10}, {'value': 20}]})
    print(f"Report status: {report['status']}")
    print(f"Components: {report['components']}")
except Exception as e:
    logger.error(f"Report generation failed completely: {e}")
```

## 🧪 Error Testing

### Testing Error Scenarios

#### Before: No Error Testing
```python
# BAD: No tests for error scenarios
def test_process_data():
    data = {'name': 'test', 'age': 25}
    result = process_data(data)
    assert result is not None
```

#### After: Comprehensive Error Testing
```python
# GOOD: Comprehensive error testing
import pytest
from unittest.mock import patch, Mock
import requests

class TestErrorHandling:
    def test_validation_error_missing_fields(self):
        """Test validation error for missing fields"""
        with pytest.raises(ValidationException) as exc_info:
            process_user_data_good({'name': 'John'})
        
        assert exc_info.value.error_code == "MISSING_FIELDS"
        assert 'age' in exc_info.value.context['missing_fields']
        assert 'email' in exc_info.value.context['missing_fields']
    
    def test_validation_error_invalid_age(self):
        """Test validation error for invalid age"""
        with pytest.raises(ValidationException) as exc_info:
            process_user_data_good({'name': 'John', 'age': -5, 'email': 'john@example.com'})
        
        assert exc_info.value.error_code == "INVALID_AGE"
        assert exc_info.value.context['age'] == -5
    
    def test_business_error_age_restriction(self):
        """Test business rule error for age restriction"""
        with pytest.raises(BusinessException) as exc_info:
            process_user_data_good({'name': 'John', 'age': 16, 'email': 'john@example.com'})
        
        assert exc_info.value.error_code == "AGE_RESTRICTION"
        assert exc_info.value.context['age'] == 16
    
    def test_retry_mechanism_success_after_retry(self):
        """Test retry mechanism succeeds after temporary failure"""
        call_count = 0
        
        def mock_api_call():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise NetworkException("Temporary failure")
            return {"status": "success"}
        
        with patch('__main__.external_api_call', side_effect=mock_api_call):
            result = call_external_api({})
            assert result["status"] == "success"
            assert call_count == 3
    
    def test_retry_mechanism_max_attempts_reached(self):
        """Test retry mechanism fails after max attempts"""
        def mock_api_call():
            raise NetworkException("Persistent failure")
        
        with patch('__main__.external_api_call', side_effect=mock_api_call):
            with pytest.raises(NetworkException):
                call_external_api({})
    
    def test_circuit_breaker_opens_after_threshold(self):
        """Test circuit breaker opens after failure threshold"""
        circuit_breaker = CircuitBreaker(failure_threshold=3, timeout=1.0)
        
        def failing_operation():
            raise NetworkException("Service unavailable")
        
        # Should fail 3 times, then open circuit
        for i in range(3):
            with pytest.raises(NetworkException):
                circuit_breaker.call(failing_operation)
        
        # Circuit should now be open
        with pytest.raises(NetworkException) as exc_info:
            circuit_breaker.call(failing_operation)
        
        assert exc_info.value.error_code == "CIRCUIT_BREAKER_OPEN"
    
    def test_graceful_degradation_partial_success(self):
        """Test graceful degradation with partial success"""
        generator = ReportGenerator()
        
        # Mock one component to fail
        with patch.object(generator, '_generate_charts', side_effect=Exception("Chart failed")):
            report = generator.generate_report({'records': [{'value': 10}]})
            
            assert report['status'] == 'partial'
            assert report['components']['summary'] == 'success'
            assert report['components']['charts'] == 'fallback'
            assert 'summary' in report
            assert 'charts' in report
    
    def test_error_logging_with_context(self):
        """Test error logging includes context"""
        with patch('logging.Logger.error') as mock_log:
            try:
                raise ValidationException(
                    "Test error",
                    error_code="TEST_ERROR",
                    context={'test_key': 'test_value'}
                )
            except ValidationException as e:
                logger = StructuredLogger('test')
                logger.log_error(e, {'additional_context': 'test'})
                
                # Verify log was called with structured data
                mock_log.assert_called_once()
                log_message = mock_log.call_args[0][0]
                log_data = json.loads(log_message)
                
                assert log_data['error_type'] == 'ValidationException'
                assert log_data['error_message'] == 'Test error'
                assert log_data['context']['test_key'] == 'test_value'

# Integration tests
class TestErrorIntegration:
    def test_end_to_end_error_handling(self):
        """Test complete error handling flow"""
        service = DataService()
        
        # Test with invalid data
        with pytest.raises(ValidationException):
            service.process_request({})
        
        # Test with valid data
        result = service.process_request({'test': 'data'})
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_async_error_handling(self):
        """Test async error handling"""
        urls = ['https://httpbin.org/status/404', 'https://httpbin.org/json']
        
        results = await fetch_multiple_data(urls)
        
        # Should have one successful result
        assert len(results) == 1
        assert results[0][0] == 'https://httpbin.org/json'

# Performance tests for error handling
class TestErrorPerformance:
    def test_error_handling_performance(self):
        """Test error handling doesn't significantly impact performance"""
        import time
        
        start_time = time.time()
        
        for _ in range(1000):
            try:
                process_user_data_good({'name': 'Test', 'age': 25, 'email': 'test@example.com'})
            except Exception:
                pass  # Expected to succeed
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should complete 1000 operations in reasonable time
        assert duration < 1.0, f"Error handling too slow: {duration}s for 1000 operations"
```

## 🚀 Best Practices Checklist

### Exception Design & Hierarchy
- [ ] Create custom exception classes for different error categories
- [ ] Use inheritance to organize exceptions logically
- [ ] Include error codes and context information
- [ ] Implement proper exception chaining with `raise ... from`
- [ ] Make exceptions serializable for logging and monitoring
- [ ] Use type hints for exception handling

### Error Handling Patterns
- [ ] Use specific exception types instead of bare except
- [ ] Implement proper resource cleanup with context managers
- [ ] Use retry mechanisms with exponential backoff
- [ ] Implement circuit breaker pattern for external services
- [ ] Provide graceful degradation for non-critical failures
- [ ] Use async/await properly with error handling

### Logging & Monitoring
- [ ] Use structured logging with JSON format
- [ ] Include context information in error logs
- [ ] Implement error monitoring and alerting
- [ ] Use correlation IDs for request tracking
- [ ] Log both errors and successful operations
- [ ] Monitor error rates and patterns

### User Experience
- [ ] Provide user-friendly error messages
- [ ] Include error codes for support reference
- [ ] Implement proper HTTP status codes for APIs
- [ ] Provide fallback functionality when possible
- [ ] Use appropriate error severity levels
- [ ] Include recovery instructions in error messages

### Testing & Validation
- [ ] Write tests for all error scenarios
- [ ] Test retry mechanisms and circuit breakers
- [ ] Validate error logging and monitoring
- [ ] Test graceful degradation behavior
- [ ] Include performance tests for error handling
- [ ] Test error propagation through call stacks

---

**Python Version**: [PYTHON_VERSION]  
**Error Handling Framework**: Custom exceptions, Structured logging, Retry patterns  
**Last Updated**: [DATE]  
**Template Version**: 1.0
