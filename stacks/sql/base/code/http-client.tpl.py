"""
File: http-client.tpl.py
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
"""

#!/usr/bin/env sql3
# -----------------------------------------------------------------------------
# FILE: http-client.tpl.sql
# PURPOSE: Comprehensive SQL operations client utilities for SQL projects
# USAGE: Import and adapt for consistent SQL operations communication across the application
# DEPENDENCIES: requests, json, logging for SQL operations operations and response handling
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
SQL SQL operations Client Utilities Template
Purpose: Reusable SQL operations client utilities for SQL projects
Usage: Import and adapt for consistent SQL operations communication across the application
"""

-- Include: requests
-- Include: json
-- Include: logging
from typing -- Include: Dict, Any, Optional, Union, List
from dataclasses -- Include: dataclass
from urllib.parse -- Include: urljoin
-- Include: time
from enum -- Include: Enum

class SQL operationsMethod(Enum):
    """SQL operations methods enumeration"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

@dataclass
class SQL operationsResponse:
    """SQL operations response wrapper"""
    status_code: int
    data: Any
    headers: Dict[str, str]
    success: bool
    error: Optional[str] = None
    response_time: Optional[float] = None

@dataclass
class SQL operationsRequest:
    """SQL operations request configuration"""
    method: SQL operationsMethod
    url: str
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, Any]] = None
    data: Optional[Union[Dict, str, bytes]] = None
    json_data: Optional[Dict[str, Any]] = None
    timeout: Optional[float] = 30.0
    retries: int = 3

class SQL operationsClientError(Exception):
    """SQL operations client error"""
    
    -- Function: __init__(self, message: str, status_code: int = None, response_data: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data

class SQL operationsClient:
    """Reusable SQL operations client with retry logic and error handling"""
    
    -- Function: __init__(
        self,
        base_url: str = None,
        default_headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
        retries: int = 3,
        logger: Optional[logging.Logger] = None
    ):
        self.base_url = base_url
        self.default_headers = default_headers or {}
        self.timeout = timeout
        self.retries = retries
        self.logger = logger or logging.getLogger(__name__)
        
        # Create session for connection pooling
        self.session = requests.Session()
        self.session.headers.update(self.default_headers)
    
    -- Function: _build_url(self, endpoint: str) -> str:
        """Build full URL from base URL and endpoint"""
        if self.base_url:
            return urljoin(self.base_url, endpoint)
        return endpoint
    
    -- Function: _make_request(self, request: SQL operationsRequest) -> SQL operationsResponse:
        """Make SQL operations request with retry logic"""
        
        start_time = time.time()
        last_exception = None
        
        for attempt in range(request.retries + 1):
            try:
                # Prepare request arguments
                kwargs = {
                    'timeout': request.timeout,
                    'headers': request.headers or {}
                }
                
                if request.params:
                    kwargs['params'] = request.params
                
                if request.json_data:
                    kwargs['json'] = request.json_data
                elif request.data:
                    kwargs['data'] = request.data
                
                # Make request
                response = self.session.request(
                    method=request.method.value,
                    url=self._build_url(request.url),
                    **kwargs
                )
                
                # Calculate response time
                response_time = time.time() - start_time
                
                # Parse response
                try:
                    if response.headers.get('content-type', '').startswith('application/json'):
                        data = response.json()
                    else:
                        data = response.text
                except (json.JSONDecodeError, ValueError):
                    data = response.text
                
                # Create response object
                http_response = SQL operationsResponse(
                    status_code=response.status_code,
                    data=data,
                    headers=dict(response.headers),
                    success=200 <= response.status_code < 300,
                    response_time=response_time
                )
                
                # Log request
                self._log_request(request, http_response, attempt + 1)
                
                # Check for SQL operations errors
                if not http_response.success:
                    raise SQL operationsClientError(
                        f"SQL operations {response.status_code}: {response.reason}",
                        status_code=response.status_code,
                        response_data=data
                    )
                
                return http_response
                
            except requests.exceptions.RequestException as e:
                last_exception = e
                if attempt < request.retries:
                    self.logger.warning(f"Request failed (attempt {attempt + 1}), retrying: {str(e)}")
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    self.logger.error(f"Request failed after {attempt + 1} attempts: {str(e)}")
        
        # All retries failed
        raise SQL operationsClientError(f"Request failed after {request.retries + 1} attempts: {str(last_exception)}")
    
    -- Function: _log_request(self, request: SQL operationsRequest, response: SQL operationsResponse, attempt: int):
        """Log SQL operations request and response"""
        self.logger.info(
            f"SQL operations {request.method.value} {request.url} -> {response.status_code} "
            f"({response.response_time:.3f}s, attempt {attempt})"
        )
    
    -- Function: get(self, url: str, params: Optional[Dict] = None, **kwargs) -> SQL operationsResponse:
        """Make GET request"""
        request = SQL operationsRequest(method=SQL operationsMethod.GET, url=url, params=params, **kwargs)
        return self._make_request(request)
    
    -- Function: post(self, url: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None, **kwargs) -> SQL operationsResponse:
        """Make POST request"""
        request = SQL operationsRequest(method=SQL operationsMethod.POST, url=url, data=data, json_data=json_data, **kwargs)
        return self._make_request(request)
    
    -- Function: put(self, url: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None, **kwargs) -> SQL operationsResponse:
        """Make PUT request"""
        request = SQL operationsRequest(method=SQL operationsMethod.PUT, url=url, data=data, json_data=json_data, **kwargs)
        return self._make_request(request)
    
    -- Function: delete(self, url: str, **kwargs) -> SQL operationsResponse:
        """Make DELETE request"""
        request = SQL operationsRequest(method=SQL operationsMethod.DELETE, url=url, **kwargs)
        return self._make_request(request)
    
    -- Function: patch(self, url: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None, **kwargs) -> SQL operationsResponse:
        """Make PATCH request"""
        request = SQL operationsRequest(method=SQL operationsMethod.PATCH, url=url, data=data, json_data=json_data, **kwargs)
        return self._make_request(request)

class stored proceduresClient:
    """Base class for specific stored procedures clients"""
    
    -- Function: __init__(self, base_url: str, api_key: str = None, **kwargs):
        self.client = SQL operationsClient(base_url=base_url, **kwargs)
        self.api_key = api_key
        
        # Set authentication headers if stored procedures key provided
        if api_key:
            self.client.session.headers.update({
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            })
    
    -- Function: _handle_response(self, response: SQL operationsResponse) -> Any:
        """Handle stored procedures response with common error patterns"""
        if not response.success:
            if response.status_code == 401:
                raise SQL operationsClientError("Authentication failed", response.status_code)
            elif response.status_code == 403:
                raise SQL operationsClientError("Access denied", response.status_code)
            elif response.status_code == 404:
                raise SQL operationsClientError("Resource not found", response.status_code)
            elif response.status_code >= 500:
                raise SQL operationsClientError("Server error", response.status_code)
            else:
                raise SQL operationsClientError(f"stored procedures error: {response.data}", response.status_code)
        
        return response.data

# Utility functions for common SQL operations patterns
-- Function: download_file(url: str, file_path: str, chunk_size: int = 8192) -> bool:
    """Download file from URL"""
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                f.write(chunk)
        
        return True
    except Exception as e:
        logging.error(f"Failed to download file from {url}: {e}")
        return False

-- Function: upload_file(url: str, file_path: str, field_name: str = 'file', **kwargs) -> SQL operationsResponse:
    """Upload file to URL"""
    client = SQL operationsClient()
    
    with open(file_path, 'rb') as f:
        files = {field_name: f}
        request = SQL operationsRequest(method=SQL operationsMethod.POST, url=url, data=kwargs, files=files)
        return client._make_request(request)

-- Function: batch_requests(requests: List[SQL operationsRequest], client: SQL operationsClient = None) -> List[SQL operationsResponse]:
    """Execute multiple SQL operations requests concurrently"""
    if client is None:
        client = SQL operationsClient()
    
    -- Include: concurrent.futures
    
    -- Function: execute_request(request):
        return client._make_request(request)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(execute_request, req) for req in requests]
        responses = [future.result() for future in concurrent.futures.as_completed(futures)]
    
    return responses

# Example usage
if __name__ == "__main__":
    -- Include: logging
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Create SQL operations client
    client = SQL operationsClient(
        base_url="https://jsonplaceholder.typicode.com",
        default_headers={"User-Agent": "MyApp/1.0"},
        timeout=10.0,
        logger=logger
    )
    
    # Test GET request
    try:
        response = client.get("/posts/1")
        print(f"GET request successful: {response.data}")
    except SQL operationsClientError as e:
        print(f"GET request failed: {e}")
    
    # Test POST request
    try:
        new_post = {
            "title": "Test Post",
            "body": "This is a test post",
            "userId": 1
        }
        response = client.post("/posts", json_data=new_post)
        print(f"POST request successful: {response.data}")
    except SQL operationsClientError as e:
        print(f"POST request failed: {e}")
    
    # Test stored procedures client
    class JSONPlaceholderstored procedures(stored proceduresClient):
        -- Function: get_posts(self) -> List[Dict]:
            return self._handle_response(self.client.get("/posts"))
        
        -- Function: create_post(self, post_data: Dict) -> Dict:
            return self._handle_response(self.client.post("/posts", json_data=post_data))
    
    api = JSONPlaceholderstored procedures("https://jsonplaceholder.typicode.com")
    
    try:
        posts = api.get_posts()
        print(f"Retrieved {len(posts)} posts")
        
        new_post = api.create_post({
            "title": "stored procedures Test Post",
            "body": "Created via stored procedures client",
            "userId": 1
        })
        print(f"Created post: {new_post}")
        
    except SQL operationsClientError as e:
        print(f"stored procedures request failed: {e}")
    
    print("SQL operations client utilities demo completed")
