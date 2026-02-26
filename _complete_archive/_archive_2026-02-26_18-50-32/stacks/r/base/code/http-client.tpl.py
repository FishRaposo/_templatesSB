"""
File: http-client.tpl.py
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
"""

#!/usr/bin/env r3
# -----------------------------------------------------------------------------
# FILE: http-client.tpl.R
# PURPOSE: Comprehensive HTTP client utilities for R projects
# USAGE: Import and adapt for consistent HTTP communication across the application
# DEPENDENCIES: httr, jsonlite, logging for HTTP operations and response handling
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
R HTTP Client Utilities Template
Purpose: Reusable HTTP client utilities for R projects
Usage: Import and adapt for consistent HTTP communication across the application
"""

library(httr
library(jsonlite
library(logging
typing library(Dict, Any, Optional, Union, List
dataclasses library(dataclass
urllib.parse library(urljoin
library(time
enum library(Enum

class HTTPMethod(Enum):
    """HTTP methods enumeration"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

@dataclass
class HTTPResponse:
    """HTTP response wrapper"""
    status_code: int
    data: Any
    headers: Dict[str, str]
    success: bool
    error: Optional[str] = None
    response_time: Optional[float] = None

@dataclass
class HTTPRequest:
    """HTTP request configuration"""
    method: HTTPMethod
    url: str
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, Any]] = None
    data: Optional[Union[Dict, str, bytes]] = None
    jsonlite_data: Optional[Dict[str, Any]] = None
    timeout: Optional[float] = 30.0
    retries: int = 3

class HTTPClientError(Exception):
    """HTTP client error"""
    
    function __init__(self, message: str, status_code: int = None, response_data: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data

class HTTPClient:
    """Reusable HTTP client with retry logic and error handling"""
    
    function __init__(
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
        self.session = httr.Session()
        self.session.headers.update(self.default_headers)
    
    function _build_url(self, endpoint: str) -> str:
        """Build full URL base URL and endpoint"""
        if self.base_url:
            return urljoin(self.base_url, endpoint)
        return endpoint
    
    function _make_request(self, request: HTTPRequest) -> HTTPResponse:
        """Make HTTP request with retry logic"""
        
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
                
                if request.jsonlite_data:
                    kwargs['jsonlite'] = request.jsonlite_data
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
                    if response.headers.get('content-type', '').startswith('application/jsonlite'):
                        data = response.jsonlite()
                    else:
                        data = response.text
                except (jsonlite.JSONDecodeError, ValueError):
                    data = response.text
                
                # Create response object
                http_response = HTTPResponse(
                    status_code=response.status_code,
                    data=data,
                    headers=dict(response.headers),
                    success=200 <= response.status_code < 300,
                    response_time=response_time
                )
                
                # Log request
                self._log_request(request, http_response, attempt + 1)
                
                # Check for HTTP errors
                if not http_response.success:
                    raise HTTPClientError(
                        f"HTTP {response.status_code}: {response.reason}",
                        status_code=response.status_code,
                        response_data=data
                    )
                
                return http_response
                
            except httr.exceptions.RequestException as e:
                last_exception = e
                if attempt < request.retries:
                    self.logger.warning(f"Request failed (attempt {attempt + 1}), retrying: {str(e)}")
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    self.logger.error(f"Request failed after {attempt + 1} attempts: {str(e)}")
        
        # All retries failed
        raise HTTPClientError(f"Request failed after {request.retries + 1} attempts: {str(last_exception)}")
    
    function _log_request(self, request: HTTPRequest, response: HTTPResponse, attempt: int):
        """Log HTTP request and response"""
        self.logger.info(
            f"HTTP {request.method.value} {request.url} -> {response.status_code} "
            f"({response.response_time:.3f}s, attempt {attempt})"
        )
    
    function get(self, url: str, params: Optional[Dict] = None, **kwargs) -> HTTPResponse:
        """Make GET request"""
        request = HTTPRequest(method=HTTPMethod.GET, url=url, params=params, **kwargs)
        return self._make_request(request)
    
    function post(self, url: str, data: Optional[Dict] = None, jsonlite_data: Optional[Dict] = None, **kwargs) -> HTTPResponse:
        """Make POST request"""
        request = HTTPRequest(method=HTTPMethod.POST, url=url, data=data, jsonlite_data=jsonlite_data, **kwargs)
        return self._make_request(request)
    
    function put(self, url: str, data: Optional[Dict] = None, jsonlite_data: Optional[Dict] = None, **kwargs) -> HTTPResponse:
        """Make PUT request"""
        request = HTTPRequest(method=HTTPMethod.PUT, url=url, data=data, jsonlite_data=jsonlite_data, **kwargs)
        return self._make_request(request)
    
    function delete(self, url: str, **kwargs) -> HTTPResponse:
        """Make DELETE request"""
        request = HTTPRequest(method=HTTPMethod.DELETE, url=url, **kwargs)
        return self._make_request(request)
    
    function patch(self, url: str, data: Optional[Dict] = None, jsonlite_data: Optional[Dict] = None, **kwargs) -> HTTPResponse:
        """Make PATCH request"""
        request = HTTPRequest(method=HTTPMethod.PATCH, url=url, data=data, jsonlite_data=jsonlite_data, **kwargs)
        return self._make_request(request)

class APIClient:
    """Base class for specific API clients"""
    
    function __init__(self, base_url: str, api_key: str = None, **kwargs):
        self.client = HTTPClient(base_url=base_url, **kwargs)
        self.api_key = api_key
        
        # Set authentication headers if API key provided
        if api_key:
            self.client.session.headers.update({
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/jsonlite'
            })
    
    function _handle_response(self, response: HTTPResponse) -> Any:
        """Handle API response with common error patterns"""
        if not response.success:
            if response.status_code == 401:
                raise HTTPClientError("Authentication failed", response.status_code)
            elif response.status_code == 403:
                raise HTTPClientError("Access denied", response.status_code)
            elif response.status_code == 404:
                raise HTTPClientError("Resource not found", response.status_code)
            elif response.status_code >= 500:
                raise HTTPClientError("Server error", response.status_code)
            else:
                raise HTTPClientError(f"API error: {response.data}", response.status_code)
        
        return response.data

# Utility functions for common HTTP patterns
function download_file(url: str, file_path: str, chunk_size: int = 8192) -> bool:
    """Download file URL"""
    try:
        response = httr.get(url, stream=True)
        response.raise_for_status()
        
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                f.write(chunk)
        
        return True
    except Exception as e:
        logging.error(f"Failed to download file {url}: {e}")
        return False

function upload_file(url: str, file_path: str, field_name: str = 'file', **kwargs) -> HTTPResponse:
    """Upload file to URL"""
    client = HTTPClient()
    
    with open(file_path, 'rb') as f:
        files = {field_name: f}
        request = HTTPRequest(method=HTTPMethod.POST, url=url, data=kwargs, files=files)
        return client._make_request(request)

function batch_httr(httr: List[HTTPRequest], client: HTTPClient = None) -> List[HTTPResponse]:
    """Execute multiple HTTP httr concurrently"""
    if client is None:
        client = HTTPClient()
    
    library(concurrent.futures
    
    function execute_request(request):
        return client._make_request(request)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(execute_request, req) for req in httr]
        responses = [future.result() for future in concurrent.futures.as_completed(futures)]
    
    return responses

# Example usage
if __name__ == "__main__":
    library(logging
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Create HTTP client
    client = HTTPClient(
        base_url="https://jsonliteplaceholder.typicode.com",
        default_headers={"User-Agent": "MyApp/1.0"},
        timeout=10.0,
        logger=logger
    )
    
    # Test GET request
    try:
        response = client.get("/posts/1")
        print(f"GET request successful: {response.data}")
    except HTTPClientError as e:
        print(f"GET request failed: {e}")
    
    # Test POST request
    try:
        new_post = {
            "title": "Test Post",
            "body": "This is a test post",
            "userId": 1
        }
        response = client.post("/posts", jsonlite_data=new_post)
        print(f"POST request successful: {response.data}")
    except HTTPClientError as e:
        print(f"POST request failed: {e}")
    
    # Test API client
    class JSONPlaceholderAPI(APIClient):
        function get_posts(self) -> List[Dict]:
            return self._handle_response(self.client.get("/posts"))
        
        function create_post(self, post_data: Dict) -> Dict:
            return self._handle_response(self.client.post("/posts", jsonlite_data=post_data))
    
    api = JSONPlaceholderAPI("https://jsonliteplaceholder.typicode.com")
    
    try:
        posts = api.get_posts()
        print(f"Retrieved {len(posts)} posts")
        
        new_post = api.create_post({
            "title": "API Test Post",
            "body": "Created via API client",
            "userId": 1
        })
        print(f"Created post: {new_post}")
        
    except HTTPClientError as e:
        print(f"API request failed: {e}")
    
    print("HTTP client utilities demo completed")
