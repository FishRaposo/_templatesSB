<!--
File: http-client-pattern.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# ----------------------------------------------------------------------------- 
# FILE: http-client-pattern.tpl.md
# PURPOSE: Generic HTTP client design pattern
# USAGE: Adapt this pattern for your specific technology stack
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# HTTP Client Pattern

## Overview
A robust HTTP client is essential for communicating with external APIs, microservices, and web services. This pattern provides a structured approach to HTTP communication with proper error handling, retries, and configuration.

## Core Design Pattern

### 1. HTTP Client Architecture

#### Core Components
- **Base Client**: Core HTTP communication with configuration
- **Request Builder**: Fluent interface for building requests
- **Response Handler**: Standardized response processing
- **Error Handler**: HTTP-specific error handling
- **Retry Logic**: Automatic retry with exponential backoff
- **Authentication**: Multiple auth strategies (Bearer, Basic, API Key)
- **Rate Limiting**: Request throttling and rate limit handling
- **Logging**: Request/response logging for debugging

### 2. Pseudocode Implementation

```pseudocode
class HTTPClient:
    function __init__(base_url, timeout=30, max_retries=3):
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.default_headers = {}
        self.auth_handler = None
        self.rate_limiter = RateLimiter()
        self.logger = Logger()
    
    function set_default_headers(headers):
        self.default_headers = merge(self.default_headers, headers)
    
    function set_auth(strategy, credentials):
        self.auth_handler = AuthHandler(strategy, credentials)
    
    function get(endpoint, params=None, headers=None):
        return self.request("GET", endpoint, params=params, headers=headers)
    
    function post(endpoint, data=None, headers=None):
        return self.request("POST", endpoint, data=data, headers=headers)
    
    function put(endpoint, data=None, headers=None):
        return self.request("PUT", endpoint, data=data, headers=headers)
    
    function delete(endpoint, headers=None):
        return self.request("DELETE", endpoint, headers=headers)
    
    function request(method, endpoint, data=None, params=None, headers=None):
        # Rate limiting
        self.rate_limiter.wait_if_needed()
        
        # Build request
        url = self.build_url(endpoint)
        request_headers = self.build_headers(headers)
        
        # Add authentication
        if self.auth_handler:
            request_headers = self.auth_handler.add_auth(request_headers)
        
        # Execute with retry logic
        return self.execute_with_retry(method, url, data, params, request_headers)
    
    function execute_with_retry(method, url, data, params, headers):
        last_error = None
        
        for attempt in range(self.max_retries + 1):
            try:
                response = self.execute_request(method, url, data, params, headers)
                self.log_request(method, url, response, attempt + 1)
                return self.handle_response(response)
                
            except NetworkError as e:
                last_error = e
                if attempt < self.max_retries and self.should_retry(e):
                    delay = self.calculate_backoff(attempt)
                    sleep(delay)
                    continue
                else:
                    break
                    
            except HTTPError as e:
                # Don't retry client errors (4xx)
                if e.status_code >= 400 and e.status_code < 500:
                    raise e
                last_error = e
                if attempt < self.max_retries:
                    delay = self.calculate_backoff(attempt)
                    sleep(delay)
                    continue
                else:
                    break
        
        raise last_error
    
    function execute_request(method, url, data, params, headers):
        # Platform-specific HTTP request execution
        # This would be implemented differently for each language/framework
        pass
    
    function handle_response(response):
        if response.status_code >= 200 and response.status_code < 300:
            return {
                "success": true,
                "status": response.status_code,
                "data": response.body,
                "headers": response.headers
            }
        else:
            raise HTTPError(response.status_code, response.body, response.headers)
    
    function should_retry(error):
        # Retry on network errors and server errors (5xx)
        return isinstance(error, NetworkError) or \
               (isinstance(error, HTTPError) and error.status_code >= 500)
    
    function calculate_backoff(attempt):
        # Exponential backoff with jitter
        base_delay = 1000  # 1 second
        max_delay = 30000  # 30 seconds
        delay = min(base_delay * (2 ** attempt), max_delay)
        jitter = random.uniform(0, delay * 0.1)
        return delay + jitter

class AuthHandler:
    function __init__(strategy, credentials):
        self.strategy = strategy
        self.credentials = credentials
    
    function add_auth(headers):
        if self.strategy == "bearer":
            return self.add_bearer_token(headers)
        elif self.strategy == "basic":
            return self.add_basic_auth(headers)
        elif self.strategy == "api_key":
            return self.add_api_key(headers)
        return headers
    
    function add_bearer_token(headers):
        headers["Authorization"] = f"Bearer {self.credentials.token}"
        return headers
    
    function add_basic_auth(headers):
        credentials = base64_encode(f"{self.credentials.username}:{self.credentials.password}")
        headers["Authorization"] = f"Basic {credentials}"
        return headers
    
    function add_api_key(headers):
        headers[self.credentials.key_header] = self.credentials.api_key
        return headers

class RateLimiter:
    function __init__(requests_per_second=10):
        self.requests_per_second = requests_per_second
        self.last_request_time = 0
    
    function wait_if_needed():
        current_time = current_milliseconds()
        time_since_last = current_time - self.last_request_time
        min_interval = 1000 / self.requests_per_second
        
        if time_since_last < min_interval:
            sleep(min_interval - time_since_last)
        
        self.last_request_time = current_milliseconds()

// Usage Examples
function example_usage():
    # Initialize client
    client = HTTPClient("https://api.example.com", timeout=30, max_retries=3)
    
    # Set authentication
    client.set_auth("bearer", {"token": "your-jwt-token"})
    
    # Set default headers
    client.set_default_headers({
        "User-Agent": "MyApp/1.0",
        "Accept": "application/json"
    })
    
    # Make requests
    try:
        users = client.get("/users", {"page": 1, "limit": 10})
        user = client.get("/users/123")
        new_user = client.post("/users", {
            "name": "John Doe",
            "email": "john@example.com"
        })
        
    except HTTPError as e:
        print(f"HTTP Error: {e.status_code} - {e.message}")
    except NetworkError as e:
        print(f"Network Error: {e.message}")
```

## Technology-Specific Implementations

### Node.js (JavaScript/TypeScript)
```typescript
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';

export class HTTPClient {
    private client: AxiosInstance;
    private rateLimiter: RateLimiter;

    constructor(
        baseURL: string,
        timeout: number = 30000,
        maxRetries: number = 3
    ) {
        this.rateLimiter = new RateLimiter();
        
        this.client = axios.create({
            baseURL,
            timeout,
            headers: {
                'Content-Type': 'application/json',
            },
        });

        this.setupInterceptors(maxRetries);
    }

    private setupInterceptors(maxRetries: number): void {
        // Request interceptor for rate limiting
        this.client.interceptors.request.use(async (config) => {
            await this.rateLimiter.waitIfNeeded();
            return config;
        });

        // Response interceptor for retry logic
        this.client.interceptors.response.use(
            (response) => response,
            async (error) => {
                const originalRequest = error.config;
                
                if (this.shouldRetry(error) && !originalRequest._retryCount) {
                    originalRequest._retryCount = 0;
                }
                
                if (this.shouldRetry(error) && originalRequest._retryCount < maxRetries) {
                    originalRequest._retryCount += 1;
                    const delay = this.calculateBackoff(originalRequest._retryCount);
                    await this.sleep(delay);
                    return this.client(originalRequest);
                }
                
                throw error;
            }
        );
    }

    setAuth(strategy: 'bearer' | 'basic' | 'apiKey', credentials: any): void {
        switch (strategy) {
            case 'bearer':
                this.client.defaults.headers.common['Authorization'] = `Bearer ${credentials.token}`;
                break;
            case 'basic':
                const encoded = Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64');
                this.client.defaults.headers.common['Authorization'] = `Basic ${encoded}`;
                break;
            case 'apiKey':
                this.client.defaults.headers.common[credentials.keyHeader] = credentials.apiKey;
                break;
        }
    }

    async get<T = any>(endpoint: string, params?: any, headers?: any): Promise<APIResponse<T>> {
        try {
            const response = await this.client.get<T>(endpoint, { params, headers });
            return this.formatResponse(response);
        } catch (error) {
            throw this.handleError(error);
        }
    }

    async post<T = any>(endpoint: string, data?: any, headers?: any): Promise<APIResponse<T>> {
        try {
            const response = await this.client.post<T>(endpoint, data, { headers });
            return this.formatResponse(response);
        } catch (error) {
            throw this.handleError(error);
        }
    }

    private formatResponse<T>(response: AxiosResponse<T>): APIResponse<T> {
        return {
            success: true,
            status: response.status,
            data: response.data,
            headers: response.headers,
        };
    }

    private handleError(error: any): HTTPError {
        if (error.response) {
            throw new HTTPError(
                error.response.status,
                error.response.data,
                error.response.headers
            );
        } else if (error.request) {
            throw new NetworkError('Network error: No response received');
        } else {
            throw new NetworkError(`Request error: ${error.message}`);
        }
    }
}

// Usage
const client = new HTTPClient('https://api.example.com');
client.setAuth('bearer', { token: 'jwt-token' });

const users = await client.get('/users', { page: 1, limit: 10 });
const user = await client.post('/users', { name: 'John', email: 'john@example.com' });
```

### Python
```python
import requests
import time
import random
from typing import Dict, Any, Optional, Union
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class HTTPClient:
    def __init__(self, base_url: str, timeout: int = 30, max_retries: int = 3):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.default_headers = {'Content-Type': 'application/json'}
        self.auth_handler = None
        self.rate_limiter = RateLimiter()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def set_auth(self, strategy: str, credentials: Dict[str, Any]):
        self.auth_handler = AuthHandler(strategy, credentials)
    
    def get(self, endpoint: str, params: Optional[Dict] = None, 
            headers: Optional[Dict] = None) -> Dict[str, Any]:
        return self.request('GET', endpoint, params=params, headers=headers)
    
    def post(self, endpoint: str, data: Optional[Dict] = None, 
             headers: Optional[Dict] = None) -> Dict[str, Any]:
        return self.request('POST', endpoint, json=data, headers=headers)
    
    def request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        # Rate limiting
        self.rate_limiter.wait_if_needed()
        
        # Build request
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {**self.default_headers, **(kwargs.get('headers', {}))}
        
        # Add authentication
        if self.auth_handler:
            headers = self.auth_handler.add_auth(headers)
        
        kwargs['headers'] = headers
        kwargs['timeout'] = self.timeout
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            
            return {
                'success': True,
                'status': response.status_code,
                'data': response.json() if response.content else None,
                'headers': dict(response.headers)
            }
            
        except requests.exceptions.HTTPError as e:
            raise HTTPError(e.response.status_code, e.response.text, dict(e.response.headers))
        except requests.exceptions.RequestException as e:
            raise NetworkError(str(e))

class RateLimiter:
    def __init__(self, requests_per_second: int = 10):
        self.requests_per_second = requests_per_second
        self.last_request_time = 0
    
    def wait_if_needed(self):
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        min_interval = 1.0 / self.requests_per_second
        
        if time_since_last < min_interval:
            time.sleep(min_interval - time_since_last)
        
        self.last_request_time = time.time()

# Usage
client = HTTPClient('https://api.example.com')
client.set_auth('bearer', {'token': 'jwt-token'})

users = client.get('/users', {'page': 1, 'limit': 10})
user = client.post('/users', {'name': 'John', 'email': 'john@example.com'})
```

### Go
```go
package httpclient

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "time"
)

type HTTPClient struct {
    client        *http.Client
    baseURL       string
    defaultHeaders map[string]string
    authHandler   *AuthHandler
    rateLimiter   *RateLimiter
    maxRetries    int
}

type Response struct {
    Success bool        `json:"success"`
    Status  int         `json:"status"`
    Data    interface{} `json:"data"`
    Headers http.Header `json:"headers"`
}

func NewHTTPClient(baseURL string, timeout time.Duration, maxRetries int) *HTTPClient {
    return &HTTPClient{
        client: &http.Client{
            Timeout: timeout,
        },
        baseURL:       strings.TrimSuffix(baseURL, "/"),
        defaultHeaders: make(map[string]string),
        rateLimiter:   NewRateLimiter(10), // 10 requests per second
        maxRetries:    maxRetries,
    }
}

func (c *HTTPClient) SetAuth(strategy string, credentials map[string]interface{}) {
    c.authHandler = NewAuthHandler(strategy, credentials)
}

func (c *HTTPClient) SetDefaultHeaders(headers map[string]string) {
    for k, v := range headers {
        c.defaultHeaders[k] = v
    }
}

func (c *HTTPClient) Get(endpoint string, params map[string]string) (*Response, error) {
    return c.Request("GET", endpoint, nil, params, nil)
}

func (c *HTTPClient) Post(endpoint string, data interface{}) (*Response, error) {
    return c.Request("POST", endpoint, data, nil, nil)
}

func (c *HTTPClient) Request(method, endpoint string, data interface{}, 
    params map[string]string, headers map[string]string) (*Response, error) {
    
    // Rate limiting
    c.rateLimiter.WaitIfNeeded()
    
    // Build URL
    fullURL, err := url.Parse(c.baseURL + "/" + strings.TrimPrefix(endpoint, "/"))
    if err != nil {
        return nil, fmt.Errorf("invalid URL: %w", err)
    }
    
    // Add query parameters
    if params != nil {
        q := fullURL.Query()
        for k, v := range params {
            q.Set(k, v)
        }
        fullURL.RawQuery = q.Encode()
    }
    
    // Prepare request body
    var body io.Reader
    if data != nil {
        jsonData, err := json.Marshal(data)
        if err != nil {
            return nil, fmt.Errorf("failed to marshal data: %w", err)
        }
        body = bytes.NewBuffer(jsonData)
    }
    
    // Create request
    req, err := http.NewRequest(method, fullURL.String(), body)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    
    // Set headers
    for k, v := range c.defaultHeaders {
        req.Header.Set(k, v)
    }
    for k, v := range headers {
        req.Header.Set(k, v)
    }
    
    // Add authentication
    if c.authHandler != nil {
        c.authHandler.AddAuth(req)
    }
    
    // Execute with retry
    return c.executeWithRetry(req)
}

func (c *HTTPClient) executeWithRetry(req *http.Request) (*Response, error) {
    var lastErr error
    
    for attempt := 0; attempt <= c.maxRetries; attempt++ {
        resp, err := c.client.Do(req)
        if err != nil {
            lastErr = err
            if attempt < c.maxRetries {
                time.Sleep(c.calculateBackoff(attempt))
                continue
            }
            break
        }
        
        defer resp.Body.Close()
        
        if resp.StatusCode >= 200 && resp.StatusCode < 300 {
            // Success
            body, err := io.ReadAll(resp.Body)
            if err != nil {
                return nil, fmt.Errorf("failed to read response: %w", err)
            }
            
            var data interface{}
            if len(body) > 0 {
                if err := json.Unmarshal(body, &data); err != nil {
                    data = string(body)
                }
            }
            
            return &Response{
                Success: true,
                Status:  resp.StatusCode,
                Data:    data,
                Headers: resp.Header,
            }, nil
        }
        
        // Handle errors
        if resp.StatusCode >= 400 && resp.StatusCode < 500 {
            // Client errors - don't retry
            body, _ := io.ReadAll(resp.Body)
            return nil, &HTTPError{
                StatusCode: resp.StatusCode,
                Message:    string(body),
                Headers:    resp.Header,
            }
        }
        
        // Server errors - retry
        if attempt < c.maxRetries {
            time.Sleep(c.calculateBackoff(attempt))
            continue
        }
        
        body, _ := io.ReadAll(resp.Body)
        return nil, &HTTPError{
            StatusCode: resp.StatusCode,
            Message:    string(body),
            Headers:    resp.Header,
        }
    }
    
    return nil, lastErr
}

func (c *HTTPClient) calculateBackoff(attempt int) time.Duration {
    baseDelay := time.Second
    maxDelay := 30 * time.Second
    delay := baseDelay * time.Duration(1<<uint(attempt))
    if delay > maxDelay {
        delay = maxDelay
    }
    // Add jitter
    jitter := time.Duration(float64(delay) * 0.1 * (rand.Float64() - 0.5))
    return delay + jitter
}
```

## Best Practices

### 1. Request Design
- Use appropriate HTTP methods (GET, POST, PUT, DELETE)
- Include proper headers (Content-Type, User-Agent)
- Handle query parameters correctly
- Support both JSON and form data

### 2. Error Handling
- Distinguish between client errors (4xx) and server errors (5xx)
- Implement retry logic for transient failures
- Use exponential backoff with jitter
- Log failed requests for debugging

### 3. Performance
- Implement connection pooling
- Use appropriate timeout values
- Add rate limiting to avoid overwhelming services
- Cache responses when appropriate

### 4. Security
- Never log sensitive data (passwords, tokens)
- Use HTTPS for all communications
- Validate SSL certificates
- Implement proper authentication

## Adaptation Checklist

- [ ] Choose HTTP library for your technology stack
- [ ] Implement base client with configuration
- [ ] Add authentication strategies (Bearer, Basic, API Key)
- [ ] Implement retry logic with exponential backoff
- [ ] Add rate limiting functionality
- [ ] Set up proper error handling and logging
- [ ] Create request/response helpers
- [ ] Add unit tests for HTTP client functionality

## Common Pitfalls

1. **No timeouts** - Always set reasonable timeout values
2. **Missing error handling** - Handle network and HTTP errors properly
3. **Hardcoded URLs** - Use configuration for endpoints
4. **Ignoring rate limits** - Respect API rate limits
5. **Logging sensitive data** - Never log passwords or tokens

---

*Generic HTTP Client Pattern - Adapt to your technology stack*
