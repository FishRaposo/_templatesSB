// Template: http-client.tpl.go
// Purpose: http-client template
// Stack: go
// Tier: base

# Universal Template System - Go Stack
# Generated: 2025-12-10
# Purpose: HTTP client utilities
# Tier: base
# Stack: go
# Category: utilities

// -----------------------------------------------------------------------------
// FILE: http-client.tpl.go
// PURPOSE: Comprehensive HTTP client utilities for Go projects
// USAGE: Import and adapt for consistent HTTP communication across the application
// DEPENDENCIES: bytes, context, encoding/json, fmt, io, net/http, net/url
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPMethod represents HTTP methods
type HTTPMethod string

const (
	GET    HTTPMethod = "GET"
	POST   HTTPMethod = "POST"
	PUT    HTTPMethod = "PUT"
	DELETE HTTPMethod = "DELETE"
	PATCH  HTTPMethod = "PATCH"
	HEAD   HTTPMethod = "HEAD"
)

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	StatusCode    int                    `json:"status_code"`
	Data          interface{}            `json:"data"`
	Headers       map[string]string      `json:"headers"`
	Success       bool                   `json:"success"`
	Error         string                 `json:"error,omitempty"`
	ResponseTime  time.Duration          `json:"response_time,omitempty"`
	RequestID     string                 `json:"request_id,omitempty"`
	ContentType   string                 `json:"content_type,omitempty"`
	RawBody       []byte                 `json:"-"`
}

// HTTPClientError represents an HTTP client error
type HTTPClientError struct {
	Message      string        `json:"message"`
	StatusCode   int           `json:"status_code"`
	ResponseData interface{}   `json:"response_data,omitempty"`
	RequestID    string        `json:"request_id,omitempty"`
	ResponseTime time.Duration `json:"response_time,omitempty"`
}

// Error implements the error interface
func (e *HTTPClientError) Error() string {
	return e.Message
}

// HTTPClientConfig represents HTTP client configuration
type HTTPClientConfig struct {
	BaseURL         string            `json:"base_url"`
	DefaultHeaders  map[string]string `json:"default_headers"`
	Timeout         time.Duration     `json:"timeout"`
	MaxRetries      int               `json:"max_retries"`
	RetryDelay      time.Duration     `json:"retry_delay"`
	EnableLogging   bool              `json:"enable_logging"`
	EnableCache     bool              `json:"enable_cache"`
	CacheMaxAge     time.Duration     `json:"cache_max_age"`
	UserAgent       string            `json:"user_agent"`
	FollowRedirects bool              `json:"follow_redirects"`
}

// DefaultHTTPClientConfig returns default HTTP client configuration
func DefaultHTTPClientConfig() HTTPClientConfig {
	return HTTPClientConfig{
		DefaultHeaders: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
		Timeout:         30 * time.Second,
		MaxRetries:      3,
		RetryDelay:      1 * time.Second,
		EnableLogging:   false,
		EnableCache:     false,
		CacheMaxAge:     5 * time.Minute,
		UserAgent:       "Go-HTTPClient/1.0",
		FollowRedirects: true,
	}
}

// HTTPClient represents an HTTP client
type HTTPClient struct {
	config     HTTPClientConfig
	httpClient *http.Client
	cache      *RequestCache
	metrics    *HTTPMetrics
	interceptors []RequestInterceptor
}

// RequestInterceptor interface for request/response interceptors
type RequestInterceptor interface {
	Intercept(req *HTTPRequest) (*HTTPRequest, error)
}

// HTTPRequest represents an HTTP request
type HTTPRequest struct {
	Method      HTTPMethod         `json:"method"`
	URL         string             `json:"url"`
	Headers     map[string]string  `json:"headers"`
	Body        interface{}        `json:"body,omitempty"`
	QueryParams map[string]string  `json:"query_params,omitempty"`
	Context     context.Context    `json:"-"`
	RequestID   string             `json:"request_id,omitempty"`
	Timeout     time.Duration      `json:"timeout,omitempty"`
}

// NewHTTPClient creates a new HTTP client
func NewHTTPClient(config HTTPClientConfig) *HTTPClient {
	client := &HTTPClient{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		cache:      NewRequestCache(config.CacheMaxAge),
		metrics:    NewHTTPMetrics(),
		interceptors: make([]RequestInterceptor, 0),
	}

	// Set user agent
	if config.UserAgent != "" {
		client.config.DefaultHeaders["User-Agent"] = config.UserAgent
	}

	return client
}

// AddInterceptor adds a request interceptor
func (c *HTTPClient) AddInterceptor(interceptor RequestInterceptor) {
	c.interceptors = append(c.interceptors, interceptor)
}

// buildURL builds the full URL
func (c *HTTPClient) buildURL(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return c.config.BaseURL + path
}

// buildHeaders builds headers for the request
func (c *HTTPClient) buildHeaders(additionalHeaders map[string]string) map[string]string {
	headers := make(map[string]string)
	for k, v := range c.config.DefaultHeaders {
		headers[k] = v
	}
	for k, v := range additionalHeaders {
		headers[k] = v
	}
	return headers
}

// generateRequestID generates a unique request ID
func (c *HTTPClient) generateRequestID() string {
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}

// executeRequest executes an HTTP request with retry logic
func (c *HTTPClient) executeRequest(req *HTTPRequest) (*HTTPResponse, error) {
	var lastErr error
	
	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		response, err := c.doRequest(req)
		if err == nil {
			return response, nil
		}

		lastErr = err

		if attempt < c.config.MaxRetries && c.shouldRetry(err) {
			delay := c.config.RetryDelay * time.Duration(attempt+1)
			time.Sleep(delay)
			continue
		}

		break
	}

	return nil, lastErr
}

// doRequest performs a single HTTP request
func (c *HTTPClient) doRequest(req *HTTPRequest) (*HTTPResponse, error) {
	startTime := time.Now()

	// Apply interceptors
	for _, interceptor := range c.interceptors {
		modifiedReq, err := interceptor.Intercept(req)
		if err != nil {
			return nil, err
		}
		req = modifiedReq
	}

	// Check cache for GET requests
	if req.Method == GET && c.config.EnableCache {
		if cached := c.cache.Get(req.URL, req.Headers); cached != nil {
			return cached, nil
		}
	}

	// Build URL with query parameters
	fullURL := req.URL
	if len(req.QueryParams) > 0 {
		u, err := url.Parse(req.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid URL: %w", err)
		}
		
		q := u.Query()
		for k, v := range req.QueryParams {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		fullURL = u.String()
	}

	// Prepare request body
	var bodyReader io.Reader
	if req.Body != nil {
		bodyBytes, err := json.Marshal(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(req.Context, string(req.Method), fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Set request ID header
	if req.RequestID != "" {
		httpReq.Header.Set("X-Request-ID", req.RequestID)
	}

	// Execute request
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		responseTime := time.Since(startTime)
		c.metrics.RecordError(req.Method, err)
		return nil, &HTTPClientError{
			Message:      err.Error(),
			ResponseTime: responseTime,
			RequestID:    req.RequestID,
		}
	}
	defer httpResp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		responseTime := time.Since(startTime)
		return nil, &HTTPClientError{
			Message:      fmt.Sprintf("failed to read response body: %v", err),
			StatusCode:   httpResp.StatusCode,
			ResponseTime: responseTime,
			RequestID:    req.RequestID,
		}
	}

	responseTime := time.Since(startTime)

	// Parse response body
	var responseData interface{}
	contentType := httpResp.Header.Get("Content-Type")
	
	if strings.Contains(contentType, "application/json") {
		if len(bodyBytes) > 0 {
			if err := json.Unmarshal(bodyBytes, &responseData); err != nil {
				responseData = string(bodyBytes)
			}
		}
	} else {
		responseData = string(bodyBytes)
	}

	// Build response headers
	headers := make(map[string]string)
	for k, v := range httpResp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	// Create response
	response := &HTTPResponse{
		StatusCode:   httpResp.StatusCode,
		Data:         responseData,
		Headers:      headers,
		Success:      httpResp.StatusCode >= 200 && httpResp.StatusCode < 300,
		ResponseTime: responseTime,
		RequestID:    req.RequestID,
		ContentType:  contentType,
		RawBody:      bodyBytes,
	}

	// Cache successful GET responses
	if req.Method == GET && response.Success && c.config.EnableCache {
		c.cache.Set(req.URL, req.Headers, response)
	}

	// Record metrics
	if response.Success {
		c.metrics.RecordSuccess(req.Method, responseTime)
	} else {
		c.metrics.RecordHTTPError(req.Method, response.StatusCode)
	}

	// Return error for non-successful responses
	if !response.Success {
		response.Error = fmt.Sprintf("HTTP %d: %s", response.StatusCode, httpResp.Status)
		return response, &HTTPClientError{
			Message:      response.Error,
			StatusCode:   response.StatusCode,
			ResponseData: responseData,
			ResponseTime: responseTime,
			RequestID:    req.RequestID,
		}
	}

	return response, nil
}

// shouldRetry determines if a request should be retried
func (c *HTTPClient) shouldRetry(err error) bool {
	if httpErr, ok := err.(*HTTPClientError); ok {
		// Retry on 5xx errors and 429 (rate limiting)
		return httpErr.StatusCode == 429 || httpErr.StatusCode >= 500
	}
	
	// Retry on network errors
	return strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "connection") ||
		strings.Contains(err.Error(), "network")
}

// Get performs a GET request
func (c *HTTPClient) Get(url string, options ...RequestOption) (*HTTPResponse, error) {
	req := &HTTPRequest{
		Method:    GET,
		URL:       c.buildURL(url),
		Headers:   c.buildHeaders(nil),
		RequestID: c.generateRequestID(),
		Context:   context.Background(),
	}

	// Apply options
	for _, option := range options {
		option(req)
	}

	return c.executeRequest(req)
}

// Post performs a POST request
func (c *HTTPClient) Post(url string, body interface{}, options ...RequestOption) (*HTTPResponse, error) {
	req := &HTTPRequest{
		Method:    POST,
		URL:       c.buildURL(url),
		Headers:   c.buildHeaders(nil),
		Body:      body,
		RequestID: c.generateRequestID(),
		Context:   context.Background(),
	}

	// Apply options
	for _, option := range options {
		option(req)
	}

	return c.executeRequest(req)
}

// Put performs a PUT request
func (c *HTTPClient) Put(url string, body interface{}, options ...RequestOption) (*HTTPResponse, error) {
	req := &HTTPRequest{
		Method:    PUT,
		URL:       c.buildURL(url),
		Headers:   c.buildHeaders(nil),
		Body:      body,
		RequestID: c.generateRequestID(),
		Context:   context.Background(),
	}

	// Apply options
	for _, option := range options {
		option(req)
	}

	return c.executeRequest(req)
}

// Delete performs a DELETE request
func (c *HTTPClient) Delete(url string, options ...RequestOption) (*HTTPResponse, error) {
	req := &HTTPRequest{
		Method:    DELETE,
		URL:       c.buildURL(url),
		Headers:   c.buildHeaders(nil),
		RequestID: c.generateRequestID(),
		Context:   context.Background(),
	}

	// Apply options
	for _, option := range options {
		option(req)
	}

	return c.executeRequest(req)
}

// Patch performs a PATCH request
func (c *HTTPClient) Patch(url string, body interface{}, options ...RequestOption) (*HTTPResponse, error) {
	req := &HTTPRequest{
		Method:    PATCH,
		URL:       c.buildURL(url),
		Headers:   c.buildHeaders(nil),
		Body:      body,
		RequestID: c.generateRequestID(),
		Context:   context.Background(),
	}

	// Apply options
	for _, option := range options {
		option(req)
	}

	return c.executeRequest(req)
}

// RequestOption represents a request option function
type RequestOption func(*HTTPRequest)

// WithHeaders adds headers to the request
func WithHeaders(headers map[string]string) RequestOption {
	return func(req *HTTPRequest) {
		for k, v := range headers {
			req.Headers[k] = v
		}
	}
}

// WithQueryParams adds query parameters to the request
func WithQueryParams(params map[string]string) RequestOption {
	return func(req *HTTPRequest) {
		if req.QueryParams == nil {
			req.QueryParams = make(map[string]string)
		}
		for k, v := range params {
			req.QueryParams[k] = v
		}
	}
}

// WithContext sets the context for the request
func WithContext(ctx context.Context) RequestOption {
	return func(req *HTTPRequest) {
		req.Context = ctx
	}
}

// WithTimeout sets a custom timeout for the request
func WithTimeout(timeout time.Duration) RequestOption {
	return func(req *HTTPRequest) {
		req.Timeout = timeout
	}
}

// WithRequestID sets a custom request ID
func WithRequestID(requestID string) RequestOption {
	return func(req *HTTPRequest) {
		req.RequestID = requestID
	}
}

// GetMetrics returns HTTP client metrics
func (c *HTTPClient) GetMetrics() HTTPMetricsSnapshot {
	return c.metrics.Snapshot()
}

// ClearCache clears the request cache
func (c *HTTPClient) ClearCache() {
	c.cache.Clear()
}

// RequestCache provides simple caching for GET requests
type RequestCache struct {
	items map[string]*cacheItem
	ttl   time.Duration
}

type cacheItem struct {
	response   *HTTPResponse
	expiration time.Time
}

// NewRequestCache creates a new request cache
func NewRequestCache(ttl time.Duration) *RequestCache {
	cache := &RequestCache{
		items: make(map[string]*cacheItem),
		ttl:   ttl,
	}
	
	// Start cleanup goroutine
	go cache.cleanup()
	
	return cache
}

// Get retrieves a cached response
func (c *RequestCache) Get(url string, headers map[string]string) *HTTPResponse {
	key := c.buildKey(url, headers)
	
	item, exists := c.items[key]
	if !exists || time.Now().After(item.expiration) {
		delete(c.items, key)
		return nil
	}
	
	return item.response
}

// Set stores a response in cache
func (c *RequestCache) Set(url string, headers map[string]string, response *HTTPResponse) {
	key := c.buildKey(url, headers)
	
	c.items[key] = &cacheItem{
		response:   response,
		expiration: time.Now().Add(c.ttl),
	}
}

// Clear clears all cached items
func (c *RequestCache) Clear() {
	c.items = make(map[string]*cacheItem)
}

// buildKey builds a cache key from URL and headers
func (c *RequestCache) buildKey(url string, headers map[string]string) string {
	// Simple key generation - in production, you might want something more sophisticated
	return fmt.Sprintf("%s:%v", url, headers)
}

// cleanup removes expired items from cache
func (c *RequestCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		now := time.Now()
		for key, item := range c.items {
			if now.After(item.expiration) {
				delete(c.items, key)
			}
		}
	}
}

// HTTPMetrics tracks HTTP client metrics
type HTTPMetrics struct {
	totalRequests    int64
	successfulRequests int64
	failedRequests   int64
	totalResponseTime time.Duration
	errorsByStatus   map[int]int64
	errorsByType     map[string]int64
}

// NewHTTPMetrics creates new HTTP metrics
func NewHTTPMetrics() *HTTPMetrics {
	return &HTTPMetrics{
		errorsByStatus: make(map[int]int64),
		errorsByType:   make(map[string]int64),
	}
}

// RecordSuccess records a successful request
func (m *HTTPMetrics) RecordSuccess(method HTTPMethod, responseTime time.Duration) {
	m.totalRequests++
	m.successfulRequests++
	m.totalResponseTime += responseTime
}

// RecordError records an error
func (m *HTTPMetrics) RecordError(method HTTPMethod, err error) {
	m.totalRequests++
	m.failedRequests++
	m.errorsByType[err.Error()]++
}

// RecordHTTPError records an HTTP error
func (m *HTTPMetrics) RecordHTTPError(method HTTPMethod, statusCode int) {
	m.totalRequests++
	m.failedRequests++
	m.errorsByStatus[statusCode]++
}

// Snapshot returns a snapshot of current metrics
func (m *HTTPMetrics) Snapshot() HTTPMetricsSnapshot {
	avgResponseTime := time.Duration(0)
	if m.totalRequests > 0 {
		avgResponseTime = m.totalResponseTime / time.Duration(m.totalRequests)
	}

	return HTTPMetricsSnapshot{
		TotalRequests:       m.totalRequests,
		SuccessfulRequests:  m.successfulRequests,
		FailedRequests:      m.failedRequests,
		AverageResponseTime: avgResponseTime,
		SuccessRate:         float64(m.successfulRequests) / float64(m.totalRequests) * 100,
		ErrorsByStatus:      m.errorsByStatus,
		ErrorsByType:        m.errorsByType,
	}
}

// HTTPMetricsSnapshot represents a snapshot of HTTP metrics
type HTTPMetricsSnapshot struct {
	TotalRequests       int64            `json:"total_requests"`
	SuccessfulRequests  int64            `json:"successful_requests"`
	FailedRequests      int64            `json:"failed_requests"`
	AverageResponseTime time.Duration    `json:"average_response_time"`
	SuccessRate         float64          `json:"success_rate"`
	ErrorsByStatus      map[int]int64    `json:"errors_by_status"`
	ErrorsByType        map[string]int64 `json:"errors_by_type"`
}

// API client base class
type APIClient struct {
	httpClient *HTTPClient
	baseURL    string
	apiVersion string
}

// NewAPIClient creates a new API client
func NewAPIClient(baseURL, apiVersion string, config HTTPClientConfig) *APIClient {
	config.BaseURL = baseURL
	return &APIClient{
		httpClient: NewHTTPClient(config),
		baseURL:    baseURL,
		apiVersion: apiVersion,
	}
}

// buildEndpoint builds an API endpoint URL
func (c *APIClient) buildEndpoint(endpoint string) string {
	return fmt.Sprintf("/api/%s/%s", c.apiVersion, endpoint)
}

// Get performs a GET request to the API
func (c *APIClient) Get(endpoint string, options ...RequestOption) (*HTTPResponse, error) {
	return c.httpClient.Get(c.buildEndpoint(endpoint), options...)
}

// Post performs a POST request to the API
func (c *APIClient) Post(endpoint string, body interface{}, options ...RequestOption) (*HTTPResponse, error) {
	return c.httpClient.Post(c.buildEndpoint(endpoint), body, options...)
}

// Put performs a PUT request to the API
func (c *APIClient) Put(endpoint string, body interface{}, options ...RequestOption) (*HTTPResponse, error) {
	return c.httpClient.Put(c.buildEndpoint(endpoint), body, options...)
}

// Delete performs a DELETE request to the API
func (c *APIClient) Delete(endpoint string, options ...RequestOption) (*HTTPResponse, error) {
	return c.httpClient.Delete(c.buildEndpoint(endpoint), options...)
}

// Example usage demonstrates how to use the HTTP client
func ExampleUsage() {
	// Create HTTP client
	config := DefaultHTTPClientConfig()
	config.BaseURL = "https://api.example.com"
	config.EnableLogging = true
	
	client := NewHTTPClient(config)

	// Make GET request
	resp, err := client.Get("/users/1")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	fmt.Printf("GET Response: %+v\n", resp.Data)

	// Make POST request
	userData := map[string]interface{}{
		"name":  "John Doe",
		"email": "john@example.com",
	}
	
	resp, err = client.Post("/users", userData)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	
	fmt.Printf("POST Response: %+v\n", resp.Data)

	// Use API client
	apiClient := NewAPIClient("https://api.example.com", "v1", config)
	resp, err = apiClient.Get("users/1")
	if err != nil {
		fmt.Printf("API Error: %v\n", err)
		return
	}
	
	fmt.Printf("API Response: %+v\n", resp.Data)

	// Get metrics
	metrics := client.GetMetrics()
	fmt.Printf("HTTP Metrics: %+v\n", metrics)
}
