/**
 * Template: http-client.tpl.js
 * Purpose: http-client template
 * Stack: node
 * Tier: base
 */

# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: HTTP client utilities
# Tier: base
# Stack: node
# Category: utilities

#!/usr/bin/env node
/**
 * Node.js HTTP Client Utilities Template
 * Purpose: Reusable HTTP client utilities for Node.js projects
 * Usage: Import and adapt for consistent HTTP communication across the application
 */

const axios = require('axios');
const https = require('https');
const http = require('http');
const { EventEmitter } = require('events');

/**
 * HTTP methods enumeration
 */
const HTTPMethod = {
    GET: 'GET',
    POST: 'POST',
    PUT: 'PUT',
    DELETE: 'DELETE',
    PATCH: 'PATCH',
    HEAD: 'HEAD',
    OPTIONS: 'OPTIONS'
};

/**
 * HTTP response wrapper
 */
class HTTPResponse {
    constructor(statusCode, data, headers, options = {}) {
        this.statusCode = statusCode;
        this.data = data;
        this.headers = headers;
        this.success = statusCode >= 200 && statusCode < 300;
        this.error = null;
        this.responseTime = options.responseTime || null;
        this.requestId = options.requestId || null;
    }

    /**
     * Check if response is successful
     */
    isSuccessful() {
        return this.success;
    }

    /**
     * Get response data as JSON
     */
    toJSON() {
        return {
            statusCode: this.statusCode,
            data: this.data,
            headers: this.headers,
            success: this.success,
            error: this.error,
            responseTime: this.responseTime,
            requestId: this.requestId
        };
    }
}

/**
 * HTTP client error
 */
class HTTPClientError extends Error {
    constructor(message, statusCode = null, responseData = null, options = {}) {
        super(message);
        this.name = 'HTTPClientError';
        this.statusCode = statusCode;
        this.responseData = responseData;
        this.requestId = options.requestId || null;
        this.responseTime = options.responseTime || null;
    }
}

/**
 * HTTP client with retry logic and error handling
 */
class HTTPClient extends EventEmitter {
    constructor(options = {}) {
        super();
        
        this.options = {
            baseURL: options.baseURL || null,
            timeout: options.timeout || 30000,
            retries: options.retries || 3,
            retryDelay: options.retryDelay || 1000,
            retryBackoff: options.retryBackoff || 2,
            headers: options.headers || {},
            httpsAgent: options.httpsAgent || null,
            httpAgent: options.httpAgent || null,
            validateStatus: options.validateStatus || ((status) => status < 500),
            enableMetrics: options.enableMetrics || false,
            ...options
        };

        this.metrics = {
            totalRequests: 0,
            successfulRequests: 0,
            failedRequests: 0,
            totalResponseTime: 0,
            errorsByStatus: {}
        };

        // Create axios instance
        this.axios = this._createAxiosInstance();
    }

    /**
     * Create axios instance with configuration
     */
    _createAxiosInstance() {
        const config = {
            timeout: this.options.timeout,
            headers: this.options.headers,
            validateStatus: this.options.validateStatus
        };

        if (this.options.baseURL) {
            config.baseURL = this.options.baseURL;
        }

        if (this.options.httpsAgent) {
            config.httpsAgent = this.options.httpsAgent;
        } else {
            // Default HTTPS agent for development
            config.httpsAgent = new https.Agent({
                rejectUnauthorized: process.env.NODE_ENV === 'production'
            });
        }

        if (this.options.httpAgent) {
            config.httpAgent = this.options.httpAgent;
        }

        return axios.create(config);
    }

    /**
     * Make HTTP request with retry logic
     */
    async _makeRequest(method, url, options = {}) {
        const startTime = Date.now();
        const requestId = this._generateRequestId();
        let lastError;

        const requestOptions = {
            method,
            url,
            ...options,
            headers: {
                ...this.options.headers,
                ...options.headers
            }
        };

        for (let attempt = 0; attempt <= this.options.retries; attempt++) {
            try {
                const response = await this.axios.request(requestOptions);
                const responseTime = Date.now() - startTime;

                const httpResponse = new HTTPResponse(
                    response.status,
                    response.data,
                    response.headers,
                    { responseTime, requestId }
                );

                // Log request
                this._logRequest(method, url, httpResponse, attempt + 1);

                // Update metrics
                if (this.options.enableMetrics) {
                    this._updateMetrics(httpResponse);
                }

                // Emit success event
                this.emit('success', httpResponse);

                return httpResponse;

            } catch (error) {
                lastError = error;
                const responseTime = Date.now() - startTime;

                if (attempt < this.options.retries && this._shouldRetry(error)) {
                    const delay = this.options.retryDelay * Math.pow(this.options.retryBackoff, attempt);
                    
                    this.emit('retry', {
                        attempt: attempt + 1,
                        error: error.message,
                        delay,
                        requestId
                    });

                    await this._sleep(delay);
                } else {
                    // All retries failed or error is not retryable
                    const httpResponse = new HTTPResponse(
                        error.response?.status || 500,
                        error.response?.data || null,
                        error.response?.headers || {},
                        { responseTime, requestId }
                    );

                    httpResponse.error = error.message;

                    // Log failure
                    this._logRequest(method, url, httpResponse, attempt + 1);

                    // Update metrics
                    if (this.options.enableMetrics) {
                        this._updateMetrics(httpResponse);
                    }

                    // Emit error event
                    this.emit('error', httpResponse, error);

                    throw new HTTPClientError(
                        error.message,
                        error.response?.status,
                        error.response?.data,
                        { requestId, responseTime }
                    );
                }
            }
        }

        throw lastError;
    }

    /**
     * Check if error should be retried
     */
    _shouldRetry(error) {
        // Don't retry on 4xx errors (except 429 Too Many Requests)
        if (error.response && error.response.status >= 400 && error.response.status < 500) {
            return error.response.status === 429; // Only retry on rate limiting
        }

        // Retry on network errors and 5xx errors
        return !error.response || error.response.status >= 500;
    }

    /**
     * Generate unique request ID
     */
    _generateRequestId() {
        return Math.random().toString(36).substr(2, 9);
    }

    /**
     * Sleep utility for retry delays
     */
    _sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Log HTTP request
     */
    _logRequest(method, url, response, attempt) {
        const logData = {
            method,
            url,
            statusCode: response.statusCode,
            responseTime: response.responseTime,
            attempt,
            requestId: response.requestId,
            success: response.success
        };

        if (response.success) {
            this.emit('log', 'info', 'HTTP request completed', logData);
        } else {
            this.emit('log', 'error', 'HTTP request failed', logData);
        }
    }

    /**
     * Update request metrics
     */
    _updateMetrics(response) {
        this.metrics.totalRequests++;
        
        if (response.success) {
            this.metrics.successfulRequests++;
        } else {
            this.metrics.failedRequests++;
            this.metrics.errorsByStatus[response.statusCode] = 
                (this.metrics.errorsByStatus[response.statusCode] || 0) + 1;
        }

        if (response.responseTime) {
            this.metrics.totalResponseTime += response.responseTime;
        }
    }

    /**
     * HTTP method helpers
     */
    async get(url, options = {}) {
        return this._makeRequest(HTTPMethod.GET, url, options);
    }

    async post(url, data = null, options = {}) {
        return this._makeRequest(HTTPMethod.POST, url, { data, ...options });
    }

    async put(url, data = null, options = {}) {
        return this._makeRequest(HTTPMethod.PUT, url, { data, ...options });
    }

    async patch(url, data = null, options = {}) {
        return this._makeRequest(HTTPMethod.PATCH, url, { data, ...options });
    }

    async delete(url, options = {}) {
        return this._makeRequest(HTTPMethod.DELETE, url, options);
    }

    async head(url, options = {}) {
        return this._makeRequest(HTTPMethod.HEAD, url, options);
    }

    /**
     * Get client metrics
     */
    getMetrics() {
        const avgResponseTime = this.metrics.totalRequests > 0 
            ? this.metrics.totalResponseTime / this.metrics.totalRequests 
            : 0;

        return {
            ...this.metrics,
            averageResponseTime: Math.round(avgResponseTime),
            successRate: this.metrics.totalRequests > 0 
                ? (this.metrics.successfulRequests / this.metrics.totalRequests * 100).toFixed(2) + '%'
                : '0%'
        };
    }

    /**
     * Reset metrics
     */
    resetMetrics() {
        this.metrics = {
            totalRequests: 0,
            successfulRequests: 0,
            failedRequests: 0,
            totalResponseTime: 0,
            errorsByStatus: {}
        };
    }
}

/**
 * API client base class
 */
class APIClient extends EventEmitter {
    constructor(baseURL, options = {}) {
        super();
        
        this.client = new HTTPClient({
            baseURL,
            enableMetrics: true,
            ...options
        });

        this.setupEventHandlers();
    }

    /**
     * Setup event handlers for the HTTP client
     */
    setupEventHandlers() {
        this.client.on('success', (response) => {
            this.emit('apiSuccess', response);
        });

        this.client.on('error', (response, error) => {
            this.emit('apiError', response, error);
        });

        this.client.on('retry', (data) => {
            this.emit('apiRetry', data);
        });
    }

    /**
     * Handle API response with common error patterns
     */
    _handleResponse(response) {
        if (!response.success) {
            if (response.statusCode === 401) {
                throw new HTTPClientError('Authentication failed', 401, response.data);
            } else if (response.statusCode === 403) {
                throw new HTTPClientError('Access denied', 403, response.data);
            } else if (response.statusCode === 404) {
                throw new HTTPClientError('Resource not found', 404, response.data);
            } else if (response.statusCode >= 500) {
                throw new HTTPClientError('Server error', response.statusCode, response.data);
            } else {
                throw new HTTPClientError(`API error: ${response.error}`, response.statusCode, response.data);
            }
        }

        return response.data;
    }

    /**
     * Generic API methods
     */
    async get(endpoint, options = {}) {
        const response = await this.client.get(endpoint, options);
        return this._handleResponse(response);
    }

    async post(endpoint, data, options = {}) {
        const response = await this.client.post(endpoint, data, options);
        return this._handleResponse(response);
    }

    async put(endpoint, data, options = {}) {
        const response = await this.client.put(endpoint, data, options);
        return this._handleResponse(response);
    }

    async delete(endpoint, options = {}) {
        const response = await this.client.delete(endpoint, options);
        return this._handleResponse(response);
    }

    /**
     * Get API metrics
     */
    getMetrics() {
        return this.client.getMetrics();
    }
}

/**
 * File download utility
 */
async function downloadFile(url, filePath, options = {}) {
    const client = new HTTPClient();
    const fs = require('fs');
    const { pipeline } = require('stream');
    const { promisify } = require('util');

    try {
        const response = await client.get(url, {
            responseType: 'stream'
        });

        const stream = fs.createWriteStream(filePath);
        await promisify(pipeline)(response.data, stream);

        return {
            success: true,
            filePath,
            size: response.headers['content-length'] || 0
        };

    } catch (error) {
        throw new HTTPClientError(`Failed to download file: ${error.message}`, null, null);
    }
}

/**
 * File upload utility
 */
async function uploadFile(url, filePath, fieldName = 'file', options = {}) {
    const FormData = require('form-data');
    const fs = require('fs');

    try {
        const form = new FormData();
        form.append(fieldName, fs.createReadStream(filePath));

        // Add additional fields
        if (options.fields) {
            Object.entries(options.fields).forEach(([key, value]) => {
                form.append(key, value);
            });
        }

        const client = new HTTPClient();
        const response = await client.post(url, form, {
            headers: {
                ...form.getHeaders(),
                ...options.headers
            }
        });

        return response.data;

    } catch (error) {
        throw new HTTPClientError(`Failed to upload file: ${error.message}`, null, null);
    }
}

/**
 * Batch request utility
 */
async function batchRequests(requests, options = {}) {
    const { concurrency = 5 } = options;
    const client = new HTTPClient();

    const chunks = [];
    for (let i = 0; i < requests.length; i += concurrency) {
        chunks.push(requests.slice(i, i + concurrency));
    }

    const results = [];
    for (const chunk of chunks) {
        const chunkPromises = chunk.map(async (request) => {
            try {
                return await client._makeRequest(request.method, request.url, request.options);
            } catch (error) {
                return { error: error.message, statusCode: error.statusCode };
            }
        });

        const chunkResults = await Promise.all(chunkPromises);
        results.push(...chunkResults);
    }

    return results;
}

/**
 * Express middleware for HTTP client logging
 */
function httpClientMiddleware(logger) {
    return (req, res, next) => {
        const originalSend = res.send;
        
        res.send = function(data) {
            logger.info('HTTP response', {
                method: req.method,
                url: req.url,
                statusCode: res.statusCode,
                contentLength: data ? data.length : 0
            });
            
            return originalSend.call(this, data);
        };

        next();
    };
}

// Example usage
if (require.main === module) {
    async function main() {
        try {
            // Create HTTP client
            const client = new HTTPClient({
                baseURL: 'https://jsonplaceholder.typicode.com',
                timeout: 10000,
                retries: 2,
                enableMetrics: true
            });

            // Setup event listeners
            client.on('success', (response) => {
                console.log(`✅ Request succeeded: ${response.statusCode}`);
            });

            client.on('error', (response, error) => {
                console.error(`❌ Request failed: ${error.message}`);
            });

            // Test GET request
            try {
                const response = await client.get('/posts/1');
                console.log('GET result:', response.data);
            } catch (error) {
                console.error('GET error:', error.message);
            }

            // Test POST request
            try {
                const newPost = {
                    title: 'Test Post',
                    body: 'This is a test post',
                    userId: 1
                };

                const response = await client.post('/posts', newPost);
                console.log('POST result:', response.data);
            } catch (error) {
                console.error('POST error:', error.message);
            }

            // Test API client
            class JSONPlaceholderAPI extends APIClient {
                constructor() {
                    super('https://jsonplaceholder.typicode.com');
                }

                async getPosts() {
                    return this.get('/posts');
                }

                async createPost(postData) {
                    return this.post('/posts', postData);
                }
            }

            const api = new JSONPlaceholderAPI();

            try {
                const posts = await api.getPosts();
                console.log(`Retrieved ${posts.length} posts`);

                const newPost = await api.createPost({
                    title: 'API Test Post',
                    body: 'Created via API client',
                    userId: 1
                });
                console.log('Created post:', newPost);

            } catch (error) {
                console.error('API error:', error.message);
            }

            // Show metrics
            console.log('HTTP Client Metrics:', client.getMetrics());
            console.log('API Client Metrics:', api.getMetrics());

        } catch (error) {
            console.error('Demo error:', error.message);
        }
    }

    main();
}

module.exports = {
    // Classes
    HTTPClient,
    APIClient,
    HTTPResponse,
    HTTPClientError,

    // Utilities
    downloadFile,
    uploadFile,
    batchRequests,
    httpClientMiddleware,

    // Constants
    HTTPMethod
};
