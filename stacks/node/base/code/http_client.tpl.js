/*
File: http_client.tpl.js
Purpose: Resilient HTTP client with axios and retry
Generated for: {{PROJECT_NAME}}
*/

const axios = require('axios');
const axiosRetry = require('axios-retry').default;

class HTTPClient {
    constructor(config = {}) {
        this.config = {
            baseURL: config.baseURL || '',
            timeout: config.timeout || 30000,
            maxRetries: config.maxRetries || 3,
            headers: config.headers || {},
        };

        this.client = axios.create({
            baseURL: this.config.baseURL,
            timeout: this.config.timeout,
            headers: this.config.headers,
        });

        // Configure retry logic
        axiosRetry(this.client, {
            retries: this.config.maxRetries,
            retryDelay: axiosRetry.exponentialDelay,
            retryCondition: (error) => {
                return axiosRetry.isNetworkOrIdempotentRequestError(error) ||
                    error.response?.status >= 500;
            },
            onRetry: (retryCount, error) => {
                console.warn(`Retry ${retryCount} after error: ${error.message}`);
            },
        });

        // Request interceptor
        this.client.interceptors.request.use(
            (config) => {
                // Add request logging
                console.log(`[HTTP] ${config.method?.toUpperCase()} ${config.url}`);
                return config;
            },
            (error) => Promise.reject(error)
        );

        // Response interceptor
        this.client.interceptors.response.use(
            (response) => response,
            (error) => {
                console.error(`[HTTP] Error: ${error.message}`);
                return Promise.reject(this._formatError(error));
            }
        );
    }

    _formatError(error) {
        if (error.response) {
            return {
                status: error.response.status,
                message: error.response.data?.message || error.message,
                data: error.response.data,
            };
        }
        if (error.request) {
            return {
                status: 0,
                message: 'No response received',
                data: null,
            };
        }
        return {
            status: 0,
            message: error.message,
            data: null,
        };
    }

    async get(url, params = {}, headers = {}) {
        const response = await this.client.get(url, { params, headers });
        return response.data;
    }

    async post(url, data = {}, headers = {}) {
        const response = await this.client.post(url, data, { headers });
        return response.data;
    }

    async put(url, data = {}, headers = {}) {
        const response = await this.client.put(url, data, { headers });
        return response.data;
    }

    async patch(url, data = {}, headers = {}) {
        const response = await this.client.patch(url, data, { headers });
        return response.data;
    }

    async delete(url, headers = {}) {
        const response = await this.client.delete(url, { headers });
        return response.data;
    }

    // Set authorization header
    setAuthToken(token) {
        this.client.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }

    // Clear authorization header
    clearAuthToken() {
        delete this.client.defaults.headers.common['Authorization'];
    }
}

// Create a singleton instance
const createClient = (config) => new HTTPClient(config);

module.exports = {
    HTTPClient,
    createClient,
};

// Usage:
// const { createClient } = require('./http_client');
// const client = createClient({ baseURL: 'https://api.example.com' });
// const user = await client.get('/users/1');
