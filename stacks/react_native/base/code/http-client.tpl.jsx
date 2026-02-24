/**
 * File: http-client.tpl.jsx
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

// -----------------------------------------------------------------------------
// FILE: http-client.tpl.jsx
// PURPOSE: Comprehensive HTTP client utilities for React Native projects
// USAGE: Import and adapt for consistent HTTP communication across the application
// DEPENDENCIES: React Native (createContext, useContext, useCallback, useState, useEffect)
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

/**
 * React Native HTTP Client Utilities Template
 * Purpose: Reusable HTTP client utilities for React Native projects
 * Usage: Import and adapt for consistent HTTP communication across the application
 */

import React Native, { createContext, useContext, useCallback, useState, useEffect } from 'react_native';

/**
 * HTTP methods
 */
export const HTTPMethod = {
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
export class HTTPResponse {
  constructor(statusCode, data, headers, options = {}) {
    this.statusCode = statusCode;
    this.data = data;
    this.headers = headers;
    this.success = statusCode >= 200 && statusCode < 300;
    this.error = null;
    this.responseTime = options.responseTime || null;
    this.requestId = options.requestId || null;
  }

  isSuccessful() {
    return this.success;
  }

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
export class HTTPClientError extends Error {
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
 * HTTP client context
 */
const HTTPContext = createContext();

/**
 * HTTP client provider
 */
export const HTTPProvider = ({ children, config = {} }) => {
  const [baseURL] = useState(config.baseURL || '');
  const [defaultHeaders] = useState(config.defaultHeaders || {});
  const [timeout] = useState(config.timeout || 30000);
  const [metrics, setMetrics] = useState({
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    totalResponseTime: 0,
    errorsByStatus: {}
  });

  /**
   * Generate unique request ID
   */
  const generateRequestId = useCallback(() => {
    return Math.random().toString(36).substr(2, 9);
  }, []);

  /**
   * Update request metrics
   */
  const updateMetrics = useCallback((response) => {
    setMetrics(prev => {
      const newMetrics = { ...prev };
      newMetrics.totalRequests++;
      
      if (response.success) {
        newMetrics.successfulRequests++;
      } else {
        newMetrics.failedRequests++;
        newMetrics.errorsByStatus[response.statusCode] = 
          (newMetrics.errorsByStatus[response.statusCode] || 0) + 1;
      }

      if (response.responseTime) {
        newMetrics.totalResponseTime += response.responseTime;
      }

      return newMetrics;
    });
  }, []);

  /**
   * Make HTTP request
   */
  const makeRequest = useCallback(async (method, url, options = {}) => {
    const startTime = performance.now();
    const requestId = generateRequestId();
    
    const fullURL = baseURL ? `${baseURL}${url}` : url;
    
    const requestOptions = {
      method,
      headers: {
        ...defaultHeaders,
        ...options.headers
      },
      ...options
    };

    // Add timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    requestOptions.signal = controller.signal;

    try {
      const response = await fetch(fullURL, requestOptions);
      const responseTime = Math.round(performance.now() - startTime);
      
      clearTimeout(timeoutId);

      let data;
      const contentType = response.headers.get('content-type');
      
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else if (contentType && contentType.includes('text/')) {
        data = await response.text();
      } else {
        data = await response.blob();
      }

      const httpResponse = new HTTPResponse(
        response.status,
        data,
        Object.fromEntries(response.headers.entries()),
        { responseTime, requestId }
      );

      updateMetrics(httpResponse);
      
      if (!httpResponse.success) {
        throw new HTTPClientError(
          `HTTP ${response.status}: ${response.statusText}`,
          response.status,
          data,
          { requestId, responseTime }
        );
      }

      return httpResponse;

    } catch (error) {
      clearTimeout(timeoutId);
      const responseTime = Math.round(performance.now() - startTime);
      
      const httpResponse = new HTTPResponse(
        error.name === 'AbortError' ? 408 : 500,
        null,
        {},
        { responseTime, requestId }
      );
      
      httpResponse.error = error.message;
      updateMetrics(httpResponse);
      
      throw new HTTPClientError(
        error.message,
        error.name === 'AbortError' ? 408 : 500,
        null,
        { requestId, responseTime }
      );
    }
  }, [baseURL, defaultHeaders, timeout, generateRequestId, updateMetrics]);

  /**
   * HTTP method helpers
   */
  const get = useCallback((url, options = {}) => {
    return makeRequest(HTTPMethod.GET, url, options);
  }, [makeRequest]);

  const post = useCallback((url, data, options = {}) => {
    return makeRequest(HTTPMethod.POST, url, {
      body: JSON.stringify(data),
      ...options
    });
  }, [makeRequest]);

  const put = useCallback((url, data, options = {}) => {
    return makeRequest(HTTPMethod.PUT, url, {
      body: JSON.stringify(data),
      ...options
    });
  }, [makeRequest]);

  const patch = useCallback((url, data, options = {}) => {
    return makeRequest(HTTPMethod.PATCH, url, {
      body: JSON.stringify(data),
      ...options
    });
  }, [makeRequest]);

  const deleteRequest = useCallback((url, options = {}) => {
    return makeRequest(HTTPMethod.DELETE, url, options);
  }, [makeRequest]);

  const value = {
    // Methods
    get,
    post,
    put,
    patch,
    delete: deleteRequest,
    makeRequest,
    
    // Utilities
    generateRequestId,
    
    // Metrics
    metrics,
    getMetrics: () => {
      const avgResponseTime = metrics.totalRequests > 0 
        ? metrics.totalResponseTime / metrics.totalRequests 
        : 0;

      return {
        ...metrics,
        averageResponseTime: Math.round(avgResponseTime),
        successRate: metrics.totalRequests > 0 
          ? (metrics.successfulRequests / metrics.totalRequests * 100).toFixed(2) + '%'
          : '0%'
      };
    },
    resetMetrics: () => {
      setMetrics({
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        totalResponseTime: 0,
        errorsByStatus: {}
      });
    }
  };

  return (
    <HTTPContext.Provider value={value}>
      {children}
    </HTTPContext.Provider>
  );
};

/**
 * Hook to use HTTP client
 */
export const useHTTP = () => {
  const context = useContext(HTTPContext);
  if (!context) {
    throw new Error('useHTTP must be used within an HTTPProvider');
  }
  return context;
};

/**
 * API client base class
 */
export class APIClient {
  constructor(baseURL, options = {}) {
    this.baseURL = baseURL;
    this.options = {
      timeout: 30000,
      retries: 3,
      retryDelay: 1000,
      ...options
    };
  }

  /**
   * Make request with retry logic
   */
  async request(method, url, options = {}) {
    let lastError;
    
    for (let attempt = 0; attempt <= this.options.retries; attempt++) {
      try {
        const response = await fetch(`${this.baseURL}${url}`, {
          method,
          timeout: this.options.timeout,
          ...options
        });

        if (!response.ok) {
          throw new HTTPClientError(
            `HTTP ${response.status}: ${response.statusText}`,
            response.status
          );
        }

        return await response.json();

      } catch (error) {
        lastError = error;

        if (attempt < this.options.retries && this.shouldRetry(error)) {
          await new Promise(resolve => 
            setTimeout(resolve, this.options.retryDelay * Math.pow(2, attempt))
          );
        } else {
          throw error;
        }
      }
    }

    throw lastError;
  }

  /**
   * Check if error should be retried
   */
  shouldRetry(error) {
    if (error instanceof HTTPClientError) {
      // Don't retry on 4xx errors (except 429)
      return error.statusCode === 429 || error.statusCode >= 500;
    }
    return true;
  }

  /**
   * Generic API methods
   */
  async get(url, options = {}) {
    return this.request(HTTPMethod.GET, url, options);
  }

  async post(url, data, options = {}) {
    return this.request(HTTPMethod.POST, url, {
      body: JSON.stringify(data),
      ...options
    });
  }

  async put(url, data, options = {}) {
    return this.request(HTTPMethod.PUT, url, {
      body: JSON.stringify(data),
      ...options
    });
  }

  async delete(url, options = {}) {
    return this.request(HTTPMethod.DELETE, url, options);
  }
}

/**
 * Hook for API calls with loading states
 */
export const useAPI = (apiClient) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const http = useHTTP();

  const callAPI = useCallback(async (method, url, data = null, options = {}) => {
    setLoading(true);
    setError(null);

    try {
      let response;
      
      switch (method) {
        case HTTPMethod.GET:
          response = await http.get(url, options);
          break;
        case HTTPMethod.POST:
          response = await http.post(url, data, options);
          break;
        case HTTPMethod.PUT:
          response = await http.put(url, data, options);
          break;
        case HTTPMethod.DELETE:
          response = await http.delete(url, options);
          break;
        default:
          throw new Error(`Unsupported HTTP method: ${method}`);
      }

      return response.data;

    } catch (err) {
      setError(err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [http]);

  return {
    callAPI,
    loading,
    error
  };
};

/**
 * Hook for file upload
 */
export const useFileUpload = () => {
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState(null);
  const http = useHTTP();

  const uploadFile = useCallback(async (url, file, options = {}) => {
    setUploading(true);
    setProgress(0);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      // Add additional fields
      if (options.fields) {
        Object.entries(options.fields).forEach(([key, value]) => {
          formData.append(key, value);
        });
      }

      const response = await http.post(url, formData, {
        headers: {
          // Don't set Content-Type for FormData - mobile app sets it with boundary
        },
        onUploadProgress: (progressEvent) => {
          if (progressEvent.lengthComputable) {
            const percentCompleted = Math.round(
              (progressEvent.loaded * 100) / progressEvent.total
            );
            setProgress(percentCompleted);
          }
        },
        ...options
      });

      return response.data;

    } catch (err) {
      setError(err);
      throw err;
    } finally {
      setUploading(false);
      setProgress(0);
    }
  }, [http]);

  return {
    uploadFile,
    uploading,
    progress,
    error
  };
};

/**
 * Hook for file download
 */
export const useFileDownload = () => {
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState(null);
  const http = useHTTP();

  const downloadFile = useCallback(async (url, filename = null, options = {}) => {
    setDownloading(true);
    setError(null);

    try {
      const response = await http.get(url, options);
      
      // Get filename from Content-Disposition header or use provided filename
      const contentDisposition = response.headers['content-disposition'];
      let finalFilename = filename;
      
      if (!finalFilename && contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/);
        if (filenameMatch) {
          finalFilename = filenameMatch[1];
        }
      }

      if (!finalFilename) {
        finalFilename = 'download';
      }

      // Create download link
      const blob = new Blob([response.data]);
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = finalFilename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(downloadUrl);

      return { success: true, filename: finalFilename };

    } catch (err) {
      setError(err);
      throw err;
    } finally {
      setDownloading(false);
    }
  }, [http]);

  return {
    downloadFile,
    downloading,
    error
  };
};

/**
 * Request cache for GET requests
 */
class RequestCache {
  constructor(maxSize = 100, ttl = 300000) { // 5 minutes default TTL
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttl = ttl;
  }

  get(key) {
    const item = this.cache.get(key);
    if (!item) return null;

    if (Date.now() - item.timestamp > this.ttl) {
      this.cache.delete(key);
      return null;
    }

    return item.data;
  }

  set(key, data) {
    // Remove oldest item if cache is full
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }

    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  clear() {
    this.cache.clear();
  }
}

/**
 * Global request cache instance
 */
const globalCache = new RequestCache();

/**
 * Hook for cached GET requests
 */
export const useCachedAPI = () => {
  const http = useHTTP();

  const getCached = useCallback(async (url, options = {}) => {
    const cacheKey = `${url}${JSON.stringify(options)}`;
    
    // Try to get from cache first
    const cached = globalCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    // Fetch from API
    const response = await http.get(url, options);
    
    // Cache the response
    globalCache.set(cacheKey, response.data);
    
    return response.data;
  }, [http]);

  const clearCache = useCallback(() => {
    globalCache.clear();
  }, []);

  return {
    getCached,
    clearCache
  };
};

/**
 * HTTP metrics dashboard component
 */
export const HTTPMetricsDashboard = () => {
  const { metrics, getMetrics, resetMetrics } = useHTTP();

  const metricsData = getMetrics();

  return (
    <div className="http-metrics-dashboard">
      <h3>HTTP Metrics</h3>
      <div className="metrics-grid">
        <div className="metric-item">
          <span className="metric-label">Total Requests</span>
          <span className="metric-value">{metricsData.totalRequests}</span>
        </div>
        <div className="metric-item">
          <span className="metric-label">Successful</span>
          <span className="metric-value">{metricsData.successfulRequests}</span>
        </div>
        <div className="metric-item">
          <span className="metric-label">Failed</span>
          <span className="metric-value">{metricsData.failedRequests}</span>
        </div>
        <div className="metric-item">
          <span className="metric-label">Success Rate</span>
          <span className="metric-value">{metricsData.successRate}</span>
        </div>
        <div className="metric-item">
          <span className="metric-label">Avg Response Time</span>
          <span className="metric-value">{metricsData.averageResponseTime}ms</span>
        </div>
      </div>
      
      {Object.keys(metricsData.errorsByStatus).length > 0 && (
        <div className="error-breakdown">
          <h4>Errors by Status</h4>
          {Object.entries(metricsData.errorsByStatus).map(([status, count]) => (
            <div key={status} className="error-item">
              <span>HTTP {status}</span>
              <span>{count}</span>
            </div>
          ))}
        </div>
      )}
      
      <button onClick={resetMetrics}>Reset Metrics</button>
    </div>
  );
};

// Example usage component
export const ExampleComponent = () => {
  const { get, post, metrics } = useHTTP();
  const { callAPI, loading, error } = useAPI();
  const { uploadFile, uploading, progress } = useFileUpload();
  const { getCached } = useCachedAPI();

  const handleGetRequest = async () => {
    try {
      const response = await get('/api/users');
      console.log('GET response:', response.data);
    } catch (err) {
      console.error('GET error:', err);
    }
  };

  const handlePostRequest = async () => {
    try {
      const response = await post('/api/users', { name: 'John Doe' });
      console.log('POST response:', response.data);
    } catch (err) {
      console.error('POST error:', err);
    }
  };

  const handleFileUpload = async (file) => {
    try {
      const result = await uploadFile('/api/upload', file);
      console.log('Upload result:', result);
    } catch (err) {
      console.error('Upload error:', err);
    }
  };

  const handleCachedRequest = async () => {
    try {
      const data = await getCached('/api/config');
      console.log('Cached data:', data);
    } catch (err) {
      console.error('Cached request error:', err);
    }
  };

  return (
    <div className="example-http-client">
      <h2>HTTP Client Example</h2>
      
      <button onClick={handleGetRequest} disabled={loading}>
        GET Request
      </button>
      
      <button onClick={handlePostRequest} disabled={loading}>
        POST Request
      </button>
      
      <input
        type="file"
        onChange={(e) => e.target.files[0] && handleFileUpload(e.target.files[0])}
        disabled={uploading}
      />
      
      {uploading && (
        <div>Upload progress: {progress}%</div>
      )}
      
      <button onClick={handleCachedRequest}>
        Cached Request
      </button>
      
      {error && (
        <div className="error-message">
          Error: {error.message}
        </div>
      )}
      
      <HTTPMetricsDashboard />
    </div>
  );
};

export default {
  HTTPProvider,
  useHTTP,
  APIClient,
  useAPI,
  useFileUpload,
  useFileDownload,
  useCachedAPI,
  HTTPMetricsDashboard,
  
  // Classes
  HTTPResponse,
  HTTPClientError,
  
  // Constants
  HTTPMethod
};
