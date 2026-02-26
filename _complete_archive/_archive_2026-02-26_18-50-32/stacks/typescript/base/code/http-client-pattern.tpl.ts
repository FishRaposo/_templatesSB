/**
 * File: http-client-pattern.tpl.ts
 * Purpose: Template for unknown implementation
 * Generated for: {{PROJECT_NAME}}
 */

// -----------------------------------------------------------------------------
// FILE: http-client-pattern.tpl.ts
// PURPOSE: TypeScript HTTP client pattern with interceptors, retry logic, and caching
// USAGE: Import and adapt for HTTP client functionality in TypeScript applications
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

// TypeScript HTTP Client Pattern
// Author: [[.Author]]
// Version: [[.Version]]
// Date: [[.Date]]

/**
 * HTTP Client Pattern for TypeScript Applications
 * 
 * This pattern provides a type-safe HTTP client with request/response interceptors,
 * retry logic, caching, and comprehensive error handling.
 */

// ==================== HTTP INTERFACES ====================

export interface HttpHeaders {
  [key: string]: string;
}

export interface HttpRequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';
  headers?: HttpHeaders;
  body?: any;
  params?: Record<string, any>;
  timeout?: number;
  retries?: number;
  cache?: boolean;
  validateStatus?: (status: number) => boolean;
}

export interface HttpResponse<T = any> {
  data: T;
  status: number;
  statusText: string;
  headers: HttpHeaders;
  config: HttpRequestOptions;
  request: {
    url: string;
    method: string;
    headers: HttpHeaders;
  };
}

export interface HttpError extends Error {
  config: HttpRequestOptions;
  code?: string;
  request?: {
    url: string;
    method: string;
    headers: HttpHeaders;
  };
  response?: HttpResponse;
  isRetryable?: boolean;
}

export interface RequestInterceptor {
  onFulfilled?: (config: HttpRequestOptions) => HttpRequestOptions | Promise<HttpRequestOptions>;
  onRejected?: (error: any) => any;
}

export interface ResponseInterceptor {
  onFulfilled?: (response: HttpResponse) => HttpResponse | Promise<HttpResponse>;
  onRejected?: (error: HttpError) => any;
}

export interface CacheOptions {
  enabled: boolean;
  ttl: number; // Time to live in milliseconds
  maxSize: number; // Maximum number of cached items
}

export interface RetryOptions {
  retries: number;
  retryDelay: number;
  retryCondition?: (error: HttpError) => boolean;
  retryDelayMultiplier?: number;
}

// ==================== HTTP CLIENT IMPLEMENTATION ====================

export class HttpClient {
  private baseURL: string;
  private defaultHeaders: HttpHeaders;
  private timeout: number;
  private requestInterceptors: RequestInterceptor[] = [];
  private responseInterceptors: ResponseInterceptor[] = [];
  private cache: Map<string, { data: any; timestamp: number }> = new Map();
  private cacheOptions: CacheOptions;
  private retryOptions: RetryOptions;

  constructor(config: {
    baseURL?: string;
    defaultHeaders?: HttpHeaders;
    timeout?: number;
    cache?: Partial<CacheOptions>;
    retry?: Partial<RetryOptions>;
  } = {}) {
    this.baseURL = config.baseURL || '';
    this.defaultHeaders = config.defaultHeaders || {};
    this.timeout = config.timeout || 10000;
    this.cacheOptions = {
      enabled: config.cache?.enabled ?? false,
      ttl: config.cache?.ttl ?? 300000, // 5 minutes
      maxSize: config.cache?.maxSize ?? 100,
      ...config.cache,
    };
    this.retryOptions = {
      retries: config.retry?.retries ?? 3,
      retryDelay: config.retry?.retryDelay ?? 1000,
      retryCondition: config.retry?.retryCondition ?? this.defaultRetryCondition,
      retryDelayMultiplier: config.retry?.retryDelayMultiplier ?? 2,
      ...config.retry,
    };
  }

  // ==================== INTERCEPTOR MANAGEMENT ====================

  public addRequestInterceptor(interceptor: RequestInterceptor): number {
    return this.requestInterceptors.push(interceptor) - 1;
  }

  public removeRequestInterceptor(id: number): void {
    this.requestInterceptors.splice(id, 1);
  }

  public addResponseInterceptor(interceptor: ResponseInterceptor): number {
    return this.responseInterceptors.push(interceptor) - 1;
  }

  public removeResponseInterceptor(id: number): void {
    this.responseInterceptors.splice(id, 1);
  }

  // ==================== HTTP METHODS ====================

  public async get<T = any>(
    url: string,
    options: HttpRequestOptions = {}
  ): Promise<HttpResponse<T>> {
    return this.request<T>(url, { ...options, method: 'GET' });
  }

  public async post<T = any>(
    url: string,
    data?: any,
    options: HttpRequestOptions = {}
  ): Promise<HttpResponse<T>> {
    return this.request<T>(url, { ...options, method: 'POST', body: data });
  }

  public async put<T = any>(
    url: string,
    data?: any,
    options: HttpRequestOptions = {}
  ): Promise<HttpResponse<T>> {
    return this.request<T>(url, { ...options, method: 'PUT', body: data });
  }

  public async patch<T = any>(
    url: string,
    data?: any,
    options: HttpRequestOptions = {}
  ): Promise<HttpResponse<T>> {
    return this.request<T>(url, { ...options, method: 'PATCH', body: data });
  }

  public async delete<T = any>(
    url: string,
    options: HttpRequestOptions = {}
  ): Promise<HttpResponse<T>> {
    return this.request<T>(url, { ...options, method: 'DELETE' });
  }

  // ==================== CORE REQUEST METHOD ====================

  public async request<T = any>(
    url: string,
    options: HttpRequestOptions = {}
  ): Promise<HttpResponse<T>> {
    // Apply request interceptors
    let config = await this.applyRequestInterceptors({
      method: 'GET',
      headers: { ...this.defaultHeaders },
      timeout: this.timeout,
      retries: this.retryOptions.retries,
      cache: this.cacheOptions.enabled,
      validateStatus: (status) => status >= 200 && status < 300,
      ...options,
    });

    // Build full URL
    const fullUrl = this.buildUrl(url, config.params);

    // Check cache for GET requests
    if (config.method === 'GET' && config.cache) {
      const cached = this.getFromCache(fullUrl);
      if (cached) {
        return cached;
      }
    }

    // Execute request with retry logic
    const response = await this.executeWithRetry<T>(fullUrl, config);

    // Cache GET responses
    if (config.method === 'GET' && config.cache) {
      this.setCache(fullUrl, response);
    }

    // Apply response interceptors
    return this.applyResponseInterceptors(response);
  }

  // ==================== PRIVATE METHODS ====================

  private buildUrl(url: string, params?: Record<string, any>): string {
    const fullUrl = url.startsWith('http') ? url : `${this.baseURL}${url}`;
    
    if (!params) {
      return fullUrl;
    }

    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        searchParams.append(key, String(value));
      }
    });

    const queryString = searchParams.toString();
    return queryString ? `${fullUrl}?${queryString}` : fullUrl;
  }

  private async applyRequestInterceptors(
    config: HttpRequestOptions
  ): Promise<HttpRequestOptions> {
    let processedConfig = { ...config };

    for (const interceptor of this.requestInterceptors) {
      if (interceptor.onFulfilled) {
        processedConfig = await interceptor.onFulfilled(processedConfig);
      }
    }

    return processedConfig;
  }

  private async applyResponseInterceptors<T>(
    response: HttpResponse<T>
  ): Promise<HttpResponse<T>> {
    let processedResponse = { ...response };

    for (const interceptor of this.responseInterceptors) {
      if (interceptor.onFulfilled) {
        processedResponse = await interceptor.onFulfilled(processedResponse);
      }
    }

    return processedResponse;
  }

  private async executeWithRetry<T>(
    url: string,
    config: HttpRequestOptions,
    attempt: number = 1
  ): Promise<HttpResponse<T>> {
    try {
      return await this.executeRequest<T>(url, config);
    } catch (error) {
      const httpError = error as HttpError;
      
      if (
        attempt <= config.retries! &&
        this.retryOptions.retryCondition!(httpError)
      ) {
        const delay = this.retryOptions.retryDelay * 
          Math.pow(this.retryOptions.retryDelayMultiplier!, attempt - 1);
        
        await this.sleep(delay);
        return this.executeWithRetry(url, config, attempt + 1);
      }

      throw httpError;
    }
  }

  private async executeRequest<T>(
    url: string,
    config: HttpRequestOptions
  ): Promise<HttpResponse<T>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.timeout);

    try {
      const response = await fetch(url, {
        method: config.method,
        headers: config.headers,
        body: config.body ? JSON.stringify(config.body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const error: HttpError = new Error(`HTTP ${response.status}: ${response.statusText}`) as HttpError;
        error.config = config;
        error.response = {
          data: null,
          status: response.status,
          statusText: response.statusText,
          headers: Object.fromEntries(response.headers.entries()),
          config,
          request: {
            url,
            method: config.method!,
            headers: config.headers!,
          },
        };
        error.isRetryable = this.isRetryableError(response.status);
        throw error;
      }

      const data = await response.json();

      const httpResponse: HttpResponse<T> = {
        data,
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        config,
        request: {
          url,
          method: config.method!,
          headers: config.headers!,
        },
      };

      return httpResponse;
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error.name === 'AbortError') {
        const timeoutError: HttpError = new Error('Request timeout') as HttpError;
        timeoutError.config = config;
        timeoutError.code = 'TIMEOUT';
        timeoutError.isRetryable = true;
        throw timeoutError;
      }

      throw error;
    }
  }

  private defaultRetryCondition(error: HttpError): boolean {
    if (!error.isRetryable) {
      return false;
    }

    // Retry on network errors, timeouts, and 5xx server errors
    return (
      error.code === 'TIMEOUT' ||
      error.code === 'NETWORK_ERROR' ||
      (error.response?.status && error.response.status >= 500)
    );
  }

  private isRetryableError(status: number): boolean {
    // Retry on 5xx server errors and some 4xx errors
    return status >= 500 || status === 408 || status === 429;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ==================== CACHE MANAGEMENT ====================

  private getFromCache<T>(key: string): HttpResponse<T> | null {
    if (!this.cacheOptions.enabled) {
      return null;
    }

    const cached = this.cache.get(key);
    if (!cached) {
      return null;
    }

    const now = Date.now();
    if (now - cached.timestamp > this.cacheOptions.ttl) {
      this.cache.delete(key);
      return null;
    }

    return cached.data;
  }

  private setCache<T>(key: string, data: HttpResponse<T>): void {
    if (!this.cacheOptions.enabled) {
      return;
    }

    // Clean up old entries if cache is full
    if (this.cache.size >= this.cacheOptions.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }

    this.cache.set(key, {
      data,
      timestamp: Date.now(),
    });
  }

  public clearCache(): void {
    this.cache.clear();
  }
}

// ==================== HTTP CLIENT FACTORY ====================

export class HttpClientFactory {
  public static createClient(config?: {
    baseURL?: string;
    defaultHeaders?: HttpHeaders;
    timeout?: number;
    cache?: Partial<CacheOptions>;
    retry?: Partial<RetryOptions>;
  }): HttpClient {
    return new HttpClient(config);
  }

  public static createAuthenticatedClient(
    token: string,
    config?: {
      baseURL?: string;
      defaultHeaders?: HttpHeaders;
      timeout?: number;
      cache?: Partial<CacheOptions>;
      retry?: Partial<RetryOptions>;
    }
  ): HttpClient {
    const client = new HttpClient(config);
    
    // Add authorization header
    client.addRequestInterceptor({
      onFulfilled: (config) => ({
        ...config,
        headers: {
          ...config.headers,
          Authorization: `Bearer ${token}`,
        },
      }),
    });

    return client;
  }

  public static createApiClient(
    apiKey: string,
    config?: {
      baseURL?: string;
      defaultHeaders?: HttpHeaders;
      timeout?: number;
      cache?: Partial<CacheOptions>;
      retry?: Partial<RetryOptions>;
    }
  ): HttpClient {
    const client = new HttpClient(config);
    
    // Add API key header
    client.addRequestInterceptor({
      onFulfilled: (config) => ({
        ...config,
        headers: {
          ...config.headers,
          'X-API-Key': apiKey,
        },
      }),
    });

    return client;
  }
}

// ==================== TYPE-SAFE API CLIENTS ====================

export interface User {
  id: string;
  name: string;
  email: string;
  createdAt: string;
}

export interface CreateUserRequest {
  name: string;
  email: string;
  password: string;
}

export interface UpdateUserRequest {
  name?: string;
  email?: string;
}

export class UserApiClient {
  private client: HttpClient;

  constructor(baseURL: string, authToken: string) {
    this.client = HttpClientFactory.createAuthenticatedClient(authToken, {
      baseURL,
      timeout: 15000,
      cache: { enabled: true, ttl: 60000 }, // 1 minute cache
    });
  }

  public async getUsers(): Promise<User[]> {
    const response = await this.client.get<User[]>('/users');
    return response.data;
  }

  public async getUser(id: string): Promise<User> {
    const response = await this.client.get<User>(`/users/${id}`);
    return response.data;
  }

  public async createUser(userData: CreateUserRequest): Promise<User> {
    const response = await this.client.post<User>('/users', userData);
    return response.data;
  }

  public async updateUser(id: string, userData: UpdateUserRequest): Promise<User> {
    const response = await this.client.patch<User>(`/users/${id}`, userData);
    return response.data;
  }

  public async deleteUser(id: string): Promise<void> {
    await this.client.delete(`/users/${id}`);
  }
}

// ==================== HTTP CLIENT DECORATORS ====================

/**
 * Decorator for automatic retry on specific errors
 */
export function RetryOnCondition(condition: (error: HttpError) => boolean) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      try {
        return await originalMethod.apply(this, args);
      } catch (error) {
        const httpError = error as HttpError;
        
        if (condition(httpError)) {
          // Implement retry logic here
          console.log(`Retrying ${propertyKey} due to error: ${httpError.message}`);
          return await originalMethod.apply(this, args);
        }
        
        throw error;
      }
    };

    return descriptor;
  };
}

/**
 * Decorator for caching HTTP responses
 */
export function CacheResponse(ttl: number = 300000) {
  const cache = new Map<string, { data: any; timestamp: number }>();

  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const cacheKey = `${propertyKey}_${JSON.stringify(args)}`;
      const cached = cache.get(cacheKey);

      if (cached && Date.now() - cached.timestamp < ttl) {
        return cached.data;
      }

      const result = await originalMethod.apply(this, args);
      cache.set(cacheKey, { data: result, timestamp: Date.now() });

      return result;
    };

    return descriptor;
  };
}

// ==================== USAGE EXAMPLES ====================

/**
 * Example service using the HTTP client
 */
export class ApiService {
  private httpClient: HttpClient;
  private userClient: UserApiClient;

  constructor(baseURL: string, authToken: string) {
    this.httpClient = HttpClientFactory.createClient({
      baseURL,
      timeout: 10000,
      retry: { retries: 3, retryDelay: 1000 },
    });

    this.userClient = new UserApiClient(baseURL, authToken);

    // Add logging interceptor
    this.httpClient.addRequestInterceptor({
      onFulfilled: (config) => {
        console.log(`Making ${config.method} request to ${config.url}`);
        return config;
      },
    });

    this.httpClient.addResponseInterceptor({
      onFulfilled: (response) => {
        console.log(`Received response with status ${response.status}`);
        return response;
      },
    });
  }

  @RetryOnCondition((error) => error.isRetryable!)
  @CacheResponse(60000) // Cache for 1 minute
  public async getPublicData(): Promise<any> {
    const response = await this.httpClient.get('/public/data');
    return response.data;
  }

  public async createUsers(users: CreateUserRequest[]): Promise<User[]> {
    const promises = users.map(user => this.userClient.createUser(user));
    return Promise.all(promises);
  }
}

// ==================== EXPORTS ====================

export default HttpClient;

// Type exports
export type {
  HttpHeaders,
  HttpRequestOptions,
  HttpResponse,
  HttpError,
  RequestInterceptor,
  ResponseInterceptor,
  CacheOptions,
  RetryOptions,
};

// Class exports
export {
  HttpClientFactory,
  UserApiClient,
};

// Decorator exports
export {
  RetryOnCondition,
  CacheResponse,
};

// ==================== BEST PRACTICES ====================

/*
1. **Type Safety**: Use generic types for request/response data
2. **Error Handling**: Implement comprehensive error handling with retry logic
3. **Interceptors**: Use request/response interceptors for cross-cutting concerns
4. **Caching**: Implement intelligent caching for GET requests
5. **Timeouts**: Always set appropriate timeouts for HTTP requests
6. **Retry Logic**: Implement exponential backoff for retryable errors
7. **Authentication**: Use factory methods for authenticated clients
8. **Type-Safe APIs**: Create typed API client classes for different services
9. **Decorators**: Use decorators for cross-cutting concerns like caching and retry
10. **Configuration**: Make HTTP client configuration flexible and extensible
*/
