# API Documentation Template

**Purpose**: Comprehensive API documentation structure template for REST APIs, GraphQL APIs, and SDKs.

**Last Updated**: [CURRENT_DATE]  
**API Version**: [API_VERSION]  
**Documentation Standard**: OpenAPI 3.0 + Comprehensive Examples

---

## 🎯 How to Use This Template

### For REST APIs:
1. **Replace placeholders** with your API-specific information
2. **Add endpoint documentation** following the provided structure
3. **Include authentication details** specific to your auth method
4. **Provide code examples** in multiple programming languages
5. **Generate OpenAPI spec** from this documentation

### For GraphQL APIs:
1. **Adapt endpoint sections** for GraphQL queries/mutations
2. **Document schema types** instead of individual endpoints
3. **Include GraphQL examples** and playground information
4. **Document subscription endpoints** if applicable

### For SDKs/Libraries:
1. **Focus on class/method documentation** instead of HTTP endpoints
2. **Include installation and setup instructions**
3. **Provide usage examples** for common scenarios
4. **Document configuration options**

---

## 📋 API Documentation Structure

### 🏠 Header Information
- **API Name**: [API_NAME]
- **Version**: [API_VERSION]
- **Base URL**: [BASE_URL]
- **Documentation Version**: [DOC_VERSION]
- **Last Updated**: [CURRENT_DATE]

---

## 🔐 Authentication

### Authentication Method: [AUTH_TYPE]

**Description**: [AUTH_DESCRIPTION]

#### Setup Instructions:
1. [SETUP_STEP_1]
2. [SETUP_STEP_2]
3. [SETUP_STEP_3]

#### Authentication Examples:

```bash
# cURL Example
curl -X [HTTP_METHOD] "[BASE_URL][ENDPOINT]" \
  -H "Authorization: [AUTH_HEADER_EXAMPLE]" \
  -H "Content-Type: application/json"
```

```javascript
// JavaScript/Node.js Example
const [AUTH_LIBRARY] = require('[AUTH_PACKAGE]');
const client = new [AUTH_LIBRARY]({
  [AUTH_CONFIG_KEY]: '[AUTH_CONFIG_VALUE]'
});
```

```python
# Python Example
import [AUTH_LIBRARY]
client = [AUTH_LIBRARY].[AUTH_METHOD]('[AUTH_VALUE]')
```

#### Token Management:
- **Token Expiration**: [TOKEN_EXPIRATION_TIME]
- **Refresh Token**: [REFRESH_TOKEN_AVAILABLE]
- **Token Storage**: [TOKEN_STORAGE_RECOMMENDATION]

---

## 📊 Base Response Format

### Success Response (2xx)
```json
{
  "success": true,
  "data": [RESPONSE_DATA],
  "message": "[SUCCESS_MESSAGE]",
  "timestamp": "[ISO_TIMESTAMP]",
  "requestId": "[UNIQUE_REQUEST_ID]"
}
```

### Error Response (4xx/5xx)
```json
{
  "success": false,
  "error": {
    "code": "[ERROR_CODE]",
    "message": "[ERROR_MESSAGE]",
    "details": [ERROR_DETAILS],
    "timestamp": "[ISO_TIMESTAMP]",
    "requestId": "[UNIQUE_REQUEST_ID]"
  }
}
```

---

## 🚀 API Endpoints

### [RESOURCE_GROUP_1]

#### [ENDPOINT_1] - [ENDPOINT_DESCRIPTION]
**Endpoint**: `[HTTP_METHOD] [BASE_URL][ENDPOINT_PATH]`  
**Description**: [DETAILED_DESCRIPTION]  
**Authentication**: [REQUIRED_AUTHENTICATION]  
**Rate Limit**: [RATE_LIMIT_INFO]

**Request Parameters:**
| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| [PARAM_1] | [TYPE] | [REQUIRED] | [DESCRIPTION] | [EXAMPLE] |
| [PARAM_2] | [TYPE] | [REQUIRED] | [DESCRIPTION] | [EXAMPLE] |

**Request Body:**
```json
{
  "[FIELD_1]": "[VALUE_1]",
  "[FIELD_2]": "[VALUE_2]"
}
```

**Response Body:**
```json
{
  "success": true,
  "data": {
    "[RESPONSE_FIELD_1]": "[RESPONSE_VALUE_1]",
    "[RESPONSE_FIELD_2]": "[RESPONSE_VALUE_2]"
  }
}
```

**Code Examples:**

```bash
# cURL
curl -X [HTTP_METHOD] "[BASE_URL][ENDPOINT_PATH]" \
  -H "Authorization: Bearer [TOKEN]" \
  -H "Content-Type: application/json" \
  -d '{
    "[FIELD_1]": "[VALUE_1]",
    "[FIELD_2]": "[VALUE_2]"
  }'
```

```javascript
// JavaScript/Node.js
const response = await fetch('[BASE_URL][ENDPOINT_PATH]', {
  method: '[HTTP_METHOD]',
  headers: {
    'Authorization': 'Bearer [TOKEN]',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    [FIELD_1]: '[VALUE_1]',
    [FIELD_2]: '[VALUE_2]'
  })
});

const data = await response.json();
```

```python
# Python
import requests

response = requests.[HTTP_METHOD.lower()](
    '[BASE_URL][ENDPOINT_PATH]',
    headers={
        'Authorization': 'Bearer [TOKEN]',
        'Content-Type': 'application/json'
    },
    json={
        '[FIELD_1]': '[VALUE_1]',
        '[FIELD_2]': '[VALUE_2]'
    }
)

data = response.json()
```

**Error Responses:**
- **400 Bad Request**: Invalid request parameters
- **401 Unauthorized**: Authentication failed
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **429 Too Many Requests**: Rate limit exceeded

---

## 📝 Data Models

### [MODEL_NAME_1]
**Description**: [MODEL_DESCRIPTION]

**Properties:**
| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| [PROPERTY_1] | [TYPE] | [REQUIRED] | [DESCRIPTION] | [EXAMPLE] |
| [PROPERTY_2] | [TYPE] | [REQUIRED] | [DESCRIPTION] | [EXAMPLE] |

**Example:**
```json
{
  "[PROPERTY_1]": "[VALUE_1]",
  "[PROPERTY_2]": "[VALUE_2]"
}
```

### [MODEL_NAME_2]
**Description**: [MODEL_DESCRIPTION]

**Properties:**
| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| [PROPERTY_1] | [TYPE] | [REQUIRED] | [DESCRIPTION] | [EXAMPLE] |
| [PROPERTY_2] | [TYPE] | [REQUIRED] | [DESCRIPTION] | [EXAMPLE] |

**Example:**
```json
{
  "[PROPERTY_1]": "[VALUE_1]",
  "[PROPERTY_2]": "[VALUE_2]"
}
```

---

## ⚠️ Error Codes

### Client Errors (4xx)

| Error Code | HTTP Status | Description | Resolution |
|------------|-------------|-------------|------------|
| [ERROR_CODE_1] | 400 | [ERROR_DESCRIPTION] | [RESOLUTION] |
| [ERROR_CODE_2] | 401 | [ERROR_DESCRIPTION] | [RESOLUTION] |
| [ERROR_CODE_3] | 403 | [ERROR_DESCRIPTION] | [RESOLUTION] |
| [ERROR_CODE_4] | 404 | [ERROR_DESCRIPTION] | [RESOLUTION] |
| [ERROR_CODE_5] | 429 | [ERROR_DESCRIPTION] | [RESOLUTION] |

### Server Errors (5xx)

| Error Code | HTTP Status | Description | Resolution |
|------------|-------------|-------------|------------|
| [ERROR_CODE_6] | 500 | [ERROR_DESCRIPTION] | [RESOLUTION] |
| [ERROR_CODE_7] | 502 | [ERROR_DESCRIPTION] | [RESOLUTION] |
| [ERROR_CODE_8] | 503 | [ERROR_DESCRIPTION] | [RESOLUTION] |

---

## 🔄 Common Workflows

### Workflow 1: [WORKFLOW_NAME_1]
**Description**: [WORKFLOW_DESCRIPTION]

**Steps:**
1. [WORKFLOW_STEP_1]
2. [WORKFLOW_STEP_2]
3. [WORKFLOW_STEP_3]

**Example:**
```javascript
// Complete workflow example
async function [WORKFLOW_FUNCTION_NAME]() {
  try {
    // Step 1: [STEP_DESCRIPTION]
    const [VARIABLE_1] = await [API_CALL_1];
    
    // Step 2: [STEP_DESCRIPTION]
    const [VARIABLE_2] = await [API_CALL_2];
    
    // Step 3: [STEP_DESCRIPTION]
    const result = await [API_CALL_3];
    
    return result;
  } catch (error) {
    console.error('Workflow failed:', error);
    throw error;
  }
}
```

### Workflow 2: [WORKFLOW_NAME_2]
**Description**: [WORKFLOW_DESCRIPTION]

**Steps:**
1. [WORKFLOW_STEP_1]
2. [WORKFLOW_STEP_2]
3. [WORKFLOW_STEP_3]

---

## 📊 Rate Limiting

### Rate Limit Policy
- **Requests per minute**: [RATE_LIMIT_PER_MINUTE]
- **Requests per hour**: [RATE_LIMIT_PER_HOUR]
- **Requests per day**: [RATE_LIMIT_PER_DAY]
- **Burst limit**: [BURST_LIMIT]

### Rate Limit Headers
```http
X-RateLimit-Limit: [RATE_LIMIT_HEADER]
X-RateLimit-Remaining: [REMAINING_REQUESTS]
X-RateLimit-Reset: [RESET_TIMESTAMP]
```

### Handling Rate Limits
```javascript
// Example rate limit handling
async function makeRequestWithRetry(url, options, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url, options);
      
      if (response.status === 429) {
        const resetTime = parseInt(response.headers.get('X-RateLimit-Reset'));
        const waitTime = resetTime - Date.now();
        
        if (waitTime > 0) {
          await new Promise(resolve => setTimeout(resolve, waitTime));
          continue;
        }
      }
      
      return response;
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, i)));
    }
  }
}
```

---

## 🧪 Testing and Debugging

### Testing Environment
- **Base URL**: [TEST_BASE_URL]
- **Authentication**: [TEST_AUTH_METHOD]
- **Test Data**: [TEST_DATA_SOURCE]

### Debugging Tools
- **API Playground**: [PLAYGROUND_URL]
- **Request Inspector**: [DEBUG_TOOL_URL]
- **Logging**: [LOGGING_METHOD]

### Common Debugging Scenarios

#### Authentication Issues
```bash
# Test authentication
curl -X GET "[BASE_URL]/auth/test" \
  -H "Authorization: Bearer [TEST_TOKEN]"
```

#### Request/Response Inspection
```javascript
// Enable debug logging
const debug = require('debug')('[PROJECT_NAME]:api');

// Log request details
debug('Making request to:', url);
debug('Request headers:', headers);
debug('Request body:', body);
```

---

## 📱 SDKs and Libraries

### Official SDKs

#### JavaScript/Node.js
**Installation:**
```bash
npm install [SDK_PACKAGE_NAME]
```

**Usage:**
```javascript
const [SDK_NAME] = require('[SDK_PACKAGE_NAME]');

const client = new [SDK_NAME]({
  apiKey: '[API_KEY]',
  baseURL: '[BASE_URL]'
});

// Example usage
const result = await client.[METHOD_NAME]([PARAMETERS]);
```

#### Python
**Installation:**
```bash
pip install [SDK_PACKAGE_NAME]
```

**Usage:**
```python
import [SDK_PACKAGE_NAME]

client = [SDK_PACKAGE_NAME].[ClientClass](
    api_key='[API_KEY]',
    base_url='[BASE_URL]'
)

# Example usage
result = client.[method_name]([parameters])
```

#### Other Languages
- **[LANGUAGE_1]**: [INSTALLATION_INSTRUCTIONS]
- **[LANGUAGE_2]**: [INSTALLATION_INSTRUCTIONS]
- **[LANGUAGE_3]**: [INSTALLATION_INSTRUCTIONS]

---

## 🔄 Versioning and Changelog

### API Versioning Strategy
- **Current Version**: [CURRENT_VERSION]
- **Versioning Method**: [VERSIONING_METHOD] (URL, Header, Query Parameter)
- **Backward Compatibility**: [COMPATIBILITY_POLICY]
- **Deprecation Policy**: [DEPRECATION_POLICY]

### Recent Changes
#### [VERSION_NUMBER] - [DATE]
- **Added**: [NEW_FEATURE_1]
- **Changed**: [MODIFIED_FEATURE_1]
- **Deprecated**: [DEPRECATED_FEATURE_1]
- **Removed**: [REMOVED_FEATURE_1]
- **Fixed**: [BUG_FIX_1]

#### [PREVIOUS_VERSION] - [DATE]
- **Added**: [NEW_FEATURE_2]
- **Changed**: [MODIFIED_FEATURE_2]
- **Fixed**: [BUG_FIX_2]

---

## 📞 Support and Resources

### Getting Help
- **Documentation**: [DOCUMENTATION_URL]
- **API Reference**: [API_REFERENCE_URL]
- **Support Email**: [SUPPORT_EMAIL]
- **Community Forum**: [FORUM_URL]
- **Status Page**: [STATUS_PAGE_URL]

### Additional Resources
- **OpenAPI Specification**: [OPENAPI_SPEC_URL]
- **Postman Collection**: [POSTMAN_COLLECTION_URL]
- **GitHub Repository**: [GITHUB_REPO_URL]
- **Examples Repository**: [EXAMPLES_REPO_URL]

### Contact Information
- **Technical Support**: [TECH_SUPPORT_EMAIL]
- **Business Inquiries**: [BUSINESS_EMAIL]
- **Bug Reports**: [BUG_REPORT_URL]
- **Feature Requests**: [FEATURE_REQUEST_URL]

---

## 📋 Quick Reference

### Base URLs
- **Production**: [PRODUCTION_BASE_URL]
- **Staging**: [STAGING_BASE_URL]
- **Development**: [DEVELOPMENT_BASE_URL]

### Authentication
- **Method**: [AUTH_METHOD]
- **Header**: [AUTH_HEADER_NAME]
- **Token Endpoint**: [TOKEN_ENDPOINT]

### Common Endpoints
- **Health Check**: `GET /health`
- **Authentication**: `POST /auth/token`
- **User Info**: `GET /user/me`
- **Rate Limits**: `GET /rate-limits`

### Error Handling
- **Success Codes**: 200, 201, 202, 204
- **Client Errors**: 400, 401, 403, 404, 429
- **Server Errors**: 500, 502, 503

---

**API Documentation Version**: [DOC_VERSION]  
**Last Updated**: [CURRENT_DATE]  
**Maintainer**: [API_MAINTAINER]

---

## 📋 **Appendix: Implementation Examples**

### **🚨 Optional: Concrete API Examples**

**Note**: These examples demonstrate how to adapt the universal template for specific implementations. Replace with your project-specific details.

#### **Example: REST API Endpoints**
```json
{
  "endpoints": {
    "users": {
      "GET /api/users": "List all users with pagination",
      "POST /api/users": "Create new user account",
      "GET /api/users/{id}": "Get user by ID",
      "PUT /api/users/{id}": "Update user profile",
      "DELETE /api/users/{id}": "Delete user account"
    },
    "products": {
      "GET /api/products": "List all products with filters",
      "POST /api/products": "Create new product",
      "GET /api/products/{id}": "Get product details",
      "PUT /api/products/{id}": "Update product information",
      "DELETE /api/products/{id}": "Remove product"
    },
    "orders": {
      "GET /api/orders": "List orders with status",
      "POST /api/orders": "Create new order",
      "GET /api/orders/{id}": "Get order details",
      "PUT /api/orders/{id}": "Update order status",
      "DELETE /api/orders/{id}": "Cancel order"
    },
    "tasks": {
      "GET /api/tasks": "List tasks with priority",
      "POST /api/tasks": "Create new task",
      "GET /api/tasks/{id}": "Get task details",
      "PUT /api/tasks/{id}": "Update task status",
      "DELETE /api/tasks/{id}": "Remove task"
    }
  }
}
```

#### **Example: GraphQL Schema**
```graphql
type User {
  id: ID!
  username: String!
  email: String!
  createdAt: DateTime!
  updatedAt: DateTime!
}

type Product {
  id: ID!
  name: String!
  description: String!
  price: Float!
  category: String!
  inStock: Boolean!
  createdAt: DateTime!
  updatedAt: DateTime!
}

type Order {
  id: ID!
  userId: ID!
  productId: ID!
  quantity: Int!
  status: OrderStatus!
  totalAmount: Float!
  createdAt: DateTime!
  updatedAt: DateTime!
}

enum OrderStatus {
  PENDING
  PROCESSING
  SHIPPED
  DELIVERED
  CANCELLED
}

type Query {
  users(limit: Int, offset: Int): [User!]!
  user(id: ID!): User
  products(category: String, inStock: Boolean): [Product!]!
  product(id: ID!): Product
  orders(userId: ID!, status: OrderStatus): [Order!]!
  order(id: ID!): Order
}

type Mutation {
  createUser(input: CreateUserInput!): User!
  updateUser(id: ID!, input: UpdateUserInput!): User!
  createProduct(input: CreateProductInput!): Product!
  updateProduct(id: ID!, input: UpdateProductInput!): Product!
  createOrder(input: CreateOrderInput!): Order!
  updateOrder(id: ID!, input: UpdateOrderInput!): Order!
  cancelOrder(id: ID!): Boolean!
}

input CreateUserInput {
  username: String!
  email: String!
}

input UpdateUserInput {
  username: String
  email: String
}

input CreateProductInput {
  name: String!
  description: String!
  price: Float!
  category: String!
  inStock: Boolean!
}

input UpdateProductInput {
  name: String
  description: String
  price: Float
  category: String
  inStock: Boolean
}

input CreateOrderInput {
  userId: ID!
  productId: ID!
  quantity: Int!
}

input UpdateOrderInput {
  status: OrderStatus
}
```

#### **Example: Authentication Flow**
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure_password"
}

Response:
{
  "token": "jwt_token_here",
  "user": {
    "id": "user_id",
    "email": "user@example.com",
    "username": "username"
  },
  "expiresIn": 3600
}
```

#### **Example: Error Response Format**
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": [
      {
        "field": "email",
        "message": "Email is required"
      },
      {
        "field": "password",
        "message": "Password must be at least 8 characters"
      }
    ],
    "timestamp": "2024-12-08T20:00:00Z",
    "requestId": "req_123456789"
  }
}
```

#### **Example: Rate Limit Implementation**
```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1702065600
Retry-After: 60

{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Try again later.",
    "retryAfter": 60
  }
}
```

**Adaptation Guidelines**:
1. **Replace Examples**: Use these as starting points for your specific API
2. **Customize Schemas**: Adapt data models to match your domain
3. **Update Endpoints**: Modify endpoint paths and methods
4. **Adjust Authentication**: Implement appropriate auth strategy
5. **Localize Error Messages**: Customize error responses for your application  
**API Version**: [API_VERSION]  
**Contact**: [CONTACT_EMAIL]

---

*This template provides comprehensive API documentation structure. Customize all bracketed placeholders with your API-specific information and adapt the structure to match your API's specific requirements and conventions.*
