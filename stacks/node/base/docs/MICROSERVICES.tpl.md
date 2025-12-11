# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: node template utilities
# Tier: base
# Stack: node
# Category: template

# Node.js Microservices Patterns

## Purpose
Comprehensive guide to building microservices with Node.js, including service architecture, communication patterns, and deployment strategies.

## Microservice Architecture

### 1. Basic Microservice Structure
```javascript
// src/app.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

class UserService {
  constructor() {
    this.app = express();
    this.port = process.env.PORT || 3001;
    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandling();
  }
  
  setupMiddleware() {
    // Security middleware
    this.app.use(helmet());
    this.app.use(cors({
      origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
      credentials: true
    }));
    
    // Performance middleware
    this.app.use(compression());
    
    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP'
    });
    this.app.use('/api/', limiter);
    
    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));
    
    // Request logging
    this.app.use((req, res, next) => {
      console.log(`${req.method} ${req.path} - ${new Date().toISOString()}`);
      next();
    });
  }
  
  setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        service: 'user-service',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0'
      });
    });
    
    // API routes
    this.app.use('/api/users', require('./routes/users'));
    this.app.use('/api/auth', require('./routes/auth'));
    
    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Not Found',
        message: `Route ${req.originalUrl} not found`
      });
    });
  }
  
  setupErrorHandling() {
    // Global error handler
    this.app.use((err, req, res, next) => {
      console.error('Error:', err);
      
      // Don't leak error details in production
      const isDevelopment = process.env.NODE_ENV === 'development';
      
      res.status(err.status || 500).json({
        error: err.name || 'Internal Server Error',
        message: isDevelopment ? err.message : 'Something went wrong',
        ...(isDevelopment && { stack: err.stack })
      });
    });
    
    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled Rejection at:', promise, 'reason:', reason);
      // Graceful shutdown
      this.gracefulShutdown();
    });
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (err) => {
      console.error('Uncaught Exception:', err);
      // Graceful shutdown
      this.gracefulShutdown();
    });
  }
  
  start() {
    this.server = this.app.listen(this.port, () => {
      console.log(`User service running on port ${this.port}`);
    });
    
    // Graceful shutdown
    process.on('SIGTERM', () => this.gracefulShutdown());
    process.on('SIGINT', () => this.gracefulShutdown());
  }
  
  gracefulShutdown() {
    console.log('Starting graceful shutdown...');
    
    if (this.server) {
      this.server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
      });
    }
    
    // Force close after 30 seconds
    setTimeout(() => {
      console.error('Could not close connections in time, forcefully shutting down');
      process.exit(1);
    }, 30000);
  }
}

module.exports = UserService;

// Start service if run directly
if (require.main === module) {
  const service = new UserService();
  service.start();
}
```

### 2. Service Discovery and Registration
```javascript
// src/serviceRegistry.js
const consul = require('consul')({
  host: process.env.CONSUL_HOST || 'localhost',
  port: process.env.CONSUL_PORT || 8500
});

class ServiceRegistry {
  constructor(serviceName, serviceId, port) {
    this.serviceName = serviceName;
    this.serviceId = serviceId;
    this.port = port;
    this.consul = consul;
    this.healthCheckInterval = 10000; // 10 seconds
  }
  
  async register() {
    const serviceDetails = {
      name: this.serviceName,
      id: this.serviceId,
      address: this.getServiceAddress(),
      port: this.port,
      check: {
        http: `http://${this.getServiceAddress()}:${this.port}/health`,
        interval: `${this.healthCheckInterval}ms`,
        timeout: '5s',
        deregistercriticalserviceafter: '30s'
      },
      tags: this.getServiceTags()
    };
    
    try {
      await this.consul.agent.service.register(serviceDetails);
      console.log(`Service ${this.serviceName} registered with Consul`);
      
      // Start health check
      this.startHealthCheck();
      
    } catch (error) {
      console.error('Failed to register service:', error);
      throw error;
    }
  }
  
  async deregister() {
    try {
      await this.consul.agent.service.deregister(this.serviceId);
      console.log(`Service ${this.serviceName} deregistered from Consul`);
    } catch (error) {
      console.error('Failed to deregister service:', error);
    }
  }
  
  async discoverServices(serviceName) {
    try {
      const services = await this.consul.health.service({
        service: serviceName,
        passing: true
      });
      
      return services.map(service => ({
        id: service.Service.ID,
        address: service.Service.Address,
        port: service.Service.Port,
        tags: service.Service.Tags
      }));
    } catch (error) {
      console.error(`Failed to discover ${serviceName} services:`, error);
      return [];
    }
  }
  
  getServiceAddress() {
    return process.env.SERVICE_HOST || 'localhost';
  }
  
  getServiceTags() {
    return (process.env.SERVICE_TAGS || '').split(',').filter(tag => tag.trim());
  }
  
  startHealthCheck() {
    setInterval(async () => {
      try {
        const response = await fetch(`http://${this.getServiceAddress()}:${this.port}/health`);
        if (!response.ok) {
          console.warn('Health check failed');
        }
      } catch (error) {
        console.error('Health check error:', error);
      }
    }, this.healthCheckInterval);
  }
}

module.exports = ServiceRegistry;

// Usage in main service
const ServiceRegistry = require('./serviceRegistry');

const serviceRegistry = new ServiceRegistry(
  'user-service',
  `user-service-${process.env.INSTANCE_ID || Date.now()}`,
  port
);

// Register on startup
await serviceRegistry.register();

// Deregister on shutdown
process.on('SIGTERM', async () => {
  await serviceRegistry.deregister();
  process.exit(0);
});
```

## Inter-Service Communication

### 1. HTTP Client with Circuit Breaker
```javascript
// src/httpClient.js
const axios = require('axios');
const CircuitBreaker = require('opossum');

class ServiceClient {
  constructor(serviceName, options = {}) {
    this.serviceName = serviceName;
    this.serviceRegistry = options.serviceRegistry;
    this.circuitBreakerOptions = options.circuitBreaker || {
      timeout: 3000, // 3 seconds
      errorThresholdPercentage: 50,
      resetTimeout: 30000 // 30 seconds
    };
    
    this.httpClient = axios.create({
      timeout: options.timeout || 5000,
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': this.generateRequestId()
      }
    });
    
    this.setupCircuitBreaker();
    this.setupInterceptors();
  }
  
  async getServiceUrl() {
    if (this.serviceRegistry) {
      const services = await this.serviceRegistry.discoverServices(this.serviceName);
      if (services.length === 0) {
        throw new Error(`No healthy ${this.serviceName} instances found`);
      }
      
      // Load balancing - round robin
      const service = services[Math.floor(Math.random() * services.length)];
      return `http://${service.address}:${service.port}`;
    }
    
    // Fallback to environment variable
    return process.env[`${this.serviceName.toUpperCase()}_URL`];
  }
  
  setupCircuitBreaker() {
    this.circuitBreaker = new CircuitBreaker(
      async (url, config) => {
        const response = await this.httpClient.get(url, config);
        return response.data;
      },
      this.circuitBreakerOptions
    );
    
    this.circuitBreaker.on('open', () => {
      console.warn(`Circuit breaker opened for ${this.serviceName}`);
    });
    
    this.circuitBreaker.on('halfOpen', () => {
      console.info(`Circuit breaker half-open for ${this.serviceName}`);
    });
    
    this.circuitBreaker.on('close', () => {
      console.info(`Circuit breaker closed for ${this.serviceName}`);
    });
  }
  
  setupInterceptors() {
    // Request interceptor
    this.httpClient.interceptors.request.use(
      (config) => {
        config.headers['X-Request-ID'] = this.generateRequestId();
        config.metadata = { startTime: Date.now() };
        return config;
      },
      (error) => Promise.reject(error)
    );
    
    // Response interceptor
    this.httpClient.interceptors.response.use(
      (response) => {
        const duration = Date.now() - response.config.metadata.startTime;
        console.log(`${this.serviceName} request completed in ${duration}ms`);
        return response;
      },
      (error) => {
        if (error.config) {
          const duration = Date.now() - error.config.metadata.startTime;
          console.error(`${this.serviceName} request failed after ${duration}ms:`, error.message);
        }
        return Promise.reject(error);
      }
    );
  }
  
  async get(endpoint, config = {}) {
    try {
      const baseUrl = await this.getServiceUrl();
      const url = `${baseUrl}${endpoint}`;
      
      return await this.circuitBreaker.fire(url, config);
    } catch (error) {
      console.error(`Failed to call ${this.serviceName}${endpoint}:`, error.message);
      throw error;
    }
  }
  
  async post(endpoint, data, config = {}) {
    try {
      const baseUrl = await this.getServiceUrl();
      const url = `${baseUrl}${endpoint}`;
      
      const response = await this.httpClient.post(url, data, config);
      return response.data;
    } catch (error) {
      console.error(`Failed to call ${this.serviceName}${endpoint}:`, error.message);
      throw error;
    }
  }
  
  generateRequestId() {
    return `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

module.exports = ServiceClient;

// Usage example
const orderServiceClient = new ServiceClient('order-service', {
  serviceRegistry: serviceRegistry,
  circuitBreaker: {
    timeout: 5000,
    errorThresholdPercentage: 50,
    resetTimeout: 30000
  }
});

// Make service call
try {
  const orders = await orderServiceClient.get('/api/orders/user/123');
  console.log('User orders:', orders);
} catch (error) {
  console.error('Failed to fetch orders:', error);
}
```

### 2. Message Queue Communication
```javascript
// src/messageBroker.js
const amqp = require('amqplib');

class MessageBroker {
  constructor(options = {}) {
    this.url = options.url || process.env.RABBITMQ_URL || 'amqp://localhost:5672';
    this.connection = null;
    this.channel = null;
    this.exchanges = new Map();
    this.queues = new Map();
  }
  
  async connect() {
    try {
      this.connection = await amqp.connect(this.url);
      this.channel = await this.connection.createChannel();
      
      // Handle connection errors
      this.connection.on('error', (err) => {
        console.error('RabbitMQ connection error:', err);
      });
      
      this.connection.on('close', () => {
        console.warn('RabbitMQ connection closed');
        // Attempt reconnection
        setTimeout(() => this.connect(), 5000);
      });
      
      console.log('Connected to RabbitMQ');
    } catch (error) {
      console.error('Failed to connect to RabbitMQ:', error);
      throw error;
    }
  }
  
  async declareExchange(name, type = 'topic', options = {}) {
    try {
      await this.channel.assertExchange(name, type, { durable: true, ...options });
      this.exchanges.set(name, { name, type, options });
      console.log(`Exchange ${name} declared`);
    } catch (error) {
      console.error(`Failed to declare exchange ${name}:`, error);
      throw error;
    }
  }
  
  async declareQueue(name, options = {}) {
    try {
      const queue = await this.channel.assertQueue(name, { durable: true, ...options });
      this.queues.set(name, queue);
      console.log(`Queue ${name} declared`);
      return queue;
    } catch (error) {
      console.error(`Failed to declare queue ${name}:`, error);
      throw error;
    }
  }
  
  async publish(exchangeName, routingKey, message, options = {}) {
    try {
      const messageBuffer = Buffer.from(JSON.stringify(message));
      const published = this.channel.publish(
        exchangeName,
        routingKey,
        messageBuffer,
        { persistent: true, ...options }
      );
      
      if (published) {
        console.log(`Message published to ${exchangeName} with routing key ${routingKey}`);
      } else {
        console.warn('Failed to publish message - channel full');
      }
      
      return published;
    } catch (error) {
      console.error('Failed to publish message:', error);
      throw error;
    }
  }
  
  async subscribe(queueName, handler, options = {}) {
    try {
      await this.channel.consume(queueName, async (msg) => {
        if (msg === null) {
          console.log('Consumer cancelled by server');
          return;
        }
        
        try {
          const message = JSON.parse(msg.content.toString());
          
          // Handle message
          await handler(message, msg);
          
          // Acknowledge message
          this.channel.ack(msg);
          
        } catch (error) {
          console.error('Error processing message:', error);
          
          // Reject message (with requeue option)
          this.channel.nack(msg, false, options.requeue !== false);
        }
      });
      
      console.log(`Subscribed to queue ${queueName}`);
    } catch (error) {
      console.error(`Failed to subscribe to queue ${queueName}:`, error);
      throw error;
    }
  }
  
  async disconnect() {
    try {
      if (this.channel) {
        await this.channel.close();
      }
      if (this.connection) {
        await this.connection.close();
      }
      console.log('Disconnected from RabbitMQ');
    } catch (error) {
      console.error('Error disconnecting from RabbitMQ:', error);
    }
  }
}

// Event publisher
class EventPublisher {
  constructor(messageBroker) {
    this.broker = messageBroker;
  }
  
  async publishUserCreated(user) {
    await this.broker.publish(
      'user.events',
      'user.created',
      {
        eventType: 'user.created',
        eventId: this.generateEventId(),
        timestamp: new Date().toISOString(),
        data: {
          userId: user.id,
          email: user.email,
          role: user.role
        }
      }
    );
  }
  
  async publishUserUpdated(userId, changes) {
    await this.broker.publish(
      'user.events',
      'user.updated',
      {
        eventType: 'user.updated',
        eventId: this.generateEventId(),
        timestamp: new Date().toISOString(),
        data: {
          userId,
          changes
        }
      }
    );
  }
  
  generateEventId() {
    return `evt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Usage example
const messageBroker = new MessageBroker();
await messageBroker.connect();

// Declare exchange
await messageBroker.declareExchange('user.events', 'topic');

// Declare queue for this service
await messageBroker.declareQueue('user-service-events');

// Bind queue to exchange
await messageBroker.channel.bindQueue('user-service-events', 'user.events', 'user.*');

// Subscribe to events
await messageBroker.subscribe('user-service-events', async (message) => {
  console.log('Received user event:', message);
  
  switch (message.eventType) {
    case 'order.created':
      // Handle order creation event
      await handleOrderCreated(message.data);
      break;
    case 'payment.completed':
      // Handle payment completion event
      await handlePaymentCompleted(message.data);
      break;
  }
});

// Publish events
const eventPublisher = new EventPublisher(messageBroker);
await eventPublisher.publishUserCreated(newUser);
```

## Data Management

### 1. Database per Service Pattern
```javascript
// src/database.js
const mongoose = require('mongoose');
const { MongoClient } = require('mongodb');

class DatabaseManager {
  constructor(config) {
    this.config = config;
    this.connections = new Map();
  }
  
  async connectMongoDB(name, url) {
    try {
      const client = new MongoClient(url, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      });
      
      await client.connect();
      const db = client.db();
      
      this.connections.set(name, { client, db, type: 'mongodb' });
      console.log(`Connected to MongoDB database: ${name}`);
      
      return db;
    } catch (error) {
      console.error(`Failed to connect to MongoDB ${name}:`, error);
      throw error;
    }
  }
  
  async connectMongoose(name, url) {
    try {
      await mongoose.connect(url, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      });
      
      this.connections.set(name, { connection: mongoose, type: 'mongoose' });
      console.log(`Connected to Mongoose database: ${name}`);
      
      return mongoose;
    } catch (error) {
      console.error(`Failed to connect to Mongoose ${name}:`, error);
      throw error;
    }
  }
  
  async getConnection(name) {
    const connection = this.connections.get(name);
    if (!connection) {
      throw new Error(`Database connection ${name} not found`);
    }
    return connection;
  }
  
  async disconnect(name) {
    const connection = this.connections.get(name);
    if (!connection) {
      return;
    }
    
    try {
      if (connection.type === 'mongodb') {
        await connection.client.close();
      } else if (connection.type === 'mongoose') {
        await connection.connection.disconnect();
      }
      
      this.connections.delete(name);
      console.log(`Disconnected from database: ${name}`);
    } catch (error) {
      console.error(`Error disconnecting from ${name}:`, error);
    }
  }
  
  async disconnectAll() {
    const disconnectPromises = Array.from(this.connections.keys())
      .map(name => this.disconnect(name));
    
    await Promise.all(disconnectPromises);
  }
}

// Database configuration
const dbConfig = {
  userDb: {
    type: 'mongoose',
    url: process.env.USER_DB_URL || 'mongodb://localhost:27017/user-service'
  },
  cacheDb: {
    type: 'mongodb',
    url: process.env.CACHE_DB_URL || 'mongodb://localhost:27017/user-cache'
  }
};

// Initialize database manager
const dbManager = new DatabaseManager();

// Connect to databases
await dbManager.connectMongoose('userDb', dbConfig.userDb.url);
await dbManager.connectMongoDB('cacheDb', dbConfig.cacheDb.url);
```

### 2. Event Sourcing Pattern
```javascript
// src/eventStore.js
class EventStore {
  constructor(database) {
    this.db = database;
    this.events = this.db.collection('events');
  }
  
  async saveEvent(aggregateId, eventType, eventData, version) {
    const event = {
      _id: this.generateEventId(),
      aggregateId,
      eventType,
      eventData,
      version,
      timestamp: new Date(),
      metadata: {
        correlationId: this.generateCorrelationId(),
        causationId: null
      }
    };
    
    try {
      await this.events.insertOne(event);
      console.log(`Event saved: ${eventType} for aggregate ${aggregateId}`);
      return event;
    } catch (error) {
      console.error('Failed to save event:', error);
      throw error;
    }
  }
  
  async getEvents(aggregateId, fromVersion = 0) {
    try {
      const events = await this.events
        .find({ aggregateId, version: { $gt: fromVersion } })
        .sort({ version: 1 })
        .toArray();
      
      return events;
    } catch (error) {
      console.error('Failed to get events:', error);
      throw error;
    }
  }
  
  async getEventsByType(eventType, fromTimestamp = null) {
    try {
      const query = { eventType };
      if (fromTimestamp) {
        query.timestamp = { $gte: fromTimestamp };
      }
      
      const events = await this.events
        .find(query)
        .sort({ timestamp: 1 })
        .toArray();
      
      return events;
    } catch (error) {
      console.error('Failed to get events by type:', error);
      throw error;
    }
  }
  
  generateEventId() {
    return `evt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  
  generateCorrelationId() {
    return `corr-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Aggregate base class
class Aggregate {
  constructor(id) {
    this.id = id;
    this.version = 0;
    this.uncommittedEvents = [];
  }
  
  applyEvent(event) {
    // Apply event to aggregate state
    this.when(event);
    this.version++;
  }
  
  addEvent(eventType, eventData) {
    const event = {
      aggregateId: this.id,
      eventType,
      eventData,
      version: this.version + 1
    };
    
    this.applyEvent(event);
    this.uncommittedEvents.push(event);
  }
  
  async save(eventStore) {
    for (const event of this.uncommittedEvents) {
      await eventStore.saveEvent(event.aggregateId, event.eventType, event.eventData, event.version);
    }
    
    this.uncommittedEvents = [];
  }
  
  static async fromHistory(eventStore, aggregateId) {
    const aggregate = new this(aggregateId);
    const events = await eventStore.getEvents(aggregateId);
    
    for (const event of events) {
      aggregate.applyEvent(event);
    }
    
    return aggregate;
  }
}

// User aggregate
class User extends Aggregate {
  constructor(id) {
    super(id);
    this.email = null;
    this.name = null;
    this.active = false;
  }
  
  when(event) {
    switch (event.eventType) {
      case 'user.created':
        this.email = event.eventData.email;
        this.name = event.eventData.name;
        this.active = true;
        break;
      case 'user.email.changed':
        this.email = event.eventData.newEmail;
        break;
      case 'user.deactivated':
        this.active = false;
        break;
    }
  }
  
  create(email, name) {
    this.addEvent('user.created', { email, name });
  }
  
  changeEmail(newEmail) {
    if (this.email !== newEmail) {
      this.addEvent('user.email.changed', { oldEmail: this.email, newEmail });
    }
  }
  
  deactivate() {
    if (this.active) {
      this.addEvent('user.deactivated', {});
    }
  }
}

// Usage example
const eventStore = new EventStore(database);

// Create new user
const user = new User('user-123');
user.create('john@example.com', 'John Doe');
await user.save(eventStore);

// Load user from history
const loadedUser = await User.fromHistory(eventStore, 'user-123');
console.log('Loaded user:', loadedUser);
```

## API Gateway Pattern

### 1. Simple API Gateway
```javascript
// gateway/index.js
const express = require('express');
const httpProxy = require('http-proxy-middleware');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

class APIGateway {
  constructor() {
    this.app = express();
    this.port = process.env.GATEWAY_PORT || 3000;
    this.services = new Map();
    this.setupMiddleware();
    this.setupRoutes();
  }
  
  setupMiddleware() {
    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 1000 // limit each IP to 1000 requests per windowMs
    });
    this.app.use(limiter);
    
    // JWT authentication
    this.app.use('/api', this.authenticate.bind(this));
    
    // Request logging
    this.app.use((req, res, next) => {
      console.log(`${req.method} ${req.path} - ${new Date().toISOString()}`);
      next();
    });
  }
  
  setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        service: 'api-gateway',
        timestamp: new Date().toISOString()
      });
    });
    
    // Proxy to user service
    this.app.use('/api/users', this.createProxy('user-service', {
      target: process.env.USER_SERVICE_URL || 'http://localhost:3001',
      changeOrigin: true,
      pathRewrite: {
        '^/api/users': '/api/users'
      }
    }));
    
    // Proxy to order service
    this.app.use('/api/orders', this.createProxy('order-service', {
      target: process.env.ORDER_SERVICE_URL || 'http://localhost:3002',
      changeOrigin: true,
      pathRewrite: {
        '^/api/orders': '/api/orders'
      }
    }));
    
    // Proxy to product service
    this.app.use('/api/products', this.createProxy('product-service', {
      target: process.env.PRODUCT_SERVICE_URL || 'http://localhost:3003',
      changeOrigin: true,
      pathRewrite: {
        '^/api/products': '/api/products'
      }
    }));
  }
  
  createProxy(serviceName, options) {
    const proxy = httpProxy.createProxyMiddleware(options);
    
    return (req, res, next) => {
      // Add service context to request
      req.serviceName = serviceName;
      
      // Add correlation ID
      req.headers['x-correlation-id'] = req.headers['x-correlation-id'] || 
        this.generateCorrelationId();
      
      proxy(req, res, (err) => {
        if (err) {
          console.error(`Proxy error for ${serviceName}:`, err);
          res.status(502).json({
            error: 'Bad Gateway',
            message: `Service ${serviceName} is unavailable`
          });
        } else {
          next(err);
        }
      });
    };
  }
  
  authenticate(req, res, next) {
    // Skip authentication for certain paths
    const publicPaths = ['/health', '/api/auth/login', '/api/auth/register'];
    if (publicPaths.some(path => req.path.startsWith(path))) {
      return next();
    }
    
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'No token provided'
      });
    }
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
    } catch (error) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid token'
      });
    }
  }
  
  generateCorrelationId() {
    return `corr-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  
  start() {
    this.app.listen(this.port, () => {
      console.log(`API Gateway running on port ${this.port}`);
    });
  }
}

// Start gateway
const gateway = new APIGateway();
gateway.start();
```

## Testing Microservices

### 1. Integration Testing with Test Containers
```javascript
// tests/integration/userService.test.js
const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const UserService = require('../../src/app');

describe('User Service Integration Tests', () => {
  let app;
  let mongoServer;
  
  beforeAll(async () => {
    // Start in-memory MongoDB
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    // Connect to test database
    await mongoose.connect(mongoUri);
    
    // Start service
    app = new UserService();
    app.start();
  });
  
  afterAll(async () => {
    // Cleanup
    if (app) {
      await app.gracefulShutdown();
    }
    if (mongoose.connection) {
      await mongoose.connection.close();
    }
    if (mongoServer) {
      await mongoServer.stop();
    }
  });
  
  beforeEach(async () => {
    // Clear database before each test
    const collections = mongoose.connection.collections;
    for (const key in collections) {
      await collections[key].deleteMany({});
    }
  });
  
  describe('POST /api/users', () => {
    it('should create a new user', async () => {
      const userData = {
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123'
      };
      
      const response = await request(app.app)
        .post('/api/users')
        .send(userData)
        .expect(201);
      
      expect(response.body).toMatchObject({
        email: userData.email,
        name: userData.name
      });
      expect(response.body).not.toHaveProperty('password');
    });
    
    it('should return validation error for invalid data', async () => {
      const invalidData = {
        email: 'invalid-email',
        name: ''
      };
      
      const response = await request(app.app)
        .post('/api/users')
        .send(invalidData)
        .expect(400);
      
      expect(response.body).toHaveProperty('error');
    });
  });
  
  describe('GET /api/users/:id', () => {
    it('should return user by ID', async () => {
      // Create user first
      const createResponse = await request(app.app)
        .post('/api/users')
        .send({
          email: 'test@example.com',
          name: 'Test User',
          password: 'password123'
        });
      
      const userId = createResponse.body.id;
      
      // Get user
      const response = await request(app.app)
        .get(`/api/users/${userId}`)
        .expect(200);
      
      expect(response.body).toMatchObject({
        id: userId,
        email: 'test@example.com',
        name: 'Test User'
      });
    });
    
    it('should return 404 for non-existent user', async () => {
      const response = await request(app.app)
        .get('/api/users/non-existent-id')
        .expect(404);
      
      expect(response.body).toHaveProperty('error');
    });
  });
});
```

## Deployment and Monitoring

### 1. Docker Compose for Microservices
```yaml
# docker-compose.yml
version: '3.8'

services:
  # API Gateway
  api-gateway:
    build: ./gateway
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - USER_SERVICE_URL=http://user-service:3001
      - ORDER_SERVICE_URL=http://order-service:3002
      - PRODUCT_SERVICE_URL=http://product-service:3003
      - JWT_SECRET=${JWT_SECRET}
    depends_on:
      - user-service
      - order-service
      - product-service
    networks:
      - microservices

  # User Service
  user-service:
    build: ./services/user
    ports:
      - "3001:3001"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=mongodb://mongodb:27017/user-service
      - REDIS_URL=redis://redis:6379
      - RABBITMQ_URL=amqp://rabbitmq:5672
    depends_on:
      - mongodb
      - redis
      - rabbitmq
    networks:
      - microservices

  # Order Service
  order-service:
    build: ./services/order
    ports:
      - "3002:3002"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=mongodb://mongodb:27017/order-service
      - REDIS_URL=redis://redis:6379
      - RABBITMQ_URL=amqp://rabbitmq:5672
    depends_on:
      - mongodb
      - redis
      - rabbitmq
    networks:
      - microservices

  # Product Service
  product-service:
    build: ./services/product
    ports:
      - "3003:3003"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=mongodb://mongodb:27017/product-service
      - REDIS_URL=redis://redis:6379
    depends_on:
      - mongodb
      - redis
    networks:
      - microservices

  # Infrastructure Services
  mongodb:
    image: mongo:5.0
    ports:
      - "27017:27017"
    volumes:
      - mongodb_data:/data/db
    networks:
      - microservices

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - microservices

  rabbitmq:
    image: rabbitmq:3-management
    ports:
      - "5672:5672"
      - "15672:15672"
    environment:
      - RABBITMQ_DEFAULT_USER=admin
      - RABBITMQ_DEFAULT_PASS=password
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq
    networks:
      - microservices

  # Monitoring
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
    networks:
      - microservices

  grafana:
    image: grafana/grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana
    networks:
      - microservices

volumes:
  mongodb_data:
  redis_data:
  rabbitmq_data:
  grafana_data:

networks:
  microservices:
    driver: bridge
```

### 2. Health Check and Monitoring
```javascript
// src/healthCheck.js
const prometheus = require('prom-client');

class HealthChecker {
  constructor() {
    this.checks = new Map();
    this.metrics = this.setupMetrics();
  }
  
  setupMetrics() {
    const register = new prometheus.Registry();
    
    // Default metrics
    prometheus.collectDefaultMetrics({ register });
    
    // Custom metrics
    const httpRequestDuration = new prometheus.Histogram({
      name: 'http_request_duration_seconds',
      help: 'Duration of HTTP requests in seconds',
      labelNames: ['method', 'route', 'status_code']
    });
    
    const activeConnections = new prometheus.Gauge({
      name: 'active_connections',
      help: 'Number of active connections'
    });
    
    register.registerMetric(httpRequestDuration);
    register.registerMetric(activeConnections);
    
    return {
      register,
      httpRequestDuration,
      activeConnections
    };
  }
  
  addCheck(name, checkFunction) {
    this.checks.set(name, checkFunction);
  }
  
  async runChecks() {
    const results = {};
    
    for (const [name, checkFunction] of this.checks) {
      try {
        const result = await checkFunction();
        results[name] = {
          status: 'healthy',
          ...result
        };
      } catch (error) {
        results[name] = {
          status: 'unhealthy',
          error: error.message
        };
      }
    }
    
    return results;
  }
  
  async getHealthStatus() {
    const checks = await this.runChecks();
    const allHealthy = Object.values(checks).every(check => check.status === 'healthy');
    
    return {
      status: allHealthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString(),
      checks
    };
  }
  
  getMetrics() {
    return this.metrics.register.metrics();
  }
}

// Usage in service
const healthChecker = new HealthChecker();

// Add health checks
healthChecker.addCheck('database', async () => {
  const db = await dbManager.getConnection('userDb');
  await db.connection.db.admin().ping();
  return { message: 'Database connection successful' };
});

healthChecker.addCheck('redis', async () => {
  const redis = require('./redis');
  await redis.ping();
  return { message: 'Redis connection successful' };
});

healthChecker.addCheck('rabbitmq', async () => {
  const messageBroker = require('./messageBroker');
  await messageBroker.channel.checkQueue('health-check');
  return { message: 'RabbitMQ connection successful' });
});

// Add health check endpoint
app.get('/health', async (req, res) => {
  const health = await healthChecker.getHealthStatus();
  const statusCode = health.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(health);
});

// Add metrics endpoint
app.get('/metrics', (req, res) => {
  res.set('Content-Type', prometheus.register.contentType);
  res.end(healthChecker.getMetrics());
});
```

This comprehensive microservices guide covers the essential patterns and practices for building scalable, maintainable Node.js microservices including service discovery, inter-service communication, data management, API gateway, testing, and monitoring.
