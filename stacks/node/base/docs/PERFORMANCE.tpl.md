# Universal Template System - Node Stack
# Generated: 2025-12-10
# Purpose: node template utilities
# Tier: base
# Stack: node
# Category: template

# Performance Optimization Guide - Node.js

This guide covers performance optimization techniques, profiling tools, and best practices for Node.js applications.

## 🚀 Node.js Performance Overview

Node.js provides excellent performance for I/O-bound applications through its event-driven, non-blocking I/O model. This guide covers event loop optimization, memory management, and performance strategies.

## 📊 Performance Metrics

### Key Performance Indicators
- **Response Time**: Time to process requests
- **Throughput**: Requests per second (RPS)
- **CPU Usage**: Processor utilization percentage
- **Memory Usage**: Heap and RSS memory consumption
- **Event Loop Lag**: Delay in event loop processing

### Performance Targets
```javascript
// Target performance metrics
const TARGET_RESPONSE_TIME_MS = 100;
const TARGET_THROUGHPUT_RPS = 1000;
const TARGET_CPU_PERCENTAGE = 70;
const TARGET_MEMORY_USAGE_MB = 512;
const TARGET_EVENT_LOOP_LAG_MS = 10;
```

## 🔍 Performance Profiling Tools

### Built-in Node.js Profiler
```javascript
// Built-in V8 profiler
// Run with profiling
node --prof app.js
node --prof-process isolate-*.log > processed.txt

// Heap profiling
node --heap-prof app.js
node --heap-prof-process *.heapprofile > heap-analysis.txt

// CPU profiling
node --cpu-prof app.js
node --cpu-prof-process *.cpuprofile > cpu-analysis.txt
```

### Chrome DevTools Integration
```javascript
// Enable inspector for debugging
node --inspect app.js
node --inspect-brk app.js  # Break on start

// In Chrome: chrome://inspect
// Connect to Node.js process for profiling
```

### Clinic.js - Comprehensive Performance Suite
```bash
# Install Clinic.js
npm install -g clinic

# CPU profiling
clinic doctor -- node app.js

# Event loop analysis
clinic bubbleprof -- node app.js

# Flame graph generation
clinic flame -- node app.js

# Heap profiling
clinic heapprofiler -- node app.js
```

### Custom Performance Monitoring
```javascript
const performance = require('perf_hooks');

class PerformanceMonitor {
  constructor() {
    this.metrics = new Map();
  }

  startTimer(name) {
    this.metrics.set(name, performance.now());
  }

  endTimer(name) {
    const startTime = this.metrics.get(name);
    if (startTime) {
      const duration = performance.now() - startTime;
      console.log(`${name}: ${duration.toFixed(2)}ms`);
      return duration;
    }
  }

  measureFunction(name, fn) {
    return (...args) => {
      this.startTimer(name);
      const result = fn(...args);
      this.endTimer(name);
      return result;
    };
  }
}

// Usage
const monitor = new PerformanceMonitor();

const wrappedFunction = monitor.measureFunction('expensive-operation', (data) => {
  // Expensive operation
  return processData(data);
});
```

## ⚡ Event Loop Optimization

### Event Loop Monitoring
```javascript
// BAD: Blocking event loop
function blockingOperation() {
  const start = Date.now();
  while (Date.now() - start < 1000) {
    // CPU-intensive blocking operation
    Math.sqrt(Math.random() * 1000000);
  }
}

// GOOD: Non-blocking with setImmediate
function nonBlockingOperation(data, callback) {
  setImmediate(() => {
    // Process in next tick
    const result = processData(data);
    callback(result);
  });
}

// BETTER: Using process.nextTick for high priority
function highPriorityOperation(data, callback) {
  process.nextTick(() => {
    const result = processData(data);
    callback(result);
  });
}
```

### Event Loop Lag Measurement
```javascript
// Monitor event loop lag
function measureEventLoopLag() {
  let lastTime = process.hrtime.bigint();
  
  setInterval(() => {
    const currentTime = process.hrtime.bigint();
    const lag = Number(currentTime - lastTime) / 1000000; // Convert to ms
    
    if (lag > 10) { // Alert if lag > 10ms
      console.warn(`Event loop lag: ${lag.toFixed(2)}ms`);
    }
    
    lastTime = currentTime;
  }, 1000);
}

measureEventLoopLag();
```

### Asynchronous Operations Optimization

#### Before: Callback Hell
```javascript
// BAD: Nested callbacks
function fetchDataBad(callback) {
  fetchUser((user) => {
    fetchPosts(user.id, (posts) => {
      fetchComments(posts[0].id, (comments) => {
        callback({ user, posts, comments });
      });
    });
  });
}
```

#### After: Async/Await
```javascript
// GOOD: Async/await pattern
async function fetchDataGood() {
  try {
    const user = await fetchUser();
    const posts = await fetchPosts(user.id);
    const comments = await fetchComments(posts[0].id);
    
    return { user, posts, comments };
  } catch (error) {
    console.error('Error fetching data:', error);
    throw error;
  }
}

// BETTER: Parallel execution with Promise.all
async function fetchDataParallel() {
  try {
    const [user, posts, comments] = await Promise.all([
      fetchUser(),
      fetchPosts(),
      fetchComments()
    ]);
    
    return { user, posts, comments };
  } catch (error) {
    console.error('Error fetching data:', error);
    throw error;
  }
}
```

## 💾 Memory Management

### Memory Leak Detection
```javascript
// Memory monitoring
const memoryUsage = () => {
  const used = process.memoryUsage();
  const format = (bytes) => `${Math.round(bytes / 1024 / 1024 * 100) / 100} MB`;
  
  console.log('Memory Usage:');
  console.log(`RSS: ${format(used.rss)}`);
  console.log(`Heap Total: ${format(used.heapTotal)}`);
  console.log(`Heap Used: ${format(used.heapUsed)}`);
  console.log(`External: ${format(used.external)}`);
};

// Monitor memory every 30 seconds
setInterval(memoryUsage, 30000);
```

### Efficient Memory Usage

#### Before: Memory Leaks
```javascript
// BAD: Memory leak with event listeners
class EventEmitterBad {
  constructor() {
    this.listeners = [];
  }
  
  on(event, callback) {
    this.listeners.push({ event, callback });
  }
  
  emit(event, data) {
    this.listeners
      .filter(l => l.event === event)
      .forEach(l => l.callback(data));
  }
}

// Memory leak - listeners never removed
const emitter = new EventEmitterBad();
setInterval(() => {
  emitter.on('data', () => {}); // Adds listener but never removes
}, 1000);
```

#### After: Proper Memory Management
```javascript
// GOOD: Proper event listener management
const EventEmitter = require('events');

class ManagedEmitter extends EventEmitter {
  constructor() {
    super();
    this.setMaxListeners(100); // Prevent memory leak warnings
  }
  
  // Auto-cleanup method
  onWithTimeout(event, callback, timeout = 30000) {
    const wrappedCallback = (...args) => {
      callback(...args);
      this.off(event, wrappedCallback); // Auto-remove after execution
    };
    
    this.on(event, wrappedCallback);
    
    // Auto-remove after timeout
    setTimeout(() => {
      this.off(event, wrappedCallback);
    }, timeout);
    
    return wrappedCallback;
  }
}

// Usage with proper cleanup
const emitter = new ManagedEmitter();

const cleanup = () => {
  emitter.removeAllListeners();
  process.exit();
};

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);
```

### Stream Optimization
```javascript
// BAD: Loading entire file into memory
const fs = require('fs');

function processLargeFileBad(filePath) {
  const data = fs.readFileSync(filePath, 'utf8'); // Loads entire file
  const lines = data.split('\n');
  
  return lines.map(line => line.trim()).filter(line => line.length > 0);
}

// GOOD: Streaming file processing
const stream = require('stream');

function processLargeFileGood(filePath) {
  return new Promise((resolve, reject) => {
    const results = [];
    const readStream = fs.createReadStream(filePath, { encoding: 'utf8' });
    
    readStream.on('data', (chunk) => {
      const lines = chunk.split('\n');
      const processedLines = lines
        .map(line => line.trim())
        .filter(line => line.length > 0);
      
      results.push(...processedLines);
    });
    
    readStream.on('end', () => {
      resolve(results);
    });
    
    readStream.on('error', reject);
  });
}

// BETTER: Transform stream for memory efficiency
class LineProcessor extends stream.Transform {
  constructor() {
    super({ objectMode: true });
  }
  
  _transform(chunk, encoding, callback) {
    const lines = chunk.split('\n');
    const processedLines = lines
      .map(line => line.trim())
      .filter(line => line.length > 0);
    
    processedLines.forEach(line => this.push(line));
    callback();
  }
}

function processWithTransform(filePath) {
  return new Promise((resolve, reject) => {
    const results = [];
    const readStream = fs.createReadStream(filePath, { encoding: 'utf8' });
    const processor = new LineProcessor();
    
    processor.on('data', (line) => {
      results.push(line);
    });
    
    processor.on('end', () => {
      resolve(results);
    });
    
    processor.on('error', reject);
    
    readStream.pipe(processor);
  });
}
```

## 🔄 Concurrency Optimization

### Worker Threads for CPU-Intensive Tasks
```javascript
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

// Main thread
function runWorkerTask(data) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, {
      workerData: data
    });
    
    worker.on('message', resolve);
    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`Worker stopped with exit code ${code}`));
      }
    });
  });
}

// Worker thread
if (!isMainThread) {
  const result = heavyComputation(workerData);
  parentPort.postMessage(result);
}

// Usage
async function processWithWorkers(items) {
  const workers = [];
  
  for (const item of items) {
    workers.push(runWorkerTask(item));
  }
  
  const results = await Promise.all(workers);
  return results;
}

// CPU-intensive function
function heavyComputation(data) {
  // Simulate heavy computation
  let result = 0;
  for (let i = 0; i < 1000000; i++) {
    result += Math.sqrt(data * i);
  }
  return result;
}
```

### Connection Pooling
```javascript
// GOOD: Database connection pool
const mysql = require('mysql2/promise');

class ConnectionPool {
  constructor(config, maxConnections = 10) {
    this.config = config;
    this.maxConnections = maxConnections;
    this.pool = [];
    this.waitingQueue = [];
  }
  
  async getConnection() {
    if (this.pool.length > 0) {
      return this.pool.pop();
    }
    
    if (this.pool.length + this.waitingQueue.length < this.maxConnections) {
      return mysql.createConnection(this.config);
    }
    
    // Wait for available connection
    return new Promise((resolve) => {
      this.waitingQueue.push(resolve);
    });
  }
  
  async releaseConnection(connection) {
    if (this.waitingQueue.length > 0) {
      const resolve = this.waitingQueue.shift();
      resolve(connection);
    } else {
      this.pool.push(connection);
    }
  }
}

// Usage
const pool = new ConnectionPool({
  host: 'localhost',
  user: 'user',
  password: 'password',
  database: 'database'
});

async function executeQuery(sql, params) {
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.execute(sql, params);
    return rows;
  } finally {
    await pool.releaseConnection(connection);
  }
}
```

## 🗄️ Database Performance

### Query Optimization
```javascript
// BAD: N+1 query problem
async function getUsersWithPostsBad() {
  const users = await db.query('SELECT * FROM users');
  
  for (const user of users) {
    user.posts = await db.query(
      'SELECT * FROM posts WHERE user_id = ?', 
      [user.id]
    );
  }
  
  return users;
}

// GOOD: Single query with JOIN
async function getUsersWithPostsGood() {
  const query = `
    SELECT 
      u.*, 
      p.id as post_id, 
      p.title, 
      p.content
    FROM users u
    LEFT JOIN posts p ON u.id = p.user_id
    ORDER BY u.id, p.id
  `;
  
  const rows = await db.query(query);
  
  // Group results by user
  const users = {};
  rows.forEach(row => {
    if (!users[row.id]) {
      users[row.id] = {
        id: row.id,
        name: row.name,
        email: row.email,
        posts: []
      };
    }
    
    if (row.post_id) {
      users[row.id].posts.push({
        id: row.post_id,
        title: row.title,
        content: row.content
      });
    }
  });
  
  return Object.values(users);
}
```

### Caching Strategy
```javascript
// GOOD: In-memory caching with TTL
class Cache {
  constructor(defaultTTL = 300000) { // 5 minutes default
    this.cache = new Map();
    this.defaultTTL = defaultTTL;
  }
  
  set(key, value, ttl = this.defaultTTL) {
    this.cache.set(key, {
      value,
      expiry: Date.now() + ttl
    });
  }
  
  get(key) {
    const item = this.cache.get(key);
    
    if (!item) {
      return null;
    }
    
    if (Date.now() > item.expiry) {
      this.cache.delete(key);
      return null;
    }
    
    return item.value;
  }
  
  delete(key) {
    this.cache.delete(key);
  }
  
  clear() {
    this.cache.clear();
  }
  
  // Clean up expired items
  cleanup() {
    const now = Date.now();
    for (const [key, item] of this.cache.entries()) {
      if (now > item.expiry) {
        this.cache.delete(key);
      }
    }
  }
}

// Usage with database queries
const cache = new Cache();

async function getUserById(id) {
  // Check cache first
  const cachedUser = cache.get(`user:${id}`);
  if (cachedUser) {
    return cachedUser;
  }
  
  // Query database
  const user = await db.query('SELECT * FROM users WHERE id = ?', [id]);
  
  // Cache result
  cache.set(`user:${id}`, user);
  
  return user;
}

// Clean up expired cache items every 5 minutes
setInterval(() => cache.cleanup(), 300000);
```

## 🧪 Performance Testing

### Load Testing with Artillery
```yaml
# artillery-config.yml
config:
  target: 'http://localhost:3000'
  phases:
    - duration: 60
      arrivalRate: 10
    - duration: 120
      arrivalRate: 50
    - duration: 60
      arrivalRate: 100

scenarios:
  - name: "API Load Test"
    requests:
      - get:
          url: "/api/users"
      - post:
          url: "/api/users"
          json:
            name: "Test User"
            email: "test@example.com"
```

### Benchmark Testing
```javascript
const Benchmark = require('benchmark');

function benchmarkFunctions() {
  const suite = new Benchmark.Suite();
  
  suite
    .add('Bad Implementation', () => {
      findDuplicatesBad([1, 2, 3, 2, 4, 3, 5]);
    })
    .add('Good Implementation', () => {
      findDuplicatesGood([1, 2, 3, 2, 4, 3, 5]);
    })
    .on('cycle', (event) => {
      console.log(String(event.target));
    })
    .on('complete', function() {
      console.log('Fastest is ' + this.filter('fastest').map('name'));
    })
    .run({ async: true });
}

// Functions to benchmark
function findDuplicatesBad(arr) {
  const duplicates = [];
  for (let i = 0; i < arr.length; i++) {
    for (let j = i + 1; j < arr.length; j++) {
      if (arr[i] === arr[j] && !duplicates.includes(arr[i])) {
        duplicates.push(arr[i]);
      }
    }
  }
  return duplicates;
}

function findDuplicatesGood(arr) {
  const seen = new Set();
  const duplicates = new Set();
  
  for (const num of arr) {
    if (seen.has(num)) {
      duplicates.add(num);
    } else {
      seen.add(num);
    }
  }
  
  return Array.from(duplicates);
}
```

## 📈 Performance Monitoring

### Application Performance Monitoring (APM)
```javascript
// Custom APM implementation
class APM {
  constructor() {
    this.metrics = {
      requests: 0,
      errors: 0,
      responseTime: [],
      memoryUsage: []
    };
  }
  
  recordRequest(duration, error = null) {
    this.metrics.requests++;
    this.metrics.responseTime.push(duration);
    
    if (error) {
      this.metrics.errors++;
    }
    
    // Keep only last 1000 measurements
    if (this.metrics.responseTime.length > 1000) {
      this.metrics.responseTime.shift();
    }
  }
  
  getStats() {
    const responseTimes = this.metrics.responseTime;
    const avgResponseTime = responseTimes.length > 0 
      ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length 
      : 0;
    
    return {
      totalRequests: this.metrics.requests,
      totalErrors: this.metrics.errors,
      errorRate: this.metrics.requests > 0 
        ? (this.metrics.errors / this.metrics.requests) * 100 
        : 0,
      avgResponseTime: avgResponseTime.toFixed(2),
      memoryUsage: process.memoryUsage()
    };
  }
}

// Express middleware for APM
const apm = new APM();

function apmMiddleware(req, res, next) {
  const startTime = process.hrtime.bigint();
  
  res.on('finish', () => {
    const endTime = process.hrtime.bigint();
    const duration = Number(endTime - startTime) / 1000000; // Convert to ms
    
    apm.recordRequest(duration, res.statusCode >= 400);
  });
  
  next();
}

// Usage in Express
const express = require('express');
const app = express();

app.use(apmMiddleware);

// Stats endpoint
app.get('/stats', (req, res) => {
  res.json(apm.getStats());
});
```

## 🚀 Best Practices Checklist

### Event Loop Optimization
- [ ] Avoid blocking operations in event loop
- [ ] Use async/await for asynchronous operations
- [ ] Implement proper error handling in async code
- [ ] Monitor event loop lag
- [ ] Use setImmediate for non-critical operations
- [ ] Batch operations to reduce overhead

### Memory Management
- [ ] Monitor memory usage regularly
- [ ] Clean up event listeners and timers
- [ ] Use streams for large data processing
- [ ] Implement proper object lifecycle management
- [ ] Avoid memory leaks with proper cleanup
- [ ] Use object pooling for expensive objects

### Concurrency & Parallelism
- [ ] Use worker threads for CPU-intensive tasks
- [ ] Implement connection pooling for databases
- [ ] Use Promise.all for parallel async operations
- [ ] Avoid creating too many concurrent operations
- [ ] Implement proper error handling in concurrent code
- [ ] Monitor thread pool usage

### Database Performance
- [ ] Use connection pooling
- [ ] Implement query optimization
- [ ] Add appropriate database indexes
- [ ] Use caching for frequently accessed data
- [ ] Monitor query performance
- [ ] Use bulk operations for multiple records

### Monitoring & Testing
- [ ] Implement performance monitoring
- [ ] Set up load testing
- [ ] Monitor memory and CPU usage
- [ ] Use profiling tools regularly
- [ ] Set up alerts for performance degradation
- [ ] Conduct regular performance audits

---

**Node.js Version**: [NODE_VERSION]  
**Performance Framework**: Clinic.js, Chrome DevTools, Artillery  
**Last Updated**: [DATE]  
**Template Version**: 1.0
