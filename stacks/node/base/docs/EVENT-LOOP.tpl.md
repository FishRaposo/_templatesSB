<!--
File: EVENT-LOOP.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Node.js Event Loop Patterns

## Purpose
Comprehensive guide to Node.js event loop patterns, asynchronous programming, and non-blocking I/O operations.

## Core Event Loop Concepts

### 1. Understanding the Event Loop
```javascript
// Event Loop Phases (in order):
// 1. Timers (setTimeout, setInterval)
// 2. Pending Callbacks (I/O callbacks)
// 3. Idle, Prepare (internal use)
// 4. Poll (retrieve new I/O events)
// 5. Check (setImmediate callbacks)
// 6. Close Callbacks (close event callbacks)

console.log('Start'); // Synchronous - runs first

setTimeout(() => {
  console.log('Timeout'); // Timer phase
}, 0);

setImmediate(() => {
  console.log('Immediate'); // Check phase
});

Promise.resolve().then(() => {
  console.log('Promise'); // Microtask - runs before next phase
});

process.nextTick(() => {
  console.log('NextTick'); // Microtask - highest priority
});

console.log('End'); // Synchronous

// Output order:
// Start, End, NextTick, Promise, Timeout/Immediate (order varies)
```

### 2. Microtasks vs Macrotasks
```javascript
// Microtasks (higher priority):
// - process.nextTick()
// - Promise.then/catch/finally
// - Async/await

// Macrotasks (lower priority):
// - setTimeout/setInterval
// - setImmediate
// - I/O operations
// - UI rendering

console.log('1');

process.nextTick(() => console.log('2')); // Microtask

Promise.resolve().then(() => console.log('3')); // Microtask

setTimeout(() => console.log('4'), 0); // Macrotask

setImmediate(() => console.log('5')); // Macrotask

console.log('6');

// Output: 1, 6, 2, 3, 4, 5
```

### 3. Event Loop Monitoring
```javascript
const { performance, setImmediate } = require('perf_hooks');

function monitorEventLoop() {
  let start = performance.now();
  
  setImmediate(() => {
    const delay = performance.now() - start;
    
    if (delay > 10) {
      console.warn(`Event loop delay: ${delay.toFixed(2)}ms`);
    }
    
    // Continue monitoring
    monitorEventLoop();
  });
}

// Start monitoring
monitorEventLoop();
```

## Asynchronous Patterns

### 1. Callback Pattern
```javascript
const fs = require('fs');

// Basic callback pattern
function readFileCallback(path, callback) {
  fs.readFile(path, 'utf8', (err, data) => {
    if (err) {
      callback(err);
      return;
    }
    
    // Process data
    const processed = data.toUpperCase();
    callback(null, processed);
  });
}

// Usage
readFileCallback('file.txt', (err, data) => {
  if (err) {
    console.error('Error:', err);
    return;
  }
  
  console.log('Data:', data);
});

// Callback hell (pyramid of doom) - AVOID THIS
fs.readFile('file1.txt', 'utf8', (err, data1) => {
  if (err) throw err;
  
  fs.readFile('file2.txt', 'utf8', (err, data2) => {
    if (err) throw err;
    
    fs.readFile('file3.txt', 'utf8', (err, data3) => {
      if (err) throw err;
      
      console.log(data1 + data2 + data3);
    });
  });
});
```

### 2. Promise Pattern
```javascript
const fs = require('fs').promises;

// Convert callback to promise
function readFilePromise(path) {
  return fs.readFile(path, 'utf8');
}

// Promise chaining
readFilePromise('file1.txt')
  .then(data1 => {
    console.log('File 1:', data1);
    return readFilePromise('file2.txt');
  })
  .then(data2 => {
    console.log('File 2:', data2);
    return readFilePromise('file3.txt');
  })
  .then(data3 => {
    console.log('File 3:', data3);
  })
  .catch(err => {
    console.error('Error:', err);
  });

// Parallel execution with Promise.all
async function readAllFiles() {
  try {
    const [data1, data2, data3] = await Promise.all([
      fs.readFile('file1.txt', 'utf8'),
      fs.readFile('file2.txt', 'utf8'),
      fs.readFile('file3.txt', 'utf8')
    ]);
    
    return { data1, data2, data3 };
  } catch (err) {
    console.error('Error reading files:', err);
    throw err;
  }
}

// Race conditions with Promise.race
function fetchWithTimeout(url, timeout = 5000) {
  return Promise.race([
    fetch(url),
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Timeout')), timeout)
    )
  ]);
}
```

### 3. Async/Await Pattern
```javascript
const fs = require('fs').promises;

// Clean async/await pattern
async function readFilesSequentially() {
  try {
    const data1 = await fs.readFile('file1.txt', 'utf8');
    console.log('File 1:', data1);
    
    const data2 = await fs.readFile('file2.txt', 'utf8');
    console.log('File 2:', data2);
    
    const data3 = await fs.readFile('file3.txt', 'utf8');
    console.log('File 3:', data3);
    
    return { data1, data2, data3 };
  } catch (err) {
    console.error('Error reading files:', err);
    throw err;
  }
}

// Parallel execution with async/await
async function readAllFilesParallel() {
  try {
    const filePromises = [
      fs.readFile('file1.txt', 'utf8'),
      fs.readFile('file2.txt', 'utf8'),
      fs.readFile('file3.txt', 'utf8')
    ];
    
    const [data1, data2, data3] = await Promise.all(filePromises);
    
    return { data1, data2, data3 };
  } catch (err) {
    console.error('Error:', err);
    throw err;
  }
}

// Error handling with async/await
async function robustFileOperation() {
  try {
    const data = await fs.readFile('file.txt', 'utf8');
    
    // Process data
    const processed = data.toUpperCase();
    
    // Write processed data
    await fs.writeFile('output.txt', processed);
    
    return processed;
  } catch (err) {
    if (err.code === 'ENOENT') {
      console.error('File not found');
    } else if (err.code === 'EACCES') {
      console.error('Permission denied');
    } else {
      console.error('Unknown error:', err);
    }
    
    throw err;
  }
}
```

## Stream Patterns

### 1. Readable Streams
```javascript
const fs = require('fs');
const { Readable } = require('stream');

// Create readable stream from file
const readStream = fs.createReadStream('large-file.txt', {
  encoding: 'utf8',
  highWaterMark: 1024 // 1KB chunks
});

// Handle stream events
readStream.on('data', (chunk) => {
  console.log('Received chunk:', chunk.length, 'bytes');
  // Process chunk
});

readStream.on('end', () => {
  console.log('Stream finished');
});

readStream.on('error', (err) => {
  console.error('Stream error:', err);
});

// Custom readable stream
class CounterStream extends Readable {
  constructor(max) {
    super();
    this.max = max;
    this.index = 0;
  }
  
  _read() {
    const i = this.index++;
    
    if (i >= this.max) {
      this.push(null); // End of stream
    } else {
      const buf = Buffer.from(`${i}\n`, 'utf8');
      this.push(buf);
    }
  }
}

// Usage
const counter = new CounterStream(5);
counter.pipe(process.stdout);
```

### 2. Writable Streams
```javascript
const fs = require('fs');
const { Writable } = require('stream');

// Create writable stream
const writeStream = fs.createWriteStream('output.txt', {
  encoding: 'utf8'
});

// Write to stream
writeStream.write('Hello, World!\n');
writeStream.write('This is a test.\n');
writeStream.end(); // Signal end of writing

// Custom writable stream
class UppercaseStream extends Writable {
  constructor() {
    super({ objectMode: true }); // Handle objects
  }
  
  _write(chunk, encoding, callback) {
    try {
      // Transform and write
      const transformed = chunk.toString().toUpperCase();
      console.log('Writing:', transformed);
      callback();
    } catch (err) {
      callback(err);
    }
  }
}

// Usage
const upperStream = new UppercaseStream();
upperStream.write('hello');
upperStream.write('world');
upperStream.end();
```

### 3. Transform Streams
```javascript
const { Transform } = require('stream');

// Custom transform stream
class UppercaseTransform extends Transform {
  _transform(chunk, encoding, callback) {
    const transformed = chunk.toString().toUpperCase();
    this.push(transformed);
    callback();
  }
}

// CSV parser transform
class CSVParser extends Transform {
  constructor(options) {
    super({ objectMode: true });
    this.options = options;
    this.headers = null;
    this.isFirstRow = true;
  }
  
  _transform(chunk, encoding, callback) {
    const lines = chunk.toString().split('\n');
    
    for (const line of lines) {
      if (line.trim() === '') continue;
      
      const values = line.split(',');
      
      if (this.isFirstRow) {
        this.headers = values;
        this.isFirstRow = false;
      } else {
        const obj = {};
        this.headers.forEach((header, index) => {
          obj[header.trim()] = values[index]?.trim();
        });
        this.push(obj);
      }
    }
    
    callback();
  }
}

// Pipeline usage
const fs = require('fs');
const pipeline = require('stream').pipeline;

pipeline(
  fs.createReadStream('data.csv'),
  new CSVParser(),
  new UppercaseTransform(),
  fs.createWriteStream('output.txt'),
  (err) => {
    if (err) {
      console.error('Pipeline failed:', err);
    } else {
      console.log('Pipeline completed');
    }
  }
);
```

## Event Emitter Patterns

### 1. Basic Event Emitter
```javascript
const EventEmitter = require('events');

class TaskManager extends EventEmitter {
  constructor() {
    super();
    this.tasks = new Map();
  }
  
  addTask(id, task) {
    this.tasks.set(id, task);
    
    // Emit events
    this.emit('taskAdded', { id, task });
    
    // Execute task asynchronously
    setImmediate(() => {
      this.executeTask(id);
    });
  }
  
  executeTask(id) {
    const task = this.tasks.get(id);
    
    this.emit('taskStarted', { id, task });
    
    // Simulate async task
    setTimeout(() => {
      this.emit('taskCompleted', { id, task });
      this.tasks.delete(id);
    }, 1000);
  }
}

// Usage
const taskManager = new TaskManager();

// Listen for events
taskManager.on('taskAdded', ({ id, task }) => {
  console.log(`Task ${id} added: ${task.name}`);
});

taskManager.on('taskStarted', ({ id, task }) => {
  console.log(`Task ${id} started: ${task.name}`);
});

taskManager.on('taskCompleted', ({ id, task }) => {
  console.log(`Task ${id} completed: ${task.name}`);
});

// Add tasks
taskManager.addTask(1, { name: 'Process data' });
taskManager.addTask(2, { name: 'Send email' });
```

### 2. Error Handling with Events
```javascript
class DatabaseConnection extends EventEmitter {
  constructor(config) {
    super();
    this.config = config;
    this.connected = false;
  }
  
  async connect() {
    try {
      // Simulate connection
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      this.connected = true;
      this.emit('connected');
      
    } catch (err) {
      this.emit('error', err);
      this.emit('disconnected');
    }
  }
  
  async query(sql) {
    if (!this.connected) {
      const err = new Error('Not connected to database');
      this.emit('error', err);
      throw err;
    }
    
    try {
      // Simulate query
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const results = [{ id: 1, name: 'test' }];
      this.emit('queryExecuted', { sql, results });
      
      return results;
      
    } catch (err) {
      this.emit('error', err);
      throw err;
    }
  }
}

// Usage with error handling
const db = new DatabaseConnection({ host: 'localhost' });

// Handle events
db.on('connected', () => {
  console.log('Database connected');
});

db.on('error', (err) => {
  console.error('Database error:', err);
});

db.on('disconnected', () => {
  console.log('Database disconnected');
});

// Connect and query
db.connect().then(() => {
  return db.query('SELECT * FROM users');
}).then(results => {
  console.log('Query results:', results);
}).catch(err => {
  console.error('Operation failed:', err);
});
```

## Performance Patterns

### 1. Non-blocking I/O
```javascript
const fs = require('fs');

// BAD: Blocking I/O
function blockingOperation() {
  const data = fs.readFileSync('large-file.txt', 'utf8'); // Blocks event loop
  console.log('File read synchronously');
  return data;
}

// GOOD: Non-blocking I/O
function nonBlockingOperation() {
  fs.readFile('large-file.txt', 'utf8', (err, data) => {
    if (err) {
      console.error('Error:', err);
      return;
    }
    console.log('File read asynchronously');
    // Process data
  });
  console.log('Function returned immediately');
}

// BEST: Promise-based non-blocking I/O
async function modernNonBlockingOperation() {
  try {
    const data = await fs.promises.readFile('large-file.txt', 'utf8');
    console.log('File read with async/await');
    return data;
  } catch (err) {
    console.error('Error:', err);
    throw err;
  }
}
```

### 2. Worker Threads for CPU-intensive Tasks
```javascript
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

// Main thread
function runInWorker(taskFunction, data) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(__filename, {
      workerData: { task: taskFunction.toString(), data }
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
  const { task: taskString, data } = workerData;
  
  // Execute task function
  const taskFunction = eval(`(${taskString})`);
  const result = taskFunction(data);
  
  parentPort.postMessage(result);
}

// Usage
async function processLargeDataset(data) {
  if (isMainThread) {
    console.log('Running in main thread - would block event loop');
    const result = await runInWorker(cpuIntensiveTask, data);
    return result;
  }
}

function cpuIntensiveTask(data) {
  // Simulate CPU-intensive work
  let result = 0;
  for (let i = 0; i < data.length; i++) {
    result += Math.sqrt(data[i] * data[i]);
  }
  return result;
}

// Example usage
if (isMainThread) {
  const largeData = Array.from({ length: 1000000 }, (_, i) => i);
  
  processLargeDataset(largeData)
    .then(result => console.log('Result:', result))
    .catch(err => console.error('Error:', err));
}
```

### 3. Connection Pooling
```javascript
class ConnectionPool extends EventEmitter {
  constructor(maxConnections = 10) {
    super();
    this.maxConnections = maxConnections;
    this.connections = [];
    this.waitingQueue = [];
  }
  
  async getConnection() {
    return new Promise((resolve, reject) => {
      // Check for available connection
      if (this.connections.length > 0) {
        const connection = this.connections.pop();
        resolve(connection);
        return;
      }
      
      // Check if we can create new connection
      if (this.getTotalConnections() < this.maxConnections) {
        this.createConnection()
          .then(resolve)
          .catch(reject);
        return;
      }
      
      // Add to waiting queue
      this.waitingQueue.push({ resolve, reject });
    });
  }
  
  releaseConnection(connection) {
    if (this.waitingQueue.length > 0) {
      // Give to waiting request
      const { resolve } = this.waitingQueue.shift();
      resolve(connection);
    } else {
      // Return to pool
      this.connections.push(connection);
    }
  }
  
  async createConnection() {
    // Simulate connection creation
    await new Promise(resolve => setTimeout(resolve, 100));
    return { id: Date.now(), created: new Date() };
  }
  
  getTotalConnections() {
    return this.connections.length + 
           (this.maxConnections - this.waitingQueue.length);
  }
}

// Usage
const pool = new ConnectionPool(5);

async function performDatabaseOperation() {
  let connection;
  
  try {
    connection = await pool.getConnection();
    console.log('Got connection:', connection.id);
    
    // Perform operation
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    console.log('Operation completed');
    
  } finally {
    if (connection) {
      pool.releaseConnection(connection);
      console.log('Released connection:', connection.id);
    }
  }
}

// Run multiple operations
for (let i = 0; i < 10; i++) {
  performDatabaseOperation();
}
```

## Testing Event-driven Code

### 1. Testing Async Code
```javascript
const assert = require('assert');

// Testing callbacks
function testCallbackFunction(done) {
  asyncFunction((err, result) => {
    assert.strictEqual(err, null);
    assert.strictEqual(result, 'expected');
    done();
  });
}

// Testing promises
async function testPromiseFunction() {
  const result = await promiseFunction();
  assert.strictEqual(result, 'expected');
}

// Testing event emitters
function testEventEmitter(done) {
  const emitter = new EventEmitter();
  
  emitter.on('data', (data) => {
    assert.strictEqual(data, 'expected');
    done();
  });
  
  emitter.emit('data', 'expected');
}

// Testing with mocks
const sinon = require('sinon');

function testWithMock() {
  const mock = sinon.stub(fs, 'readFile');
  mock.resolves('mock data');
  
  const result = await readFileFunction();
  
  assert.strictEqual(result, 'mock data');
  mock.restore();
}
```

## Best Practices

### 1. Avoid Blocking the Event Loop
```javascript
// BAD: Synchronous operations
function badExample() {
  const data = fs.readFileSync('large-file.txt'); // Blocks
  const result = crypto.pbkdf2Sync('password', 'salt', 100000, 512, 'sha512'); // Blocks
  return result;
}

// GOOD: Asynchronous operations
async function goodExample() {
  const data = await fs.promises.readFile('large-file.txt'); // Non-blocking
  const result = await new Promise((resolve, reject) => {
    crypto.pbkdf2('password', 'salt', 100000, 512, 'sha512', (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
  return result;
}
```

### 2. Proper Error Handling
```javascript
// Always handle errors in callbacks
fs.readFile('file.txt', (err, data) => {
  if (err) {
    console.error('Error reading file:', err);
    return;
  }
  // Process data
});

// Use try-catch with async/await
async function robustFunction() {
  try {
    const data = await fs.promises.readFile('file.txt');
    return data;
  } catch (err) {
    console.error('Error:', err);
    throw err; // Re-throw or handle appropriately
  }
}

// Handle promise rejections
promiseFunction()
  .then(result => console.log(result))
  .catch(err => console.error(err));

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
```

### 3. Memory Management
```javascript
// Avoid memory leaks with event listeners
class Component extends EventEmitter {
  constructor() {
    super();
    this.timers = [];
  }
  
  startTimer(callback) {
    const timer = setInterval(callback, 1000);
    this.timers.push(timer);
  }
  
  destroy() {
    // Clean up timers
    this.timers.forEach(timer => clearInterval(timer));
    this.timers = [];
    
    // Remove all listeners
    this.removeAllListeners();
  }
}

// Stream cleanup
function processLargeFile(filePath) {
  const readStream = fs.createReadStream(filePath);
  const writeStream = fs.createWriteStream('output.txt');
  
  readStream.pipe(writeStream);
  
  // Handle cleanup
  readStream.on('end', () => {
    writeStream.end();
  });
  
  readStream.on('error', (err) => {
    console.error('Read error:', err);
    writeStream.destroy();
  });
  
  writeStream.on('error', (err) => {
    console.error('Write error:', err);
    readStream.destroy();
  });
}
```

This comprehensive event loop guide covers the fundamental patterns and best practices for building efficient, non-blocking Node.js applications.
