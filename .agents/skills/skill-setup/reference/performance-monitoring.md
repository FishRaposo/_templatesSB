# Performance Monitoring Guide for AI Agent Skills

This guide provides comprehensive strategies for monitoring, analyzing, and optimizing the performance of AI agent skills.

## Monitoring Overview

Performance monitoring for skills involves tracking:
- Execution time
- Memory usage
- Resource consumption
- Error rates
- Success rates
- User satisfaction

## Key Performance Metrics

### 1. Execution Metrics
```javascript
class PerformanceMetrics {
  constructor() {
    this.metrics = {
      executions: {
        total: 0,
        successful: 0,
        failed: 0,
        averageTime: 0,
        maxTime: 0,
        minTime: Infinity
      },
      resources: {
        peakMemory: 0,
        averageMemory: 0,
        cpuTime: 0
      },
      errors: {
        types: new Map(),
        frequency: 0
      }
    };
  }
  
  recordExecution(duration, success, memoryUsage, error = null) {
    this.metrics.executions.total++;
    
    if (success) {
      this.metrics.executions.successful++;
    } else {
      this.metrics.executions.failed++;
      if (error) {
        const count = this.metrics.errors.types.get(error) || 0;
        this.metrics.errors.types.set(error, count + 1);
      }
    }
    
    // Update timing metrics
    this.metrics.executions.averageTime = 
      (this.metrics.executions.averageTime * (this.metrics.executions.total - 1) + duration) / 
      this.metrics.executions.total;
    this.metrics.executions.maxTime = Math.max(this.metrics.executions.maxTime, duration);
    this.metrics.executions.minTime = Math.min(this.metrics.executions.minTime, duration);
    
    // Update memory metrics
    this.metrics.resources.peakMemory = Math.max(this.metrics.resources.peakMemory, memoryUsage);
    this.metrics.resources.averageMemory = 
      (this.metrics.resources.averageMemory * (this.metrics.executions.total - 1) + memoryUsage) / 
      this.metrics.executions.total;
  }
  
  getSuccessRate() {
    return this.metrics.executions.total > 0 ? 
      (this.metrics.executions.successful / this.metrics.executions.total) * 100 : 0;
  }
  
  getErrorRate() {
    return this.metrics.executions.total > 0 ? 
      (this.metrics.executions.failed / this.metrics.executions.total) * 100 : 0;
  }
}
```

### 2. Real-time Monitoring
```javascript
import { performance } from 'perf_hooks';
import { EventEmitter } from 'events';

class SkillMonitor extends EventEmitter {
  constructor(skillName) {
    super();
    this.skillName = skillName;
    this.metrics = new PerformanceMetrics();
    this.activeExecutions = new Map();
    this.alerts = {
      maxExecutionTime: 30000, // 30 seconds
      maxMemoryUsage: 512 * 1024 * 1024, // 512MB
      maxErrorRate: 10 // 10%
    };
  }
  
  startExecution(executionId) {
    const startTime = performance.now();
    const startMemory = process.memoryUsage().heapUsed;
    
    this.activeExecutions.set(executionId, {
      startTime,
      startMemory,
      lastCheck: Date.now()
    });
    
    // Set up monitoring interval
    const interval = setInterval(() => {
      this.checkExecution(executionId, interval);
    }, 1000);
    
    return { startTime, interval };
  }
  
  endExecution(executionId, success, error = null, interval) {
    clearInterval(interval);
    
    const execution = this.activeExecutions.get(executionId);
    if (!execution) return;
    
    const endTime = performance.now();
    const endMemory = process.memoryUsage().heapUsed;
    
    const duration = endTime - execution.startTime;
    const memoryDelta = endMemory - execution.startMemory;
    
    this.metrics.recordExecution(duration, success, endMemory, error);
    this.activeExecutions.delete(executionId);
    
    // Emit metrics
    this.emit('execution', {
      executionId,
      duration,
      success,
      memoryUsage: endMemory,
      error
    });
    
    // Check alerts
    this.checkAlerts(duration, endMemory);
  }
  
  checkExecution(executionId, interval) {
    const execution = this.activeExecutions.get(executionId);
    if (!execution) {
      clearInterval(interval);
      return;
    }
    
    const now = performance.now();
    const duration = now - execution.startTime;
    const memory = process.memoryUsage().heapUsed;
    
    // Check for long-running execution
    if (duration > this.alerts.maxExecutionTime) {
      this.emit('alert', {
        type: 'slow_execution',
        executionId,
        duration,
        threshold: this.alerts.maxExecutionTime
      });
    }
    
    // Check for high memory usage
    if (memory > this.alerts.maxMemoryUsage) {
      this.emit('alert', {
        type: 'high_memory',
        executionId,
        memory,
        threshold: this.alerts.maxMemoryUsage
      });
    }
  }
  
  checkAlerts(duration, memory) {
    const errorRate = this.metrics.getErrorRate();
    
    if (errorRate > this.alerts.maxErrorRate) {
      this.emit('alert', {
        type: 'high_error_rate',
        errorRate,
        threshold: this.alerts.maxErrorRate
      });
    }
  }
}
```

## Performance Optimization Strategies

### 1. Lazy Loading
```javascript
class LazyLoader {
  constructor() {
    this.cache = new Map();
    this.loadPromises = new Map();
  }
  
  async load(resource, loader) {
    // Return from cache if available
    if (this.cache.has(resource)) {
      return this.cache.get(resource);
    }
    
    // Return existing promise if loading
    if (this.loadPromises.has(resource)) {
      return this.loadPromises.get(resource);
    }
    
    // Load resource
    const promise = loader().then(result => {
      this.cache.set(resource, result);
      this.loadPromises.delete(resource);
      return result;
    }).catch(error => {
      this.loadPromises.delete(resource);
      throw error;
    });
    
    this.loadPromises.set(resource, promise);
    return promise;
  }
  
  clearCache() {
    this.cache.clear();
  }
}

// Usage example
const loader = new LazyLoader();

async function getTemplate(templateName) {
  return await loader.load(templateName, async () => {
    return await fs.readFile(`./templates/${templateName}.md`, 'utf-8');
  });
}
```

### 2. Connection Pooling
```javascript
import https from 'https';

class ConnectionPool {
  constructor(maxConnections = 10) {
    this.maxConnections = maxConnections;
    this.connections = [];
    this.waiting = [];
  }
  
  async getConnection(url) {
    return new Promise((resolve, reject) => {
      // Check for available connection
      const available = this.connections.find(conn => !conn.inUse);
      
      if (available) {
        available.inUse = true;
        resolve(available);
        return;
      }
      
      // Create new connection if under limit
      if (this.connections.length < this.maxConnections) {
        const conn = this.createConnection(url);
        conn.inUse = true;
        this.connections.push(conn);
        resolve(conn);
        return;
      }
      
      // Queue request
      this.waiting.push({ resolve, reject });
    });
  }
  
  releaseConnection(connection) {
    connection.inUse = false;
    
    // Process waiting requests
    if (this.waiting.length > 0) {
      const next = this.waiting.shift();
      connection.inUse = true;
      next.resolve(connection);
    }
  }
  
  createConnection(url) {
    // Create persistent connection
    return {
      url,
      inUse: false,
      lastUsed: Date.now(),
      request: (options) => {
        return new Promise((resolve, reject) => {
          const req = https.request(url, options, resolve);
          req.on('error', reject);
          req.end();
        });
      }
    };
  }
}
```

### 3. Caching Strategies
```javascript
class SkillCache {
  constructor(options = {}) {
    this.cache = new Map();
    this.ttl = options.ttl || 300000; // 5 minutes default
    this.maxSize = options.maxSize || 1000;
    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0
    };
  }
  
  set(key, value, customTtl) {
    // Evict if at capacity
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      this.evictOldest();
    }
    
    const item = {
      value,
      expires: Date.now() + (customTtl || this.ttl),
      accessed: Date.now(),
      hits: 0
    };
    
    this.cache.set(key, item);
  }
  
  get(key) {
    const item = this.cache.get(key);
    
    if (!item) {
      this.stats.misses++;
      return null;
    }
    
    // Check expiration
    if (Date.now() > item.expires) {
      this.cache.delete(key);
      this.stats.misses++;
      return null;
    }
    
    item.accessed = Date.now();
    item.hits++;
    this.stats.hits++;
    return item.value;
  }
  
  evictOldest() {
    let oldest = null;
    let oldestTime = Date.now();
    
    for (const [key, item] of this.cache.entries()) {
      if (item.accessed < oldestTime) {
        oldestTime = item.accessed;
        oldest = key;
      }
    }
    
    if (oldest) {
      this.cache.delete(oldest);
      this.stats.evictions++;
    }
  }
  
  getStats() {
    const total = this.stats.hits + this.stats.misses;
    return {
      ...this.stats,
      hitRate: total > 0 ? (this.stats.hits / total) * 100 : 0,
      size: this.cache.size
    };
  }
}
```

## Performance Profiling

### 1. Execution Profiler
```javascript
import { performance } from 'perf_hooks';

class SkillProfiler {
  constructor() {
    this.profiles = new Map();
    this.currentProfile = null;
  }
  
  startProfile(name) {
    this.currentProfile = {
      name,
      startTime: performance.now(),
      startMemory: process.memoryUsage(),
      steps: [],
      checkpoints: []
    };
  }
  
  addStep(stepName) {
    if (!this.currentProfile) return;
    
    const now = performance.now();
    const memory = process.memoryUsage();
    
    this.currentProfile.steps.push({
      name: stepName,
      timestamp: now,
      memory: memory.heapUsed,
      timeSinceStart: now - this.currentProfile.startTime,
      memorySinceStart: memory.heapUsed - this.currentProfile.startMemory.heapUsed
    });
  }
  
  checkpoint(label) {
    if (!this.currentProfile) return;
    
    this.currentProfile.checkpoints.push({
      label,
      timestamp: performance.now(),
      memory: process.memoryUsage()
    });
  }
  
  endProfile() {
    if (!this.currentProfile) return null;
    
    const endTime = performance.now();
    const endMemory = process.memoryUsage();
    
    const profile = {
      ...this.currentProfile,
      endTime,
      endMemory,
      duration: endTime - this.currentProfile.startTime,
      memoryDelta: endMemory.heapUsed - this.currentProfile.startMemory.heapUsed
    };
    
    // Store profile
    if (!this.profiles.has(profile.name)) {
      this.profiles.set(profile.name, []);
    }
    this.profiles.get(profile.name).push(profile);
    
    this.currentProfile = null;
    return profile;
  }
  
  getAverageProfile(name) {
    const profiles = this.profiles.get(name) || [];
    if (profiles.length === 0) return null;
    
    const avg = {
      name,
      sampleCount: profiles.length,
      avgDuration: 0,
      avgMemoryDelta: 0,
      steps: {}
    };
    
    profiles.forEach(profile => {
      avg.avgDuration += profile.duration;
      avg.avgMemoryDelta += profile.memoryDelta;
      
      profile.steps.forEach(step => {
        if (!avg.steps[step.name]) {
          avg.steps[step.name] = {
            count: 0,
            avgTime: 0,
            avgMemory: 0
          };
        }
        
        const stepAvg = avg.steps[step.name];
        stepAvg.count++;
        stepAvg.avgTime += step.timeSinceStart;
        stepAvg.avgMemory += step.memorySinceStart;
      });
    });
    
    avg.avgDuration /= profiles.length;
    avg.avgMemoryDelta /= profiles.length;
    
    // Calculate step averages
    Object.values(avg.steps).forEach(step => {
      step.avgTime /= step.count;
      step.avgMemory /= step.count;
    });
    
    return avg;
  }
}
```

### 2. Resource Usage Tracker
```javascript
class ResourceTracker {
  constructor() {
    this.samples = [];
    this.interval = null;
    this.maxSamples = 1000;
  }
  
  start(sampleInterval = 1000) {
    this.interval = setInterval(() => {
      this.sample();
    }, sampleInterval);
  }
  
  stop() {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }
  
  sample() {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    
    const sample = {
      timestamp: Date.now(),
      memory: {
        rss: memUsage.rss,
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal,
        external: memUsage.external
      },
      cpu: {
        user: cpuUsage.user,
        system: cpuUsage.system
      }
    };
    
    this.samples.push(sample);
    
    // Keep only recent samples
    if (this.samples.length > this.maxSamples) {
      this.samples.shift();
    }
  }
  
  getStats(duration = 60000) {
    const now = Date.now();
    const recentSamples = this.samples.filter(
      s => now - s.timestamp <= duration
    );
    
    if (recentSamples.length === 0) return null;
    
    const stats = {
      sampleCount: recentSamples.length,
      duration,
      memory: {
        avg: 0,
        max: 0,
        min: Infinity
      },
      cpu: {
        avgUser: 0,
        avgSystem: 0
      }
    };
    
    recentSamples.forEach(sample => {
      // Memory stats
      stats.memory.avg += sample.memory.heapUsed;
      stats.memory.max = Math.max(stats.memory.max, sample.memory.heapUsed);
      stats.memory.min = Math.min(stats.memory.min, sample.memory.heapUsed);
      
      // CPU stats
      stats.cpu.avgUser += sample.cpu.user;
      stats.cpu.avgSystem += sample.cpu.system;
    });
    
    stats.memory.avg /= recentSamples.length;
    stats.cpu.avgUser /= recentSamples.length;
    stats.cpu.avgSystem /= recentSamples.length;
    
    return stats;
  }
}
```

## Performance Benchmarks

### 1. Benchmark Suite
```javascript
class SkillBenchmark {
  constructor(skillPath) {
    this.skillPath = skillPath;
    this.results = [];
  }
  
  async runBenchmark(testCases) {
    console.log(`\n🏃 Running benchmarks for ${path.basename(this.skillPath)}`);
    
    for (const testCase of testCases) {
      const result = await this.runSingleTest(testCase);
      this.results.push(result);
      
      console.log(`  ✓ ${testCase.name}: ${result.duration.toFixed(2)}ms`);
    }
    
    return this.generateReport();
  }
  
  async runSingleTest(testCase) {
    const startMemory = process.memoryUsage().heapUsed;
    const startTime = performance.now();
    
    try {
      // Run test case
      const result = await testCase.execute();
      
      const endTime = performance.now();
      const endMemory = process.memoryUsage().heapUsed;
      
      return {
        name: testCase.name,
        duration: endTime - startTime,
        memoryDelta: endMemory - startMemory,
        success: true,
        result
      };
    } catch (error) {
      const endTime = performance.now();
      const endMemory = process.memoryUsage().heapUsed;
      
      return {
        name: testCase.name,
        duration: endTime - startTime,
        memoryDelta: endMemory - startMemory,
        success: false,
        error: error.message
      };
    }
  }
  
  generateReport() {
    const successful = this.results.filter(r => r.success);
    const failed = this.results.filter(r => !r.success);
    
    const report = {
      summary: {
        total: this.results.length,
        successful: successful.length,
        failed: failed.length,
        successRate: (successful.length / this.results.length) * 100
      },
      performance: {
        avgDuration: successful.reduce((sum, r) => sum + r.duration, 0) / successful.length,
        maxDuration: Math.max(...successful.map(r => r.duration)),
        minDuration: Math.min(...successful.map(r => r.duration)),
        avgMemoryDelta: successful.reduce((sum, r) => sum + r.memoryDelta, 0) / successful.length
      },
      details: this.results
    };
    
    return report;
  }
}
```

### 2. Performance Regression Detection
```javascript
class PerformanceRegressionDetector {
  constructor(baselineFile) {
    this.baselineFile = baselineFile;
    this.baseline = null;
    this.thresholds = {
      durationIncrease: 20, // 20% increase
      memoryIncrease: 30,   // 30% increase
      successRateDrop: 5    // 5% drop
    };
  }
  
  async loadBaseline() {
    try {
      const data = await fs.readFile(this.baselineFile, 'utf-8');
      this.baseline = JSON.parse(data);
    } catch (error) {
      console.warn('No baseline file found, creating new baseline');
      this.baseline = null;
    }
  }
  
  async saveBaseline(report) {
    await fs.writeFile(
      this.baselineFile,
      JSON.stringify(report, null, 2)
    );
    this.baseline = report;
  }
  
  checkRegression(currentReport) {
    if (!this.baseline) {
      return { regression: false, reason: 'No baseline available' };
    }
    
    const regressions = [];
    
    // Check duration
    const durationIncrease = 
      ((currentReport.performance.avgDuration - this.baseline.performance.avgDuration) / 
       this.baseline.performance.avgDuration) * 100;
    
    if (durationIncrease > this.thresholds.durationIncrease) {
      regressions.push({
        type: 'duration',
        current: currentReport.performance.avgDuration,
        baseline: this.baseline.performance.avgDuration,
        increase: durationIncrease
      });
    }
    
    // Check memory
    const memoryIncrease = 
      ((currentReport.performance.avgMemoryDelta - this.baseline.performance.avgMemoryDelta) / 
       Math.abs(this.baseline.performance.avgMemoryDelta || 1)) * 100;
    
    if (memoryIncrease > this.thresholds.memoryIncrease) {
      regressions.push({
        type: 'memory',
        current: currentReport.performance.avgMemoryDelta,
        baseline: this.baseline.performance.avgMemoryDelta,
        increase: memoryIncrease
      });
    }
    
    // Check success rate
    const successRateDrop = 
      this.baseline.summary.successRate - currentReport.summary.successRate;
    
    if (successRateDrop > this.thresholds.successRateDrop) {
      regressions.push({
        type: 'success_rate',
        current: currentReport.summary.successRate,
        baseline: this.baseline.summary.successRate,
        drop: successRateDrop
      });
    }
    
    return {
      regression: regressions.length > 0,
      regressions
    };
  }
}
```

## Performance Optimization Checklist

### Code Level
- [ ] Remove unnecessary computations
- [ ] Optimize loops and recursion
- [ ] Use efficient data structures
- [ ] Implement proper caching
- [ ] Minimize memory allocations
- [ ] Use streaming for large data
- [ ] Parallelize independent operations

### I/O Operations
- [ ] Use connection pooling
- [ ] Implement request batching
- [ ] Add proper timeouts
- [ ] Use compression for transfers
- [ ] Implement retry logic
- [ ] Cache external API responses
- [ ] Use CDN for static assets

### Memory Management
- [ ] Release unused resources
- [ ] Avoid memory leaks
- [ ] Use object pooling
- [ ] Implement size limits
- [ ] Monitor garbage collection
- [ ] Use streams for large files
- [ ] Clear caches appropriately

### Monitoring
- [ ] Track execution time
- [ ] Monitor memory usage
- [ ] Measure success rates
- [ ] Log performance metrics
- [ ] Set up alerts
- [ ] Create dashboards
- [ ] Regular performance reviews

## Performance Monitoring Tools

### 1. Metrics Dashboard
```javascript
class MetricsDashboard {
  constructor() {
    this.metrics = new Map();
    this.alerts = [];
  }
  
  addMetric(name, value, timestamp = Date.now()) {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    
    this.metrics.get(name).push({ value, timestamp });
    
    // Keep only last 1000 data points
    const data = this.metrics.get(name);
    if (data.length > 1000) {
      data.shift();
    }
  }
  
  getMetrics(name, duration = 3600000) { // Default 1 hour
    const data = this.metrics.get(name) || [];
    const now = Date.now();
    
    return data.filter(d => now - d.timestamp <= duration);
  }
  
  generateReport() {
    const report = {};
    
    for (const [name, data] of this.metrics.entries()) {
      if (data.length === 0) continue;
      
      const values = data.map(d => d.value);
      report[name] = {
        current: values[values.length - 1],
        average: values.reduce((a, b) => a + b, 0) / values.length,
        min: Math.min(...values),
        max: Math.max(...values),
        count: values.length
      };
    }
    
    return report;
  }
}
```

This comprehensive performance monitoring guide helps ensure your AI agent skills run efficiently and reliably. Regular monitoring and optimization are key to maintaining high performance as your skills evolve.
