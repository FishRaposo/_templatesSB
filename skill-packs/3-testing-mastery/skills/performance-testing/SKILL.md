---
name: performance-testing
description: Use this skill when testing system performance under load. This includes load testing, stress testing, soak testing, and benchmarking. Measure response times, throughput, resource utilization, and identify performance bottlenecks under various load conditions.
---

# Performance Testing

I'll help you test system performance under load — measuring response times, throughput, and identifying bottlenecks. We'll use load testing, stress testing, and benchmarking.

## Core Approach

### Types of Performance Tests

| Type | Purpose | Duration | Load |
|------|---------|----------|------|
| **Load** | Normal expected load | Minutes | Target capacity |
| **Stress** | Breaking point | Minutes | Beyond capacity |
| **Spike** | Sudden load changes | Seconds | Rapid increase |
| **Soak** | Memory leaks | Hours | Sustained load |
| **Benchmark** | Comparison baseline | Varies | Specific scenarios |

### Key Metrics

- **Response Time** — Latency (p50, p95, p99)
- **Throughput** — Requests/sec, transactions/sec
- **Error Rate** — % of failed requests
- **Resource Usage** — CPU, memory, disk, network

## Step-by-Step Instructions

### 1. Define Performance Goals

```
Example SLA:
- p95 response time < 200ms
- Throughput > 1000 req/sec
- Error rate < 0.1%
- CPU usage < 70% at peak load
```

### 2. Create Test Scenarios

**k6 (JavaScript)**
```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

// Test configuration
export const options = {
  stages: [
    { duration: '2m', target: 100 },   // Ramp up
    { duration: '5m', target: 100 },   // Steady state
    { duration: '2m', target: 200 },   // Increase load
    { duration: '5m', target: 200 },   // Sustained high load
    { duration: '2m', target: 0 },     // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<200'],  // 95% under 200ms
    http_req_failed: ['rate<0.1'],      // < 0.1% errors
  },
};

export default function () {
  const response = http.get('https://api.example.com/users');
  
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 200ms': (r) => r.timings.duration < 200,
  });
  
  sleep(1);
}
```

**Python (Locust)**
```python
from locust import HttpUser, task, between

class WebsiteUser(HttpUser):
    wait_time = between(1, 5)
    
    @task(3)
    def view_items(self):
        self.client.get("/items")
    
    @task(1)
    def create_item(self):
        self.client.post("/items", json={
            "name": "Test Item",
            "price": 29.99
        })
    
    @task(1)
    def view_cart(self):
        self.client.get("/cart")

# Run: locust -f locustfile.py --host=http://localhost:8000
```

**Go (Vegeta or custom)**
```go
package main

import (
    "fmt"
    "time"
    "github.com/tsenart/vegeta/v12/lib"
)

func main() {
    rate := vegeta.Rate{Freq: 1000, Per: time.Second}  // 1000 RPS
    duration := 30 * time.Second
    
    targeter := vegeta.NewStaticTargeter(vegeta.Target{
        Method: "GET",
        URL:    "https://api.example.com/users",
    })
    
    attacker := vegeta.NewAttacker()
    var metrics vegeta.Metrics
    
    for res := range attacker.Attack(targeter, rate, duration, "Load Test") {
        metrics.Add(res)
    }
    metrics.Close()
    
    fmt.Printf("P99: %s\n", metrics.Latencies.P99)
    fmt.Printf("Success: %.2f%%\n", metrics.Success*100)
}
```

### 3. Analyze Results

**k6 output**
```
running (10m00.0s), 000/200 VUs, 119850 complete and 0 interrupted iterations

     ✓ status is 200
     ✓ response time < 200ms

   ✓ checks.........................: 100.00% ✓ 239700 ✗ 0
   ✗ http_req_duration..............: avg=145.2ms min=23.4ms med=132.1ms max=892.3ms p(90)=212.4ms p(95)=245.8ms
     http_reqs......................: 119850  199.75/s
     http_req_failed................: 0.00%   ✓ 0      ✗ 119850
```

**Interpreting results:**
- p95 = 245.8ms (exceeds 200ms SLA)
- Error rate = 0% ✓
- Throughput = 199.75 req/sec

### 4. Stress Testing

Find the breaking point:

```javascript
// k6 stress test
export const options = {
  stages: [
    { duration: '2m', target: 100 },
    { duration: '5m', target: 100 },
    { duration: '2m', target: 200 },
    { duration: '5m', target: 200 },
    { duration: '2m', target: 300 },
    { duration: '5m', target: 300 },
    { duration: '2m', target: 400 },  // Keep increasing
    { duration: '5m', target: 400 },
    { duration: '10m', target: 0 },   // Recovery
  ],
};
```

### 5. Soak Testing

Find memory leaks and stability issues:

```javascript
// k6 soak test (4 hours)
export const options = {
  stages: [
    { duration: '2m', target: 100 },   // Ramp up
    { duration: '3h56m', target: 100 }, // Sustained load
    { duration: '2m', target: 0 },    // Ramp down
  ],
};
```

## Multi-Language Examples

### API Load Testing

**k6 with Authentication**
```javascript
import http from 'k6/http';
import { check, group } from 'k6';

const BASE_URL = 'https://api.example.com';
const AUTH_TOKEN = __ENV.AUTH_TOKEN;

export const options = {
  vus: 50,
  duration: '10m',
};

export default function() {
  const params = {
    headers: {
      'Authorization': `Bearer ${AUTH_TOKEN}`,
      'Content-Type': 'application/json',
    },
  };
  
  group('User Flow', () => {
    // Get user profile
    let profile = http.get(`${BASE_URL}/me`, params);
    check(profile, {
      'profile status 200': (r) => r.status === 200,
    });
    
    // Get orders
    let orders = http.get(`${BASE_URL}/orders`, params);
    check(orders, {
      'orders status 200': (r) => r.status === 200,
    });
    
    // Create order
    let create = http.post(
      `${BASE_URL}/orders`,
      JSON.stringify({ items: ['item1', 'item2'] }),
      params
    );
    check(create, {
      'create status 201': (r) => r.status === 201,
    });
  });
}
```

**Python (Locust with custom shapes)**
```python
from locust import LoadTestShape

class StepLoadShape(LoadTestShape):
    """Increase load in steps"""
    
    step_time = 60  # 1 minute per step
    step_load = 50  # Add 50 users per step
    spawn_rate = 10
    
    def tick(self):
        run_time = self.get_run_time()
        current_step = run_time // self.step_time
        
        if current_step > 10:
            return None
        
        return (current_step + 1) * self.step_load, self.spawn_rate
```

### Database Performance Testing

**Python**
```python
import time
import statistics
from concurrent.futures import ThreadPoolExecutor

def benchmark_query(query_func, iterations=1000, concurrency=10):
    """Benchmark database query performance"""
    times = []
    
    def run_query():
        start = time.perf_counter()
        query_func()
        elapsed = time.perf_counter() - start
        times.append(elapsed * 1000)  # Convert to ms
    
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        executor.map(lambda _: run_query(), range(iterations))
    
    return {
        'count': len(times),
        'min': min(times),
        'max': max(times),
        'mean': statistics.mean(times),
        'median': statistics.median(times),
        'p95': statistics.quantiles(times, n=20)[18],  # 95th percentile
        'p99': statistics.quantiles(times, n=100)[98], # 99th percentile
    }

# Usage
results = benchmark_query(
    lambda: db.query("SELECT * FROM users WHERE id = %s", (1,))
)
print(f"p95: {results['p95']:.2f}ms")
```

## Best Practices

### Test Environment
- Mirror production as closely as possible
- Same hardware specs (or proportional)
- Same database size and distribution
- Same network latency (or simulate it)

### Data Realism
- Use production-like data volumes
- Realistic data distribution
- Vary request patterns (don't hit same records)

### Monitoring
- Monitor system under test
- Collect metrics during tests
- Correlate load with resource usage

### Analysis
- Look for trends, not single measurements
- Test at different times of day
- Account for cold starts vs warm caches

## Common Pitfalls

❌ **Testing from the same machine as the service**
- Resource contention skews results

❌ **Not warming up caches**
- First requests are always slower
- Run a warm-up phase before measuring

❌ **Testing with insufficient data**
- Empty database performs differently
- Small datasets fit in cache unrealistically

❌ **Not simulating realistic user behavior**
- Real users pause, navigate, think
- Add think time between requests

## Validation Checklist

- [ ] Performance goals (SLAs) are defined
- [ ] Test environment mirrors production
- [ ] Tests use realistic data volumes
- [ ] Metrics include p50, p95, p99 latencies
- [ ] Error rates are monitored
- [ ] Resource usage is tracked
- [ ] Bottlenecks are identified and documented
- [ ] Tests run regularly (not just once)

## Related Skills

- **test-strategy** — When to performance test
- **integration-testing** — Test before load testing
- **test-automation** — Automate performance tests in CI
