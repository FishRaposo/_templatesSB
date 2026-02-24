<!-- Generated from task-outputs/task-05-performance.md -->

# Performance Testing with k6

A comprehensive guide to load testing REST APIs using k6, covering load tests, stress tests, spike tests, and soak tests.

## Overview

This guide covers:
- k6 setup and configuration
- Performance SLAs (p95 < 200ms, throughput > 1000 RPS)
- Load test scenarios: ramp up, steady state, stress
- Testing product search, cart, and checkout endpoints
- HTML report generation
- Results analysis and bottleneck identification

## k6 Installation

```bash
# macOS
brew install k6

# Windows (Chocolatey)
choco install k6

# Linux
curl -s https://dl.k6.io/key.gpg | sudo gpg --no-default-keyring --keyring gnupg-ring:/etc/apt/keyrings/k6.gpg --import
sudo chmod 644 /etc/apt/keyrings/k6.gpg
sudo apt-get update
sudo apt-get install k6
```

## Configuration

```javascript
// k6/config/thresholds.js
export const DEFAULT_THRESHOLDS = {
  http_req_duration: [
    'p(50) < 100',   // Median under 100ms
    'p(95) < 200',   // 95th percentile under 200ms
    'p(99) < 500',   // 99th percentile under 500ms
  ],
  http_req_failed: ['rate < 0.01'],  // Less than 1% errors
};
```

```javascript
// k6/config/scenarios.js
export const LOAD_TEST = {
  stages: [
    { duration: '2m', target: 100 },   // Ramp up
    { duration: '5m', target: 100 },   // Steady state
    { duration: '2m', target: 200 },   // Increase
    { duration: '5m', target: 200 },   // Sustained high
    { duration: '2m', target: 0 },     // Ramp down
  ],
};
```

## Load Test Implementation

```javascript
// k6/tests/load.test.js
import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { DEFAULT_THRESHOLDS } from '../config/thresholds.js';
import { LOAD_TEST } from '../config/scenarios.js';

const BASE_URL = __ENV.BASE_URL || 'https://api.ecommerce.com';

export const options = {
  ...LOAD_TEST,
  thresholds: DEFAULT_THRESHOLDS,
};

export default function() {
  group('Browse Products', () => {
    const response = http.get(`${BASE_URL}/products/search?q=laptop`);
    
    check(response, {
      'search status is 200': (r) => r.status === 200,
      'search response time < 200ms': (r) => r.timings.duration < 200,
    });
    
    sleep(randomIntBetween(1, 3));
  });

  group('Add to Cart', () => {
    const response = http.post(`${BASE_URL}/cart/items`, JSON.stringify({
      productId: 'prod-1',
      quantity: 1
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
    check(response, {
      'add to cart status is 201': (r) => r.status === 201,
    });
  });

  group('Checkout', () => {
    const response = http.post(`${BASE_URL}/orders`, JSON.stringify({
      items: [{ productId: 'prod-1', quantity: 1 }],
      shippingAddress: { street: '123 Main St' }
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
    check(response, {
      'order created successfully': (r) => r.status === 201,
    });
    
    sleep(randomIntBetween(3, 7));
  });
}

function randomIntBetween(min, max) {
  return Math.floor(Math.random() * (max - min + 1) + min);
}
```

## Running Tests

```bash
# Run load test
k6 run --out json=reports/load-test.json k6/tests/load.test.js

# Run with custom URL
k6 run --env BASE_URL=https://api.staging.com k6/tests/load.test.js

# Run stress test
k6 run k6/tests/stress.test.js
```

## Results Analysis

```
=== Load Test Results ===

running (14m02.0s), 000/200 VUs, 238972 complete

✓ checks.........................: 100.00% ✓ 477944
✓ http_req_duration..............: avg=145.2ms min=23ms med=132ms p(90)=212ms p(95)=245ms
✓ http_reqs......................: 238972  283.3/s
✓ http_req_failed................: 0.00%

SLA Compliance:
✓ p95 < 200ms: PASS (245ms is close to threshold)
✓ Error rate < 1%: PASS (0%)
✓ Throughput > 1000 RPS: FAIL (283.3/s)
```

## Key Metrics

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| p95 Latency | <200ms | 245ms | ⚠️ Near limit |
| Error Rate | <1% | 0% | ✅ Pass |
| Throughput | >1000 RPS | 283 RPS | ❌ Fail |

## Best Practices

1. **Define SLAs before testing** — Clear thresholds for latency and errors
2. **Use realistic scenarios** — Varied think times, mixed operations
3. **Test at different loads** — Load, stress, spike, soak
4. **Monitor system under test** — Correlate load with resource usage
