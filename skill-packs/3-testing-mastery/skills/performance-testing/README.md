# Performance Testing

Test system performance under load — measure response times, throughput, and identify bottlenecks.

## Quick Start

```javascript
// k6 load test
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  vus: 50,
  duration: '10m',
  thresholds: {
    http_req_duration: ['p(95)<200'],
  },
};

export default function () {
  const response = http.get('https://api.example.com');
  check(response, {
    'status is 200': (r) => r.status === 200,
  });
}
```

## Test Types

| Type | Purpose | Duration |
|------|---------|----------|
| **Load** | Normal expected load | Minutes |
| **Stress** | Breaking point | Minutes |
| **Spike** | Sudden load changes | Seconds |
| **Soak** | Memory leaks | Hours |

## Key Metrics

- **Response Time** — p50, p95, p99
- **Throughput** — Requests/sec
- **Error Rate** — % failed
- **Resource Usage** — CPU, memory

## Python (Locust)

```python
from locust import HttpUser, task, between

class WebsiteUser(HttpUser):
    wait_time = between(1, 5)
    
    @task
    def view_page(self):
        self.client.get("/")
```

## Key Principles

- Mirror production environment
- Use realistic data volumes
- Monitor system under test
- Look for trends, not single measurements

## Examples

See `examples/basic-examples.md` for full performance testing examples.

## Related Skills

- `test-strategy` — When to performance test
- `integration-testing` — Test before load testing
- `test-automation` — Automate performance tests
