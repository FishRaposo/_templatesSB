# Performance Testing Examples

## k6 Load Test

```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

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

export default function() {
  const response = http.get('https://api.example.com/users');
  
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 200ms': (r) => r.timings.duration < 200,
  });
  
  sleep(1);
}
```

## Python (Locust)

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

# Run: locust -f locustfile.py --host=http://localhost:8000
```

## Go (Vegeta)

```go
package main

import (
    "fmt"
    "time"
    "github.com/tsenart/vegeta/v12/lib"
)

func main() {
    rate := vegeta.Rate{Freq: 1000, Per: time.Second}
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

## Stress Test (Find Breaking Point)

```javascript
export const options = {
  stages: [
    { duration: '2m', target: 100 },
    { duration: '5m', target: 100 },
    { duration: '2m', target: 300 },
    { duration: '5m', target: 300 },
    { duration: '2m', target: 500 },  // Push to breaking point
    { duration: '5m', target: 500 },
    { duration: '10m', target: 0 },   // Recovery
  ],
};
```

## Soak Test (Memory Leaks)

```javascript
export const options = {
  stages: [
    { duration: '2m', target: 100 },     // Ramp up
    { duration: '3h56m', target: 100 },  // Sustained load for 4 hours
    { duration: '2m', target: 0 },       // Ramp down
  ],
};
```

## Best Practices

- Define SLAs before testing (p95 < 200ms)
- Mirror production environment
- Use realistic data volumes
- Monitor system under test
- Look for trends, not single measurements
