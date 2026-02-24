# Flow Control Utilities

Production-ready flow control patterns for Node.js.

## Retry with Exponential Backoff

```javascript
#!/usr/bin/env node
class FlowControl {
    static async retry(fn, maxAttempts = 3, delay = 1000) {
        let lastError;
        
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return await fn();
            } catch (error) {
                lastError = error;
                if (attempt === maxAttempts) throw error;
                await new Promise(resolve => 
                    setTimeout(resolve, delay * Math.pow(2, attempt - 1))
                );
            }
        }
        
        throw lastError;
    }
    
    static async withTimeout(promise, timeoutMs) {
        const timeout = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Timeout')), timeoutMs);
        });
        return Promise.race([promise, timeout]);
    }
    
    static circuitBreaker(fn, options = {}) {
        const {
            failureThreshold = 5,
            resetTimeout = 60000,
        } = options;
        
        let state = 'CLOSED';
        let failures = 0;
        let lastFailureTime = 0;
        
        return async (...args) => {
            if (state === 'OPEN') {
                if (Date.now() - lastFailureTime > resetTimeout) {
                    state = 'HALF_OPEN';
                } else {
                    throw new Error('Circuit breaker is OPEN');
                }
            }
            
            try {
                const result = await fn(...args);
                if (state === 'HALF_OPEN') {
                    state = 'CLOSED';
                    failures = 0;
                }
                return result;
            } catch (error) {
                failures++;
                lastFailureTime = Date.now();
                if (failures >= failureThreshold) state = 'OPEN';
                throw error;
            }
        };
    }
    
    static async processBatch(items, processor, concurrency = 5) {
        const results = [];
        const executing = [];
        
        for (const item of items) {
            const promise = processor(item).then(result => {
                results.push(result);
                executing.splice(executing.indexOf(promise), 1);
            });
            
            executing.push(promise);
            if (executing.length >= concurrency) {
                await Promise.race(executing);
            }
        }
        
        await Promise.all(executing);
        return results;
    }
}
```

## Pattern Matching Utility

```javascript
#!/usr/bin/env node
class Matcher {
    constructor(value) {
        this.value = value;
        this.matches = [];
    }
    
    when(condition, result) {
        this.matches.push({ condition, result });
        return this;
    }
    
    default(result) {
        this.defaultResult = result;
        return this;
    }
    
    exec() {
        for (const match of this.matches) {
            if (typeof match.condition === 'function' ? 
                match.condition(this.value) : 
                this.value === match.condition) {
                return typeof match.result === 'function' ? 
                    match.result(this.value) : match.result;
            }
        }
        return typeof this.defaultResult === 'function' ? 
            this.defaultResult(this.value) : this.defaultResult;
    }
}

const match = (value) => new Matcher(value);

// Usage
const result = match(user)
    .when(u => u.age < 18, 'Minor')
    .when(u => u.age >= 18 && u.age < 65, 'Adult')
    .when(u => u.age >= 65, 'Senior')
    .default('Unknown')
    .exec();
```
