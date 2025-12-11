# Tool Call Limits and Optimization

> Guidelines for optimizing tool calls and managing limits in {{PROJECT_NAME}}

## 🎯 Overview

This document provides guidelines for optimizing tool usage, managing call limits, and ensuring efficient operation when working with AI agents and automated systems in {{PROJECT_NAME}}.

## 📊 Current Limits

### Tool Call Limits
{{#each TOOL_LIMITS}}
- **{{tool_name}}**: {{limit}} calls per {{period}}
- **{{tool_name}}**: {{limit}} calls per {{period}}
- **{{tool_name}}**: {{limit}} calls per {{period}}
{{/each}}

### Rate Limits
- **API Calls**: {{API_RATE_LIMIT}} requests/minute
- **File Operations**: {{FILE_OP_LIMIT}} operations/minute
- **Concurrent Calls**: {{MAX_CONCURRENT}} simultaneous calls

## 🔄 Optimization Strategies

### 1. Batch Operations
```python
# Instead of multiple calls
for item in items:
    process_item(item)

# Use batch processing
batch_process(items)
```

### 2. Caching Results
```python
# Cache expensive operations
@lru_cache(maxsize=128)
def expensive_operation(param):
    return compute_result(param)
```

### 3. Parallel Processing
```python
# Process in parallel when possible
with ThreadPoolExecutor(max_workers={{MAX_WORKERS}}) as executor:
    futures = [executor.submit(process, item) for item in items]
    results = [f.result() for f in futures]
```

## 📋 Best Practices

### Tool Usage Guidelines
{{#each TOOL_GUIDELINES}}
- **{{tool}}**: {{guideline}}
{{/each}}

### Call Pattern Optimization
1. **Group Similar Operations**
   - Combine file reads/writes
   - Batch API requests
   - Aggregate data processing

2. **Minimize Redundant Calls**
   - Check cache before calling
   - Use conditional execution
   - Implement request deduplication

3. **Optimize Data Transfer**
   - Use compression for large data
   - Stream when possible
   - Limit response size

## 🚨 Common Pitfalls

### Excessive Tool Calls
**Problem**: Making too many individual calls
```python
# BAD: Individual calls
for file in files:
    content = read_file(file)
    process(content)
```

**Solution**: Batch operations
```python
# GOOD: Batch processing
contents = read_multiple_files(files)
process_batch(contents)
```

### Inefficient Patterns
- Polling instead of webhooks
- Synchronous calls where async is better
- Not using available bulk operations

### Memory Issues
- Loading entire datasets into memory
- Not cleaning up resources
- Ignoring garbage collection

## 🛠️ Implementation Examples

### File Operations
```python
# Optimized file handling
def process_files_efficiently(file_list):
    """Process multiple files efficiently"""
    # Batch read
    contents = {}
    for file_path in file_list:
        if file_path not in cache:
            contents[file_path] = read_file(file_path)
    
    # Batch process
    results = process_batch(contents)
    
    # Batch write if needed
    if results:
        write_multiple_files(results)
```

### API Calls
```python
# Rate-limited API client
class RateLimitedClient:
    def __init__(self, rate_limit={{RATE_LIMIT}}):
        self.rate_limit = rate_limit
        self.last_call = 0
    
    def call_api(self, endpoint, data):
        # Respect rate limits
        elapsed = time.time() - self.last_call
        if elapsed < (1 / self.rate_limit):
            time.sleep((1 / self.rate_limit) - elapsed)
        
        result = api_call(endpoint, data)
        self.last_call = time.time()
        return result
```

## 📊 Monitoring and Metrics

### Key Metrics to Track
- Tool call frequency
- Response times
- Error rates
- Cache hit ratios
- Resource usage

### Monitoring Implementation
```python
# Tool usage tracker
class ToolTracker:
    def __init__(self):
        self.calls = defaultdict(int)
        self.limits = {{TOOL_LIMITS_DICT}}
    
    def track_call(self, tool_name):
        self.calls[tool_name] += 1
        if self.calls[tool_name] > self.limits[tool_name]:
            raise ToolLimitExceeded(tool_name)
    
    def get_usage_report(self):
        return {
            tool: {
                'used': count,
                'limit': self.limits[tool],
                'remaining': self.limits[tool] - count
            }
            for tool, count in self.calls.items()
        }
```

## 🔧 Configuration

### Environment Variables
```bash
# Tool limits
TOOL_CALL_LIMIT={{DEFAULT_TOOL_LIMIT}}
API_RATE_LIMIT={{DEFAULT_API_RATE}}
MAX_CONCURRENT_CALLS={{DEFAULT_CONCURRENT}}

# Optimization settings
ENABLE_CACHING=true
CACHE_SIZE={{DEFAULT_CACHE_SIZE}}
BATCH_SIZE={{DEFAULT_BATCH_SIZE}}
```

### Configuration File
```yaml
# tool-limits.yml
limits:
  file_operations: 1000/hour
  api_calls: 500/minute
  search_queries: 200/minute

optimization:
  batch_size: 50
  cache_ttl: 3600
  enable_compression: true
  
monitoring:
  track_usage: true
  alert_threshold: 0.8
  report_interval: 300
```

## 🚀 Performance Tips

### 1. Use Appropriate Data Structures
```python
# Use sets for membership testing
valid_items = set(item_list)  # O(1) lookup
if item in valid_items:  # Fast check
    process(item)
```

### 2. Lazy Loading
```python
# Load data only when needed
def get_large_dataset():
    if not hasattr(self, '_dataset'):
        self._dataset = load_dataset()
    return self._dataset
```

### 3. Connection Pooling
```python
# Reuse connections
connection_pool = create_pool(max_size={{POOL_SIZE}})
with connection_pool.get_connection() as conn:
    result = execute_query(conn, query)
```

## 📝 Testing Optimization

### Load Testing
```python
def test_tool_limits():
    """Test that tool limits are respected"""
    tracker = ToolTracker()
    
    # Should not exceed limits
    for _ in range(LIMIT):
        tracker.track_call('test_tool')
    
    # Should raise exception
    with pytest.raises(ToolLimitExceeded):
        tracker.track_call('test_tool')
```

### Performance Benchmarks
```python
def benchmark_operation():
    """Benchmark operation performance"""
    start = time.time()
    result = perform_operation()
    duration = time.time() - start
    
    assert duration < MAX_DURATION
    return result
```

## 🔍 Troubleshooting

### Common Issues
1. **Rate Limit Exceeded**
   - Reduce call frequency
   - Implement backoff strategy
   - Use caching

2. **Memory Leaks**
   - Profile memory usage
   - Clean up resources
   - Use generators for large data

3. **Slow Performance**
   - Profile bottlenecks
   - Optimize algorithms
   - Consider parallel processing

### Debug Tools
```python
# Tool call profiler
def profile_tool_usage(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start
        
        log_tool_call(func.__name__, duration)
        return result
    return wrapper
```

## 📚 Related Documentation

- [docs/PROMPT-VALIDATION.md](PROMPT-VALIDATION.md) - Prompt optimization
- [WORKFLOW.md](../WORKFLOW.md) - Workflow optimization
- [EVALS.md](../EVALS.md) - Performance testing

---

## 🔄 Maintenance

### Regular Tasks
- Monitor tool usage patterns
- Update limits based on usage
- Optimize slow operations
- Review and update caching strategy

### Alerts
- Set up alerts for limit breaches
- Monitor error rates
- Track performance degradation

---

**Last Updated**: {{LAST_UPDATED_DATE}}  
**Next Review**: {{NEXT_REVIEW_DATE}}

---

*Follow these guidelines to ensure optimal performance and avoid hitting tool limits in {{PROJECT_NAME}}.*
