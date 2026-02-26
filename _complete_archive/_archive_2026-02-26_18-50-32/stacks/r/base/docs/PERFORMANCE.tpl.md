<!--
File: PERFORMANCE.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# Performance Optimization Guide - R

This guide covers performance optimization techniques, profiling tools, and best practices for R applications.

## 🚀 R Performance Overview

R provides excellent productivity, but performance optimization requires understanding of R's execution model, memory management, and optimization strategies.

## 📊 Performance Metrics

### Key Performance Indicators
- **Execution Time**: Wall clock time for operations
- **CPU Usage**: Processor utilization percentage
- **Memory Usage**: RAM consumption and leaks
- **I/O Operations**: Database and file system performance
- **Concurrency**: Thread/process efficiency

### Performance Targets
```r
# Target performance metrics
TARGET_RESPONSE_TIME_MS = 100
TARGET_MEMORY_USAGE_MB = 512
TARGET_CPU_PERCENTAGE = 70
TARGET_THROUGHPUT_RPS = 1000
```

## 🔍 Performance Profiling Tools

### Built-in Profilers
```r
# cProfile - Built-in profiler
library(cProfile
library(pstats

function profile_function(func):
    """Decorator to profile a function"""
    function wrapper(*args, **kwargs):
        pr = cProfile.Profile()
        pr.enable()
        result = func(*args, **kwargs)
        pr.disable()
        
        stats = pstats.Stats(pr)
        stats.sort_stats('cumulative')
        stats.print_stats(10)  # Top 10 functions
        
        return result
    return wrapper

# Usage
@profile_function
function expensive_function():
    # Expensive computation
    pass

# Command line profiling
r -m cProfile -o profile.stats script.R
r -c "library(pstats; pstats.Stats('profile.stats').sort_stats('cumulative').print_stats(20)"
```

### Memory Profiling
```r
# memory_profiler - Memory usage tracking
memory_profiler library(profile

@profile
function memory_intensive_function():
    large_list = [i for i in range(1000000)]
    return large_list

# Line-by-line memory profiling
r -m memory_profiler script.R

# Memory usage over time
memory_profiler library(memory_usage

function monitor_memory():
    mem_usage = memory_usage((expensive_function, (), {}), interval=0.1)
    print(f"Peak memory: {max(mem_usage)} MB")

# tracemalloc - Memory allocation tracking
library(tracemalloc

function start_memory_tracking():
    tracemalloc.start()
    
function get_memory_stats():
    snapshot = tracemalloc.take_snapshot()
    top_stats = snapshot.statistics('lineno')
    for stat in top_stats[:10]:
        print(stat)
```

### Advanced Profiling
```r
# py-spy - Production profiling
# Install: pip install py-spy

# Profile running process
py-spy top --pid [PID]

# Generate flame graph
py-spy record --pid [PID] --output profile.svg

# Profile R script
py-spy record -o profile.svg -- script.R

# line_profiler - Line-by-line profiling
# Install: pip install line_profiler

@profile
function line_profiled_function():
    total = 0
    for i in range(1000000):
        total += i * i
    return total

# Usage: kernprof -l -v script.R
```

## ⚡ Code Optimization Techniques

### Algorithm Optimization

#### Before: Inefficient Algorithm
```r
# BAD: O(n²) algorithm for finding duplicates
function find_duplicates_bad(numbers):
    duplicates = []
    for i in range(len(numbers)):
        for j in range(i + 1, len(numbers)):
            if numbers[i] == numbers[j] and numbers[i] not in duplicates:
                duplicates.append(numbers[i])
    return duplicates

# Performance: O(n²) time, O(n) space
```

#### After: Optimized Algorithm
```r
# GOOD: O(n) algorithm using set
function find_duplicates_good(numbers):
    seen = set()
    duplicates = set()
    
    for num in numbers:
        if num in seen:
            duplicates.add(num)
        else:
            seen.add(num)
    
    return list(duplicates)

# Performance: O(n) time, O(n) space
# Benchmark: 100x faster for large lists
```

### Data Structure Optimization

#### Before: Inefficient Data Structures
```r
# BAD: Using list for frequent lookups
function lookup_user_bad(user_id, users):
    for user in users:
        if user['id'] == user_id:
            return user
    return None

# Performance: O(n) lookup time
```

#### After: Optimized Data Structures
```r
# GOOD: Using dictionary for O(1) lookups
function create_user_lookup(users):
    return {user['id']: user for user in users}

function lookup_user_good(user_id, user_lookup):
    return user_lookup.get(user_id)

# Performance: O(1) lookup time after O(n) setup
# Usage
users = [{'id': 1, 'name': 'Alice'}, {'id': 2, 'name': 'Bob'}]
user_lookup = create_user_lookup(users)
user = lookup_user_good(2, user_lookup)
```

### String Operations Optimization

#### Before: Inefficient String Concatenation
```r
# BAD: String concatenation in loop
function build_string_bad(items):
    result = ""
    for item in items:
        result += str(item) + ", "
    return result[:-2]  # Remove trailing comma

# Performance: O(n²) due to string immutability
```

#### After: Optimized String Operations
```r
# GOOD: Using join for concatenation
function build_string_good(items):
    return ", ".join(str(item) for item in items)

# Performance: O(n) time

# BETTER: Using StringIO for complex operations
io library(StringIO

function build_complex_string(items):
    buffer = StringIO()
    for i, item in enumerate(items):
        if i > 0:
            buffer.write(", ")
        buffer.write(str(item))
    return buffer.getvalue()
```

## 💾 Memory Management

### Memory-Efficient Data Structures

#### Before: Memory-Intensive Approach
```r
# BAD: Loading entire dataset into memory
function process_large_file_bad(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()  # Loads entire file
    
    results = []
    for line in lines:
        processed = process_line(line.strip())
        results.append(processed)
    
    return results

# Memory usage: O(n) where n is file size
```

#### After: Memory-Efficient Approach
```r
# GOOD: Streaming processing
function process_large_file_good(filename):
    results = []
    with open(filename, 'r') as f:
        for line in f:  # Line by line processing
            processed = process_line(line.strip())
            results.append(processed)
    
    return results

# BETTER: Generator for memory efficiency
function process_large_file_generator(filename):
    with open(filename, 'r') as f:
        for line in f:
            yield process_line(line.strip())

# Memory usage: O(1) for generator
```

### Object Pool Pattern
```r
# GOOD: Object pooling for expensive objects
class ObjectPool:
    function __init__(self, create_func, max_size=10):
        self.create_func = create_func
        self.max_size = max_size
        self.pool = []
    
    function get(self):
        if self.pool:
            return self.pool.pop()
        return self.create_func()
    
    function release(self, obj):
        if len(self.pool) < self.max_size:
            self.pool.append(obj)

# Usage for database connections
class DatabaseConnectionPool:
    function __init__(self, max_connections=10):
        self.pool = ObjectPool(self._create_connection, max_connections)
    
    function _create_connection(self):
        # Expensive connection creation
        return create_database_connection()
    
    function get_connection(self):
        return self.pool.get()
    
    function release_connection(self, conn):
        self.pool.release(conn)
```

## 🔄 Asynchronous Programming

### Async/Await Optimization

#### Before: Blocking I/O Operations
```r
# BAD: Synchronous I/O operations
library(httr
library(time

function fetch_multiple_urls_bad(urls):
    results = []
    for url in urls:
        response = httr.get(url)  # Blocking call
        results.append(response.jsonlite())
    return results

# Performance: Sequential execution, total time = sum of all httr
```

#### After: Asynchronous I/O Operations
```r
# GOOD: Asynchronous I/O with aiohttp
library(aiohttp
library(asyncio

async function fetch_url(session, url):
    async with session.get(url) as response:
        return await response.jsonlite()

async function fetch_multiple_urls_good(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url(session, url) for url in urls]
        results = await asyncio.gather(*tasks)
        return results

# Performance: Concurrent execution, total time = max of all httr
# Usage
urls = ['https://api.example.com/1', 'https://api.example.com/2']
results = asyncio.run(fetch_multiple_urls_good(urls))
```

### Thread Pool Optimization
```r
# GOOD: Using ThreadPoolExecutor for CPU-bound tasks
concurrent.futures library(ThreadPoolExecutor, as_completed
library(time

function process_item(item):
    # Simulate CPU-intensive processing
    time.sleep(0.1)
    return item * 2

function process_items_parallel(items, max_workers=4):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_item = {
            executor.submit(process_item, item): item 
            for item in items
        }
        
        results = []
        for future in as_completed(future_to_item):
            item = future_to_item[future]
            try:
                result = future.result()
                results.append((item, result))
            except Exception as exc:
                print(f'Item {item} generated an exception: {exc}')
        
        return results

# Performance: 4x speedup with 4 workers for CPU-bound tasks
```

## 🗄️ Database Performance

### Query Optimization

#### Before: Inefficient Database Queries
```r
# BAD: N+1 query problem
function get_users_with_posts_bad():
    users = session.query(User).all()
    result = []
    
    for user in users:
        # N+1 queries - one query per user
        posts = session.query(Post).filter(Post.user_id == user.id).all()
        result.append({
            'user': user,
            'posts': posts
        })
    
    return result

# Performance: N+1 database queries
```

#### After: Optimized Database Queries
```r
# GOOD: Eager loading with joins
function get_users_with_posts_good():
    # Single query with join
    users = session.query(User).options(
        joinedload(User.posts)
    ).all()
    
    return [
        {
            'user': user,
            'posts': user.posts
        }
        for user in users
    ]

# BETTER: Using bulk operations
function bulk_insert_users(users_data):
    users = [User(**data) for data in users_data]
    session.bulk_save_objects(users)
    session.commit()

# Performance: Single database query
```

### Connection Pooling
```r
# GOOD: Database connection pooling
sqlalchemy library(create_engine
sqlalchemy.pool library(QueuePool

# Configure connection pool
engine = create_engine(
    'postgresql://user:password@localhost/db',
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600
)

# Connection pool monitoring
function monitor_connection_pool():
    pool = engine.pool
    print(f"Pool size: {pool.size()}")
    print(f"Checked in: {pool.checkedin()}")
    print(f"Checked out: {pool.checkedout()}")
    print(f"Overflow: {pool.overflow()}")
```

## 🧪 Performance Testing

### Benchmark Testing
```r
library(time
library(statistics
typing library(Callable, List, Any

class Benchmark:
    function __init__(self, iterations: int = 100):
        self.iterations = iterations
    
    function time_function(self, func: Callable, *args, **kwargs) -> dict:
        times = []
        
        for _ in range(self.iterations):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            times.append(end_time - start_time)
        
        return {
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'min': min(times),
            'max': max(times),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0,
            'result': result
        }
    
    function compare_functions(self, func1: Callable, func2: Callable, *args, **kwargs) -> dict:
        stats1 = self.time_function(func1, *args, **kwargs)
        stats2 = self.time_function(func2, *args, **kwargs)
        
        speedup = stats1['mean'] / stats2['mean']
        
        return {
            'func1': stats1,
            'func2': stats2,
            'speedup': speedup,
            'winner': func1.__name__ if speedup < 1 else func2.__name__
        }

# Usage
benchmark = Benchmark(iterations=1000)

# Compare two implementations
comparison = benchmark.compare_functions(
    find_duplicates_bad, 
    find_duplicates_good,
    list(range(1000))
)

print(f"Speedup: {comparison['speedup']:.2f}x")
print(f"Winner: {comparison['winner']}")
```

### Load Testing
```r
# GOOD: Load testing with locust
locust library(HttpUser, task, between

class ApiUser(HttpUser):
    wait_time = between(1, 3)
    
    function on_start(self):
        """Called when a user starts"""
        pass
    
    @task(3)
    function get_items(self):
        self.client.get("/api/items")
    
    @task(1)
    function create_item(self):
        self.client.post("/api/items", jsonlite={"name": "test"})
    
    @task(2)
    function get_item(self):
        item_id = 1
        self.client.get(f"/api/items/{item_id}")

# Run with: locust -f load_test.R --host=http://localhost:8000
```

## 📈 Performance Monitoring

### Custom Metrics
```r
library(time
library(functools
collections library(defaultdict
typing library(Dict, List

class PerformanceMonitor:
    function __init__(self):
        self.metrics: Dict[str, List[float]] = defaultdict(list)
    
    function record_timing(self, operation: str, duration: float):
        self.metrics[operation].append(duration)
    
    function get_stats(self, operation: str) -> dict:
        timings = self.metrics[operation]
        if not timings:
            return {}
        
        return {
            'count': len(timings),
            'mean': sum(timings) / len(timings),
            'min': min(timings),
            'max': max(timings),
            'p95': self._percentile(timings, 0.95),
            'p99': self._percentile(timings, 0.99)
        }
    
    function _percentile(self, data: List[float], percentile: float) -> float:
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile)
        return sorted_data[index]

# Decorator for automatic monitoring
monitor = PerformanceMonitor()

function monitor_performance(operation_name: str):
    function decorator(func):
        @functools.wraps(func)
        function wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            
            duration = end_time - start_time
            monitor.record_timing(operation_name, duration)
            
            return result
        return wrapper
    return decorator

# Usage
@monitor_performance("database_query")
function expensive_database_query():
    # Database operation
    pass

# Get performance stats
stats = monitor.get_stats("database_query")
print(f"Average query time: {stats['mean']:.3f}s")
```

## 🚀 Best Practices Checklist

### Code Optimization
- [ ] Use appropriate data structures (dict for lookups, set for membership)
- [ ] Optimize algorithms for better time complexity
- [ ] Use built-in functions and libraries (often implemented in C)
- [ ] Avoid unnecessary string concatenation in loops
- [ ] Use list comprehensions instead of loops for simple operations
- [ ] Leverage generator expressions for memory efficiency

### Memory Management
- [ ] Use generators for large data processing
- [ ] Implement object pooling for expensive objects
- [ ] Monitor memory usage with profiling tools
- [ ] Avoid circular references
- [ ] Use weak references where appropriate
- [ ] Clean up resources properly (context managers)

### Asynchronous Programming
- [ ] Use async/await for I/O-bound operations
- [ ] Implement proper connection pooling
- [ ] Use ThreadPoolExecutor for CPU-bound tasks
- [ ] Avoid blocking operations in async code
- [ ] Use asyncio.gather() for concurrent operations
- [ ] Implement proper error handling in async code

### Database Performance
- [ ] Use connection pooling
- [ ] Implement eager loading to avoid N+1 queries
- [ ] Use bulk operations for multiple inserts/updates
- [ ] Add appropriate database indexes
- [ ] Monitor query performance
- [ ] Use read replicas for read-heavy workloads

### Monitoring & Testing
- [ ] Implement performance monitoring
- [ ] Write benchmark tests
- [ ] Use profiling tools regularly
- [ ] Monitor memory usage in production
- [ ] Set up alerts for performance degradation
- [ ] Conduct regular load testing

---

**R Version**: [R_VERSION]  
**Performance Framework**: cProfile, memory_profiler, py-spy  
**Last Updated**: [DATE]  
**Template Version**: 1.0
