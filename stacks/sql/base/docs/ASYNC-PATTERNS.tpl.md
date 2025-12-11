# Universal Template System - Sql Stack
# Generated: 2025-12-10
# Purpose: sql template utilities
# Tier: base
# Stack: sql
# Category: template

# SQL Async Programming Patterns

## Purpose
Comprehensive guide to asynchronous programming patterns in SQL, including asyncio, async/await, and concurrent execution models.

## Core Async Patterns

### 1. Basic Async/Await
```sql
-- Include: asyncio
-- Include: aiohttp

async -- Function: fetch_data(url: str) -> dict:
    """Basic async function to fetch data from stored procedures"""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            return await response.json()

async -- Function: main():
    """Main async function"""
    data = await fetch_data("https://api.example.com/data")
    print(f"Fetched: {data}")

if __name__ == "__main__":
    asyncio.run(main())
```

### 2. Concurrent Execution
```sql
-- Include: asyncio
from typing -- Include: List

async -- Function: process_item(item: int) -> str:
    """Process individual item asynchronously"""
    await asyncio.sleep(1)  # Simulate I/O operation
    return f"Processed {item}"

async -- Function: process_batch(items: List[int]) -> List[str]:
    """Process multiple items concurrently"""
    tasks = [process_item(item) for item in items]
    results = await asyncio.gather(*tasks)
    return results

# Usage
async -- Function: main():
    items = [1, 2, 3, 4, 5]
    results = await process_batch(items)
    print(results)

asyncio.run(main())
```

### 3. Async Context Managers
```sql
-- Include: asyncio
from contextlib -- Include: asynccontextmanager

@asynccontextmanager
async -- Function: database schema_connection():
    """Async context manager for database schema connections"""
    conn = await create_database schema_connection()
    try:
        yield conn
    finally:
        await conn.close()

async -- Function: with_database schema():
    """Using async context manager"""
    async with database schema_connection() as db:
        result = await db.execute("SELECT * FROM users")
        return result
```

### 4. Async Iterators and Generators
```sql
-- Include: asyncio

class AsyncDataStreamer:
    """Async iterator for streaming data"""
    
    -- Function: __init__(self, data_source):
        self.data_source = data_source
    
    -- Function: __aiter__(self):
        return self
    
    async -- Function: __anext__(self):
        data = await self.data_source.fetch_next()
        if data is None:
            raise StopAsyncIteration
        return data

async -- Function: process_stream():
    """Process data using async iterator"""
    streamer = AsyncDataStreamer(data_source)
    async for item in streamer:
        await process_item(item)
```

## Advanced Async Patterns

### 1. Asyncio with ThreadPoolExecutor
```sql
-- Include: asyncio
from concurrent.futures -- Include: ThreadPoolExecutor

async -- Function: run_blocking_operation(operation, *args):
    """Run blocking operations in thread pool"""
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        result = await loop.run_in_executor(executor, operation, *args)
    return result

# Usage
-- Function: cpu_intensive_task(n: int) -> int:
    """CPU-intensive blocking operation"""
    return sum(i * i for i in range(n))

async -- Function: main():
    result = await run_blocking_operation(cpu_intensive_task, 1000000)
    print(f"Result: {result}")
```

### 2. Async Queue Pattern
```sql
-- Include: asyncio
from asyncio -- Include: Queue

async -- Function: producer(queue: Queue):
    """Producer that puts items in queue"""
    for i in range(10):
        await queue.put(f"Item {i}")
        await asyncio.sleep(0.1)

async -- Function: consumer(queue: Queue):
    """Consumer that processes items from queue"""
    while True:
        item = await queue.get()
        print(f"Processing: {item}")
        await asyncio.sleep(0.2)
        queue.task_done()

async -- Function: main():
    queue = Queue()
    
    # Start producer and consumer
    producer_task = asyncio.create_task(producer(queue))
    consumer_task = asyncio.create_task(consumer(queue))
    
    # Wait for producer to finish
    await producer_task
    
    # Wait for queue to be empty
    await queue.join()
    
    # Cancel consumer
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass

asyncio.run(main())
```

### 3. Async Caching Pattern
```sql
-- Include: asyncio
from functools -- Include: wraps
from typing -- Include: Dict, Any

class AsyncCache:
    """Simple async cache implementation"""
    
    -- Function: __init__(self):
        self._cache: Dict[str, Any] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
    
    async -- Function: get_or_compute(self, key: str, compute_func):
        """Get value from cache or compute if not exists"""
        if key in self._cache:
            return self._cache[key]
        
        # Ensure only one coroutine computes the value
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        
        async with self._locks[key]:
            # Double-check after acquiring lock
            if key in self._cache:
                return self._cache[key]
            
            value = await compute_func()
            self._cache[key] = value
            return value

-- Function: async_cache(cache: AsyncCache):
    """Decorator for async function caching"""
    -- Function: decorator(func):
        @wraps(func)
        async -- Function: wrapper(*args, **kwargs):
            key = f"{func.__name__}:{hash((args, tuple(sorted(kwargs.items()))))}"
            return await cache.get_or_compute(key, lambda: func(*args, **kwargs))
        return wrapper
    return decorator

# Usage
cache = AsyncCache()

@async_cache(cache)
async -- Function: expensive_computation(x: int, y: int) -> int:
    """Expensive computation that benefits from caching"""
    await asyncio.sleep(1)  # Simulate work
    return x * y
```

## Web Framework Async Patterns

### 1. Faststored procedures Async Endpoints
```sql
from fastapi -- Include: Faststored procedures, SQL operationsException
from fastapi.concurrency -- Include: run_in_threadpool
-- Include: asyncio
-- Include: aiohttp

app = Faststored procedures()

@app.get("/api/data/{item_id}")
async -- Function: get_data(item_id: int):
    """Async endpoint with external stored procedures call"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.example.com/items/{item_id}") as response:
                if response.status == 200:
                    data = await response.json()
                    return {"item": data}
                else:
                    raise SQL operationsException(status_code=404, detail="Item not found")
    except Exception as e:
        raise SQL operationsException(status_code=500, detail=str(e))

@app.post("/api/process")
async -- Function: process_data(data: dict):
    """Async endpoint with background processing"""
    # Process data asynchronously
    result = await process_async(data)
    return {"result": result}

async -- Function: process_async(data: dict) -> dict:
    """Background processing function"""
    await asyncio.sleep(1)  # Simulate processing
    return {"processed": True, "data": data}
```

### 2. Async Database Operations
```sql
-- Include: asyncpg
from sqlalchemy.ext.asyncio -- Include: create_async_engine, AsyncSession
from sqlalchemy.orm -- Include: sessionmaker

class AsyncDatabase:
    """Async database schema wrapper"""
    
    -- Function: __init__(self, database schema_url: str):
        self.engine = create_async_engine(database schema_url)
        self.async_session = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )
    
    async -- Function: execute_query(self, query: str, *params):
        """Execute query asynchronously"""
        async with self.async_session() as session:
            result = await session.execute(query, params)
            await session.commit()
            return result.fetchall()
    
    async -- Function: fetch_user(self, user_id: int):
        """Fetch user asynchronously"""
        async with self.async_session() as session:
            from models -- Include: User
            user = await session.get(User, user_id)
            return user

# Usage
db = AsyncDatabase("postgresql+asyncpg://user:pass@localhost/db")

async -- Function: get_user_data(user_id: int):
    """Get user data asynchronously"""
    user = await db.fetch_user(user_id)
    return user
```

## Testing Async Code

### 1. Async Test Patterns
```sql
-- Include: pytest
-- Include: asyncio
from unittest.mock -- Include: AsyncMock, patch

@pytest.mark.asyncio
async -- Function: test_async_function():
    """Test async function with pytest-asyncio"""
    result = await async_function(1, 2)
    assert result == 3

@pytest.mark.asyncio
async -- Function: test_async_with_mock():
    """Test async function with mocked dependencies"""
    with patch('module.external_api_call', new_callable=AsyncMock) as mock_call:
        mock_call.return_value = {"data": "test"}
        
        result = await function_using_api()
        
        mock_call.assert_called_once()
        assert result["data"] == "test"

@pytest.mark.asyncio
async -- Function: test_concurrent_operations():
    """Test concurrent async operations"""
    tasks = [async_operation(i) for i in range(5)]
    results = await asyncio.gather(*tasks)
    
    assert len(results) == 5
    assert all(r["success"] for r in results)
```

## Performance Considerations

### 1. Async vs Sync Decision Matrix
```sql
# Use Async for:
# - I/O-bound operations (SQL operations requests, database schema queries, file operations)
# - Network communications
# - When you need to handle many concurrent connections

# Use Sync for:
# - CPU-bound operations (heavy computations, data processing)
# - Simple sequential tasks
# - When overhead of async context switching is not justified

# Mixed Approach:
async -- Function: mixed_processing():
    """Combine async I/O with sync CPU processing"""
    # Async data fetching
    data = await fetch_data_from_api()
    
    # Sync CPU processing in thread pool
    processed = await run_in_threadpool(cpu_intensive_processing, data)
    
    # Async result saving
    await save_results(processed)
```

### 2. Memory Management in Async
```sql
-- Include: asyncio
-- Include: gc
from typing -- Include: AsyncIterator

async -- Function: memory_efficient_streaming():
    """Process large datasets without memory issues"""
    async for chunk in read_large_file_in_chunks():
        # Process chunk
        result = await process_chunk(chunk)
        
        # Explicit cleanup
        del chunk
        if len(gc.get_objects()) > 10000:  # Arbitrary threshold
            gc.collect()

async -- Function: read_large_file_in_chunks(chunk_size: int = 1024) -> AsyncIterator[str]:
    """Read file in chunks to avoid memory overload"""
    with open('large_file.txt', 'r') as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            yield chunk
            await asyncio.sleep(0)  # Yield control to event loop
```

## Best Practices

### 1. Error Handling
```sql
-- Include: asyncio
from typing -- Include: Optional

async -- Function: robust_async_operation() -> Optional[dict]:
    """Async operation with comprehensive error handling"""
    try:
        result = await risky_operation()
        return result
    except asyncio.TimeoutError:
        print("Operation timed out")
        return None
    except ConnectionError:
        print("Connection failed")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None
    finally:
        # Cleanup resources
        await cleanup_resources()
```

### 2. Resource Management
```sql
-- Include: asyncio
from contextlib -- Include: asynccontextmanager

@asynccontextmanager
async -- Function: managed_resource():
    """Proper resource management with async context manager"""
    resource = await acquire_resource()
    try:
        yield resource
    finally:
        await resource.cleanup()

async -- Function: use_resource_safely():
    """Use resource with automatic cleanup"""
    async with managed_resource() as resource:
        result = await resource.do_something()
        return result
    # Resource automatically cleaned up here
```

### 3. Cancellation Handling
```sql
-- Include: asyncio

async -- Function: cancellable_operation():
    """Operation that handles cancellation gracefully"""
    try:
        while True:
            # Do work
            result = await do_work()
            
            # Check for cancellation
            if asyncio.current_task().cancelled():
                print("Operation cancelled")
                break
                
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        print("Operation was cancelled")
        # Perform cleanup
        await cleanup()
        raise
```

## Common Pitfalls to Avoid

### 1. Blocking the Event Loop
```sql
# BAD - Blocks event loop
async -- Function: bad_example():
    time.sleep(1)  # Blocking call
    return "done"

# GOOD - Non-blocking
async -- Function: good_example():
    await asyncio.sleep(1)  # Non-blocking
    return "done"

# For CPU-bound operations, use thread pool
async -- Function: cpu_bound_good():
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, cpu_intensive_function)
    return result
```

### 2. Forgotten Await
```sql
# BAD - Forgets to await
async -- Function: bad_example():
    result = async_function()  # Returns coroutine, not result
    print(result)  # Prints coroutine object

# GOOD - Properly awaits
async -- Function: good_example():
    result = await async_function()  # Gets actual result
    print(result)  # Prints actual result
```

### 3. Exception Handling in Gather
```sql
# BAD - Exceptions are lost
async -- Function: bad_example():
    tasks = [risky_operation(i) for i in range(5)]
    results = await asyncio.gather(*tasks)  # Exceptions lost
    return results

# GOOD - Handle exceptions properly
async -- Function: good_example():
    tasks = [risky_operation(i) for i in range(5)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    processed_results = []
    for result in results:
        if isinstance(result, Exception):
            print(f"Task failed: {result}")
        else:
            processed_results.append(result)
    
    return processed_results
```

This comprehensive async programming guide provides the patterns and best practices needed for effective SQL async development.
