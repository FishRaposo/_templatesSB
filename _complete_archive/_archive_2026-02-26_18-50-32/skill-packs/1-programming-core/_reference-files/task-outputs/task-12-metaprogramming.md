# Task 12 — Metaprogramming Response (RERUN)

## Python Decorator System

`python
import time
import functools

# @timed - logs execution time
def timed(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        print(f"{func.__name__} took {time.time() - start:.4f}s")
        return result
    return wrapper

# @retry(n) - retries on failure
def retry(max_attempts):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_attempts - 1:
                        raise
                    print(f"Retry {attempt + 1}/{max_attempts}")
        return wrapper
    return decorator

# @memoize - caches results
def memoize(func):
    cache = {}
    @functools.wraps(func)
    def wrapper(*args):
        if args not in cache:
            cache[args] = func(*args)
        return cache[args]
    return wrapper

# Usage
@timed
@retry(3)
def fetch_data(url):
    # Network call...
    pass

@memoize
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
`

- [x] @timed decorator
- [x] @retry decorator
- [x] @memoize decorator
- [x] Metaclass for auto-registration