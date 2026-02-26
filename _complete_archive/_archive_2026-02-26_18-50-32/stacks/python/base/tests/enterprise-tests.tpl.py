#!/usr/bin/env python3
"""
File: enterprise-tests.tpl.py
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
"""

# -----------------------------------------------------------------------------
# FILE: enterprise-tests.tpl.py
# PURPOSE: Enterprise-level testing templates with advanced patterns
# USAGE: Load testing, chaos engineering, fault injection, and resilience testing
# DEPENDENCIES: locust, pytest, asyncio, concurrent.futures, chaospy, prometheus_client
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
Python Enterprise Testing Template
Purpose: Enterprise-level testing templates with advanced patterns
Usage: Load testing, chaos engineering, fault injection, and resilience testing
"""

import asyncio
import concurrent.futures
import json
import logging
import random
import time
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable, Union, AsyncGenerator
from unittest.mock import patch, MagicMock
import statistics
import psutil
import socket
import os
import signal
import subprocess
import sys

import pytest
import httpx
import requests
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import redis
from elasticsearch import Elasticsearch

# =============================================================================
# LOAD TESTING FRAMEWORK
# =============================================================================

@dataclass
class LoadTestConfig:
    """Configuration for load testing"""
    base_url: str
    endpoints: List[Dict[str, Any]]
    concurrent_users: int = 100
    ramp_up_time: int = 60  # seconds
    test_duration: int = 300  # seconds
    think_time: float = 1.0  # seconds between requests
    timeout: int = 30  # request timeout
    auth_token: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    metrics_port: int = 8000

@dataclass
class LoadTestMetrics:
    """Metrics collected during load testing"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    response_times: List[float] = field(default_factory=list)
    error_counts: Dict[str, int] = field(default_factory=dict)
    throughput: float = 0.0  # requests per second
    avg_response_time: float = 0.0
    p95_response_time: float = 0.0
    p99_response_time: float = 0.0
    error_rate: float = 0.0

class LoadTester:
    """Enterprise-grade load testing framework"""
    
    def __init__(self, config: LoadTestConfig):
        self.config = config
        self.metrics = LoadTestMetrics()
        self.session = requests.Session()
        self.setup_session()
        self.setup_prometheus_metrics()
    
    def setup_session(self):
        """Setup HTTP session with configuration"""
        self.session.headers.update(self.config.headers)
        if self.config.auth_token:
            self.session.headers['Authorization'] = f'Bearer {self.config.auth_token}'
    
    def setup_prometheus_metrics(self):
        """Setup Prometheus metrics collection"""
        self.request_counter = Counter('load_test_requests_total', 'Total requests', ['endpoint', 'status'])
        self.response_time_histogram = Histogram('load_test_response_time_seconds', 'Response times', ['endpoint'])
        self.active_users_gauge = Gauge('load_test_active_users', 'Number of active users')
        
        # Start Prometheus metrics server
        start_http_server(self.config.metrics_port)
    
    def make_request(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Make a single request and collect metrics"""
        start_time = time.time()
        result = {
            'success': False,
            'response_time': 0,
            'status_code': None,
            'error': None
        }
        
        try:
            method = endpoint.get('method', 'GET')
            url = f"{self.config.base_url}{endpoint['path']}"
            params = endpoint.get('params', {})
            data = endpoint.get('data', {})
            json_data = endpoint.get('json', {})
            
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json_data,
                timeout=self.config.timeout
            )
            
            result['success'] = 200 <= response.status_code < 400
            result['status_code'] = response.status_code
            
        except Exception as e:
            result['error'] = str(e)
        
        finally:
            result['response_time'] = time.time() - start_time
            
            # Update Prometheus metrics
            status = 'success' if result['success'] else 'error'
            self.request_counter.labels(endpoint=endpoint['path'], status=status).inc()
            self.response_time_histogram.labels(endpoint=endpoint['path']).observe(result['response_time'])
        
        return result
    
    def simulate_user(self, user_id: int, stop_event: threading.Event):
        """Simulate a single user's behavior"""
        self.active_users_gauge.inc()
        
        try:
            while not stop_event.is_set():
                # Select random endpoint based on weights
                endpoint = random.choices(
                    self.config.endpoints,
                    weights=[ep.get('weight', 1) for ep in self.config.endpoints]
                )[0]
                
                result = self.make_request(endpoint)
                
                # Update metrics
                self.metrics.total_requests += 1
                self.metrics.response_times.append(result['response_time'])
                
                if result['success']:
                    self.metrics.successful_requests += 1
                else:
                    self.metrics.failed_requests += 1
                    error_key = result['error'] or f"HTTP_{result['status_code']}"
                    self.metrics.error_counts[error_key] = self.metrics.error_counts.get(error_key, 0) + 1
                
                # Think time between requests
                if self.config.think_time > 0:
                    time.sleep(self.config.think_time)
        
        finally:
            self.active_users_gauge.dec()
    
    def ramp_up_users(self, stop_event: threading.Event):
        """Gradually ramp up concurrent users"""
        ramp_interval = self.config.ramp_up_time / self.config.concurrent_users
        active_threads = []
        
        for i in range(self.config.concurrent_users):
            if stop_event.is_set():
                break
            
            thread = threading.Thread(target=self.simulate_user, args=(i, stop_event))
            thread.start()
            active_threads.append(thread)
            
            time.sleep(ramp_interval)
        
        return active_threads
    
    def run_load_test(self) -> LoadTestMetrics:
        """Execute the load test"""
        print(f"Starting load test: {self.config.concurrent_users} users for {self.config.test_duration}s")
        print(f"Prometheus metrics available at http://localhost:{self.config.metrics_port}")
        
        stop_event = threading.Event()
        start_time = time.time()
        
        # Start user threads
        active_threads = self.ramp_up_users(stop_event)
        
        # Run for specified duration
        time.sleep(self.config.test_duration)
        
        # Stop all threads
        stop_event.set()
        for thread in active_threads:
            thread.join(timeout=10)
        
        # Calculate final metrics
        end_time = time.time()
        total_time = end_time - start_time
        
        self.metrics.throughput = self.metrics.total_requests / total_time
        self.metrics.avg_response_time = statistics.mean(self.metrics.response_times) if self.metrics.response_times else 0
        self.metrics.p95_response_time = statistics.quantiles(self.metrics.response_times, n=20)[18] if len(self.metrics.response_times) > 20 else 0
        self.metrics.p99_response_time = statistics.quantiles(self.metrics.response_times, n=100)[98] if len(self.metrics.response_times) > 100 else 0
        self.metrics.error_rate = (self.metrics.failed_requests / self.metrics.total_requests * 100) if self.metrics.total_requests > 0 else 0
        
        return self.metrics
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive load test report"""
        return {
            'test_config': {
                'base_url': self.config.base_url,
                'concurrent_users': self.config.concurrent_users,
                'test_duration': self.config.test_duration,
                'ramp_up_time': self.config.ramp_up_time
            },
            'metrics': {
                'total_requests': self.metrics.total_requests,
                'successful_requests': self.metrics.successful_requests,
                'failed_requests': self.metrics.failed_requests,
                'throughput_rps': round(self.metrics.throughput, 2),
                'avg_response_time_s': round(self.metrics.avg_response_time, 3),
                'p95_response_time_s': round(self.metrics.p95_response_time, 3),
                'p99_response_time_s': round(self.metrics.p99_response_time, 3),
                'error_rate_percent': round(self.metrics.error_rate, 2)
            },
            'error_breakdown': self.metrics.error_counts,
            'response_time_distribution': {
                'min': min(self.metrics.response_times) if self.metrics.response_times else 0,
                'max': max(self.metrics.response_times) if self.metrics.response_times else 0,
                'median': statistics.median(self.metrics.response_times) if self.metrics.response_times else 0
            }
        }

# =============================================================================
# CHAOS ENGINEERING FRAMEWORK
# =============================================================================

@dataclass
class ChaosExperiment:
    """Configuration for chaos experiment"""
    name: str
    description: str
    fault_type: str  # 'latency', 'error', 'resource', 'network'
    target_component: str
    parameters: Dict[str, Any]
    duration: int = 60  # seconds
    rollback_strategy: str = 'immediate'

class ChaosEngine:
    """Chaos engineering framework for resilience testing"""
    
    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger(__name__)
        self.active_experiments = []
        self.system_metrics = {}
    
    def inject_latency(self, target: str, delay_ms: int, jitter_ms: int = 0):
        """Inject network latency"""
        def latency_decorator(func):
            def wrapper(*args, **kwargs):
                actual_delay = delay_ms + random.randint(-jitter_ms, jitter_ms)
                time.sleep(actual_delay / 1000.0)
                return func(*args, **kwargs)
            return wrapper
        
        self.logger.info(f"Injecting {delay_ms}ms latency to {target}")
        return latency_decorator
    
    def inject_error(self, target: str, error_rate: float, error_type: Exception = Exception):
        """Inject errors into function calls"""
        def error_decorator(func):
            def wrapper(*args, **kwargs):
                if random.random() < error_rate:
                    raise error_type(f"Chaos injection error in {target}")
                return func(*args, **kwargs)
            return wrapper
        
        self.logger.info(f"Injecting {error_rate*100}% error rate to {target}")
        return error_decorator
    
    def consume_resources(self, cpu_percent: float = 80, memory_mb: int = 512, duration: int = 60):
        """Consume system resources"""
        def cpu_load():
            end_time = time.time() + duration
            while time.time() < end_time:
                # CPU intensive work
                sum(i * i for i in range(1000))
                time.sleep(0.01)
        
        def memory_load():
            # Allocate memory
            data = []
            try:
                while len(data) * 8 < memory_mb * 1024 * 1024:  # Approximate memory usage
                    data.append(b' ' * 1024 * 1024)  # 1MB chunks
                    time.sleep(0.1)
            except MemoryError:
                self.logger.warning("Memory limit reached during chaos experiment")
        
        self.logger.info(f"Starting resource consumption: CPU={cpu_percent}%, Memory={memory_mb}MB")
        
        # Start resource consumption in background
        cpu_thread = threading.Thread(target=cpu_load)
        memory_thread = threading.Thread(target=memory_load)
        
        cpu_thread.start()
        memory_thread.start()
        
        return cpu_thread, memory_thread
    
    def network_partition(self, target_host: str, port: int, duration: int = 60):
        """Simulate network partition"""
        def block_network():
            # Use iptables to block network (requires root)
            try:
                subprocess.run([
                    'sudo', 'iptables', '-A', 'OUTPUT', '-d', target_host,
                    '-p', 'tcp', '--dport', str(port), '-j', 'DROP'
                ], check=True)
                
                self.logger.info(f"Network partition active for {target_host}:{port}")
                time.sleep(duration)
                
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to create network partition: {e}")
            
            finally:
                # Clean up iptables rule
                try:
                    subprocess.run([
                        'sudo', 'iptables', '-D', 'OUTPUT', '-d', target_host,
                        '-p', 'tcp', '--dport', str(port), '-j', 'DROP'
                    ], check=True)
                except subprocess.CalledProcessError:
                    pass
        
        return threading.Thread(target=block_network)
    
    def run_experiment(self, experiment: ChaosExperiment) -> Dict[str, Any]:
        """Run a chaos experiment and collect metrics"""
        self.logger.info(f"Starting chaos experiment: {experiment.name}")
        
        # Collect baseline metrics
        baseline_metrics = self.collect_system_metrics()
        
        # Apply chaos
        chaos_thread = None
        try:
            if experiment.fault_type == 'latency':
                delay_ms = experiment.parameters.get('delay_ms', 1000)
                jitter_ms = experiment.parameters.get('jitter_ms', 200)
                # Apply latency injection (implementation depends on target)
                
            elif experiment.fault_type == 'error':
                error_rate = experiment.parameters.get('error_rate', 0.1)
                # Apply error injection (implementation depends on target)
                
            elif experiment.fault_type == 'resource':
                cpu_percent = experiment.parameters.get('cpu_percent', 80)
                memory_mb = experiment.parameters.get('memory_mb', 512)
                chaos_thread = self.consume_resources(cpu_percent, memory_mb, experiment.duration)
                
            elif experiment.fault_type == 'network':
                target_host = experiment.parameters.get('target_host')
                port = experiment.parameters.get('port')
                chaos_thread = self.network_partition(target_host, port, experiment.duration)
            
            if chaos_thread:
                if isinstance(chaos_thread, tuple):
                    for thread in chaos_thread:
                        thread.start()
                else:
                    chaos_thread.start()
            
            # Monitor during chaos
            chaos_metrics = []
            start_time = time.time()
            
            while time.time() - start_time < experiment.duration:
                metrics = self.collect_system_metrics()
                chaos_metrics.append(metrics)
                time.sleep(5)  # Collect metrics every 5 seconds
            
        finally:
            # Clean up chaos
            if chaos_thread:
                if isinstance(chaos_thread, tuple):
                    for thread in chaos_thread:
                        thread.join(timeout=10)
                else:
                    chaos_thread.join(timeout=10)
        
        # Collect recovery metrics
        recovery_metrics = self.collect_system_metrics()
        
        return {
            'experiment': experiment.name,
            'baseline_metrics': baseline_metrics,
            'chaos_metrics': chaos_metrics,
            'recovery_metrics': recovery_metrics,
            'duration': experiment.duration
        }
    
    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect current system metrics"""
        return {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': {
                'bytes_sent': psutil.net_io_counters().bytes_sent,
                'bytes_recv': psutil.net_io_counters().bytes_recv
            },
            'process_count': len(psutil.pids())
        }

# =============================================================================
# RESILIENCE TESTING
# =============================================================================

class ResilienceTester:
    """Framework for testing system resilience"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.chaos_engine = ChaosEngine()
    
    def test_circuit_breaker(self, service_name: str, failure_threshold: int = 5) -> Dict[str, Any]:
        """Test circuit breaker functionality"""
        results = {
            'service': service_name,
            'failure_threshold': failure_threshold,
            'circuit_opened': False,
            'recovery_time': None,
            'requests_during_outage': 0,
            'successful_requests': 0,
            'failed_requests': 0
        }
        
        # Simulate failures to trigger circuit breaker
        for i in range(failure_threshold + 2):
            try:
                response = requests.get(f"{self.base_url}/{service_name}", timeout=5)
                if response.status_code == 503:  # Service unavailable
                    results['circuit_opened'] = True
                    results['requests_during_outage'] += 1
                else:
                    results['successful_requests'] += 1
            except Exception:
                results['failed_requests'] += 1
                results['requests_during_outage'] += 1
        
        # Test recovery after wait time
        time.sleep(10)  # Wait for circuit breaker to potentially recover
        
        try:
            response = requests.get(f"{self.base_url}/{service_name}", timeout=5)
            if response.status_code == 200:
                results['recovery_time'] = 10  # Simplified recovery time
        except Exception:
            pass
        
        return results
    
    def test_retry_mechanism(self, endpoint: str, max_retries: int = 3) -> Dict[str, Any]:
        """Test retry mechanism with transient failures"""
        results = {
            'endpoint': endpoint,
            'max_retries': max_retries,
            'total_attempts': 0,
            'successful_after_retries': False,
            'final_success': False
        }
        
        # Simulate transient failures
        for attempt in range(max_retries + 1):
            results['total_attempts'] += 1
            
            try:
                # Add random delay to simulate recovery
                if attempt > 0:
                    time.sleep(random.uniform(0.5, 2.0))
                
                response = requests.get(f"{self.base_url}/{endpoint}", timeout=5)
                
                if response.status_code == 200:
                    if attempt > 0:
                        results['successful_after_retries'] = True
                    results['final_success'] = True
                    break
                    
            except Exception as e:
                if attempt == max_retries:
                    results['final_success'] = False
        
        return results
    
    def test_rate_limiting(self, endpoint: str, rate_limit: int = 100) -> Dict[str, Any]:
        """Test rate limiting functionality"""
        results = {
            'endpoint': endpoint,
            'rate_limit': rate_limit,
            'requests_sent': 0,
            'requests_accepted': 0,
            'requests_rejected': 0,
            'rate_limit_hit': False
        }
        
        # Send burst of requests
        start_time = time.time()
        
        for i in range(rate_limit + 20):  # Send more than rate limit
            results['requests_sent'] += 1
            
            try:
                response = requests.get(f"{self.base_url}/{endpoint}", timeout=5)
                
                if response.status_code == 429:  # Too Many Requests
                    results['requests_rejected'] += 1
                    results['rate_limit_hit'] = True
                elif response.status_code == 200:
                    results['requests_accepted'] += 1
                    
            except Exception:
                results['requests_rejected'] += 1
        
        results['test_duration'] = time.time() - start_time
        return results

# =============================================================================
# FAULT INJECTION FRAMEWORK
# =============================================================================

class FaultInjector:
    """Framework for injecting various types of faults"""
    
    def __init__(self):
        self.active_faults = {}
    
    def inject_database_fault(self, fault_type: str, target_table: str = None):
        """Inject database-related faults"""
        def database_fault_decorator(func):
            def wrapper(*args, **kwargs):
                if fault_type == 'connection_timeout':
                    time.sleep(random.uniform(5, 10))  # Simulate timeout
                    raise ConnectionError("Database connection timeout")
                
                elif fault_type == 'slow_query':
                    time.sleep(random.uniform(2, 5))  # Simulate slow query
                
                elif fault_type == 'deadlock':
                    raise Exception("Database deadlock detected")
                
                elif fault_type == 'constraint_violation':
                    raise Exception("Constraint violation")
                
                return func(*args, **kwargs)
            return wrapper
        
        return database_fault_decorator
    
    def inject_cache_fault(self, fault_type: str, cache_key: str = None):
        """Inject cache-related faults"""
        def cache_fault_decorator(func):
            def wrapper(*args, **kwargs):
                if fault_type == 'cache_miss':
                    # Simulate cache miss by not caching
                    pass
                
                elif fault_type == 'cache_stale':
                    # Simulate stale cache data
                    kwargs['_force_stale_cache'] = True
                
                elif fault_type == 'cache_unavailable':
                    raise ConnectionError("Cache service unavailable")
                
                return func(*args, **kwargs)
            return wrapper
        
        return cache_fault_decorator
    
    def inject_external_service_fault(self, service_name: str, fault_type: str):
        """Inject external service faults"""
        def service_fault_decorator(func):
            def wrapper(*args, **kwargs):
                if fault_type == 'timeout':
                    raise TimeoutError(f"External service {service_name} timeout")
                
                elif fault_type == 'rate_limit':
                    raise Exception(f"External service {service_name} rate limit exceeded")
                
                elif fault_type == 'service_unavailable':
                    raise ConnectionError(f"External service {service_name} unavailable")
                
                elif fault_type == 'invalid_response':
                    return {"error": "Invalid response from external service"}
                
                return func(*args, **kwargs)
            return wrapper
        
        return service_fault_decorator

# =============================================================================
# PYTEST FIXTURES FOR ENTERPRISE TESTING
# =============================================================================

@pytest.fixture
def load_test_config():
    """Configuration for load testing"""
    return LoadTestConfig(
        base_url="http://localhost:8000",
        endpoints=[
            {"path": "/api/users", "method": "GET", "weight": 3},
            {"path": "/api/products", "method": "GET", "weight": 2},
            {"path": "/api/orders", "method": "POST", "weight": 1, "data": {"user_id": 1}}
        ],
        concurrent_users=50,
        test_duration=60,
        ramp_up_time=30
    )

@pytest.fixture
def chaos_engine():
    """Chaos engineering engine"""
    return ChaosEngine()

@pytest.fixture
def resilience_tester():
    """Resilience testing framework"""
    return ResilienceTester("http://localhost:8000")

@pytest.fixture
def fault_injector():
    """Fault injection framework"""
    return FaultInjector()

# =============================================================================
# ENTERPRISE TEST EXAMPLES
# =============================================================================

@pytest.mark.enterprise
@pytest.mark.performance
def test_load_scenario(load_test_config):
    """Example load test"""
    tester = LoadTester(load_test_config)
    metrics = tester.run_load_test()
    report = tester.generate_report()
    
    # Assert performance requirements
    assert metrics.error_rate < 1.0, f"Error rate too high: {metrics.error_rate}%"
    assert metrics.avg_response_time < 2.0, f"Average response time too high: {metrics.avg_response_time}s"
    assert metrics.throughput > 10, f"Throughput too low: {metrics.throughput} RPS"
    
    print("Load test report:")
    print(json.dumps(report, indent=2))

@pytest.mark.enterprise
@pytest.mark.chaos
def test_database_resilience(chaos_engine, fault_injector):
    """Test database resilience with chaos engineering"""
    experiment = ChaosExperiment(
        name="database_latency_injection",
        description="Inject database latency to test resilience",
        fault_type="latency",
        target_component="database",
        parameters={"delay_ms": 2000, "jitter_ms": 500},
        duration=60
    )
    
    # Apply database fault injection
    @fault_injector.inject_database_fault("slow_query")
    def mock_database_operation():
        time.sleep(0.1)  # Normal operation
        return {"status": "success"}
    
    # Run chaos experiment
    results = chaos_engine.run_experiment(experiment)
    
    # Verify system handles the fault gracefully
    assert results['chaos_metrics'], "No chaos metrics collected"
    
    # Test that system recovers
    recovery_time = time.time()
    result = mock_database_operation()
    recovery_time = time.time() - recovery_time
    
    assert result['status'] == 'success', "System did not recover from database fault"
    assert recovery_time < 5.0, f"Recovery time too slow: {recovery_time}s"

@pytest.mark.enterprise
@pytest.mark.resilience
def test_circuit_breaker_pattern(resilience_tester):
    """Test circuit breaker implementation"""
    results = resilience_tester.test_circuit_breaker("api/users", failure_threshold=3)
    
    assert results['circuit_opened'], "Circuit breaker did not open as expected"
    assert results['requests_during_outage'] > 0, "No requests were made during outage"

@pytest.mark.enterprise
@pytest.mark.fault_injection
def test_external_service_failure(fault_injector):
    """Test handling of external service failures"""
    
    @fault_injector.inject_external_service_fault("payment_gateway", "timeout")
    def process_payment():
        return {"status": "success", "transaction_id": "12345"}
    
    # Test that system handles external service timeout gracefully
    with pytest.raises(TimeoutError):
        result = process_payment()
    
    # Test fallback mechanism
    @fault_injector.inject_external_service_fault("payment_gateway", "service_unavailable")
    def process_payment_with_fallback():
        try:
            # This would normally call external service
            raise ConnectionError("Service unavailable")
        except ConnectionError:
            # Fallback to alternative payment method
            return {"status": "fallback", "transaction_id": "fallback_12345"}
    
    result = process_payment_with_fallback()
    assert result['status'] == 'fallback', "Fallback mechanism did not work"

# =============================================================================
# PERFORMANCE BENCHMARKING
# =============================================================================

class PerformanceBenchmark:
    """Framework for performance benchmarking"""
    
    def __init__(self):
        self.results = {}
    
    def benchmark_function(self, func: Callable, iterations: int = 1000) -> Dict[str, Any]:
        """Benchmark a function's performance"""
        times = []
        
        for _ in range(iterations):
            start_time = time.perf_counter()
            result = func()
            end_time = time.perf_counter()
            times.append(end_time - start_time)
        
        return {
            'function': func.__name__,
            'iterations': iterations,
            'min_time': min(times),
            'max_time': max(times),
            'avg_time': statistics.mean(times),
            'median_time': statistics.median(times),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0,
            'p95': statistics.quantiles(times, n=20)[18] if len(times) > 20 else max(times),
            'p99': statistics.quantiles(times, n=100)[98] if len(times) > 100 else max(times)
        }
    
    def compare_performance(self, func1: Callable, func2: Callable, iterations: int = 1000) -> Dict[str, Any]:
        """Compare performance of two functions"""
        result1 = self.benchmark_function(func1, iterations)
        result2 = self.benchmark_function(func2, iterations)
        
        speedup = result2['avg_time'] / result1['avg_time'] if result1['avg_time'] > 0 else float('inf')
        
        return {
            'function1': result1,
            'function2': result2,
            'speedup': speedup,
            'faster_function': func1.__name__ if speedup > 1 else func2.__name__
        }

# Export main classes for easy import
__all__ = [
    "LoadTestConfig",
    "LoadTester",
    "ChaosExperiment",
    "ChaosEngine",
    "ResilienceTester",
    "FaultInjector",
    "PerformanceBenchmark"
]