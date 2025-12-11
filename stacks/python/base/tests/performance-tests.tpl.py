#!/usr/bin/env python3
"""
File: performance-tests.tpl.py
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
"""

# -----------------------------------------------------------------------------
# FILE: performance-tests.tpl.py
# PURPOSE: Performance testing patterns for Python projects
# USAGE: Test application performance under various load conditions
# DEPENDENCIES: pytest, pytest-asyncio, httpx, locust, psutil, memory_profiler
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
Python Performance Tests Template
Purpose: Performance testing patterns for Python projects
Usage: Test application performance under various load conditions
"""

import pytest
import asyncio
import httpx
import time
import psutil
import gc
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import json
import tempfile
import os
from memory_profiler import profile
from locust import HttpUser, task, between
from fastapi.testclient import TestClient

# Import your application modules here
# from your_app.main import app
# from your_app.database import get_db
# from your_app.services import UserService, ProductService

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of default event loop for test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="function")
def performance_client():
    """Create HTTP client optimized for performance testing"""
    return httpx.AsyncClient(
        timeout=30.0,
        limits=httpx.Limits(max_keepalive_connections=50, max_connections=100)
    )

class TestAPIPerformance:
    """Test API performance under various conditions"""
    
    @pytest.mark.asyncio
    async def test_api_response_time_under_load(self, performance_client: httpx.AsyncClient):
        """Test API response time under sustained load"""
        # Act - Generate sustained load
        start_time = time.time()
        response_times = []
        
        for i in range(100):  # 100 requests
            request_start = time.time()
            response = await performance_client.get("http://api:8000/performance-test")
            request_end = time.time()
            
            response_times.append(request_end - request_start)
            
            # Assert - Response should be successful
            assert response.status_code == 200
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Assert - Performance metrics
        avg_response_time = sum(response_times) / len(response_times)
        assert avg_response_time < 0.5, f"Average response time {avg_response_time:.3f}s exceeds 500ms threshold"
        assert total_time < 60, f"Total execution time {total_time:.2f}s exceeds 60s threshold"
        
        # Assert - 95th percentile
        sorted_times = sorted(response_times)
        p95_response_time = sorted_times[int(0.95 * len(sorted_times))]
        assert p95_response_time < 1.0, f"95th percentile {p95_response_time:.3f}s exceeds 1s threshold"
    
    @pytest.mark.asyncio
    async def test_concurrent_user_performance(self, performance_client: httpx.AsyncClient):
        """Test performance with concurrent users"""
        # Act - Simulate 50 concurrent users
        concurrent_users = 50
        requests_per_user = 10
        
        async def simulate_user(user_id):
            user_times = []
            for request_id in range(requests_per_user):
                start_time = time.time()
                response = await performance_client.get(
                    f"http://api:8000/user-performance?user_id={user_id}&req_id={request_id}"
                )
                end_time = time.time()
                
                user_times.append(end_time - start_time)
                assert response.status_code == 200
            
            return {
                "user_id": user_id,
                "avg_response_time": sum(user_times) / len(user_times),
                "total_time": sum(user_times)
            }
        
        # Execute concurrent users
        start_time = time.time()
        tasks = [simulate_user(user_id) for user_id in range(concurrent_users)]
        results = await asyncio.gather(*tasks)
        end_time = time.time()
        
        # Assert - Concurrent performance metrics
        total_time = end_time - start_time
        avg_user_time = sum(r["avg_response_time"] for r in results) / len(results)
        
        assert total_time < 30, f"Concurrent test completed in {total_time:.2f}s"
        assert avg_user_time < 1.0, f"Average user response time {avg_user_time:.3f}s exceeds 1s"
        
        # Assert - No user was significantly slower
        user_times = [r["avg_response_time"] for r in results]
        max_user_time = max(user_times)
        min_user_time = min(user_times)
        assert max_user_time / min_user_time < 3.0, "Performance variance too high between users"
    
    @pytest.mark.asyncio
    async def test_memory_usage_under_load(self, performance_client: httpx.AsyncClient):
        """Test memory usage during sustained load"""
        # Act - Monitor memory during load
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Generate sustained load
        for i in range(200):
            response = await performance_client.get("http://api:8000/memory-intensive")
            assert response.status_code == 200
            
            # Check memory every 50 requests
            if i % 50 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                memory_increase = current_memory - initial_memory
                
                # Assert - Memory usage reasonable
                assert memory_increase < 100, f"Memory increased by {memory_increase:.1f}MB"
        
        final_memory = process.memory_info().rss / 1024 / 1024
        total_memory_increase = final_memory - initial_memory
        
        # Assert - Total memory usage acceptable
        assert total_memory_increase < 200, f"Total memory increase {total_memory_increase:.1f}MB exceeds 200MB"
        
        # Force garbage collection
        gc.collect()
        after_gc_memory = process.memory_info().rss / 1024 / 1024
        memory_freed = final_memory - after_gc_memory
        
        # Assert - Garbage collection effective
        assert memory_freed > 0, "No memory freed after garbage collection"
    
    @pytest.mark.asyncio
    async def test_database_performance_under_load(self, performance_client: httpx.AsyncClient):
        """Test database performance under concurrent load"""
        # Act - Generate database load
        concurrent_operations = 20
        operations_per_thread = 50
        
        def database_operations():
            operation_times = []
            for i in range(operations_per_thread):
                start_time = time.time()
                response = performance_client.post(
                    "http://api:8000/db-operation",
                    json={"operation": "select", "table": "users", "id": i % 1000 + 1}
                )
                end_time = time.time()
                
                operation_times.append(end_time - start_time)
                assert response.status_code == 200
            
            return operation_times
        
        # Execute concurrent database operations
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=concurrent_operations) as executor:
            futures = [executor.submit(database_operations) for _ in range(concurrent_operations)]
            all_operation_times = []
            
            for future in as_completed(futures):
                all_operation_times.extend(future.result())
        
        end_time = time.time()
        
        # Assert - Database performance metrics
        total_time = end_time - start_time
        total_operations = len(all_operation_times)
        avg_operation_time = sum(all_operation_times) / total_operations
        
        assert total_time < 60, f"Database operations completed in {total_time:.2f}s"
        assert avg_operation_time < 0.1, f"Average DB operation time {avg_operation_time:.3f}s exceeds 100ms"
        assert total_operations == concurrent_operations * operations_per_thread, "All operations completed"

class TestLoadTesting:
    """Load testing with Locust integration"""
    
    @pytest.mark.asyncio
    async def test_load_testing_scenarios(self):
        """Test different load testing scenarios"""
        # This would integrate with Locust for actual load testing
        # Here we simulate the load testing patterns
        
        load_scenarios = [
            {
                "name": "Ramp-up Load",
                "users": 10,
                "spawn_rate": 2,
                "duration": 60,
                "expected_rps": 20
            },
            {
                "name": "Sustained Load",
                "users": 50,
                "spawn_rate": 50,
                "duration": 300,
                "expected_rps": 100
            },
            {
                "name": "Peak Load",
                "users": 200,
                "spawn_rate": 50,
                "duration": 120,
                "expected_rps": 500
            }
        ]
        
        for scenario in load_scenarios:
            # Act - Simulate load scenario
            start_time = time.time()
            
            # This would normally use Locust to generate actual load
            # Here we simulate the expected behavior
            await self._simulate_load_scenario(scenario)
            
            end_time = time.time()
            actual_duration = end_time - start_time
            
            # Assert - Load scenario completed successfully
            assert actual_duration >= scenario["duration"], f"Load scenario {scenario['name']} duration too short"
            assert actual_duration <= scenario["duration"] + 10, f"Load scenario {scenario['name']} exceeded expected duration"
    
    async def _simulate_load_scenario(self, scenario):
        """Simulate a load testing scenario"""
        # In real implementation, this would use Locust
        # Here we simulate the expected metrics
        await asyncio.sleep(scenario["duration"])
        
        # Simulate meeting RPS targets
        expected_requests = scenario["expected_rps"] * scenario["duration"]
        # In real test, we would verify actual requests >= expected

class TestScalabilityTesting:
    """Test application scalability"""
    
    @pytest.mark.asyncio
    async def test_horizontal_scalability(self, performance_client: httpx.AsyncClient):
        """Test horizontal scalability (adding more instances)"""
        # Act - Test with different numbers of API instances
        instance_counts = [1, 2, 4, 8]
        performance_metrics = []
        
        for instance_count in instance_counts:
            # Simulate load against multiple instances
            start_time = time.time()
            
            tasks = []
            for i in range(100):  # 100 requests distributed across instances
                instance_id = i % instance_count
                task = performance_client.get(f"http://api-instance-{instance_id}:8000/scalability-test")
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks)
            end_time = time.time()
            
            # Calculate metrics
            successful_responses = [r for r in responses if r.status_code == 200]
            success_rate = len(successful_responses) / len(responses)
            avg_response_time = sum(end_time - start_time for r in successful_responses) / len(successful_responses)
            
            performance_metrics.append({
                "instance_count": instance_count,
                "success_rate": success_rate,
                "avg_response_time": avg_response_time,
                "throughput": len(successful_responses) / (end_time - start_time)
            })
        
        # Assert - Scalability improvements
        baseline_throughput = performance_metrics[0]["throughput"]
        
        for i in range(1, len(performance_metrics)):
            current_throughput = performance_metrics[i]["throughput"]
            scaling_efficiency = current_throughput / (baseline_throughput * performance_metrics[i]["instance_count"])
            
            # Assert - Reasonable scaling efficiency (should be close to linear)
            assert scaling_efficiency > 0.7, f"Poor scaling efficiency at {performance_metrics[i]['instance_count']} instances"
    
    @pytest.mark.asyncio
    async def test_vertical_scalability(self, performance_client: httpx.AsyncClient):
        """Test vertical scalability (increasing resources)"""
        # Act - Test with different resource allocations
        resource_configs = [
            {"cpu": 1, "memory": "1GB", "name": "Small"},
            {"cpu": 2, "memory": "2GB", "name": "Medium"},
            {"cpu": 4, "memory": "4GB", "name": "Large"}
        ]
        
        performance_by_config = {}
        
        for config in resource_configs:
            # Simulate testing with different resource configs
            start_time = time.time()
            
            # Generate load appropriate for resource level
            load_factor = config["cpu"]  # More CPU = more concurrent requests
            tasks = []
            
            for i in range(load_factor * 20):
                task = performance_client.get(f"http://api-{config['name'].lower()}:8000/resource-test")
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks)
            end_time = time.time()
            
            # Calculate performance
            successful_responses = [r for r in responses if r.status_code == 200]
            throughput = len(successful_responses) / (end_time - start_time)
            
            performance_by_config[config["name"]] = {
                "throughput": throughput,
                "config": config
            }
        
        # Assert - Performance scales with resources
        small_throughput = performance_by_config["Small"]["throughput"]
        large_throughput = performance_by_config["Large"]["throughput"]
        
        scaling_ratio = large_throughput / small_throughput
        resource_ratio = 4  # Large has 4x CPU of Small
        
        # Assert - Reasonable scaling (should be somewhat proportional to resources)
        assert scaling_ratio > resource_ratio * 0.5, "Vertical scaling not effective enough"

class TestStressTesting:
    """Stress testing to find breaking points"""
    
    @pytest.mark.asyncio
    async def test_api_stress_to_breaking_point(self, performance_client: httpx.AsyncClient):
        """Test API stress until breaking point is found"""
        # Act - Gradually increase load until failure
        concurrent_users = 10
        max_concurrent_users = 500
        breaking_point_found = False
        
        while concurrent_users <= max_concurrent_users and not breaking_point_found:
            print(f"Testing with {concurrent_users} concurrent users...")
            
            try:
                start_time = time.time()
                
                # Generate load
                tasks = []
                for i in range(concurrent_users):
                    task = performance_client.get("http://api:8000/stress-test")
                    tasks.append(task)
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                end_time = time.time()
                
                # Analyze results
                successful_responses = [r for r in responses if hasattr(r, 'status_code') and r.status_code == 200]
                success_rate = len(successful_responses) / len(responses)
                
                # Check if breaking point reached
                if success_rate < 0.95 or (end_time - start_time) > 60:
                    breaking_point_found = True
                    print(f"Breaking point found at {concurrent_users} concurrent users")
                    print(f"Success rate: {success_rate:.2f}")
                    break
                
                concurrent_users += 50  # Increase load gradually
                
            except Exception as e:
                breaking_point_found = True
                print(f"Exception at {concurrent_users} concurrent users: {e}")
                break
        
        # Assert - Breaking point was found
        assert breaking_point_found, "No breaking point found within test limits"
        assert concurrent_users > 50, "Breaking point found too early"
    
    @pytest.mark.asyncio
    async def test_memory_stress_testing(self, performance_client: httpx.AsyncClient):
        """Test memory stress until limits are reached"""
        # Act - Generate memory stress
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        
        # Generate memory-intensive operations
        memory_stress_tasks = []
        for i in range(100):
            task = performance_client.post(
                "http://api:8000/memory-stress",
                json={"data_size": "10MB", "operations": 100}
            )
            memory_stress_tasks.append(task)
        
        try:
            responses = await asyncio.gather(*memory_stress_tasks)
            
            # Check final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024
            memory_increase = final_memory - initial_memory
            
            # Assert - Memory stress handled appropriately
            successful_responses = [r for r in responses if r.status_code == 200]
            success_rate = len(successful_responses) / len(responses)
            
            # Some requests should fail due to memory pressure
            assert success_rate < 1.0, "All memory stress requests succeeded (unexpected)"
            assert memory_increase > 100, "Memory usage didn't increase significantly"
            
        except MemoryError:
            # Expected to hit memory limits
            assert True, "Memory stress should trigger MemoryError"
        except Exception as e:
            # Other exceptions acceptable under stress
            assert "memory" in str(e).lower() or "resource" in str(e).lower()

class TestPerformanceProfiling:
    """Performance profiling and optimization"""
    
    @profile
    def test_function_performance_profiling(self):
        """Profile function performance with memory_profiler"""
        # Act - Execute function to be profiled
        def cpu_intensive_function():
            result = 0
            for i in range(100000):
                result += i * i * 0.5  # CPU intensive operation
            return result
        
        # Execute profiled function
        start_time = time.time()
        result = cpu_intensive_function()
        end_time = time.time()
        
        # Assert - Function executed successfully
        assert isinstance(result, (int, float))
        assert end_time - start_time < 5.0, "Function took too long to execute"
    
    @pytest.mark.asyncio
    async def test_database_query_profiling(self, performance_client: httpx.AsyncClient):
        """Profile database query performance"""
        # Act - Execute and profile database queries
        query_types = [
            {"name": "Simple SELECT", "query": "SELECT * FROM users WHERE id = 1"},
            {"name": "Complex JOIN", "query": "SELECT u.*, p.* FROM users u JOIN profiles p ON u.id = p.user_id WHERE u.active = true"},
            {"name": "Aggregation", "query": "SELECT COUNT(*), AVG(age) FROM users GROUP BY department"}
        ]
        
        for query_type in query_types:
            response = await performance_client.post(
                "http://api:8000/profile-query",
                json={"query": query_type["query"], "profile": True}
            )
            
            assert response.status_code == 200
            profile_data = response.json()
            
            # Assert - Query profiling data present
            assert "execution_time" in profile_data
            assert "rows_examined" in profile_data
            assert "index_used" in profile_data
            
            # Assert - Performance reasonable
            execution_time = profile_data["execution_time"]
            if query_type["name"] == "Simple SELECT":
                assert execution_time < 0.01, f"Simple query too slow: {execution_time:.3f}s"
            elif query_type["name"] == "Complex JOIN":
                assert execution_time < 0.5, f"Complex query too slow: {execution_time:.3f}s"
            elif query_type["name"] == "Aggregation":
                assert execution_time < 1.0, f"Aggregation query too slow: {execution_time:.3f}s"

class TestPerformanceRegression:
    """Performance regression testing"""
    
    @pytest.mark.asyncio
    async def test_api_performance_regression(self, performance_client: httpx.AsyncClient):
        """Test for performance regressions compared to baseline"""
        # Act - Execute performance tests and compare to baseline
        baseline_metrics = {
            "get_user": {"avg_response_time": 0.1, "p95_response_time": 0.2, "max_response_time": 0.5},
            "list_users": {"avg_response_time": 0.2, "p95_response_time": 0.4, "max_response_time": 1.0},
            "create_user": {"avg_response_time": 0.15, "p95_response_time": 0.3, "max_response_time": 0.8}
        }
        
        current_metrics = {}
        
        # Test GET user endpoint
        response_times = []
        for i in range(50):
            start_time = time.time()
            response = await performance_client.get("http://api:8000/users/1")
            end_time = time.time()
            
            assert response.status_code == 200
            response_times.append(end_time - start_time)
        
        current_metrics["get_user"] = {
            "avg_response_time": sum(response_times) / len(response_times),
            "p95_response_time": sorted(response_times)[int(0.95 * len(response_times))],
            "max_response_time": max(response_times)
        }
        
        # Assert - No significant regression
        for endpoint, metrics in current_metrics.items():
            baseline = baseline_metrics[endpoint]
            
            # Allow 20% degradation before flagging as regression
            regression_threshold = 1.2
            
            assert metrics["avg_response_time"] <= baseline["avg_response_time"] * regression_threshold, \
                f"Average response time regression for {endpoint}"
            assert metrics["p95_response_time"] <= baseline["p95_response_time"] * regression_threshold, \
                f"P95 response time regression for {endpoint}"
            assert metrics["max_response_time"] <= baseline["max_response_time"] * regression_threshold, \
                f"Max response time regression for {endpoint}"

if __name__ == "__main__":
    pytest.main([
        __file__, 
        "-v", 
        "--cov=your_app", 
        "--cov-report=html",
        "--cov-report=term-missing",
        "-m performance"  # Run performance tests
    ])