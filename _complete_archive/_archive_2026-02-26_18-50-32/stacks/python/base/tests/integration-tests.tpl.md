# Python Integration Testing Template
# Integration testing patterns for Python projects using pytest and testcontainers

"""
Python Integration Test Patterns
Adapted from Go integration test patterns to Python
"""

import pytest
import asyncio
import asyncpg
import redis.asyncio as redis
from typing import AsyncGenerator, List, Dict, Any
import httpx
import json
from datetime import datetime, timedelta

# ====================
# PYTEST-ASYNCIO CONFIGURATION
# ====================

pytest_plugins = ('pytest_asyncio',)

# ====================
# TEST SETUP AND FIXTURES
# ====================

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the session scope"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session", autouse=True)
async def test_containers():
    """Setup test containers for the entire test session"""
    # This would use testcontainers-python in real implementation
    # For now, we'll document the patterns
    
    containers = {
        'postgres': await start_postgres_container(),
        'redis': await start_redis_container()
    }
    
    yield containers
    
    # Cleanup
    for container in containers.values():
        await container.stop()

async def start_postgres_container():
    """Start PostgreSQL test container"""
    # Implementation with testcontainers-python
    # from testcontainers.postgres import PostgresContainer
    # 
    # postgres = PostgresContainer("postgres:15-alpine")
    # postgres.start()
    # return postgres
    
    # Mock for documentation
    class MockPostgres:
        def get_connection_url(self):
            return "postgresql://test:test@localhost:5432/testdb"
        
        async def stop(self):
            pass
    
    return MockPostgres()

async def start_redis_container():
    """Start Redis test container"""
    # Implementation with testcontainers-python
    # from testcontainers.redis import RedisContainer
    # 
    # redis = RedisContainer("redis:7-alpine")
    # redis.start()
    # return redis
    
    # Mock for documentation
    class MockRedis:
        def get_client(self):
            return redis.Redis(host='localhost', port=6379, decode_responses=True)
        
        async def stop(self):
            pass
    
    return MockRedis()

@pytest.fixture
def postgres_url(test_containers):
    """Get PostgreSQL connection URL"""
    return test_containers['postgres'].get_connection_url()

@pytest.fixture
async def postgres_pool(postgres_url):
    """Create PostgreSQL connection pool"""
    pool = await asyncpg.create_pool(postgres_url)
    yield pool
    await pool.close()

@pytest.fixture
async def redis_client(test_containers):
    """Get Redis client"""
    return test_containers['redis'].get_client()

@pytest.fixture
def test_app():
    """Create test FastAPI application"""
    from main import create_app
    return create_app(testing=True)

@pytest.fixture
async def test_client(test_app):
    """Create async test client"""
    async with httpx.AsyncClient(app=test_app, base_url="http://test") as client:
        yield client

# ====================
# INTEGRATION TEST BASE CLASS
# ====================

class IntegrationTestBase:
    """Base class for integration tests with shared utilities"""
    
    async def make_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        path: str,
        json_data: dict = None,
        token: str = None
    ) -> httpx.Response:
        """Make HTTP request with optional authentication"""
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        response = await client.request(
            method=method,
            url=path,
            json=json_data,
            headers=headers
        )
        return response
    
    async def authenticate(
        self,
        client: httpx.AsyncClient,
        email: str,
        password: str
    ) -> str:
        """Authenticate and get access token"""
        response = await self.make_request(
            client,
            "POST",
            "/api/v1/auth/login",
            {"email": email, "password": password}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        return data["access_token"]
    
    async def wait_for_job_completion(
        self,
        pool: asyncpg.Pool,
        job_id: str,
        timeout: int = 120
    ):
        """Wait for async job to complete"""
        start_time = asyncio.get_event_loop().time()
        
        while (asyncio.get_event_loop().time() - start_time) < timeout:
            record = await pool.fetchrow(
                "SELECT status FROM jobs WHERE id = $1",
                job_id
            )
            
            if record and record["status"] in ["completed", "failed"]:
                if record["status"] == "failed":
                    pytest.fail(f"Job {job_id} failed")
                return
            
            await asyncio.sleep(0.5)
        
        pytest.fail(f"Job {job_id} did not complete within {timeout} seconds")

@pytest.mark.integration
class TestUserRegistrationFlow(IntegrationTestBase):
    """Test complete user registration flow"""
    
    async def test_complete_registration_flow(
        self,
        test_client: httpx.AsyncClient,
        postgres_pool: asyncpg.Pool
    ):
        """Test complete user registration, verification, and login"""
        
        # Step 1: Register new user
        register_data = {
            "name": "Alice Johnson",
            "email": "alice@example.com",
            "password": "SecurePass123!"
        }
        
        response = await self.make_request(
            test_client,
            "POST",
            "/api/v1/users/register",
            register_data
        )
        
        assert response.status_code == 201
        user_data = response.json()
        assert user_data["email"] == "alice@example.com"
        assert "password" not in user_data
        user_id = user_data["id"]
        
        # Verify user is created in database
        db_user = await postgres_pool.fetchrow(
            "SELECT * FROM users WHERE id = $1",
            user_id
        )
        assert db_user is not None
        assert db_user["email"] == "alice@example.com"
        assert db_user["is_verified"] is False
        
        # Step 2: Verify email (simulate email verification)
        verification_token = "test_verification_token_123"
        await postgres_pool.execute(
            "UPDATE users SET verification_token = $1 WHERE id = $2",
            verification_token, user_id
        )
        
        response = await self.make_request(
            test_client,
            "POST",
            "/api/v1/users/verify",
            {"token": verification_token}
        )
        
        assert response.status_code == 200
        
        # Verify user is now verified
        db_user = await postgres_pool.fetchrow(
            "SELECT * FROM users WHERE id = $1",
            user_id
        )
        assert db_user["is_verified"] is True
        
        # Step 3: Login with verified account
        login_data = {
            "email": "alice@example.com",
            "password": "SecurePass123!"
        }
        
        response = await self.make_request(
            test_client,
            "POST",
            "/api/v1/auth/login",
            login_data
        )
        
        assert response.status_code == 200
        login_data = response.json()
        assert "access_token" in login_data
        assert "refresh_token" in login_data
        
        # Step 4: Access protected endpoint
        token = login_data["access_token"]
        response = await self.make_request(
            test_client,
            "GET",
            f"/api/v1/users/{user_id}",
            token=token
        )
        
        assert response.status_code == 200
        profile = response.json()
        assert profile["email"] == "alice@example.com"

@pytest.mark.integration
class TestOrderWorkflow(IntegrationTestBase):
    """Test complete e-commerce order workflow"""
    
    async def test_complete_order_flow(
        self,
        test_client: httpx.AsyncClient,
        postgres_pool: asyncpg.Pool,
        redis_client
    ):
        """Test complete order flow: create order, process payment, verify updates"""
        
        # Step 0: Create and authenticate user
        user_data = {
            "name": "Customer One",
            "email": "customer@example.com",
            "password": "Password123!"
        }
        
        response = await self.make_request(
            test_client,
            "POST",
            "/api/v1/users/register",
            user_data
        )
        user_id = response.json()["id"]
        
        # Authenticate
        token = await self.authenticate(
            test_client,
            "customer@example.com",
            "Password123!"
        )
        
        # Step 1: Create products (admin operation)
        products = []
        for i in range(3):
            product_data = {
                "name": f"Product {i}",
                "price": 29.99 + i,
                "stock": 100
            }
            response = await self.make_request(
                test_client,
                "POST",
                "/api/v1/products",
                product_data,
                token=token
            )
            products.append(response.json())
        
        # Step 2: Add items to cart
        cart_items = [
            {"product_id": products[0]["id"], "quantity": 2},
            {"product_id": products[1]["id"], "quantity": 1}
        ]
        
        response = await self.make_request(
            test_client,
            "POST",
            "/api/v1/cart",
            {"items": cart_items},
            token=token
        )
        assert response.status_code == 201
        cart = response.json()
        assert len(cart["items"]) == 2
        cart_id = cart["id"]
        
        # Step 3: Checkout
        checkout_data = {
            "cart_id": cart_id,
            "shipping_address": {
                "street": "123 Main St",
                "city": "Springfield",
                "state": "IL",
                "zip": "62701",
                "country": "USA"
            },
            "billing_address": {
                "street": "123 Main St",
                "city": "Springfield",
                "state": "IL",
                "zip": "62701",
                "country": "USA"
            }
        }
        
        response = await self.make_request(
            test_client,
            "POST",
            "/api/v1/orders",
            checkout_data,
            token=token
        )
        assert response.status_code == 201
        order = response.json()
        order_id = order["id"]
        
        # Verify order in database
        db_order = await postgres_pool.fetchrow(
            "SELECT * FROM orders WHERE id = $1",
            order_id
        )
        assert db_order is not None
        assert db_order["status"] == "pending"
        
        # Calculate expected total
        expected_total = (products[0]["price"] * 2) + products[1]["price"]
        assert abs(db_order["total"] - expected_total) < 0.01
        
        # Step 4: Process payment
        payment_data = {
            "order_id": order_id,
            "amount": expected_total,
            "method": "credit_card",
            "card_token": "tok_visa_test_123",
            "billing_address": checkout_data["billing_address"]
        }
        
        response = await self.make_request(
            test_client,
            "POST",
            "/api/v1/payments",
            payment_data,
            token=token
        )
        assert response.status_code == 200
        
        payment = response.json()
        assert payment["status"] == "completed"
        assert payment["order_id"] == order_id
        
        # Wait for async order update
        await asyncio.sleep(0.5)
        
        # Step 5: Verify order status updated
        response = await self.make_request(
            test_client,
            "GET",
            f"/api/v1/orders/{order_id}",
            token=token
        )
        assert response.status_code == 200
        
        updated_order = response.json()
        assert updated_order["status"] == "paid"
        assert updated_order["paid_at"] is not None
        
        # Step 6: Verify inventory updated
        db_product = await postgres_pool.fetchrow(
            "SELECT stock FROM products WHERE id = $1",
            products[0]["id"]
        )
        assert db_product["stock"] == 98  # 100 - 2 purchased

@pytest.mark.integration
class TestDataPipelineIntegration(IntegrationTestBase):
    """Test complete ETL data pipeline"""
    
    async def test_etl_pipeline(
        self,
        test_client: httpx.AsyncClient,
        postgres_pool: asyncpg.Pool
    ):
        """Test complete ETL pipeline from ingestion to warehouse"""
        
        # Setup: Create admin user and authenticate
        admin_token = await self.authenticate(
            test_client,
            "admin@example.com",
            "AdminPass123!"
        )
        
        # Step 1: Ingest from multiple sources
        sources = [
            {
                "type": "api",
                "url": "https://api.example.com/data1",
                "format": "json",
                "schedule": "hourly"
            },
            {
                "type": "csv",
                "path": "s3://data-bucket/input.csv",
                "format": "csv",
                "schedule": "daily"
            }
        ]
        
        ingestion_jobs = []
        for source in sources:
            response = await self.make_request(
                test_client,
                "POST",
                "/api/v1/ingest",
                source,
                token=admin_token
            )
            assert response.status_code == 202
            
            job = response.json()
            ingestion_jobs.append(job["id"])
        
        # Step 2: Wait for ingestion to complete
        for job_id in ingestion_jobs:
            await self.wait_for_job_completion(postgres_pool, job_id, timeout=300)
        
        # Verify raw data ingested
        raw_count = await postgres_pool.fetchval(
            "SELECT COUNT(*) FROM raw_data"
        )
        assert raw_count > 0
        
        # Step 3: Transform data
        transform_config = {
            "source_jobs": ingestion_jobs,
            "transformations": [
                {
                    "type": "clean_missing_values",
                    "config": {"strategy": "drop"}
                },
                {
                    "type": "normalize_dates",
                    "config": {"target_format": "ISO8601"}
                },
                {
                    "type": "calculate_metrics",
                    "config": {
                        "metrics": ["mean", "median", "std"]
                    }
                }
            ]
        }
        
        response = await self.make_request(
            test_client,
            "POST",
            "/api/v1/transform",
            transform_config,
            token=admin_token
        )
        assert response.status_code == 202
        
        transform_job_id = response.json()["id"]
        await self.wait_for_job_completion(postgres_pool, transform_job_id, timeout=600)
        
        # Step 4: Load to data warehouse
        load_config = {
            "destination": "warehouse",
            "table": "analytics.fact_events",
            "strategy": "incremental",
            "primary_key": "event_id"
        }
        
        response = await self.make_request(
            test_client,
            "POST",
            "/api/v1/load",
            load_config,
            token=admin_token
        )
        assert response.status_code == 202
        
        load_job_id = response.json()["id"]
        await self.wait_for_job_completion(postgres_pool, load_job_id, timeout=300)
        
        # Step 5: Verify data in warehouse
        warehouse_count = await postgres_pool.fetchval(
            "SELECT COUNT(*) FROM analytics.fact_events"
        )
        assert warehouse_count > 0
        
        # Step 6: Generate report
        report_config = {
            "type": "daily_summary",
            "date_range": {
                "start": (datetime.now() - timedelta(days=7)).isoformat(),
                "end": datetime.now().isoformat()
            },
            "metrics": ["total_events", "unique_users", "conversion_rate"]
        }
        
        response = await self.make_request(
            test_client,
            "POST",
            "/api/v1/reports",
            report_config,
            token=admin_token
        )
        assert response.status_code == 201
        
        report = response.json()
        assert report["status"] == "completed"
        assert "data" in report
        assert len(report["data"]) > 0

@pytest.mark.integration
class TestConcurrentLoad(IntegrationTestBase):
    """Test system under concurrent load"""
    
    @pytest.mark.slow
    async def test_concurrent_user_access(
        self,
        test_client: httpx.AsyncClient,
        postgres_pool: asyncpg.Pool
    ):
        """Test multiple users accessing system concurrently"""
        
        concurrent_users = 50
        requests_per_user = 20
        
        # Create multiple users
        users = []
        for i in range(concurrent_users):
            user_data = {
                "name": f"Concurrent User {i}",
                "email": f"concurrent{i}@example.com",
                "password": "Password123!"
            }
            
            response = await self.make_request(
                test_client,
                "POST",
                "/api/v1/users/register",
                user_data
            )
            user_id = response.json()["id"]
            users.append(user_id)
        
        # Authenticate all users
        tokens = []
        for i, user_id in enumerate(users):
            token = await self.authenticate(
                test_client,
                f"concurrent{i}@example.com",
                "Password123!"
            )
            tokens.append(token)
        
        # Concurrent access simulation
        async def make_concurrent_requests(user_index: int):
            results = {"success": 0, "failed": 0}
            
            for j in range(requests_per_user):
                endpoints = [
                    f"/api/v1/users/{users[user_index]}",
                    "/api/v1/products",
                    "/api/v1/users/me",
                ]
                endpoint = endpoints[j % len(endpoints)]
                
                try:
                    response = await self.make_request(
                        test_client,
                        "GET",
                        endpoint,
                        token=tokens[user_index]
                    )
                    
                    if response.status_code == 200:
                        results["success"] += 1
                    else:
                        results["failed"] += 1
                except Exception:
                    results["failed"] += 1
            
            return results
        
        # Execute concurrent requests
        tasks = [
            make_concurrent_requests(i)
            for i in range(concurrent_users)
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Verify results
        total_success = sum(r["success"] for r in results)
        total_failed = sum(r["failed"] for r in results)
        total_requests = concurrent_users * requests_per_user
        
        success_rate = total_success / total_requests
        assert success_rate > 0.95, f"Success rate {success_rate} below 95%"
        
        # Verify no deadlocks in database
        pg_stats = await postgres_pool.fetch("""
            SELECT * FROM pg_stat_activity 
            WHERE state = 'idle in transaction'
        """)
        assert len(pg_stats) == 0, "Potential database deadlocks detected"

# ====================
# INTEGRATION TEST UTILITIES
# ====================

async def setup_test_database(pool: asyncpg.Pool):
    """Setup test database with schema"""
    await pool.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            is_verified BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    await pool.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            price DECIMAL(10,2) NOT NULL,
            stock INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    await pool.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            total DECIMAL(10,2) NOT NULL,
            status VARCHAR(50) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            paid_at TIMESTAMP
        )
    """)

async def cleanup_test_database(pool: asyncpg.Pool):
    """Cleanup test database"""
    await pool.execute("DROP TABLE IF EXISTS orders")
    await pool.execute("DROP TABLE IF EXISTS products")
    await pool.execute("DROP TABLE IF EXISTS users")

# ====================
# RUN INTEGRATION TESTS
# ====================

'''
# Run integration tests
pytest tests/integration/ -v -m integration

# Run specific integration test file
pytest tests/integration/test_user_flows.py -v

# Run with live output
pytest tests/integration/ -v -s

# Run in parallel (if tests are independent)
pytest tests/integration/ -n auto

# Run slow integration tests
pytest tests/integration/ -m "slow"

# Run with coverage
pytest tests/integration/ --cov=app --cov-report=html

# Run and generate JUnit XML for CI
pytest tests/integration/ --junitxml=reports/integration.xml
'''
