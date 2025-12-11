# Python System Testing Template
# End-to-end system testing patterns for Python projects

"""
Python System Test Patterns
Adapted from Go system test patterns to Python with Playwright/Selenium
"""

import pytest
import asyncio
from typing import Dict, List, Any
from datetime import datetime, timedelta
import json
import time
import os
import subprocess
import requests

# ====================
# SYSTEM TEST CONFIGURATION
# ====================

class SystemTestConfig:
    """System test configuration"""
    def __init__(self):
        self.base_url = os.getenv("SYSTEM_TEST_URL", "http://localhost:8000")
        self.admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
        self.admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
        self.test_user_email = os.getenv("TEST_USER_EMAIL", "testuser@example.com")
        self.test_user_password = os.getenv("TEST_USER_PASSWORD", "testpass123")
        self.environment = os.getenv("ENVIRONMENT", "test")
        self.timeout = 30  # seconds

@pytest.fixture(scope="session")
def system_config():
    """System test configuration fixture"""
    return SystemTestConfig()

@pytest.fixture(scope="session")
def wait_for_system_ready(system_config):
    """Wait for system to be ready before tests"""
    max_attempts = 30
    for attempt in range(max_attempts):
        try:
            response = requests.get(
                f"{system_config.base_url}/health",
                timeout=5
            )
            if response.status_code == 200:
                health = response.json()
                if health.get("status") == "healthy":
                    return True
        except Exception as e:
            print(f"System not ready yet: {e}")
        
        time.sleep(5)
    
    pytest.fail("System did not become ready in time")

# ====================
# AUTHENTICATION HELPER
# ====================

class AuthenticationHelper:
    """Helper for authentication in system tests"""
    
    def __init__(self, system_config: SystemTestConfig):
        self.config = system_config
        self.tokens = {}
    
    def authenticate(self, email: str, password: str) -> str:
        """Authenticate and get access token"""
        response = requests.post(
            f"{self.config.base_url}/api/v1/auth/login",
            json={"email": email, "password": password},
            timeout=self.config.timeout
        )
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("access_token")
            self.tokens[email] = token
            return token
        
        return ""
    
    def get_headers(self, token: str = None) -> Dict[str, str]:
        """Get headers with optional authentication"""
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

@pytest.fixture(scope="session")
def auth_helper(system_config):
    return AuthenticationHelper(system_config)

@pytest.fixture(scope="session")
def admin_token(auth_helper):
    """Get admin token for the test session"""
    return auth_helper.authenticate(auth_helper.config.admin_email, auth_helper.config.admin_password)

@pytest.fixture(scope="session")
def user_token(auth_helper):
    """Get regular user token for the test session"""
    return auth_helper.authenticate(auth_helper.config.test_user_email, auth_helper.config.test_user_password)

# ====================
# SYSTEM HEALTH TESTS
# ====================

@pytest.mark.system
class TestSystemHealth:
    """Test system health and readiness"""
    
    def test_api_health_endpoint(self, system_config, wait_for_system_ready):
        """Test API health check endpoint"""
        response = requests.get(
            f"{system_config.base_url}/health",
            timeout=system_config.timeout
        )
        
        assert response.status_code == 200
        
        health = response.json()
        assert health["status"] == "healthy"
        
        # Verify all dependencies are healthy
        dependencies = health.get("dependencies", {})
        assert dependencies.get("database") == "healthy"
        assert dependencies.get("redis") == "healthy"
    
    def test_metrics_endpoint(self, system_config):
        """Test metrics endpoint"""
        response = requests.get(
            f"{system_config.base_url}/metrics",
            timeout=system_config.timeout
        )
        
        assert response.status_code == 200
        
        # Check for Prometheus format
        metrics_text = response.text
        assert "python_info" in metrics_text or "process_cpu_seconds_total" in metrics_text
    
    def test_all_service_endpoints(self, system_config):
        """Test all critical service endpoints"""
        endpoints = [
            ("GET", "/api/v1/health"),
            ("GET", "/api/v1/config"),
            ("GET", "/api/v1/metrics"),
        ]
        
        for method, path in endpoints:
            response = requests.request(
                method,
                f"{system_config.base_url}{path}",
                timeout=system_config.timeout
            )
            assert response.status_code in [200, 401], f"{method} {path} failed"

# ====================
# END-TO-END BUSINESS FLOW TESTS
# ====================

@pytest.mark.system
@pytest.mark.slow
class TestCompleteECommerceFlow:
    """Test complete e-commerce flow from registration to order completion"""
    
    def test_complete_user_journey(self, system_config, auth_helper):
        """Test complete user journey through e-commerce flow"""
        
        # Step 1: User registration
        user_data = {
            "name": "Customer Journey Test",
            "email": "journey@example.com",
            "password": "SecurePass123!",
            "password_confirm": "SecurePass123!"
        }
        
        response = requests.post(
            f"{system_config.base_url}/api/v1/users/register",
            json=user_data,
            timeout=system_config.timeout
        )
        assert response.status_code == 201
        user = response.json()
        user_id = user["id"]
        
        # Step 2: Email verification (simulate in test environment)
        # In production, this would involve clicking email link
        
        # Step 3: Login
        token = auth_helper.authenticate(
            "journey@example.com",
            "SecurePass123!"
        )
        assert token != ""
        
        # Step 4: Create shipping and billing addresses
        address_data = {
            "street": "123 Shopping St",
            "city": "Commerce City",
            "state": "CA",
            "zip": "90210",
            "country": "USA"
        }
        
        response = requests.post(
            f"{system_config.base_url}/api/v1/addresses",
            json=address_data,
            headers=auth_helper.get_headers(token),
            timeout=system_config.timeout
        )
        assert response.status_code == 201
        address = response.json()
        
        # Step 5: Browse products
        response = requests.get(
            f"{system_config.base_url}/api/v1/products",
            headers=auth_helper.get_headers(token),
            timeout=system_config.timeout
        )
        assert response.status_code == 200
        products = response.json()
        assert len(products) > 0
        
        # Step 6: Add products to cart
        cart_items = [
            {"product_id": products[0]["id"], "quantity": 2},
            {"product_id": products[1]["id"], "quantity": 1}
        ]
        
        response = requests.post(
            f"{system_config.base_url}/api/v1/cart",
            json={"items": cart_items},
            headers=auth_helper.get_headers(token),
            timeout=system_config.timeout
        )
        assert response.status_code == 201
        cart = response.json()
        assert len(cart["items"]) == 2
        
        # Step 7: Checkout
        checkout_data = {
            "cart_id": cart["id"],
            "shipping_address_id": address["id"],
            "billing_address_id": address["id"]
        }
        
        response = requests.post(
            f"{system_config.base_url}/api/v1/orders",
            json=checkout_data,
            headers=auth_helper.get_headers(token),
            timeout=system_config.timeout
        )
        assert response.status_code == 201
        order = response.json()
        order_id = order["id"]
        
        # Step 8: Process payment
        payment_data = {
            "order_id": order_id,
            "amount": order["total"],
            "method": "stripe",
            "payment_method_id": "pm_test_card"
        }
        
        response = requests.post(
            f"{system_config.base_url}/api/v1/payments",
            json=payment_data,
            headers=auth_helper.get_headers(token),
            timeout=system_config.timeout
        )
        assert response.status_code in [200, 201]
        
        payment = response.json()
        assert payment["status"] in ["succeeded", "completed"]
        
        # Step 9: Verify order status updated
        time.sleep(2)  # Wait for async processing
        
        response = requests.get(
            f"{system_config.base_url}/api/v1/orders/{order_id}",
            headers=auth_helper.get_headers(token),
            timeout=system_config.timeout
        )
        assert response.status_code == 200
        
        updated_order = response.json()
        assert updated_order["status"] == "paid"
        assert updated_order["paid_at"] is not None
        
        # Step 10: Check email notifications
        # In test environment, check email logs or mock
        
        # Step 11: Verify order in user order history
        response = requests.get(
            f"{system_config.base_url}/api/v1/users/{user_id}/orders",
            headers=auth_helper.get_headers(token),
            timeout=system_config.timeout
        )
        assert response.status_code == 200
        
        orders = response.json()
        assert len(orders) > 0
        assert any(o["id"] == order_id for o in orders)
    
    def test_failed_payment_flow(self, system_config, auth_helper, user_token):
        """Test order flow with failed payment"""
        
        # Create order
        response = requests.post(
            f"{system_config.base_url}/api/v1/orders",
            json={
                "items": [{"product_id": 1, "quantity": 1}],
                "shipping_address_id": 1
            },
            headers=auth_helper.get_headers(user_token),
            timeout=system_config.timeout
        )
        order = response.json()
        
        # Attempt payment with invalid card
        payment_data = {
            "order_id": order["id"],
            "amount": order["total"],
            "method": "stripe",
            "payment_method_id": "pm_test_card_declined"
        }
        
        response = requests.post(
            f"{system_config.base_url}/api/v1/payments",
            json=payment_data,
            headers=auth_helper.get_headers(user_token),
            timeout=system_config.timeout
        )
        assert response.status_code == 402
        
        # Verify order status remains pending
        response = requests.get(
            f"{system_config.base_url}/api/v1/orders/{order['id']}",
            headers=auth_helper.get_headers(user_token),
            timeout=system_config.timeout
        )
        
        updated_order = response.json()
        assert updated_order["status"] == "pending"
        assert updated_order["paid_at"] is None

@pytest.mark.system
@pytest.mark.slow
class TestDataAnalyticsPipeline:
    """Test complete data analytics pipeline"""
    
    def test_complete_data_pipeline(self, system_config, admin_token):
        """Test complete data pipeline from ingestion to visualization"""
        
        # Step 1: Ingest data from multiple sources
        sources = [
            {
                "type": "api",
                "url": "https://api.example.com/user_events",
                "format": "json",
                "schedule": "hourly"
            },
            {
                "type": "csv",
                "bucket": "data-bucket",
                "path": "events/daily.csv",
                "format": "csv"
            },
            {
                "type": "database",
                "connection": "postgresql://source:5432/db",
                "query": "SELECT * FROM transactions WHERE created_at > NOW() - INTERVAL '1 day'"
            }
        ]
        
        ingestion_jobs = []
        for source in sources:
            response = requests.post(
                f"{system_config.base_url}/api/v1/ingest",
                json=source,
                headers=auth_helper.get_headers(admin_token),
                timeout=system_config.timeout
            )
            assert response.status_code == 202
            ingestion_jobs.append(response.json()["id"])
        
        # Step 2: Wait for ingestion to complete
        time.sleep(5)  # Wait for async processing
        
        # Verify raw data ingested
        response = requests.get(
            f"{system_config.base_url}/api/v1/raw-data/count",
            headers=auth_helper.get_headers(admin_token),
            timeout=system_config.timeout
        )
        assert response.status_code == 200
        assert response.json()["count"] > 0
        
        # Step 3: Transform data
        transform_config = {
            "source_jobs": ingestion_jobs,
            "transformations": [
                {
                    "type": "clean_missing_values",
                    "config": {"strategy": "interpolate"}
                },
                {
                    "type": "normalize_timestamps",
                    "config": {"timezone": "UTC"}
                },
                {
                    "type": "enrich_user_data",
                    "config": {"lookup_table": "users"}
                },
                {
                    "type": "calculate_metrics",
                    "config": {
                        "metrics": ["revenue", "user_count", "conversion_rate"]
                    }
                }
            ]
        }
        
        response = requests.post(
            f"{system_config.base_url}/api/v1/transform",
            json=transform_config,
            headers=auth_helper.get_headers(admin_token),
            timeout=system_config.timeout
        )
        assert response.status_code == 202
        
        transform_job = response.json()
        
        # Step 4: Load to data warehouse
        load_config = {
            "destination": "warehouse",
            "table": "analytics.fact_events",
            "strategy": "incremental",
            "primary_key": "event_id"
        }
        
        response = requests.post(
            f"{system_config.base_url}/api/v1/load",
            json=load_config,
            headers=auth_helper.get_headers(admin_token),
            timeout=system_config.timeout
        )
        assert response.status_code == 202
        
        # Step 5: Generate analytics report
        report_config = {
            "type": "daily_kpis",
            "date_range": {
                "start": (datetime.now() - timedelta(days=7)).isoformat(),
                "end": datetime.now().isoformat()
            },
            "metrics": [
                "daily_active_users",
                "revenue",
                "conversion_rate",
                "average_order_value"
            ],
            "visualizations": ["line_chart", "bar_chart", "heatmap"]
        }
        
        response = requests.post(
            f"{system_config.base_url}/api/v1/reports",
            json=report_config,
            headers=auth_helper.get_headers(admin_token),
            timeout=60  # Longer timeout for report generation
        )
        assert response.status_code in [200, 201]
        
        report = response.json()
        assert report["status"] == "completed"
        assert "data" in report
        assert len(report["data"]) > 0
        assert len(report["visualizations"]) > 0

# ====================
# PERFORMANCE AND LOAD TESTS
# ====================

@pytest.mark.system
@pytest.mark.slow
class TestSystemPerformance:
    """Test system performance under load"""
    
    def test_system_under_load(self, system_config, auth_helper):
        """Test system under concurrent user load"""
        
        concurrent_users = 50
        requests_per_user = 30
        
        # Create multiple users
        users = []
        for i in range(concurrent_users):
            user_data = {
                "name": f"Load Test User {i}",
                "email": f"loadtest{i}@example.com",
                "password": "LoadTest123!"
            }
            
            response = requests.post(
                f"{system_config.base_url}/api/v1/users/register",
                json=user_data,
                timeout=system_config.timeout
            )
            
            if response.status_code == 201:
                users.append(f"loadtest{i}@example.com")
        
        # Authenticate all users
        tokens = []
        for email in users:
            token = auth_helper.authenticate(email, "LoadTest123!")
            if token:
                tokens.append(token)
        
        # Concurrent access
        import threading
        from concurrent.futures import ThreadPoolExecutor
        
        results = {"success": 0, "failed": 0, "total_time": 0}
        lock = threading.Lock()
        
        def make_requests(token_index: int):
            token = tokens[token_index] if token_index < len(tokens) else None
            local_results = {"success": 0, "failed": 0, "total_time": 0}
            
            for i in range(requests_per_user):
                start_time = time.time()
                
                try:
                    # Mix of endpoints
                    endpoints = [
                        f"/api/v1/users/profile",
                        f"/api/v1/products",
                        f"/api/v1/health",
                    ]
                    endpoint = endpoints[i % len(endpoints)]
                    
                    headers = auth_helper.get_headers(token)
                    response = requests.get(
                        f"{system_config.base_url}{endpoint}",
                        headers=headers,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        local_results["success"] += 1
                    else:
                        local_results["failed"] += 1
                    
                except Exception:
                    local_results["failed"] += 1
                
                local_results["total_time"] += (time.time() - start_time)
            
            with lock:
                results["success"] += local_results["success"]
                results["failed"] += local_results["failed"]
                results["total_time"] += local_results["total_time"]
        
        # Execute concurrent requests
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            executor.map(make_requests, range(len(tokens)))
        
        # Calculate statistics
        total_requests = len(tokens) * requests_per_user
        success_rate = results["success"] / total_requests
        avg_response_time = results["total_time"] / total_requests
        
        assert success_rate > 0.95, f"Success rate {success_rate:.2%} below 95%"
        assert avg_response_time < 1.0, f"Average response time {avg_response_time:.2f}s above 1s"

# ====================
# DISASTER RECOVERY TESTS
# ====================

@pytest.mark.system
class TestDisasterRecovery:
    """Test system recovery from failures"""
    
    def test_system_recovery(self, system_config):
        """Test system recovery after simulated failure"""
        
        # Step 1: Verify system is healthy
        response = requests.get(
            f"{system_config.base_url}/health",
            timeout=system_config.timeout
        )
        assert response.status_code == 200
        
        # Step 2: Simulate database failure (in test environment)
        # This would involve stopping the database container or blocking connections
        
        # Step 3: Verify graceful degradation
        # System should return 503 Service Unavailable, not crash
        
        # Step 4: Restore database
        # Start database container again
        
        # Step 5: Verify system recovers
        time.sleep(5)  # Wait for reconnection
        
        response = requests.get(
            f"{system_config.base_url}/health",
            timeout=system_config.timeout
        )
        assert response.status_code == 200

# ====================
# SECURITY TESTS
# ====================

@pytest.mark.system
class TestSecurity:
    """Test security vulnerabilities and protections"""
    
    def test_sql_injection_protection(self, system_config):
        """Test SQL injection attempts are blocked"""
        
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "1' OR 1=1--",
        ]
        
        for injection in malicious_inputs:
            response = requests.get(
                f"{system_config.base_url}/api/v1/search",
                params={"q": injection},
                timeout=system_config.timeout
            )
            
            # Should not return 500 (server error)
            # Should not return sensitive error messages
            assert response.status_code != 500
    
    def test_rate_limiting(self, system_config):
        """Test rate limiting on API endpoints"""
        
        # Make many rapid requests
        for i in range(150):
            response = requests.post(
                f"{system_config.base_url}/api/v1/auth/login",
                json={
                    "email": f"test{i}@example.com",
                    "password": "wrongpassword"
                },
                timeout=5
            )
            
            if i > 100:
                # Should eventually get rate limited
                if response.status_code == 429:
                    assert "Retry-After" in response.headers
                    break
    
    def test_authentication_bypass_attempts(self, system_config, auth_helper):
        """Test authentication bypass attempts are blocked"""
        
        bypass_attempts = [
            {"email": "admin@example.com", "password": "' OR '1'='1"},
            {"email": "' OR '1'='1' --", "password": "password"},
            {"email": "admin@example.com", "password": "admin'--"},
        ]
        
        for attempt in bypass_attempts:
            token = auth_helper.authenticate(
                attempt["email"],
                attempt["password"]
            )
            assert token == "", f"Bypass attempt should fail for {attempt}"

# ====================
# COMPLIANCE TESTS
# ====================

@pytest.mark.system
class TestCompliance:
    """Test compliance requirements (GDPR, CCPA, etc.)"""
    
    def test_gdpr_data_export(self, system_config, auth_helper, user_token):
        """Test GDPR right to data portability"""
        
        # Create user data
        headers = auth_helper.get_headers(user_token)
        
        # Request data export
        response = requests.get(
            f"{system_config.base_url}/api/v1/users/export",
            headers=headers,
            timeout=system_config.timeout
        )
        
        assert response.status_code == 200
        
        export = response.json()
        assert "personal_info" in export
        assert "activity_logs" in export
        assert "orders" in export
        assert "preferences" in export
    
    def test_gdpr_data_deletion(self, system_config, auth_helper):
        """Test GDPR right to erasure"""
        
        # Create a test user
        user_data = {
            "name": "GDPR Test User",
            "email": "gdprtest@example.com",
            "password": "Test123!"
        }
        
        response = requests.post(
            f"{system_config.base_url}/api/v1/users/register",
            json=user_data,
            timeout=system_config.timeout
        )
        user = response.json()
        
        # Authenticate
        token = auth_helper.authenticate(
            "gdprtest@example.com",
            "Test123!"
        )
        
        # Delete account
        headers = auth_helper.get_headers(token)
        response = requests.delete(
            f"{system_config.base_url}/api/v1/users/{user['id']}",
            headers=headers,
            timeout=system_config.timeout
        )
        assert response.status_code == 204
        
        # Verify user data is anonymized/deleted
        response = requests.get(
            f"{system_config.base_url}/api/v1/users/{user['id']}",
            headers=auth_helper.get_headers(auth_helper.authenticate(auth_helper.config.admin_email, auth_helper.config.admin_password)),
            timeout=system_config.timeout
        )
        assert response.status_code == 200
        
        deleted_user = response.json()
        assert "[DELETED]" in deleted_user.get("email", "")
        assert "[DELETED]" in deleted_user.get("name", "")

# ====================
# RUN SYSTEM TESTS
# ====================

'''
# Run all system tests
pytest tests/system/ -v -m system

# Run specific system test
pytest tests/system/test_ecommerce.py::TestCompleteECommerceFlow -v

# Run with live output
pytest tests/system/ -v -s

# Run slow system tests only
pytest tests/system/ -m "system and slow"

# Run system tests in parallel (if independent)
pytest tests/system/ -n 2

# Generate HTML report
pytest tests/system/ --html=reports/system_tests.html

# Run with screenshots (for browser tests)
pip install pytest-playwright
pytest tests/system/ --screenshot=on

# Run with video recording
pytest tests/system/ --video=on

# Run system tests in CI mode
pytest tests/system/ --ci
'''
