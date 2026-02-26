# 🎯 [PROJECT_NAME] Feature Tests Template

## 📋 Overview

This template provides comprehensive feature testing structure for [PROJECT_NAME] with clear distinction between current and planned implementations using pytest markers.

**Purpose**: Validate individual features and API endpoints with implementation status tracking  
**Integration**: Works with pytest markers for current vs planned feature testing  
**Scope**: [PROJECT_SCOPE]  

---

## 🏷️ Test Status Markers

```python
# Pytest markers for implementation status
pytest.mark.current = pytest.mark.current  # Actually implemented features
pytest.mark.planned = pytest.mark.planned  # Planned features (will be skipped)
```

---

## 🔐 Authentication Feature Tests

### Current Implementation Tests

```python
@pytest.mark.current
def test_[PRIMARY_AUTH_METHOD]_login_feature(client: TestClient):
    """Test [PRIMARY_AUTH_METHOD] login feature (CURRENT)"""
    response = client.get("/api/v1/auth/[AUTH_LOGIN_ENDPOINT]")
    
    assert response.status_code == [REDIRECT_STATUS_CODE]
    assert "[AUTH_DOMAIN]" in response.headers["location"]

@pytest.mark.current
@patch('[MOCK_MODULE]')
def test_[PRIMARY_AUTH_METHOD]_callback_feature(mock_get, client: TestClient):
    """Test [PRIMARY_AUTH_METHOD] callback feature (CURRENT)"""
    # Mock [AUTH_PROVIDER] validation response
    mock_[AUTH_PROVIDER]_response = Mock()
    mock_[AUTH_PROVIDER]_response.status_code = 200
    mock_[AUTH_PROVIDER]_response.text = "[VALIDATION_RESPONSE]"
    mock_get.return_value = mock_[AUTH_PROVIDER]_response
    
    callback_params = {
        "[PARAM_1]": "[PARAM_1_VALUE]",
        "[PARAM_2]": "[PARAM_2_VALUE]",
        # ... additional callback parameters
    }
    
    response = client.get("/api/v1/auth/[AUTH_CALLBACK_ENDPOINT]", params=callback_params)
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "[TOKEN_TYPE]"
    assert "[USER_ID_FIELD]" in data

@pytest.mark.current
def test_token_refresh_feature(client: TestClient):
    """Test token refresh feature (CURRENT)"""
    [USER_ID] = "test-[USER_TYPE]-id"
    
    response = client.post("/api/v1/auth/[REFRESH_ENDPOINT]", json={"[USER_ID_FIELD]": [USER_ID]})
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "[TOKEN_TYPE]"
```

### Planned Implementation Tests

```python
@pytest.mark.planned
def test_social_login_feature(client: TestClient):
    """Test social login feature (PLANNED - [SOCIAL_PROVIDERS])"""
    pytest.skip("Social login feature not yet implemented")

@pytest.mark.planned
def test_logout_feature(client: TestClient):
    """Test logout feature (PLANNED)"""
    pytest.skip("Logout feature not yet implemented")

@pytest.mark.planned
def test_multi_factor_auth_feature(client: TestClient):
    """Test multi-factor authentication feature (PLANNED)"""
    pytest.skip("Multi-factor authentication feature not yet implemented")
```

---

## 📚 [PRIMARY_FEATURE_MODULE] Feature Tests

### Current Implementation Tests

```python
@pytest.mark.current
async def test_[FEATURE_NAME]_search_feature(async_client: AsyncClient, [SAMPLE_DATA]):
    """Test [FEATURE_NAME] search feature (CURRENT)"""
    response = await async_client.get("/api/v1/[ENDPOINT_PATH]?[SEARCH_PARAM]=[SEARCH_VALUE]&limit=[LIMIT]")
    
    assert response.status_code == 200
    data = response.json()
    assert "[RESULTS_FIELD]" in data
    assert "[TOTAL_FIELD]" in data
    assert isinstance(data["[RESULTS_FIELD]"], list)

@pytest.mark.current
async def test_[FEATURE_NAME]_details_feature(async_client: AsyncClient, [SAMPLE_DATA]):
    """Test [FEATURE_NAME] details feature (CURRENT)"""
    response = await async_client.get(f"/api/v1/[ENDPOINT_PATH]/{[SAMPLE_DATA].id}")
    
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert "[TITLE_FIELD]" in data

@pytest.mark.current
async def test_[FEATURE_NAME]_creation_feature(async_client: AsyncClient):
    """Test [FEATURE_NAME] creation feature (CURRENT - [ADMIN_TYPE] function)"""
    [FEATURE_DATA] = {
        "[FIELD_1]": "[VALUE_1]",
        "[FIELD_2]": "[VALUE_2]",
        "[FIELD_3]": "[VALUE_3]",
        # ... additional fields
    }
    
    response = await async_client.post("/api/v1/[ENDPOINT_PATH]", json=[FEATURE_DATA])
    
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["[VALIDATION_FIELD]"] == [FEATURE_DATA]["[VALIDATION_FIELD]"]
```

### Planned Implementation Tests

```python
@pytest.mark.planned
async def test_[ADVANCED_FEATURE]_feature(async_client: AsyncClient):
    """Test [ADVANCED_FEATURE_DESCRIPTION] feature (PLANNED)"""
    pytest.skip("[ADVANCED_FEATURE] feature not yet implemented")

@pytest.mark.planned
async def test_[FILTERING_FEATURE]_feature(async_client: AsyncClient):
    """Test [FILTERING_FEATURE_DESCRIPTION] feature (PLANNED)"""
    pytest.skip("[FILTERING_FEATURE] feature not yet implemented")

@pytest.mark.planned
async def test_[SOCIAL_FEATURE]_feature(async_client: AsyncClient):
    """Test [SOCIAL_FEATURE_DESCRIPTION] feature (PLANNED)"""
    pytest.skip("[SOCIAL_FEATURE] feature not yet implemented")
```

---

## 🎬 [USER_TYPE_2] Feature Tests

### Current Implementation Tests

```python
@pytest.mark.current
async def test_[USER_TYPE_2_FEATURE]_profile_feature(async_client: AsyncClient, [SAMPLE_USER_TYPE_2]):
    """Test [USER_TYPE_2_FEATURE] profile feature (CURRENT)"""
    response = await async_client.get(f"/api/v1/[USER_TYPE_2_ENDPOINT]/me?[USER_ID_PARAM]={[SAMPLE_USER_TYPE_2].[USER_ID_FIELD]}")
    
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert "[USER_TYPE_2_ID_FIELD]" in data

@pytest.mark.current
async def test_[USER_TYPE_2_FEATURE]_creation_feature(async_client: AsyncClient):
    """Test [USER_TYPE_2_FEATURE] creation feature (CURRENT)"""
    [USER_TYPE_2_DATA] = {
        "[FIELD_1]": "[VALUE_1]",
        "[FIELD_2]": "[VALUE_2]",
        "[FIELD_3]": "[VALUE_3]",
        # ... additional fields
    }
    
    [USER_ID] = "test-user-id"
    response = await async_client.post(f"/api/v1/[USER_TYPE_2_ENDPOINT]?[USER_ID_PARAM]={[USER_ID]}", json=[USER_TYPE_2_DATA])
    
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert data["[VALIDATION_FIELD]"] == [USER_TYPE_2_DATA]["[VALIDATION_FIELD]"]
```

### Planned Implementation Tests

```python
@pytest.mark.planned
async def test_[USER_TYPE_2_ADVANCED_FEATURE]_feature(async_client: AsyncClient):
    """Test [USER_TYPE_2_ADVANCED_FEATURE_DESCRIPTION] feature (PLANNED)"""
    pytest.skip("[USER_TYPE_2_ADVANCED_FEATURE] feature not yet implemented")

@pytest.mark.planned
async def test_[USER_TYPE_2_ANALYTICS]_feature(async_client: AsyncClient):
    """Test [USER_TYPE_2_ANALYTICS_DESCRIPTION] feature (PLANNED)"""
    pytest.skip("[USER_TYPE_2_ANALYTICS] feature not yet implemented")
```

---

## 🛡️ [USER_TYPE_3] Feature Tests

### Current Implementation Tests

```python
@pytest.mark.current
async def test_[USER_TYPE_3_FEATURE]_inspection_feature(async_client: AsyncClient, [SAMPLE_DATA]):
    """Test [USER_TYPE_3_FEATURE] inspection feature (CURRENT)"""
    response = await async_client.get(f"/api/v1/[USER_TYPE_3_ENDPOINT]/[INSPECTION_TYPE]/{[SAMPLE_DATA].id}")
    
    assert response.status_code == 200
    data = response.json()
    assert "[RESOURCE_ID_FIELD]" in data
    assert "[INSPECTION_DATA_FIELD]" in data

@pytest.mark.current
async def test_[USER_TYPE_3_QUERY_FEATURE]_feature(async_client: AsyncClient, [SAMPLE_DATA]):
    """Test [USER_TYPE_3_QUERY_FEATURE] feature (CURRENT)"""
    response = await async_client.post(f"/api/v1/[USER_TYPE_3_ENDPOINT]/[QUERY_TYPE]?[QUERY_PARAM]={[SAMPLE_DATA].id}&limit=[LIMIT]")
    
    assert response.status_code == 200
    data = response.json()
    assert "[RESULTS_FIELD]" in data
    assert isinstance(data["[RESULTS_FIELD]"], list)
```

### Planned Implementation Tests

```python
@pytest.mark.planned
async def test_[USER_TYPE_3_MANAGEMENT]_feature(async_client: AsyncClient):
    """Test [USER_TYPE_3_MANAGEMENT_DESCRIPTION] feature (PLANNED)"""
    pytest.skip("[USER_TYPE_3_MANAGEMENT] feature not yet implemented")

@pytest.mark.planned
async def test_[USER_TYPE_3_MONITORING]_feature(async_client: AsyncClient):
    """Test [USER_TYPE_3_MONITORING_DESCRIPTION] feature (PLANNED)"""
    pytest.skip("[USER_TYPE_3_MONITORING] feature not yet implemented")
```

---

## ⚡ Performance Feature Tests

### Current Implementation Tests

```python
@pytest.mark.current
async def test_[FEATURE_NAME]_performance_feature(async_client: AsyncClient, performance_monitor):
    """Test [FEATURE_NAME] performance feature (CURRENT)"""
    performance_monitor.start()
    
    response = await async_client.get("/api/v1/[ENDPOINT_PATH]?[PARAMS]")
    
    performance_monitor.stop()
    
    assert response.status_code == 200
    assert performance_monitor.get_duration() < [PERFORMANCE_THRESHOLD]
```

### Planned Implementation Tests

```python
@pytest.mark.planned
async def test_concurrent_users_performance_feature(async_client: AsyncClient):
    """Test concurrent users performance feature (PLANNED)"""
    pytest.skip("Concurrent performance testing not yet implemented")

@pytest.mark.planned
async def test_load_testing_feature(async_client: AsyncClient):
    """Test load testing feature (PLANNED)"""
    pytest.skip("Load testing feature not yet implemented")
```

---

## 🔒 Security Feature Tests

### Current Implementation Tests

```python
@pytest.mark.current
def test_[SECURITY_FEATURE]_security_feature(client: TestClient):
    """Test [SECURITY_FEATURE] security feature (CURRENT)"""
    # Test [SECURITY_SCENARIO]
    [MALICIOUS_INPUT] = "[MALICIOUS_PAYLOAD]"
    
    response = client.get(f"/api/v1/[ENDPOINT_PATH]?[INPUT_PARAM]={[MALICIOUS_INPUT]}")
    
    # Should not crash or return 500
    assert response.status_code in [200, 400, 422]

@pytest.mark.current
def test_input_validation_feature(client: TestClient):
    """Test input validation feature (CURRENT)"""
    # Test various invalid inputs
    invalid_inputs = [
        "[SQL_INJECTION_PAYLOAD]",
        "[XSS_PAYLOAD]",
        "[PATH_TRAVERSAL_PAYLOAD]",
        # ... additional test cases
    ]
    
    for invalid_input in invalid_inputs:
        response = client.get(f"/api/v1/[ENDPOINT_PATH]?[PARAM]={invalid_input}")
        assert response.status_code in [200, 400, 422]
```

### Planned Implementation Tests

```python
@pytest.mark.planned
async def test_rate_limiting_feature(async_client: AsyncClient):
    """Test rate limiting feature (PLANNED)"""
    pytest.skip("Rate limiting feature not yet implemented")

@pytest.mark.planned
async def test_authorization_feature(async_client: AsyncClient):
    """Test authorization feature (PLANNED)"""
    pytest.skip("Authorization feature not yet implemented")

@pytest.mark.planned
async def test_authentication_bypass_feature(async_client: AsyncClient):
    """Test authentication bypass protection feature (PLANNED)"""
    pytest.skip("Authentication bypass protection feature not yet implemented")
```

---

## 🔄 Feature Integration Tests

### Current Implementation Tests

```python
@pytest.mark.current
async def test_[MODULE_1]_to_[MODULE_2]_integration_feature(async_client: AsyncClient, [SAMPLE_DATA]):
    """Test [MODULE_1] to [MODULE_2] integration feature (CURRENT)"""
    # Get [MODULE_1] data
    [MODULE_1_RESPONSE] = await async_client.get("/api/v1/[MODULE_1_ENDPOINT]")
    assert [MODULE_1_RESPONSE].status_code == 200
    
    # Use [MODULE_1] data for [MODULE_2] operation
    [MODULE_1_DATA] = [MODULE_1_RESPONSE].json()
    [MODULE_2_RESPONSE] = await async_client.get(f"/api/v1/[MODULE_2_ENDPOINT]?[PARAM]={[MODULE_1_DATA]['id']}")
    assert [MODULE_2_RESPONSE].status_code == 200
    [MODULE_2_DATA] = [MODULE_2_RESPONSE].json()
    assert "[MODULE_2_VALIDATION_FIELD]" in [MODULE_2_DATA]

@pytest.mark.current
async def test_end_to_end_[WORKFLOW_TYPE]_feature(async_client: AsyncClient):
    """Test end-to-end [WORKFLOW_TYPE] feature (CURRENT)"""
    # Step 1: [STEP_1_DESCRIPTION]
    [STEP_1_RESPONSE] = await async_client.[STEP_1_METHOD]("[STEP_1_ENDPOINT]")
    assert [STEP_1_RESPONSE].status_code == [STEP_1_SUCCESS_CODE]
    
    # Step 2: [STEP_2_DESCRIPTION]
    [STEP_2_RESPONSE] = await async_client.[STEP_2_METHOD]("[STEP_2_ENDPOINT]")
    assert [STEP_2_RESPONSE].status_code == [STEP_2_SUCCESS_CODE]
    
    # Step 3: [STEP_3_DESCRIPTION]
    [STEP_3_RESPONSE] = await async_client.[STEP_3_METHOD]("[STEP_3_ENDPOINT]")
    assert [STEP_3_RESPONSE].status_code == [STEP_3_SUCCESS_CODE]
```

### Planned Implementation Tests

```python
@pytest.mark.planned
async def test_[ADVANCED_INTEGRATION]_feature(async_client: AsyncClient):
    """Test [ADVANCED_INTEGRATION_DESCRIPTION] feature (PLANNED)"""
    pytest.skip("[ADVANCED_INTEGRATION] feature not yet implemented")
```

---

## 🧪 Async Feature Tests

```python
@pytest.mark.asyncio
class TestAsyncFeatures:
    """Test features with async client"""

    async def test_concurrent_[FEATURE_TYPE]_features(self, async_client: AsyncClient):
        """Test multiple concurrent [FEATURE_TYPE] features"""
        import asyncio
        
        # Simulate multiple users performing actions simultaneously
        tasks = [
            async_client.get("/api/v1/[ENDPOINT_1]?[PARAMS]"),
            async_client.get("/api/v1/[ENDPOINT_2]?[PARAMS]"),
            async_client.get("/api/v1/[ENDPOINT_3]?[PARAMS]"),
        ]
        
        responses = await asyncio.gather(*tasks)
        
        # All requests should succeed
        for response in responses:
            assert response.status_code == [SUCCESS_CODE]
            data = response.json()
            assert "[EXPECTED_FIELD]" in data

    async def test_feature_error_recovery(self, async_client: AsyncClient):
        """Test feature error handling and recovery"""
        # Try to access non-existent resource
        response = await async_client.get("/api/v1/[ENDPOINT]/[INVALID_ID]")
        assert response.status_code == 404
        
        # Continue with valid operation
        response = await async_client.get("/api/v1/[ENDPOINT]?[VALID_PARAMS]")
        assert response.status_code == 200
```

---

## 📊 Test Configuration

### Pytest Configuration

```python
def pytest_configure(config):
    """Configure pytest markers"""
    config.addinivalue_line(
        "markers", "current: marks tests as testing currently implemented features"
    )
    config.addinivalue_line(
        "markers", "planned: marks tests as testing planned features (will be skipped)"
    )

def pytest_collection_modifyitems(config, items):
    """Modify test collection to add feature status information"""
    current_count = 0
    planned_count = 0
    
    for item in items:
        if "current" in item.keywords:
            current_count += 1
        elif "planned" in item.keywords:
            planned_count += 1
    
    print(f"\n=== Feature Test Status ===")
    print(f"Current Features: {current_count} tests")
    print(f"Planned Features: {planned_count} tests (will be skipped)")
    print(f"Total Feature Coverage: {current_count + planned_count} tests")
    print(f"Implementation Ratio: {current_count}/{current_count + planned_count} ({current_count/(current_count + planned_count)*100:.1f}%)")
    print("========================\n")
```

### Test Run Commands

```bash
# Run only current implementation tests
pytest tests/test_features.py -m current

# Run all tests (planned will be skipped)
pytest tests/test_features.py

# Run with coverage
pytest tests/test_features.py --cov=app --cov-report=html

# Run performance tests
pytest tests/test_features.py::TestAsyncFeatures -v

# Run security tests
pytest tests/test_features.py -k "security" -v
```

---

## 🎯 Template Customization Guide

### **Project-Specific Adaptations**
1. **Replace Placeholders**: Update all `[PROJECT_NAME]`, `[AUTH_DOMAIN]`, etc.
2. **Feature Modules**: Customize feature sections based on your project's modules
3. **User Types**: Adjust based on your project's user roles and personas
4. **Endpoints**: Update with actual endpoint paths and parameters
5. **Performance Thresholds**: Set appropriate performance targets

### **Feature Expansion**
1. **Add New Features**: Include additional features as needed
2. **Detail Levels**: Adjust feature detail based on project complexity
3. **Integration Points**: Add project-specific integration features
4. **Security Features**: Include security and compliance features if needed

### **Testing Strategy**
1. **Current vs Planned**: Maintain clear distinction between implemented and planned features
2. **Cross-Feature Testing**: Ensure features test integration between modules
3. **Performance Testing**: Include performance benchmarks for critical features
4. **Error Handling**: Test error scenarios and recovery procedures

### **Maintenance Automation**
1. **CI/CD Integration**: Add feature validation to your CI/CD pipeline
2. **Status Tracking**: Implement automatic status detection from code
3. **Change Detection**: Set up triggers for feature updates on code changes
4. **Quality Gates**: Add feature documentation quality checks

---

**📝 Template Notes**: This template provides a comprehensive feature testing framework that scales with your project. Start with current implementation tests and expand to planned features as they're developed. The marker system ensures transparency about implementation status and provides clear metrics for development progress.
