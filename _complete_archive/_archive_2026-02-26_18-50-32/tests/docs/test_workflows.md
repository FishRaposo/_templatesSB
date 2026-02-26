# 🔄 [PROJECT_NAME] Workflow Tests Template

## 📋 Overview

This template provides comprehensive workflow testing structure for [PROJECT_NAME] with clear distinction between current and planned implementations.

**Purpose**: Validate complete user journeys across multiple API endpoints  
**Integration**: Works with pytest markers for implementation status tracking  
**Scope**: [PROJECT_SCOPE]  

---

## 🏷️ Test Status Markers

```python
# Pytest markers for implementation status
pytest.mark.current = pytest.mark.current  # Actually implemented features
pytest.mark.planned = pytest.mark.planned  # Planned features (will be skipped)
```

---

## 🔐 Authentication Workflow Tests

### Current Implementation Tests

```python
@pytest.mark.current
def test_steam_oauth_login_workflow(client: TestClient):
    """Test Steam OAuth login workflow (CURRENT)"""
    response = client.get("/api/v1/auth/steam/login")
    
    assert response.status_code == 302
    assert "[AUTH_DOMAIN]" in response.headers["location"]

@pytest.mark.current
@patch('httpx.AsyncClient.get')
def test_steam_oauth_callback_workflow(mock_get, client: TestClient):
    """Test Steam OAuth callback workflow (CURRENT)"""
    # Mock Steam validation response
    mock_steam_response = Mock()
    mock_steam_response.status_code = 200
    mock_steam_response.text = "is_valid:true"
    mock_get.return_value = mock_steam_response
    
    callback_params = {
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.mode": "id_res",
        "openid.return_to": "[RETURN_URL]",
        "openid.claimed_id": "https://steamcommunity.com/openid/id/[STEAM_ID]",
        "openid.identity": "https://steamcommunity.com/openid/id/[STEAM_ID]",
        "openid.signed": "signed,claimed_id,identity",
        "openid.sig": "mock_signature"
    }
    
    response = client.get("/api/v1/auth/steam/callback", params=callback_params)
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
```

### Planned Implementation Tests

```python
@pytest.mark.planned
def test_social_login_workflow(client: TestClient):
    """Test social login workflow (PLANNED - Google, Facebook, etc.)"""
    pytest.skip("Social login feature not yet implemented")

@pytest.mark.planned
def test_logout_workflow(client: TestClient):
    """Test logout workflow (PLANNED)"""
    pytest.skip("Logout feature not yet implemented")
```

---

## 📚 [PRIMARY_FEATURE_MODULE] Workflow Tests

### Current Implementation Tests

```python
@pytest.mark.current
async def test_[FEATURE_NAME]_workflow(async_client: AsyncClient):
    """Test [FEATURE_DESCRIPTION] workflow (CURRENT)"""
    response = await async_client.get("/api/v1/[ENDPOINT_PATH]?[PARAM_NAME]=[PARAM_VALUE]")
    
    assert response.status_code == 200
    data = response.json()
    assert "[EXPECTED_FIELD]" in data
    assert isinstance(data["[EXPECTED_ARRAY_FIELD]"], list)

@pytest.mark.current
async def test_[FEATURE_NAME]_creation_workflow(async_client: AsyncClient):
    """Test [FEATURE_DESCRIPTION] creation workflow (CURRENT)"""
    [FEATURE_DATA] = {
        "[FIELD_1]": "[VALUE_1]",
        "[FIELD_2]": "[VALUE_2]",
        "[FIELD_3]": "[VALUE_3]"
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
async def test_[ADVANCED_FEATURE]_workflow(async_client: AsyncClient):
    """Test [ADVANCED_FEATURE_DESCRIPTION] workflow (PLANNED)"""
    pytest.skip("[ADVANCED_FEATURE] feature not yet implemented")
```

---

## 🎬 [USER_TYPE_2] Workflow Tests

### Current Implementation Tests

```python
@pytest.mark.current
async def test_[USER_TYPE_2_FEATURE]_workflow(async_client: AsyncClient):
    """Test [USER_TYPE_2_FEATURE_DESCRIPTION] workflow (CURRENT)"""
    response = await async_client.get(f"/api/v1/[USER_TYPE_2_ENDPOINT]/[RESOURCE_ID]")
    
    assert response.status_code == 200
    data = response.json()
    assert "[USER_TYPE_2_FIELD]" in data
```

### Planned Implementation Tests

```python
@pytest.mark.planned
async def test_[USER_TYPE_2_ADVANCED_FEATURE]_workflow(async_client: AsyncClient):
    """Test [USER_TYPE_2_ADVANCED_FEATURE_DESCRIPTION] workflow (PLANNED)"""
    pytest.skip("[USER_TYPE_2_ADVANCED_FEATURE] feature not yet implemented")
```

---

## 🛡️ [USER_TYPE_3] Workflow Tests

### Current Implementation Tests

```python
@pytest.mark.current
async def test_[USER_TYPE_3_FEATURE]_workflow(async_client: AsyncClient):
    """Test [USER_TYPE_3_FEATURE_DESCRIPTION] workflow (CURRENT)"""
    response = await async_client.get(f"/api/v1/[USER_TYPE_3_ENDPOINT]/[RESOURCE_ID]")
    
    assert response.status_code == 200
    data = response.json()
    assert "[USER_TYPE_3_FIELD]" in data
```

### Planned Implementation Tests

```python
@pytest.mark.planned
async def test_[USER_TYPE_3_ADVANCED_FEATURE]_workflow(async_client: AsyncClient):
    """Test [USER_TYPE_3_ADVANCED_FEATURE_DESCRIPTION] workflow (PLANNED)"""
    pytest.skip("[USER_TYPE_3_ADVANCED_FEATURE] feature not yet implemented")
```

---

## 🔄 Cross-Module Workflow Tests

### Current Implementation Tests

```python
@pytest.mark.current
async def test_complete_[USER_TYPE]_onboarding_workflow(async_client: AsyncClient):
    """Test complete [USER_TYPE] onboarding: [STEP_1] → [STEP_2] → [STEP_3]"""
    # Step 1: [STEP_1_DESCRIPTION]
    [STEP_1_RESPONSE] = await async_client.[STEP_1_METHOD]("[STEP_1_ENDPOINT]")
    assert [STEP_1_RESPONSE].status_code == [STEP_1_SUCCESS_CODE]
    
    # Step 2: [STEP_2_DESCRIPTION]
    [STEP_2_RESPONSE] = await async_client.[STEP_2_METHOD]("[STEP_2_ENDPOINT]")
    assert [STEP_2_RESPONSE].status_code == [STEP_2_SUCCESS_CODE]
    
    # Step 3: [STEP_3_DESCRIPTION]
    [STEP_3_RESPONSE] = await async_client.[STEP_3_METHOD]("[STEP_3_ENDPOINT]")
    assert [STEP_3_RESPONSE].status_code == [STEP_3_SUCCESS_CODE]
    [STEP_3_DATA] = [STEP_3_RESPONSE].json()
    assert "[STEP_3_VALIDATION_FIELD]" in [STEP_3_DATA]

@pytest.mark.current
async def test_[MODULE_1]_to_[MODULE_2]_integration_workflow(async_client: AsyncClient):
    """Test workflow from [MODULE_1] to [MODULE_2]"""
    # Get [MODULE_1] data
    [MODULE_1_RESPONSE] = await async_client.get("/api/v1/[MODULE_1_ENDPOINT]")
    assert [MODULE_1_RESPONSE].status_code == 200
    
    # Use [MODULE_1] data for [MODULE_2] operation
    [MODULE_1_DATA] = [MODULE_1_RESPONSE].json()
    [MODULE_2_RESPONSE] = await async_client.get(f"/api/v1/[MODULE_2_ENDPOINT]?[PARAM]={[MODULE_1_DATA]['id']}")
    assert [MODULE_2_RESPONSE].status_code == 200
    [MODULE_2_DATA] = [MODULE_2_RESPONSE].json()
    assert "[MODULE_2_VALIDATION_FIELD]" in [MODULE_2_DATA]
```

### Planned Implementation Tests

```python
@pytest.mark.planned
async def test_[ADVANCED_INTEGRATION]_workflow(async_client: AsyncClient):
    """Test [ADVANCED_INTEGRATION_DESCRIPTION] workflow (PLANNED)"""
    pytest.skip("[ADVANCED_INTEGRATION] workflow not yet implemented")
```

---

## ⚡ Performance Workflow Tests

### Current Implementation Tests

```python
@pytest.mark.current
async def test_[WORKFLOW_NAME]_performance_workflow(async_client: AsyncClient, performance_monitor):
    """Test [WORKFLOW_NAME] performance workflow (CURRENT)"""
    performance_monitor.start()
    
    response = await async_client.get("/api/v1/[ENDPOINT_PATH]?[PARAMS]")
    
    performance_monitor.stop()
    
    assert response.status_code == 200
    assert performance_monitor.get_duration() < [PERFORMANCE_THRESHOLD]
```

### Planned Implementation Tests

```python
@pytest.mark.planned
async def test_concurrent_users_performance_workflow(async_client: AsyncClient):
    """Test concurrent users performance workflow (PLANNED)"""
    pytest.skip("Concurrent performance testing not yet implemented")
```

---

## 🔒 Security Workflow Tests

### Current Implementation Tests

```python
@pytest.mark.current
def test_[SECURITY_FEATURE]_security_workflow(client: TestClient):
    """Test [SECURITY_FEATURE] security workflow (CURRENT)"""
    # Test [SECURITY_SCENARIO]
    [MALICIOUS_INPUT] = "[MALICIOUS_PAYLOAD]"
    
    response = client.get(f"/api/v1/[ENDPOINT_PATH]?[INPUT_PARAM]={[MALICIOUS_INPUT]}")
    
    # Should not crash or return 500
    assert response.status_code in [200, 400, 422]
```

### Planned Implementation Tests

```python
@pytest.mark.planned
async def test_[ADVANCED_SECURITY]_workflow(async_client: AsyncClient):
    """Test [ADVANCED_SECURITY_DESCRIPTION] workflow (PLANNED)"""
    pytest.skip("[ADVANCED_SECURITY] workflow not yet implemented")
```

---

## 🧪 Async Workflow Tests

```python
@pytest.mark.asyncio
class TestAsyncWorkflows:
    """Test workflows with async client"""

    async def test_concurrent_[WORKFLOW_TYPE]_workflows(self, async_client: AsyncClient):
        """Test multiple concurrent [WORKFLOW_TYPE] workflows"""
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

    async def test_workflow_error_recovery(self, async_client: AsyncClient):
        """Test workflow error handling and recovery"""
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
    """Modify test collection to add workflow status information"""
    current_count = 0
    planned_count = 0
    
    for item in items:
        if "current" in item.keywords:
            current_count += 1
        elif "planned" in item.keywords:
            planned_count += 1
    
    print(f"\n=== Workflow Test Status ===")
    print(f"Current Workflows: {current_count} tests")
    print(f"Planned Workflows: {planned_count} tests (will be skipped)")
    print(f"Total Workflow Coverage: {current_count + planned_count} tests")
    print(f"Implementation Ratio: {current_count}/{current_count + planned_count} ({current_count/(current_count + planned_count)*100:.1f}%)")
    print("===========================\n")
```

### Test Run Commands

```bash
# Run only current implementation tests
pytest tests/test_workflows.py -m current

# Run all tests (planned will be skipped)
pytest tests/test_workflows.py

# Run with coverage
pytest tests/test_workflows.py --cov=app --cov-report=html

# Run performance tests
pytest tests/test_workflows.py::TestAsyncWorkflows -v
```

---

## 🎯 Template Customization Guide

### **Project-Specific Adaptations**
1. **Replace Placeholders**: Update all `[PROJECT_NAME]`, `[AUTH_DOMAIN]`, etc.
2. **Workflow Modules**: Customize workflow sections based on your project's modules
3. **User Types**: Adjust based on your project's user roles and personas
4. **Endpoints**: Update with actual endpoint paths and parameters
5. **Performance Thresholds**: Set appropriate performance targets

### **Workflow Expansion**
1. **Add New Workflows**: Include additional user journeys as needed
2. **Detail Levels**: Adjust workflow detail based on project complexity
3. **Integration Points**: Add project-specific integration workflows
4. **Security Workflows**: Include security and compliance workflows if needed

### **Testing Strategy**
1. **Current vs Planned**: Maintain clear distinction between implemented and planned features
2. **Cross-Module Testing**: Ensure workflows test integration between modules
3. **Performance Testing**: Include performance benchmarks for critical workflows
4. **Error Handling**: Test error scenarios and recovery procedures

### **Maintenance Automation**
1. **CI/CD Integration**: Add workflow validation to your CI/CD pipeline
2. **Status Tracking**: Implement automatic status detection from code
3. **Change Detection**: Set up triggers for workflow updates on code changes
4. **Quality Gates**: Add workflow documentation quality checks

---

**📝 Template Notes**: This template provides a comprehensive workflow testing framework that scales with your project. Start with current implementation tests and expand to planned features as they're developed. The marker system ensures transparency about implementation status.
