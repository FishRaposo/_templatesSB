# Universal Template System - Unknown Stack
# Generated: 2025-12-10
# Purpose: Testing utilities
# Tier: core
# Stack: unknown
# Category: testing

# Comprehensive Python Testing Template
# Purpose: Core-level testing template with unit, integration, and feature tests for Python applications
# Usage: Copy to tests/ directory and customize for your Python project
# Stack: Python (.py)
# Tier: Core (Production Ready)

## Purpose

Core-level Python testing template providing comprehensive testing coverage including unit tests, integration tests, and feature tests for production-ready applications. Focuses on testing business logic, data persistence, API endpoints, and complete user features.

## Usage

```bash
# Copy to your Python project
cp _templates/tiers/core/tests/comprehensive-tests-python.tpl.py tests/test_comprehensive.py

# Install dependencies
pip install pytest pytest-cov pytest-mock pytest-asyncio httpx fastapi

# Run tests
pytest tests/test_comprehensive.py -v

# Run with coverage
pytest tests/test_comprehensive.py --cov=your_app --cov-report=html

# Run integration tests
pytest tests/test_comprehensive.py::TestIntegration -v
```

## Structure

```python
# tests/test_comprehensive.py
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import json
import tempfile
import os
from fastapi.testclient import TestClient
from httpx import AsyncClient

from your_app.main import app, User, Product, UserManagementService, ProductService
from your_app.database import DatabaseService
from your_app.auth import AuthService
from your_app.api import APIService
from your_app.models import UserModel, ProductModel
from your_app.schemas import UserCreate, ProductCreate
from your_app.exceptions import ValidationError, NotFoundError, AuthenticationError

# Test Fixtures
@pytest.fixture
def sample_user_data():
    """Fixture providing sample user data"""
    return {
        "id": 1,
        "name": "Test User",
        "email": "test@example.com",
        "age": 25,
        "active": True,
        "created_at": datetime.now()
    }

@pytest.fixture
def sample_product_data():
    """Fixture providing sample product data"""
    return {
        "id": 1,
        "name": "Test Product",
        "price": 10.99,
        "quantity": 100,
        "category": "electronics",
        "created_at": datetime.now()
    }

@pytest.fixture
def mock_database_service():
    """Mock database service fixture"""
    mock_db = Mock(spec=DatabaseService)
    mock_db.create_user = AsyncMock()
    mock_db.get_user = AsyncMock()
    mock_db.update_user = AsyncMock()
    mock_db.delete_user = AsyncMock()
    mock_db.create_product = AsyncMock()
    mock_db.get_product = AsyncMock()
    mock_db.update_product = AsyncMock()
    mock_db.delete_product = AsyncMock()
    mock_db.list_users = AsyncMock()
    mock_db.list_products = AsyncMock()
    return mock_db

@pytest.fixture
def mock_auth_service():
    """Mock authentication service fixture"""
    mock_auth = Mock(spec=AuthService)
    mock_auth.hash_password = Mock(return_value="hashed_password")
    mock_auth.verify_password = Mock(return_value=True)
    mock_auth.generate_token = Mock(return_value="jwt_token_123")
    mock_auth.verify_token = Mock(return_value={"user_id": 1})
    return mock_auth

@pytest.fixture
def mock_api_service():
    """Mock API service fixture"""
    mock_api = Mock(spec=APIService)
    mock_api.create_user = AsyncMock()
    mock_api.get_user = AsyncMock()
    mock_api.update_user = AsyncMock()
    mock_api.create_product = AsyncMock()
    mock_api.get_product = AsyncMock()
    return mock_api

@pytest.fixture
def test_client():
    """FastAPI test client fixture"""
    return TestClient(app)

@pytest.fixture
async def async_client():
    """Async HTTP client fixture"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

# Unit Tests - Business Logic
class TestUserModel:
    """Test user model business logic"""
    
    def test_user_creation_with_valid_data(self, sample_user_data):
        """Test creating user with valid data"""
        user = User(**sample_user_data)
        
        assert user.id == sample_user_data["id"]
        assert user.name == sample_user_data["name"]
        assert user.email == sample_user_data["email"]
        assert user.age == sample_user_data["age"]
        assert user.active is True
    
    def test_user_validation(self, sample_user_data):
        """Test user data validation"""
        user = User(**sample_user_data)
        
        # Valid user
        assert user.is_valid() is True
        
        # Invalid email
        user.email = "invalid-email"
        assert user.is_valid() is False
        
        # Invalid age
        user.email = sample_user_data["email"]
        user.age = 15
        assert user.is_valid() is False
    
    def test_user_age_calculation(self, sample_user_data):
        """Test user age calculation from birth date"""
        birth_date = datetime.now() - timedelta(days=365 * 25)
        sample_user_data["birth_date"] = birth_date
        
        user = User(**sample_user_data)
        calculated_age = user.calculate_age()
        
        assert calculated_age == 25
    
    def test_user_display_name(self, sample_user_data):
        """Test user display name formatting"""
        user = User(**sample_user_data)
        
        assert user.display_name == "Test User"
        
        user.name = ""
        assert user.display_name == "test@example.com"
    
    def test_user_is_adult(self, sample_user_data):
        """Test adult status determination"""
        user = User(**sample_user_data)
        
        assert user.is_adult() is True
        
        user.age = 17
        assert user.is_adult() is False

class TestProductModel:
    """Test product model business logic"""
    
    def test_product_creation_with_valid_data(self, sample_product_data):
        """Test creating product with valid data"""
        product = Product(**sample_product_data)
        
        assert product.id == sample_product_data["id"]
        assert product.name == sample_product_data["name"]
        assert product.price == sample_product_data["price"]
        assert product.quantity == sample_product_data["quantity"]
    
    def test_product_total_value_calculation(self, sample_product_data):
        """Test product total value calculation"""
        product = Product(**sample_product_data)
        
        expected_total = sample_product_data["price"] * sample_product_data["quantity"]
        assert product.total_value == expected_total
    
    def test_product_stock_status(self, sample_product_data):
        """Test product stock availability"""
        product = Product(**sample_product_data)
        
        assert product.is_in_stock() is True
        
        product.quantity = 0
        assert product.is_in_stock() is False
        
        product.quantity = -1
        assert product.is_in_stock() is False
    
    def test_product_price_validation(self, sample_product_data):
        """Test product price validation"""
        product = Product(**sample_product_data)
        
        assert product.has_valid_price() is True
        
        product.price = -10.0
        assert product.has_valid_price() is False
        
        product.price = 0.0
        assert product.has_valid_price() is False
    
    def test_product_category_validation(self, sample_product_data):
        """Test product category validation"""
        product = Product(**sample_product_data)
        
        valid_categories = ["electronics", "books", "clothing", "food"]
        assert product.is_valid_category(valid_categories) is True
        
        product.category = "invalid_category"
        assert product.is_valid_category(valid_categories) is False

class TestUserManagementService:
    """Test user management service business logic"""
    
    @pytest.mark.asyncio
    async def test_create_user_success(self, mock_database_service, mock_auth_service):
        """Test successful user creation"""
        service = UserManagementService(
            database=mock_database_service,
            auth=mock_auth_service
        )
        
        user_data = UserCreate(
            name="New User",
            email="newuser@example.com",
            password="SecurePass123!",
            age=25
        )
        
        mock_database_service.create_user.return_value = User(
            id=1, name=user_data.name, email=user_data.email, age=user_data.age
        )
        
        result = await service.create_user(user_data)
        
        assert result is not None
        assert result.name == user_data.name
        assert result.email == user_data.email
        mock_auth_service.hash_password.assert_called_once_with(user_data.password)
        mock_database_service.create_user.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_user_validation_error(self, mock_database_service, mock_auth_service):
        """Test user creation with validation error"""
        service = UserManagementService(
            database=mock_database_service,
            auth=mock_auth_service
        )
        
        invalid_user_data = UserCreate(
            name="",  # Invalid empty name
            email="invalid-email",
            password="weak",  # Weak password
            age=15  # Underage
        )
        
        with pytest.raises(ValidationError) as exc_info:
            await service.create_user(invalid_user_data)
        
        assert "validation failed" in str(exc_info.value).lower()
        mock_database_service.create_user.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_get_user_by_id_success(self, mock_database_service):
        """Test successful user retrieval by ID"""
        service = UserManagementService(database=mock_database_service)
        
        expected_user = User(id=1, name="Test User", email="test@example.com", age=25)
        mock_database_service.get_user.return_value = expected_user
        
        result = await service.get_user_by_id(1)
        
        assert result == expected_user
        mock_database_service.get_user.assert_called_once_with(1)
    
    @pytest.mark.asyncio
    async def test_get_user_by_id_not_found(self, mock_database_service):
        """Test user retrieval when user not found"""
        service = UserManagementService(database=mock_database_service)
        
        mock_database_service.get_user.return_value = None
        
        with pytest.raises(NotFoundError) as exc_info:
            await service.get_user_by_id(999)
        
        assert "user not found" in str(exc_info.value).lower()
        mock_database_service.get_user.assert_called_once_with(999)
    
    @pytest.mark.asyncio
    async def test_update_user_success(self, mock_database_service):
        """Test successful user update"""
        service = UserManagementService(database=mock_database_service)
        
        existing_user = User(id=1, name="Old Name", email="old@example.com", age=25)
        updated_data = {"name": "New Name", "age": 26}
        
        mock_database_service.get_user.return_value = existing_user
        mock_database_service.update_user.return_value = User(
            id=1, name="New Name", email="old@example.com", age=26
        )
        
        result = await service.update_user(1, updated_data)
        
        assert result.name == "New Name"
        assert result.age == 26
        mock_database_service.get_user.assert_called_once_with(1)
        mock_database_service.update_user.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_user_success(self, mock_database_service):
        """Test successful user deletion"""
        service = UserManagementService(database=mock_database_service)
        
        mock_database_service.get_user.return_value = User(id=1, name="Test User", email="test@example.com", age=25)
        mock_database_service.delete_user.return_value = True
        
        result = await service.delete_user(1)
        
        assert result is True
        mock_database_service.get_user.assert_called_once_with(1)
        mock_database_service.delete_user.assert_called_once_with(1)

class TestProductService:
    """Test product service business logic"""
    
    @pytest.mark.asyncio
    async def test_create_product_success(self, mock_database_service):
        """Test successful product creation"""
        service = ProductService(database=mock_database_service)
        
        product_data = ProductCreate(
            name="New Product",
            price=10.99,
            quantity=100,
            category="electronics"
        )
        
        expected_product = Product(
            id=1, name=product_data.name, price=product_data.price,
            quantity=product_data.quantity, category=product_data.category
        )
        mock_database_service.create_product.return_value = expected_product
        
        result = await service.create_product(product_data)
        
        assert result == expected_product
        mock_database_service.create_product.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_product_stock(self, mock_database_service):
        """Test updating product stock quantity"""
        service = ProductService(database=mock_database_service)
        
        existing_product = Product(id=1, name="Test Product", price=10.99, quantity=50)
        mock_database_service.get_product.return_value = existing_product
        mock_database_service.update_product.return_value = Product(
            id=1, name="Test Product", price=10.99, quantity=75
        )
        
        result = await service.update_stock(1, 25)  # Add 25 to stock
        
        assert result.quantity == 75
        mock_database_service.get_product.assert_called_once_with(1)
        mock_database_service.update_product.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_products_by_category(self, mock_database_service):
        """Test retrieving products by category"""
        service = ProductService(database=mock_database_service)
        
        electronics_products = [
            Product(id=1, name="Phone", price=999.99, quantity=10, category="electronics"),
            Product(id=2, name="Laptop", price=1299.99, quantity=5, category="electronics"),
        ]
        
        mock_database_service.list_products.return_value = electronics_products
        
        result = await service.get_products_by_category("electronics")
        
        assert len(result) == 2
        assert all(p.category == "electronics" for p in result)
        mock_database_service.list_products.assert_called_once()

# Integration Tests - API Endpoints and Data Flow
class TestUserAPI:
    """Test user API endpoints"""
    
    def test_create_user_endpoint_success(self, test_client, mock_database_service, mock_auth_service):
        """Test successful user creation via API"""
        with patch('your_app.main.user_service', UserManagementService(mock_database_service, mock_auth_service)):
            mock_database_service.create_user.return_value = User(
                id=1, name="Test User", email="test@example.com", age=25
            )
            
            user_data = {
                "name": "Test User",
                "email": "test@example.com",
                "password": "SecurePass123!",
                "age": 25
            }
            
            response = test_client.post("/api/users", json=user_data)
            
            assert response.status_code == 201
            assert response.json()["name"] == "Test User"
            assert response.json()["email"] == "test@example.com"
    
    def test_create_user_endpoint_validation_error(self, test_client):
        """Test user creation API with validation error"""
        invalid_user_data = {
            "name": "",  # Invalid
            "email": "invalid-email",
            "password": "weak",
            "age": 15
        }
        
        response = test_client.post("/api/users", json=invalid_user_data)
        
        assert response.status_code == 422
        assert "detail" in response.json()
    
    def test_get_user_endpoint_success(self, test_client, mock_database_service):
        """Test successful user retrieval via API"""
        with patch('your_app.main.user_service', UserManagementService(mock_database_service)):
            expected_user = User(id=1, name="Test User", email="test@example.com", age=25)
            mock_database_service.get_user.return_value = expected_user
            
            response = test_client.get("/api/users/1")
            
            assert response.status_code == 200
            assert response.json()["id"] == 1
            assert response.json()["name"] == "Test User"
    
    def test_get_user_endpoint_not_found(self, test_client, mock_database_service):
        """Test user retrieval API when user not found"""
        with patch('your_app.main.user_service', UserManagementService(mock_database_service)):
            mock_database_service.get_user.return_value = None
            
            response = test_client.get("/api/users/999")
            
            assert response.status_code == 404
            assert "not found" in response.json()["detail"].lower()
    
    def test_update_user_endpoint_success(self, test_client, mock_database_service):
        """Test successful user update via API"""
        with patch('your_app.main.user_service', UserManagementService(mock_database_service)):
            existing_user = User(id=1, name="Old Name", email="old@example.com", age=25)
            updated_user = User(id=1, name="New Name", email="old@example.com", age=26)
            
            mock_database_service.get_user.return_value = existing_user
            mock_database_service.update_user.return_value = updated_user
            
            update_data = {"name": "New Name", "age": 26}
            response = test_client.put("/api/users/1", json=update_data)
            
            assert response.status_code == 200
            assert response.json()["name"] == "New Name"
            assert response.json()["age"] == 26
    
    def test_delete_user_endpoint_success(self, test_client, mock_database_service):
        """Test successful user deletion via API"""
        with patch('your_app.main.user_service', UserManagementService(mock_database_service)):
            mock_database_service.get_user.return_value = User(id=1, name="Test User", email="test@example.com", age=25)
            mock_database_service.delete_user.return_value = True
            
            response = test_client.delete("/api/users/1")
            
            assert response.status_code == 204

class TestProductAPI:
    """Test product API endpoints"""
    
    def test_create_product_endpoint_success(self, test_client, mock_database_service):
        """Test successful product creation via API"""
        with patch('your_app.main.product_service', ProductService(mock_database_service)):
            expected_product = Product(id=1, name="Test Product", price=10.99, quantity=100, category="electronics")
            mock_database_service.create_product.return_value = expected_product
            
            product_data = {
                "name": "Test Product",
                "price": 10.99,
                "quantity": 100,
                "category": "electronics"
            }
            
            response = test_client.post("/api/products", json=product_data)
            
            assert response.status_code == 201
            assert response.json()["name"] == "Test Product"
            assert response.json()["price"] == 10.99
    
    def test_list_products_endpoint_success(self, test_client, mock_database_service):
        """Test successful product listing via API"""
        with patch('your_app.main.product_service', ProductService(mock_database_service)):
            products = [
                Product(id=1, name="Product 1", price=10.99, quantity=50, category="electronics"),
                Product(id=2, name="Product 2", price=20.50, quantity=30, category="books"),
            ]
            
            mock_database_service.list_products.return_value = products
            
            response = test_client.get("/api/products")
            
            assert response.status_code == 200
            assert len(response.json()) == 2
            assert response.json()[0]["name"] == "Product 1"
            assert response.json()[1]["name"] == "Product 2"
    
    def test_get_products_by_category_endpoint(self, test_client, mock_database_service):
        """Test retrieving products by category via API"""
        with patch('your_app.main.product_service', ProductService(mock_database_service)):
            electronics_products = [
                Product(id=1, name="Phone", price=999.99, quantity=10, category="electronics"),
            ]
            
            mock_database_service.list_products.return_value = electronics_products
            
            response = test_client.get("/api/products?category=electronics")
            
            assert response.status_code == 200
            assert len(response.json()) == 1
            assert response.json()[0]["category"] == "electronics"

# Feature Tests - Complete User Workflows
class TestUserRegistrationFeature:
    """Test complete user registration feature"""
    
    @pytest.mark.asyncio
    async def test_complete_registration_workflow(self, async_client, mock_database_service, mock_auth_service):
        """Test complete user registration workflow"""
        with patch('your_app.main.user_service', UserManagementService(mock_database_service, mock_auth_service)):
            # Mock successful user creation
            created_user = User(id=1, name="John Doe", email="john@example.com", age=25)
            mock_database_service.create_user.return_value = created_user
            
            # Registration data
            registration_data = {
                "name": "John Doe",
                "email": "john@example.com",
                "password": "SecurePass123!",
                "confirm_password": "SecurePass123!",
                "age": 25,
                "accept_terms": True
            }
            
            # Register user
            response = await async_client.post("/api/auth/register", json=registration_data)
            
            assert response.status_code == 201
            assert response.json()["user"]["name"] == "John Doe"
            assert response.json()["user"]["email"] == "john@example.com"
            assert "token" in response.json()
            
            # Verify password was hashed
            mock_auth_service.hash_password.assert_called_once_with("SecurePass123!")
            
            # Verify user was saved to database
            mock_database_service.create_user.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_registration_with_weak_password(self, async_client):
        """Test registration workflow with weak password"""
        registration_data = {
            "name": "John Doe",
            "email": "john@example.com",
            "password": "weak",  # Weak password
            "confirm_password": "weak",
            "age": 25,
            "accept_terms": True
        }
        
        response = await async_client.post("/api/auth/register", json=registration_data)
        
        assert response.status_code == 400
        assert "password too weak" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_registration_password_mismatch(self, async_client):
        """Test registration workflow with password mismatch"""
        registration_data = {
            "name": "John Doe",
            "email": "john@example.com",
            "password": "SecurePass123!",
            "confirm_password": "DifferentPass123!",
            "age": 25,
            "accept_terms": True
        }
        
        response = await async_client.post("/api/auth/register", json=registration_data)
        
        assert response.status_code == 400
        assert "passwords do not match" in response.json()["detail"].lower()

class TestProductPurchaseFeature:
    """Test complete product purchase feature"""
    
    @pytest.mark.asyncio
    async def test_complete_purchase_workflow(self, async_client, mock_database_service):
        """Test complete product purchase workflow"""
        with patch('your_app.main.product_service', ProductService(mock_database_service)):
            # Mock product availability
            product = Product(id=1, name="Test Product", price=10.99, quantity=100, category="electronics")
            mock_database_service.get_product.return_value = product
            
            # Mock successful stock update
            updated_product = Product(id=1, name="Test Product", price=10.99, quantity=95, category="electronics")
            mock_database_service.update_product.return_value = updated_product
            
            # Purchase data
            purchase_data = {
                "product_id": 1,
                "quantity": 5,
                "payment_method": "credit_card"
            }
            
            # Create purchase
            response = await async_client.post("/api/purchases", json=purchase_data)
            
            assert response.status_code == 201
            assert response.json()["product_id"] == 1
            assert response.json()["quantity"] == 5
            assert response.json()["total_amount"] == 54.95  # 5 * 10.99
            assert response.json()["status"] == "completed"
            
            # Verify stock was updated
            mock_database_service.get_product.assert_called_once_with(1)
            mock_database_service.update_product.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_purchase_insufficient_stock(self, async_client, mock_database_service):
        """Test purchase workflow with insufficient stock"""
        with patch('your_app.main.product_service', ProductService(mock_database_service)):
            # Mock product with low stock
            product = Product(id=1, name="Test Product", price=10.99, quantity=2, category="electronics")
            mock_database_service.get_product.return_value = product
            
            # Purchase data requesting more than available
            purchase_data = {
                "product_id": 1,
                "quantity": 5,
                "payment_method": "credit_card"
            }
            
            response = await async_client.post("/api/purchases", json=purchase_data)
            
            assert response.status_code == 400
            assert "insufficient stock" in response.json()["detail"].lower()

class TestUserDashboardFeature:
    """Test complete user dashboard feature"""
    
    @pytest.mark.asyncio
    async def test_dashboard_data_aggregation(self, async_client, mock_database_service):
        """Test dashboard data aggregation feature"""
        with patch('your_app.main.user_service', UserManagementService(mock_database_service)), \
             patch('your_app.main.product_service', ProductService(mock_database_service)):
            
            # Mock user data
            user = User(id=1, name="Test User", email="test@example.com", age=25)
            mock_database_service.get_user.return_value = user
            
            # Mock user's recent purchases
            recent_purchases = [
                {"id": 1, "product_name": "Product 1", "total_amount": 10.99, "created_at": datetime.now()},
                {"id": 2, "product_name": "Product 2", "total_amount": 20.50, "created_at": datetime.now()},
            ]
            
            # Mock recommended products
            recommended_products = [
                Product(id=3, name="Recommended 1", price=15.99, quantity=50, category="electronics"),
                Product(id=4, name="Recommended 2", price: 25.99, quantity=30, category="books"),
            ]
            
            mock_database_service.list_products.return_value = recommended_products
            
            # Get dashboard data
            response = await async_client.get("/api/dashboard/1")
            
            assert response.status_code == 200
            
            dashboard_data = response.json()
            assert dashboard_data["user"]["name"] == "Test User"
            assert len(dashboard_data["recent_purchases"]) == 2
            assert len(dashboard_data["recommended_products"]) == 2
            assert dashboard_data["total_spent"] == 31.48  # 10.99 + 20.50

# Performance Tests
class TestPerformance:
    """Test performance of critical operations"""
    
    @pytest.mark.asyncio
    async def test_large_product_list_performance(self, mock_database_service):
        """Test performance of large product list retrieval"""
        service = ProductService(database=mock_database_service)
        
        # Generate large product list
        large_product_list = [
            Product(id=i, name=f"Product {i}", price=10.99 + i, quantity=100, category="electronics")
            for i in range(1000)
        ]
        
        mock_database_service.list_products.return_value = large_product_list
        
        # Measure execution time
        import time
        start_time = time.time()
        
        result = await service.list_products()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        assert len(result) == 1000
        assert execution_time < 1.0  # Should complete within 1 second
    
    def test_user_validation_performance(self):
        """Test performance of user validation"""
        user_data = {
            "id": 1,
            "name": "Test User",
            "email": "test@example.com",
            "age": 25,
            "active": True,
            "created_at": datetime.now()
        }
        
        user = User(**user_data)
        
        # Measure validation performance
        import time
        start_time = time.time()
        
        for _ in range(1000):
            user.is_valid()
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        assert execution_time < 0.1  # Should complete 1000 validations within 0.1 seconds

# Test Utilities and Helpers
class TestDataFactory:
    """Factory for creating test data"""
    
    @staticmethod
    def create_user(**overrides):
        """Create test user with optional overrides"""
        default_user = {
            "id": 1,
            "name": "Test User",
            "email": "test@example.com",
            "age": 25,
            "active": True,
            "created_at": datetime.now()
        }
        default_user.update(overrides)
        return User(**default_user)
    
    @staticmethod
    def create_product(**overrides):
        """Create test product with optional overrides"""
        default_product = {
            "id": 1,
            "name": "Test Product",
            "price": 10.99,
            "quantity": 100,
            "category": "electronics",
            "created_at": datetime.now()
        }
        default_product.update(overrides)
        return Product(**default_product)
    
    @staticmethod
    def create_user_list(count):
        """Create list of test users"""
        return [TestDataFactory.create_user(id=i, name=f"User {i}", email=f"user{i}@example.com") 
                for i in range(1, count + 1)]
    
    @staticmethod
    def create_product_list(count):
        """Create list of test products"""
        return [TestDataFactory.create_product(id=i, name=f"Product {i}", price=10.99 + i) 
                for i in range(1, count + 1)]

class CustomAssertions:
    """Custom assertion methods for testing"""
    
    @staticmethod
    def assert_valid_user(user):
        """Assert that user data is valid"""
        assert user.id > 0, "User ID should be positive"
        assert len(user.name) > 0, "User name should not be empty"
        assert "@" in user.email and "." in user.email, "User email should be valid"
        assert 18 <= user.age <= 120, "User age should be between 18 and 120"
        assert user.is_valid(), "User should pass validation"
    
    @staticmethod
    def assert_valid_product(product):
        """Assert that product data is valid"""
        assert product.id > 0, "Product ID should be positive"
        assert len(product.name) > 0, "Product name should not be empty"
        assert product.price > 0, "Product price should be positive"
        assert product.quantity >= 0, "Product quantity should be non-negative"
        assert product.has_valid_price(), "Product should have valid price"
    
    @staticmethod
    def assert_api_response_structure(response, expected_status=200):
        """Assert that API response has expected structure"""
        assert response.status_code == expected_status, f"Expected status {expected_status}, got {response.status_code}"
        
        if response.status_code < 400:
            # Success response should have data
            assert "data" in response.json() or response.json() != {}, "Success response should contain data"
        else:
            # Error response should have error details
            assert "detail" in response.json(), "Error response should contain detail"

# Test Configuration
class TestConfig:
    """Test configuration constants"""
    
    TIMEOUT_SECONDS = 30
    MAX_RETRIES = 3
    TEST_DATABASE_URL = "sqlite:///:memory:"
    TEST_API_BASE_URL = "http://localhost:8000/api"
    PERFORMANCE_THRESHOLD_SECONDS = 1.0

if __name__ == "__main__":
    # Run tests when script is executed directly
    pytest.main([__file__, "-v"])
```

## Guidelines

### Test Organization
- **Unit Tests**: Business logic, models, services with comprehensive mocking
- **Integration Tests**: API endpoints and data flow validation
- **Feature Tests**: Complete user workflows and feature validation
- **Performance Tests**: Critical path performance validation

### Test Structure
- Use `pytest` fixtures for reusable test setup
- Use `@pytest.mark.asyncio` for async test functions
- Use `unittest.mock` for mocking external dependencies
- Use descriptive test names and docstrings

### Coverage Requirements
- **Unit Tests**: 85%+ coverage for business logic
- **Integration Tests**: 75%+ coverage for API endpoints
- **Feature Tests**: 70%+ coverage for user workflows
- **Overall**: 80%+ minimum for Core tier

## Required Dependencies

Add to `requirements.txt` or `pyproject.toml`:

```txt
pytest>=7.4.0
pytest-cov>=4.1.0
pytest-mock>=3.11.1
pytest-asyncio>=0.21.1
httpx>=0.24.1
fastapi>=0.104.1
```

## What's Included

- **Unit Tests**: Business logic, models, services with comprehensive mocking
- **Integration Tests**: FastAPI endpoints and data persistence
- **Feature Tests**: Complete user workflows (registration, purchase, dashboard)
- **Performance Tests**: Critical path performance validation
- **Test Helpers**: Data factories and custom assertions

## What's NOT Included

- Database migration tests
- Third-party service integration tests
- Load testing with real traffic
- Security penetration tests

---

**Template Version**: 2.0 (Core)  
**Last Updated**: 2025-12-10  
**Stack**: Python  
**Tier**: Core  
**Framework**: pytest + FastAPI + AsyncIO
