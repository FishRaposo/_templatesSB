<!--
File: integration-tests.tpl.md
Purpose: Comprehensive integration testing template for generic/technology-agnostic projects
Template Version: 1.0
-->

# ----------------------------------------------------------------------------- 
# FILE: integration-tests.tpl.md
# PURPOSE: Comprehensive integration testing for generic/technology-agnostic projects
# USAGE: Technology-agnostic integration testing principles and patterns
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Integration Testing Suite - Generic Implementation

## Overview

This comprehensive integration testing suite provides technology-agnostic patterns for testing component interactions, API integrations, database operations, and cross-system communication. It focuses on universal integration testing principles that apply across all technology stacks.

## Core Integration Testing Principles

### 1. Integration Test Categories

#### Component Integration
- **Service-to-Service**: Internal service communication
- **Module-to-Module**: Cross-module dependencies
- **Layer-to-Layer**: Presentation, business, data layer integration
- **Library Integration**: Third-party library interactions

#### Data Integration
- **Database Integration**: CRUD operations, transactions, constraints
- **Cache Integration**: Redis, Memcached, in-memory caching
- **File System Integration**: File upload, storage, retrieval
- **Message Queue Integration**: Async messaging, event processing

#### External Integration
- **API Integration**: REST, GraphQL, gRPC endpoints
- **Authentication Integration**: OAuth, SAML, JWT flows
- **Payment Integration**: Payment gateway interactions
- **Notification Integration**: Email, SMS, push notifications

### 2. Universal Integration Patterns

#### Service Container Pattern
```pseudocode
class IntegrationTestContainer:
    function __init__():
        self.services = {}
        self.databases = {}
        self.external_apis = {}
        self.message_queues = {}
    
    function register_service(name, service_instance):
        self.services[name] = service_instance
    
    function register_database(name, database_connection):
        self.databases[name] = database_connection
    
    function register_external_api(name, api_client):
        self.external_apis[name] = api_client
    
    function start_all():
        # Start all services in dependency order
        for service in topological_sort(self.services):
            service.start()
    
    function stop_all():
        # Stop all services in reverse order
        for service in reversed(topological_sort(self.services)):
            service.stop()
    
    function reset_all():
        # Reset all services to clean state
        for service in self.services.values():
            service.reset()
        
        for database in self.databases.values():
            database.cleanup()
```

#### Test Data Seeding Pattern
```pseudocode
class IntegrationTestDataSeeder:
    function __init__(database_manager, fixture_loader):
        self.db = database_manager
        self.fixtures = fixture_loader
    
    function seed_minimum_viable_data():
        # Seed essential data for basic functionality
        admin_user = self.create_admin_user()
        system_settings = self.create_system_settings()
        basic_permissions = self.create_basic_permissions()
        
        return {
            "admin_user": admin_user,
            "system_settings": system_settings,
            "permissions": basic_permissions
        }
    
    function seed_typical_usage_scenario():
        # Seed data representing normal usage
        users = self.create_user_base(count=10)
        products = self.create_product_catalog(count=50)
        orders = self.create_order_history(count=20)
        
        return {
            "users": users,
            "products": products,
            "orders": orders
        }
    
    function seed_edge_case_scenario():
        # Seed data for boundary testing
        edge_cases = {
            "empty_collections": self.create_empty_collections(),
            "maximum_size_objects": self.create_maximum_size_objects(),
            "special_characters": self.create_special_character_data(),
            "boundary_values": self.create_boundary_value_data()
        }
        
        return edge_cases
    
    function create_relational_data():
        # Create interconnected data for relationship testing
        author = self.create_author()
        books = self.create_books(author_id=author.id, count=3)
        reviews = self.create_reviews_for_books(books)
        
        return {
            "author": author,
            "books": books,
            "reviews": reviews,
            "relationships": {
                "author_books": [book.author_id == author.id for book in books],
                "book_reviews": self.group_reviews_by_book(reviews, books)
            }
        }
```

#### Mock Service Pattern
```pseudocode
class IntegrationMockService:
    function __init__(port, service_name):
        self.port = port
        self.service_name = service_name
        self.endpoints = {}
        self.request_log = []
        self.response_delays = {}
        self.failure_simulations = {}
    
    function add_endpoint(method, path, response, status_code=200):
        endpoint_key = f"{method}:{path}"
        self.endpoints[endpoint_key] = {
            "response": response,
            "status_code": status_code,
            "call_count": 0,
            "response_time": 100  # Default 100ms
        }
    
    function add_dynamic_endpoint(method, path, response_function):
        endpoint_key = f"{method}:{path}"
        self.endpoints[endpoint_key] = {
            "dynamic_response": response_function,
            "call_count": 0
        }
    
    function simulate_timeout(path, timeout_ms=5000):
        self.response_delays[path] = timeout_ms + 1000  # Exceed timeout
    
    function simulate_failure(path, failure_rate=0.5):
        self.failure_simulations[path] = failure_rate
    
    function handle_request(request):
        # Log incoming request
        self.log_request(request)
        
        endpoint_key = f"{request.method}:{request.path}"
        endpoint = self.endpoints.get(endpoint_key)
        
        if not endpoint:
            return create_response(404, {"error": "Endpoint not found"})
        
        # Simulate failures if configured
        if self.should_simulate_failure(request.path):
            return create_response(500, {"error": "Simulated failure"})
        
        # Add response delay if configured
        delay = self.response_delays.get(request.path, endpoint.get("response_time", 0))
        if delay > 0:
            sleep(delay)
        
        # Generate response
        if "dynamic_response" in endpoint:
            response_data = endpoint["dynamic_response"](request)
        else:
            response_data = endpoint["response"]
        
        endpoint["call_count"] += 1
        
        return create_response(
            endpoint.get("status_code", 200),
            response_data
        )
    
    function verify_call_count(method, path, expected_count):
        endpoint_key = f"{method}:{path}"
        endpoint = self.endpoints.get(endpoint_key)
        
        if not endpoint:
            return false
        
        return endpoint["call_count"] == expected_count
    
    function get_request_log():
        return self.request_log.copy()
    
    function reset():
        self.request_log.clear()
        for endpoint in self.endpoints.values():
            endpoint["call_count"] = 0
```

### 3. Database Integration Testing

#### Transaction Testing
```pseudocode
class DatabaseIntegrationTest:
    function test_transaction_commit():
        # Arrange
        initial_balance = account_repository.get_balance("user123")
        transfer_amount = 100
        
        # Act
        transaction_result = transaction_manager.execute({
            debit_operation: {
                account_id: "user123",
                amount: transfer_amount
            },
            credit_operation: {
                account_id: "user456", 
                amount: transfer_amount
            }
        })
        
        # Assert
        assert transaction_result.success == true
        
        new_balance = account_repository.get_balance("user123")
        assert new_balance == initial_balance - transfer_amount
        
        recipient_balance = account_repository.get_balance("user456")
        assert recipient_balance == initial_recipient_balance + transfer_amount
    
    function test_transaction_rollback():
        # Arrange
        initial_balance = account_repository.get_balance("user123")
        
        # Act - Simulate operation that fails
        try:
            transaction_manager.execute({
                valid_operation: {
                    account_id: "user123",
                    amount: 50
                },
                failing_operation: {
                    account_id: "invalid_account",  # This will fail
                    amount: 50
                }
            })
            assert false, "Transaction should have failed"
        except TransactionFailedException:
            pass  # Expected
        
        # Assert - Verify rollback
        final_balance = account_repository.get_balance("user123")
        assert final_balance == initial_balance  # No change due to rollback
    
    function test_database_constraints():
        # Test unique constraints
        user_data = { "email": "unique@example.com", "username": "unique_user" }
        
        # First insertion should succeed
        result1 = user_repository.create(user_data)
        assert result1.success == true
        
        # Second insertion with same email should fail
        duplicate_data = { "email": "unique@example.com", "username": "different_user" }
        result2 = user_repository.create(duplicate_data)
        assert result2.success == false
        assert result2.error_type == "constraint_violation"
        
        # Test foreign key constraints
        order_data = { "user_id": "nonexistent_user", "items": [] }
        result3 = order_repository.create(order_data)
        assert result3.success == false
        assert result3.error_type == "foreign_key_violation"
```

#### Migration Testing
```pseudocode
class DatabaseMigrationTest:
    function test_migration_up():
        # Arrange - Start with old schema version
        database_manager.set_schema_version("1.0")
        
        # Act - Apply migration
        migration_result = migration_manager.migrate_up("1.1")
        
        # Assert
        assert migration_result.success == true
        assert database_manager.get_schema_version() == "1.1"
        
        # Verify new columns exist
        table_schema = database_manager.get_table_schema("users")
        assert "new_column" in table_schema.columns
    
    function test_migration_down():
        # Arrange - Start with new schema version
        database_manager.set_schema_version("1.1")
        
        # Act - Rollback migration
        rollback_result = migration_manager.migrate_down("1.0")
        
        # Assert
        assert rollback_result.success == true
        assert database_manager.get_schema_version() == "1.0"
        
        # Verify old schema is restored
        table_schema = database_manager.get_table_schema("users")
        assert "new_column" not in table_schema.columns
    
    function test_data_migration():
        # Arrange - Create data in old format
        old_data = [
            { "first_name": "John", "last_name": "Doe" },
            { "first_name": "Jane", "last_name": "Smith" }
        ]
        
        for record in old_data:
            database_manager.insert("users", record)
        
        # Act - Apply data migration
        migration_result = migration_manager.migrate_data("split_name_to_full_name")
        
        # Assert - Verify data transformation
        assert migration_result.success == true
        
        migrated_records = database_manager.query("SELECT * FROM users")
        for record in migrated_records:
            assert record.full_name != null
            assert record.first_name == null  # Old column removed
            assert record.last_name == null   # Old column removed
```

### 4. API Integration Testing

#### REST API Testing
```pseudocode
class RESTAPIIntegrationTest:
    function test_crud_operations():
        # Test Create
        create_response = api_client.post("/api/users", {
            "username": "test_user",
            "email": "test@example.com",
            "password": "TestPass123!"
        })
        
        assert create_response.status_code == 201
        assert create_response.data.id != null
        created_user_id = create_response.data.id
        
        # Test Read
        read_response = api_client.get(f"/api/users/{created_user_id}")
        assert read_response.status_code == 200
        assert read_response.data.username == "test_user"
        assert read_response.data.email == "test@example.com"
        
        # Test Update
        update_response = api_client.put(f"/api/users/{created_user_id}", {
            "username": "updated_user"
        })
        assert update_response.status_code == 200
        assert update_response.data.username == "updated_user"
        
        # Test Delete
        delete_response = api_client.delete(f"/api/users/{created_user_id}")
        assert delete_response.status_code == 204
        
        # Verify deletion
        verify_response = api_client.get(f"/api/users/{created_user_id}")
        assert verify_response.status_code == 404
    
    function test_api_error_handling():
        # Test validation errors
        invalid_data = { "username": "", "email": "invalid-email" }
        response = api_client.post("/api/users", invalid_data)
        
        assert response.status_code == 400
        assert response.data.errors != null
        assert response.data.errors.username != null
        assert response.data.errors.email != null
        
        # Test authentication errors
        unauthenticated_response = api_client.get("/api/protected-resource")
        assert unauthenticated_response.status_code == 401
        
        # Test authorization errors
        unauthorized_response = api_client.get("/api/admin-only-resource")
        assert unauthorized_response.status_code == 403
    
    function test_api_pagination():
        # Create multiple items
        for i in range(25):
            api_client.post("/api/items", {
                "name": f"Item {i}",
                "description": f"Description for item {i}"
            })
        
        # Test page 1
        page1_response = api_client.get("/api/items?page=1&limit=10")
        assert page1_response.status_code == 200
        assert len(page1_response.data.items) == 10
        assert page1_response.data.pagination.page == 1
        assert page1_response.data.pagination.limit == 10
        assert page1_response.data.pagination.total >= 25
        
        # Test page 2
        page2_response = api_client.get("/api/items?page=2&limit=10")
        assert page2_response.status_code == 200
        assert len(page2_response.data.items) == 10
        assert page2_response.data.pagination.page == 2
        
        # Verify no overlap between pages
        page1_ids = [item.id for item in page1_response.data.items]
        page2_ids = [item.id for item in page2_response.data.items]
        assert len(intersection(page1_ids, page2_ids)) == 0
    
    function test_api_filtering_and_sorting():
        # Create test data with various attributes
        test_items = [
            { "name": "Alpha", "category": "A", "price": 100 },
            { "name": "Beta", "category": "B", "price": 200 },
            { "name": "Charlie", "category": "A", "price": 150 },
            { "name": "Delta", "category": "B", "price": 250 }
        ]
        
        for item in test_items:
            api_client.post("/api/items", item)
        
        # Test filtering by category
        filtered_response = api_client.get("/api/items?category=A")
        assert filtered_response.status_code == 200
        assert len(filtered_response.data.items) == 2
        assert all(item.category == "A" for item in filtered_response.data.items)
        
        # Test sorting by price
        sorted_response = api_client.get("/api/items?sort=price&order=asc")
        assert sorted_response.status_code == 200
        prices = [item.price for item in sorted_response.data.items]
        assert is_sorted(prices, ascending=True)
```

#### GraphQL API Testing
```pseudocode
class GraphQLIntegrationTest:
    function test_graphql_query():
        # Test basic query
        query = """
        query {
            users(limit: 5) {
                id
                username
                email
                createdAt
            }
        }
        """
        
        response = graphql_client.query(query)
        assert response.status_code == 200
        assert response.data.users != null
        assert len(response.data.users) <= 5
        
        # Verify all requested fields are present
        for user in response.data.users:
            assert user.id != null
            assert user.username != null
            assert user.email != null
            assert user.createdAt != null
    
    function test_graphql_mutation():
        # Test mutation with variables
        mutation = """
        mutation CreateUser($input: CreateUserInput!) {
            createUser(input: $input) {
                id
                username
                email
            }
        }
        """
        
        variables = {
            "input": {
                "username": "graphql_user",
                "email": "graphql@example.com",
                "password": "GraphPass123!"
            }
        }
        
        response = graphql_client.mutate(mutation, variables)
        assert response.status_code == 200
        assert response.data.createUser != null
        assert response.data.createUser.username == "graphql_user"
        assert response.data.createUser.email == "graphql@example.com"
    
    function test_graphql_errors():
        # Test validation error
        invalid_mutation = """
        mutation {
            createUser(input: {
                username: "",
                email: "invalid-email",
                password: "weak"
            }) {
                id
            }
        }
        """
        
        response = graphql_client.mutate(invalid_mutation)
        assert response.status_code == 200  # GraphQL returns 200 even with errors
        assert response.errors != null
        assert len(response.errors) > 0
        
        # Verify error structure
        error = response.errors[0]
        assert error.message != null
        assert error.extensions != null
```

### 5. Message Queue Integration Testing

#### Message Publishing and Consumption
```pseudocode
class MessageQueueIntegrationTest:
    function test_message_publishing():
        # Arrange
        test_message = {
            "type": "user_registered",
            "payload": {
                "user_id": "user123",
                "email": "newuser@example.com",
                "timestamp": current_timestamp()
            }
        }
        
        # Act
        publish_result = message_queue.publish("user-events", test_message)
        
        # Assert
        assert publish_result.success == true
        assert publish_result.message_id != null
    
    function test_message_consumption():
        # Arrange - Publish test message
        test_message = {
            "type": "order_created",
            "payload": { "order_id": "order456", "amount": 99.99 }
        }
        
        message_queue.publish("order-events", test_message)
        
        # Act - Consume message
        consumed_messages = []
        
        def message_handler(message):
            consumed_messages.append(message)
            return true  # Acknowledge message
        
        consumer = message_queue.create_consumer("order-events", message_handler)
        consumer.start()
        
        # Wait for message processing
        sleep(2000)
        consumer.stop()
        
        # Assert
        assert len(consumed_messages) == 1
        assert consumed_messages[0].type == "order_created"
        assert consumed_messages[0].payload.order_id == "order456"
    
    function test_message_retry_mechanism():
        # Arrange - Create consumer that fails first time
        attempt_count = 0
        processed_messages = []
        
        def failing_handler(message):
            nonlocal attempt_count
            attempt_count += 1
            
            if attempt_count == 1:
                return false  # Fail first attempt
            else:
                processed_messages.append(message)
                return true  # Succeed on retry
        
        # Act
        consumer = message_queue.create_consumer("retry-test", failing_handler)
        consumer.start()
        
        # Publish message
        message_queue.publish("retry-test", {"id": "retry-msg-1"})
        
        # Wait for retry mechanism
        sleep(5000)
        consumer.stop()
        
        # Assert
        assert len(processed_messages) == 1
        assert attempt_count == 2  # Failed once, succeeded on retry
```

### 6. Cross-Technology Integration Testing

#### Polyglot Persistence Testing
```pseudocode
class PolyglotPersistenceIntegrationTest:
    function test_relational_and_document_database_integration():
        # Arrange - Create user in relational database
        user_data = {
            "username": "polyglot_user",
            "email": "polyglot@example.com",
            "profile_data": { "preferences": { "theme": "dark" } }
        }
        
        # Act - Store in both databases
        relational_result = relational_db.insert("users", user_data)
        document_result = document_db.insert("user_profiles", {
            "user_id": relational_result.id,
            "extended_profile": user_data.profile_data
        })
        
        # Assert - Verify data consistency
        assert relational_result.success == true
        assert document_result.success == true
        
        # Verify cross-database reference integrity
        user_from_relational = relational_db.find_by_id("users", relational_result.id)
        profile_from_document = document_db.find_by_user_id("user_profiles", relational_result.id)
        
        assert user_from_relational != null
        assert profile_from_document != null
        assert profile_from_document.user_id == user_from_relational.id
    
    function test_cache_database_integration():
        # Arrange - Create data in primary database
        product_data = {
            "id": "product123",
            "name": "Test Product",
            "price": 99.99,
            "inventory_count": 50
        }
        
        primary_db.insert("products", product_data)
        
        # Act - Cache frequently accessed data
        cache_key = f"product:{product_data.id}"
        cache_result = cache.set(cache_key, product_data, ttl=3600)
        
        # Assert
        assert cache_result.success == true
        
        # Verify cache hit
        cached_product = cache.get(cache_key)
        assert cached_product != null
        assert cached_product.id == product_data.id
        assert cached_product.price == product_data.price
        
        # Test cache invalidation
        primary_db.update("products", product_data.id, { "price": 79.99 })
        cache.invalidate(cache_key)
        
        invalidated_product = cache.get(cache_key)
        assert invalidated_product == null  # Should be invalidated
```

#### Multi-Service Integration Testing
```pseudocode
class MicroserviceIntegrationTest:
    function test_service_discovery_and_communication():
        # Arrange - Register services
        service_registry.register("user-service", "http://user-service:8080")
        service_registry.register("order-service", "http://order-service:8081")
        service_registry.register("payment-service", "http://payment-service:8082")
        
        # Act - Test service discovery
        user_service_url = service_registry.discover("user-service")
        order_service_url = service_registry.discover("order-service")
        
        # Assert
        assert user_service_url != null
        assert order_service_url != null
        
        # Test inter-service communication
        user_client = create_service_client(user_service_url)
        order_client = create_service_client(order_service_url)
        
        # Create user and order
        user = user_client.create_user({ "name": "Test User" })
        order = order_client.create_order({ 
            "user_id": user.id,
            "items": [{ "product_id": "prod123", "quantity": 2 }]
        })
        
        assert user.id != null
        assert order.id != null
        assert order.user_id == user.id
    
    function test_circuit_breaker_pattern():
        # Arrange - Configure circuit breaker
        circuit_breaker = CircuitBreaker(
            failure_threshold=3,
            recovery_timeout=30000,
            expected_exception=ServiceUnavailableException
        )
        
        # Act - Simulate service failures
        failure_count = 0
        
        for i in range(5):
            try:
                circuit_breaker.execute({
                    # Simulate failing service call
                    if i < 3:
                        raise ServiceUnavailableException("Service unavailable")
                    else:
                        return "Success"
                })
            except ServiceUnavailableException:
                failure_count += 1
        
        # Assert
        assert failure_count == 5  # All calls should fail (circuit open)
        
        # Test circuit breaker state
        assert circuit_breaker.state == "OPEN"
        
        # Wait for recovery timeout
        sleep(31000)
        
        # Test recovery
        recovery_result = circuit_breaker.execute({
            return "Recovered"
        })
        
        assert recovery_result == "Recovered"
        assert circuit_breaker.state == "CLOSED"
```

## Implementation Guidelines

### 1. Test Environment Setup
- Use containerized services for consistency
- Implement proper service orchestration
- Configure service dependencies correctly
- Set up test data management

### 2. Test Data Management
- Create realistic test datasets
- Implement data cleanup strategies
- Use data factories for consistent generation
- Handle data conflicts and isolation

### 3. Service Mocking Strategy
- Mock external dependencies appropriately
- Implement realistic mock behaviors
- Configure mock response scenarios
- Handle edge cases and failures

### 4. Performance Considerations
- Set appropriate timeouts for operations
- Monitor resource usage during tests
- Implement performance assertions
- Test under load conditions

### 5. Reliability and Stability
- Handle flaky dependencies gracefully
- Implement retry mechanisms
- Use health checks for services
- Implement proper cleanup procedures

This comprehensive integration testing suite provides universal patterns for testing complex system interactions while maintaining technology-agnostic principles applicable across all technology stacks.