<!--
File: system-tests.tpl.md
Purpose: Comprehensive system testing template for generic/technology-agnostic projects
Template Version: 1.0
-->

# ----------------------------------------------------------------------------- 
# FILE: system-tests.tpl.md
# PURPOSE: Comprehensive system testing for generic/technology-agnostic projects
# USAGE: Technology-agnostic system testing principles and patterns
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# System Testing Suite - Generic Implementation

## Overview

This comprehensive system testing suite provides technology-agnostic patterns for end-to-end testing, complete workflow validation, and full system integration testing. It focuses on universal system testing principles that validate entire application ecosystems across all technology stacks.

## Core System Testing Principles

### 1. System Test Categories

#### End-to-End Workflow Testing
- **Complete User Journeys**: Registration → Authentication → Core Functionality
- **Business Process Flows**: Order processing, payment flows, content publishing
- **Multi-Step Transactions**: Complex operations spanning multiple services
- **Cross-System Integration**: Data flow between different system components

#### Environment Testing
- **Production-like Environments**: Staging, pre-production validation
- **Configuration Testing**: Environment-specific settings and parameters
- **Infrastructure Testing**: Database, cache, message queue functionality
- **Network Configuration**: Load balancers, proxies, firewall rules

#### Performance and Scalability Testing
- **Load Testing**: System behavior under expected load
- **Stress Testing**: System limits and breaking points
- **Volume Testing**: Large data set handling
- **Concurrency Testing**: Simultaneous user operations

#### Security Testing
- **Authentication Flows**: Login, logout, session management
- **Authorization Testing**: Role-based access control
- **Data Protection**: Encryption, secure transmission
- **Vulnerability Scanning**: Common security flaws

### 2. Universal System Testing Patterns

#### Complete Workflow Pattern
```pseudocode
class EndToEndWorkflowTest:
    function test_complete_user_registration_workflow():
        # Step 1: User Registration
        registration_data = {
            "username": "newuser_" + generate_timestamp(),
            "email": "newuser@example.com",
            "password": "SecurePass123!",
            "first_name": "Test",
            "last_name": "User"
        }
        
        registration_response = user_service.register_user(registration_data)
        assert registration_response.success == true
        assert registration_response.user_id != null
        user_id = registration_response.user_id
        
        # Step 2: Email Verification
        verification_token = email_service.get_verification_token(registration_data.email)
        assert verification_token != null
        
        verification_response = user_service.verify_email(user_id, verification_token)
        assert verification_response.success == true
        assert verification_response.email_verified == true
        
        # Step 3: User Login
        login_response = auth_service.login({
            "username": registration_data.username,
            "password": registration_data.password
        })
        assert login_response.success == true
        assert login_response.access_token != null
        assert login_response.refresh_token != null
        
        access_token = login_response.access_token
        
        # Step 4: Access Protected Resource
        profile_response = user_service.get_profile(user_id, access_token)
        assert profile_response.success == true
        assert profile_response.user.username == registration_data.username
        assert profile_response.user.email_verified == true
        
        # Step 5: User Profile Update
        update_response = user_service.update_profile(user_id, {
            "bio": "Test user bio",
            "preferences": { "theme": "dark", "language": "en" }
        }, access_token)
        assert update_response.success == true
        assert update_response.user.bio == "Test user bio"
        
        # Step 6: Password Change
        password_change_response = auth_service.change_password(user_id, {
            "current_password": registration_data.password,
            "new_password": "NewSecurePass456!"
        }, access_token)
        assert password_change_response.success == true
        
        # Step 7: Logout
        logout_response = auth_service.logout(access_token)
        assert logout_response.success == true
        
        # Step 8: Verify Logout (Token should be invalid)
        invalid_access_response = user_service.get_profile(user_id, access_token)
        assert invalid_access_response.success == false
        assert invalid_access_response.error_code == "UNAUTHORIZED"
```

#### Multi-Service Transaction Pattern
```pseudocode
class MultiServiceTransactionTest:
    function test_ecommerce_order_workflow():
        # Setup - Create test data across services
        user = user_service.create_test_user({
            "username": "shopper_" + generate_id(),
            "email": "shopper@example.com",
            "balance": 1000.00
        })
        
        products = inventory_service.create_test_products([
            { "name": "Laptop", "price": 899.99, "stock": 5 },
            { "name": "Mouse", "price": 29.99, "stock": 50 }
        ])
        
        # Step 1: Add Items to Cart
        cart_response = shopping_service.add_to_cart(user.id, products[0].id, 1)
        assert cart_response.success == true
        assert len(cart_response.cart.items) == 1
        
        cart_response = shopping_service.add_to_cart(user.id, products[1].id, 2)
        assert cart_response.success == true
        assert len(cart_response.cart.items) == 2
        
        # Step 2: Calculate Total
        checkout_response = shopping_service.calculate_checkout(user.id)
        assert checkout_response.success == true
        expected_total = 899.99 + (29.99 * 2)  # Laptop + 2 Mice
        assert checkout_response.total == expected_total
        
        # Step 3: Process Payment
        payment_response = payment_service.process_payment({
            "user_id": user.id,
            "amount": checkout_response.total,
            "payment_method": "credit_card",
            "card_token": "test_card_token_123"
        })
        assert payment_response.success == true
        assert payment_response.transaction_id != null
        
        # Step 4: Reserve Inventory
        reservation_response = inventory_service.reserve_items([
            { "product_id": products[0].id, "quantity": 1 },
            { "product_id": products[1].id, "quantity": 2 }
        ])
        assert reservation_response.success == true
        assert reservation_response.reservation_id != null
        
        # Step 5: Create Order
        order_response = order_service.create_order({
            "user_id": user.id,
            "items": cart_response.cart.items,
            "payment_transaction_id": payment_response.transaction_id,
            "inventory_reservation_id": reservation_response.reservation_id,
            "shipping_address": {
                "street": "123 Test St",
                "city": "Test City",
                "zip_code": "12345"
            }
        })
        assert order_response.success == true
        assert order_response.order_id != null
        assert order_response.order_status == "confirmed"
        
        # Step 6: Send Confirmation Email
        email_response = notification_service.send_order_confirmation({
            "user_id": user.id,
            "order_id": order_response.order_id,
            "order_total": checkout_response.total
        })
        assert email_response.success == true
        
        # Step 7: Update User Balance
        balance_response = user_service.get_balance(user.id)
        assert balance_response.success == true
        expected_balance = 1000.00 - checkout_response.total
        assert balance_response.balance == expected_balance
        
        # Step 8: Verify Inventory Deduction
        inventory_response = inventory_service.get_product_stock(products[0].id)
        assert inventory_response.success == true
        assert inventory_response.stock == 4  # Reduced by 1
        
        # Step 9: Schedule Shipping
        shipping_response = shipping_service.schedule_shipping({
            "order_id": order_response.order_id,
            "shipping_address": order_response.shipping_address
        })
        assert shipping_response.success == true
        assert shipping_response.tracking_number != null
```

#### Cross-System Data Flow Pattern
```pseudocode
class CrossSystemDataFlowTest:
    function test_data_synchronization_workflow():
        # System 1: CRM System
        crm_customer = crm_system.create_customer({
            "name": "Enterprise Corp",
            "industry": "Technology",
            "contact_email": "contact@enterprise.com"
        })
        
        # Verify customer created in CRM
        assert crm_customer.id != null
        assert crm_customer.sync_status == "pending"
        
        # System 2: ERP System (via integration layer)
        # Wait for data synchronization
        sleep(2000)  # Allow time for async sync
        
        erp_customer = erp_system.get_customer_by_crm_id(crm_customer.id)
        assert erp_customer != null
        assert erp_customer.name == crm_customer.name
        assert erp_customer.source_system == "CRM"
        
        # System 3: Billing System
        billing_account = billing_system.get_account_by_erp_id(erp_customer.id)
        assert billing_account != null
        assert billing_account.customer_name == erp_customer.name
        assert billing_account.status == "active"
        
        # Test bidirectional sync
        # Update in ERP system
        erp_system.update_customer(erp_customer.id, {
            "billing_address": {
                "street": "456 Business Ave",
                "city": "Commerce City",
                "country": "USA"
            }
        })
        
        # Wait for sync back to CRM
        sleep(2000)
        
        updated_crm_customer = crm_system.get_customer(crm_customer.id)
        assert updated_crm_customer.billing_address != null
        assert updated_crm_customer.billing_address.street == "456 Business Ave"
        
        # Test sync conflict resolution
        # Update same field in both systems simultaneously
        crm_system.update_customer(crm_customer.id, {
            "phone": "+1-555-CRM-PHONE"
        })
        
        erp_system.update_customer(erp_customer.id, {
            "phone": "+1-555-ERP-PHONE"
        })
        
        sleep(3000)  # Allow conflict resolution
        
        # Verify conflict resolution (CRM wins as source system)
        final_crm_customer = crm_system.get_customer(crm_customer.id)
        final_erp_customer = erp_system.get_customer(erp_customer.id)
        
        assert final_crm_customer.phone == "+1-555-CRM-PHONE"
        assert final_erp_customer.phone == "+1-555-CRM-PHONE"  # Synced from CRM
```

### 3. Performance and Load Testing

#### Load Testing Pattern
```pseudocode
class LoadTestingPattern:
    function test_system_under_load():
        # Configuration
        test_config = {
            "concurrent_users": 100,
            "requests_per_second": 50,
            "test_duration_seconds": 300,
            "ramp_up_time_seconds": 60
        }
        
        # Test scenarios
        scenarios = [
            {
                "name": "user_registration",
                "weight": 0.3,
                "script": user_registration_scenario
            },
            {
                "name": "product_browsing", 
                "weight": 0.5,
                "script": product_browsing_scenario
            },
            {
                "name": "checkout_process",
                "weight": 0.2,
                "script": checkout_process_scenario
            }
        ]
        
        # Execute load test
        load_test = LoadTestEngine(test_config)
        results = load_test.execute(scenarios)
        
        # Analyze results
        assert results.success_rate > 0.95  # 95% success rate
        assert results.avg_response_time < 2000  # < 2 seconds
        assert results.p95_response_time < 5000  # 95th percentile < 5 seconds
        assert results.error_rate < 0.05  # < 5% error rate
        
        # System stability checks
        assert results.memory_usage_peak < 0.8  # < 80% memory usage
        assert results.cpu_usage_peak < 0.9  # < 90% CPU usage
        assert results.database_connections_peak < 0.8  # < 80% DB connections
```

#### Stress Testing Pattern
```pseudocode
class StressTestingPattern:
    function test_system_breaking_point():
        # Gradually increase load until system breaks
        current_load = 10
        max_load = 1000
        load_increment = 10
        
        breaking_point_data = null
        
        while current_load <= max_load:
            print(f"Testing with {current_load} concurrent users")
            
            test_result = execute_load_test({
                "concurrent_users": current_load,
                "duration": 60,  # 1 minute at each level
                "scenarios": basic_user_scenarios
            })
            
            # Check for breaking indicators
            if (test_result.success_rate < 0.5 or  # Less than 50% success
                test_result.avg_response_time > 10000 or  # > 10 seconds
                test_result.error_rate > 0.3 or  # > 30% errors
                test_result.system_health.critical_errors > 0):
                
                breaking_point_data = {
                    "breaking_load": current_load,
                    "success_rate": test_result.success_rate,
                    "avg_response_time": test_result.avg_response_time,
                    "error_rate": test_result.error_rate,
                    "system_metrics": test_result.system_health
                }
                break
            
            current_load += load_increment
        
        # Assert breaking point was found
        assert breaking_point_data != null
        assert breaking_point_data.breaking_load > 50  # Should handle at least 50 users
        
        # Verify graceful degradation
        assert breaking_point_data.system_metrics.crashes == 0
        assert breaking_point_data.system_metrics.data_corruption == false
```

### 4. Security System Testing

#### Authentication Flow Testing
```pseudocode
class SecuritySystemTest:
    function test_complete_authentication_workflow():
        # Step 1: User Registration with Security Measures
        registration_data = {
            "username": "security_user",
            "email": "security@example.com",
            "password": "ComplexPass123!@#",
            "security_questions": [
                { "question": "First pet name", "answer": "Fluffy" },
                { "question": "Birth city", "answer": "Springfield" }
            ]
        }
        
        reg_response = auth_service.register(registration_data)
        assert reg_response.success == true
        assert reg_response.requires_email_verification == true
        
        # Step 2: Email Verification with Token Expiration
        verification_token = email_service.extract_token(registration_data.email)
        
        # Test token expiration
        sleep(3601000)  # Wait for token to expire (1 hour + 1 second)
        expired_response = auth_service.verify_email(reg_response.user_id, verification_token)
        assert expired_response.success == false
        assert expired_response.error == "TOKEN_EXPIRED"
        
        # Get new token
        new_token = auth_service.resend_verification_email(reg_response.user_id)
        verification_response = auth_service.verify_email(reg_response.user_id, new_token)
        assert verification_response.success == true
        
        # Step 3: Multi-Factor Authentication Setup
        mfa_setup_response = auth_service.setup_mfa(reg_response.user_id)
        assert mfa_setup_response.success == true
        assert mfa_setup_response.qr_code != null
        assert mfa_setup_response.backup_codes.length == 10
        
        # Simulate MFA code generation
        mfa_code = mfa_generator.generate_code(mfa_setup_response.secret)
        mfa_verify_response = auth_service.verify_mfa_setup(reg_response.user_id, mfa_code)
        assert mfa_verify_response.success == true
        
        # Step 4: Login with MFA
        login_attempt = auth_service.login({
            "username": registration_data.username,
            "password": registration_data.password
        })
        assert login_attempt.success == true
        assert login_attempt.requires_mfa == true
        
        # Complete MFA authentication
        final_login = auth_service.complete_mfa_login(
            login_attempt.session_id,
            mfa_code
        )
        assert final_login.success == true
        assert final_login.access_token != null
        assert final_login.refresh_token != null
        
        # Step 5: Session Management
        session_info = auth_service.get_session_info(final_login.session_id)
        assert session_info.success == true
        assert session_info.user_id == reg_response.user_id
        assert session_info.ip_address != null
        assert session_info.user_agent != null
        
        # Test session timeout
        sleep(1801000)  # Wait for session timeout (30 minutes + 1 second)
        expired_session_response = auth_service.validate_session(final_login.session_id)
        assert expired_session_response.success == false
        assert expired_session_response.error == "SESSION_EXPIRED"
```

#### Authorization and Access Control Testing
```pseudocode
    function test_role_based_access_control():
        # Setup - Create users with different roles
        admin_user = user_service.create_user({
            "username": "admin_user",
            "email": "admin@example.com",
            "roles": ["admin", "user"]
        })
        
        regular_user = user_service.create_user({
            "username": "regular_user", 
            "email": "user@example.com",
            "roles": ["user"]
        })
        
        guest_user = user_service.create_user({
            "username": "guest_user",
            "email": "guest@example.com", 
            "roles": ["guest"]
        })
        
        # Test admin access
        admin_token = auth_service.login({
            "username": admin_user.username,
            "password": "AdminPass123!"
        }).access_token
        
        # Admin should access all resources
        admin_resources = [
            "/api/admin/users",
            "/api/admin/settings",
            "/api/user/profile",
            "/api/public/status"
        ]
        
        for resource in admin_resources:
            access_result = auth_service.check_access(admin_token, resource, "GET")
            assert access_result.allowed == true
        
        # Test regular user access
        user_token = auth_service.login({
            "username": regular_user.username,
            "password": "UserPass123!"
        }).access_token
        
        # User should access user and public resources only
        user_access_tests = [
            { "resource": "/api/admin/users", "expected": false },
            { "resource": "/api/admin/settings", "expected": false },
            { "resource": "/api/user/profile", "expected": true },
            { "resource": "/api/public/status", "expected": true }
        ]
        
        for test in user_access_tests:
            access_result = auth_service.check_access(user_token, test.resource, "GET")
            assert access_result.allowed == test.expected
        
        # Test permission inheritance
        manager_user = user_service.create_user({
            "username": "manager_user",
            "email": "manager@example.com",
            "roles": ["manager", "user"],  # Manager inherits user permissions
            "permissions": ["manage_team", "view_reports"]
        })
        
        manager_token = auth_service.login({
            "username": manager_user.username,
            "password": "ManagerPass123!"
        }).access_token
        
        # Manager should have both manager and user permissions
        manager_access_tests = [
            { "resource": "/api/manager/team", "expected": true },
            { "resource": "/api/manager/reports", "expected": true },
            { "resource": "/api/user/profile", "expected": true },  # Inherited
            { "resource": "/api/admin/users", "expected": false }   # Not inherited
        ]
        
        for test in manager_access_tests:
            access_result = auth_service.check_access(manager_token, test.resource, "GET")
            assert access_result.allowed == test.expected
```

### 5. Disaster Recovery Testing

#### Backup and Restore Testing
```pseudocode
class DisasterRecoveryTest:
    function test_complete_system_backup_and_restore():
        # Setup - Create comprehensive test data
        test_data = {
            "users": user_service.create_test_users(count=100),
            "products": inventory_service.create_test_products(count=500),
            "orders": order_service.create_test_orders(count=200),
            "transactions": payment_service.create_test_transactions(count=150)
        }
        
        # Step 1: Create Full System Backup
        backup_result = backup_service.create_full_backup({
            "include_databases": true,
            "include_file_storage": true,
            "include_configurations": true,
            "backup_type": "complete_snapshot"
        })
        
        assert backup_result.success == true
        assert backup_result.backup_id != null
        assert backup_result.backup_size > 0
        assert backup_result.checksum != null
        
        # Step 2: Modify Data (Simulate changes after backup)
        additional_users = user_service.create_test_users(count=50)
        modified_products = []
        for product in test_data.products[:10]:
            updated = inventory_service.update_product(product.id, {
                "price": product.price * 1.1  # 10% price increase
            })
            modified_products.append(updated)
        
        # Step 3: Restore from Backup
        restore_result = restore_service.restore_from_backup(backup_result.backup_id, {
            "restore_type": "complete_restore",
            "target_environment": "test_restore",
            "validate_checksum": true
        })
        
        assert restore_result.success == true
        assert restore_result.restore_id != null
        assert restore_result.validation_passed == true
        
        # Step 4: Verify Restored Data Integrity
        restored_data_checks = {
            "users": user_service.count_users(),
            "products": inventory_service.count_products(),
            "orders": order_service.count_orders(),
            "transactions": payment_service.count_transactions()
        }
        
        # Should match original data counts (not including post-backup changes)
        assert restored_data_checks.users == 100  # Original 100, not 150
        assert restored_data_checks.products == 500
        assert restored_data_checks.orders == 200
        assert restored_data_checks.transactions == 150
        
        # Step 5: Verify Restored Product Prices
        for product in test_data.products:
            restored_product = inventory_service.get_product(product.id)
            assert restored_product.price == product.price  # Original price, not increased
        
        # Step 6: Test System Functionality After Restore
        functionality_test = {
            "user_login": auth_service.test_login(test_data.users[0].username),
            "product_search": inventory_service.search_products("laptop"),
            "order_creation": order_service.create_test_order(test_data.users[0].id),
            "payment_processing": payment_service.test_payment_processing()
        }
        
        for test_name, result in functionality_test.items():
            assert result.success == true, f"Functionality test failed: {test_name}"
```

#### Failover Testing
```pseudocode
    function test_high_availability_failover():
        # Setup - Primary and secondary systems
        primary_system = get_primary_system()
        secondary_system = get_secondary_system()
        
        # Step 1: Verify Initial State
        assert primary_system.status == "active"
        assert secondary_system.status == "standby"
        assert primary_system.health == "healthy"
        assert secondary_system.health == "healthy"
        
        # Step 2: Create Test Data
        test_customers = []
        for i in range(20):
            customer = primary_system.create_customer({
                "name": f"Failover Test Customer {i}",
                "email": f"failover{i}@example.com"
            })
            test_customers.append(customer)
        
        # Step 3: Simulate Primary System Failure
        failure_simulation = primary_system.simulate_failure("hardware_failure")
        assert failure_simulation.success == true
        
        # Step 4: Wait for Failover Detection
        max_wait_time = 30000  # 30 seconds
        failover_detected = false
        start_time = current_time()
        
        while (current_time() - start_time) < max_wait_time:
            secondary_status = secondary_system.get_status()
            if secondary_status.role == "active":
                failover_detected = true
                break
            sleep(1000)
        
        assert failover_detected == true
        assert secondary_system.status == "active"
        
        # Step 5: Verify Data Consistency After Failover
        for customer in test_customers:
            # Customer should be accessible from secondary system
            retrieved_customer = secondary_system.get_customer(customer.id)
            assert retrieved_customer != null
            assert retrieved_customer.name == customer.name
            assert retrieved_customer.email == customer.email
        
        # Step 6: Test System Operations on Secondary
        new_customer = secondary_system.create_customer({
            "name": "Post-Failover Customer",
            "email": "postfailover@example.com"
        })
        assert new_customer != null
        assert new_customer.id != null
        
        # Step 7: Test Primary System Recovery
        recovery_result = primary_system.recover_from_failure()
        assert recovery_result.success == true
        
        # Primary should become standby
        assert primary_system.status == "standby"
        assert secondary_system.status == "active"  # Secondary remains active
        
        # Step 8: Test Data Sync After Recovery
        # New customer created during failover should sync back to primary
        synced_customer = primary_system.get_customer(new_customer.id)
        assert synced_customer != null
        assert synced_customer.name == new_customer.name
```

## Implementation Guidelines

### 1. Test Environment Requirements
- Production-like infrastructure setup
- Realistic data volumes and variety
- Network configuration matching production
- Security configurations and certificates

### 2. Test Data Management
- Comprehensive test data sets
- Data consistency across systems
- Privacy and security compliance
- Data cleanup and reset procedures

### 3. Monitoring and Observability
- System health monitoring during tests
- Performance metrics collection
- Error tracking and logging
- Business metrics validation

### 4. Test Execution Strategy
- Parallel test execution where possible
- Dependency management between tests
- Resource allocation and cleanup
- Failure isolation and recovery

### 5. Results Analysis and Reporting
- Comprehensive test result metrics
- Performance baseline comparison
- Error analysis and categorization
- Business impact assessment

This comprehensive system testing suite provides universal patterns for validating complete application ecosystems while maintaining technology-agnostic principles applicable across all technology stacks.