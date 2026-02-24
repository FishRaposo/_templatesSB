// Universal Template System - Rust Unit Tests Template
use std::collections::HashMap;
use crate::testing_helpers::*;
use mockall::predicate::*;

// =============================================================================
// TEST MODULE STRUCTURE
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{{MODULE_NAME}};

    // =============================================================================
    // FIXTURES AND SETUP
    // =============================================================================

    fn setup_test_context() -> TestContext {
        TestContext::new()
    }

    struct TestContext {
        database: InMemoryDatabase,
        mock_http: MockHttpClient,
        users: Vec<User>,
    }

    impl TestContext {
        fn new() -> Self {
            let mut ctx = Self {
                database: InMemoryDatabase::new(),
                mock_http: MockHttpClient::new(),
                users: Vec::new(),
            };
            
            // Create default test users
            ctx.users.push(User::factory().with_id(1).with_name("Test User").build());
            ctx.users.push(User::factory().with_id(2).with_name("Another User").build());
            
            ctx
        }

        fn add_user_to_db(&mut self, user: User) -> User {
            self.database.add_user(user)
        }
    }

    // =============================================================================
    // {{COMPONENT_NAME}} UNIT TESTS
    // =============================================================================

    #[test]
    fn test_{{component_name}}_creation() {
        let ctx = setup_test_context();
        
        // Test component creation
        let component = {{COMPONENT_NAME}}::new();
        
        assert!(component.is_valid());
        assert_eq!(component.name(), "{{COMPONENT_NAME}}");
    }

    #[test]
    fn test_{{component_name}}_with_valid_data() {
        let ctx = setup_test_context();
        let component = {{COMPONENT_NAME}}::new();
        
        let result = component.process_valid_data();
        
        assert!(result.is_ok());
        let processed = result.unwrap();
        assert_eq!(processed.status, "success");
    }

    #[test]
    fn test_{{component_name}}_with_invalid_data() {
        let ctx = setup_test_context();
        let component = {{COMPONENT_NAME}}::new();
        
        let invalid_data = create_invalid_data();
        let result = component.process_data(invalid_data);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), {{COMPONENT_NAME}}Error::ValidationError(_)));
    }

    #[test]
    fn test_{{component_name}}_state_transitions() {
        let ctx = setup_test_context();
        let mut component = {{COMPONENT_NAME}}::new();
        
        // Initial state
        assert_eq!(component.state(), State::Initial);
        
        // Transition to processing
        component.start_processing().expect_ok("Failed to start processing");
        assert_eq!(component.state(), State::Processing);
        
        // Complete processing
        component.complete_processing().expect_ok("Failed to complete processing");
        assert_eq!(component.state(), State::Completed);
    }

    // =============================================================================
    // INTEGRATION WITH DEPENDENCIES
    // =============================================================================

    #[test]
    fn test_{{component_name}}_with_database() {
        let mut ctx = setup_test_context();
        let component = {{COMPONENT_NAME}}::new();
        
        // Add test data to database
        let user = ctx.add_user_to_db(ctx.users[0].clone());
        
        // Test database interaction
        let result = component.load_user(user.id);
        assert!(result.is_ok());
        
        let loaded_user = result.unwrap();
        assert_eq!(loaded_user.id, user.id);
        assert_eq!(loaded_user.name, user.name);
    }

    #[tokio::test]
    async fn test_{{component_name}}_with_http_client() {
        let mut ctx = setup_test_context();
        let component = {{COMPONENT_NAME}}::new();
        
        // Mock HTTP response
        let mock_response = create_json_response(200, &serde_json::json!({
            "message": "Success",
            "data": "test data"
        }));
        
        ctx.mock_http
            .expect_get()
            .with(eq("https://api.example.com/test"))
            .times(1)
            .returning(move |_| Ok(mock_response.clone()));
        
        // Test HTTP interaction
        let result = component.fetch_external_data().await;
        assert!(result.is_ok());
        
        let data = result.unwrap();
        assert_eq!(data.message, "Success");
    }

    // =============================================================================
    // ERROR HANDLING TESTS
    // =============================================================================

    #[test]
    fn test_{{component_name}}_handles_database_errors() {
        let mut ctx = setup_test_context();
        let component = {{COMPONENT_NAME}}::new();
        
        // Try to load non-existent user
        let result = component.load_user(999);
        assert!(result.is_err());
        
        assert!(matches!(result.unwrap_err(), {{COMPONENT_NAME}}Error::UserNotFound));
    }

    #[tokio::test]
    async fn test_{{component_name}}_handles_network_errors() {
        let mut ctx = setup_test_context();
        let component = {{COMPONENT_NAME}}::new();
        
        // Mock network error
        ctx.mock_http
            .expect_get()
            .with(eq("https://api.example.com/test"))
            .times(1)
            .returning(|_| Err(HttpError::NetworkError));
        
        let result = component.fetch_external_data().await;
        assert!(result.is_err());
        
        assert!(matches!(result.unwrap_err(), {{COMPONENT_NAME}}Error::NetworkError(_)));
    }

    // =============================================================================
    // PERFORMANCE TESTS
    // =============================================================================

    #[test]
    fn test_{{component_name}}_performance_under_load() {
        let ctx = setup_test_context();
        let component = {{COMPONENT_NAME}}::new();
        
        let mut benchmark = Benchmark::new("component_processing");
        
        // Measure processing time for multiple iterations
        for _ in 0..100 {
            benchmark.start();
            let _ = component.process_valid_data();
            benchmark.stop();
        }
        
        // Should complete in under 100ms on average
        benchmark.assert_faster_than(Duration::from_millis(100));
    }

    #[test]
    fn test_{{component_name}}_memory_usage() {
        let ctx = setup_test_context();
        let component = {{COMPONENT_NAME}}::new();
        
        // Process large dataset
        let large_dataset = create_large_test_dataset(1000);
        let result = component.process_batch(large_dataset);
        
        assert!(result.is_ok());
        
        // Verify memory is cleaned up
        // Note: This would require a memory profiler in real scenarios
    }

    // =============================================================================
    // EDGE CASES
    // =============================================================================

    #[test]
    fn test_{{component_name}}_with_empty_data() {
        let ctx = setup_test_context();
        let component = {{COMPONENT_NAME}}::new();
        
        let empty_data = Vec::new();
        let result = component.process_batch(empty_data);
        
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_{{component_name}}_with_maximum_data() {
        let ctx = setup_test_context();
        let component = {{COMPONENT_NAME}}::new();
        
        let max_data = create_maximum_test_dataset();
        let result = component.process_batch(max_data);
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_{{component_name}}_concurrent_access() {
        use std::sync::{Arc, Mutex};
        use std::thread;
        
        let ctx = Arc::new(Mutex::new(setup_test_context()));
        let component = Arc::new(Mutex::new({{COMPONENT_NAME}}::new()));
        
        let mut handles = vec![];
        
        // Spawn multiple threads
        for i in 0..10 {
            let ctx_clone = Arc::clone(&ctx);
            let component_clone = Arc::clone(&component);
            
            let handle = thread::spawn(move || {
                let mut ctx = ctx_clone.lock().unwrap();
                let mut comp = component_clone.lock().unwrap();
                
                let user = User::factory().with_id(i + 100).build();
                let added_user = ctx.add_user_to_db(user);
                
                comp.load_user(added_user.id).unwrap()
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
    }

    // =============================================================================
    // HELPER FUNCTIONS
    // =============================================================================

    fn create_invalid_data() -> TestData {
        TestData {
            id: 0,
            name: String::new(),
            // Missing required fields
        }
    }

    fn create_large_test_dataset(size: usize) -> Vec<TestData> {
        (0..size)
            .map(|i| TestData {
                id: i as u64,
                name: format!("Test Item {}", i),
                description: Some(format!("Description for item {}", i)),
            })
            .collect()
    }

    fn create_maximum_test_dataset() -> Vec<TestData> {
        create_large_test_dataset(10000)
    }
}

// =============================================================================
// TEST DATA STRUCTURES
// =============================================================================

#[derive(Debug, Clone)]
pub struct TestData {
    pub id: u64,
    pub name: String,
    pub description: Option<String>,
}

// =============================================================================
// COMPONENT UNDER TEST (Example Structure)
// =============================================================================

pub struct {{COMPONENT_NAME}} {
    state: State,
    database: InMemoryDatabase,
    http_client: MockHttpClient,
}

#[derive(Debug, PartialEq)]
pub enum State {
    Initial,
    Processing,
    Completed,
    Failed,
}

#[derive(Debug)]
pub enum {{COMPONENT_NAME}}Error {
    ValidationError(String),
    UserNotFound,
    NetworkError(HttpError),
    DatabaseError(DatabaseError),
}

impl {{COMPONENT_NAME}} {
    pub fn new() -> Self {
        Self {
            state: State::Initial,
            database: InMemoryDatabase::new(),
            http_client: MockHttpClient::new(),
        }
    }

    pub fn is_valid(&self) -> bool {
        !matches!(self.state, State::Failed)
    }

    pub fn name(&self) -> &str {
        "{{COMPONENT_NAME}}"
    }

    pub fn state(&self) -> State {
        self.state.clone()
    }

    pub fn process_valid_data(&self) -> Result<ProcessedData, {{COMPONENT_NAME}}Error> {
        Ok(ProcessedData {
            status: "success".to_string(),
            timestamp: chrono::Utc::now(),
        })
    }

    pub fn process_data(&self, data: TestData) -> Result<ProcessedData, {{COMPONENT_NAME}}Error> {
        if data.id == 0 || data.name.is_empty() {
            return Err({{COMPONENT_NAME}}Error::ValidationError("Invalid data".to_string()));
        }
        self.process_valid_data()
    }

    pub fn start_processing(&mut self) -> Result<(), {{COMPONENT_NAME}}Error> {
        self.state = State::Processing;
        Ok(())
    }

    pub fn complete_processing(&mut self) -> Result<(), {{COMPONENT_NAME}}Error> {
        self.state = State::Completed;
        Ok(())
    }

    pub fn load_user(&self, id: u64) -> Result<User, {{COMPONENT_NAME}}Error> {
        self.database
            .get_user(id)
            .ok_or({{COMPONENT_NAME}}Error::UserNotFound)
    }

    pub async fn fetch_external_data(&self) -> Result<ExternalData, {{COMPONENT_NAME}}Error> {
        match self.http_client.get("https://api.example.com/test").await {
            Ok(response) => {
                let data: ExternalData = serde_json::from_str(&response.body)
                    .map_err(|_| {{COMPONENT_NAME}}Error::ValidationError("Invalid response".to_string()))?;
                Ok(data)
            }
            Err(e) => Err({{COMPONENT_NAME}}Error::NetworkError(e)),
        }
    }

    pub fn process_batch(&self, data: Vec<TestData>) -> Result<Vec<ProcessedData>, {{COMPONENT_NAME}}Error> {
        let results: Result<Vec<_>, _> = data
            .into_iter()
            .map(|item| self.process_data(item))
            .collect();
        results
    }
}

#[derive(Debug)]
pub struct ProcessedData {
    pub status: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ExternalData {
    pub message: String,
    pub data: String,
}
