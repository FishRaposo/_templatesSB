# Migration Documentation Template

**Purpose**: Comprehensive migration documentation template for software projects transitioning between technologies, platforms, or architectures.

**Last Updated**: [CURRENT_DATE]  
**Migration Type**: [MIGRATION_TYPE]  
**Source Platform**: [SOURCE_PLATFORM]  
**Target Platform**: [TARGET_PLATFORM]  
**Migration Status**: [MIGRATION_STATUS]

---

## 🎯 How to Use This Template

### For Technology Migrations:
1. **Customize migration type** - Specify platform, framework, or architectural migration
2. **Update platform details** - Replace source and target platform information
3. **Document specific challenges** - Include migration-specific obstacles and solutions
4. **Add timeline and milestones** - Customize migration phases and deliverables
5. **Include technical details** - Add specific code examples and conversion patterns

### For Different Migration Types:
- **Platform Migration**: Focus on environment and deployment differences
- **Framework Migration**: Emphasize pattern translations and API changes
- **Architecture Migration**: Document structural changes and design decisions
- **Database Migration**: Focus on schema changes and data transformation
- **Language Migration**: Highlight syntax differences and idiomatic changes

---

## 📊 Migration Overview

### Project Context
[MIGRATION_PROJECT_DESCRIPTION] represents a [MIGRATION_TYPE] from [SOURCE_PLATFORM] to [TARGET_PLATFORM]. The migration aims to [MIGRATION_GOALS] while [MIGRATION_CONSTRAINTS].

### Migration Success Criteria (Current Status)
- ✅ **[CRITERION_1]**: [CRITERION_1_STATUS]
- ✅ **[CRITERION_2]**: [CRITERION_2_STATUS]
- ✅ **[CRITERION_3]**: [CRITERION_3_STATUS]
- 🚧 **[CRITERION_4]**: [CRITERION_4_STATUS]
- 🚧 **[CRITERION_5]**: [CRITERION_5_STATUS]

---

## 📋 Migration Implementation Status

### ✅ Completed Migration Components
- [COMPLETED_COMPONENT_1]: [COMPLETED_DESCRIPTION]
- [COMPLETED_COMPONENT_2]: [COMPLETED_DESCRIPTION]
- [COMPLETED_COMPONENT_3]: [COMPLETED_DESCRIPTION]
- [COMPLETED_COMPONENT_4]: [COMPLETED_DESCRIPTION]

### 🚧 Pending Migration Components
- [PENDING_COMPONENT_1]: [PENDING_DESCRIPTION]
- [PENDING_COMPONENT_2]: [PENDING_DESCRIPTION]
- [PENDING_COMPONENT_3]: [PENDING_DESCRIPTION]
- [PENDING_COMPONENT_4]: [PENDING_DESCRIPTION]

---

## 🏗️ Architecture Mapping

### Core Components Translation

| Source Component | Target Component | Migration Status | Notes |
|------------------|------------------|------------------|-------|
| [SOURCE_COMPONENT_1] | [TARGET_COMPONENT_1] | ✅ Complete | [MIGRATION_NOTES_1] |
| [SOURCE_COMPONENT_2] | [TARGET_COMPONENT_2] | 🚧 In Progress | [MIGRATION_NOTES_2] |
| [SOURCE_COMPONENT_3] | [TARGET_COMPONENT_3] | ❌ Not Started | [MIGRATION_NOTES_3] |

### Data Layer Migration

#### Source Data Structure
```[SOURCE_LANGUAGE]
// Source data model
class [SOURCE_MODEL_CLASS] {
  [SOURCE_PROPERTY_1]: [SOURCE_TYPE_1];
  [SOURCE_PROPERTY_2]: [SOURCE_TYPE_2];
  [SOURCE_PROPERTY_3]: [SOURCE_TYPE_3];
  
  [SOURCE_METHOD_1](): [SOURCE_RETURN_TYPE] {
    // Source implementation
  }
}
```

#### Target Data Structure
```[TARGET_LANGUAGE]
// Target data model
class [TARGET_MODEL_CLASS] {
  [TARGET_PROPERTY_1]: [TARGET_TYPE_1];
  [TARGET_PROPERTY_2]: [TARGET_TYPE_2];
  [TARGET_PROPERTY_3]: [TARGET_TYPE_3];
  
  [TARGET_METHOD_1](): [TARGET_RETURN_TYPE] {
    // Target implementation
  }
}
```

#### Data Migration Script
```[SCRIPT_LANGUAGE]
// Data migration script
async function migrate[DATA_TYPE](): Promise<void> {
  const sourceData = await [SOURCE_DATABASE].findAll();
  
  for (const sourceItem of sourceData) {
    const targetItem = new [TARGET_MODEL_CLASS]();
    targetItem.[TARGET_PROPERTY_1] = convert[FIELD_1](sourceItem.[SOURCE_PROPERTY_1]);
    targetItem.[TARGET_PROPERTY_2] = convert[FIELD_2](sourceItem.[SOURCE_PROPERTY_2]);
    targetItem.[TARGET_PROPERTY_3] = convert[FIELD_3](sourceItem.[SOURCE_PROPERTY_3]);
    
    await [TARGET_DATABASE].save(targetItem);
  }
}

function convert[FIELD_1](sourceValue: [SOURCE_TYPE_1]): [TARGET_TYPE_1] {
  // Conversion logic
  return [CONVERSION_RESULT];
}
```

---

## 🔄 Pattern Equivalence Matrix

### Framework Selection
Using the Pattern Equivalence Matrix from framework patterns:

| Concept | Source Implementation | Target Implementation |
|---------|----------------------|------------------------|
| **[CONCEPT_1]** | [SOURCE_PATTERN_1] | [TARGET_PATTERN_1] |
| **[CONCEPT_2]** | [SOURCE_PATTERN_2] | [TARGET_PATTERN_2] |
| **[CONCEPT_3]** | [SOURCE_PATTERN_3] | [TARGET_PATTERN_3] |
| **[CONCEPT_4]** | [SOURCE_PATTERN_4] | [TARGET_PATTERN_4] |
| **[CONCEPT_5]** | [SOURCE_PATTERN_5] | [TARGET_PATTERN_5] |

### Implementation Examples

#### State Management Migration
**Source Implementation:**
```[SOURCE_LANGUAGE]
// Source state management
class [SOURCE_STATE_CLASS] {
  private [STATE_PROPERTY]: [STATE_TYPE];
  
  constructor() {
    this.[STATE_PROPERTY] = [INITIAL_STATE];
  }
  
  [UPDATE_METHOD](newState: [STATE_TYPE]): void {
    this.[STATE_PROPERTY] = newState;
    this.[NOTIFY_METHOD]();
  }
  
  private [NOTIFY_METHOD](): void {
    // Source notification logic
  }
}
```

**Target Implementation:**
```[TARGET_LANGUAGE]
// Target state management
class [TARGET_STATE_CLASS] {
  private [STATE_PROPERTY]: [STATE_TYPE] = [INITIAL_STATE];
  private [OBSERVERS_PROPERTY]: Set<() => void> = new Set();
  
  [UPDATE_METHOD](newState: Partial<[STATE_TYPE]>): void {
    this.[STATE_PROPERTY] = { ...this.[STATE_PROPERTY], ...newState };
    this.[NOTIFY_METHOD]();
  }
  
  subscribe(observer: () => void): () => void {
    this.[OBSERVERS_PROPERTY].add(observer);
    return () => this.[OBSERVERS_PROPERTY].delete(observer);
  }
  
  private [NOTIFY_METHOD](): void {
    this.[OBSERVERS_PROPERTY].forEach(observer => observer());
  }
}
```

---

## 📱 Platform-Specific Considerations

### [PLATFORM_1] Migration

#### Build Configuration
**Source Build Config:**
```[BUILD_LANGUAGE]
# Source build configuration
[CONFIG_PROPERTY_1] = [CONFIG_VALUE_1]
[CONFIG_PROPERTY_2] = [CONFIG_VALUE_2]
[CONFIG_PROPERTY_3] = [CONFIG_VALUE_3]
```

**Target Build Config:**
```[BUILD_LANGUAGE]
# Target build configuration
[CONFIG_PROPERTY_1] = [CONFIG_VALUE_1]
[CONFIG_PROPERTY_2] = [CONFIG_VALUE_2]
[CONFIG_PROPERTY_3] = [CONFIG_VALUE_3]
```

#### Platform Integration
- **Permissions**: [PERMISSION_MIGRATION_NOTES]
- **Native APIs**: [NATIVE_API_MIGRATION_NOTES]
- **Platform Services**: [PLATFORM_SERVICE_MIGRATION_NOTES]

### [PLATFORM_2] Migration

#### Deployment Configuration
**Source Deployment:**
```[DEPLOY_LANGUAGE]
# Source deployment configuration
[DEPLOY_PROPERTY_1] = [DEPLOY_VALUE_1]
[DEPLOY_PROPERTY_2] = [DEPLOY_VALUE_2]
```

**Target Deployment:**
```[DEPLOY_LANGUAGE]
# Target deployment configuration
[DEPLOY_PROPERTY_1] = [DEPLOY_VALUE_1]
[DEPLOY_PROPERTY_2] = [DEPLOY_VALUE_2]
```

---

## 🧪 Testing Migration Strategy

### Test Coverage Translation

| Test Type | Source Framework | Target Framework | Migration Status |
|-----------|------------------|------------------|------------------|
| Unit Tests | [SOURCE_UNIT_FRAMEWORK] | [TARGET_UNIT_FRAMEWORK] | ✅ Complete |
| Integration Tests | [SOURCE_INTEGRATION_FRAMEWORK] | [TARGET_INTEGRATION_FRAMEWORK] | 🚧 In Progress |
| E2E Tests | [SOURCE_E2E_FRAMEWORK] | [TARGET_E2E_FRAMEWORK] | ❌ Not Started |

### Test Migration Examples

#### Unit Test Migration
**Source Test:**
```[SOURCE_TEST_LANGUAGE]
// Source unit test
describe('[SOURCE_TEST_SUBJECT]', () => {
  it('should [TEST_BEHAVIOR]', () => {
    const [TEST_VARIABLE] = new [SOURCE_CLASS]();
    const result = [TEST_VARIABLE].[SOURCE_METHOD]([TEST_ARGUMENTS]);
    expect(result).toEqual([EXPECTED_RESULT]);
  });
});
```

**Target Test:**
```[TARGET_TEST_LANGUAGE]
// Target unit test
describe('[TARGET_TEST_SUBJECT]', () => {
  it('should [TEST_BEHAVIOR]', async () => {
    const [TEST_VARIABLE] = new [TARGET_CLASS]();
    const result = await [TEST_VARIABLE].[TARGET_METHOD]([TEST_ARGUMENTS]);
    expect(result).toEqual([EXPECTED_RESULT]);
  });
});
```

---

## 🚀 Deployment Strategy

### Migration Phases

#### Phase 1: Foundation ([PHASE_1_DURATION])
**Objectives:**
- [PHASE_1_OBJECTIVE_1]
- [PHASE_1_OBJECTIVE_2]
- [PHASE_1_OBJECTIVE_3]

**Deliverables:**
- [PHASE_1_DELIVERABLE_1]
- [PHASE_1_DELIVERABLE_2]
- [PHASE_1_DELIVERABLE_3]

**Success Criteria:**
- [PHASE_1_SUCCESS_1]
- [PHASE_1_SUCCESS_2]

#### Phase 2: Core Features ([PHASE_2_DURATION])
**Objectives:**
- [PHASE_2_OBJECTIVE_1]
- [PHASE_2_OBJECTIVE_2]
- [PHASE_2_OBJECTIVE_3]

**Deliverables:**
- [PHASE_2_DELIVERABLE_1]
- [PHASE_2_DELIVERABLE_2]
- [PHASE_2_DELIVERABLE_3]

**Success Criteria:**
- [PHASE_2_SUCCESS_1]
- [PHASE_2_SUCCESS_2]

#### Phase 3: Advanced Features ([PHASE_3_DURATION])
**Objectives:**
- [PHASE_3_OBJECTIVE_1]
- [PHASE_3_OBJECTIVE_2]
- [PHASE_3_OBJECTIVE_3]

**Deliverables:**
- [PHASE_3_DELIVERABLE_1]
- [PHASE_3_DELIVERABLE_2]
- [PHASE_3_DELIVERABLE_3]

**Success Criteria:**
- [PHASE_3_SUCCESS_1]
- [PHASE_3_SUCCESS_2]

---

## 🔧 Migration Tools and Scripts

### Automated Migration Scripts

#### Data Migration Script
```[SCRIPT_LANGUAGE]
#!/usr/bin/env [SCRIPT_INTERPRETER]

/**
 * Automated data migration from [SOURCE_PLATFORM] to [TARGET_PLATFORM]
 */

const [SOURCE_ADAPTER] = require('[SOURCE_ADAPTER_PACKAGE]');
const [TARGET_ADAPTER] = require('[TARGET_ADAPTER_PACKAGE]');

class [MIGRATION_CLASS] {
  constructor() {
    this.sourceClient = new [SOURCE_ADAPTER]([SOURCE_CONFIG]);
    this.targetClient = new [TARGET_ADAPTER]([TARGET_CONFIG]);
  }

  async migrateAll(): Promise<void> {
    console.log('Starting migration...');
    
    try {
      await this.migrate[ENTITY_1]();
      await this.migrate[ENTITY_2]();
      await this.migrate[ENTITY_3]();
      
      console.log('Migration completed successfully');
    } catch (error) {
      console.error('Migration failed:', error);
      throw error;
    }
  }

  private async migrate[ENTITY_1](): Promise<void> {
    console.log('Migrating [ENTITY_1]...');
    
    const sourceData = await this.sourceClient.findAll[ENTITY_1]();
    const targetData = sourceData.map(item => this.transform[ENTITY_1](item));
    
    await this.targetClient.saveAll[ENTITY_1](targetData);
    console.log(`Migrated ${targetData.length} [ENTITY_1] records`);
  }

  private transform[ENTITY_1](sourceItem: any): any {
    return {
      [TARGET_FIELD_1]: sourceItem.[SOURCE_FIELD_1],
      [TARGET_FIELD_2]: this.convert[FIELD_2](sourceItem.[SOURCE_FIELD_2]),
      [TARGET_FIELD_3]: new Date(sourceItem.[SOURCE_FIELD_3])
    };
  }

  private convert[FIELD_2](sourceValue: any): any {
    // Field-specific conversion logic
    return [CONVERTED_VALUE];
  }
}

// Execute migration
const migration = new [MIGRATION_CLASS]();
migration.migrateAll().catch(console.error);
```

#### Code Migration Script
```[SCRIPT_LANGUAGE]
#!/usr/bin/env [SCRIPT_INTERPRETER]

/**
 * Automated code migration helper
 */

const [FILE_SYSTEM] = require('[FILE_SYSTEM_PACKAGE]');
const [PATH_UTIL] = require('[PATH_PACKAGE]');

class [CODE_MIGRATION_CLASS] {
  private readonly [SOURCE_PATTERNS]: Map<string, string> = new Map([
    ['[SOURCE_PATTERN_1]', '[TARGET_PATTERN_1]'],
    ['[SOURCE_PATTERN_2]', '[TARGET_PATTERN_2]'],
    ['[SOURCE_PATTERN_3]', '[TARGET_PATTERN_3]']
  ]);

  async migrateDirectory(sourceDir: string, targetDir: string): Promise<void> {
    const files = this.getAllFiles(sourceDir, [FILE_EXTENSIONS]);
    
    for (const file of files) {
      await this.migrateFile(file, sourceDir, targetDir);
    }
  }

  private async migrateFile(filePath: string, sourceDir: string, targetDir: string): Promise<void> {
    const relativePath = [PATH_UTIL].relative(sourceDir, filePath);
    const targetPath = [PATH_UTIL].join(targetDir, relativePath);
    
    // Ensure target directory exists
    await [FILE_SYSTEM].mkdirs([PATH_UTIL].dirname(targetPath), { recursive: true });
    
    // Read and transform file content
    const sourceContent = await [FILE_SYSTEM].readFile(filePath, 'utf8');
    const targetContent = this.transformContent(sourceContent);
    
    // Write transformed content
    await [FILE_SYSTEM].writeFile(targetPath, targetContent, 'utf8');
    console.log(`Migrated: ${relativePath}`);
  }

  private transformContent(content: string): string {
    let transformed = content;
    
    for (const [sourcePattern, targetPattern] of this.[SOURCE_PATTERNS]) {
      transformed = transformed.replace(new RegExp(sourcePattern, 'g'), targetPattern);
    }
    
    return transformed;
  }

  private getAllFiles(dir: string, extensions: string[]): string[] {
    const files: string[] = [];
    
    for (const item of [FILE_SYSTEM].readdirSync(dir)) {
      const fullPath = [PATH_UTIL].join(dir, item);
      const stat = [FILE_SYSTEM].statSync(fullPath);
      
      if (stat.isDirectory()) {
        files.push(...this.getAllFiles(fullPath, extensions));
      } else if (extensions.some(ext => item.endsWith(ext))) {
        files.push(fullPath);
      }
    }
    
    return files;
  }
}

// Usage example
const migrator = new [CODE_MIGRATION_CLASS]();
migrator.migrateDirectory('[SOURCE_DIRECTORY]', '[TARGET_DIRECTORY]')
  .then(() => console.log('Code migration completed'))
  .catch(console.error);
```

---

## 🚨 Common Migration Pitfalls

### Technical Challenges Overcome
- **[CHALLENGE_1]**: [CHALLENGE_SOLUTION_1]
- **[CHALLENGE_2]**: [CHALLENGE_SOLUTION_2]
- **[CHALLENGE_3]**: [CHALLENGE_SOLUTION_3]
- **[CHALLENGE_4]**: [CHALLENGE_SOLUTION_4]

### Process Improvements
- **[IMPROVEMENT_1]**: [IMPROVEMENT_DESCRIPTION_1]
- **[IMPROVEMENT_2]**: [IMPROVEMENT_DESCRIPTION_2]
- **[IMPROVEMENT_3]**: [IMPROVEMENT_DESCRIPTION_3]
- **[IMPROVEMENT_4]**: [IMPROVEMENT_DESCRIPTION_4]

---

## 📚 Lessons Learned

### Technical Insights
1. **[INSIGHT_1]**: [INSIGHT_DESCRIPTION_1]
2. **[INSIGHT_2]**: [INSIGHT_DESCRIPTION_2]
3. **[INSIGHT_3]**: [INSIGHT_DESCRIPTION_3]
4. **[INSIGHT_4]**: [INSIGHT_DESCRIPTION_4]
5. **[INSIGHT_5]**: [INSIGHT_DESCRIPTION_5]

### Process Recommendations
1. **[RECOMMENDATION_1]**: [RECOMMENDATION_DESCRIPTION_1]
2. **[RECOMMENDATION_2]**: [RECOMMENDATION_DESCRIPTION_2]
3. **[RECOMMENDATION_3]**: [RECOMMENDATION_DESCRIPTION_3]
4. **[RECOMMENDATION_4]**: [RECOMMENDATION_DESCRIPTION_4]
5. **[RECOMMENDATION_5]**: [RECOMMENDATION_DESCRIPTION_5]

---

## 🔄 Future Considerations

### Potential Enhancements
- **[ENHANCEMENT_1]**: [ENHANCEMENT_DESCRIPTION_1]
- **[ENHANCEMENT_2]**: [ENHANCEMENT_DESCRIPTION_2]
- **[ENHANCEMENT_3]**: [ENHANCEMENT_DESCRIPTION_3]
- **[ENHANCEMENT_4]**: [ENHANCEMENT_DESCRIPTION_4]

### Maintenance Strategy
- **[STRATEGY_1]**: [STRATEGY_DESCRIPTION_1]
- **[STRATEGY_2]**: [STRATEGY_DESCRIPTION_2]
- **[STRATEGY_3]**: [STRATEGY_DESCRIPTION_3]

---

## 📊 Migration Metrics

### Performance Comparison

| Metric | Source Platform | Target Platform | Improvement |
|--------|------------------|------------------|-------------|
| [METRIC_1] | [SOURCE_VALUE_1] | [TARGET_VALUE_1] | [IMPROVEMENT_1] |
| [METRIC_2] | [SOURCE_VALUE_2] | [TARGET_VALUE_2] | [IMPROVEMENT_2] |
| [METRIC_3] | [SOURCE_VALUE_3] | [TARGET_VALUE_3] | [IMPROVEMENT_3] |

### Code Quality Metrics

| Metric | Before Migration | After Migration | Change |
|--------|------------------|-----------------|--------|
| [QUALITY_METRIC_1] | [BEFORE_VALUE_1] | [AFTER_VALUE_1] | [CHANGE_1] |
| [QUALITY_METRIC_2] | [BEFORE_VALUE_2] | [AFTER_VALUE_2] | [CHANGE_2] |
| [QUALITY_METRIC_3] | [BEFORE_VALUE_3] | [AFTER_VALUE_3] | [CHANGE_3] |

---

## 📞 Support and Resources

### Migration Team
- **Migration Lead**: [LEAD_NAME] ([LEAD_EMAIL])
- **Technical Architect**: [ARCHITECT_NAME] ([ARCHITECT_EMAIL])
- **QA Lead**: [QA_LEAD_NAME] ([QA_LEAD_EMAIL])
- **DevOps Engineer**: [DEVOPS_NAME] ([DEVOPS_EMAIL])

### Documentation and Resources
- **Migration Playbook**: [PLAYBOOK_URL]
- **API Documentation**: [API_DOCS_URL]
- **Troubleshooting Guide**: [TROUBLESHOOTING_URL]
- **Best Practices Guide**: [BEST_PRACTICES_URL]

---

**Migration Documentation Version**: [DOC_VERSION]  
**Last Updated**: [CURRENT_DATE]  
**Migration Type**: [MIGRATION_TYPE]  
**Status**: [MIGRATION_STATUS]

---

## 📋 **Appendix: Implementation Examples**

### **🚨 Optional: Concrete Migration Examples**

**Note**: These examples demonstrate how to adapt the universal template for specific migration scenarios. Replace with your project-specific details.

#### **Example: Database Migration Script**
```sql
-- Migration: v1.0.0 to v2.0.0
-- Description: Add user authentication and core business entities

-- Create users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create products table
CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    category VARCHAR(50),
    in_stock BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create orders table
CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    total_amount DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create order_items table
CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Migrate existing data
INSERT INTO users (username, email, password_hash)
SELECT 'admin', 'admin@example.com', 'hashed_password'
WHERE NOT EXISTS (SELECT 1 FROM users);

-- Add indexes for performance
CREATE INDEX idx_orders_user_id ON orders(user_id);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_products_category ON products(category);
CREATE INDEX idx_order_items_order_id ON order_items(order_id);
CREATE INDEX idx_order_items_product_id ON order_items(product_id);
```

#### **Example: File Structure Migration**
```bash
#!/bin/bash
# Migration: Legacy to Modular Architecture
# Description: Restructure project from monolithic to feature-based layout

SOURCE_DIR="src"
TARGET_DIR="lib"

# Create new modular structure
mkdir -p "$TARGET_DIR/shared/core"
mkdir -p "$TARGET_DIR/shared/data"
mkdir -p "$TARGET_DIR/shared/domain"
mkdir -p "$TARGET_DIR/shared/presentation"
mkdir -p "$TARGET_DIR/features/auth/data"
mkdir -p "$TARGET_DIR/features/auth/domain"
mkdir -p "$TARGET_DIR/features/auth/presentation"
mkdir -p "$TARGET_DIR/features/products/data"
mkdir -p "$TARGET_DIR/features/products/domain"
mkdir -p "$TARGET_DIR/features/products/presentation"
mkdir -p "$TARGET_DIR/features/orders/data"
mkdir -p "$TARGET_DIR/features/orders/domain"
mkdir -p "$TARGET_DIR/features/orders/presentation"
mkdir -p "$TARGET_DIR/app/routing"
mkdir -p "$TARGET_DIR/app/dependency_injection"
mkdir -p "$TARGET_DIR/app/configuration"

# Migrate core utilities
mv "$SOURCE_DIR/utils"/* "$TARGET_DIR/shared/core/"
mv "$SOURCE_DIR/models"/* "$TARGET_DIR/shared/domain/"
mv "$SOURCE_DIR/services"/* "$TARGET_DIR/shared/data/"

# Migrate feature modules
mv "$SOURCE_DIR/auth"/* "$TARGET_DIR/features/auth/"
mv "$SOURCE_DIR/products"/* "$TARGET_DIR/features/products/"
mv "$SOURCE_DIR/orders"/* "$TARGET_DIR/features/orders/"

# Update import statements (example for [LANGUAGE])
find "$TARGET_DIR" -name "*.[LANGUAGE_EXTENSION]" -exec sed -i 's|import '\''../utils/|import '\''../../../shared/core/|g' {} \;
find "$TARGET_DIR" -name "*.[LANGUAGE_EXTENSION]" -exec sed -i 's|import '\''../models/|import '\''../../../shared/domain/|g' {} \;
find "$TARGET_DIR" -name "*.[LANGUAGE_EXTENSION]" -exec sed -i 's|import '\''../services/|import '\''../../../shared/data/|g' {} \;

echo "Migration completed successfully!"
```

#### **Example: Configuration Migration**
```yaml
# Old configuration (config.yaml)
database:
  host: localhost
  port: 5432
  name: [DATABASE_NAME]
  user: [DATABASE_USER]
  password: [DATABASE_PASSWORD]

# New configuration (config.yaml)
app:
  name: [PROJECT_NAME]
  version: [VERSION_NUMBER]
  environment: development

database:
  default:
    host: localhost
    port: 5432
    name: [DATABASE_NAME]
    user: [DATABASE_USER]
    password: [DATABASE_PASSWORD]
    pool_size: 10
    timeout: 30

features:
  authentication:
    enabled: true
    provider: [AUTH_PROVIDER]
    secret_key: [JWT_SECRET]
  
  core_business:
    enabled: true
    max_items_per_user: [MAX_ITEMS]
    categories:
      - [CATEGORY_1]
      - [CATEGORY_2]
      - [CATEGORY_3]
      - [CATEGORY_4]

logging:
  level: info
  format: json
  outputs:
    - console
    - file: logs/app.log
```

#### **Example: API Migration (REST to GraphQL)**
```graphql
# Old REST endpoints:
# GET /api/users
# POST /api/users
# GET /api/users/{id}
# PUT /api/users/{id}
# DELETE /api/users/{id}

# New GraphQL Schema:
type User {
  id: ID!
  username: String!
  email: String!
  createdAt: DateTime!
  updatedAt: DateTime!
}

type Query {
  users(limit: Int = 20, offset: Int = 0): [User!]!
  user(id: ID!): User
}

type Mutation {
  createUser(input: CreateUserInput!): User!
  updateUser(id: ID!, input: UpdateUserInput!): User!
  deleteUser(id: ID!): Boolean!
}

input CreateUserInput {
  username: String!
  email: String!
  password: String!
}

input UpdateUserInput {
  username: String
  email: String
}
```

#### **Example: Testing Migration**
```dart
// Old test structure
// test/user_test.dart
// test/inventory_test.dart

// New modular test structure
// test/unit/shared/core/utils_test.dart
// test/unit/shared/domain/models_test.dart
// test/unit/features/auth/domain/auth_service_test.dart
// test/unit/features/inventory/domain/inventory_service_test.dart
// test/integration/auth_flow_test.dart
// test/integration/inventory_management_test.dart
// test/e2e/full_user_journey_test.dart

void main() {
  group('User Service Tests', () {
    late UserService userService;
    
    setUp(() {
      userService = UserService(MockDatabase());
    });
    
    test('should create user successfully', () async {
      // Test implementation
      final user = await userService.createUser(
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
      );
      
      expect(user.username, equals('testuser'));
      expect(user.email, equals('test@example.com'));
    });
  });
}
```

**Adaptation Guidelines**:
1. **Customize Examples**: Use these as starting points for your specific migration
2. **Update Paths**: Modify file paths and directory structures
3. **Adapt Schemas**: Customize data models and API schemas
4. **Configure Environment**: Adjust configuration for your deployment
5. **Test Thoroughly**: Ensure all migration scripts are tested before execution

---

*This template provides comprehensive migration documentation structure. Customize all bracketed placeholders with your migration-specific information and adapt the structure to match your migration's specific requirements and challenges.*
