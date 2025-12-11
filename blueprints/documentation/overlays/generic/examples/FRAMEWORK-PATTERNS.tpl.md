# Framework Patterns Template

**Purpose**: Technology patterns and architectural framework guide template for software projects.

**Last Updated**: [CURRENT_DATE]  
**Framework Version**: [FRAMEWORK_VERSION]  
**Technology Stack**: [PRIMARY_TECH_STACK]

---

## 🎯 How to Use This Template

### For Different Technology Stacks:
1. **Customize technology sections** - Replace with your specific stack
2. **Adapt patterns** - Modify patterns to match your framework conventions
3. **Update examples** - Use code examples from your actual implementation
4. **Add framework-specific patterns** - Include patterns unique to your stack

### For Different Project Types:
- **Web Applications**: Focus on MVC/MVVM, API patterns, state management
- **Mobile Apps**: Emphasize UI patterns, data persistence, platform integration
- **API Projects**: Prioritize service patterns, data access, security
- **Desktop Applications**: Focus on MVVM, plugin architecture, threading

---

## 🏗️ Architecture Overview

### Primary Architecture Pattern: [ARCHITECTURE_PATTERN]

**Description**: [ARCHITECTURE_DESCRIPTION]

**Benefits:**
- [BENEFIT_1]
- [BENEFIT_2]
- [BENEFIT_3]

**Trade-offs:**
- [TRADEOFF_1]
- [TRADEOFF_2]

**When to Use:**
- [USE_CASE_1]
- [USE_CASE_2]

---

## 🎨 Design Patterns

### [PATTERN_CATEGORY_1]

#### [PATTERN_NAME_1] - [PATTERN_PURPOSE]
**Context**: [PATTERN_CONTEXT]  
**Problem**: [PATTERN_PROBLEM]  
**Solution**: [PATTERN_SOLUTION]

**Implementation Example:**
```[PROGRAMMING_LANGUAGE]
// [PATTERN_NAME_1] implementation
class [CLASS_NAME] {
  constructor([PARAMETERS]) {
    this.[PROPERTY_1] = [PROPERTY_1];
    this.[PROPERTY_2] = [PROPERTY_2];
  }

  [METHOD_NAME]([PARAMETERS]) {
    // Pattern implementation
    return [IMPLEMENTATION];
  }
}

// Usage example
const instance = new [CLASS_NAME]([ARGUMENTS]);
const result = instance.[METHOD_NAME]([ARGUMENTS]);
```

**Variations:**
- [VARIATION_1]: [VARIATION_DESCRIPTION]
- [VARIATION_2]: [VARIATION_DESCRIPTION]

#### [PATTERN_NAME_2] - [PATTERN_PURPOSE]
**Context**: [PATTERN_CONTEXT]  
**Problem**: [PATTERN_PROBLEM]  
**Solution**: [PATTERN_SOLUTION]

**Implementation Example:**
```[PROGRAMMING_LANGUAGE]
// [PATTERN_NAME_2] implementation
interface [INTERFACE_NAME] {
  [METHOD_SIGNATURE_1];
  [METHOD_SIGNATURE_2];
}

class [IMPLEMENTATION_CLASS] implements [INTERFACE_NAME] {
  [METHOD_IMPLEMENTATION_1] {
    // Implementation
  }

  [METHOD_IMPLEMENTATION_2] {
    // Implementation
  }
}
```

### [PATTERN_CATEGORY_2]

#### [PATTERN_NAME_3] - [PATTERN_PURPOSE]
**Context**: [PATTERN_CONTEXT]  
**Problem**: [PATTERN_PROBLEM]  
**Solution**: [PATTERN_SOLUTION]

**Implementation Example:**
```[PROGRAMMING_LANGUAGE]
// [PATTERN_NAME_3] implementation
class [PATTERN_CLASS] {
  private [PRIVATE_PROPERTY]: [PROPERTY_TYPE];

  constructor([PARAMETERS]) {
    this.[PRIVATE_PROPERTY] = [INITIAL_VALUE];
  }

  public [PUBLIC_METHOD](): [RETURN_TYPE] {
    // Pattern implementation
    return this.[PRIVATE_PROPERTY].[METHOD_CHAIN]();
  }
}
```

---

## 🔄 Behavioral Patterns

### State Management Pattern: [STATE_MANAGEMENT_PATTERN]

**Description**: [STATE_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// State management implementation
class [STATE_MANAGER] {
  private state: [STATE_TYPE] = [INITIAL_STATE];

  getState(): [STATE_TYPE] {
    return this.state;
  }

  setState(newState: Partial<[STATE_TYPE]>): void {
    this.state = { ...this.state, ...newState };
    this.notifySubscribers();
  }

  subscribe(callback: (state: [STATE_TYPE]) => void): () => void {
    // Subscribe implementation
    return () => { /* unsubscribe */ };
  }

  private notifySubscribers(): void {
    // Notify all subscribers
  }
}
```

### Event Handling Pattern: [EVENT_PATTERN]

**Description**: [EVENT_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Event handling implementation
interface [EVENT_INTERFACE] {
  type: string;
  payload?: any;
  timestamp: number;
}

class [EVENT_DISPATCHER] {
  private listeners: Map<string, Function[]> = new Map();

  on(eventType: string, listener: Function): void {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, []);
    }
    this.listeners.get(eventType)!.push(listener);
  }

  emit(event: [EVENT_INTERFACE]): void {
    const listeners = this.listeners.get(event.type) || [];
    listeners.forEach(listener => listener(event));
  }

  off(eventType: string, listener: Function): void {
    const listeners = this.listeners.get(eventType) || [];
    const index = listeners.indexOf(listener);
    if (index > -1) {
      listeners.splice(index, 1);
    }
  }
}
```

---

## 📝 Mandatory Code Comments Standards

### Commenting Requirements for All Languages
**Purpose**: Ensure code is self-documenting and maintainable through comprehensive commenting

#### Universal Commenting Standards
- **Class/Interface Headers**: Every class and interface must have a header comment explaining purpose, usage, and examples
- **Method Documentation**: All public methods must document parameters, return values, exceptions, and usage examples
- **Complex Logic**: Any complex algorithm or business logic must have inline comments explaining the approach
- **Configuration Documentation**: All configuration files and environment variables must be documented
- **API Documentation**: All API endpoints must document request/response formats, authentication, and error codes

### Language-Specific Comment Examples

#### JavaScript/TypeScript Documentation
```javascript
/**
 * UserService handles user authentication and profile management
 * Provides methods for creating, updating, and managing user accounts
 * @example
 * const userService = new UserService(database);
 * const user = await userService.createUser({ email: 'user@example.com', name: 'John Doe' });
 */
class UserService {
  /**
   * Creates a new user with validation and error handling
   * @param {CreateUserRequest} userData - User profile data including email and name
   * @param {string} userData.email - Valid email address for the user
   * @param {string} userData.name - Display name for the user (2-50 characters)
   * @returns {Promise<User>} Created user object with generated ID and timestamps
   * @throws {ValidationError} When email format is invalid or name length is out of bounds
   * @throws {DuplicateUserError} When a user with the same email already exists
   */
  async createUser(userData) {
    // Validate email format using regex pattern
    if (!this.emailValidator.isValid(userData.email)) {
      throw new ValidationError('Invalid email format');
    }
    
    // Check for existing user to prevent duplicates
    const existingUser = await this.findByEmail(userData.email);
    if (existingUser) {
      throw new DuplicateUserError('User with this email already exists');
    }
    
    // Hash password for security before storing
    const hashedPassword = await this.passwordHasher.hash(userData.password);
    
    // Create user object with timestamps
    const user = {
      id: this.generateId(),
      ...userData,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    return await this.database.save(user);
  }
}
```

#### Python Documentation
```python
class UserService:
    """
    UserService handles user authentication and profile management.
    
    Provides comprehensive user management functionality including creation,
    authentication, profile updates, and account deletion. All operations
    include proper validation and error handling.
    
    Args:
        database (Database): Database connection instance for user persistence
        email_validator (EmailValidator): Validator for email format checking
        password_hasher (PasswordHasher): Service for secure password hashing
    
    Example:
        >>> user_service = UserService(database, EmailValidator(), PasswordHasher())
        >>> user = await user_service.create_user({
        ...     'email': 'user@example.com',
        ...     'name': 'John Doe',
        ...     'password': 'secure_password'
        ... })
        >>> print(user.id)
        'uuid-generated-id'
    """
    
    async def create_user(self, user_data: dict) -> User:
        """
        Creates a new user with comprehensive validation and security measures.
        
        Validates email format, checks for duplicates, hashes passwords,
        and creates user record with proper timestamps.
        
        Args:
            user_data (dict): User profile data containing:
                - email (str): Valid email address (required)
                - name (str): Display name, 2-50 characters (required)
                - password (str): Plain text password (required)
        
        Returns:
            User: Created user object with generated ID and timestamps
        
        Raises:
            ValidationError: When email format is invalid or name length is out of bounds
            DuplicateUserError: When a user with the same email already exists
            DatabaseError: When database operation fails
        
        Example:
            >>> user = await user_service.create_user({
            ...     'email': 'john@example.com',
            ...     'name': 'John Doe',
            ...     'password': 'secure_password'
            ... })
            >>> print(f"User created with ID: {user.id}")
        """
        # Validate email format using regex pattern
        if not self.email_validator.is_valid(user_data['email']):
            raise ValidationError('Invalid email format')
        
        # Check for existing user to prevent duplicates
        existing_user = await self.find_by_email(user_data['email'])
        if existing_user:
            raise DuplicateUserError('User with this email already exists')
        
        # Hash password for security before storing
        hashed_password = await self.password_hasher.hash(user_data['password'])
        
        # Create user object with timestamps and metadata
        user = User(
            id=self.generate_id(),
            email=user_data['email'],
            name=user_data['name'],
            password=hashed_password,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        return await self.database.save(user)
```

#### Java Documentation
```java
/**
 * UserService handles user authentication and profile management.
 * 
 * <p>This service provides comprehensive user management functionality including
 * user creation, authentication, profile updates, and account deletion. All
 * operations include proper validation, error handling, and security measures.</p>
 * 
 * <p>Example usage:</p>
 * <pre>{@code
 * UserService userService = new UserService(database, emailValidator, passwordHasher);
 * User user = userService.createUser(
 *     new CreateUserRequest("user@example.com", "John Doe", "password")
 * );
 * System.out.println("User created with ID: " + user.getId());
 * }</pre>
 * 
 * @author Development Team
 * @version 1.0
 * @since 1.0
 */
public class UserService {
    
    /**
     * Creates a new user with comprehensive validation and security measures.
     * 
     * <p>This method validates the email format, checks for existing users,
     * hashes the password for security, and creates a new user record with
     * proper timestamps and metadata.</p>
     * 
     * @param userData User profile data containing email, name, and password
     * @return Created user object with generated ID and timestamps
     * @throws IllegalArgumentException When email format is invalid or name is null/empty
     * @throws DuplicateUserException When a user with the same email already exists
     * @throws DataAccessException When database operation fails
     * 
     * @example
     * <pre>{@code
     * User user = userService.createUser(
     *     new CreateUserRequest("john@example.com", "John Doe", "securePassword")
     * );
     * }</pre>
     */
    public User createUser(CreateUserRequest userData) {
        // Validate email format using regex pattern
        if (!emailValidator.isValid(userData.getEmail())) {
            throw new IllegalArgumentException("Invalid email format");
        }
        
        // Check for existing user to prevent duplicates
        Optional<User> existingUser = findByEmail(userData.getEmail());
        if (existingUser.isPresent()) {
            throw new DuplicateUserException("User with this email already exists");
        }
        
        // Hash password for security before storing
        String hashedPassword = passwordHasher.hash(userData.getPassword());
        
        // Create user object with timestamps and metadata
        User user = new User(
            generateId(),
            userData.getEmail(),
            userData.getName(),
            hashedPassword,
            LocalDateTime.now(),
            LocalDateTime.now()
        );
        
        return database.save(user);
    }
}
```

#### C# Documentation
```csharp
/// <summary>
/// UserService handles user authentication and profile management.
/// </summary>
/// <remarks>
/// This service provides comprehensive user management functionality including
/// user creation, authentication, profile updates, and account deletion. All
/// operations include proper validation, error handling, and security measures.
/// </remarks>
/// <example>
/// <code>
/// var userService = new UserService(database, emailValidator, passwordHasher);
/// var user = await userService.CreateUserAsync(new CreateUserRequest {
///     Email = "user@example.com",
///     Name = "John Doe",
///     Password = "secure_password"
/// });
/// Console.WriteLine($"User created with ID: {user.Id}");
/// </code>
/// </example>
public class UserService
{
    /// <summary>
    /// Creates a new user with comprehensive validation and security measures.
    /// </summary>
    /// <param name="userData">User profile data containing email, name, and password</param>
    /// <returns>Created user object with generated ID and timestamps</returns>
    /// <exception cref="ArgumentException">Thrown when email format is invalid or name is null/empty</exception>
    /// <exception cref="DuplicateUserException">Thrown when a user with the same email already exists</exception>
    /// <exception cref="DatabaseException">Thrown when database operation fails</exception>
    /// <example>
    /// <code>
    /// var user = await userService.CreateUserAsync(new CreateUserRequest {
    ///     Email = "john@example.com",
    ///     Name = "John Doe",
    ///     Password = "securePassword"
    /// });
    /// </code>
    /// </example>
    public async Task<User> CreateUserAsync(CreateUserRequest userData)
    {
        // Validate email format using regex pattern
        if (!emailValidator.IsValid(userData.Email))
        {
            throw new ArgumentException("Invalid email format");
        }
        
        // Check for existing user to prevent duplicates
        var existingUser = await FindByEmailAsync(userData.Email);
        if (existingUser != null)
        {
            throw new DuplicateUserException("User with this email already exists");
        }
        
        // Hash password for security before storing
        var hashedPassword = await passwordHasher.HashAsync(userData.Password);
        
        // Create user object with timestamps and metadata
        var user = new User
        {
            Id = GenerateId(),
            Email = userData.Email,
            Name = userData.Name,
            Password = hashedPassword,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        
        return await database.SaveAsync(user);
    }
}
```

---

## 🗄️ Data Access Patterns

### Repository Pattern: [REPOSITORY_IMPLEMENTATION]

**Description**: [REPOSITORY_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Repository pattern implementation
interface [REPOSITORY_INTERFACE]<T> {
  findById(id: string): Promise<T | null>;
  findAll(): Promise<T[]>;
  create(entity: Omit<T, 'id'>): Promise<T>;
  update(id: string, entity: Partial<T>): Promise<T>;
  delete(id: string): Promise<void>;
}

class [REPOSITORY_IMPLEMENTATION]<T> implements [REPOSITORY_INTERFACE]<T> {
  constructor(
    private database: [DATABASE_TYPE],
    private tableName: string
  ) {}

  async findById(id: string): Promise<T | null> {
    const result = await this.database
      .select()
      .from(this.tableName)
      .where('id', '=', id)
      .first();
    
    return result || null;
  }

  async findAll(): Promise<T[]> {
    return await this.database.select().from(this.tableName);
  }

  async create(entity: Omit<T, 'id'>): Promise<T> {
    const [result] = await this.database
      .insert(entity)
      .into(this.tableName)
      .returning('*');
    
    return result;
  }

  async update(id: string, entity: Partial<T>): Promise<T> {
    const [result] = await this.database
      .update(entity)
      .from(this.tableName)
      .where('id', '=', id)
      .returning('*');
    
    return result;
  }

  async delete(id: string): Promise<void> {
    await this.database
      .from(this.tableName)
      .where('id', '=', id)
      .delete();
  }
}
```

### Data Mapper Pattern: [MAPPER_IMPLEMENTATION]

**Description**: [MAPPER_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Data mapper implementation
interface [MAPPER_INTERFACE]<T, D> {
  toDomain(data: D): T;
  toData(entity: T): D;
}

class [MAPPER_IMPLEMENTATION] implements [MAPPER_INTERFACE]<[ENTITY_TYPE], [DATA_TYPE]> {
  toDomain(data: [DATA_TYPE]): [ENTITY_TYPE] {
    return new [ENTITY_TYPE](
      data.id,
      data.[PROPERTY_1],
      data.[PROPERTY_2],
      new Date(data.[DATE_PROPERTY])
    );
  }

  toData(entity: [ENTITY_TYPE]): [DATA_TYPE] {
    return {
      id: entity.getId(),
      [PROPERTY_1]: entity.[PROPERTY_1],
      [PROPERTY_2]: entity.[PROPERTY_2],
      [DATE_PROPERTY]: entity.[DATE_PROPERTY].toISOString()
    };
  }
}
```

---

## 🔌 Service Layer Patterns

### Service Pattern: [SERVICE_IMPLEMENTATION]

**Description**: [SERVICE_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Service layer implementation
class [SERVICE_CLASS] {
  constructor(
    private [REPOSITORY_NAME]: [REPOSITORY_TYPE],
    private [MAPPER_NAME]: [MAPPER_TYPE],
    private [LOGGER_NAME]: [LOGGER_TYPE]
  ) {}

  async [SERVICE_METHOD]([PARAMETERS]): Promise<[RETURN_TYPE]> {
    try {
      // Business logic
      const data = await this.[REPOSITORY_NAME].[REPOSITORY_METHOD]([PARAMETERS]);
      const entity = this.[MAPPER_NAME].toDomain(data);
      
      // Additional business logic
      const result = this.[BUSINESS_METHOD](entity);
      
      this.[LOGGER_NAME].info('[SERVICE_METHOD] completed successfully');
      return result;
    } catch (error) {
      this.[LOGGER_NAME].error('[SERVICE_METHOD] failed', error);
      throw new [CUSTOM_ERROR]('[ERROR_MESSAGE]', error);
    }
  }

  private [BUSINESS_METHOD](entity: [ENTITY_TYPE]): [RETURN_TYPE] {
    // Private business logic
    return [BUSINESS_RESULT];
  }
}
```

### Factory Pattern: [FACTORY_IMPLEMENTATION]

**Description**: [FACTORY_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Factory pattern implementation
interface [FACTORY_INTERFACE] {
  create([PARAMETERS]): [PRODUCT_TYPE];
}

class [FACTORY_IMPLEMENTATION] implements [FACTORY_INTERFACE] {
  create([PARAMETERS]): [PRODUCT_TYPE] {
    switch ([PARAMETER]) {
      case '[CASE_1]':
        return new [CONCRETE_PRODUCT_1]([ARGUMENTS]);
      case '[CASE_2]':
        return new [CONCRETE_PRODUCT_2]([ARGUMENTS]);
      default:
        throw new Error('[ERROR_MESSAGE]');
    }
  }
}

// Abstract factory implementation
abstract class [ABSTRACT_FACTORY] {
  abstract createProductA(): [PRODUCT_A_TYPE];
  abstract createProductB(): [PRODUCT_B_TYPE];
}

class [CONCRETE_FACTORY] extends [ABSTRACT_FACTORY] {
  createProductA(): [PRODUCT_A_TYPE] {
    return new [CONCRETE_PRODUCT_A]();
  }

  createProductB(): [PRODUCT_B_TYPE] {
    return new [CONCRETE_PRODUCT_B]();
  }
}
```

---

## 🎭 Presentation Layer Patterns

### MVC/MVVM Pattern: [PRESENTATION_IMPLEMENTATION]

**Description**: [PRESENTATION_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// MVVM implementation
abstract class [VIEW_MODEL] {
  protected [STATE_PROPERTY]: [STATE_TYPE];
  protected [OBSERVERS_PROPERTY]: Set<() => void> = new Set();

  getState(): [STATE_TYPE] {
    return this.[STATE_PROPERTY];
  }

  protected setState(newState: Partial<[STATE_TYPE]>): void {
    this.[STATE_PROPERTY] = { ...this.[STATE_PROPERTY], ...newState };
    this.notifyObservers();
  }

  subscribe(observer: () => void): () => void {
    this.[OBSERVERS_PROPERTY].add(observer);
    return () => this.[OBSERVERS_PROPERTY].delete(observer);
  }

  private notifyObservers(): void {
    this.[OBSERVERS_PROPERTY].forEach(observer => observer());
  }

  abstract [ACTION_METHOD]([PARAMETERS]): Promise<void>;
}

class [CONCRETE_VIEW_MODEL] extends [VIEW_MODEL] {
  constructor(private [SERVICE_NAME]: [SERVICE_TYPE]) {
    super();
    this.[STATE_PROPERTY] = [INITIAL_STATE];
  }

  async [ACTION_METHOD]([PARAMETERS]): Promise<void> {
    this.setState({ loading: true });
    
    try {
      const result = await this.[SERVICE_NAME].[SERVICE_METHOD]([PARAMETERS]);
      this.setState({ 
        data: result, 
        loading: false,
        error: null 
      });
    } catch (error) {
      this.setState({ 
        error: error.message, 
        loading: false 
      });
    }
  }
}
```

### Observer Pattern: [OBSERVER_IMPLEMENTATION]

**Description**: [OBSERVER_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Observer pattern implementation
interface [OBSERVER_INTERFACE] {
  update(data: any): void;
}

interface [SUBJECT_INTERFACE] {
  subscribe(observer: [OBSERVER_INTERFACE]): void;
  unsubscribe(observer: [OBSERVER_INTERFACE]): void;
  notify(data: any): void;
}

class [SUBJECT_IMPLEMENTATION] implements [SUBJECT_INTERFACE] {
  private observers: [OBSERVER_INTERFACE][] = [];

  subscribe(observer: [OBSERVER_INTERFACE]): void {
    this.observers.push(observer);
  }

  unsubscribe(observer: [OBSERVER_INTERFACE]): void {
    const index = this.observers.indexOf(observer);
    if (index > -1) {
      this.observers.splice(index, 1);
    }
  }

  notify(data: any): void {
    this.observers.forEach(observer => observer.update(data));
  }
}

class [CONCRETE_OBSERVER] implements [OBSERVER_INTERFACE] {
  constructor(private name: string) {}

  update(data: any): void {
    console.log(`${this.name} received data:`, data);
  }
}
```

---

## 🔐 Security Patterns

### Authentication Pattern: [AUTH_IMPLEMENTATION]

**Description**: [AUTH_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Authentication pattern implementation
interface [AUTH_INTERFACE] {
  authenticate(credentials: [CREDENTIALS_TYPE]): Promise<[AUTH_RESULT_TYPE]>;
  authorize(token: string, permissions: string[]): Promise<boolean>;
  refreshToken(refreshToken: string): Promise<[TOKEN_RESULT_TYPE]>;
}

class [AUTH_IMPLEMENTATION] implements [AUTH_INTERFACE] {
  constructor(
    private [USER_SERVICE]: [USER_SERVICE_TYPE],
    private [TOKEN_SERVICE]: [TOKEN_SERVICE_TYPE],
    private [CACHE_SERVICE]: [CACHE_SERVICE_TYPE]
  ) {}

  async authenticate(credentials: [CREDENTIALS_TYPE]): Promise<[AUTH_RESULT_TYPE]> {
    const user = await this.[USER_SERVICE].findByEmail(credentials.email);
    if (!user || !await this.[VALIDATE_METHOD](credentials.password, user.password)) {
      throw new [AUTH_ERROR]('[INVALID_CREDENTIALS_MESSAGE]');
    }

    const tokens = await this.[TOKEN_SERVICE].generateTokens(user);
    await this.[CACHE_SERVICE].store(user.id, tokens.refreshToken);

    return {
      user: this.[SANITIZE_METHOD](user),
      tokens
    };
  }

  async authorize(token: string, permissions: string[]): Promise<boolean> {
    const payload = await this.[TOKEN_SERVICE].verifyToken(token);
    const userPermissions = await this.[USER_SERVICE].getPermissions(payload.userId);
    
    return permissions.every(permission => userPermissions.includes(permission));
  }

  async refreshToken(refreshToken: string): Promise<[TOKEN_RESULT_TYPE]> {
    const payload = await this.[TOKEN_SERVICE].verifyRefreshToken(refreshToken);
    const storedToken = await this.[CACHE_SERVICE].get(payload.userId);
    
    if (storedToken !== refreshToken) {
      throw new [AUTH_ERROR]('[INVALID_TOKEN_MESSAGE]');
    }

    const user = await this.[USER_SERVICE].findById(payload.userId);
    const tokens = await this.[TOKEN_SERVICE].generateTokens(user);
    
    await this.[CACHE_SERVICE].store(user.id, tokens.refreshToken);
    return tokens;
  }

  private async [VALIDATE_METHOD](password: string, hash: string): Promise<boolean> {
    // Password validation implementation
    return await [COMPARISON_FUNCTION](password, hash);
  }

  private [SANITIZE_METHOD](user: [USER_TYPE]): [SANITIZED_USER_TYPE] {
    // Remove sensitive information
    const { password, ...sanitizedUser } = user;
    return sanitizedUser;
  }
}
```

---

## 🧪 Testing Patterns

### Test Factory Pattern: [TEST_FACTORY_IMPLEMENTATION]

**Description**: [TEST_FACTORY_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Test factory implementation
class [TEST_FACTORY] {
  static create[ENTITY_NAME](overrides?: Partial<[ENTITY_TYPE]>): [ENTITY_TYPE] {
    return {
      id: '[TEST_ID]',
      [PROPERTY_1]: '[DEFAULT_VALUE_1]',
      [PROPERTY_2]: '[DEFAULT_VALUE_2]',
      [DATE_PROPERTY]: new Date(),
      ...overrides
    };
  }

  static create[ENTITY_NAME]List(count: number, overrides?: Partial<[ENTITY_TYPE]>): [ENTITY_TYPE][] {
    return Array.from({ length: count }, (_, index) =>
      this.create[ENTITY_NAME]({ ...overrides, id: `test-id-${index}` })
    );
  }
}

// Usage in tests
describe('[TEST_SUBJECT]', () => {
  it('should handle [TEST_CASE]', async () => {
    const testData = [TEST_FACTORY].create[ENTITY_NAME]({
      [PROPERTY_1]: '[TEST_VALUE]'
    });

    const result = await [SYSTEM_UNDER_TEST].[METHOD_UNDER_TEST](testData);
    
    expect(result).toEqual([EXPECTED_RESULT]);
  });
});
```

### Mock Pattern: [MOCK_IMPLEMENTATION]

**Description**: [MOCK_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Mock implementation
class [MOCK_CLASS] implements [INTERFACE_TYPE] {
  private [METHODS_PROPERTY]: Map<string, any> = new Map();

  when(methodName: string, returnValue: any): this {
    this.[METHODS_PROPERTY].set(methodName, returnValue);
    return this;
  }

  [METHOD_NAME_1]([PARAMETERS]): [RETURN_TYPE_1] {
    return this.[METHODS_PROPERTY].get('[METHOD_NAME_1]') || [DEFAULT_RETURN_1];
  }

  [METHOD_NAME_2]([PARAMETERS]): [RETURN_TYPE_2] {
    return this.[METHODS_PROPERTY].get('[METHOD_NAME_2]') || [DEFAULT_RETURN_2];
  }
}

// Usage in tests
const mockService = new [MOCK_CLASS]()
  .when('[METHOD_NAME_1]', [MOCK_RETURN_VALUE_1])
  .when('[METHOD_NAME_2]', [MOCK_RETURN_VALUE_2]);

const systemUnderTest = new [SYSTEM_CLASS](mockService);
```

---

## 🚀 Performance Patterns

### Caching Pattern: [CACHE_IMPLEMENTATION]

**Description**: [CACHE_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Caching pattern implementation
interface [CACHE_INTERFACE] {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
}

class [CACHE_IMPLEMENTATION] implements [CACHE_INTERFACE] {
  private cache: Map<string, { value: any; expiry: number }> = new Map();

  async get<T>(key: string): Promise<T | null> {
    const item = this.cache.get(key);
    
    if (!item) {
      return null;
    }

    if (Date.now() > item.expiry) {
      this.cache.delete(key);
      return null;
    }

    return item.value;
  }

  async set<T>(key: string, value: T, ttl: number = 3600): Promise<void> {
    const expiry = Date.now() + (ttl * 1000);
    this.cache.set(key, { value, expiry });
  }

  async delete(key: string): Promise<void> {
    this.cache.delete(key);
  }

  async clear(): Promise<void> {
    this.cache.clear();
  }
}

// Cached service implementation
class [CACHED_SERVICE] {
  constructor(
    private [SERVICE_NAME]: [SERVICE_TYPE],
    private [CACHE_NAME]: [CACHE_TYPE]
  ) {}

  async [METHOD_NAME]([PARAMETERS]): Promise<[RETURN_TYPE]> {
    const cacheKey = `[CACHE_PREFIX]:${JSON.stringify([PARAMETERS])}`;
    
    // Try to get from cache first
    const cached = await this.[CACHE_NAME].get<[RETURN_TYPE]>(cacheKey);
    if (cached) {
      return cached;
    }

    // Get from service and cache result
    const result = await this.[SERVICE_NAME].[METHOD_NAME]([PARAMETERS]);
    await this.[CACHE_NAME].set(cacheKey, result, [CACHE_TTL]);
    
    return result;
  }
}
```

---

## 📊 Monitoring Patterns

### Logging Pattern: [LOGGING_IMPLEMENTATION]

**Description**: [LOGGING_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Logging pattern implementation
enum [LOG_LEVEL] {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error'
}

interface [LOG_ENTRY] {
  level: [LOG_LEVEL];
  message: string;
  timestamp: Date;
  context?: any;
  error?: Error;
}

interface [LOGGER_INTERFACE] {
  debug(message: string, context?: any): void;
  info(message: string, context?: any): void;
  warn(message: string, context?: any): void;
  error(message: string, error?: Error, context?: any): void;
}

class [LOGGER_IMPLEMENTATION] implements [LOGGER_INTERFACE] {
  constructor(private [TRANSPORT_NAME]: [TRANSPORT_TYPE]) {}

  debug(message: string, context?: any): void {
    this.log([LOG_LEVEL].DEBUG, message, context);
  }

  info(message: string, context?: any): void {
    this.log([LOG_LEVEL].INFO, message, context);
  }

  warn(message: string, context?: any): void {
    this.log([LOG_LEVEL].WARN, message, context);
  }

  error(message: string, error?: Error, context?: any): void {
    this.log([LOG_LEVEL].ERROR, message, context, error);
  }

  private log(level: [LOG_LEVEL], message: string, context?: any, error?: Error): void {
    const entry: [LOG_ENTRY] = {
      level,
      message,
      timestamp: new Date(),
      context,
      error
    };

    this.[TRANSPORT_NAME].log(entry);
  }
}

// Decorator pattern for method logging
function [LOGGING_DECORATOR](logger: [LOGGER_INTERFACE]) {
  return function(target: any, propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value;

    descriptor.value = async function(...args: any[]) {
      logger.debug(`Calling ${propertyName}`, { args });
      
      try {
        const result = await method.apply(this, args);
        logger.info(`${propertyName} completed successfully`, { result });
        return result;
      } catch (error) {
        logger.error(`${propertyName} failed`, error, { args });
        throw error;
      }
    };

    return descriptor;
  };
}
```

---

## 🔄 Integration Patterns

### Adapter Pattern: [ADAPTER_IMPLEMENTATION]

**Description**: [ADAPTER_DESCRIPTION]

**Implementation:**
```[PROGRAMMING_LANGUAGE]
// Adapter pattern implementation
interface [TARGET_INTERFACE] {
  [METHOD_1](): [RETURN_TYPE_1];
  [METHOD_2](): [RETURN_TYPE_2];
}

class [ADAPTEE_CLASS] {
  [ADAPTEE_METHOD_1](): [ADAPTEE_RETURN_TYPE_1] {
    // Legacy implementation
    return [ADAPTEE_RESULT_1];
  }

  [ADAPTEE_METHOD_2](): [ADAPTEE_RETURN_TYPE_2] {
    // Legacy implementation
    return [ADAPTEE_RESULT_2];
  }
}

class [ADAPTER_CLASS] implements [TARGET_INTERFACE] {
  constructor(private adaptee: [ADAPTEE_CLASS]) {}

  [METHOD_1](): [RETURN_TYPE_1] {
    const legacyResult = this.adaptee.[ADAPTEE_METHOD_1]();
    // Convert legacy format to new format
    return this.[CONVERSION_METHOD_1](legacyResult);
  }

  [METHOD_2](): [RETURN_TYPE_2] {
    const legacyResult = this.adaptee.[ADAPTEE_METHOD_2]();
    // Convert legacy format to new format
    return this.[CONVERSION_METHOD_2](legacyResult);
  }

  private [CONVERSION_METHOD_1](legacy: [ADAPTEE_RETURN_TYPE_1]): [RETURN_TYPE_1] {
    // Conversion logic
    return [CONVERTED_RESULT_1];
  }

  private [CONVERSION_METHOD_2](legacy: [ADAPTEE_RETURN_TYPE_2]): [RETURN_TYPE_2] {
    // Conversion logic
    return [CONVERTED_RESULT_2];
  }
}
```

---

## 📋 Pattern Selection Guide

### Decision Matrix

| Scenario | Recommended Pattern | Alternative | When to Choose |
|----------|-------------------|-------------|----------------|
| [SCENARIO_1] | [PATTERN_1] | [ALTERNATIVE_1] | [SELECTION_CRITERIA_1] |
| [SCENARIO_2] | [PATTERN_2] | [ALTERNATIVE_2] | [SELECTION_CRITERIA_2] |
| [SCENARIO_3] | [PATTERN_3] | [ALTERNATIVE_3] | [SELECTION_CRITERIA_3] |

### Pattern Combinations

#### [COMBINATION_NAME_1]
**Patterns Used**: [PATTERN_A], [PATTERN_B]  
**Use Case**: [COMBINATION_USE_CASE]  
**Benefits**: [COMBINATION_BENEFITS]

#### [COMBINATION_NAME_2]
**Patterns Used**: [PATTERN_C], [PATTERN_D], [PATTERN_E]  
**Use Case**: [COMBINATION_USE_CASE]  
**Benefits**: [COMBINATION_BENEFITS]

---

## 🎯 Best Practices

### Pattern Implementation Guidelines:
1. **Understand the Problem**: Choose patterns that solve actual problems
2. **Keep It Simple**: Don't over-engineer solutions
3. **Follow Conventions**: Use established patterns for your framework
4. **Document Decisions**: Explain why specific patterns were chosen
5. **Test Thoroughly**: Ensure pattern implementations are well-tested

### Anti-Patterns to Avoid:
- **[ANTI_PATTERN_1]**: [ANTI_PATTERN_DESCRIPTION]
- **[ANTI_PATTERN_2]**: [ANTI_PATTERN_DESCRIPTION]
- **[ANTI_PATTERN_3]**: [ANTI_PATTERN_DESCRIPTION]

---

## 🏗️ **Modular Architecture Patterns**

### **Modular Design Principles**
**Purpose**: Create scalable, maintainable applications through clear module boundaries and dependencies

#### **Feature-Based Module Structure**
```
[PROJECT_DIRECTORY]/
├── shared/                          # Cross-cutting concerns
│   ├── core/                        # Core utilities and constants
│   ├── data/                        # Data layer abstractions
│   ├── domain/                      # Business logic layer
│   └── presentation/                # UI abstractions and themes
├── features/                        # Feature modules
│   ├── [FEATURE_1]/                 # Self-contained feature
│   │   ├── data/                    # Feature-specific data
│   │   ├── domain/                  # Feature business logic
│   │   └── presentation/            # Feature UI components
│   ├── [FEATURE_2]/                 # Another independent feature
│   │   ├── data/                    # Feature-specific data
│   │   ├── domain/                  # Feature business logic
│   │   └── presentation/            # Feature UI components
│   └── [FEATURE_3]/                 # Additional feature
└── app/                             # Application orchestration
    ├── routing/                     # Navigation and routing
    ├── dependency_injection/        # DI container setup
    └── configuration/               # App-level configuration
```

#### **Module Dependency Rules**
- **Shared Layer**: No dependencies on feature modules
- **Feature Modules**: Can depend on shared layer, not other features
- **App Layer**: Can orchestrate all modules but maintains loose coupling
- **Cross-Feature Communication**: Through shared domain interfaces or events

#### **Dependency Injection for Modularity**
```[PROGRAMMING_LANGUAGE]
// Module-specific service registration
class [FEATURE_1]Module {
  static void registerDependencies(DIContainer container) {
    // Register feature-specific services
    container.register<[FEATURE_1]Repository>(() => 
      [FEATURE_1]RepositoryImpl(container.get<Database>()));
    container.register<[FEATURE_1]Service>(() => 
      [FEATURE_1]Service(container.get<[FEATURE_1]Repository>()));
    container.register<[FEATURE_1]Controller>(() => 
      [FEATURE_1]Controller(container.get<[FEATURE_1]Service>()));
  }
}

// Application-level DI setup
class AppModule {
  static void configureDependencies(DIContainer container) {
    // Register shared services first
    CoreModule.registerDependencies(container);
    DataModule.registerDependencies(container);
    
    // Register feature modules independently
    [FEATURE_1]Module.registerDependencies(container);
    [FEATURE_2]Module.registerDependencies(container);
    [FEATURE_3]Module.registerDependencies(container);
  }
}
```

#### **Module Communication Patterns**
```[PROGRAMMING_LANGUAGE]
// Event-driven communication between modules
class ModuleEventBus {
  final Map<Type, List<Function>> _listeners = {};
  
  void subscribe<T>(Function(T) listener) {
    _listeners.putIfAbsent(T, () => []).add(listener);
  }
  
  void publish<T>(T event) {
    final listeners = _listeners[T] ?? [];
    for (final listener in listeners) {
      listener(event);
    }
  }
}

// Shared domain events
abstract class DomainEvent {
  final DateTime timestamp;
  DomainEvent() : timestamp = DateTime.now();
}

class [FEATURE_1]UpdatedEvent extends DomainEvent {
  final [FEATURE_1]Item item;
  [FEATURE_1]UpdatedEvent(this.item);
}

// Feature modules communicate through events
class [FEATURE_2]Service {
  final ModuleEventBus _eventBus;
  
  [FEATURE_2]Service(this._eventBus) {
    _eventBus.subscribe<[FEATURE_1]UpdatedEvent>(_handleFeature1Update);
  }
  
  void _handleFeature1Update([FEATURE_1]UpdatedEvent event) {
    // React to changes in other feature
  }
}
```

#### **Module Configuration and Loading**
```[PROGRAMMING_LANGUAGE]
// Module configuration interface
abstract class Module {
  String get name;
  List<String> get dependencies;
  void initialize(DIContainer container);
  void dispose();
}

// Feature module implementation
class [FEATURE_1]Module extends Module {
  @override
  String get name => '[FEATURE_1]';
  
  @override
  List<String> get dependencies => ['core', 'data'];
  
  @override
  void initialize(DIContainer container) {
    // Register feature-specific dependencies
    container.register<[FEATURE_1]Repository>(() => 
      [FEATURE_1]RepositoryImpl());
    container.register<[FEATURE_1]Service>(() => 
      [FEATURE_1]Service(container.get<[FEATURE_1]Repository>()));
  }
  
  @override
  void dispose() {
    // Clean up feature-specific resources
  }
}

// Module loader for dynamic feature loading
class ModuleLoader {
  final Map<String, Module> _modules = {};
  final DIContainer _container;
  
  ModuleLoader(this._container);
  
  Future<void> loadModule(Module module) async {
    // Check dependencies
    for (final dependency in module.dependencies) {
      if (!_modules.containsKey(dependency)) {
        throw ModuleDependencyError(
          'Module ${module.name} depends on $dependency which is not loaded');
      }
    }
    
    // Initialize module
    module.initialize(_container);
    _modules[module.name] = module;
  }
  
  void unloadModule(String moduleName) {
    final module = _modules[moduleName];
    if (module != null) {
      module.dispose();
      _modules.remove(moduleName);
    }
  }
}
```

#### **Testing Modular Architecture**
```[PROGRAMMING_LANGUAGE]
// Module-specific test configuration
class [FEATURE_1]TestModule extends Module {
  @override
  String get name => '[FEATURE_1]_test';
  
  @override
  List<String> get dependencies => ['core_test'];
  
  @override
  void initialize(DIContainer container) {
    // Register mock dependencies for testing
    container.register<[FEATURE_1]Repository>(() => 
      Mock[FEATURE_1]Repository());
    container.register<[FEATURE_1]Service>(() => 
      [FEATURE_1]Service(container.get<[FEATURE_1]Repository>()));
  }
}

// Integration test for module interactions
void main() {
  group('Module Integration Tests', () {
    late DIContainer container;
    late ModuleLoader moduleLoader;
    
    setUp(() {
      container = DIContainer();
      moduleLoader = ModuleLoader(container);
    });
    
    test('modules communicate through events', () async {
      // Load core and feature modules
      await moduleLoader.loadModule(CoreModule());
      await moduleLoader.loadModule([FEATURE_1]Module());
      await moduleLoader.loadModule([FEATURE_2]Module());
      
      // Test module interaction
      final feature1Service = container.get<[FEATURE_1]Service>();
      final feature2Service = container.get<[FEATURE_2]Service>();
      
      await feature1Service.performAction();
      
      // Verify feature2 reacted to feature1's event
      expect(feature2Service.lastProcessedEvent, isNotNull);
    });
  });
}
```

### **Modular Design Benefits**
- **Scalability**: Features can be developed and deployed independently
- **Maintainability**: Clear boundaries reduce coupling and improve code organization
- **Testability**: Modules can be tested in isolation with mock dependencies
- **Team Collaboration**: Different teams can work on separate modules simultaneously
- **Code Reuse**: Shared modules can be reused across different applications

### **Modular Design Guidelines**
1. **Single Responsibility**: Each module should have one clear purpose
2. **Dependency Direction**: Dependencies should point inward, never circular
3. **Interface Segregation**: Modules communicate through well-defined interfaces
4. **Configuration Over Convention**: Explicit module configuration and dependencies
5. **Independent Deployment**: Modules should be deployable independently when possible

---

**Framework Patterns Version**: [FRAMEWORK_VERSION]  
**Last Updated**: [CURRENT_DATE]  
**Technology Stack**: [PRIMARY_TECH_STACK]  
**Maintainer**: [MAINTAINER_NAME]

---

*This template provides comprehensive framework patterns and architectural guidance. Customize all bracketed placeholders with your technology-specific information and adapt patterns to match your framework's conventions and best practices.*
