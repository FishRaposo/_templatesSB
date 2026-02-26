<!--
File: README.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# TypeScript Stack Template

> **TypeScript**: JavaScript with syntax for types, providing static typing and enhanced developer experience.

## 🎯 Stack Overview

The TypeScript stack provides a robust, type-safe foundation for building scalable Node.js applications with modern JavaScript features, enhanced tooling, and compile-time error detection.

### 🚀 Key Features

- **Static Typing**: Compile-time type checking and enhanced IDE support
- **Modern JavaScript**: ES2020+ features with full TypeScript support
- **Enhanced Tooling**: Superior autocompletion, refactoring, and error detection
- **Framework Support**: Express.js, NestJS, and modern TypeScript frameworks
- **Type Safety**: Interfaces, generics, decorators, and advanced type features
- **Developer Experience**: Hot reloading, debugging, and comprehensive testing

### 📁 Project Structure

```
typescript-project/
├── src/                    # Source code directory
│   ├── controllers/        # Route controllers
│   ├── services/          # Business logic services
│   ├── models/            # Data models and interfaces
│   ├── middleware/        # Express middleware
│   ├── utils/             # Utility functions
│   ├── types/             # TypeScript type definitions
│   └── index.ts           # Application entry point
├── tests/                 # Test files
├── dist/                  # Compiled JavaScript output
├── logs/                  # Application logs
├── docs/                  # Documentation
├── package.json           # Dependencies and scripts
├── tsconfig.json          # TypeScript configuration
├── jest.config.js         # Jest testing configuration
├── .eslintrc.js           # ESLint configuration
└── README.md              # Project documentation
```

## 🛠️ Technology Stack

### Core Technologies
- **TypeScript 4.9+**: Static typing and modern JavaScript
- **Node.js 18+**: JavaScript runtime environment
- **Express.js**: Web application framework
- **Jest**: Testing framework with TypeScript support

### Development Tools
- **ts-node-dev**: Hot reloading for TypeScript development
- **ESLint**: Code linting and formatting
- **Prettier**: Code formatting
- **Nodemon**: Process monitoring and auto-restart

### Type Safety & Validation
- **Joi**: Runtime data validation
- **TypeScript Interfaces**: Compile-time type checking
- **Generic Types**: Reusable type-safe components
- **Decorators**: Metadata and cross-cutting concerns

## 📋 Available Templates

### Code Patterns
- **config-management-pattern.tpl.ts**: Type-safe configuration management with environment variables
- **error-handling-pattern.tpl.ts**: Comprehensive error handling with custom error classes
- **http-client-pattern.tpl.ts**: Type-safe HTTP client with interceptors and retry logic
- **logging-utilities-pattern.tpl.ts**: Structured logging with correlation IDs and performance monitoring
- **authentication-pattern.tpl.ts**: JWT-based authentication with role-based access control
- **data-validation-pattern.tpl.ts**: Runtime validation with TypeScript schema definitions

### Documentation
- **README.tpl.md**: Project documentation and setup guide
- **setup-guide.tpl.md**: Detailed installation and configuration instructions

### Testing Patterns
- **unit-tests-pattern.tpl.md**: Unit testing with Jest and TypeScript
- **integration-tests-pattern.tpl.md**: API and database integration testing
- **test-utilities-pattern.tpl.md**: Testing utilities and mock factories

## 🚀 Quick Start

### Prerequisites
- Node.js 18.0 or higher
- npm or yarn package manager
- TypeScript knowledge (basic to intermediate)

### Installation

```bash
# Clone the template
git clone <repository-url> my-typescript-app
cd my-typescript-app

# Install dependencies
npm install

# or with yarn
yarn install
```

### Development

```bash
# Start development server with hot reloading
npm run dev

# or with yarn
yarn dev
```

### Building

```bash
# Compile TypeScript to JavaScript
npm run build

# or with yarn
yarn build
```

### Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

## 🔧 Configuration

### TypeScript Configuration (tsconfig.json)

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "**/*.test.ts"]
}
```

### Environment Variables

```bash
# .env.development
NODE_ENV=development
DEBUG=true
SERVER_PORT=3000
DB_HOST=localhost
DB_PORT=5432
JWT_SECRET=your-super-secret-jwt-key
```

## 📚 TypeScript Features

### Type Safety

```typescript
// Interface definitions
interface User {
  id: string;
  email: string;
  name: string;
  roles: string[];
}

// Generic types
interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

// Type-safe functions
function createUser(userData: CreateUserRequest): Promise<User> {
  // Implementation with full type safety
}
```

### Decorators

```typescript
// Method decorators for cross-cutting concerns
@LogMethod('info')
@ValidateBody(UserValidationSchema)
public async createUser(req: Request): Promise<ApiResponse<User>> {
  // Method implementation
}

// Class decorators
@Controller('/users')
export class UserController {
  // Controller methods
}
```

### Advanced Types

```typescript
// Utility types
type PartialUser = Partial<User>;
type UserWithoutPassword = Omit<User, 'password'>;

// Conditional types
type ApiResponse<T> = T extends string 
  ? { message: T } 
  : { data: T };

// Generic constraints
interface Repository<T extends { id: string }> {
  findById(id: string): Promise<T | null>;
  save(entity: T): Promise<T>;
}
```

## 🔒 Security Best Practices

### Type-Safe Validation

```typescript
// Runtime validation with TypeScript
const userSchema = SchemaBuilder.create()
  .string('name', [Validators.required(), Validators.minLength(2)], true)
  .email('email', true)
  .string('password', [Validators.required(), Validators.minLength(8)], true)
  .build();

// Type-safe request handling
@ValidateBody(userSchema)
public async createUser(req: Request): Promise<User> {
  // req.body is fully typed and validated
}
```

### Authentication & Authorization

```typescript
// Type-safe authentication middleware
@RequireAuth()
@RequirePermissions(['create:user'])
public async createUsers(req: AuthenticatedRequest): Promise<User[]> {
  // Method implementation with type safety
}
```

## 🧪 Testing with TypeScript

### Unit Tests

```typescript
// Type-safe test examples
describe('UserService', () => {
  let userService: UserService;

  beforeEach(() => {
    userService = new UserService();
  });

  it('should create user with valid data', async () => {
    const userData: CreateUserRequest = {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'securepassword123',
    };

    const user = await userService.createUser(userData);
    
    expect(user.email).toBe(userData.email);
    expect(user.id).toBeDefined();
  });
});
```

### Integration Tests

```typescript
// API integration tests
describe('User API', () => {
  let app: Express;

  beforeAll(async () => {
    app = await createTestApp();
  });

  it('should create user via POST /users', async () => {
    const response = await request(app)
      .post('/users')
      .send({
        name: 'John Doe',
        email: 'john@example.com',
        password: 'securepassword123',
      })
      .expect(201);

    expect(response.body.success).toBe(true);
    expect(response.body.data.email).toBe('john@example.com');
  });
});
```

## 📊 Performance Optimization

### Compilation Performance

```json
{
  "compilerOptions": {
    "incremental": true,
    "tsBuildInfoFile": ".tsbuildinfo",
    "skipLibCheck": true,
    "strict": true
  }
}
```

### Runtime Performance

```typescript
// Efficient type guards
function isUser(obj: any): obj is User {
  return obj && typeof obj.id === 'string' && typeof obj.email === 'string';
}

// Generic caching with type safety
class TypeSafeCache<K, V> {
  private cache = new Map<K, V>();
  
  public get(key: K): V | undefined {
    return this.cache.get(key);
  }
  
  public set(key: K, value: V): void {
    this.cache.set(key, value);
  }
}
```

## 🔄 Migration from JavaScript

### Step-by-Step Migration

1. **Add TypeScript**: Install TypeScript and configure tsconfig.json
2. **Rename Files**: Change .js to .ts extensions
3. **Add Types**: Add type annotations to functions and variables
4. **Fix Errors**: Address TypeScript compilation errors
5. **Enable Strict Mode**: Gradually enable stricter TypeScript options

### Compatibility Considerations

```typescript
// Allow JavaScript interop
declare module 'some-js-library' {
  export function someFunction(arg: any): any;
}

// Type assertion for legacy code
const legacyData = someJavaScriptFunction() as UserData;
```

## 🏗️ Architecture Patterns

### Repository Pattern

```typescript
interface IUserRepository {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  save(user: User): Promise<User>;
  delete(id: string): Promise<void>;
}

class UserRepository implements IUserRepository {
  // Type-safe database operations
}
```

### Service Layer Pattern

```typescript
class UserService {
  constructor(
    private userRepository: IUserRepository,
    private emailService: IEmailService
  ) {}

  public async createUser(userData: CreateUserRequest): Promise<User> {
    // Business logic with full type safety
  }
}
```

## 📦 Package Management

### Dependencies Structure

```json
{
  "dependencies": {
    "express": "^4.18.0",
    "joi": "^17.7.0",
    "jsonwebtoken": "^9.0.0",
    "bcryptjs": "^2.4.3"
  },
  "devDependencies": {
    "@types/node": "^18.0.0",
    "@types/express": "^4.17.0",
    "@types/jest": "^29.0.0",
    "typescript": "^4.9.0",
    "ts-jest": "^29.0.0",
    "ts-node-dev": "^2.0.0"
  }
}
```

## 🔧 Development Workflow

### Code Quality

```bash
# Type checking
npm run type-check

# Linting
npm run lint

# Auto-fix linting issues
npm run lint:fix

# Format code
npm run format
```

### Debugging

```typescript
// Source maps for debugging
// tsconfig.json
{
  "compilerOptions": {
    "sourceMap": true,
    "inlineSourceMap": true
  }
}

// VS Code launch configuration
{
  "type": "node",
  "request": "launch",
  "program": "${workspaceFolder}/src/index.ts",
  "outFiles": ["${workspaceFolder}/dist/**/*.js"],
  "runtimeArgs": ["-r", "ts-node/register"]
}
```

## 🚀 Deployment

### Production Build

```bash
# Compile for production
npm run build

# Start production server
npm start
```

### Docker Configuration

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY dist ./dist
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

## 🤝 Contributing

### Code Style

- Use TypeScript strict mode
- Follow ESLint configuration
- Write comprehensive type definitions
- Include JSDoc comments for public APIs
- Add unit tests for all functions

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Add types and tests
4. Ensure all type checks pass
5. Submit pull request with type annotations

## 📚 Learning Resources

- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Express.js TypeScript Guide](https://expressjs.com/en/guide/)
- [Jest TypeScript Testing](https://jestjs.io/docs/getting-started#using-typescript)
- [TypeScript Deep Dive](https://basarat.gitbook.io/typescript/)

## 🆘 Troubleshooting

### Common Issues

**TypeScript compilation errors**
- Check tsconfig.json configuration
- Ensure all @types packages are installed
- Verify import/export syntax

**Hot reloading not working**
- Ensure ts-node-dev is installed
- Check file watching configuration
- Verify source file paths

**Type errors in tests**
- Configure Jest with ts-jest
- Add type definitions for test utilities
- Use proper test file naming

---

## 📄 License

Users should add their appropriate license when using this template.

## 🏆 Acknowledgments

- **TypeScript Team**: For the excellent type system and tooling
- **Express.js Community**: For the robust web framework
- **Jest Team**: For the comprehensive testing framework
- **TypeScript Community**: For amazing packages and tools

---

**TypeScript Version**: [[.TYPESCRIPT_VERSION]]  
**Node.js Version**: [[.NODE_VERSION]]  
**Template Version**: [[.Version]]  
**Author**: [[.Author]]  
**Date**: [[.Date]]
