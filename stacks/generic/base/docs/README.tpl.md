<!--
File: README.tpl.md
Purpose: Template for unknown implementation
Template Version: 1.0
-->

# [PROJECT_NAME]

> **Generic Technology Stack Template** - Adaptable to any programming language or framework

## 🎯 Choose Your Technology Stack

This is a **generic template** designed to work with any technology stack. Select your preferred stack below to see stack-specific setup instructions:

### **Popular Stacks**
- [🐍 Python](#python-setup) - FastAPI, Django, Flask
- [🟢 Node.js](#nodejs-setup) - Express, NestJS, Next.js  
- [🔷 Go](#go-setup) - Gin, Echo, Fiber
- [☕ Java](#java-setup) - Spring Boot, Quarkus
- [🦀 Rust](#rust-setup) - Actix, Rocket, Axum
- [🫧 C#](#csharp-setup) - ASP.NET Core
- [💎 Ruby](#ruby-setup) - Rails, Sinatra
- [🐘 PHP](#php-setup) - Laravel, Symfony

### **Other Technologies**
- [📚 Other Languages](#other-languages) - Adapt patterns to any language

---

## 🚀 Quick Start

### 1. Template Selection
```bash
# Clone this template
git clone [TEMPLATE_REPOSITORY_URL]
cd [PROJECT_NAME]

# Choose your stack and follow the setup instructions below
```

### 2. Core Patterns (All Stacks)
This template provides these universal design patterns:
- **Configuration Management** - Environment-based config with validation
- **Error Handling** - Structured error management with logging
- **HTTP Client** - Robust API communication with retries
- **Logging** - Structured logging with multiple outputs
- **Authentication** - JWT, OAuth, and session-based auth
- **Data Validation** - Input validation and sanitization

### 3. Adaptation Process
1. **Select your technology stack** from sections below
2. **Implement the patterns** using your chosen language/framework
3. **Customize for your needs** - modify patterns as required
4. **Test thoroughly** - ensure all patterns work in your environment

---

## 🐍 Python Setup

### Prerequisites
- Python 3.9+
- pip or poetry
- virtualenv (recommended)

### Installation
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install fastapi uvicorn pydantic sqlalchemy alembic
pip install python-jose[cryptography] passlib[bcrypt]
pip install python-multipart pyyaml structlog

# Development dependencies
pip install pytest pytest-asyncio black flake8 mypy
```

### Project Structure
```
[PROJECT_NAME]/
├── src/
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py          # Configuration management
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── jwt_handler.py       # JWT authentication
│   │   └── password_manager.py  # Password hashing
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── http_client.py       # HTTP client with retries
│   │   ├── logger.py            # Structured logging
│   │   ├── errors.py            # Error handling
│   │   └── validators.py        # Data validation
│   ├── models/
│   ├── services/
│   └── api/
├── tests/
├── requirements.txt
├── pyproject.toml
└── README.md
```

### Key Libraries
- **FastAPI** - Web framework
- **Pydantic** - Data validation
- **SQLAlchemy** - ORM
- **python-jose** - JWT handling
- **structlog** - Structured logging
- **httpx** - HTTP client

---

## 🟢 Node.js Setup

### Prerequisites
- Node.js 16+
- npm or yarn
- TypeScript (recommended)

### Installation
```bash
# Initialize project
npm init -y
# or: yarn init -y

# Install dependencies
npm install express jsonwebtoken bcryptjs
npm install joi express-rate-limit helmet cors
npm install winston axios pino

# Development dependencies
npm install -D typescript @types/node @types/express
npm install -D nodemon jest eslint prettier
npm install -D @types/jsonwebtoken @types/bcryptjs

# TypeScript setup
npx tsc --init
```

### Project Structure
```
[PROJECT_NAME]/
├── src/
│   ├── config/
│   │   ├── index.ts             # Configuration management
│   │   └── database.ts
│   ├── auth/
│   │   ├── jwt.ts               # JWT authentication
│   │   └── password.ts          # Password hashing
│   ├── utils/
│   │   ├── http.ts              # HTTP client
│   │   ├── logger.ts            # Structured logging
│   │   ├── errors.ts            # Error handling
│   │   └── validation.ts        # Data validation
│   ├── models/
│   ├── services/
│   └── routes/
├── tests/
├── package.json
├── tsconfig.json
└── README.md
```

### Key Libraries
- **Express** - Web framework
- **Joi** - Data validation
- **jsonwebtoken** - JWT handling
- **winston** - Structured logging
- **axios** - HTTP client
- **TypeScript** - Type safety

---

## 🔷 Go Setup

### Prerequisites
- Go 1.19+
- Go modules

### Installation
```bash
# Initialize module
go mod init [MODULE_NAME]

# Install dependencies
go get github.com/gin-gonic/gin
go get github.com/golang-jwt/jwt/v5
go get golang.org/x/crypto/bcrypt
go get github.com/go-playground/validator/v10
go get github.com/sirupsen/logrus
go get github.com/joho/godotenv

# Development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/air-verse/air@latest
```

### Project Structure
```
[PROJECT_NAME]/
├── cmd/
│   └── server/
│       └── main.go              # Application entry point
├── internal/
│   ├── config/
│   │   └── config.go            # Configuration management
│   ├── auth/
│   │   ├── jwt.go               # JWT authentication
│   │   └── password.go          # Password hashing
│   ├── utils/
│   │   ├── http.go              # HTTP client
│   │   ├── logger.go            # Structured logging
│   │   ├── errors.go            # Error handling
│   │   └── validation.go        # Data validation
│   ├── models/
│   ├── services/
│   └── handlers/
├── pkg/
├── tests/
├── go.mod
├── go.sum
├── .air.toml
└── README.md
```

### Key Libraries
- **Gin** - Web framework
- **validator** - Data validation
- **golang-jwt** - JWT handling
- **logrus** - Structured logging
- **bcrypt** - Password hashing
- **godotenv** - Environment variables

---

## ☕ Java Setup

### Prerequisites
- Java 17+
- Maven or Gradle
- Spring Boot (recommended)

### Installation (Maven)
```xml
<!-- pom.xml dependencies -->
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.11.5</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-logging</artifactId>
    </dependency>
</dependencies>
```

### Project Structure
```
[PROJECT_NAME]/
├── src/main/java/com/example/
│   ├── config/
│   │   ├── AppConfig.java      # Configuration management
│   │   └── SecurityConfig.java # Security configuration
│   ├── auth/
│   │   ├── JwtService.java     # JWT authentication
│   │   └── PasswordService.java # Password hashing
│   ├── utils/
│   │   ├── HttpClient.java     # HTTP client
│   │   ├── Logger.java         # Logging utilities
│   │   ├── ErrorHandler.java   # Error handling
│   │   └── Validator.java      # Data validation
│   ├── model/
│   ├── service/
│   └── controller/
├── src/test/java/
├── pom.xml
└── README.md
```

### Key Libraries
- **Spring Boot** - Application framework
- **Spring Security** - Security framework
- **Validation** - Bean validation
- **JWT** - Token handling
- **SLF4J** - Logging facade

---

## 🦀 Rust Setup

### Prerequisites
- Rust 1.70+
- Cargo

### Installation
```bash
# Create new project
cargo new [PROJECT_NAME] --bin
cd [PROJECT_NAME]

# Add dependencies to Cargo.toml
cat >> Cargo.toml << 'EOF'
[dependencies]
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
jsonwebtoken = "8.0"
bcrypt = "0.13"
validator = { version = "0.16", features = ["derive"] }
log = "0.4"
env_logger = "0.10"
reqwest = { version = "0.11", features = ["json"] }
thiserror = "1.0"
EOF

# Install
cargo build
```

### Project Structure
```
[PROJECT_NAME]/
├── src/
│   ├── config/
│   │   └── mod.rs               # Configuration management
│   ├── auth/
│   │   ├── jwt.rs               # JWT authentication
│   │   └── password.rs          # Password hashing
│   ├── utils/
│   │   ├── http.rs              # HTTP client
│   │   ├── logger.rs            # Logging utilities
│   │   ├── errors.rs            # Error handling
│   │   └── validation.rs        # Data validation
│   ├── models/
│   ├── services/
│   └── handlers/
├── tests/
├── Cargo.toml
└── README.md
```

### Key Libraries
- **Tokio** - Async runtime
- **Serde** - Serialization
- **jsonwebtoken** - JWT handling
- **bcrypt** - Password hashing
- **validator** - Data validation
- **reqwest** - HTTP client

---

## 🫧 C# Setup

### Prerequisites
- .NET 6.0+
- Visual Studio or VS Code

### Installation
```bash
# Create new project
dotnet new webapi -n [PROJECT_NAME]
cd [PROJECT_NAME]

# Install packages
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.AspNetCore.Authorization
dotnet add package FluentValidation
dotnet add package Serilog
dotnet add package Serilog.AspNetCore
dotnet add package Microsoft.Extensions.Http
dotnet add package BCrypt.Net-Next
```

### Project Structure
```
[PROJECT_NAME]/
├── Config/
│   ├── AppConfig.cs             # Configuration management
│   └── AuthConfig.cs            # Authentication configuration
├── Auth/
│   ├── JwtService.cs            # JWT authentication
│   └── PasswordService.cs       # Password hashing
├── Utils/
│   ├── HttpClientService.cs     # HTTP client
│   ├── LoggerService.cs         # Logging utilities
│   ├── ErrorHandler.cs          # Error handling
│   └── ValidationService.cs     # Data validation
├── Models/
├── Services/
├── Controllers/
├── Tests/
├── [PROJECT_NAME].csproj
└── README.md
```

### Key Libraries
- **ASP.NET Core** - Web framework
- **JWT Bearer** - JWT authentication
- **FluentValidation** - Data validation
- **Serilog** - Structured logging
- **HttpClient** - HTTP client

---

## 💎 Ruby Setup

### Prerequisites
- Ruby 3.0+
- Bundler
- Rails (optional)

### Installation
```bash
# Create new project
rails new [PROJECT_NAME] --api
cd [PROJECT_NAME]

# Add gems to Gemfile
cat >> Gemfile << 'EOF'
gem 'jwt'
gem 'bcrypt'
gem 'dry-validation'
gem 'httparty'
gem 'lograge'
gem 'dotenv-rails'
EOF

# Install
bundle install
```

### Project Structure
```
[PROJECT_NAME]/
├── config/
│   ├── application.rb          # Configuration management
│   └── initializers/
│       └── jwt.rb               # JWT configuration
├── app/
│   ├── services/
│   │   ├── auth_service.rb      # Authentication
│   │   ├── http_client.rb       # HTTP client
│   │   └── logger_service.rb    # Logging
│   ├── utils/
│   │   ├── error_handler.rb     # Error handling
│   │   └── validator.rb         # Data validation
│   ├── models/
│   └── controllers/
├── spec/
├── Gemfile
└── README.md
```

### Key Libraries
- **Rails** - Web framework (optional)
- **JWT** - Token handling
- **bcrypt** - Password hashing
- **dry-validation** - Data validation
- **httparty** - HTTP client

---

## 🐘 PHP Setup

### Prerequisites
- PHP 8.0+
- Composer
- Laravel (recommended)

### Installation
```bash
# Create new Laravel project
composer create-project laravel/laravel [PROJECT_NAME]
cd [PROJECT_NAME]

# Install packages
composer require firebase/php-jwt
composer require bcrypt
composer require respect/validation
composer require guzzlehttp/guzzle
composer require monolog/monolog
```

### Project Structure
```
[PROJECT_NAME]/
├── config/
│   ├── app.php                  # Configuration management
│   └── auth.php                 # Authentication configuration
├── app/
│   ├── Services/
│   │   ├── AuthService.php      # Authentication
│   │   ├── HttpClientService.php # HTTP client
│   │   └── LoggerService.php    # Logging
│   ├── Utils/
│   │   ├── ErrorHandler.php     # Error handling
│   │   └── Validator.php        # Data validation
│   ├── Models/
│   └── Http/Controllers/
├── tests/
├── composer.json
└── README.md
```

### Key Libraries
- **Laravel** - Web framework
- **firebase/php-jwt** - JWT handling
- **bcrypt** - Password hashing
- **respect/validation** - Data validation
- **guzzlehttp** - HTTP client

---

## 📚 Other Languages

### Adaptation Guidelines
For languages not listed above, follow these steps:

1. **Choose Core Libraries**
   - Web framework (Express, Django, Spring, etc.)
   - JWT library for authentication
   - Validation library for input validation
   - HTTP client library for API calls
   - Logging library for structured logging

2. **Implement Patterns**
   - Review the design patterns in `base/code/`
   - Adapt pseudocode to your language syntax
   - Follow language-specific best practices
   - Use appropriate naming conventions

3. **Project Structure**
   ```
   [PROJECT_NAME]/
   ├── config/          # Configuration management
   ├── auth/            # Authentication services
   ├── utils/           # Utilities (HTTP, logging, validation)
   ├── models/          # Data models
   ├── services/        # Business logic
   ├── controllers/     # HTTP handlers
   ├── tests/           # Test files
   └── README.md        # Documentation
   ```

4. **Common Libraries by Language**
   - **Elixir**: Phoenix, Guardian, Ecto
   - **Kotlin**: Ktor, Spring Boot, Jackson
   - **Scala**: Play, Akka, Circe
   - **C++**: Crow, Pistache, nlohmann/json
   - **Swift**: Vapor, JWT, Validation

---

## 🛠️ Development Workflow

### 1. Environment Setup
```bash
# Copy environment template
cp .env.example .env
# Edit .env with your configuration

# Install dependencies
# [Language-specific install command]

# Run development server
# [Language-specific dev server command]
```

### 2. Code Quality
```bash
# Format code
# [Language-specific formatter]

# Lint code
# [Language-specific linter]

# Run tests
# [Language-specific test runner]

# Type checking (if applicable)
# [Language-specific type checker]
```

### 3. Configuration
- **Environment Variables**: Use `.env` files for local development
- **Configuration Files**: YAML/JSON for structured config
- **Secret Management**: Use environment variables for sensitive data
- **Feature Flags**: Implement feature toggles for new features

---

## 🧪 Testing Strategy

### Test Categories
1. **Unit Tests**: Individual function and class tests
2. **Integration Tests**: Database and external service tests
3. **API Tests**: Endpoint testing
4. **End-to-End Tests**: Full workflow testing

### Test Organization
```
tests/
├── unit/                    # Unit tests
│   ├── auth/
│   ├── utils/
│   └── services/
├── integration/             # Integration tests
│   ├── database/
│   └── external_apis/
├── api/                     # API tests
│   ├── auth/
│   └── endpoints/
└── e2e/                     # End-to-end tests
```

### Test Data Management
- Use factories for test data generation
- Mock external services
- Clean up test data after each test
- Use transaction rollback for database tests

---

## 🚀 Deployment

### Production Considerations
- **Environment**: Production configuration
- **Security**: SSL/TLS, security headers
- **Monitoring**: Application metrics and health checks
- **Logging**: Centralized log aggregation
- **Scaling**: Load balancing and horizontal scaling

### Deployment Options
- **Cloud Platforms**: AWS, Azure, GCP, Heroku
- **Container**: Docker, Kubernetes
- **Serverless**: AWS Lambda, Azure Functions
- **Traditional**: VPS, dedicated servers

---

## 📚 Documentation

### API Documentation
- **OpenAPI/Swagger**: REST API documentation
- **Postman**: API testing and documentation
- **Inline Docs**: Code documentation and comments

### Developer Documentation
- **Setup Guide**: Local development setup
- **Architecture Guide**: System design and patterns
- **Contributing Guide**: Development workflow
- **Deployment Guide**: Production deployment

---

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create feature branch
3. Implement changes with tests
4. Follow code style guidelines
5. Submit pull request

### Code Standards
- Follow language-specific style guides
- Write comprehensive tests
- Add documentation for new features
- Use descriptive commit messages

---

## 📞 Support

### Getting Help
- **Documentation**: Check the `docs/` directory
- **Issues**: Create GitHub issue for bugs
- **Discussions**: Use GitHub Discussions for questions
- **Examples**: Review implementation examples

### Common Issues
- **Configuration**: Check environment variables
- **Dependencies**: Verify library versions
- **Authentication**: Validate JWT configuration
- **Database**: Check connection settings

---

## 📄 License

Users should add their appropriate license when using this template.

---

## 🏆 Acknowledgments

- **Universal Template System**: For the excellent template framework
- **Open Source Community**: For amazing libraries and tools
- **Contributors**: For improving this template

---

**Generic Stack Template**  
**Version**: 1.0  
**Last Updated**: [DATE]  
**Adaptable to any technology stack**

---

*Choose your technology stack and adapt these patterns to build robust, scalable applications.*
