# Universal Template System - Generic Stack
# Generated: 2025-12-10
# Purpose: generic template utilities
# Tier: base
# Stack: generic
# Category: template

# ----------------------------------------------------------------------------- 
# FILE: setup-guide.tpl.md
# PURPOSE: Generic setup guide for any technology stack
# USAGE: Adapt this guide for your specific technology stack
# AUTHOR: [[.Author]]
# VERSION: [[.Version]]
# SINCE: [[.Version]]
# -----------------------------------------------------------------------------

# Setup Guide

## 🎯 Technology Stack Selection

This setup guide supports multiple technology stacks. **Select your stack below:**

- [🐍 Python](#python-setup)
- [🟢 Node.js](#nodejs-setup)  
- [🔷 Go](#go-setup)
- [☕ Java](#java-setup)
- [🦀 Rust](#rust-setup)
- [🫧 C#](#csharp-setup)
- [💎 Ruby](#ruby-setup)
- [🐘 PHP](#php-setup)

---

## 🐍 Python Setup

### Prerequisites
```bash
# Check Python version (requires 3.9+)
python --version

# Install pip if not present
python -m ensurepip --upgrade

# Install virtualenv
pip install virtualenv
```

### Project Setup
```bash
# 1. Create project directory
mkdir [PROJECT_NAME]
cd [PROJECT_NAME]

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# Unix/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 4. Upgrade pip
pip install --upgrade pip

# 5. Create requirements.txt
cat > requirements.txt << 'EOF'
fastapi>=0.68.0
uvicorn>=0.15.0
pydantic>=1.8.0
sqlalchemy>=1.4.23
alembic>=1.7.0
python-jose[cryptography]>=3.3.0
passlib[bcrypt]>=1.7.4
python-multipart>=0.0.5
pyyaml>=5.4.1
structlog>=21.1.0
httpx>=0.24.0
python-dotenv>=0.19.0
EOF

# 6. Install dependencies
pip install -r requirements.txt

# 7. Create development requirements
cat > requirements-dev.txt << 'EOF'
pytest>=6.2.5
pytest-asyncio>=0.15.0
pytest-cov>=2.12.1
black>=21.9b0
flake8>=3.9.0
mypy>=0.910
pre-commit>=2.15.0
EOF

# 8. Install development dependencies
pip install -r requirements-dev.txt

# 9. Create project structure
mkdir -p src/{config,auth,utils,models,services,api}
mkdir -p tests/{unit,integration,api}
```

### Configuration Files
```bash
# Create .env template
cat > .env.example << 'EOF'
# Application Settings
APP_NAME=[PROJECT_NAME]
APP_VERSION=1.0.0
DEBUG=True
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=sqlite:///./app.db
DATABASE_POOL_SIZE=10

# Server
HOST=0.0.0.0
PORT=8000
WORKERS=1

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# JWT
JWT_SECRET_KEY=your-jwt-secret-key
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# External Services
REDIS_URL=redis://localhost:6379
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EOF

# Create pyproject.toml
cat > pyproject.toml << 'EOF'
[tool.black]
line-length = 88
target-version = ['py39']
include = '\.pyi?$'

[tool.mypy]
python_version = "3.9"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = "--cov=src --cov-report=html --cov-report=term-missing"
EOF

# Create pytest.ini
cat > pytest.ini << 'EOF'
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = --verbose --tb=short --cov=src --cov-report=html
EOF
```

### Development Setup
```bash
# 1. Copy environment file
cp .env.example .env

# 2. Edit .env with your configuration
nano .env

# 3. Install pre-commit hooks
pre-commit install

# 4. Run initial database migration
alembic init alembic
alembic revision --autogenerate -m "Initial migration"
alembic upgrade head

# 5. Run tests
pytest

# 6. Start development server
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

---

## 🟢 Node.js Setup

### Prerequisites
```bash
# Check Node.js version (requires 16+)
node --version

# Check npm version
npm --version

# Install yarn (optional)
npm install -g yarn
```

### Project Setup
```bash
# 1. Create project directory
mkdir [PROJECT_NAME]
cd [PROJECT_NAME]

# 2. Initialize npm project
npm init -y
# or with yarn:
# yarn init -y

# 3. Install production dependencies
npm install express jsonwebtoken bcryptjs
npm install joi express-rate-limit helmet cors
npm install winston axios pino dotenv

# 4. Install development dependencies
npm install -D typescript @types/node @types/express
npm install -D @types/jsonwebtoken @types/bcryptjs @types/cors
npm install -D nodemon jest ts-jest eslint prettier
npm install -D @typescript-eslint/parser @typescript-eslint/eslint-plugin

# 5. Create project structure
mkdir -p src/{config,auth,utils,models,services,routes,middleware}
mkdir -p tests/{unit,integration,api}
mkdir -p dist
```

### Configuration Files
```bash
# Create TypeScript configuration
cat > tsconfig.json << 'EOF'
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
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
EOF

# Create .env template
cat > .env.example << 'EOF'
# Application Settings
APP_NAME=[PROJECT_NAME]
APP_VERSION=1.0.0
NODE_ENV=development
PORT=3000
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
DATABASE_POOL_SIZE=10

# JWT
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRES_IN=24h

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# External Services
REDIS_URL=redis://localhost:6379
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EOF

# Create package.json scripts
npm pkg set scripts.dev="nodemon src/index.ts"
npm pkg set scripts.build="tsc"
npm pkg set scripts.start="node dist/index.js"
npm pkg set scripts.test="jest"
npm pkg set scripts.test:watch="jest --watch"
npm pkg set scripts.test:coverage="jest --coverage"
npm pkg set scripts.lint="eslint src/**/*.ts"
npm pkg set scripts.lint:fix="eslint src/**/*.ts --fix"
npm pkg set scripts.format="prettier --write src/**/*.ts"

# Create jest configuration
cat > jest.config.js << 'EOF'
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
};
EOF

# Create eslint configuration
cat > .eslintrc.js << 'EOF'
module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module',
  },
  extends: [
    '@typescript-eslint/recommended',
  ],
  rules: {
    '@typescript-eslint/no-unused-vars': 'error',
    '@typescript-eslint/explicit-function-return-type': 'warn',
  },
};
EOF

# Create prettier configuration
cat > .prettierrc << 'EOF'
{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 80,
  "tabWidth": 2
}
EOF

# Create nodemon configuration
cat > nodemon.json << 'EOF'
{
  "watch": ["src"],
  "ext": "ts,json",
  "ignore": ["src/**/*.spec.ts"],
  "exec": "ts-node src/index.ts"
}
EOF
```

### Development Setup
```bash
# 1. Copy environment file
cp .env.example .env

# 2. Edit .env with your configuration
nano .env

# 3. Build the project
npm run build

# 4. Run tests
npm test

# 5. Start development server
npm run dev
```

---

## 🔷 Go Setup

### Prerequisites
```bash
# Check Go version (requires 1.19+)
go version

# Set up Go workspace (if needed)
mkdir -p ~/go/{bin,src,pkg}
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc
```

### Project Setup
```bash
# 1. Create project directory
mkdir -p [PROJECT_NAME]
cd [PROJECT_NAME]

# 2. Initialize Go module
go mod init [MODULE_NAME]

# 3. Install dependencies
go get github.com/gin-gonic/gin
go get github.com/golang-jwt/jwt/v5
go get golang.org/x/crypto/bcrypt
go get github.com/go-playground/validator/v10
go get github.com/sirupsen/logrus
go get github.com/joho/godotenv
go get github.com/stretchr/testify/assert
go get github.com/stretchr/testify/mock

# 4. Create project structure
mkdir -p cmd/server
mkdir -p internal/{config,auth,utils,models,services,handlers}
mkdir -p pkg/{http,logger}
mkdir -p tests/{unit,integration}
mkdir -p docs
mkdir -p scripts
```

### Configuration Files
```bash
# Create .env template
cat > .env.example << 'EOF'
# Application Settings
APP_NAME=[PROJECT_NAME]
APP_VERSION=1.0.0
GO_ENV=development
PORT=8080
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
DATABASE_POOL_SIZE=10

# JWT
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRES_IN=24h

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# External Services
REDIS_URL=redis://localhost:6379
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EOF

# Create .air.toml for hot reload
cat > .air.toml << 'EOF'
root = "."
testdata_dir = "testdata"
tmp_dir = "tmp"

[build]
  args_bin = []
  bin = "./tmp/main"
  cmd = "go build -o ./tmp/main ./cmd/server"
  delay = 1000
  exclude_dir = ["assets", "tmp", "vendor", "testdata"]
  exclude_file = []
  exclude_regex = ["_test.go"]
  exclude_unchanged = false
  follow_symlink = false
  full_bin = ""
  include_dir = []
  include_ext = ["go", "tpl", "tmpl", "html"]
  kill_delay = "0s"
  log = "build-errors.log"
  send_interrupt = false
  stop_on_root = false

[color]
  app = ""
  build = "yellow"
  main = "magenta"
  runner = "green"
  watcher = "cyan"

[log]
  time = false

[misc]
  clean_on_exit = false
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM golang:1.19-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/main .
COPY --from=builder /app/.env.example .env

EXPOSE 8080
CMD ["./main"]
EOF

# Create Makefile
cat > Makefile << 'EOF'
.PHONY: build run test clean docker-build docker-run

build:
	go build -o bin/main ./cmd/server

run:
	go run ./cmd/server

test:
	go test -v ./...

test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf bin/ coverage.out coverage.html tmp/

docker-build:
	docker build -t $(APP_NAME) .

docker-run:
	docker run -p 8080:8080 $(APP_NAME)

lint:
	golangci-lint run

fmt:
	go fmt ./...

mod-tidy:
	go mod tidy
EOF
```

### Development Setup
```bash
# 1. Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/air-verse/air@latest

# 2. Copy environment file
cp .env.example .env

# 3. Edit .env with your configuration
nano .env

# 4. Run tests
make test

# 5. Start development server with hot reload
air
# or: make run
```

---

## ☕ Java Setup

### Prerequisites
```bash
# Check Java version (requires 17+)
java -version

# Install Maven (if not present)
# Ubuntu/Debian:
sudo apt-get install maven
# macOS:
brew install maven
# Windows: Download from maven.apache.org
```

### Project Setup
```bash
# 1. Create project directory
mkdir [PROJECT_NAME]
cd [PROJECT_NAME]

# 2. Create Spring Boot project with Maven
mvn archetype:generate -DgroupId=com.example -DartifactId=[PROJECT_NAME] -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false

# 3. Create project structure
mkdir -p src/main/java/com/example/{config,auth,utils,model,service,controller}
mkdir -p src/main/resources
mkdir -p src/test/java/com/example/{config,auth,utils,model,service,controller}
```

### Configuration Files
```bash
# Create pom.xml
cat > pom.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.example</groupId>
    <artifactId>[PROJECT_NAME]</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.0.0</version>
        <relativePath/>
    </parent>
    
    <properties>
        <java.version>17</java.version>
        <jwt.version>0.11.5</jwt.version>
    </properties>
    
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
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-logging</artifactId>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>${jwt.version}</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>${jwt.version}</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>${jwt.version}</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
    
    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
EOF

# Create application.yml
cat > src/main/resources/application.yml << 'EOF'
spring:
  application:
    name: [PROJECT_NAME]
  
  datasource:
    url: jdbc:postgresql://localhost:5432/[PROJECT_NAME]
    username: ${DB_USER:postgres}
    password: ${DB_PASSWORD:password}
    driver-class-name: org.postgresql.Driver
  
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    properties:
      hibernate:
        format_sql: true
  
  logging:
    level:
      com.example: INFO
      org.springframework.security: DEBUG

app:
  jwt:
    secret: ${JWT_SECRET:your-jwt-secret-key}
    expiration: 86400000 # 24 hours
  
server:
  port: ${PORT:8080}
EOF

# Create application-dev.yml
cat > src/main/resources/application-dev.yml << 'EOF'
spring:
  jpa:
    show-sql: true
    hibernate:
      ddl-auto: update
  
  logging:
    level:
      com.example: DEBUG
      org.springframework.web: DEBUG
EOF

# Create application-prod.yml
cat > src/main/resources/application-prod.yml << 'EOF'
spring:
  jpa:
    show-sql: false
    hibernate:
      ddl-auto: validate
  
  logging:
    level:
      com.example: INFO
      org.springframework.web: WARN
EOF
```

### Development Setup
```bash
# 1. Set environment variables
export JWT_SECRET=your-jwt-secret-key
export DB_USER=postgres
export DB_PASSWORD=password

# 2. Run tests
mvn test

# 3. Build project
mvn clean compile

# 4. Run application
mvn spring-boot:run

# 5. Build JAR for production
mvn clean package
java -jar target/[PROJECT_NAME]-1.0.0.jar
```

---

## 🦀 Rust Setup

### Prerequisites
```bash
# Check Rust version (requires 1.70+)
rustc --version

# Install rustup (if not present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Project Setup
```bash
# 1. Create new project
cargo new [PROJECT_NAME] --bin
cd [PROJECT_NAME]

# 2. Create project structure
mkdir -p src/{config,auth,utils,models,services,handlers}
mkdir -p tests/{unit,integration}
mkdir -p migrations
```

### Configuration Files
```bash
# Update Cargo.toml
cat > Cargo.toml << 'EOF'
[package]
name = "[PROJECT_NAME]"
version = "1.0.0"
edition = "2021"

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
anyhow = "1.0"
uuid = { version = "1.0", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
dotenv = "0.15"

[dev-dependencies]
tokio-test = "0.4"
mockall = "0.11"

[[bin]]
name = "[PROJECT_NAME]"
path = "src/main.rs"
EOF

# Create .env template
cat > .env.example << 'EOF'
# Application Settings
APP_NAME=[PROJECT_NAME]
APP_VERSION=1.0.0
RUST_LOG=info
PORT=8080
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# JWT
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRES_IN=24h

# External Services
REDIS_URL=redis://localhost:6379
EOF

# Create justfile (task runner)
cat > justfile << 'EOF'
default: run

build:
    cargo build

run:
    cargo run

test:
    cargo test

test-coverage:
    cargo tarpaulin --out Html

lint:
    cargo clippy -- -D warnings

fmt:
    cargo fmt

clean:
    cargo clean

docker-build:
    docker build -t [PROJECT_NAME] .

docker-run:
    docker run -p 8080:8080 [PROJECT_NAME]
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM rust:1.70 as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/[PROJECT_NAME] /usr/local/bin/[PROJECT_NAME]

EXPOSE 8080
CMD ["[PROJECT_NAME]"]
EOF
```

### Development Setup
```bash
# 1. Install just (task runner)
cargo install just

# 2. Copy environment file
cp .env.example .env

# 3. Edit .env with your configuration
nano .env

# 4. Run tests
just test

# 5. Start development server
just run
```

---

## 🫧 C# Setup

### Prerequisites
```bash
# Check .NET version (requires 6.0+)
dotnet --version

# Install .NET (if not present)
# Ubuntu/Debian:
wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y dotnet-sdk-6.0
```

### Project Setup
```bash
# 1. Create new project
dotnet new webapi -n [PROJECT_NAME]
cd [PROJECT_NAME]

# 2. Create project structure
mkdir -p Config Auth Utils Models Services Controllers
mkdir -p Tests/{Unit,Integration}
```

### Configuration Files
```bash
# Install packages
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.AspNetCore.Authorization
dotnet add package FluentValidation
dotnet add package Serilog
dotnet add package Serilog.AspNetCore
dotnet add package Microsoft.Extensions.Http
dotnet add package BCrypt.Net-Next
dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL

# Create appsettings.Development.json
cat > appsettings.Development.json << 'EOF'
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=[PROJECT_NAME]_dev;Username=postgres;Password=password"
  },
  "JwtSettings": {
    "Secret": "your-jwt-secret-key",
    "Issuer": "[PROJECT_NAME]",
    "Audience": "[PROJECT_NAME]",
    "ExpirationMinutes": 60
  }
}
EOF

# Create appsettings.Production.json
cat > appsettings.Production.json << 'EOF'
{
  "Logging": {
    "LogLevel": {
      "Default": "Warning",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "ConnectionStrings": {
    "DefaultConnection": "${DATABASE_URL}"
  },
  "JwtSettings": {
    "Secret": "${JWT_SECRET}",
    "Issuer": "[PROJECT_NAME]",
    "Audience": "[PROJECT_NAME]",
    "ExpirationMinutes": 1440
  }
}
EOF
```

### Development Setup
```bash
# 1. Run tests
dotnet test

# 2. Build project
dotnet build

# 3. Run application
dotnet run

# 4. Build for production
dotnet publish -c Release -o publish
```

---

## 💎 Ruby Setup

### Prerequisites
```bash
# Check Ruby version (requires 3.0+)
ruby --version

# Install Rails (if not present)
gem install rails
```

### Project Setup
```bash
# 1. Create new Rails API project
rails new [PROJECT_NAME] --api --database=postgresql
cd [PROJECT_NAME]

# 2. Add gems to Gemfile
cat >> Gemfile << 'EOF'
gem 'jwt'
gem 'bcrypt'
gem 'dry-validation'
gem 'httparty'
gem 'lograge'
gem 'dotenv-rails'
gem 'rack-cors'

group :development, :test do
  gem 'rspec-rails'
  gem 'factory_bot_rails'
  gem 'faker'
end
EOF

# 3. Install gems
bundle install

# 4. Generate RSpec
rails generate rspec:install
```

### Development Setup
```bash
# 1. Create database
rails db:create

# 2. Run migrations
rails db:migrate

# 3. Run tests
bundle exec rspec

# 4. Start development server
rails server
```

---

## 🐘 PHP Setup

### Prerequisites
```bash
# Check PHP version (requires 8.0+)
php --version

# Install Composer (if not present)
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer
```

### Project Setup
```bash
# 1. Create new Laravel project
composer create-project laravel/laravel [PROJECT_NAME]
cd [PROJECT_NAME]

# 2. Install packages
composer require firebase/php-jwt
composer require bcrypt
composer require respect/validation
composer require guzzlehttp/guzzle
composer require monolog/monolog
```

### Development Setup
```bash
# 1. Create environment file
cp .env.example .env

# 2. Generate application key
php artisan key:generate

# 3. Create database
php artisan migrate

# 4. Run tests
php artisan test

# 5. Start development server
php artisan serve
```

---

## 🔧 Common Development Tasks

### Environment Management
```bash
# Copy environment template
cp .env.example .env

# Generate secrets
# Python:
python -c "import secrets; print(secrets.token_urlsafe(32))"
# Node.js:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Go:
go run -c 'package main; import ("crypto/rand"; "encoding/hex"; "fmt"); func main() { b := make([]byte, 32); rand.Read(b); fmt.Println(hex.EncodeToString(b)) }'
```

### Database Setup
```bash
# PostgreSQL
createdb [PROJECT_NAME]_dev
createdb [PROJECT_NAME]_test

# MySQL
mysql -u root -e "CREATE DATABASE [PROJECT_NAME]_dev;"
mysql -u root -e "CREATE DATABASE [PROJECT_NAME]_test;"
```

### Testing Commands
```bash
# Python
pytest --cov=src --cov-report=html

# Node.js
npm test -- --coverage

# Go
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Java
mvn test

# Rust
cargo test

# C#
dotnet test

# Ruby
bundle exec rspec

# PHP
php artisan test
```

### Code Quality
```bash
# Python
black src/
flake8 src/
mypy src/

# Node.js
npm run lint
npm run format

# Go
golangci-lint run
go fmt ./...

# Java
mvn checkstyle:check

# Rust
cargo clippy
cargo fmt

# C#
dotnet format

# Ruby
rubocop

# PHP
composer run-script lint
```

---

## 🐛 Troubleshooting

### Common Issues

1. **Port already in use**
   ```bash
   # Find process using port
   lsof -i :8000
   # Kill process
   kill -9 <PID>
   ```

2. **Database connection failed**
   - Check database server is running
   - Verify connection string in .env
   - Ensure database exists

3. **Module/package not found**
   ```bash
   # Python
   pip install -r requirements.txt
   # Node.js
   npm install
   # Go
   go mod download
   # Java
   mvn clean install
   ```

4. **Permission denied**
   ```bash
   # Fix file permissions
   chmod +x scripts/*.sh
   # or use sudo if necessary
   ```

### Getting Help

- Check the documentation in the `docs/` directory
- Review error messages for specific issues
- Search online for error messages
- Create GitHub issue for persistent problems

---

## ✅ Setup Verification

After completing setup, verify everything works:

1. **Environment variables** are set correctly
2. **Dependencies** are installed without errors
3. **Database** connection works
4. **Tests** pass successfully
5. **Development server** starts without errors
6. **API endpoints** respond correctly

Run the verification script for your stack:
```bash
# Python
python scripts/verify_setup.py

# Node.js
npm run verify

# Go
go run scripts/verify_setup.go

# Java
mvn exec:java -Dexec.mainClass="com.example.VerifySetup"
```

---

**Generic Setup Guide**  
**Adaptable to any technology stack**  
**Version**: 1.0  
**Last Updated**: [DATE]

---

*Select your technology stack and follow the specific setup instructions above.*
