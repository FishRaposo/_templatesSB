# Gitignore Examples

**Purpose**: Comprehensive .gitignore examples for different technology stacks and project types  
**Version**: 2.0  
**AI Integration**: AI automatically generates and manages .gitignore for project privacy

---

## 🎯 How to Use This Template

### **For AI Assistants:**
```
When creating a new project:
1. Analyze tech stack and project structure
2. Generate appropriate .gitignore using examples below
3. Add _templates/ to .gitignore automatically
4. Include security-sensitive patterns
5. Verify .gitignore covers all necessary files
```

### **For Human Developers:**
1. **Use as reference** for your project's .gitignore
2. **Copy relevant sections** for your tech stack
3. **Customize** for your specific needs
4. **Review regularly** for security-sensitive files

---

## 📂 Gitignore Structure

```bash
# Template collection privacy (mandatory)
_templates/

# OS files
.DS_Store
Thumbs.db

# IDE/Editor files
.idea/
.vscode/
*.swp
*.swo

# Dependencies
node_modules/
venv/
__pycache__/

# Build outputs
dist/
build/
*.class
*.pyc

# Environment files
.env
.env.local
.secrets/

# Logs
*.log
logs/

# Database files
*.sqlite
*.db
```

---

## 🤖 AI-Managed Gitignore Patterns

### **Mandatory for Template Privacy**
```bash
# Universal Documentation Templates - Private Use
# This folder contains personal best-practice templates
# Not intended for public repositories - use for scaffolding only
_templates/

# Exclude all template files from version control
# They contain personal/best-practice patterns for project scaffolding
ai-templates/
.project-setup/
.template-cache/
```

### **For AI-Agent Projects**
```bash
# AI agent configuration files (personal to each developer)
.ai-agent-config/
.ai-quickstart-temp/

# AI-generated temporary files
*.ai-generated
.ai-cache/
```

---

## 💻 Technology-Specific Examples

### **Node.js/TypeScript Projects**

```bash
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.*.local

# Build outputs
dist/
build/
out/

# TypeScript
*.tsbuildinfo

# Testing
coverage/
.nyc_output/

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/
```

### **Python Projects**

```bash
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/
.nox/

# Environment
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Build
dist/
build/
*.egg-info/
```

### **Flutter/Dart Projects**

```bash
# Flutter
build/
.dart_tool/
.flutter-plugins
.flutter-plugins-dependencies
.pub-cache/
.pub/

# Dart
*.dart.js
*.js_
*.js.deps
*.js.map

# IDE
.idea/
.vscode/

# OS
.DS_Store
Thumbs.db

# Testing
coverage/
```

### **React/TypeScript Projects**

```bash
# Dependencies
node_modules/
.pnp
.pnp.js

# Testing
coverage/

# Production builds
build/
dist/
out/

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db

# Logs
npm-debug.log*
yarn-debug.log*
yarn-error.log*
```

### **.NET/C# Projects**

```bash
# .NET
bin/
obj/
out/

# User-specific files
*.user
*.userosscache
*.suo
*.userprefs

# Mono auto generated files
mono_crash.*

# Build results
[Dd]ebug/
[Dd]ebugPublic/
[Rr]elease/
[Rr]eleases/
x64/
x86/
[Ww][Ii][Nn]32/
[Aa][Rr][Mm]/
[Aa][Rr][Mm]64/
bld/
[Bb]in/
[Oo]bj/
[Ll]og/
[Ll]ogs/

# IDE
.vs/
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db
```

### **Java/Spring Boot Projects**

```bash
# Java
target/
!.mvn/wrapper/maven-wrapper.jar
!**/src/main/**/target/
!**/src/test/**/target/

# Maven
pom.xml.tag
pom.xml.releaseBackup
pom.xml.versionsBackup
pom.xml.next
release.properties
dependency-reduced-pom.xml
buildNumber.properties

# IDE
.vscode/
.idea/
*.iml
*.ipr
*.iws

# OS
.DS_Store
Thumbs.db
```

### **Go Projects**

```bash
# Binaries for programs and plugins
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary, built with `go test -c`
*.test

# Output of the go coverage tool
*.out

# Dependency directories
vendor/

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db
```

### **Ruby/Rails Projects**

```bash
# Ruby
*.gem
*.rbc
/.config
/coverage/
/InstalledFiles
/pkg/
/spec/reports/
/spec/examples.txt
/test/tmp/
/test/version_tmp/
/tmp/

# Rails
/log/*
/tmp/*
!/log/.keep
!/tmp/.keep

# Environment
.env
.env.local

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db
```

---

## 🔒 Security-Sensitive Files

### **Always Exclude (All Projects)**
```bash
# Environment variables
.env
.env.local
.env.*.local
.envrc

# Secrets
.secrets/
*.secret
*.key
*.pem
*.crt
*.p12
*.pfx

# AWS credentials
.aws/
.aws/credentials
.aws/config

# Google Cloud credentials
gcloud/
gcp-key.json

# SSH keys
.ssh/
*.pem
*.key

# Database credentials
*.db.credentials
*.database.config

# API keys
api-keys.json
config/secrets.json
```

### **Credentials in Any Format**
```bash
# Any file containing "key", "secret", "credential", "password", "token"
# AI should detect and add patterns for these
*key*
*secret*
*credential*
*password*
*token*
!template.key.example
```

---

## 📋 Language-Specific Files

### **Python**
```bash
# Virtual environments
venv/
env/
ENV/

# Python cache
__pycache__/
*.py[cod]
*$py.class

# Testing
.coverage
htmlcov/
.pytest_cache/

# Build artifacts
/dist/
/build/
*.egg-info/
```

### **JavaScript/TypeScript**
```bash
# Dependencies
node_modules/

# Build outputs
dist/
build/
out/

# TypeScript
*.tsbuildinfo

# Testing
coverage/
.nyc_output/

# Environment
.env*
```

### **Java**
```bash
# Maven/Gradle
target/
build/

# IDE
.idea/
*.iml
*.ipr
*.iws

# Compiled classes
*.class
```

### **Dart/Flutter**
```bash
# Flutter
build/
.dart_tool/
.flutter-plugins

# Dart
*.dart.js
*.js_
*.js.deps
*.js.map
```

### **C/C++**
```bash
# Compiled files
*.o
*.out
*.exe
*.so
*.dylib
*.a

# Build directories
build/
cmake-build-*/
```

---

## 🧪 AI-Specific Files

```bash
# AI agent configuration (personal to each developer)
.ai-agent-config/
.ai-quickstart-temp/

# AI-generated temporary files
*.ai-generated
.ai-cache/
.ai-patterns/

# Template cache
.template-cache/
```

---

## 📁 Project-Specific Patterns

### **Monorepo Projects**
```bash
# Root level
/node_modules/
/coverage/
/dist/

# Individual packages
/packages/*/node_modules/
/packages/*/dist/
/packages/*/coverage/
```

### **Microservices**
```bash
# Each service
/service-*/node_modules/
/service-*/dist/
/service-*/coverage/

# Shared libraries
/common/*/node_modules/
/common/*/dist/
```

### **Library/SDK Projects**
```bash
# Build outputs
lib/
dist/
build/

# Examples (often committed)
!examples/
!example/

# Documentation (often committed)
!docs/
!doc/
```

---

## 🛡️ Security Best Practices

### **Never Commit:**
- API keys
- Database credentials
- AWS/GCP/Azure credentials
- Private SSH keys
- SSL certificates
- Environment variables with secrets
- Passwords or tokens
- Database connection strings

### **AI Command for Security:**
```
"Analyze this project for security-sensitive files and add them to .gitignore automatically"
```

---

## 🤖 AI Generation Command

**When creating new project:**
```
"Generate appropriate .gitignore for [TECH_STACK] project
1. Include all technology-specific patterns
2. Add AI-managed patterns for _templates/
3. Include security-sensitive patterns
4. Add OS and IDE files
5. Verify coverage"
```

**Example Output:**
```bash
# Generated .gitignore for React/Node.js project

# Dependencies
node_modules/

# Build
build/
dist/

# Environment
.env
.env.local

# AI Templates (private)
_templates/
.ai-agent-config/

# Security
.envrc
.secrets/

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db

# Testing
coverage/
.nyc_output/
```

---

## 🐛 Common Mistakes to Avoid

### **❌ DON'T:**
```bash
# Don't commit these
credentials.json
config/secrets.js
.env.production
key.pem
password.txt
```

### **✅ DO:**
```bash
# Do commit these examples
!credentials.example.json
!config/secrets.example.js
!env.example
```

---

## 📞 Support & Reference

**When in doubt:**
1. Use examples from same tech stack
2. Include OS and IDE files
3. Always exclude environment files
4. Never commit credentials/secrets
5. Add `_templates/` for privacy

---

**Template Status**: ✅ Production Ready  
**AI Integration**: 🤖 AI automatically generates and manages  
**Security**: 🔒 Privacy-first, security-sensitive patterns included  
**Best Practices**: ✅ Technology-specific, comprehensive, battle-tested

---

*This .gitignore template provides comprehensive patterns for all major tech stacks, with AI automation for security and privacy management.*