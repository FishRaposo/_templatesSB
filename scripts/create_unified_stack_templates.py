#!/usr/bin/env python3
"""
Create Unified Stack Templates Script
Generates comprehensive README.md files for each stack that combine
universal templates with stack-specific implementations

Usage: python scripts/create_unified_stack_templates.py
"""

import os
from pathlib import Path
from typing import Dict, List

# Stack configurations with stack-specific information
STACK_CONFIGS = {
    'python': {
        'name': 'Python',
        'description': 'Python development with FastAPI, Django, and data science frameworks',
        'key_features': [
            'FastAPI & Django web frameworks',
            'Data science with pandas, numpy, scikit-learn',
            'Async/await support with asyncio',
            'Comprehensive testing with pytest',
            'Package management with pip/poetry',
            'Type hints and modern Python features'
        ],
        'core_tech': ['Python 3.9+', 'FastAPI', 'Django', 'pytest', 'pandas'],
        'resources': {
            'handbook': 'https://docs.python.org/3/',
            'fastapi': 'https://fastapi.tiangolo.com/',
            'django': 'https://docs.djangoproject.com/',
            'pytest': 'https://docs.pytest.org/'
        }
    },
    'node': {
        'name': 'Node.js',
        'description': 'JavaScript runtime with Express, npm, and modern ES features',
        'key_features': [
            'Express.js web framework',
            'Modern ES2020+ JavaScript features',
            'npm/yarn package management',
            'Async/await and Promise patterns',
            'Rich ecosystem with 1M+ packages',
            'Jest testing framework'
        ],
        'core_tech': ['Node.js 18+', 'Express.js', 'npm', 'Jest', 'ES2020+'],
        'resources': {
            'handbook': 'https://nodejs.org/docs/',
            'express': 'https://expressjs.com/',
            'npm': 'https://docs.npmjs.com/',
            'jest': 'https://jestjs.io/docs/getting-started'
        }
    },
    'go': {
        'name': 'Go',
        'description': 'High-performance systems programming with Go',
        'key_features': [
            'High-performance compiled language',
            'Built-in concurrency with goroutines',
            'Simple deployment with single binary',
            'Rich standard library',
            'Gin, Echo, and Fiber web frameworks',
            'Built-in testing and benchmarking'
        ],
        'core_tech': ['Go 1.19+', 'Gin', 'Echo', 'standard library', 'go modules'],
        'resources': {
            'handbook': 'https://golang.org/doc/',
            'gin': 'https://gin-gonic.com/docs/',
            'echo': 'https://echo.labstack.com/guide/',
            'modules': 'https://go.dev/blog/using-go-modules'
        }
    },
    'flutter': {
        'name': 'Flutter',
        'description': 'Cross-platform mobile development with Flutter and Dart',
        'key_features': [
            'Cross-platform iOS/Android apps',
            'Hot reload for fast development',
            'Rich widget library and Material Design',
            'Dart language with modern features',
            'State management solutions',
            'Comprehensive testing framework'
        ],
        'core_tech': ['Flutter SDK', 'Dart 2.19+', 'Material Design', 'Android Studio', 'VS Code'],
        'resources': {
            'handbook': 'https://flutter.dev/docs',
            'dart': 'https://dart.dev/guides',
            'widgets': 'https://flutter.dev/docs/development/ui/widgets',
            'testing': 'https://flutter.dev/docs/testing'
        }
    },
    'react': {
        'name': 'React',
        'description': 'Modern frontend development with React and JavaScript/TypeScript',
        'key_features': [
            'Component-based architecture',
            'Virtual DOM for performance',
            'Rich ecosystem with React Router, Redux',
            'Modern hooks and context API',
            'Create React App scaffolding',
            'Comprehensive testing with Jest/React Testing Library'
        ],
        'core_tech': ['React 18+', 'JavaScript/TypeScript', 'npm/yarn', 'Jest', 'React Router'],
        'resources': {
            'handbook': 'https://react.dev/',
            'tutorial': 'https://react.dev/learn',
            'api': 'https://react.dev/reference/react',
            'testing': 'https://testing-library.com/docs/react-testing-library/intro/'
        }
    },
    'react_native': {
        'name': 'React Native',
        'description': 'Cross-platform mobile apps with React Native',
        'key_features': [
            'Cross-platform iOS/Android development',
            'Native performance with JavaScript',
            'Rich component library',
            'Hot reloading and fast refresh',
            'Expo for simplified development',
            'Comprehensive testing with Jest'
        ],
        'core_tech': ['React Native', 'Expo', 'JavaScript/TypeScript', 'Metro bundler', 'Jest'],
        'resources': {
            'handbook': 'https://reactnative.dev/docs/getting-started',
            'expo': 'https://docs.expo.dev/',
            'components': 'https://reactnative.dev/docs/components-and-apis',
            'testing': 'https://reactnative.dev/docs/testing-overview'
        }
    },
    'next': {
        'name': 'Next.js',
        'description': 'Full-stack React framework with server-side rendering',
        'key_features': [
            'Server-side rendering (SSR) and static generation',
            'API routes for backend functionality',
            'Automatic code splitting and optimization',
            'Image and font optimization',
            'Built-in CSS and Sass support',
            'Comprehensive deployment options'
        ],
        'core_tech': ['Next.js 13+', 'React 18+', 'Vercel', 'TypeScript', 'Tailwind CSS'],
        'resources': {
            'handbook': 'https://nextjs.org/docs',
            'tutorial': 'https://nextjs.org/learn',
            'api': 'https://nextjs.org/docs/api-reference',
            'deployment': 'https://nextjs.org/docs/deployment'
        }
    },
    'sql': {
        'name': 'SQL',
        'description': 'Database schemas, migrations, and SQL patterns',
        'key_features': [
            'Database-agnostic SQL patterns',
            'Schema design and normalization',
            'Migration management',
            'Query optimization patterns',
            'Multi-database compatibility',
            'Data validation and constraints'
        ],
        'core_tech': ['SQL', 'PostgreSQL', 'MySQL', 'SQLite', 'migration tools'],
        'resources': {
            'handbook': 'https://www.w3schools.com/sql/',
            'postgres': 'https://www.postgresql.org/docs/',
            'mysql': 'https://dev.mysql.com/doc/',
            'design': 'https://www.databasestar.com/database-normalization/'
        }
    },
    'r': {
        'name': 'R',
        'description': 'Statistical computing and data analysis with R',
        'key_features': [
            'Statistical analysis and modeling',
            'Data visualization with ggplot2',
            'Tidyverse ecosystem',
            'R Markdown for reproducible research',
            'Package management with CRAN',
            'Comprehensive testing with testthat'
        ],
        'core_tech': ['R 4.2+', 'Tidyverse', 'RStudio', 'ggplot2', 'testthat'],
        'resources': {
            'handbook': 'https://www.r-project.org/manuals.html',
            'tidyverse': 'https://www.tidyverse.org/',
            'ggplot2': 'https://ggplot2.tidyverse.org/',
            'rmarkdown': 'https://rmarkdown.rstudio.com/'
        }
    },
    'generic': {
        'name': 'Generic',
        'description': 'Technology-agnostic templates adaptable to any stack',
        'key_features': [
            'Technology-agnostic patterns',
            'Adaptable to any language/framework',
            'Universal best practices',
            'Flexible project structure',
            'Stack-independent documentation',
            'Customizable scaffolding'
        ],
        'core_tech': ['Technology-agnostic', 'Universal patterns', 'Adaptable frameworks'],
        'resources': {
            'handbook': 'https://en.wikipedia.org/wiki/Software_development',
            'patterns': 'https://refactoring.guru/design-patterns',
            'architecture': 'https://12factor.net/',
            'best-practices': 'https://google.github.io/styleguide/'
        }
    },
    'typescript': {
        'name': 'TypeScript',
        'description': 'JavaScript with static typing and enhanced tooling',
        'key_features': [
            'Static typing and compile-time error checking',
            'Modern JavaScript features with ES2020+',
            'Enhanced IDE support and autocompletion',
            'Framework support (Express, NestJS, React)',
            'Interfaces, generics, and decorators',
            'Comprehensive testing with Jest'
        ],
        'core_tech': ['TypeScript 4.9+', 'Node.js 18+', 'Express.js', 'Jest', 'ESLint'],
        'resources': {
            'handbook': 'https://www.typescriptlang.org/docs/',
            'express': 'https://expressjs.com/en/guide/',
            'jest': 'https://jestjs.io/docs/getting-started',
            'nest': 'https://docs.nestjs.com/'
        }
    }
}

def generate_stack_readme(stack_key: str, config: Dict) -> str:
    """Generate comprehensive README.md for a specific stack"""
    
    # Generate key features list
    features_list = '\n'.join([f"- {feature}" for feature in config['key_features']])
    
    # Generate core tech list
    tech_list = ', '.join(config['core_tech'])
    
    # Generate resources table
    resources_table = '\n'.join([
        f"| {key.title()} | [📗 {value.split('//')[1].split('/')[0]}]({value}) |"
        for key, value in config['resources'].items()
    ])
    
    return f"""# {config['name']} Stack - Complete Documentation & Templates

> **Comprehensive {config['name']} Development Stack** - Universal patterns + {config['name']}-specific implementations
> 
> **Last Updated**: 2025-12-10 | **Status**: ✅ Production Ready | **Version**: 3.0

---

## 🎯 Stack Overview

The {config['name']} stack provides a complete foundation for building {config['description'].lower()}. This folder contains **all templates, documentation, code samples, tests, and scaffolding** needed for {config['name']} development, combining universal development patterns with {config['name']}-specific implementations.

### 🚀 Key Features

{features_list}

---

## 📚 Complete Documentation Library

### **Universal Development Patterns** *(System-Wide Best Practices)*
> 📖 Located in `../../../universal/docs/` - These apply to ALL technology stacks

| Template | Purpose | Link |
|----------|---------|------|
| **QUICKSTART-AI** | AI-powered project initialization and setup | [📄 View](../../../universal/docs/QUICKSTART-AI.tpl.md) |
| **SYSTEM-MAP** | Complete system architecture and navigation | [📄 View](../../../universal/docs/SYSTEM-MAP.md) |
| **SYSTEM-INTEGRATION** | Integration patterns and utilities | [📄 View](../../../universal/docs/SYSTEM-INTEGRATION.tpl.md) |
| **VALIDATION** | Quality gates and validation protocols | [📄 View](../../../universal/docs/VALIDATION.tpl.md) |
| **MIGRATION-GUIDE** | Upgrade procedures and migration paths | [📄 View](../../../universal/docs/MIGRATION-GUIDE.tpl.md) |
| **TIERED-TEMPLATES** | Tier selection and progression guidelines | [📄 View](../../../universal/docs/TIERED-TEMPLATES.tpl.md) |
| **TEMPLATE-BEST-PRACTICES** | Development standards and conventions | [📄 View](../../../universal/docs/TEMPLATE-BEST-PRACTICES.tpl.md) |
| **FEATURES** | System capabilities and feature overview | [📄 View](../../../universal/docs/FEATURES.tpl.md) |
| **AI-GUIDE** | AI/LLM integration patterns | [📄 View](../../../universal/docs/AI-GUIDE.tpl.md) |
| **AGENT-GUIDE** | AI agent development guidelines | [📄 View](../../../universal/docs/AGENT-GUIDE.tpl.md) |
| **DOCUMENTATION-BLUEPRINT** | Documentation structure and standards | [📄 View](../../../universal/docs/DOCUMENTATION-BLUEPRINT.tpl.md) |
| **EXECUTION-ENGINE** | Build and deployment automation | [📄 View](../../../universal/docs/EXECUTION-ENGINE.tpl.md) |

### **{config['name']}-Specific Documentation** *(This Stack Only)*
> 🔧 {config['name']} implementations, patterns, and examples

| Template | Purpose | Location |
|----------|---------|----------|
| **{config['name']} README** | {config['name']} stack overview and setup | [📄 View](base/docs/README.tpl.md) |
| **Setup Guide** | Detailed {config['name']} environment configuration | [📄 View](base/docs/setup-guide.tpl.md) |

---

## 🛠️ Code Templates & Patterns

### **Universal Code Templates** *(System-Wide Patterns)*
> 📖 Located in `../../../universal/code/` - Adaptable patterns for any stack

| Template | Purpose | Link |
|----------|---------|------|
| **Backend Module** | Universal backend service structure | [📄 View](../../../universal/code/MODULE-TEMPLATE-BACKEND.tpl.md) |
| **Frontend Module** | Universal frontend component structure | [📄 View](../../../universal/code/MODULE-TEMPLATE-FRONTEND.tpl.md) |
| **Git Ignore** | Version control ignore patterns | [📄 View](../../../universal/code/.gitignore.tpl) |

### **{config['name']}-Specific Code Patterns** *(This Stack Only)*
> 🔧 {config['name']} implementations with best practices and optimizations

| Pattern | Purpose | Key Features | Location |
|---------|---------|--------------|----------|
| **Config Management** | Configuration management and validation | Type-safe configs, environment variables | [📄 View](base/code/config-management-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}) |
| **Error Handling** | Custom error classes and middleware | Structured errors, logging, recovery | [📄 View](base/code/error-handling-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}) |
| **HTTP Client** | HTTP client with retry and caching | Type-safe requests, interceptors | [📄 View](base/code/http-client-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}) |
| **Logging Utilities** | Structured logging framework | Multiple transports, log levels | [📄 View](base/code/logging-utilities-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}) |
| **Authentication** | Authentication and authorization | JWT, OAuth, security patterns | [📄 View](base/code/authentication-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}) |
| **Data Validation** | Data validation and schema management | Input validation, type safety | [📄 View](base/code/data-validation-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}) |

---

## 🧪 Testing Templates & Utilities

### **{config['name']} Testing Patterns** *(This Stack Only)*
> 🧪 Comprehensive testing frameworks and utilities

| Pattern | Purpose | Key Features | Location |
|---------|---------|--------------|----------|
| **Unit Tests** | Unit testing framework and patterns | Mock factories, test utilities | [📄 View](base/tests/unit-tests-pattern.tpl.md) |
| **Integration Tests** | API and integration testing | Test data management, fixtures | [📄 View](base/tests/integration-tests-pattern.tpl.md) |
| **Test Utilities** | Testing helpers and utilities | Custom matchers, test factories | [📄 View](base/tests/test-utilities-pattern.tpl.md) |

---

## 🏗️ Project Scaffolding

### **Dependencies & Configuration**
> 📦 Complete package management and tooling setup

| File | Purpose | Key Features | Location |
|------|---------|--------------|----------|
| **Dependencies** | Complete package management and configs | {tech_list} | [📄 View](dependencies.txt.tpl) |

### **Quick Project Setup**
```bash
# 1. Create new {config['name']} project
mkdir my-{stack_key}-app && cd my-{stack_key}-app

# 2. Copy dependencies template
cp [path-to-this-stack]/dependencies.txt.tpl ./package.json
npm install  # or appropriate package manager

# 3. Copy configuration files
cp [path-to-this-stack]/base/docs/setup-guide.tpl.md ./SETUP.md

# 4. Follow the setup guide for complete project initialization
```

---

## 📁 Complete Stack Structure

```
stacks/{stack_key}/                        # 🔧 THIS STACK FOLDER (Self-Contained)
├── README.md                              # 📖 This file - Complete documentation index
├── dependencies.txt.tpl                   # 📦 Package management and tooling configs
│
├── 📚 UNIVERSAL TEMPLATES (References)    # 📖 System-wide patterns and documentation
│   └── → ../../../universal/docs/         # 🔗 Links to universal documentation
│   └── → ../../../universal/code/         # 🔗 Links to universal code templates
│
├── 🔧 {config['name']}-SPECIFIC TEMPLATES # 🎯 {config['name']} implementations
│   └── base/
│       ├── docs/                          # 📖 {config['name']} documentation
│       │   ├── README.tpl.md              # {config['name']} stack overview
│       │   └── setup-guide.tpl.md         # {config['name']} environment setup
│       ├── code/                          # 💻 {config['name']} code patterns
│       │   ├── config-management-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}
│       │   ├── error-handling-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}
│       │   ├── http-client-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}
│       │   ├── logging-utilities-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}
│       │   ├── authentication-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}
│       │   └── data-validation-pattern.tpl.{'ts' if stack_key == 'typescript' else 'py' if stack_key == 'python' else 'js' if stack_key in ['node', 'react', 'react_native', 'next'] else 'go' if stack_key == 'go' else 'dart' if stack_key == 'flutter' else 'sql' if stack_key == 'sql' else 'r' if stack_key == 'r' else 'md'}
│       └── tests/                         # 🧪 {config['name']} testing patterns
│           ├── unit-tests-pattern.tpl.md
│           ├── integration-tests-pattern.tpl.md
│           └── test-utilities-pattern.tpl.md
```

---

## 🚀 Getting Started

### **For New {config['name']} Projects**
1. **Read Universal Patterns**: Start with `../../../universal/docs/QUICKSTART-AI.tpl.md`
2. **Configure Environment**: Follow `base/docs/setup-guide.tpl.md`
3. **Copy Code Patterns**: Use templates from `base/code/` directory
4. **Set Up Testing**: Implement patterns from `base/tests/` directory

### **For Existing Projects**
1. **Reference Universal Docs**: Check `../../../universal/docs/` for best practices
2. **Add {config['name']} Patterns**: Implement specific patterns from `base/code/`
3. **Enhance Testing**: Add {config['name']} testing utilities from `base/tests/`

---

## 🎯 Development Workflow

### **1. Project Planning**
- Use universal templates from `../../../universal/docs/` for architecture
- Reference {config['name']}-specific patterns for implementation details

### **2. Implementation**
- Combine universal patterns with {config['name']}-specific code templates
- Follow {config['name']} setup guide for environment configuration

### **3. Testing & Quality**
- Use {config['name']} testing patterns for comprehensive test coverage
- Apply universal validation patterns from `../../../universal/docs/VALIDATION.tpl.md`

### **4. Documentation**
- Follow universal documentation standards from `../../../universal/docs/DOCUMENTATION-BLUEPRINT.tpl.md`
- Include {config['name']}-specific setup and configuration details

---

## 🔗 Related Resources

### **System Documentation**
- [📖 Universal Documentation Index](../../../universal/docs/)
- [🗺️ System Architecture Map](../../../universal/docs/SYSTEM-MAP.md)
- [⚡ Quick Start Guide](../../../universal/docs/QUICKSTART-AI.tpl.md)

### **{config['name']} Resources**
{resources_table}

### **Template System**
- [📋 Task Templates](../../../tasks/) - 46 production tasks
- [🏗️ Tier Templates](../../../tiers/) - MVP/Core/Enterprise patterns
- [🧪 Validation Tools](../../../tests/validation/) - Quality assurance

---

## 📞 Support & Contributing

### **Getting Help**
- 📖 **Universal Issues**: Check `../../../universal/docs/` for system-wide patterns
- 🔧 **{config['name']} Issues**: Reference `base/docs/setup-guide.tpl.md` for configuration
- 🗺️ **System Navigation**: Use `SYSTEM-MAP.md` for complete system overview

### **Contributing**
1. **Universal Changes**: Modify templates in `../../../universal/`
2. **{config['name']} Changes**: Update templates in `base/` directory
3. **Documentation**: Update this README.md with new patterns and links

---

**{config['name']} Stack Template v3.0**  
*Part of the Universal Template System - 12 Technology Stacks*  
*Last Updated: 2025-12-10 | Status: ✅ Production Ready*
"""

def main():
    """Generate unified stack README files for all stacks"""
    
    print("🏗️  Creating Unified Stack Templates")
    print("=" * 50)
    
    stacks_dir = Path(__file__).parent.parent / 'stacks'
    
    for stack_key, config in STACK_CONFIGS.items():
        stack_dir = stacks_dir / stack_key
        
        # Skip if stack directory doesn't exist
        if not stack_dir.exists():
            print(f"⚠️  Skipping {stack_key} - directory not found")
            continue
        
        # Generate README content
        readme_content = generate_stack_readme(stack_key, config)
        
        # Write README file
        readme_path = stack_dir / 'README.md'
        
        # Skip TypeScript since we already created it
        if stack_key == 'typescript' and readme_path.exists():
            print(f"✅ Skipping {stack_key} - already exists")
            continue
        
        try:
            readme_path.write_text(readme_content, encoding='utf-8')
            print(f"✅ Created {stack_key} stack README")
        except Exception as e:
            print(f"❌ Failed to create {stack_key} README: {e}")
    
    print(f"\n✅ Unified stack templates created!")
    print(f"📁 Location: {stacks_dir.absolute()}")

if __name__ == "__main__":
    main()
