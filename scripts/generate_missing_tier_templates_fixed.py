#!/usr/bin/env python3
"""
Generate missing tier templates for the 4 new technology stacks
Creates tier-specific templates for react_native, next, r, and sql across MVP, Core, and Enterprise tiers
"""

import os
from pathlib import Path
from typing import Dict, List

# Stack configurations with file extensions and patterns
STACK_CONFIGS = {
    'react_native': {
        'extension': '.jsx',
        'language': 'React Native',
        'setup_command': 'npx react-native init',
        'test_command': 'npm test',
        'package_manager': 'npm',
        'platform': 'mobile'
    },
    'next': {
        'extension': '.jsx',
        'language': 'Next.js',
        'setup_command': 'npx create-next-app',
        'test_command': 'npm test',
        'package_manager': 'npm',
        'platform': 'web'
    },
    'r': {
        'extension': '.R',
        'language': 'R',
        'setup_command': 'Rscript',
        'test_command': 'Rscript -e "testthat::test_dir()"',
        'package_manager': 'R',
        'platform': 'data'
    },
    'sql': {
        'extension': '.sql',
        'language': 'SQL',
        'setup_command': 'psql',
        'test_command': 'psql -f test.sql',
        'package_manager': 'database',
        'platform': 'database'
    }
}

# Tier configurations
TIER_CONFIGS = {
    'mvp': {
        'prefix': 'minimal',
        'boilerplate_type': 'minimal-boilerplate',
        'test_type': 'basic-tests',
        'focus': 'rapid prototyping with essential features',
        'complexity': 'simple'
    },
    'core': {
        'prefix': 'production',
        'boilerplate_type': 'production-boilerplate',
        'test_type': 'comprehensive-tests',
        'focus': 'production-ready with comprehensive features',
        'complexity': 'moderate'
    },
    'enterprise': {
        'prefix': 'enterprise',
        'boilerplate_type': 'enterprise-boilerplate',
        'test_type': 'enterprise-tests',
        'focus': 'enterprise-grade with advanced security and scalability',
        'complexity': 'advanced'
    }
}

class TierTemplateGenerator:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.tiers_dir = base_dir / 'tiers'
        
    def create_directory_structure(self):
        """Ensure all tier directories exist"""
        for tier_name in TIER_CONFIGS.keys():
            tier_dir = self.tiers_dir / tier_name
            for subdir in ['code', 'docs', 'examples', 'tests']:
                (tier_dir / subdir).mkdir(parents=True, exist_ok=True)
    
    def generate_code_template(self, stack: str, tier: str) -> str:
        """Generate tier-specific code template"""
        config = STACK_CONFIGS[stack]
        tier_config = TIER_CONFIGS[tier]
        
        if stack == 'react_native':
            return self._generate_react_native_code_template(config, tier_config)
        elif stack == 'next':
            return self._generate_next_code_template(config, tier_config)
        elif stack == 'r':
            return self._generate_r_code_template(config, tier_config)
        elif stack == 'sql':
            return self._generate_sql_code_template(config, tier_config)
    
    def _generate_react_native_code_template(self, config: Dict, tier_config: Dict) -> str:
        """Generate React Native code template"""
        tier = tier_config['prefix'].title()
        
        # Use string concatenation to avoid f-string brace issues
        template_parts = [
            f"# {tier} Boilerplate Template ({tier.upper()} Tier - React Native)",
            "",
            "## Purpose",
            f"Provides {tier_config['focus']} for React Native projects following the {tier.lower()} approach.",
            "",
            "## Usage",
            f"This template should be used for:",
            f"- {tier.lower().replace('production', 'production mobile apps')}",
            f"- {tier.lower().replace('production', 'production cross-platform apps')}",
            f"- {tier.lower().replace('production', 'production enterprise mobile solutions')}",
            "",
            "## Structure",
            "```jsx",
            "import React from 'react';",
            "import {",
            "  View,",
            "  Text,",
            "  StyleSheet,",
            "  SafeAreaView,",
            "  StatusBar",
            "} from 'react-native';",
            "",
            "/**",
            f" * Main entry point for the {tier} React Native application",
            " * ",
            f" * This is the {tier.lower()} entry point that creates and runs the app.",
            f" * {tier.title()} approach: Keep it {'simple' if tier == 'Minimal' else 'robust' if tier == 'Production' else 'secure and scalable'}.",
            " */",
            f"const {tier.title()}App = () => {{",
            "  return (",
            "    <SafeAreaView style={styles.container}>",
            "      <StatusBar barStyle=\"dark-content\" />",
            "      <View style={styles.content}>",
            "        <Text style={styles.title}>",
            f"          {tier.title()} React Native App",
            "        </Text>",
            "        <Text style={styles.subtitle}>",
            f"          {tier_config['focus'].capitalize()}",
            "        </Text>",
            "      </View>",
            "    </SafeAreaView>",
            "  );",
            "};",
            "",
            "const styles = StyleSheet.create({",
            "  container: {",
            "    flex: 1,",
            "    backgroundColor: '#f5f5f5',",
            "  },",
            "  content: {",
            "    flex: 1,",
            "    justifyContent: 'center',",
            "    alignItems: 'center',",
            "    padding: 20,",
            "  },",
            "  title: {",
            "    fontSize: 24,",
            "    fontWeight: 'bold',",
            "    marginBottom: 10,",
            "    color: '#333',",
            "  },",
            "  subtitle: {",
            "    fontSize: 16,",
            "    color: '#666',",
            "    textAlign: 'center',",
            "  },",
            "});",
            "",
            f"export default {tier.title()}App;",
            "```",
            "",
            "## Features",
            f"- {tier.lower().replace('production', 'production-ready')} React Native structure",
            f"- {'Basic' if tier == 'Minimal' else 'Production' if tier == 'Production' else 'Enterprise'} navigation setup",
            f"- {'Simple' if tier == 'Minimal' else 'Comprehensive' if tier == 'Production' else 'Advanced'} styling",
            f"- {'Essential' if tier == 'Minimal' else 'Production' if tier == 'Production' else 'Enterprise'} error handling",
            ""
        ]
        
        return '\n'.join(template_parts)
    
    def _generate_next_code_template(self, config: Dict, tier_config: Dict) -> str:
        """Generate Next.js code template"""
        tier = tier_config['prefix'].title()
        
        template_parts = [
            f"# {tier} Boilerplate Template ({tier.upper()} Tier - Next.js)",
            "",
            "## Purpose",
            f"Provides {tier_config['focus']} for Next.js projects following the {tier.lower()} approach.",
            "",
            "## Usage",
            f"This template should be used for:",
            f"- {tier.lower().replace('production', 'production web applications')}",
            f"- {tier.lower().replace('production', 'production full-stack apps')}",
            f"- {tier.lower().replace('production', 'production enterprise web solutions')}",
            "",
            "## Structure",
            "```jsx",
            "import React from 'react';",
            "import Head from 'next/head';",
            "",
            "/**",
            f" * Main entry point for the {tier} Next.js application",
            " * ",
            f" * This is the {tier.lower()} entry point that creates and runs the app.",
            f" * {tier.title()} approach: Use {'minimal' if tier == 'Minimal' else 'production' if tier == 'Production' else 'enterprise'} configuration.",
            " */",
            f"export default function {tier.title()}App() {{",
            "  return (",
            "    <div>",
            "      <Head>",
            f"        <title>{tier.title()} Next.js App</title>",
            f"        <meta name=\"description\" content=\"{tier_config['focus']}\" />",
            "        <link rel=\"icon\" href=\"/favicon.ico\" />",
            "      </Head>",
            "",
            "      <main>",
            f"        <h1>{tier.title()} Next.js Application</h1>",
            f"        <p>{tier_config['focus'].capitalize()}</p>",
            "        <div>",
            "          <h2>Features</h2>",
            "          <ul>",
            f"            <li>{tier.title()} Next.js structure</li>",
            f"            <li>{'Basic' if tier == 'Minimal' else 'Production' if tier == 'Production' else 'Enterprise'} routing</li>",
            f"            <li>{'Simple' if tier == 'Minimal' else 'Comprehensive' if tier == 'Production' else 'Advanced'} styling</li>",
            f"            <li>{'Essential' if tier == 'Minimal' else 'Production' if tier == 'Production' else 'Enterprise'} error handling</li>",
            "          </ul>",
            "        </div>",
            "      </main>",
            "",
            "      <style jsx>{`",
            "        main {",
            "          padding: 2rem;",
            "          max-width: 800px;",
            "          margin: 0 auto;",
            "        }",
            "        h1 {",
            "          color: #0070f3;",
            "        }",
            "      `}</style>",
            "    </div>",
            "  );",
            "}",
            "```",
            "",
            "## Features",
            f"- {tier.lower().replace('production', 'production-ready')} Next.js structure",
            f"- {'Basic' if tier == 'Minimal' else 'Production' if tier == 'Production' else 'Enterprise'} routing",
            f"- {'Simple' if tier == 'Minimal' else 'Comprehensive' if tier == 'Production' else 'Advanced'} styling",
            f"- {'Essential' if tier == 'Minimal' else 'Production' if tier == 'Production' else 'Enterprise'} error handling",
            ""
        ]
        
        return '\n'.join(template_parts)
    
    def _generate_r_code_template(self, config: Dict, tier_config: Dict) -> str:
        """Generate R code template"""
        tier = tier_config['prefix'].title()
        
        template_parts = [
            f"# {tier} Boilerplate Template ({tier.upper()} Tier - R)",
            "",
            "## Purpose",
            f"Provides {tier_config['focus']} for R projects following the {tier.lower()} approach.",
            "",
            "## Usage",
            f"This template should be used for:",
            f"- {tier.lower().replace('production', 'production data analysis')}",
            f"- {tier.lower().replace('production', 'production statistical modeling')}",
            f"- {tier.lower().replace('production', 'production enterprise data solutions')}",
            "",
            "## Structure",
            "```r",
            f"# Main entry point for the {tier} R application",
            "# ",
            f"# This is the {tier.lower()} entry point that creates and runs the analysis.",
            f"# {tier.title()} approach: Keep it {'simple' if tier == 'Minimal' else 'robust' if tier == 'Production' else 'secure and scalable'}.",
            "",
            "# Load required libraries",
            "library(dplyr)",
            "library(ggplot2)",
        ]
        
        if tier != 'Minimal':
            template_parts.append("library(httr)")
        
        if tier == 'Enterprise':
            template_parts.append("library(DBI)")
        
        template_parts.extend([
            "",
            "# Configuration",
            "config <- list(",
            "  data_source = \"local\",",
            "  output_dir = \"./output/\",",
        ])
        
        if tier != 'Minimal':
            template_parts.append("  api_base_url = \"https://api.example.com\",")
        
        if tier == 'Enterprise':
            template_parts.append("  db_host = \"localhost\",")
        
        template_parts.extend([
            f"  enable_logging = {'TRUE' if tier != 'Minimal' else 'FALSE'}",
            ")",
            "",
            "# Main analysis function",
            "analyze_data <- function(data) {",
            f"  # {tier.title()} data analysis",
            "  summary_stats <- data %>%",
            "    group_by(category) %>%",
            "    summarise(",
            "      mean_x = mean(x, na.rm = TRUE),",
            "      mean_y = mean(y, na.rm = TRUE),",
            "      count = n()",
            "    )",
            "  ",
            "  return(summary_stats)",
            "}",
            "",
            "# Visualization function",
            "create_plot <- function(data) {",
            "  p <- ggplot(data, aes(x = x, y = y, color = category)) +",
            "    geom_point(size = 3, alpha = 0.7) +",
            f"    theme_{'minimal' if tier == 'Minimal' else 'classic' if tier == 'Production' else 'bw'}() +",
            "    labs(",
            f"      title = \"{tier.title()} R Data Analysis\",",
            "      x = \"X Values\",",
            "      y = \"Y Values\",",
            "      color = \"Category\"",
            "    )",
            "  ",
            "  return(p)",
            "}",
            "",
            "# Main execution",
            "if (interactive()) {",
            "  # Generate sample data",
            "  set.seed(123)",
            "  sample_data <- data.frame(",
            "    x = rnorm(100),",
            "    y = rnorm(100),",
            "    category = sample(c('A', 'B', 'C'), 100, replace = TRUE)",
            "  )",
            "  ",
            "  # Run analysis",
            "  results <- analyze_data(sample_data)",
            "  print(results)",
            "  ",
            "  # Create visualization",
            "  plot <- create_plot(sample_data)",
            "  print(plot)",
            "}",
            "```",
            "",
            "## Features",
            f"- {tier.lower().replace('production', 'production-ready')} R structure",
            f"- {'Basic' if tier == 'Minimal' else 'Production' if tier == 'Production' else 'Enterprise'} data analysis",
            f"- {'Simple' if tier == 'Minimal' else 'Comprehensive' if tier == 'Production' else 'Advanced'} visualization",
            f"- {'Essential' if tier == 'Minimal' else 'Production' if tier == 'Production' else 'Enterprise'} error handling",
            ""
        ])
        
        return '\n'.join(template_parts)
    
    def _generate_sql_code_template(self, config: Dict, tier_config: Dict) -> str:
        """Generate SQL code template"""
        tier = tier_config['prefix'].title()
        
        template_parts = [
            f"-- {tier} SQL Database Schema",
            f"-- Generated reference implementation for {tier.lower()} projects",
            "",
            "-- Core tables",
            "CREATE TABLE IF NOT EXISTS users (",
            "    id SERIAL PRIMARY KEY,",
            "    username VARCHAR(50) UNIQUE NOT NULL,",
            "    email VARCHAR(100) UNIQUE NOT NULL,",
            "    password_hash VARCHAR(255) NOT NULL,",
            "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,",
            "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            ");",
            "",
            "CREATE TABLE IF NOT EXISTS categories (",
            "    id SERIAL PRIMARY KEY,",
            "    name VARCHAR(100) NOT NULL,",
            "    description TEXT,",
            "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            ");",
            "",
            "CREATE TABLE IF NOT EXISTS products (",
            "    id SERIAL PRIMARY KEY,",
            "    name VARCHAR(200) NOT NULL,",
            "    price DECIMAL(10,2) NOT NULL,",
            "    category_id INTEGER REFERENCES categories(id),",
            "    description TEXT,",
            "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,",
            "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            ");",
            ""
        ])
        
        if tier != 'Minimal':
            template_parts.extend([
                "-- Audit table for production/enterprise features",
                "CREATE TABLE IF NOT EXISTS audit_trail (",
                "    id SERIAL PRIMARY KEY,",
                "    table_name VARCHAR(100),",
                "    operation VARCHAR(10),",
                "    record_id INTEGER,",
                "    old_values JSONB,",
                "    new_values JSONB,",
                "    user_id INTEGER,",
                "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                ");",
                ""
            ])
        
        if tier == 'Enterprise':
            template_parts.extend([
                "-- Security table for enterprise features",
                "CREATE TABLE IF NOT EXISTS user_sessions (",
                "    id SERIAL PRIMARY KEY,",
                "    user_id INTEGER REFERENCES users(id),",
                "    session_token VARCHAR(255) UNIQUE,",
                "    expires_at TIMESTAMP,",
                "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                ");",
                ""
            ])
        
        template_parts.extend([
            "-- Indexes for performance",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
            "CREATE INDEX IF NOT EXISTS idx_products_category ON products(category_id);",
        ])
        
        if tier != 'Minimal':
            template_parts.append("CREATE INDEX IF NOT EXISTS idx_audit_trail_created_at ON audit_trail(created_at);")
        
        if tier == 'Enterprise':
            template_parts.append("CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token);")
        
        template_parts.extend([
            "",
            "-- Triggers for automatic timestamp updates",
            "CREATE OR REPLACE FUNCTION update_updated_at_column()",
            "RETURNS TRIGGER AS $$",
            "BEGIN",
            "    NEW.updated_at = CURRENT_TIMESTAMP;",
            "    RETURN NEW;",
            "END;",
            "$$ language 'plpgsql';",
            "",
            "CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users",
            "    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();",
            "",
            "CREATE TRIGGER update_products_updated_at BEFORE UPDATE ON products",
            "    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();",
            "",
            f"-- {tier.title()} Features",
            f"-- {tier.lower().replace('production', 'production-ready')} SQL structure",
            f"-- {'Basic' if tier == 'Minimal' else 'Production' if tier == 'Production' else 'Enterprise'} schema design",
            f"-- {'Simple' if tier == 'Minimal' else 'Comprehensive' if tier == 'Production' else 'Advanced'} indexing",
            f"-- {'Essential' if tier == 'Minimal' else 'Production' if tier == 'Production' else 'Enterprise'} security features",
            ""
        ])
        
        return '\n'.join(template_parts)
    
    def generate_docs_template(self, stack: str, tier: str) -> str:
        """Generate tier-specific documentation template"""
        config = STACK_CONFIGS[stack]
        tier_config = TIER_CONFIGS[tier]
        
        return f"""# {tier.upper()} {config['language']} Setup Guide

## Overview

This guide extends the foundational {config['language']} templates with {tier.lower()}-specific configurations and {tier_config['focus']} for rapid development and deployment.

## Prerequisites

{self._get_prerequisites(stack, tier)}

## Quick Start

### 1. Project Setup

```bash
# Copy {tier.upper()} {config['language']} boilerplate
cp tiers/{tier}/code/{tier_config['boilerplate_type']}-{stack}.tpl.{config['extension']} [project-name]/main.{config['extension']}

# Copy foundational templates
cp -r stacks/{stack}/base/code/* [project-name]/
cp -r stacks/{stack}/base/tests/* [project-name]/tests/

# Setup dependencies
{self._get_setup_commands(stack, tier)}
cd [project-name]
{config['setup_command']}
```

### 2. Configuration

```bash
# Copy environment configuration
cp tiers/{tier}/docs/{tier}-{stack}-config.tpl.md [project-name]/CONFIG.md

# Update environment variables
cp .env.example .env
# Edit .env with your specific values
```

### 3. Run Application

```bash
# Development mode
{config['package_manager']} run dev

# Production mode
{config['package_manager']} run build
{config['package_manager']} run start
```

## {tier.title()} Features

{self._get_tier_features(stack, tier)}

## Testing

```bash
# Run all tests
{config['test_command']}

# Run with coverage
{config['test_command']} --coverage
```

## Deployment

{self._get_deployment_instructions(stack, tier)}

## Troubleshooting

{self._get_troubleshooting_guide(stack, tier)}

## Next Steps

- Review the {tier.lower()} example project
- Customize the boilerplate for your specific needs
- Add additional {config['language']} packages as required
- Configure your deployment pipeline
"""
    
    def _get_prerequisites(self, stack: str, tier: str) -> str:
        """Get stack-specific prerequisites"""
        if stack == 'react_native':
            return """- Node.js 16+
- React Native CLI
- Android Studio / VS Code
- Android SDK (for Android development)
- Xcode (for iOS development)"""
        elif stack == 'next':
            return """- Node.js 16+
- Next.js 13+
- React 18+
- TypeScript (recommended)"""
        elif stack == 'r':
            return """- R 4.0+
- RStudio (recommended)
- Required packages: dplyr, ggplot2, testthat"""
        elif stack == 'sql':
            return """- PostgreSQL 12+
- psql client
- Database administration tools"""
    
    def _get_setup_commands(self, stack: str, tier: str) -> str:
        """Get setup commands for stack"""
        if stack in ['react_native', 'next']:
            return "cp stacks/{stack}/package.json.tpl [project-name]/package.json"
        elif stack == 'r':
            return "cp stacks/{stack}/requirements.txt.tpl [project-name]/requirements.txt"
        elif stack == 'sql':
            return "cp stacks/{stack}/schema.sql.tpl [project-name]/schema.sql"
    
    def _get_tier_features(self, stack: str, tier: str) -> str:
        """Get tier-specific features"""
        tier_config = TIER_CONFIGS[tier]
        features = []
        
        if tier == 'mvp':
            features = [
                "Minimal project structure",
                "Essential dependencies only",
                "Basic configuration setup",
                "Simple testing framework"
            ]
        elif tier == 'core':
            features = [
                "Production-ready structure",
                "Comprehensive dependency management",
                "Advanced configuration options",
                "Full testing suite with coverage",
                "Performance optimization"
            ]
        elif tier == 'enterprise':
            features = [
                "Enterprise-grade architecture",
                "Advanced security features",
                "Comprehensive monitoring and logging",
                "Scalability optimizations",
                "Full compliance and audit features"
            ]
        
        return '\n'.join([f"- {feature}" for feature in features])
    
    def _get_deployment_instructions(self, stack: str, tier: str) -> str:
        """Get deployment instructions"""
        if stack in ['react_native', 'next']:
            return """### Development Deployment
```bash
npm run build
npm run start
```

### Production Deployment
- Configure your hosting provider
- Set up environment variables
- Deploy using your preferred method (Docker, Vercel, AWS, etc.)"""
        elif stack == 'r':
            return """### Development Deployment
```bash
Rscript main.R
```

### Production Deployment
- Package as R Markdown document
- Deploy to Shiny server if needed
- Schedule automated execution"""
        elif stack == 'sql':
            return """### Development Deployment
```bash
psql -d your_database -f schema.sql
psql -d your_database -f procedures.sql
```

### Production Deployment
- Configure database connection
- Run migration scripts
- Set up backup and monitoring"""
    
    def _get_troubleshooting_guide(self, stack: str, tier: str) -> str:
        """Get troubleshooting guide"""
        return """### Common Issues

1. **Dependency conflicts**: Ensure all dependencies are compatible
2. **Configuration errors**: Check environment variables
3. **Build failures**: Review logs for specific error messages
4. **Test failures**: Verify test data and configuration

### Getting Help

- Check the stack documentation
- Review the example projects
- Consult the troubleshooting guides
- Create an issue for specific problems"""
    
    def generate_examples_template(self, stack: str, tier: str) -> str:
        """Generate tier-specific example template"""
        config = STACK_CONFIGS[stack]
        tier_config = TIER_CONFIGS[tier]
        
        return f"""# {tier.upper()} {config['language']} Example Project

## Overview

This example demonstrates a complete {tier.lower()} {config['language']} application using the {tier_config['boilerplate_type']} template with {tier_config['focus']}.

## Project Structure

```
{tier}_{stack}_example/
├── main.{config['extension']}                    # {tier.title()} boilerplate entry point
├── config/
│   ├── app_config.{config['extension']}          # {tier.title()} configuration
│   └── env_config.{config['extension']}          # Environment settings
├── core/
│   ├── constants.{config['extension']}           # App constants
│   ├── themes.{config['extension']}             # Basic themes
│   └── routes.{config['extension']}             # Route definitions
├── data/
│   ├── models/
│   │   ├── user.{config['extension']}            # User model
│   │   └── task.{config['extension']}            # Task model
│   ├── services/
│   │   ├── auth_service.{config['extension']}    # Authentication service
│   │   └── task_service.{config['extension']}    # Task management service
│   └── repositories/
│       └── task_repository.{config['extension']} # Task data repository
├── presentation/
│   ├── pages/
│   │   ├── home.{config['extension']}            # Home page
│   │   ├── about.{config['extension']}           # About page
│   │   └── profile.{config['extension']}         # User profile
│   ├── components/
│   │   ├── header.{config['extension']}          # Header component
│   │   ├── footer.{config['extension']}          # Footer component
│   │   └── loading.{config['extension']}         # Loading component
│   └── hooks/
│       ├── use_auth.{config['extension']}        # Authentication hook
│       └── use_tasks.{config['extension']}       # Task management hook
├── tests/
│   ├── unit/
│   │   ├── services_test.{config['extension']}   # Service tests
│   │   └── models_test.{config['extension']}     # Model tests
│   ├── integration/
│   │   └── api_test.{config['extension']}        # API integration tests
│   └── e2e/
│       └── user_flow_test.{config['extension']}  # End-to-end tests
├── docs/
│   ├── API.md                                   # API documentation
│   ├── DEPLOYMENT.md                            # Deployment guide
│   └── TROUBLESHOOTING.md                       # Troubleshooting guide
├── scripts/
│   ├── build.sh                                # Build script
│   ├── deploy.sh                               # Deploy script
│   └── test.sh                                 # Test script
├── .env.example                                # Environment variables template
├── package.json                                # Dependencies and scripts
└── README.md                                   # This file
```

## Features Demonstrated

{self._get_example_features(stack, tier)}

## Usage Examples

### Basic Usage
{self._get_basic_usage_example(stack, tier)}

### Advanced Usage
{self._get_advanced_usage_example(stack, tier)}

### Testing
{self._get_testing_example(stack, tier)}

## Configuration

### Environment Variables
```bash
# Copy the template
cp .env.example .env

# Edit with your values
# Database connection, API keys, etc.
```

### Application Settings
{self._get_app_settings_example(stack, tier)}

## Deployment

### Development
```bash
# Install dependencies
{config['package_manager']} install

# Run development server
{config['package_manager']} run dev
```

### Production
```bash
# Build for production
{config['package_manager']} run build

# Start production server
{config['package_manager']} run start
```

## Best Practices

{self._get_best_practices(stack, tier)}

## Next Steps

- Customize the example for your specific use case
- Add additional features as needed
- Configure your deployment pipeline
- Set up monitoring and logging
"""
    
    def _get_example_features(self, stack: str, tier: str) -> str:
        """Get example features for stack and tier"""
        features = []
        
        if stack == 'react_native':
            features = [
                "React Native mobile app structure",
                "Navigation between screens",
                "State management with hooks",
                "API integration with fetch",
                "Local storage with AsyncStorage",
                "Basic authentication flow"
            ]
        elif stack == 'next':
            features = [
                "Next.js full-stack application",
                "Server-side rendering (SSR)",
                "API routes for backend functionality",
                "Static site generation (SSG)",
                "Client-side routing",
                "Environment-based configuration"
            ]
        elif stack == 'r':
            features = [
                "R data analysis workflow",
                "Data manipulation with dplyr",
                "Visualization with ggplot2",
                "Statistical modeling",
                "Report generation with R Markdown",
                "Package management and dependencies"
            ]
        elif stack == 'sql':
            features = [
                "PostgreSQL database schema",
                "Stored procedures and functions",
                "Data validation with constraints",
                "Performance optimization with indexes",
                "Audit trail implementation",
                "Security best practices"
            ]
        
        if tier == 'core':
            features.extend([
                "Comprehensive error handling",
                "Input validation and sanitization",
                "Performance monitoring",
                "Security middleware",
                "Caching strategies"
            ])
        elif tier == 'enterprise':
            features.extend([
                "Advanced security features",
                "Role-based access control",
                "Audit logging and compliance",
                "Scalability optimizations",
                "Monitoring and alerting",
                "Backup and disaster recovery"
            ])
        
        return '\n'.join([f"- {feature}" for feature in features])
    
    def _get_basic_usage_example(self, stack: str, tier: str) -> str:
        """Get basic usage example"""
        if stack == 'react_native':
            return """```jsx
import React from 'react';
import { View, Text, StyleSheet } from 'react-native';

const HomeScreen = () => {
  return (
    <View style={styles.container}>
      <Text style={styles.title}>Welcome to React Native!</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
  },
});

export default HomeScreen;
```"""
        elif stack == 'next':
            return """```jsx
import React from 'react';

export default function Home() {
  return (
    <div>
      <h1>Welcome to Next.js!</h1>
      <p>This is a {tier.lower()} example application.</p>
    </div>
  );
}
```"""
        elif stack == 'r':
            return """```r
# Load required libraries
library(dplyr)
library(ggplot2)

# Generate sample data
data <- data.frame(
  x = rnorm(100),
  y = rnorm(100),
  category = sample(c('A', 'B', 'C'), 100, replace = TRUE)
)

# Basic analysis
summary_stats <- data %>%
  group_by(category) %>%
  summarise(
    mean_x = mean(x),
    mean_y = mean(y),
    count = n()
  )

print(summary_stats)
```"""
        elif stack == 'sql':
            return """```sql
-- Basic query example
SELECT 
  u.username,
  u.email,
  COUNT(p.id) as product_count
FROM users u
LEFT JOIN products p ON u.id = p.user_id
GROUP BY u.id, u.username, u.email
ORDER BY product_count DESC;
```"""
    
    def _get_advanced_usage_example(self, stack: str, tier: str) -> str:
        """Get advanced usage example"""
        if stack == 'react_native':
            return """```jsx
import React, { useState, useEffect } from 'react';
import { View, Text, FlatList, StyleSheet } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

const TaskList = () => {
  const [tasks, setTasks] = useState([]);

  useEffect(() => {
    loadTasks();
  }, []);

  const loadTasks = async () => {
    try {
      const storedTasks = await AsyncStorage.getItem('tasks');
      if (storedTasks) {
        setTasks(JSON.parse(storedTasks));
      }
    } catch (error) {
      console.error('Error loading tasks:', error);
    }
  };

  return (
    <View style={styles.container}>
      <FlatList
        data={tasks}
        renderItem={({ item }) => (
          <View style={styles.taskItem}>
            <Text>{item.title}</Text>
          </View>
        )}
        keyExtractor={(item) => item.id}
      />
    </View>
  );
};
```"""
        elif stack == 'next':
            return """```jsx
import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';

export default function Dashboard() {
  const [user, setUser] = useState(null);
  const router = useRouter();

  useEffect(() => {
    // Check authentication
    const token = localStorage.getItem('authToken');
    if (!token) {
      router.push('/login');
      return;
    }
    
    // Load user data
    fetchUserData();
  }, []);

  const fetchUserData = async () => {
    try {
      const response = await fetch('/api/user');
      const userData = await response.json();
      setUser(userData);
    } catch (error) {
      console.error('Error fetching user data:', error);
    }
  };

  if (!user) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <h1>Welcome, {user.name}!</h1>
      <p>This is your dashboard.</p>
    </div>
  );
}
```"""
        elif stack == 'r':
            return """```r
# Advanced data analysis with modeling
library(caret)
library(randomForest)

# Load and prepare data
data <- read.csv('data/dataset.csv')

# Data preprocessing
preProcess <- preProcess(data, method = c('center', 'scale'))
processed_data <- predict(preProcess, data)

# Split data into training and testing
set.seed(123)
trainIndex <- createDataPartition(processed_data$target, p = 0.8, list = FALSE)
train_data <- processed_data[trainIndex, ]
test_data <- processed_data[-trainIndex, ]

# Train model
model <- randomForest(target ~ ., data = train_data, ntree = 100)

# Make predictions
predictions <- predict(model, test_data)

# Evaluate model
confusion_matrix <- confusionMatrix(predictions, test_data$target)
print(confusion_matrix)
```"""
        elif stack == 'sql':
            return """```sql
-- Advanced stored procedure with error handling
CREATE OR REPLACE FUNCTION create_user_with_audit(
    p_username VARCHAR,
    p_email VARCHAR,
    p_password_hash VARCHAR,
    p_created_by INTEGER
)
RETURNS INTEGER AS $$
DECLARE
    new_user_id INTEGER;
    audit_message TEXT;
BEGIN
    -- Insert new user
    INSERT INTO users (username, email, password_hash)
    VALUES (p_username, p_email, p_password_hash)
    RETURNING id INTO new_user_id;
    
    -- Create audit trail
    INSERT INTO audit_trail (table_name, operation, record_id, user_id, new_values)
    VALUES (
        'users',
        'INSERT',
        new_user_id,
        p_created_by,
        json_build_object('username', p_username, 'email', p_email)
    );
    
    -- Log success
    audit_message := format('User %s created successfully with ID %s', p_username, new_user_id);
    INSERT INTO system_logs (level, message, created_at)
    VALUES ('INFO', audit_message, CURRENT_TIMESTAMP);
    
    RETURN new_user_id;
    
EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION 'Username or email already exists';
    WHEN others THEN
        RAISE EXCEPTION 'Error creating user: %', SQLERRM;
END;
$$ LANGUAGE plpgsql;
```"""
    
    def _get_testing_example(self, stack: str, tier: str) -> str:
        """Get testing example"""
        if stack == 'react_native':
            return """```jsx
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react-native';
import TaskList from '../components/TaskList';

describe('TaskList', () => {
  test('renders task list correctly', () => {
    const mockTasks = [
      { id: '1', title: 'Task 1' },
      { id: '2', title: 'Task 2' },
    ];

    render(<TaskList tasks={mockTasks} />);
    
    expect(screen.getByText('Task 1')).toBeTruthy();
    expect(screen.getByText('Task 2')).toBeTruthy();
  });

  test('handles empty task list', () => {
    render(<TaskList tasks={[]} />);
    
    expect(screen.getByText('No tasks found')).toBeTruthy();
  });
});
```"""
        elif stack == 'next':
            return """```jsx
import { render, screen } from '@testing-library/react';
import Home from '../pages/index';

describe('Home Page', () => {
  test('renders welcome message', () => {
    render(<Home />);
    
    expect(screen.getByText('Welcome to Next.js!')).toBeInTheDocument();
  });

  test('renders navigation links', () => {
    render(<Home />);
    
    expect(screen.getByRole('link', { name: /about/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /contact/i })).toBeInTheDocument();
  });
});
```"""
        elif stack == 'r':
            return """```r
# Test file: test_analysis.R
library(testthat)
library(dplyr)

# Test data analysis functions
test_that("analyze_data works correctly", {
  # Create test data
  test_data <- data.frame(
    x = c(1, 2, 3, 4, 5),
    y = c(2, 4, 6, 8, 10),
    category = c('A', 'A', 'B', 'B', 'C')
  )
  
  # Test analysis function
  results <- analyze_data(test_data)
  
  expect_true(is.data.frame(results))
  expect_equal(nrow(results), 3)
  expect_true('category' %in% names(results))
})

test_that("create_plot generates valid plot", {
  test_data <- data.frame(
    x = rnorm(100),
    y = rnorm(100),
    category = sample(c('A', 'B', 'C'), 100, replace = TRUE)
  )
  
  plot <- create_plot(test_data)
  expect_s3_class(plot, 'ggplot')
})
```"""
        elif stack == 'sql':
            return """```sql
-- Test file: test_functions.sql
-- Test stored procedures and functions

-- Test user creation function
DO $$
DECLARE
    user_id INTEGER;
    test_username VARCHAR := 'testuser_' || EXTRACT(EPOCH FROM CURRENT_TIMESTAMP);
BEGIN
    -- Test successful user creation
    user_id := create_user_with_audit(test_username, 'test@example.com', 'hash123', 1);
    
    IF user_id IS NULL THEN
        RAISE EXCEPTION 'User creation failed';
    END IF;
    
    -- Verify user was created
    PERFORM 1 FROM users WHERE id = user_id AND username = test_username;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'User not found in database';
    END IF;
    
    RAISE NOTICE 'User creation test passed for user ID: %', user_id;
END $$;
```"""
    
    def _get_app_settings_example(self, stack: str, tier: str) -> str:
        """Get application settings example"""
        if stack in ['react_native', 'next']:
            return """```javascript
// config/app_config.js
export const config = {
  development: {
    apiUrl: 'http://localhost:3001/api',
    timeout: 10000,
    enableLogging: true,
  },
  production: {
    apiUrl: 'https://api.yourapp.com',
    timeout: 5000,
    enableLogging: false,
  },
  test: {
    apiUrl: 'http://localhost:3001/test-api',
    timeout: 5000,
    enableLogging: true,
  }
};
```"""
        elif stack == 'r':
            return """```r
# config/app_config.R
config <- list(
  development = list(
    data_source = "local",
    output_dir = "./output/",
    enable_logging = TRUE,
    plot_theme = "default"
  ),
  production = list(
    data_source = "database",
    output_dir = "/data/output/",
    enable_logging = TRUE,
    plot_theme = "minimal"
  ),
  test = list(
    data_source = "mock",
    output_dir = "./test_output/",
    enable_logging = TRUE,
    plot_theme = "bw"
  )
)
```"""
        elif stack == 'sql':
            return """```sql
-- Configuration settings
-- These can be stored in a configuration table or environment variables

-- Application settings
INSERT INTO config (key, value, description) VALUES
  ('app_version', '1.0.0', 'Current application version'),
  ('max_connections', '100', 'Maximum database connections'),
  ('timeout_seconds', '30', 'Query timeout in seconds'),
  ('enable_audit', 'true', 'Enable audit logging'),
  ('backup_retention_days', '30', 'Number of days to retain backups');
```"""
    
    def _get_best_practices(self, stack: str, tier: str) -> str:
        """Get best practices for stack"""
        if stack == 'react_native':
            return """1. **Component Structure**: Keep components small and focused
2. **State Management**: Use appropriate state management solutions
3. **Performance**: Optimize images and use lazy loading
4. **Security**: Validate inputs and secure API calls
5. **Testing**: Write comprehensive unit and integration tests"""
        elif stack == 'next':
            return """1. **Code Organization**: Separate concerns with clear folder structure
2. **Performance**: Use SSR and SSG appropriately
3. **SEO**: Implement proper meta tags and structured data
4. **Security**: Validate inputs and implement CSRF protection
5. **Testing**: Test both client and server-side code"""
        elif stack == 'r':
            return """1. **Code Style**: Follow tidyverse style guide
2. **Data Management**: Use proper data structures and validation
3. **Performance**: Vectorize operations when possible
4. **Documentation**: Document functions and analysis steps
5. **Testing**: Write tests for data processing functions"""
        elif stack == 'sql':
            return """1. **Schema Design**: Use proper normalization and indexing
2. **Performance**: Optimize queries and use appropriate data types
3. **Security**: Implement proper authentication and authorization
4. **Documentation**: Document schemas and procedures
5. **Testing**: Test stored procedures and data integrity"""
    
    def generate_tests_template(self, stack: str, tier: str) -> str:
        """Generate tier-specific test template"""
        config = STACK_CONFIGS[stack]
        tier_config = TIER_CONFIGS[tier]
        
        return f"""# {tier.title()} {config['language']} Testing Template
# Purpose: {tier.lower()}-level testing template with {'unit and integration' if tier == 'mvp' else 'comprehensive' if tier == 'core' else 'enterprise'} tests for {config['language']} applications
# Usage: Copy to test/ directory and customize for your {config['language']} project
# Stack: {config['language']} ({config['extension']})
# Tier: {tier.upper()} ({tier_config['prefix'].title()})

## Purpose

{tier.title()}-level {config['language']} testing template providing {'essential' if tier == 'mvp' else 'comprehensive' if tier == 'core' else 'enterprise'} testing for basic application functionality. Focuses on testing {'core business logic' if tier == 'mvp' else 'all components and integrations' if tier == 'core' else 'security, performance, and compliance'} with {'minimal' if tier == 'mvp' else 'robust' if tier == 'core' else 'enterprise-grade'} setup and {'fast' if tier == 'mvp' else 'thorough' if tier == 'core' else 'comprehensive'} execution.

## Usage

```bash
# Copy to your {config['language']} project
cp tiers/{tier}/tests/{tier_config['test_type']}-{stack}.tpl.{config['extension']} test/{tier_config['test_type']}_tests.{config['extension']}

# Run tests
{config['test_command']}

# Run with coverage
{config['test_command']} --coverage
```

## Structure

{self._get_test_structure(stack, tier)}

## Test Categories

{self._get_test_categories(stack, tier)}

## Configuration

{self._get_test_configuration(stack, tier)}

## Best Practices

{self._get_test_best_practices(stack, tier)}

## Continuous Integration

{self._get_ci_configuration(stack, tier)}
"""
    
    def _get_test_structure(self, stack: str, tier: str) -> str:
        """Get test structure for stack"""
        if stack == 'react_native':
            return """```jsx
// test/basic_tests.js
import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react-native';
import App from '../App';

describe('App Component', () => {
  test('renders correctly', () => {
    render(<App />);
    expect(screen.getByText('Welcome')).toBeTruthy();
  });

  test('handles user interactions', () => {
    render(<App />);
    const button = screen.getByText('Submit');
    fireEvent.press(button);
    expect(screen.getByText('Success')).toBeTruthy();
  });
});
```"""
        elif stack == 'next':
            return """```jsx
// test/comprehensive_tests.js
import { render, screen, fireEvent } from '@testing-library/react';
import Home from '../pages/index';
import { renderToString } from 'react-dom/server';

describe('Home Page', () => {
  test('renders on client', () => {
    render(<Home />);
    expect(screen.getByText('Welcome')).toBeInTheDocument();
  });

  test('renders on server', () => {
    const html = renderToString(<Home />);
    expect(html).toContain('Welcome');
  });

  test('handles API interactions', async () => {
    render(<Home />);
    const loadButton = screen.getByText('Load Data');
    fireEvent.click(loadButton);
    expect(await screen.findByText('Data loaded')).toBeInTheDocument();
  });
});
```"""
        elif stack == 'r':
            return """```r
# test/analysis_tests.R
library(testthat)
library(dplyr)

# Source main functions
source('../analysis.R')

describe('Data Analysis', {
  test('analyze_data returns correct structure', {
    test_data <- data.frame(
      x = rnorm(50),
      y = rnorm(50),
      category = sample(c('A', 'B'), 50, replace = TRUE)
    )
    
    result <- analyze_data(test_data)
    
    expect_s3_class(result, 'data.frame')
    expect_true('category' %in% names(result))
    expect_equal(nrow(result), 2)
  })
  
  test('create_plot generates valid ggplot', {
    test_data <- data.frame(
      x = rnorm(50),
      y = rnorm(50),
      category = sample(c('A', 'B'), 50, replace = TRUE)
    )
    
    plot <- create_plot(test_data)
    expect_s3_class(plot, 'ggplot')
  })
})
```"""
        elif stack == 'sql':
            return """```sql
-- test/procedure_tests.sql
-- Test stored procedures and functions

DO $$
DECLARE
    test_user_id INTEGER;
    test_result RECORD;
BEGIN
    -- Test user creation
    test_user_id := create_user_with_audit('testuser', 'test@example.com', 'hash123', 1);
    
    IF test_user_id IS NULL THEN
        RAISE EXCEPTION 'User creation test failed';
    END IF;
    
    -- Test user retrieval
    SELECT * INTO test_result FROM get_user_by_id(test_user_id);
    
    IF test_result.username != 'testuser' THEN
        RAISE EXCEPTION 'User retrieval test failed';
    END IF;
    
    RAISE NOTICE 'All tests passed successfully';
END $$;
```"""
    
    def _get_test_categories(self, stack: str, tier: str) -> str:
        """Get test categories"""
        categories = []
        
        if tier == 'mvp':
            categories = [
                "Unit Tests - Test individual functions and components",
                "Integration Tests - Test component interactions",
                "Basic UI Tests - Test user interface elements"
            ]
        elif tier == 'core':
            categories = [
                "Unit Tests - Comprehensive function and component testing",
                "Integration Tests - Full system integration testing",
                "API Tests - Backend API endpoint testing",
                "UI Tests - Complete user interface testing",
                "Performance Tests - Basic performance validation"
            ]
        elif tier == 'enterprise':
            categories = [
                "Unit Tests - Enterprise-grade unit testing",
                "Integration Tests - Full system integration",
                "API Tests - Comprehensive API testing",
                "UI Tests - Complete user interface testing",
                "Security Tests - Authentication and authorization testing",
                "Performance Tests - Load and stress testing",
                "Compliance Tests - Regulatory compliance validation"
            ]
        
        return '\n'.join([f"- {category}" for category in categories])
    
    def _get_test_configuration(self, stack: str, tier: str) -> str:
        """Get test configuration"""
        if stack in ['react_native', 'next']:
            return """```javascript
// jest.config.js
module.exports = {
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/test/setup.js'],
  collectCoverageFrom: [
    'src/**/*.{js,jsx}',
    '!src/index.js',
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
};
```"""
        elif stack == 'r':
            return """```r
# test/testthat.R
library(testthat)

# Set test configuration
test_check('.', reporter = "summary")
```"""
        elif stack == 'sql':
            return """```sql
-- Test configuration
-- Set up test database and data

CREATE DATABASE IF NOT EXISTS test_db;

-- Use test database
\\c test_db

-- Run test scripts
\\i test_setup.sql
\\i test_procedures.sql
\\i test_data.sql
```"""
    
    def _get_test_best_practices(self, stack: str, tier: str) -> str:
        """Get test best practices"""
        if stack in ['react_native', 'next']:
            return """1. **Test Structure**: Organize tests by feature and component
2. **Mock Data**: Use consistent mock data across tests
3. **Async Testing**: Handle asynchronous operations properly
4. **Coverage**: Maintain high test coverage
5. **CI/CD**: Integrate tests into continuous integration"""
        elif stack == 'r':
            return """1. **Test Organization**: Group tests by function and module
2. **Data Validation**: Test data processing and validation
3. **Edge Cases**: Test boundary conditions and edge cases
4. **Performance**: Test performance of data operations
5. **Documentation**: Document test scenarios and expectations"""
        elif stack == 'sql':
            return """1. **Test Data**: Use consistent test data sets
2. **Transaction Safety**: Test transaction rollback and commit
3. **Performance**: Test query performance and optimization
4. **Security**: Test SQL injection and security measures
5. **Data Integrity**: Test constraints and data validation"""
    
    def _get_ci_configuration(self, stack: str, tier: str) -> str:
        """Get CI configuration"""
        return f"""# GitHub Actions Configuration
```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup {STACK_CONFIGS[stack]['language']}
        run: |
          {self._get_setup_steps(stack)}
      - name: Install dependencies
        run: |
          {self._get_install_steps(stack)}
      - name: Run tests
        run: |
          {STACK_CONFIGS[stack]['test_command']}
```"""
    
    def _get_setup_steps(self, stack: str) -> str:
        """Get setup steps for CI"""
        if stack in ['react_native', 'next']:
            return "curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -\nsudo apt-get install -y nodejs"
        elif stack == 'r':
            return "sudo apt-get update\nsudo apt-get install -y r-base"
        elif stack == 'sql':
            return "sudo apt-get update\nsudo apt-get install -y postgresql postgresql-contrib\nsudo service postgresql start"
    
    def _get_install_steps(self, stack: str) -> str:
        """Get install steps for CI"""
        if stack in ['react_native', 'next']:
            return "npm install"
        elif stack == 'r':
            return "R -e \"install.packages(c('dplyr', 'ggplot2', 'testthat'))\""
        elif stack == 'sql':
            return "psql -c 'CREATE DATABASE test_db;' -U postgres"
    
    def generate_all_missing_templates(self) -> Dict[str, bool]:
        """Generate all missing tier templates"""
        print("🚀 Starting generation of missing tier templates...")
        print("=" * 60)
        
        results = {}
        
        for tier_name in TIER_CONFIGS.keys():
            print(f"\n📁 Processing {tier_name.upper()} tier...")
            tier_results = {}
            
            for stack_name in STACK_CONFIGS.keys():
                print(f"  🔨 Generating {stack_name} templates...")
                
                try:
                    # Generate code template
                    code_template = self.generate_code_template(stack_name, tier_name)
                    code_file = self.tiers_dir / tier_name / 'code' / f"{TIER_CONFIGS[tier_name]['boilerplate_type']}-{stack_name}.tpl.{STACK_CONFIGS[stack_name]['extension']}"
                    code_file.write_text(code_template, encoding='utf-8')
                    
                    # Generate docs template
                    docs_template = self.generate_docs_template(stack_name, tier_name)
                    docs_file = self.tiers_dir / tier_name / 'docs' / f"{tier_name}-{stack_name}-setup.tpl.md"
                    docs_file.write_text(docs_template, encoding='utf-8')
                    
                    # Generate examples template
                    examples_template = self.generate_examples_template(stack_name, tier_name)
                    examples_file = self.tiers_dir / tier_name / 'examples' / f"{tier_name}-{stack_name}-example.tpl.md"
                    examples_file.write_text(examples_template, encoding='utf-8')
                    
                    # Generate tests template
                    tests_template = self.generate_tests_template(stack_name, tier_name)
                    tests_file = self.tiers_dir / tier_name / 'tests' / f"{TIER_CONFIGS[tier_name]['test_type']}-{stack_name}.tpl.{STACK_CONFIGS[stack_name]['extension']}"
                    tests_file.write_text(tests_template, encoding='utf-8')
                    
                    tier_results[stack_name] = True
                    print(f"    ✅ {stack_name} templates generated successfully")
                    
                except Exception as e:
                    print(f"    ❌ {stack_name} templates failed: {e}")
                    tier_results[stack_name] = False
            
            results[tier_name] = all(tier_results.values())
        
        return results

def main():
    """Main execution function"""
    base_dir = Path(__file__).parent.parent
    generator = TierTemplateGenerator(base_dir)
    
    # Create directory structure
    generator.create_directory_structure()
    
    # Generate all missing templates
    results = generator.generate_all_missing_templates()
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 Generation Summary")
    print("=" * 60)
    
    success_count = 0
    for tier_name, success in results.items():
        status = "✅ Success" if success else "❌ Failed"
        print(f"{tier_name.title():12} : {status}")
        if success:
            success_count += 1
    
    print(f"\nOverall: {success_count}/{len(results)} tiers generated successfully")
    
    if success_count == len(results):
        print("🎉 All missing tier templates have been generated successfully!")
        return 0
    else:
        print("⚠️  Some tiers failed to generate. Check the logs above.")
        return 1

if __name__ == "__main__":
    exit(main())
