#!/usr/bin/env python3
"""
Generate missing technology stacks based on existing templates
Creates react_native, r, sql, and next stacks with full feature parity
"""

import os
import shutil
from pathlib import Path
from typing import Dict, List, Tuple

# Stack generation configurations
STACK_CONFIGS = {
    'react_native': {
        'base_stack': 'react',
        'file_extensions': {
            'code': '.jsx',
            'docs': '.md',
            'tests': '.jsx'
        },
        'replacements': {
            'React': 'React Native',
            'react': 'react_native',
            'web': 'mobile',
            'browser': 'mobile app',
            'DOM': 'native components',
            'useState': 'useState',
            'useEffect': 'useEffect',
            'Platform.OS': 'Platform.OS',
            'StyleSheet.create': 'StyleSheet.create',
            'View': 'View',
            'Text': 'Text',
            'TouchableOpacity': 'TouchableOpacity',
            'import React': 'import React',
            'import {': 'import {',
        },
        'adaptations': {
            'config-management.tpl.jsx': 'add Platform-specific imports and mobile config',
            'http-client.tpl.jsx': 'add mobile-specific headers and timeout handling',
            'error-handling.tpl.jsx': 'add native error boundaries and offline handling',
        }
    },
    'next': {
        'base_stack': 'react',
        'file_extensions': {
            'code': '.jsx',
            'docs': '.md',
            'tests': '.jsx'
        },
        'replacements': {
            'React': 'Next.js',
            'react': 'next',
            'create-react-app': 'Next.js',
            'client-side routing': 'server-side routing',
            'SPA': 'full-stack application',
            'export default': 'export default',
        },
        'adaptations': {
            'config-management.tpl.jsx': 'add Next.js config and environment variables',
            'http-client.tpl.jsx': 'add server-side fetch capabilities',
            'error-handling.tpl.jsx': 'add Next.js error pages and middleware',
        }
    },
    'r': {
        'base_stack': 'python',
        'file_extensions': {
            'code': '.R',
            'docs': '.md',
            'tests': '.R'
        },
        'replacements': {
            'Python': 'R',
            'python': 'r',
            '.py': '.R',
            'def ': 'function ',
            'import ': 'library(',
            'from ': '',
            'pandas': 'dplyr',
            'numpy': 'base',
            'requests': 'httr',
            'json': 'jsonlite',
            'pytest': 'testthat',
            'Flask': 'Shiny',
            'Django': 'Shiny',
        },
        'adaptations': {
            'config-management.tpl.R': 'adapt for R environment variables and config files',
            'data-validation.tpl.R': 'use R data validation packages',
            'http-client.tpl.R': 'use httr for HTTP requests',
        }
    },
    'sql': {
        'base_stack': 'python',
        'file_extensions': {
            'code': '.sql',
            'docs': '.md',
            'tests': '.sql'
        },
        'replacements': {
            'Python': 'SQL',
            'python': 'sql',
            '.py': '.sql',
            'def ': '-- Function: ',
            'import ': '-- Include: ',
            'database': 'database schema',
            'API': 'stored procedures',
            'REST': 'database operations',
            'HTTP': 'SQL operations',
        },
        'adaptations': {
            'config-management.tpl.sql': 'adapt for database configuration',
            'data-validation.tpl.sql': 'use CHECK constraints and triggers',
            'http-client.tpl.sql': 'replace with connection management',
            'error-handling.tpl.sql': 'use SQL exception handling',
        }
    }
}

class StackGenerator:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.stacks_dir = base_dir / 'stacks'
        
    def create_stack_structure(self, stack_name: str) -> Path:
        """Create the basic directory structure for a stack"""
        stack_dir = self.stacks_dir / stack_name
        base_dir = stack_dir / 'base'
        
        # Create directories
        base_dir.mkdir(parents=True, exist_ok=True)
        (base_dir / 'code').mkdir(exist_ok=True)
        (base_dir / 'docs').mkdir(exist_ok=True)
        (base_dir / 'tests').mkdir(exist_ok=True)
        
        return stack_dir
    
    def copy_and_adapt_template(self, source_file: Path, target_file: Path, 
                                config: Dict, template_name: str) -> bool:
        """Copy a template file and apply stack-specific adaptations"""
        try:
            # Read source content
            content = source_file.read_text(encoding='utf-8')
            
            # Apply basic replacements
            for old, new in config['replacements'].items():
                content = content.replace(old, new)
            
            # Apply stack-specific adaptations
            if template_name in config.get('adaptations', {}):
                content = self.apply_adaptations(content, config['adaptations'][template_name], config)
            
            # Write target file
            target_file.write_text(content, encoding='utf-8')
            return True
            
        except Exception as e:
            print(f"Error processing {source_file}: {e}")
            return False
    
    def apply_adaptations(self, content: str, adaptation_type: str, config: Dict) -> str:
        """Apply stack-specific adaptations to template content"""
        if 'react_native' in str(config.get('replacements', {})):
            # React Native specific adaptations
            if 'Platform' not in content:
                content = content.replace(
                    'import React, {',
                    'import React, {\nimport { Platform } from \'react-native\';\n\nimport React, {'
                )
            
            # Add mobile-specific error handling
            if 'error-handling' in adaptation_type:
                content += '\n\n// Mobile-specific error handling\nconst handleNetworkError = (error) => {\n  if (!__DEV__) {\n    // Production error reporting\n  }\n};'
        
        elif 'next' in str(config.get('replacements', {})):
            # Next.js specific adaptations
            if 'config-management' in adaptation_type:
                content += '\n\n// Next.js specific configuration\nexport const config = {\n  runtime: \'nodejs\',\n};'
        
        elif 'r' in str(config.get('replacements', {})):
            # R specific adaptations
            content = content.replace('def ', 'function ')
            content = content.replace(':', ' <-')
            content = content.replace('print(', 'cat(')
        
        elif 'sql' in str(config.get('replacements', {})):
            # SQL specific adaptations
            content = content.replace('def ', 'CREATE PROCEDURE ')
            content = content.replace('return', 'SELECT')
            content = content.replace('print(', '-- Output: ')
        
        return content
    
    def generate_stack(self, stack_name: str) -> bool:
        """Generate a complete stack based on configuration"""
        print(f"\n🏗️  Generating {stack_name} stack...")
        
        config = STACK_CONFIGS.get(stack_name)
        if not config:
            print(f"❌ No configuration found for {stack_name}")
            return False
        
        # Create directory structure
        stack_dir = self.create_stack_structure(stack_name)
        base_stack_dir = self.stacks_dir / config['base_stack'] / 'base'
        
        if not base_stack_dir.exists():
            print(f"❌ Base stack {config['base_stack']} not found")
            return False
        
        success_count = 0
        total_count = 0
        
        # Process code templates
        print(f"  📁 Processing code templates...")
        code_dir = stack_dir / 'base' / 'code'
        source_code_dir = base_stack_dir / 'code'
        
        if source_code_dir.exists():
            for source_file in source_code_dir.glob('*.tpl.*'):
                target_file = code_dir / source_file.name
                total_count += 1
                if self.copy_and_adapt_template(source_file, target_file, config, source_file.name):
                    success_count += 1
        
        # Process docs templates
        print(f"  📁 Processing docs templates...")
        docs_dir = stack_dir / 'base' / 'docs'
        source_docs_dir = base_stack_dir / 'docs'
        
        if source_docs_dir.exists():
            for source_file in source_docs_dir.glob('*.tpl.*'):
                target_file = docs_dir / source_file.name
                total_count += 1
                if self.copy_and_adapt_template(source_file, target_file, config, source_file.name):
                    success_count += 1
        
        # Process test templates
        print(f"  📁 Processing test templates...")
        tests_dir = stack_dir / 'base' / 'tests'
        source_tests_dir = base_stack_dir / 'tests'
        
        if source_tests_dir.exists():
            for source_file in source_tests_dir.glob('*.tpl.*'):
                target_file = tests_dir / source_file.name
                total_count += 1
                if self.copy_and_adapt_template(source_file, target_file, config, source_file.name):
                    success_count += 1
        
        # Create package management file
        if stack_name in ['react_native', 'next']:
            package_json = self.create_package_json(stack_name)
            (stack_dir / 'package.json.tpl').write_text(package_json, encoding='utf-8')
            total_count += 1
            success_count += 1
        elif stack_name == 'r':
            requirements = self.create_r_requirements()
            (stack_dir / 'requirements.txt.tpl').write_text(requirements, encoding='utf-8')
            total_count += 1
            success_count += 1
        elif stack_name == 'sql':
            schema = self.create_sql_schema()
            (stack_dir / 'schema.sql.tpl').write_text(schema, encoding='utf-8')
            total_count += 1
            success_count += 1
        
        print(f"  ✅ Generated {success_count}/{total_count} templates for {stack_name}")
        return success_count == total_count
    
    def create_package_json(self, stack_name: str) -> str:
        """Create package.json template for JavaScript stacks"""
        if stack_name == 'react_native':
            return '''{
  "name": "{{.ProjectName}}",
  "version": "1.0.0",
  "description": "{{.Description}}",
  "main": "index.js",
  "scripts": {
    "android": "react-native run-android",
    "ios": "react-native run-ios",
    "start": "react-native start",
    "test": "jest",
    "lint": "eslint . --ext .js,.jsx,.ts,.tsx"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-native": "^0.72.6"
  },
  "devDependencies": {
    "@babel/core": "^7.20.0",
    "@babel/preset-env": "^7.20.0",
    "@babel/runtime": "^7.20.0",
    "@react-native/eslint-config": "^0.72.2",
    "@react-native/metro-config": "^0.72.11",
    "@tsconfig/react-native": "^3.0.0",
    "@types/react": "^18.0.24",
    "@types/react-test-renderer": "^18.0.0",
    "babel-jest": "^29.2.1",
    "eslint": "^8.19.0",
    "jest": "^29.2.1",
    "metro-react-native-babel-preset": "0.76.8",
    "prettier": "^2.4.1",
    "react-test-renderer": "18.2.0"
  }
}'''
        elif stack_name == 'next':
            return '''{
  "name": "{{.ProjectName}}",
  "version": "1.0.0",
  "description": "{{.Description}}",
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    "test": "jest",
    "test:watch": "jest --watch"
  },
  "dependencies": {
    "next": "^14.0.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "eslint": "^8.0.0",
    "eslint-config-next": "^14.0.0",
    "jest": "^29.0.0",
    "typescript": "^5.0.0"
  }
}'''
    
    def create_r_requirements(self) -> str:
        """Create R requirements template"""
        return '''# R Package Dependencies
# Generated for {{.ProjectName}}

# Data manipulation
dplyr >= 1.1.0
tidyr >= 1.3.0
readr >= 2.1.0

# Data visualization
ggplot2 >= 3.4.0
shiny >= 1.7.0

# Web requests and APIs
httr >= 1.4.0
jsonlite >= 1.8.0

# Database connectivity
DBI >= 1.1.0
RPostgres >= 1.4.0
RSQLite >= 2.3.0

# Testing
testthat >= 3.1.0

# Configuration
config >= 0.3.0
yaml >= 2.3.0

# Utilities
purrr >= 1.0.0
stringr >= 1.5.0
lubridate >= 1.9.0'''
    
    def create_sql_schema(self) -> str:
        """Create SQL schema template"""
        return '''-- SQL Schema Template
-- Generated for {{.ProjectName}}

-- Configuration table
CREATE TABLE IF NOT EXISTS config (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Error logging table
CREATE TABLE IF NOT EXISTS error_logs (
    id SERIAL PRIMARY KEY,
    error_code VARCHAR(50),
    error_message TEXT,
    stack_trace TEXT,
    context JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit table
CREATE TABLE IF NOT EXISTS audit_trail (
    id SERIAL PRIMARY KEY,
    action VARCHAR(100),
    table_name VARCHAR(100),
    record_id INTEGER,
    old_values JSONB,
    new_values JSONB,
    user_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_error_logs_created_at ON error_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_trail_created_at ON audit_trail(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_trail_table ON audit_trail(table_name, record_id);'''
    
    def generate_all_missing_stacks(self) -> Dict[str, bool]:
        """Generate all missing stacks"""
        print("🚀 Starting generation of missing technology stacks...")
        print("=" * 60)
        
        results = {}
        
        for stack_name in STACK_CONFIGS.keys():
            results[stack_name] = self.generate_stack(stack_name)
        
        return results

def main():
    """Main execution function"""
    base_dir = Path(__file__).parent.parent
    generator = StackGenerator(base_dir)
    
    # Generate all missing stacks
    results = generator.generate_all_missing_stacks()
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 Generation Summary")
    print("=" * 60)
    
    success_count = 0
    for stack_name, success in results.items():
        status = "✅ Success" if success else "❌ Failed"
        print(f"{stack_name:12} : {status}")
        if success:
            success_count += 1
    
    print(f"\nOverall: {success_count}/{len(results)} stacks generated successfully")
    
    if success_count == len(results):
        print("🎉 All missing stacks have been generated successfully!")
        return 0
    else:
        print("⚠️  Some stacks failed to generate. Check the logs above.")
        return 1

if __name__ == "__main__":
    exit(main())
