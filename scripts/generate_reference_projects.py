#!/usr/bin/env python3
"""
Generate reference projects for all main stacks and tiers
Creates 27 reference projects: 9 stacks × 3 tiers
"""

import os
from pathlib import Path

# Stack configurations
STACKS = ['flutter', 'react_native', 'react', 'next', 'node', 'go', 'python', 'r', 'sql', 'generic', 'typescript']
TIERS = ['mvp', 'core', 'enterprise']

def create_flutter_project(project_path: Path, tier: str):
    """Create Flutter reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # main.dart
    main_dart = f"""import 'package:flutter/material.dart';

void main() {{
  runApp(MyApp());
}}

class MyApp extends StatelessWidget {{
  @override
  Widget build(BuildContext context) {{
    return MaterialApp(
      title: '{tier.title()} Flutter Reference',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: MyHomePage(),
    );
  }}
}}

class MyHomePage extends StatelessWidget {{
  @override
  Widget build(BuildContext context) {{
    return Scaffold(
      appBar: AppBar(title: Text('{tier.title()} Flutter Reference')),
      body: Center(
        child: Text('Hello from {tier.title()} Flutter Project!'),
      ),
    );
  }}
}}
"""
    
    # widget_test.dart
    test_dart = f"""import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:reference_app/main.dart';

void main() {{
  testWidgets('{tier.title()} Flutter smoke test', (WidgetTester tester) async {{
    await tester.pumpWidget(MyApp());
    expect(find.text('Hello from {tier.title()} Flutter Project!'), findsOneWidget);
  }});
}}
"""
    
    # README.md
    readme = f"""# {tier.title()} Flutter Reference Project

## Overview
This is a reference-projects/[tier]/flutter-reference project demonstrating the standard structure and patterns.

## Features
- Basic Flutter application structure
- Material Design UI
- Unit tests included
"""
    
    if tier == 'core':
        readme += """
- Production-ready configuration
- Comprehensive error handling
- Logging integration
"""
    elif tier == 'enterprise':
        readme += """
- Enterprise security features
- Comprehensive testing suite
- Performance monitoring
- Audit logging
"""
    
    readme += f"""
## Setup
```bash
flutter pub get
flutter run
```

## Testing
```bash
flutter test
```
"""
    
    # pubspec.yaml
    pubspec_yaml = f"""name: {tier}_flutter_reference
description: {tier.title()} Flutter reference project demonstrating standard patterns.
version: 1.0.0

environment:
  sdk: '>=3.0.0 <4.0.0'
  flutter: ">=3.10.0"

dependencies:
  flutter:
    sdk: flutter
  cupertino_icons: ^1.0.6
  
"""
    
    if tier == 'core':
        pubspec_yaml += """  # Core tier dependencies
  http: ^1.1.0
  logger: ^2.0.2+1
  shared_preferences: ^2.2.2
  
"""
    elif tier == 'enterprise':
        pubspec_yaml += """  # Enterprise tier dependencies
  http: ^1.1.0
  logger: ^2.0.2+1
  shared_preferences: ^2.2.2
  flutter_secure_storage: ^9.0.0
  device_info_plus: ^9.1.1
  package_info_plus: ^4.2.0
  
"""

    pubspec_yaml += """dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^3.0.0
  
"""
    
    if tier == 'core':
        pubspec_yaml += """  # Core tier test dependencies
  mockito: ^5.4.4
  build_runner: ^2.4.7
  
"""
    elif tier == 'enterprise':
        pubspec_yaml += """  # Enterprise tier test dependencies
  mockito: ^5.4.4
  build_runner: ^2.4.7
  integration_test:
    sdk: flutter
  
"""

    pubspec_yaml += """flutter:
  uses-material-design: true
"""
    
    (project_path / 'main.dart').write_text(main_dart)
    (project_path / 'widget_test.dart').write_text(test_dart)
    (project_path / 'pubspec.yaml').write_text(pubspec_yaml)
    (project_path / 'README.md').write_text(readme)

def create_react_native_project(project_path: Path, tier: str):
    """Create React Native reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # App.jsx - React Native specific
    app_jsx = f"""import React from 'react';
import {{ StyleSheet, Text, View, SafeAreaView }} from 'react-native';

function App() {{
  return (
    <SafeAreaView style={{styles.container}}>
      <View style={{styles.content}}>
        <Text style={{styles.title}}>{tier.title()} React Native Reference</Text>
        <Text style={{styles.subtitle}}>Mobile app is running!</Text>
      </View>
    </SafeAreaView>
  );
}}

const styles = StyleSheet.create({{
  container: {{
    flex: 1,
    backgroundColor: '#fff',
  }},
  content: {{
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  }},
  title: {{
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 10,
    color: '#333',
  }},
  subtitle: {{
    fontSize: 16,
    color: '#666',
  }}
}});

export default App;
"""
    
    # App.test.jsx - React Native specific
    test_jsx = f"""import React from 'react';
import {{ render, screen }} from '@testing-library/react-native';
import App from '../App';

describe('{tier.title()} React Native App', () => {{
  test('renders correctly', () => {{
    render(<App />);
    expect(screen.getByText('{tier.title()} React Native Reference')).toBeTruthy();
  }});
  
  test('renders subtitle', () => {{
    render(<App />);
    expect(screen.getByText('Mobile app is running!')).toBeTruthy();
  }});
}});
"""
    
    # .env.example
    env_example = f"""# {tier.title()} React Native Environment Configuration
# Copy this file to .env and update with your values

# React Native Configuration
REACT_APP_NAME={tier.title()} React Native Reference
REACT_APP_VERSION=1.0.0
REACT_APP_ENVIRONMENT={tier}

# API Configuration
REACT_APP_API_URL=http://localhost:3001/api
REACT_APP_API_TIMEOUT=10000

# External Services
REACT_APP_EXTERNAL_API_URL=https://api.example.com
REACT_APP_EXTERNAL_API_KEY=your-external-api-key

# Mobile-Specific Configuration
REACT_APP_ENABLE_ANALYTICS={tier != 'mvp'}
REACT_APP_ENABLE_DEBUG={tier == 'mvp'}
REACT_APP_ENABLE_ERROR_REPORTING={tier != 'mvp'}
REACT_APP_DEEP_LINK_SCHEME=myapp
"""
    
    if tier == 'core':
        env_example += """\n# Core Tier Configuration
REACT_APP_OFFLINE_SUPPORT=true
REACT_APP_ASYNC_STORAGE_ENABLED=true
REACT_APP_PUSH_NOTIFICATIONS=true
"""
    elif tier == 'enterprise':
        env_example += """\n# Enterprise Tier Configuration
REACT_APP_OFFLINE_SUPPORT=true
REACT_APP_ASYNC_STORAGE_ENABLED=true
REACT_APP_PUSH_NOTIFICATIONS=true

# Security & Compliance
REACT_APP_BIOMETRIC_AUTH=true
REACT_APP_CERTIFICATE_PINNING=true
REACT_APP_SESSION_TIMEOUT=3600
REACT_APP_AUDIT_ENDPOINT=https://audit.example.com

# Monitoring & Analytics
REACT_APP_SENTRY_DSN=your-sentry-dsn-here
REACT_APP_CRASHLYTICS_ENABLED=true
REACT_APP_PERFORMANCE_MONITORING=true
"""
    
    # Enhanced package.json with React Native dependencies
    enhanced_package_json = f"""{{
  "name": "{tier}-react-native-reference",
  "version": "1.0.0",
  "description": "{tier.title()} React Native reference project",
  "main": "index.js",
  "scripts": {{
    "android": "react-native run-android",
    "ios": "react-native run-ios",
    "start": "react-native start",
    "test": "jest",
    "test:watch": "jest --watch",
    "lint": "eslint . --ext .js,.jsx,.ts,.tsx",
    "lint:fix": "eslint . --ext .js,.jsx,.ts,.tsx --fix"
  }},
  "dependencies": {{
    "react": "^18.2.0",
    "react-native": "^0.72.6"
"""
    
    if tier == 'core':
        enhanced_package_json += """,
    "@react-navigation/native": "^6.1.9",
    "@react-navigation/stack": "^6.3.20",
    "@react-native-async-storage/async-storage": "^1.19.3",
    "react-native-vector-icons": "^10.0.0"
"""
    elif tier == 'enterprise':
        enhanced_package_json += """,
    "@react-navigation/native": "^6.1.9",
    "@react-navigation/stack": "^6.3.20",
    "@react-native-async-storage/async-storage": "^1.19.3",
    "react-native-vector-icons": "^10.0.0",
    "react-native-biometrics": "^3.0.1",
    "@sentry/react-native": "^5.15.0",
    "react-native-fs": "^2.20.0"
"""
    
    enhanced_package_json += """
  },
  "devDependencies": {
    "@testing-library/react-native": "^12.4.0",
    "@testing-library/jest-native": "^5.4.3",
    "@react-native/metro-config": "^0.72.11",
    "metro-react-native-babel-preset": "^0.76.8",
    "jest": "^29.7.0",
    "eslint": "^8.56.0"
"""
    
    if tier == 'core':
        enhanced_package_json += """,
    "react-native-test-utils": "^0.1.0"
"""
    elif tier == 'enterprise':
        enhanced_package_json += """,
    "react-native-test-utils": "^0.1.0",
    "detox": "^20.13.5"
"""
    
    enhanced_package_json += """
  },
  "jest": {
    "preset": "react-native",
    "setupFilesAfterEnv": ["@testing-library/jest-native/extend-expect"]
  }
}
"""
    
    # README.md
    readme = f"""# {tier.title()} React Native Reference Project

## Overview
This is a {tier} tier React Native reference project demonstrating mobile app development patterns.

## Features
- React Native mobile application
- Cross-platform (iOS/Android) support
- Component-based architecture
- Unit tests included
"""
    
    if tier == 'core':
        readme += """
- Navigation setup
- Async storage integration
- Push notification support
"""
    elif tier == 'enterprise':
        readme += """
- Navigation setup
- Async storage integration
- Push notification support
- Biometric authentication
- Performance monitoring
- Crash reporting
"""
    
    readme += f"""
## Setup
```bash
npm install
npx react-native start
```

## Running on iOS
```bash
npx react-native run-ios
```

## Running on Android
```bash
npx react-native run-android
```

## Testing
```bash
npm test
```
"""
    
    (project_path / 'App.jsx').write_text(app_jsx)
    (project_path / 'App.test.jsx').write_text(test_jsx)
    (project_path / '.env.example').write_text(env_example)
    (project_path / 'package.json').write_text(enhanced_package_json)
    (project_path / 'README.md').write_text(readme)

def create_react_project(project_path: Path, tier: str):
    """Create React web reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    display_name = "React"
    
    # App.jsx
    app_jsx = f"""import React from 'react';
import './App.css';

function App() {{
  return (
    <div className="App">
      <header className="App-header">
        <h1>{tier.title()} {display_name} Reference</h1>
        <p>Hello from {tier} tier React project!</p>
      </header>
    </div>
  );
}}

export default App;
"""
    
    # App.test.jsx
    test_jsx = f"""import {{ render, screen }} from '@testing-library/react';
import App from './App';

test('{tier.title()} {display_name} renders correctly', () => {{
  render(<App />);
  expect(screen.getByText('Hello from {tier} tier React project!')).toBeInTheDocument();
}});
"""
    
    # package.json
    package_json = f"""{{
  "name": "{tier}-react-reference",
  "version": "1.0.0",
  "description": "{tier.title()} {display_name} reference project",
  "scripts": {{
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  }},
  "dependencies": {{
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-scripts": "5.0.1"
  }},
  "devDependencies": {{
    "@testing-library/react": "^13.4.0",
    "@testing-library/jest-dom": "^5.16.5"
  }}
}}
"""
    
    # README.md
    readme = f"""# {tier.title()} {display_name} Reference Project

## Overview
This is a {tier} tier {display_name} reference project demonstrating standard patterns.

## Features
- Modern {display_name} application
- Component-based architecture
- Comprehensive testing
"""
    
    if tier == 'core':
        readme += """
- Production build configuration
- Error boundaries
- Performance optimization
"""
    elif tier == 'enterprise':
        readme += """
- Enterprise security patterns
- Comprehensive test coverage
- Accessibility compliance
- Performance monitoring
"""
    
    readme += f"""
## Setup
```bash
npm install
npm start
```

## Testing
```bash
npm test
```
"""
    
    # .env.example
    env_example = f"""# {tier.title()} {display_name} Environment Configuration
# Copy this file to .env and update with your values

# React Application Configuration
REACT_APP_NAME={tier.title()} {display_name} Reference
REACT_APP_VERSION=1.0.0
REACT_APP_ENVIRONMENT={tier}

# API Configuration
REACT_APP_API_URL=http://localhost:3001/api
REACT_APP_API_TIMEOUT=10000

# External Services
REACT_APP_EXTERNAL_API_URL=https://api.example.com
REACT_APP_EXTERNAL_API_KEY=your-external-api-key

# Feature Flags
REACT_APP_ENABLE_ANALYTICS={tier != 'mvp'}
REACT_APP_ENABLE_DEBUG={tier == 'mvp'}
REACT_APP_ENABLE_ERROR_REPORTING={tier != 'mvp'}
"""
    
    if tier == 'core':
        env_example += """\n# Core Tier Configuration
REACT_APP_CACHE_ENABLED=true
REACT_APP_OFFLINE_SUPPORT=true
REACT_APP_SERVICE_WORKER=true
REACT_APP_REDUX_ENABLED=true
"""
    elif tier == 'enterprise':
        env_example += """\n# Enterprise Tier Configuration
REACT_APP_CACHE_ENABLED=true
REACT_APP_OFFLINE_SUPPORT=true
REACT_APP_SERVICE_WORKER=true
REACT_APP_REDUX_ENABLED=true

# Security & Compliance
REACT_APP_CSP_ENABLED=true
REACT_APP_MFA_REQUIRED=true
REACT_APP_SESSION_TIMEOUT=3600
REACT_APP_AUDIT_ENDPOINT=https://audit.example.com

# Monitoring & Analytics
REACT_APP_SENTRY_DSN=your-sentry-dsn-here
REACT_APP_PROMETHEUS_ENDPOINT=https://metrics.example.com
REACT_APP_PERFORMANCE_MONITORING=true
"""
    
    # Enhanced package.json with tier-appropriate dependencies
    enhanced_package_json = f"""{{
  "name": "{tier}-react-reference",
  "version": "1.0.0",
  "description": "{tier.title()} {display_name} reference project",
  "scripts": {{
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test --coverage --watchAll=false",
    "test:watch": "react-scripts test",
    "eject": "react-scripts eject",
    "lint": "eslint . --ext .js,.jsx,.ts,.tsx",
    "lint:fix": "eslint . --ext .js,.jsx,.ts,.tsx --fix",
    "format": "prettier --write ."
  }},
  "dependencies": {{
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-scripts": "5.0.1",
    "react-router-dom": "^6.8.1"
"""
    
    if tier == 'core':
        enhanced_package_json += """,
    "@reduxjs/toolkit": "^1.9.3",
    "react-redux": "^8.0.5",
    "axios": "^1.3.4",
    "react-query": "^3.39.3"
"""
    elif tier == 'enterprise':
        enhanced_package_json += """,
    "@reduxjs/toolkit": "^1.9.3",
    "react-redux": "^8.0.5",
    "axios": "^1.3.4",
    "react-query": "^3.39.3",
    "@sentry/react": "^7.38.0",
    "react-helmet-async": "^1.3.0",
    "js-cookie": "^3.0.1"
"""
    
    enhanced_package_json += """
  },
  "devDependencies": {
    "@testing-library/react": "^13.4.0",
    "@testing-library/jest-dom": "^5.16.5",
    "@testing-library/user-event": "^14.4.3",
    "eslint": "^8.36.0",
    "prettier": "^2.8.4"
"""
    
    if tier == 'core':
        enhanced_package_json += """,
    "@testing-library/react-hooks": "^8.0.1",
    "msw": "^1.1.0"
"""
    elif tier == 'enterprise':
        enhanced_package_json += """,
    "@testing-library/react-hooks": "^8.0.1",
    "msw": "^1.1.0",
    "@storybook/react": "^6.5.16"
"""
    
    enhanced_package_json += """
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  }
}
"""
    
    # App.css
    app_css = f""".App {{
  text-align: center;
}}

.App-header {{
  background-color: #282c34;
  padding: 20px;
  color: white;
  margin-bottom: 20px;
}}

.App-content {{
  padding: 20px;
}}
"""
    
    # Create src directory for React files (standard Create React App structure)
    src_dir = project_path / 'src'
    src_dir.mkdir(exist_ok=True)
    
    (src_dir / 'App.jsx').write_text(app_jsx)
    (src_dir / 'App.test.jsx').write_text(test_jsx)
    (project_path / 'App.css').write_text(app_css)
    (project_path / '.env.example').write_text(env_example)
    (project_path / 'package.json').write_text(enhanced_package_json)
    (project_path / 'README.md').write_text(readme)

def create_node_project(project_path: Path, tier: str):
    """Create Node.js reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # app.js
    app_js = f"""const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get('/api/health', (req, res) => {{
  res.json({{ 
    status: 'ok', 
    message: '{tier.title()} Node.js Reference API',
    tier: '{tier}'
  }});
}});

app.get('/api/info', (req, res) => {{
  res.json({{
    name: '{tier.title()} Node.js Reference',
    version: '1.0.0',
    description: '{tier} tier Node.js reference project'
  }});
}});

// Only start server when run directly, not during tests
if (require.main === module) {{
  app.listen(PORT, () => {{
    console.log(`{tier.title()} Node.js server running on port ${{PORT}}`);
  }});
}}

module.exports = app;
"""
    
    # app.test.js
    test_js = f"""const request = require('supertest');
const app = require('./app');

describe('{tier.title()} Node.js API', () => {{
  test('GET /api/health', async () => {{
    const response = await request(app)
      .get('/api/health')
      .expect(200);
    
    expect(response.body.status).toBe('ok');
    expect(response.body.message).toContain('{tier.title()} Node.js Reference API');
  }});
  
  test('GET /api/info', async () => {{
    const response = await request(app)
      .get('/api/info')
      .expect(200);
    
    expect(response.body.name).toContain('{tier.title()} Node.js Reference');
  }});
}});
"""
    
    # package.json
    package_json = f"""{{
  "name": "{tier}-node-reference",
  "version": "1.0.0",
  "description": "{tier.title()} Node.js reference project",
  "main": "app.js",
  "scripts": {{
    "start": "node app.js",
    "test": "jest",
    "dev": "nodemon app.js"
  }},
  "dependencies": {{
    "express": "^4.18.2"
  }},
  "devDependencies": {{
    "jest": "^29.0.0",
    "supertest": "^6.3.0",
    "nodemon": "^3.0.0"
  }}
}}
"""
    
    # README.md
    readme = f"""# {tier.title()} Node.js Reference Project

## Overview
This is a reference-projects/[tier]/node-reference project demonstrating API development patterns.

## Features
- Express.js REST API
- Health check endpoint
- Comprehensive testing
"""
    
    if tier == 'core':
        readme += """
- Production configuration
- Error handling middleware
- Logging integration
- Environment variable management
"""
    elif tier == 'enterprise':
        readme += """
- Enterprise security features
- Rate limiting
- Request validation
- Audit logging
- Performance monitoring
"""
    
    readme += f"""
## Setup
```bash
npm install
npm start
```

## Testing
```bash
npm test
```

## API Endpoints
- GET /api/health - Health check
- GET /api/info - Application information
"""
    
    # .env.example
    env_example = f"""# {tier.title()} Node.js Environment Configuration
# Copy this file to .env and update with your values

# Server Configuration
PORT=3000
NODE_ENV={tier}

# Database Configuration
DATABASE_URL=mongodb://localhost:27017/{tier}_node_reference
DB_NAME={tier}_node_reference

# Security Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
API_KEY=your-api-key-here

# External Services
EXTERNAL_API_URL=https://api.example.com
EXTERNAL_API_KEY=your-external-api-key

# Logging Configuration
LOG_LEVEL={tier if tier != 'mvp' else 'info'}
LOG_FILE=logs/app.log
"""
    
    if tier == 'core':
        env_example += """\n# Core Tier Configuration
REDIS_URL=redis://localhost:6379
CACHE_TTL=3600
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
"""
    elif tier == 'enterprise':
        env_example += """\n# Enterprise Tier Configuration
REDIS_URL=redis://localhost:6379
CACHE_TTL=3600
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100

# Security & Compliance
CORS_ORIGIN=https://yourdomain.com
HELMET_ENABLED=true
AUDIT_LOG_FILE=logs/audit.log
SESSION_SECRET=your-session-secret-change-this

# Monitoring & Metrics
PROMETHEUS_PORT=9090
METRICS_ENABLED=true
HEALTH_CHECK_INTERVAL=30
"""
    
    # Enhanced package.json with tier-appropriate dependencies
    enhanced_package_json = f"""{{
  "name": "{tier}-node-reference",
  "version": "1.0.0",
  "description": "{tier.title()} Node.js reference project",
  "main": "app.js",
  "scripts": {{
    "start": "node app.js",
    "dev": "nodemon app.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint .",
    "lint:fix": "eslint . --fix"
  }},
  "dependencies": {{
    "express": "^4.18.2",
    "dotenv": "^16.3.1",
    "cors": "^2.8.5",
    "helmet": "^7.1.0"
"""
    
    if tier == 'core':
        enhanced_package_json += """,
    "mongoose": "^8.0.3",
    "redis": "^4.6.11",
    "express-rate-limit": "^7.1.5",
    "winston": "^3.11.0"
"""
    elif tier == 'enterprise':
        enhanced_package_json += """,
    "mongoose": "^8.0.3",
    "redis": "^4.6.11",
    "express-rate-limit": "^7.1.5",
    "winston": "^3.11.0",
    "express-session": "^1.17.3",
    "jsonwebtoken": "^9.0.2",
    "prom-client": "^15.1.0"
"""
    
    enhanced_package_json += """
  },
  "devDependencies": {
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "nodemon": "^3.0.2",
    "eslint": "^8.56.0"
"""
    
    if tier == 'core':
        enhanced_package_json += """,
    "mongodb-memory-server": "^9.1.3"
"""
    elif tier == 'enterprise':
        enhanced_package_json += """,
    "mongodb-memory-server": "^9.1.3",
    "jest-environment-node": "^29.7.0"
"""
    
    enhanced_package_json += """
  }
}
"""
    
    (project_path / 'app.js').write_text(app_js)
    (project_path / 'app.test.js').write_text(test_js)
    (project_path / '.env.example').write_text(env_example)
    (project_path / 'package.json').write_text(enhanced_package_json)
    (project_path / 'README.md').write_text(readme)

def create_go_project(project_path: Path, tier: str):
    """Create Go reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # main.go
    main_go = f"""package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

type HealthResponse struct {{
	Status  string `json:"status"`
	Message string `json:"message"`
	Tier    string `json:"tier"`
}}

type InfoResponse struct {{
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}}

func main() {{
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/info", infoHandler)
	
	port := os.Getenv("PORT")
	if port == "" {{
		port = "8080"
	}}
	
	log.Printf("{tier.title()} Go server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}}

func healthHandler(w http.ResponseWriter, r *http.Request) {{
	response := HealthResponse{{
		Status:  "ok",
		Message: fmt.Sprintf("{tier.title()} Go Reference API"),
		Tier:    "{tier}",
	}}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}}

func infoHandler(w http.ResponseWriter, r *http.Request) {{
	response := InfoResponse{{
		Name:        fmt.Sprintf("{tier.title()} Go Reference"),
		Version:     "1.0.0",
		Description: fmt.Sprintf("{tier} tier Go reference project"),
	}}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}}
"""
    
    # main_test.go
    test_go = f"""package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandler(t *testing.T) {{
	req, _ := http.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(healthHandler)
	
	handler.ServeHTTP(rr, req)
	
	if status := rr.Code; status != http.StatusOK {{
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}}
	
	var response HealthResponse
	json.Unmarshal(rr.Body.Bytes(), &response)
	
	if response.Status != "ok" {{
		t.Errorf("handler returned wrong status: got %v want %v", response.Status, "ok")
	}}
}}

func TestInfoHandler(t *testing.T) {{
	req, _ := http.NewRequest("GET", "/info", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(infoHandler)
	
	handler.ServeHTTP(rr, req)
	
	if status := rr.Code; status != http.StatusOK {{
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}}
	
	var response InfoResponse
	json.Unmarshal(rr.Body.Bytes(), &response)
	
	if response.Name != "{tier.title()} Go Reference" {{
		t.Errorf("handler returned wrong name: got %v want %v", response.Name, "{tier.title()} Go Reference")
	}}
}}
"""
    
    # go.mod
    go_mod = f"""module {tier}-go-reference

go 1.21
"""
    
    # README.md
    readme = f"""# {tier.title()} Go Reference Project

## Overview
This is a {tier} tier Go reference project demonstrating high-performance API development.

## Features
- HTTP server with standard library
- JSON API endpoints
- Comprehensive testing
"""
    
    if tier == 'core':
        readme += """
- Production configuration
- Graceful shutdown
- Structured logging
- Environment variable handling
"""
    elif tier == 'enterprise':
        readme += """
- Enterprise security patterns
- Request validation
- Rate limiting
- Performance monitoring
- Comprehensive error handling
"""
    
    readme += f"""
## Setup
```bash
go mod tidy
go run main.go
```

## Testing
```bash
go test ./...
```

## API Endpoints
- GET /health - Health check
- GET /info - Application information
"""
    
    # .env.example
    env_example = f"""# {tier.title()} Go Environment Configuration
# Copy this file to .env and update with your values

# Server Configuration
PORT=8080
GIN_MODE={tier if tier != 'mvp' else 'debug'}

# Database Configuration
DATABASE_URL=postgres://user:password@localhost:5432/{tier}_go_reference?sslmode=disable
DB_NAME={tier}_go_reference
DB_HOST=localhost
DB_PORT=5432
DB_USER=user
DB_PASSWORD=password

# Security Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
API_KEY=your-api-key-here

# External Services
EXTERNAL_API_URL=https://api.example.com
EXTERNAL_API_KEY=your-external-api-key

# Logging Configuration
LOG_LEVEL={tier if tier != 'mvp' else 'info'}
LOG_FILE=logs/app.log
"""
    
    if tier == 'core':
        env_example += """\n# Core Tier Configuration
REDIS_URL=redis://localhost:6379
CACHE_TTL=3600
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
MAX_CONNECTIONS=100
"""
    elif tier == 'enterprise':
        env_example += """\n# Enterprise Tier Configuration
REDIS_URL=redis://localhost:6379
CACHE_TTL=3600
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
MAX_CONNECTIONS=1000

# Security & Compliance
CORS_ORIGIN=https://yourdomain.com
TLS_CERT_FILE=certs/server.crt
TLS_KEY_FILE=certs/server.key
AUDIT_LOG_FILE=logs/audit.log

# Monitoring & Metrics
PROMETHEUS_PORT=9090
METRICS_ENABLED=true
HEALTH_CHECK_INTERVAL=30
GRACEFUL_SHUTDOWN_TIMEOUT=30
"""
    
    # Enhanced go.mod with tier-appropriate dependencies
    enhanced_go_mod = f"""module {tier}-go-reference

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/joho/godotenv v1.5.1
	github.com/gin-contrib/cors v1.4.0
"""
    
    if tier == 'core':
        enhanced_go_mod += """
	github.com/go-redis/redis/v8 v8.11.5
	github.com/lib/pq v1.10.9
	github.com/golang-jwt/jwt/v5 v5.1.0
	github.com/sirupsen/logrus v1.9.3
"""
    elif tier == 'enterprise':
        enhanced_go_mod += """
	github.com/go-redis/redis/v8 v8.11.5
	github.com/lib/pq v1.10.9
	github.com/golang-jwt/jwt/v5 v5.1.0
	github.com/sirupsen/logrus v1.9.3
	github.com/prometheus/client_golang v1.17.0
	golang.org/x/crypto v0.15.0
	github.com/gin-contrib/sessions v0.0.5
"""
    
    enhanced_go_mod += """
)
"""
    
    (project_path / 'main.go').write_text(main_go)
    (project_path / 'main_test.go').write_text(test_go)
    (project_path / '.env.example').write_text(env_example)
    (project_path / 'go.mod').write_text(enhanced_go_mod)
    (project_path / 'README.md').write_text(readme)

def create_python_project(project_path: Path, tier: str):
    """Create Python reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # app.py
    main_py = f"""from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify({{
        'status': 'ok',
        'message': '{tier.title()} Python Reference API',
        'tier': '{tier}'
    }})

@app.route('/info')
def info():
    return jsonify({{
        'name': '{tier.title()} Python Reference',
        'version': '1.0.0',
        'description': '{tier} tier Python reference project'
    }})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, port=port)
"""
    
    # test_main.py
    test_py = f"""import pytest
import sys
import os

# Add the current directory to Python path so we can import app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_health_endpoint(client):
    response = client.get('/health')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['status'] == 'ok'
    assert '{tier.title()} Python Reference API' in json_data['message']

def test_info_endpoint(client):
    response = client.get('/info')
    assert response.status_code == 200
    json_data = response.get_json()
    assert '{tier.title()} Python Reference' in json_data['name']
    assert json_data['version'] == '1.0.0'
"""
    
    # requirements.txt
    requirements = """Flask==2.3.3
pytest==8.2.0
pytest-asyncio>=0.21.0
"""
    
    # README.md
    readme = f"""# {tier.title()} Python Reference Project

## Overview
This is a reference-projects/[tier]/python-reference project demonstrating web API development patterns.

## Features
- Flask web framework
- REST API endpoints
- Comprehensive testing
"""
    
    if tier == 'core':
        readme += """
- Production configuration
- Error handling
- Logging integration
- Environment variable management
"""
    elif tier == 'enterprise':
        readme += """
- Enterprise security features
- Request validation
- Rate limiting
- Audit logging
- Performance monitoring
"""
    
    readme += f"""
## Setup
```bash
pip install -r requirements.txt
python app.py
```

## Testing
```bash
pytest
```

## API Endpoints
- GET /health - Health check
- GET /info - Application information
"""
    
    # .env.example
    env_example = f"""# {tier.title()} Python Environment Configuration
# Copy this file to .env and update with your values

# Flask Configuration
FLASK_APP=app.py
FLASK_ENV={tier if tier != 'mvp' else 'development'}
FLASK_DEBUG={tier == 'mvp'}

# Server Configuration
PORT=5000
HOST=0.0.0.0

# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/{tier}_python_reference
DB_NAME={tier}_python_reference
DB_HOST=localhost
DB_PORT=5432
DB_USER=user
DB_PASSWORD=password

# Security Configuration
SECRET_KEY=your-super-secret-key-change-this-in-production
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
API_KEY=your-api-key-here

# External Services
EXTERNAL_API_URL=https://api.example.com
EXTERNAL_API_KEY=your-external-api-key

# Logging Configuration
LOG_LEVEL={tier if tier != 'mvp' else 'INFO'}
LOG_FILE=logs/app.log
"""
    
    if tier == 'core':
        env_example += """\n# Core Tier Configuration
REDIS_URL=redis://localhost:6379/0
CACHE_TYPE=redis
CACHE_DEFAULT_TIMEOUT=300
RATELIMIT_STORAGE_URL=redis://localhost:6379/1
SQLALCHEMY_DATABASE_URI=postgresql://user:password@localhost:5432/core_python_reference
"""
    elif tier == 'enterprise':
        env_example += """\n# Enterprise Tier Configuration
REDIS_URL=redis://localhost:6379/0
CACHE_TYPE=redis
CACHE_DEFAULT_TIMEOUT=300
RATELIMIT_STORAGE_URL=redis://localhost:6379/1
SQLALCHEMY_DATABASE_URI=postgresql://user:password@localhost:5432/enterprise_python_reference

# Security & Compliance
CORS_ORIGINS=https://yourdomain.com
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
WTF_CSRF_ENABLED=True
AUDIT_LOG_FILE=logs/audit.log

# Monitoring & Metrics
PROMETHEUS_MULTIPROC_DIR=metrics
METRICS_ENABLED=True
HEALTH_CHECK_INTERVAL=30
"""
    
    # Enhanced requirements.txt with tier-appropriate dependencies
    enhanced_requirements = f"""Flask==2.3.3
pytest==8.2.0
pytest-asyncio>=0.21.0
python-dotenv==1.0.0
"""
    
    if tier == 'core':
        enhanced_requirements += """Flask-SQLAlchemy==3.1.1
Flask-Redis==0.4.0
Flask-Limiter==3.5.0
psycopg2-binary==2.9.9
gunicorn==21.2.0
"""
    elif tier == 'enterprise':
        enhanced_requirements += """Flask-SQLAlchemy==3.1.1
Flask-Redis==0.4.0
Flask-Limiter==3.5.0
Flask-JWT-Extended==4.6.0
prometheus-client==0.19.0
psycopg2-binary==2.9.9
gunicorn==21.2.0
cryptography==41.0.8
"""
    
    (project_path / 'app.py').write_text(main_py)
    (project_path / 'test_main.py').write_text(test_py)
    (project_path / '.env.example').write_text(env_example)
    (project_path / 'requirements.txt').write_text(enhanced_requirements)
    (project_path / 'README.md').write_text(readme)

def create_r_project(project_path: Path, tier: str):
    """Create R reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # main.R
    main_r = f"""# {tier.title()} R Reference Project
# Data analysis and visualization

library(ggplot2)
library(dplyr)
library(readr)

# Generate sample data
set.seed(123)
sample_data <- data.frame(
  x = rnorm(100),
  y = rnorm(100),
  category = sample(c('A', 'B', 'C'), 100, replace = TRUE)
)

# Basic analysis
summary_stats <- sample_data %>%
  group_by(category) %>%
  summarise(
    mean_x = mean(x),
    mean_y = mean(y),
    count = n()
  )

print(summary_stats)

# Create visualization
p <- ggplot(sample_data, aes(x = x, y = y, color = category)) +
  geom_point() +
  ggtitle('{tier.title()} R Data Visualization') +
  theme_minimal()

print(p)
"""
    
    # testthat.R
    test_r = f"""library(testthat)
source('main.R')

test('{tier.title()} R Analysis', {{
  # Test data generation
  expect_true(exists('sample_data'))
  expect_equal(nrow(sample_data), 100)
  expect_true('category' %in% names(sample_data))
  
  # Test analysis
  expect_true(exists('summary_stats'))
  expect_equal(nrow(summary_stats), 3)
  
  # Test visualization
  expect_true(exists('p'))
  expect_s3_class(p, 'ggplot')
}})
"""
    
    # README.md
    readme = f"""# {tier.title()} R Reference Project

## Overview
This is a {tier} tier R reference project demonstrating data analysis and visualization patterns.

## Features
- Data manipulation with dplyr
- Visualization with ggplot2
- Unit tests with testthat
"""
    
    if tier == 'core':
        readme += """
- Advanced statistical analysis
- Data export functionality
- Comprehensive error handling
"""
    elif tier == 'enterprise':
        readme += """
- Advanced statistical analysis
- Data export functionality
- Comprehensive error handling
- Production-ready reporting
- Automated data pipeline integration
"""
    
    readme += f"""
## Setup
```bash
# Install required packages
install.packages(c('ggplot2', 'dplyr', 'readr', 'testthat'))

# Run the analysis
Rscript main.R
```

## Testing
```bash
# Run tests
Rscript -e "testthat::test_dir('.')"
```
"""
    
    (project_path / 'main.R').write_text(main_r)
    (project_path / 'tests').mkdir(exist_ok=True)
    (project_path / 'tests' / 'testthat.R').write_text(test_r)
    (project_path / 'README.md').write_text(readme)

def create_sql_project(project_path: Path, tier: str):
    """Create SQL reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # schema.sql
    schema_sql = f"""-- {tier.title()} SQL Reference Project Schema
-- Database structure and tables

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""
    
    if tier == 'core':
        schema_sql += """
-- Products table
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    category VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Orders table
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL,
    total_amount DECIMAL(10,2) NOT NULL,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""
    elif tier == 'enterprise':
        schema_sql += """
-- Products table with constraints
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2) NOT NULL CHECK (price > 0),
    category VARCHAR(50),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Orders table with indexes
CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id) ON DELETE RESTRICT,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    total_amount DECIMAL(10,2) NOT NULL CHECK (total_amount > 0),
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'pending'
);

-- Indexes for performance
CREATE INDEX idx_orders_user_id ON orders(user_id);
CREATE INDEX idx_orders_date ON orders(order_date);
CREATE INDEX idx_products_category ON products(category);

-- Audit table for enterprise compliance
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    table_name VARCHAR(50) NOT NULL,
    operation VARCHAR(10) NOT NULL,
    user_id INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    old_values JSONB,
    new_values JSONB
);
"""
    
    # queries.sql
    queries_sql = f"""-- {tier.title()} SQL Reference Project Queries
-- Sample queries for data manipulation and analysis

-- Insert sample data
INSERT INTO users (username, email) VALUES 
    ('user1', 'user1@example.com'),
    ('user2', 'user2@example.com'),
    ('user3', 'user3@example.com');
"""
    
    if tier == 'core':
        queries_sql += """

-- Insert sample products
INSERT INTO products (name, price, category) VALUES 
    ('Product A', 29.99, 'Electronics'),
    ('Product B', 19.99, 'Books'),
    ('Product C', 49.99, 'Electronics');

-- Sample orders
INSERT INTO orders (user_id, product_id, quantity, total_amount) VALUES 
    (1, 1, 2, 59.98),
    (2, 2, 1, 19.99),
    (3, 3, 1, 49.99);

-- Analytical queries
SELECT 
    u.username,
    COUNT(o.id) as order_count,
    SUM(o.total_amount) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.username
ORDER BY total_spent DESC;
"""
    elif tier == 'enterprise':
        queries_sql += """

-- Insert sample products
INSERT INTO products (name, price, category, description) VALUES 
    ('Product A', 29.99, 'Electronics', 'High-quality electronic device'),
    ('Product B', 19.99, 'Books', 'Educational book'),
    ('Product C', 49.99, 'Electronics', 'Premium electronic device');

-- Sample orders with status
INSERT INTO orders (user_id, product_id, quantity, total_amount, status) VALUES 
    (1, 1, 2, 59.98, 'completed'),
    (2, 2, 1, 19.99, 'pending'),
    (3, 3, 1, 49.99, 'shipped');

-- Enterprise analytical queries
SELECT 
    u.username,
    COUNT(o.id) as order_count,
    SUM(CASE WHEN o.status = 'completed' THEN o.total_amount ELSE 0 END) as completed_revenue,
    SUM(o.total_amount) as total_spent,
    AVG(o.total_amount) as avg_order_value
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.username
HAVING COUNT(o.id) > 0
ORDER BY completed_revenue DESC;

-- Category performance analysis
SELECT 
    p.category,
    COUNT(o.id) as orders_count,
    SUM(o.total_amount) as revenue,
    AVG(o.total_amount) as avg_order_value
FROM products p
JOIN orders o ON p.id = o.product_id
WHERE o.status = 'completed'
GROUP BY p.category
ORDER BY revenue DESC;
"""
    
    # README.md
    readme = f"""# {tier.title()} SQL Reference Project

## Overview
This is a {tier} tier SQL reference project demonstrating database design and query patterns.

## Features
- Database schema design
- Sample data queries
- Basic data analysis
"""
    
    if tier == 'core':
        readme += """
- Relational database design
- Complex analytical queries
- Data integrity constraints
"""
    elif tier == 'enterprise':
        readme += """
- Relational database design
- Complex analytical queries
- Data integrity constraints
- Performance optimization with indexes
- Audit logging for compliance
"""
    
    readme += f"""
## Setup
```bash
# Create database and run schema
psql -d your_database -f schema.sql

# Insert sample data and run queries
psql -d your_database -f queries.sql
```

## Testing
```bash
# Validate SQL syntax
psql -d your_database -f schema.sql --dry-run
psql -d your_database -f queries.sql --dry-run
```
"""
    
    (project_path / 'schema.sql').write_text(schema_sql)
    (project_path / 'queries.sql').write_text(queries_sql)
    (project_path / 'README.md').write_text(readme)

def create_r_project(project_path: Path, tier: str):
    """Create R reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # analysis.R
    analysis_r = f"""# {tier.title()} R Data Analysis Project
# Generated reference implementation

# Load required libraries
library(dplyr)
library(ggplot2)
library(readr)
library(testthat)

# Sample data generation
set.seed(123)
n_samples <- 100
sample_data <- data.frame(
  x = rnorm(n_samples),
  y = rnorm(n_samples),
  category = sample(c('A', 'B', 'C'), n_samples, replace = TRUE)
)

# Basic analysis function
analyze_data <- function(data) {{
  summary_stats <- data %>%
    group_by(category) %>%
    summarise(
      mean_x = mean(x),
      mean_y = mean(y),
      count = n()
    )
  
  return(summary_stats)
}}

# Visualization function
create_plot <- function(data) {{
  p <- ggplot(data, aes(x = x, y = y, color = category)) +
    geom_point(size = 3, alpha = 0.7) +
    theme_minimal() +
    labs(
      title = "{tier.title()} R Data Analysis",
      x = "X Values",
      y = "Y Values",
      color = "Category"
    )
  
  return(p)
}}

# Main analysis
if (interactive()) {{
  results <- analyze_data(sample_data)
  print(results)
  
  plot <- create_plot(sample_data)
  print(plot)
}}

# Export results
write_csv(analyze_data(sample_data), "analysis_results.csv")
"""

    # test_analysis.R
    test_analysis_r = f"""# Test suite for {tier.title()} R Analysis Project
library(testthat)
library(dplyr)

# Test data generation
test_data <- data.frame(
  x = c(1, 2, 3, 4, 5),
  y = c(2, 4, 6, 8, 10),
  category = c('A', 'A', 'B', 'B', 'C')
)

# Test analysis function
test_that("analyze_data works correctly", {{
  source("analysis.R", local = TRUE)
  
  results <- analyze_data(test_data)
  expect_true(is.data.frame(results))
  expect_true('category' %in% names(results))
  expect_equal(nrow(results), 3)
}})

# Test visualization function
test_that("create_plot generates plot", {{
  source("analysis.R", local = TRUE)
  
  plot <- create_plot(test_data)
  expect_s3_class(plot, "ggplot")
}})

# Test data integrity
test_that("sample data has correct structure", {{
  expect_true(is.data.frame(sample_data))
  expect_true(all(c('x', 'y', 'category') %in% names(sample_data)))
  expect_equal(nrow(sample_data), 100)
}})
"""

    # requirements.txt (R packages)
    requirements_txt = f"""# R Package Dependencies for {tier.title()} Tier Project
# Generated for {{.ProjectName}}

# Data manipulation
dplyr >= 1.1.0
tidyr >= 1.3.0
readr >= 2.1.0

# Data visualization
ggplot2 >= 3.4.0
{tier != 'mvp' and 'shiny >= 1.7.0' or ''}

# Web requests and APIs
{tier != 'mvp' and 'httr >= 1.4.0' or ''}
{tier != 'mvp' and 'jsonlite >= 1.8.0' or ''}

# Database connectivity
{tier == 'enterprise' and 'DBI >= 1.1.0' or ''}
{tier == 'enterprise' and 'RPostgres >= 1.4.0' or ''}

# Testing
testthat >= 3.1.0

# Configuration
{tier != 'mvp' and 'config >= 0.3.0' or ''}
{tier != 'mvp' and 'yaml >= 2.3.0' or ''}

# Utilities
purrr >= 1.0.0
stringr >= 1.5.0
{tier != 'mvp' and 'lubridate >= 1.9.0' or ''}
"""

    # README.md
    readme = f"""# {tier.title()} R Reference Project

This is a {tier} tier R reference project demonstrating data analysis and visualization patterns.

## Features
- R data analysis with dplyr
- Data visualization with ggplot2
- {tier != 'mvp' and 'Web API integration with httr' or 'Basic data processing'}
- {tier != 'mvp' and 'Configuration management' or 'Simple configuration'}
- {tier == 'enterprise' and 'Database connectivity' or ''}
- Comprehensive testing with testthat

## Quick Start

```bash
# Install dependencies
Rscript -e "install.packages(c('dplyr', 'ggplot2', 'readr', 'testthat'))"

# Run analysis
Rscript analysis.R

# Run tests
Rscript -e "testthat::test_dir('.')"
```

## Project Structure
```
├── analysis.R          # Main analysis script
├── test_analysis.R     # Test suite
├── requirements.txt    # R package dependencies
├── .env.example        # Environment variables template
└── README.md          # This file
```

## Usage Examples

### Data Analysis
```r
source("analysis.R")
results <- analyze_data(sample_data)
print(results)
```

### Visualization
```r
source("analysis.R")
plot <- create_plot(sample_data)
print(plot)
```

## Testing
```bash
# Run all tests
Rscript -e "testthat::test_dir('.')"

# Run specific test
Rscript -e "testthat::test_file('test_analysis.R')"
```
"""

    # .env.example
    env_example = f"""# {tier.title()} R Environment Configuration
# Copy this file to .env and update values

# Data Configuration
DATA_SOURCE=local
DATA_PATH=./data/
OUTPUT_PATH=./output/

{tier != 'mvp' and '# API Configuration' or ''}
{tier != 'mvp' and 'API_BASE_URL=https://api.example.com' or ''}
{tier != 'mvp' and 'API_TIMEOUT=30' or ''}

{tier == 'enterprise' and '# Database Configuration' or ''}
{tier == 'enterprise' and 'DB_HOST=localhost' or ''}
{tier == 'enterprise' and 'DB_PORT=5432' or ''}
{tier == 'enterprise' and 'DB_NAME=r_analysis' or ''}
{tier == 'enterprise' and 'DB_USER=r_user' or ''}

# Analysis Configuration
SEED=123
SAMPLE_SIZE=100
PLOT_THEME=minimal
"""

    # Write files
    (project_path / 'analysis.R').write_text(analysis_r, encoding='utf-8')
    (project_path / 'test_analysis.R').write_text(test_analysis_r, encoding='utf-8')
    (project_path / 'requirements.txt').write_text(requirements_txt, encoding='utf-8')
    (project_path / 'README.md').write_text(readme, encoding='utf-8')
    (project_path / '.env.example').write_text(env_example, encoding='utf-8')

def create_sql_project(project_path: Path, tier: str):
    """Create SQL reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # schema.sql
    schema_sql = f"""-- {tier.title()} SQL Database Schema
-- Generated reference implementation

-- Core tables
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    category_id INTEGER REFERENCES categories(id),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

{tier != 'mvp' and '''
-- Audit table for enterprise features
CREATE TABLE IF NOT EXISTS audit_trail (
    id SERIAL PRIMARY KEY,
    table_name VARCHAR(100),
    operation VARCHAR(10),
    record_id INTEGER,
    old_values JSONB,
    new_values JSONB,
    user_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
''' or ''}

{tier == 'enterprise' and '''
-- Security table for enterprise features
CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    session_token VARCHAR(255) UNIQUE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    resource VARCHAR(100),
    action VARCHAR(50),
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
''' or ''}

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category_id);
{tier != 'mvp' and 'CREATE INDEX IF NOT EXISTS idx_audit_trail_created_at ON audit_trail(created_at);' or ''}
{tier == 'enterprise' and 'CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token);' or ''}

-- Triggers for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_products_updated_at BEFORE UPDATE ON products
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
"""

    # procedures.sql
    procedures_sql = f"""-- {tier.title()} SQL Stored Procedures
-- Generated reference implementation

-- Basic CRUD procedures
CREATE OR REPLACE FUNCTION get_user_by_id(user_id INTEGER)
RETURNS TABLE (
    id INTEGER,
    username VARCHAR(50),
    email VARCHAR(100),
    created_at TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT u.id, u.username, u.email, u.created_at
    FROM users u
    WHERE u.id = user_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_products_by_category(category_name VARCHAR)
RETURNS TABLE (
    id INTEGER,
    name VARCHAR(200),
    price DECIMAL(10,2),
    description TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT p.id, p.name, p.price, p.description
    FROM products p
    JOIN categories c ON p.category_id = c.id
    WHERE c.name = category_name;
END;
$$ LANGUAGE plpgsql;

{tier != 'mvp' and '''
-- Advanced procedures for core/enterprise tiers
CREATE OR REPLACE FUNCTION create_product_with_audit(
    product_name VARCHAR,
    product_price DECIMAL,
    category_id INTEGER,
    user_id INTEGER
)
RETURNS INTEGER AS $$
DECLARE
    new_product_id INTEGER;
BEGIN
    INSERT INTO products (name, price, category_id)
    VALUES (product_name, product_price, category_id)
    RETURNING id INTO new_product_id;
    
    INSERT INTO audit_trail (table_name, operation, record_id, user_id)
    VALUES ('products', 'INSERT', new_product_id, user_id);
    
    RETURN new_product_id;
END;
$$ LANGUAGE plpgsql;
''' or ''}

{tier == 'enterprise' and '''
-- Enterprise security procedures
CREATE OR REPLACE FUNCTION verify_user_session(session_token VARCHAR)
RETURNS TABLE (
    user_id INTEGER,
    username VARCHAR(50),
    is_valid BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT u.id, u.username, 
           CASE WHEN s.expires_at > CURRENT_TIMESTAMP THEN true ELSE false END as is_valid
    FROM users u
    JOIN user_sessions s ON u.id = s.user_id
    WHERE s.session_token = session_token;
END;
$$ LANGUAGE plpgsql;
''' or ''}

-- Utility functions
CREATE OR REPLACE FUNCTION get_database_stats()
RETURNS TABLE (
    table_name VARCHAR,
    record_count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        schemaname||'.'||tablename as table_name,
        n_tup_ins - n_tup_del as record_count
    FROM pg_stat_user_tables
    WHERE schemaname = 'public';
END;
$$ LANGUAGE plpgsql;
"""

    # test_data.sql
    test_data_sql = f"""-- {tier.title()} SQL Test Data
-- Generated reference implementation

-- Insert sample categories
INSERT INTO categories (name, description) VALUES 
    ('Electronics', 'Electronic devices and gadgets'),
    ('Books', 'Books and educational materials'),
    ('Clothing', 'Apparel and fashion items');

-- Insert sample users
INSERT INTO users (username, email, password_hash) VALUES 
    ('john_doe', 'john@example.com', 'hashed_password_1'),
    ('jane_smith', 'jane@example.com', 'hashed_password_2'),
    ('bob_wilson', 'bob@example.com', 'hashed_password_3');

-- Insert sample products
INSERT INTO products (name, price, category_id, description) VALUES 
    ('Smartphone', 699.99, 1, 'Latest smartphone with advanced features'),
    ('Laptop', 1299.99, 1, 'High-performance laptop for professionals'),
    ('Programming Book', 49.99, 2, 'Learn programming from scratch'),
    ('Fiction Novel', 19.99, 2, 'Bestselling fiction novel'),
    ('T-Shirt', 29.99, 3, 'Comfortable cotton t-shirt'),
    ('Jeans', 79.99, 3, 'Classic denim jeans');

{tier != 'mvp' and '''
-- Insert sample audit data
INSERT INTO audit_trail (table_name, operation, record_id, user_id, old_values, new_values) VALUES 
    ('products', 'INSERT', 1, 1, '{}', '{"name": "Smartphone", "price": 699.99}'),
    ('products', 'INSERT', 2, 1, '{}', '{"name": "Laptop", "price": 1299.99}'),
    ('users', 'INSERT', 1, 1, '{}', '{"username": "john_doe"}');
''' or ''}

{tier == 'enterprise' and '''
-- Insert sample session data
INSERT INTO user_sessions (user_id, session_token, expires_at) VALUES 
    (1, 'session_token_123', CURRENT_TIMESTAMP + INTERVAL '1 day'),
    (2, 'session_token_456', CURRENT_TIMESTAMP + INTERVAL '1 day'),
    (3, 'session_token_789', CURRENT_TIMESTAMP + INTERVAL '1 day');

-- Insert sample permissions
INSERT INTO permissions (user_id, resource, action) VALUES 
    (1, 'products', 'read'),
    (1, 'products', 'write'),
    (2, 'products', 'read'),
    (3, 'users', 'read');
''' or ''}
"""

    # README.md
    readme = f"""# {tier.title()} SQL Reference Project

This is a {tier} tier SQL reference project demonstrating database design and stored procedures.

## Features
- PostgreSQL database schema
- Stored procedures and functions
- {tier != 'mvp' and 'Audit trail functionality' or 'Basic CRUD operations'}
- {tier == 'enterprise' and 'Security and session management' or ''}
- Performance optimization with indexes
- Comprehensive test data

## Quick Start

```bash
# Create database
createdb {tier}_sql_reference

# Load schema
psql -d {tier}_sql_reference -f schema.sql

# Load procedures
psql -d {tier}_sql_reference -f procedures.sql

# Load test data
psql -d {tier}_sql_reference -f test_data.sql
```

## Project Structure
```
├── schema.sql         # Database schema and tables
├── procedures.sql     # Stored procedures and functions
├── test_data.sql      # Sample data for testing
├── .env.example       # Environment variables template
└── README.md         # This file
```

## Usage Examples

### Basic Queries
```sql
-- Get all products
SELECT * FROM products;

-- Get products by category
SELECT * FROM get_products_by_category('Electronics');
```

### Stored Procedures
```sql
-- Get user by ID
SELECT * FROM get_user_by_id(1);

-- Get database statistics
SELECT * FROM get_database_stats();
```

{tier != 'mvp' and '''
### Advanced Features
```sql
-- Create product with audit trail
SELECT create_product_with_audit('New Product', 99.99, 1, 1);
```
''' or ''}

## Testing
```bash
# Run all SQL files in order
psql -d {tier}_sql_reference -f schema.sql
psql -d {tier}_sql_reference -f procedures.sql
psql -d {tier}_sql_reference -f test_data.sql

# Verify data
psql -d {tier}_sql_reference -c "SELECT COUNT(*) FROM products;"
```
"""

    # .env.example
    env_example = f"""# {tier.title()} SQL Environment Configuration
# Copy this file to .env and update values

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME={tier}_sql_reference
DB_USER=sql_user
DB_PASSWORD=your_password

# Connection Settings
DB_SSL_MODE=prefer
DB_CONNECTION_TIMEOUT=30
DB_POOL_SIZE=10

{tier != 'mvp' and '# Audit Configuration' or ''}
{tier != 'mvp' and 'AUDIT_ENABLED=true' or ''}
{tier != 'mvp' and 'AUDIT_RETENTION_DAYS=90' or ''}

{tier == 'enterprise' and '# Security Configuration' or ''}
{tier == 'enterprise' and 'SESSION_TIMEOUT=3600' or ''}
{tier == 'enterprise' and 'MAX_LOGIN_ATTEMPTS=5' or ''}
{tier == 'enterprise' and 'PASSWORD_MIN_LENGTH=12' or ''}

# Development Settings
DEV_MODE=true
LOG_LEVEL=INFO
"""

    # Write files
    (project_path / 'schema.sql').write_text(schema_sql, encoding='utf-8')
    (project_path / 'procedures.sql').write_text(procedures_sql, encoding='utf-8')
    (project_path / 'test_data.sql').write_text(test_data_sql, encoding='utf-8')
    (project_path / 'README.md').write_text(readme, encoding='utf-8')
    (project_path / '.env.example').write_text(env_example, encoding='utf-8')

def create_next_project(project_path: Path, tier: str):
    """Create Next.js reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # pages/index.jsx
    index_jsx = f"""import React from 'react';
import Head from 'next/head';

export default function Home() {{
  return (
    <div>
      <Head>
        <title>{tier.title()} Next.js Reference</title>
        <meta name="description" content="{tier} tier Next.js reference project" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <main>
        <h1>{tier.title()} Next.js Reference Project</h1>
        <p>
          Welcome to your {tier} tier Next.js application!
        </p>
        <div>
          <h2>Features</h2>
          <ul>
            <li>Next.js {tier != 'mvp' and 'with API routes' or 'basic routing'}</li>
            <li>{tier != 'mvp' and 'Server-side rendering' or 'Client-side rendering'}</li>
            <li>{tier == 'enterprise' and 'Enterprise security' or 'Basic security'}</li>
            <li>{tier != 'mvp' and 'Performance optimization' or 'Simple setup'}</li>
          </ul>
        </div>
      </main>

      <footer>
        <p>Powered by Next.js</p>
      </footer>

      <style jsx>{{`
        main {{
          padding: 2rem;
          max-width: 800px;
          margin: 0 auto;
        }}
        h1 {{
          color: #0070f3;
        }}
        footer {{
          text-align: center;
          margin-top: 2rem;
        }}
      `}}</style>
    </div>
  );
}}
"""

    # pages/api/hello.jsx
    api_hello_jsx = f"""// Next.js API route for {tier.title()} tier
export default function handler(req, res) {{
  const {{ method, query }} = req;
  
  if (method === 'GET') {{
    res.status(200).json({{
      message: 'Hello from {tier.title()} Next.js API!',
      timestamp: new Date().toISOString(),
      {tier != 'mvp' and '''
      environment: process.env.NODE_ENV,
      version: '1.0.0',''' or ''}
      query: query
    }});
  }} else {{
    res.setHeader('Allow', ['GET']);
    res.status(405).json({{ error: 'Method not allowed' }});
  }}
}}
"""

    # pages/about.jsx
    about_jsx = f"""import React from 'react';
import Head from 'next/head';

export default function About() {{
  return (
    <div>
      <Head>
        <title>About - {tier.title()} Next.js</title>
      </Head>

      <main>
        <h1>About {tier.title()} Next.js Reference</h1>
        <p>
          This is a {tier} tier Next.js reference project demonstrating:
        </p>
        <ul>
          <li>Modern React patterns with Next.js</li>
          <li>{tier != 'mvp' and 'Server-side rendering and API routes' or 'Basic routing'}</li>
          <li>{tier == 'enterprise' and 'Enterprise-grade features' or 'Production-ready setup'}</li>
          <li>Performance optimization</li>
        </ul>
      </main>
    </div>
  );
}}
"""

    # tests/pages.test.jsx
    pages_test_jsx = f"""// Test suite for {tier.title()} Next.js pages
import {{ render, screen }} from '@testing-library/react';
import Home from '../pages/index';
import About from '../pages/about';

describe('Pages', () => {{
  test('Home page renders correctly', () => {{
    render(<Home />);
    expect(screen.getByText('{tier.title()} Next.js Reference Project')).toBeInTheDocument();
    expect(screen.getByText('Welcome to your {tier} tier Next.js application!')).toBeInTheDocument();
  }});

  test('About page renders correctly', () => {{
    render(<About />);
    expect(screen.getByText('About {tier.title()} Next.js Reference')).toBeInTheDocument();
    expect(screen.getByText('Modern React patterns with Next.js')).toBeInTheDocument();
  }});

  {tier != 'mvp' and '''
  test('Home page includes tier-appropriate features', () => {
    render(<Home />);
    expect(screen.getByText('Next.js with API routes')).toBeInTheDocument();
  });
  ''' or ''}
}});
"""

    # package.json
    package_json = f"""{{
  "name": "{tier}-next-reference",
  "version": "1.0.0",
  "description": "{tier.title()} Next.js reference project",
  "scripts": {{
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    "test": "jest",
    "test:watch": "jest --watch"
  }},
  "dependencies": {{
    "next": "^14.0.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0"{tier != 'mvp' and ',' or ''}
    {tier != 'mvp' and '"axios": "^1.6.0"' or ''}
    {tier == 'enterprise' and ',"next-auth": "^4.24.0"' or ''}
  }},
  "devDependencies": {{
    "@types/node": "^20.0.0",
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "eslint": "^8.0.0",
    "eslint-config-next": "^14.0.0",
    "jest": "^29.0.0",
    "@testing-library/react": "^13.4.0",
    "@testing-library/jest-dom": "^6.0.0",
    "typescript": "^5.0.0"
  }}
}}
"""

    # README.md
    readme = f"""# {tier.title()} Next.js Reference Project

This is a {tier} tier Next.js reference project demonstrating modern web development patterns.

## Features
- Next.js 14 with React 18
- {tier != 'mvp' and 'API routes and server-side rendering' or 'Basic client-side routing'}
- {tier != 'mvp' and 'Static site generation' or 'Simple setup'}
- {tier == 'enterprise' and 'Authentication and security' or 'Basic security'}
- Performance optimization
- Comprehensive testing

## Quick Start

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Start production server
npm start

# Run tests
npm test
```

## Project Structure
```
├── pages/
│   ├── index.jsx         # Home page
│   ├── about.jsx         # About page
│   └── api/
│       └── hello.jsx     # API route
├── tests/
│   └── pages.test.jsx    # Test suite
├── package.json          # Dependencies and scripts
├── .env.example          # Environment variables template
└── README.md            # This file
```

## Usage Examples

### Pages
- Home page: `http://localhost:3000`
- About page: `http://localhost:3000/about`

### API Routes
```bash
# Test API endpoint
curl http://localhost:3000/api/hello
```

### Development
```bash
# Run with environment variables
cp .env.example .env
npm run dev
```

## Testing
```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run with coverage
npm test -- --coverage
```
"""

    # .env.example
    env_example = f"""# {tier.title()} Next.js Environment Configuration
# Copy this file to .env.local and update values

# Next.js Configuration
NODE_ENV=development
NEXT_PUBLIC_APP_NAME={tier.title()} Next.js Reference
NEXT_PUBLIC_APP_VERSION=1.0.0

{tier != 'mvp' and '# API Configuration' or ''}
{tier != 'mvp' and 'NEXT_PUBLIC_API_URL=http://localhost:3000/api' or ''}
{tier != 'mvp' and 'API_TIMEOUT=10000' or ''}

{tier == 'enterprise' and '# Authentication' or ''}
{tier == 'enterprise' and 'NEXTAUTH_URL=http://localhost:3000' or ''}
{tier == 'enterprise' and 'NEXTAUTH_SECRET=your-secret-key' or ''}

# Development Settings
NEXT_PUBLIC_DEV_MODE=true
PORT=3000
"""

    # Write files
    (project_path / 'pages').mkdir(exist_ok=True)
    (project_path / 'pages' / 'api').mkdir(exist_ok=True)
    (project_path / 'tests').mkdir(exist_ok=True)
    
    (project_path / 'pages' / 'index.jsx').write_text(index_jsx, encoding='utf-8')
    (project_path / 'pages' / 'api' / 'hello.jsx').write_text(api_hello_jsx, encoding='utf-8')
    (project_path / 'pages' / 'about.jsx').write_text(about_jsx, encoding='utf-8')
    (project_path / 'tests' / 'pages.test.jsx').write_text(pages_test_jsx, encoding='utf-8')
    (project_path / 'package.json').write_text(package_json, encoding='utf-8')
    (project_path / 'README.md').write_text(readme, encoding='utf-8')
    (project_path / '.env.example').write_text(env_example, encoding='utf-8')

def create_generic_project(project_path: Path, tier: str):
    """Create Generic reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # Tier descriptions for generic projects
    tier_descriptions = {
        "mvp": "Rapid prototyping with essential patterns for quick validation",
        "core": "Production-ready patterns with comprehensive features",
        "enterprise": "Advanced patterns with scalability and security considerations"
    }
    
    # Generic README with technology selection guidance
    readme = f"""# Generic {tier.title()} Reference Project

> **Generic Technology Stack Template** - Choose your technology stack below

## 🎯 Choose Your Technology Stack

This is a **generic template** designed to work with any technology stack. Select your preferred stack:

### **Popular Stacks**
- [🐍 Python](./python-setup.md) - FastAPI, Django, Flask
- [🟢 Node.js](./nodejs-setup.md) - Express, NestJS, Next.js  
- [🔷 Go](./go-setup.md) - Gin, Echo, Fiber
- [☕ Java](./java-setup.md) - Spring Boot, Quarkus
- [🦀 Rust](./rust-setup.md) - Actix, Rocket, Axum

## 🚀 Quick Start

1. **Select your stack** from the sections above
2. **Follow setup instructions** for your chosen technology
3. **Adapt the patterns** to your specific needs
4. **Test thoroughly** with the provided testing patterns

## 📁 Project Structure

```
generic-{tier}-reference/
├── docs/                    # Documentation templates
│   ├── README.md           # Main documentation with stack selection
│   └── setup-guide.md      # Detailed setup instructions
├── code/                   # Code pattern templates
│   ├── config-management-pattern.md
│   ├── error-handling-pattern.md
│   ├── http-client-pattern.md
│   ├── logging-pattern.md
│   ├── authentication-pattern.md
│   └── data-validation-pattern.md
├── tests/                  # Testing pattern templates
│   ├── unit-tests-pattern.md
│   ├── integration-tests-pattern.md
│   └── test-utilities-pattern.md
└── dependencies.txt       # Dependency management template
```

## 🛠️ Core Patterns

This template provides universal design patterns that work across all technology stacks:

- **Configuration Management** - Environment-based config with validation
- **Error Handling** - Structured error management with logging
- **HTTP Client** - Robust API communication with retries
- **Logging** - Structured logging with multiple outputs
- **Authentication** - JWT, OAuth, and session-based auth
- **Data Validation** - Input validation and sanitization

## 📚 Documentation

- [Setup Guide](./setup-guide.md) - Detailed setup for all stacks
- [Code Patterns](./code/) - Implementation patterns with examples
- [Testing Patterns](./tests/) - Testing strategies and utilities

## 🎯 Tier: {tier.title()}

This is a **{tier}** tier reference project:
{tier_descriptions.get(tier, 'Customizable template with adaptable patterns')}

## 🤝 Contributing

1. Choose your technology stack
2. Implement the patterns using your chosen stack
3. Add stack-specific examples and optimizations
4. Test thoroughly with the provided testing patterns

---

**Generic Stack Template**  
**Tier**: {tier}  
**Adaptable to any technology stack**
"""
    
    # Generic setup guide
    setup_guide = f"""# Generic Setup Guide

## 🎯 Technology Stack Selection

This setup guide supports multiple technology stacks. **Select your stack below:**

- [🐍 Python Setup](#python-setup)
- [🟢 Node.js Setup](#nodejs-setup)  
- [🔷 Go Setup](#go-setup)
- [☕ Java Setup](#java-setup)
- [🦀 Rust Setup](#rust-setup)

## 🐍 Python Setup

### Prerequisites
- Python 3.9+
- pip or poetry

### Installation
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate

# Install dependencies
pip install fastapi uvicorn pydantic
```

## 🟢 Node.js Setup

### Prerequisites
- Node.js 16+
- npm or yarn

### Installation
```bash
# Initialize project
npm init -y

# Install dependencies
npm install express jsonwebtoken
npm install -D typescript @types/node
```

## 🔷 Go Setup

### Prerequisites
- Go 1.19+

### Installation
```bash
# Initialize module
go mod init example.com/project

# Install dependencies
go get github.com/gin-gonic/gin
go get github.com/golang-jwt/jwt/v5
```

## 🚀 Next Steps

1. **Choose your stack** from the sections above
2. **Follow the setup instructions** for your chosen technology
3. **Implement the patterns** using your stack's best practices
4. **Test your implementation** with the provided testing patterns

---

**Generic Setup Guide**  
**Adaptable to any technology stack**
"""
    
    # Create directory structure
    (project_path / 'code').mkdir(exist_ok=True)
    (project_path / 'tests').mkdir(exist_ok=True)
    (project_path / 'docs').mkdir(exist_ok=True)
    
    # Write documentation files
    (project_path / 'README.md').write_text(readme, encoding='utf-8')
    (project_path / 'docs' / 'setup-guide.md').write_text(setup_guide, encoding='utf-8')
    
    # Create placeholder files for patterns
    pattern_files = [
        'config-management-pattern.md',
        'error-handling-pattern.md', 
        'http-client-pattern.md',
        'logging-pattern.md',
        'authentication-pattern.md',
        'data-validation-pattern.md'
    ]
    
    for pattern_file in pattern_files:
        content = f"""# {pattern_file.replace('-', ' ').replace('.md', '').title()}

> **Generic Pattern** - Adapt this pattern to your technology stack

## Overview
This pattern provides a technology-agnostic approach to {pattern_file.replace('-', ' ').replace('.md', '')} that can be adapted to any programming language or framework.

## Implementation Examples

See the main [README](../README.md) for technology-specific implementation guides.

## Adaptation Checklist

- [ ] Choose appropriate libraries for your technology stack
- [ ] Implement the pattern following your language's conventions
- [ ] Add comprehensive tests for your implementation
- [ ] Document any stack-specific considerations

---

*Generic {pattern_file.replace('-', ' ').replace('.md', '').title()} Pattern*
"""
        (project_path / 'code' / pattern_file).write_text(content, encoding='utf-8')
    
    # Create testing pattern files
    test_files = [
        'unit-tests-pattern.md',
        'integration-tests-pattern.md',
        'test-utilities-pattern.md'
    ]
    
    for test_file in test_files:
        content = f"""# {test_file.replace('-', ' ').replace('.md', '').title()}

> **Generic Testing Pattern** - Adapt to your testing framework

## Overview
This pattern provides universal testing approaches that work across different testing frameworks and technology stacks.

## Framework Examples

- **Python**: pytest, unittest
- **Node.js**: Jest, Mocha
- **Go**: testing package, testify

## Implementation

See the main [README](../README.md) for detailed implementation guides.

---

*Generic {test_file.replace('-', ' ').replace('.md', '').title()} Pattern*
"""
        (project_path / 'tests' / test_file).write_text(content, encoding='utf-8')
    
    # Create dependencies template
    dependencies = """# Dependencies Template

## Choose Your Package Manager

### Python (pip/poetry)
```
fastapi>=0.68.0
uvicorn>=0.15.0
pydantic>=1.8.0
```

### Node.js (npm/yarn)
```json
{
  "dependencies": {
    "express": "^4.18.0",
    "jsonwebtoken": "^8.5.0"
  }
}
```

### Go (go.mod)
```
module example.com/project

go 1.19

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/golang-jwt/jwt/v5 v5.0.0
)
```

## Adaptation Guide

1. **Select your package manager** based on your technology stack
2. **Add stack-specific dependencies** for your chosen libraries
3. **Include development dependencies** for testing and tooling
4. **Update versions** according to your project requirements

---

*Generic Dependencies Template*
"""
    (project_path / 'dependencies.txt').write_text(dependencies, encoding='utf-8')

def create_typescript_project(project_path: Path, tier: str):
    """Create TypeScript reference project"""
    project_path.mkdir(parents=True, exist_ok=True)
    
    # Tier descriptions for TypeScript projects
    tier_descriptions = {
        "mvp": "Rapid TypeScript development with essential patterns",
        "core": "Production-ready TypeScript with comprehensive type safety",
        "enterprise": "Advanced TypeScript with enterprise patterns and scalability"
    }
    
    # TypeScript package.json
    package_json = f"""{{
  "name": "typescript-{tier}-reference",
  "version": "1.0.0",
  "description": "TypeScript {tier} reference project",
  "main": "dist/index.js",
  "scripts": {{
    "build": "tsc",
    "start": "node dist/index.js",
    "dev": "ts-node-dev --respawn --transpile-only src/index.ts",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "type-check": "tsc --noEmit",
    "clean": "rimraf dist"
  }},
  "dependencies": {{
    "express": "^4.18.0",
    "cors": "^2.8.5",
    "helmet": "^6.0.0",
    "dotenv": "^16.0.0",
    "joi": "^17.7.0",
    "jsonwebtoken": "^9.0.0",
    "bcryptjs": "^2.4.3",
    "winston": "^3.8.0"
  }},
  "devDependencies": {{
    "@types/node": "^18.0.0",
    "@types/express": "^4.17.0",
    "@types/cors": "^2.8.0",
    "@types/jest": "^29.0.0",
    "@types/jsonwebtoken": "^9.0.0",
    "@types/bcryptjs": "^2.4.0",
    "@typescript-eslint/eslint-plugin": "^5.0.0",
    "@typescript-eslint/parser": "^5.0.0",
    "eslint": "^8.0.0",
    "jest": "^29.0.0",
    "ts-jest": "^29.0.0",
    "ts-node-dev": "^2.0.0",
    "typescript": "^4.9.0",
    "rimraf": "^3.0.0"
  }},
  "engines": {{
    "node": ">=18.0.0",
    "npm": ">=8.0.0"
  }}
}}
"""
    
    # TypeScript configuration
    tsconfig_json = """{
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
    "sourceMap": true,
    "removeComments": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "noImplicitThis": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "moduleResolution": "node",
    "baseUrl": "./",
    "paths": {
      "@/*": ["src/*"]
    },
    "allowSyntheticDefaultImports": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,
    "incremental": true,
    "tsBuildInfoFile": ".tsbuildinfo"
  },
  "include": [
    "src/**/*"
  ],
  "exclude": [
    "node_modules",
    "dist",
    "**/*.test.ts",
    "**/*.spec.ts"
  ]
}
"""
    
    # Jest configuration
    jest_config = """module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  setupFilesAfterEnv: ['<rootDir>/src/test/setup.ts'],
};
"""
    
    # ESLint configuration
    eslint_config = """module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: 'tsconfig.json',
    tsconfigRootDir: __dirname,
    sourceType: 'module',
  },
  plugins: ['@typescript-eslint/eslint-plugin'],
  extends: [
    'eslint:recommended',
    '@typescript-eslint/recommended',
    '@typescript-eslint/recommended-requiring-type-checking',
  ],
  root: true,
  env: {
    node: true,
    jest: true,
  },
  ignorePatterns: ['.eslintrc.js', 'dist/**/*'],
  rules: {
    '@typescript-eslint/interface-name-prefix': 'off',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-unused-vars': 'error',
    '@typescript-eslint/prefer-const': 'error',
  },
};
"""
    
    # Main TypeScript file
    main_ts = """import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'TypeScript {tier} Reference Project',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok',
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 TypeScript server running on port ${{PORT}}`);
});

export default app;
""".format(tier=tier)
    
    # Test setup file
    test_setup = """import 'jest';

// Global test setup
beforeAll(() => {
  // Set test environment variables
  process.env.NODE_ENV = 'test';
  process.env.JWT_SECRET = 'test-secret';
});

afterAll(() => {
  // Cleanup after tests
});

// Mock console methods in tests
global.console = {
  ...console,
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
};
"""
    
    # Basic test file
    app_test_ts = """import request from 'supertest';
import app from '../index';

describe('TypeScript App', () => {
  it('should respond with welcome message', async () => {
    const response = await request(app)
      .get('/')
      .expect(200);

    expect(response.body).toMatchObject({
      message: 'TypeScript {tier} Reference Project',
      version: '1.0.0'
    });
  });

  it('should return health check', async () => {
    const response = await request(app)
      .get('/health')
      .expect(200);

    expect(response.body).toMatchObject({
      status: 'ok'
    });
    expect(response.body.timestamp).toBeDefined();
  });
});
""".format(tier=tier)
    
    # Environment example
    env_example = """# Application
NODE_ENV=development
PORT=3000
DEBUG=true

# JWT
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRES_IN=1h
JWT_ISSUER=typescript-app
JWT_AUDIENCE=typescript-users

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
LOG_FILE_ENABLED=true
LOG_FILE_PATH=./logs/app.log
"""
    
    # README
    readme = f"""# TypeScript {tier.title()} Reference Project

> **TypeScript {tier_descriptions[tier]}**

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Development mode
npm run dev

# Build for production
npm run build

# Start production server
npm start

# Run tests
npm test

# Type checking
npm run type-check
```

## 📁 Project Structure

```
src/
├── index.ts              # Application entry point
├── test/                 # Test setup
└── __tests__/            # Test files
├── dist/                 # Compiled JavaScript
├── package.json          # Dependencies and scripts
├── tsconfig.json         # TypeScript configuration
├── jest.config.js        # Jest testing configuration
├── .eslintrc.js          # ESLint configuration
└── .env.example          # Environment variables
```

## 🔧 Configuration

- **TypeScript**: Strict mode enabled with comprehensive type checking
- **Jest**: Testing framework with TypeScript support
- **ESLint**: Code linting with TypeScript rules
- **Express**: Web framework with TypeScript definitions
- **Environment**: 12-factor app configuration

## 📋 Available Scripts

- `npm run dev` - Development server with hot reload
- `npm run build` - Compile TypeScript to JavaScript
- `npm run start` - Start production server
- `npm run test` - Run test suite
- `npm run lint` - Check code quality
- `npm run type-check` - Verify TypeScript types

## 🎯 TypeScript Features

- **Strict Type Checking**: All TypeScript strict mode features enabled
- **Decorators**: Experimental decorator support for frameworks
- **Path Mapping**: Clean import paths with `@/*` aliases
- **Incremental Builds**: Fast compilation with build caching
- **Source Maps**: Debugging support for compiled code

## 🧪 Testing

TypeScript testing with Jest includes:
- Type-safe test files
- Mock support for TypeScript modules
- Coverage reporting
- Watch mode for development

---

*TypeScript {tier.title()} Reference Project*  
*Generated by Universal Template System*
"""
    
    # Create directory structure
    (project_path / 'src' / 'test').mkdir(parents=True, exist_ok=True)
    (project_path / 'src' / '__tests__').mkdir(parents=True, exist_ok=True)
    
    # Write files
    (project_path / 'package.json').write_text(package_json, encoding='utf-8')
    (project_path / 'tsconfig.json').write_text(tsconfig_json, encoding='utf-8')
    (project_path / 'jest.config.js').write_text(jest_config, encoding='utf-8')
    (project_path / '.eslintrc.js').write_text(eslint_config, encoding='utf-8')
    (project_path / 'src' / 'index.ts').write_text(main_ts, encoding='utf-8')
    (project_path / 'src' / 'test' / 'setup.ts').write_text(test_setup, encoding='utf-8')
    (project_path / 'src' / '__tests__' / 'app.test.ts').write_text(app_test_ts, encoding='utf-8')
    (project_path / '.env.example').write_text(env_example, encoding='utf-8')
    (project_path / 'README.md').write_text(readme, encoding='utf-8')

def generate_all_reference_projects():
    """Generate all reference projects"""
    base_dir = Path('reference-projects')
    
    print("🏗️  Generating Reference Projects")
    print("=" * 50)
    
    total_projects = len(STACKS) * len(TIERS)
    current_project = 0
    
    for stack in STACKS:
        for tier in TIERS:
            current_project += 1
            project_path = base_dir / tier / f"{tier}-{stack}-reference"
            
            print(f"[{current_project:2d}/{total_projects}] Creating {tier.title()} {stack.title()}...")
            
            try:
                if stack == 'flutter':
                    create_flutter_project(project_path, tier)
                elif stack == 'react':
                    create_react_project(project_path, tier)
                elif stack == 'react_native':
                    create_react_native_project(project_path, tier)
                elif stack == 'node':
                    create_node_project(project_path, tier)
                elif stack == 'go':
                    create_go_project(project_path, tier)
                elif stack == 'python':
                    create_python_project(project_path, tier)
                elif stack == 'next':
                    create_next_project(project_path, tier)
                elif stack == 'r':
                    create_r_project(project_path, tier)
                elif stack == 'sql':
                    create_sql_project(project_path, tier)
                elif stack == 'generic':
                    create_generic_project(project_path, tier)
                elif stack == 'typescript':
                    create_typescript_project(project_path, tier)
                print(f"    ✅ Created successfully")
            except Exception as e:
                print(f"    ❌ Failed: {e}")
    
    print(f"\n✅ Generated reference projects!")
    print(f"📁 Location: {base_dir.absolute()}")
    
    # Generate summary
    print(f"\n📊 Project Summary:")
    for tier in TIERS:
        tier_dir = base_dir / tier
        if tier_dir.exists():
            projects = len([d for d in tier_dir.iterdir() if d.is_dir()])
            print(f"  {tier.title():10} | {projects} projects")

if __name__ == '__main__':
    os.chdir(Path(__file__).parent.parent)
    generate_all_reference_projects()
