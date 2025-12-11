# Universal Template System - Flutter Stack
# Generated: 2025-12-10
# Purpose: flutter template utilities
# Tier: base
# Stack: flutter
# Category: template

# Flutter CI/CD Examples - {{PROJECT_NAME}}

**Tier**: {{TIER}} | **Stack**: Flutter

## 🚀 Flutter CI/CD Strategy Overview

Flutter CI/CD follows a **tiered approach** with increasing complexity and security requirements. Each tier builds upon the previous one with additional validation, testing, and deployment capabilities.

## 📊 Tier-Specific CI/CD Requirements

| Tier | Testing | Code Quality | Security | Deployment | Environment |
|------|---------|--------------|----------|------------|-------------|
| **MVP** | Unit + Widget | Basic linting | Basic checks | Manual only | Single env |
| **CORE** | All tests + Golden | Advanced linting | Dependency scanning | Automated to staging | Dev + Prod |
| **FULL** | All tests + Performance | Full quality gates | Full security scan | Multi-channel deployment | Multi-env + feature flags |

## 🔧 GitHub Actions Configuration

### **MVP Tier - Basic CI**

```yaml
# .github/workflows/ci.yml
name: Flutter CI (MVP)

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Flutter
      uses: subosito/flutter-action@v2
      with:
        flutter-version: '3.16.0'
        channel: 'stable'
        
    - name: Install dependencies
      run: flutter pub get
      
    - name: Verify formatting
      run: dart format --set-exit-if-changed .
      
    - name: Analyze code
      run: flutter analyze
      
    - name: Run unit tests
      run: flutter test --coverage
      
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: coverage/lcov.info
        
    - name: Build APK (for testing)
      run: flutter build apk --debug
```

### **CORE Tier - Production CI/CD**

```yaml
# .github/workflows/ci-core.yml
name: Flutter CI/CD (CORE)

on:
  push:
    branches: [ main, develop, release/* ]
  pull_request:
    branches: [ main, release/* ]
  release:
    types: [ published ]

env:
  FLUTTER_VERSION: '3.16.0'
  JAVA_VERSION: '17'

jobs:
  quality-gate:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Flutter
      uses: subosito/flutter-action@v2
      with:
        flutter-version: ${{ env.FLUTTER_VERSION }}
        channel: 'stable'
        
    - name: Install dependencies
      run: flutter pub get
      
    - name: Verify formatting
      run: dart format --set-exit-if-changed .
      
    - name: Custom linting
      run: flutter analyze --fatal-infos
      
    - name: Check for unused dependencies
      run: dart pub deps --style=tree
      
    - name: Run unit tests
      run: flutter test --coverage --reporter=expanded
      
    - name: Run widget tests
      run: flutter test --coverage integration_test/
      
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: coverage/lcov.info
        fail_ci_if_error: true

  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Flutter
      uses: subosito/flutter-action@v2
      with:
        flutter-version: ${{ env.FLUTTER_VERSION }}
        
    - name: Install dependencies
      run: flutter pub get
      
    - name: Run security audit
      run: |
        flutter pub deps --style=tree | grep -E "(^\s+[a-z0-9\-]+:)" | cut -d: -f1 | sort -u > deps.txt
        while read dep; do
          echo "Checking $dep for vulnerabilities..."
          # Add your security check logic here
        done < deps.txt

  build-android:
    needs: [quality-gate, security-scan]
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Java
      uses: actions/setup-java@v3
      with:
        distribution: 'temurin'
        java-version: ${{ env.JAVA_VERSION }}
        
    - name: Setup Flutter
      uses: subosito/flutter-action@v2
      with:
        flutter-version: ${{ env.FLUTTER_VERSION }}
        
    - name: Setup Android SDK
      uses: android-actions/setup-android@v2
      
    - name: Install dependencies
      run: flutter pub get
      
    - name: Build APK
      run: |
        echo "${{ secrets.KEYSTORE_BASE64 }}" | base64 -d > keystore.jks
        echo "${{ secrets.KEYSTORE_PROPERTIES }}" > key.properties
        flutter build apk --release --obfuscate --split-debug-info=build/debug-info/
        
    - name: Build App Bundle
      run: |
        flutter build appbundle --release --obfuscate --split-debug-info=build/debug-info/
        
    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: android-build
        path: |
          build/app/outputs/flutter-apk/app-release.apk
          build/app/outputs/bundle/release/app-release.aab

  build-ios:
    needs: [quality-gate, security-scan]
    runs-on: macos-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Flutter
      uses: subosito/flutter-action@v2
      with:
        flutter-version: ${{ env.FLUTTER_VERSION }}
        
    - name: Install dependencies
      run: flutter pub get
      
    - name: Install CocoaPods
      run: |
        cd ios
        pod install
        
    - name: Build iOS
      run: |
        flutter build ios --release --no-codesign
        
    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: ios-build
        path: build/ios/iphoneos/Runner.app

  deploy-staging:
    needs: [build-android, build-ios]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    
    steps:
    - name: Download artifacts
      uses: actions/download-artifact@v3
      with:
        name: android-build
        
    - name: Deploy to Firebase App Distribution
      uses: wzieba/Firebase-Distribution-Github-Action@v1
      with:
        appId: ${{ secrets.FIREBASE_ANDROID_APP_ID }}
        serviceCredentialsFileContent: ${{ secrets.FIREBASE_SERVICE_ACCOUNT_KEY }}
        groups: testers
        file: app-release.apk
        releaseNotes: "Staging build from ${{ github.sha }}"
```

### **FULL Tier - Enterprise CI/CD**

```yaml
# .github/workflows/ci-enterprise.yml
name: Flutter CI/CD (ENTERPRISE)

on:
  push:
    branches: [ main, develop, release/*, feature/* ]
  pull_request:
    branches: [ main, release/* ]
  release:
    types: [ published ]
  schedule:
    - cron: '0 2 * * *'  # Daily security scan

env:
  FLUTTER_VERSION: '3.16.0'
  JAVA_VERSION: '17'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  comprehensive-quality:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Flutter
      uses: subosito/flutter-action@v2
      with:
        flutter-version: ${{ env.FLUTTER_VERSION }}
        
    - name: Install dependencies
      run: flutter pub get
      
    - name: Verify formatting
      run: dart format --set-exit-if-changed .
      
    - name: Advanced analysis
      run: |
        flutter analyze --fatal-infos --fatal-warnings
        dart analyze --fatal-infos --fatal-warnings
        
    - name: Custom quality checks
      run: |
        # Check for hardcoded secrets
        grep -r "password\|secret\|key" lib/ --include="*.dart" | grep -v "// ignore" && exit 1 || true
        
        # Check bundle size
        flutter build apk --analyze-size --split-debug-info=build/debug-info/
        
    - name: Run comprehensive tests
      run: |
        flutter test --coverage --reporter=expanded
        flutter test integration_test/ --coverage
        flutter test test/performance/ --coverage
        
    - name: Generate test report
      uses: dorny/test-reporter@v1
      if: success() || failure()
      with:
        name: Flutter Tests
        path: test-report.json
        reporter: json
        
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: coverage/lcov.info
        fail_ci_if_error: true

  enterprise-security:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        format: 'sarif'
        output: 'trivy-results.sarif'
        
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
        
    - name: OWASP Dependency Check
      uses: dependency-check/Dependency-Check_Action@main
      with:
        project: 'flutter-app'
        path: '.'
        format: 'HTML'
        
    - name: Upload OWASP results
      uses: actions/upload-artifact@v3
      with:
        name: owasp-reports
        path: reports/

  performance-testing:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Flutter
      uses: subosito/flutter-action@v2
      with:
        flutter-version: ${{ env.FLUTTER_VERSION }}
        
    - name: Install dependencies
      run: flutter pub get
      
    - name: Run performance tests
      run: |
        flutter test test/performance/ --reporter=expanded
        
    - name: Build and analyze performance
      run: |
        flutter build apk --release --analyze-size --split-debug-info=build/debug-info/
        
    - name: Performance regression check
      run: |
        # Compare with baseline performance
        python scripts/check_performance.py

  multi-platform-build:
    needs: [comprehensive-quality, enterprise-security, performance-testing]
    strategy:
      matrix:
        platform: [android, ios, web, windows, linux, macos]
        
    runs-on: ${{ matrix.platform == 'ios' && 'macos-latest' || 'ubuntu-latest' }}
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Flutter
      uses: subosito/flutter-action@v2
      with:
        flutter-version: ${{ env.FLUTTER_VERSION }}
        
    - name: Install dependencies
      run: flutter pub get
      
    - name: Build for ${{ matrix.platform }}
      run: |
        case "${{ matrix.platform }}" in
          android)
            flutter build apk --release --obfuscate --split-debug-info=build/debug-info/
            flutter build appbundle --release --obfuscate --split-debug-info=build/debug-info/
            ;;
          ios)
            cd ios && pod install && cd ..
            flutter build ios --release --no-codesign
            ;;
          web)
            flutter build web --release --web-renderer canvaskit
            ;;
          windows)
            flutter build windows --release
            ;;
          linux)
            flutter build linux --release
            ;;
          macos)
            flutter build macos --release
            ;;
        esac
        
    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: ${{ matrix.platform }}-build
        path: build/

  enterprise-deployment:
    needs: multi-platform-build
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    
    steps:
    - name: Download all artifacts
      uses: actions/download-artifact@v3
      
    - name: Deploy to App Store
      if: contains('ios android', matrix.platform)
      run: |
        # App Store deployment logic
        echo "Deploying to App Store..."
        
    - name: Deploy to Play Store
      if: contains('android', matrix.platform)
      uses: r0adkll/upload-google-play@v1
      with:
        serviceAccountJsonPlainText: ${{ secrets.GOOGLE_PLAY_SERVICE_ACCOUNT }}
        packageName: com.example.{{PROJECT_NAME}}
        releaseFiles: "android-build/*.aab"
        track: production
        status: completed
        
    - name: Deploy to Web
      if: contains('web', matrix.platform)
      uses: peaceiris/actions-gh-pages@v3
      with:
        github_token: ${{ secrets.GITHUB_TOKEN }}
        publish_dir: ./web-build
        
    - name: Deploy to Desktop Stores
      if: contains('windows linux macos', matrix.platform)
      run: |
        # Desktop store deployment logic
        echo "Deploying to desktop stores..."

  post-deployment-validation:
    needs: enterprise-deployment
    runs-on: ubuntu-latest
    
    steps:
    - name: Run smoke tests
      run: |
        # Automated smoke tests on deployed app
        python scripts/smoke_tests.py
        
    - name: Performance monitoring
      run: |
        # Check app performance metrics
        python scripts/performance_monitoring.py
        
    - name: Security validation
      run: |
        # Post-deployment security checks
        python scripts/security_validation.py
```

## 📱 Firebase App Distribution Setup

### **Core Tier Firebase Integration**

```yaml
# .github/workflows/firebase-distribution.yml
name: Deploy to Firebase

on:
  push:
    branches: [ develop ]

jobs:
  distribute:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4
      
    - name: Setup Flutter
      uses: subosito/flutter-action@v2
      with:
        flutter-version: '3.16.0'
        
    - name: Build APK
      run: |
        flutter pub get
        flutter build apk --release
        
    - name: Distribute to Firebase
      uses: wzieba/Firebase-Distribution-Github-Action@v1
      with:
        appId: ${{ secrets.FIREBASE_ANDROID_APP_ID }}
        serviceCredentialsFileContent: ${{ secrets.FIREBASE_SERVICE_ACCOUNT_KEY }}
        groups: internal-testers, qa-team
        file: build/app/outputs/flutter-apk/app-release.apk
        releaseNotes: |
          Build: ${{ github.sha }}
          Branch: ${{ github.ref_name }}
          Date: ${{ github.event.head_commit.timestamp }}
          
          Changes:
          ${{ github.event.head_commit.message }}
```

## 🔒 Security Configuration

### **Secrets Management**

```yaml
# Environment-specific secrets
# GitHub Repository Settings > Secrets and variables > Actions

secrets:
  KEYSTORE_BASE64: # Base64 encoded Android keystore
  KEYSTORE_PROPERTIES: # Android keystore properties
  FIREBASE_SERVICE_ACCOUNT_KEY: # Firebase service account JSON
  FIREBASE_ANDROID_APP_ID: # Firebase Android app ID
  FIREBASE_IOS_APP_ID: # Firebase iOS app ID
  GOOGLE_PLAY_SERVICE_ACCOUNT: # Google Play service account JSON
  APPLE_API_KEY: # App Store Connect API key
  SLACK_WEBHOOK: # Slack notifications webhook
  SENTRY_AUTH_TOKEN: # Sentry error tracking token
```

### **Security Scanning**

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  push:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4
      
    - name: Run Semgrep
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/security-audit
          p/secrets
          p/flutter
          
    - name: Run CodeQL Analysis
      uses: github/codeql-action/init@v2
      with:
        languages: dart
        
    - name: Autobuild
      uses: github/codeql-action/autobuild@v2
      
    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
```

## 📊 Quality Gates Configuration

### **Quality Metrics Script**

```python
# scripts/quality_gate.py
import json
import sys
import subprocess

def check_coverage():
    """Check test coverage meets minimum threshold"""
    result = subprocess.run(['genhtml', 'coverage/lcov.info', '-o', 'coverage/html'], 
                          capture_output=True, text=True)
    
    # Parse coverage percentage
    coverage = parse_coverage_percentage(result.stdout)
    
    if coverage < 80:  # 80% minimum coverage
        print(f"Coverage {coverage}% is below minimum 80%")
        sys.exit(1)
    
    print(f"Coverage {coverage}% meets requirements")

def check_bundle_size():
    """Check APK size doesn't exceed limits"""
    max_size_mvp = 50 * 1024 * 1024  # 50MB
    max_size_core = 100 * 1024 * 1024  # 100MB
    
    apk_size = get_apk_size()
    
    if apk_size > max_size_core:
        print(f"APK size {apk_size}MB exceeds maximum 100MB")
        sys.exit(1)
    
    print(f"APK size {apk_size}MB within limits")

def check_performance():
    """Check performance metrics"""
    # Run performance tests and check against baselines
    pass

if __name__ == "__main__":
    check_coverage()
    check_bundle_size()
    check_performance()
    print("All quality gates passed")
```

## 🚀 Deployment Strategies

### **Blue-Green Deployment (FULL Tier)**

```yaml
# .github/workflows/blue-green-deploy.yml
name: Blue-Green Deployment

on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Deployment environment'
        required: true
        default: 'staging'

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
    - name: Deploy to Green Environment
      run: |
        # Deploy to green environment
        kubectl apply -f k8s/green/
        
    - name: Health Check Green
      run: |
        # Wait for green to be healthy
        kubectl wait --for=condition=ready pod -l app=green --timeout=300s
        
    - name: Switch Traffic to Green
      run: |
        # Update load balancer to point to green
        kubectl patch service app -p '{"spec":{"selector":{"version":"green"}}}'
        
    - name: Validate Deployment
      run: |
        # Run smoke tests on green
        python scripts/smoke_tests.py
        
    - name: Cleanup Blue Environment
      run: |
        # Remove blue environment after successful deployment
        kubectl delete -f k8s/blue/ --ignore-not-found=true
```

## 📈 Monitoring and Observability

### **CI/CD Pipeline Monitoring**

```yaml
# .github/workflows/monitoring.yml
name: Pipeline Monitoring

on:
  workflow_run:
    workflows: ["Flutter CI/CD (ENTERPRISE)"]
    types:
      - completed

jobs:
  monitor:
    runs-on: ubuntu-latest
    if: ${{ github.event.workflow_run.conclusion != 'success' }}
    
    steps:
    - name: Notify on Failure
      uses: 8398a7/action-slack@v3
      with:
        status: failure
        channel: '#ci-cd'
        text: 'Flutter CI/CD pipeline failed!'
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
        
    - name: Create Issue for Investigation
      uses: actions/github-script@v6
      with:
        script: |
          github.rest.issues.create({
            owner: context.repo.owner,
            repo: context.repo.repo,
            title: 'CI/CD Pipeline Failure Investigation',
            body: 'Pipeline failed at ' + context.payload.workflow_run.created_at,
            labels: ['ci-cd', 'investigation']
          })
```

## 🛠️ Local Development Setup

### **Pre-commit Hooks**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/dart-lang/dart-format
    rev: '1.0.0'
    hooks:
      - id: dart-format
        
  - repo: https://github.com/Flutter-Lint/flutter-lint
    rev: '1.0.0'
    hooks:
      - id: flutter-analyze
        
  - repo: local
    hooks:
      - id: flutter-test
        name: Flutter Tests
        entry: flutter test
        language: system
        pass_filenames: false
        always_run: true
```

### **Development Scripts**

```bash
#!/bin/bash
# scripts/dev-setup.sh

echo "Setting up Flutter development environment..."

# Install Flutter
if ! command -v flutter &> /dev/null; then
    echo "Installing Flutter..."
    # Flutter installation logic
fi

# Install dependencies
echo "Installing dependencies..."
flutter pub get

# Setup pre-commit hooks
echo "Setting up pre-commit hooks..."
pre-commit install

# Run initial tests
echo "Running initial tests..."
flutter test

echo "Development environment setup complete!"
```

---

**Flutter Version**: [FLUTTER_VERSION]  
**Dart Version**: [DART_VERSION]  
**Last Updated**: [DATE]  
**Template Version**: 1.0
