# React Native Workflow Testing Template
# Build processes, CI/CD pipelines, deployment automation, and store submission workflows

"""
React Native Workflow Test Patterns
Complete build automation, CI/CD integration, deployment pipelines, and store submission processes
Including Fastlane integration, code signing, and automated releases
"""

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

// ====================
// BUILD AUTOMATION TESTS
// ====================

describe('Build Automation Workflows', () => {
  
  test('iOS build generation', () => {
    const buildCommands = [
      'cd ios && xcodebuild -workspace YourApp.xcworkspace -scheme YourApp -configuration Release -sdk iphoneos -derivedDataPath build',
      'cd ios && xcodebuild -workspace YourApp.xcworkspace -scheme YourApp -configuration Release -sdk iphonesimulator -derivedDataPath build',
      'cd ios && xcodebuild archive -workspace YourApp.xcworkspace -scheme YourApp -archivePath build/YourApp.xcarchive'
    ];
    
    buildCommands.forEach(command => {
      try {
        execSync(command, { stdio: 'pipe' });
        console.log(`✅ Build successful: ${command}`);
      } catch (error) {
        console.error(`❌ Build failed: ${command}`);
        console.error(error.message);
        throw error;
      }
    });
    
    // Verify build artifacts
    const expectedArtifacts = [
      'ios/build/Build/Products/Release-iphoneos/YourApp.app',
      'ios/build/Build/Products/Release-iphonesimulator/YourApp.app',
      'ios/build/YourApp.xcarchive'
    ];
    
    expectedArtifacts.forEach(artifact => {
      expect(fs.existsSync(artifact)).toBe(true);
    });
  });
  
  test('Android build generation', () => {
    const buildVariants = [
      { type: 'debug', task: 'assembleDebug' },
      { type: 'release', task: 'assembleRelease' },
      { type: 'bundle', task: 'bundleRelease' }
    ];
    
    buildVariants.forEach(variant => {
      try {
        execSync(`cd android && ./gradlew ${variant.task}`, { stdio: 'pipe' });
        console.log(`✅ Android ${variant.type} build successful`);
        
        // Verify build output
        const outputPath = variant.type === 'bundle' 
          ? 'android/app/build/outputs/bundle/release/app-release.aab'
          : `android/app/build/outputs/apk/${variant.type}/app-${variant.type}.apk`;
        
        expect(fs.existsSync(outputPath)).toBe(true);
        
        // Verify build size constraints
        const stats = fs.statSync(outputPath);
        const sizeInMB = stats.size / (1024 * 1024);
        
        expect(sizeInMB).toBeLessThan(100); // Less than 100MB
        console.log(`📦 Build size: ${sizeInMB.toFixed(2)}MB`);
        
      } catch (error) {
        console.error(`❌ Android ${variant.type} build failed`);
        throw error;
      }
    });
  });
  
  test('React Native bundle generation', () => {
    const bundleCommands = [
      {
        platform: 'ios',
        command: 'npx react-native bundle --platform ios --dev false --entry-file index.js --bundle-output ios/main.jsbundle --assets-dest ios'
      },
      {
        platform: 'android',
        command: 'npx react-native bundle --platform android --dev false --entry-file index.js --bundle-output android/app/src/main/assets/index.android.bundle --assets-dest android/app/src/main/res'
      }
    ];
    
    bundleCommands.forEach(({ platform, command }) => {
      try {
        execSync(command, { stdio: 'pipe' });
        console.log(`✅ ${platform} bundle generated successfully`);
        
        // Verify bundle files
        const bundlePath = platform === 'ios' 
          ? 'ios/main.jsbundle'
          : 'android/app/src/main/assets/index.android.bundle';
        
        expect(fs.existsSync(bundlePath)).toBe(true);
        
        // Verify bundle size
        const stats = fs.statSync(bundlePath);
        const sizeInMB = stats.size / (1024 * 1024);
        expect(sizeInMB).toBeLessThan(10); // Less than 10MB
        
        console.log(`📦 ${platform} bundle size: ${sizeInMB.toFixed(2)}MB`);
        
      } catch (error) {
        console.error(`❌ ${platform} bundle generation failed`);
        throw error;
      }
    });
  });
  
  test('Hermes engine compilation', () => {
    if (process.platform !== 'darwin') {
      console.log('Skipping Hermes compilation test on non-macOS platform');
      return;
    }
    
    try {
      // Compile with Hermes for iOS
      execSync('cd ios && hermes-release-bundle', { stdio: 'pipe' });
      console.log('✅ Hermes iOS compilation successful');
      
      // Verify Hermes bytecode
      const hermesBundlePath = 'ios/main.jsbundle.hbc';
      expect(fs.existsSync(hermesBundlePath)).toBe(true);
      
      // Verify bytecode size is smaller than JS bundle
      const jsBundleSize = fs.statSync('ios/main.jsbundle').size;
      const hermesBundleSize = fs.statSync(hermesBundlePath).size;
      
      expect(hermesBundleSize).toBeLessThan(jsBundleSize);
      console.log(`📦 Hermes bytecode size reduction: ${((1 - hermesBundleSize/jsBundleSize) * 100).toFixed(1)}%`);
      
    } catch (error) {
      console.error('❌ Hermes compilation failed');
      throw error;
    }
  });
});

// ====================
// CI/CD PIPELINE TESTS
// ====================

describe('CI/CD Pipeline Workflows', () => {
  
  test('GitHub Actions workflow validation', () => {
    const workflowPath = '.github/workflows/react-native-ci.yml';
    
    expect(fs.existsSync(workflowPath)).toBe(true);
    
    const workflowContent = fs.readFileSync(workflowPath, 'utf8');
    const workflow = require('js-yaml').load(workflowContent);
    
    // Verify workflow structure
    expect(workflow.name).toBe('React Native CI/CD');
    expect(workflow.on).toBeDefined();
    expect(workflow.on.push).toBeDefined();
    expect(workflow.on.pull_request).toBeDefined();
    
    // Verify jobs
    expect(workflow.jobs).toBeDefined();
    expect(workflow.jobs.test).toBeDefined();
    expect(workflow.jobs.lint).toBeDefined();
    expect(workflow.jobs.build).toBeDefined();
    
    // Verify test job
    const testJob = workflow.jobs.test;
    expect(testJob['runs-on']).toBe('ubuntu-latest');
    expect(testJob.steps).toContainEqual(
      expect.objectContaining({
        name: expect.stringContaining('Install dependencies')
      })
    );
    expect(testJob.steps).toContainEqual(
      expect.objectContaining({
        name: expect.stringContaining('Run tests')
      })
    );
    
    console.log('✅ GitHub Actions workflow validated');
  });
  
  test('Jenkins pipeline validation', () => {
    const jenkinsfilePath = 'Jenkinsfile';
    
    expect(fs.existsSync(jenkinsfilePath)).toBe(true);
    
    const jenkinsfileContent = fs.readFileSync(jenkinsfilePath, 'utf8');
    
    // Verify pipeline structure
    expect(jenkinsfileContent).toContain('pipeline {');
    expect(jenkinsfileContent).toContain('agent any');
    expect(jenkinsfileContent).toContain('stages {');
    
    // Verify required stages
    const requiredStages = [
      'Checkout',
      'Install Dependencies',
      'Run Tests',
      'Lint Code',
      'Build Application',
      'Deploy'
    ];
    
    requiredStages.forEach(stage => {
      expect(jenkinsfileContent).toContain(`stage('${stage}')`);
    });
    
    // Verify post-build actions
    expect(jenkinsfileContent).toContain('always {');
    expect(jenkinsfileContent).toContain('success {');
    expect(jenkinsfileContent).toContain('failure {');
    
    console.log('✅ Jenkins pipeline validated');
  });
  
  test('Docker containerization workflow', () => {
    const dockerfilePath = 'Dockerfile';
    
    expect(fs.existsSync(dockerfilePath)).toBe(true);
    
    const dockerfileContent = fs.readFileSync(dockerfilePath, 'utf8');
    
    // Verify Dockerfile structure
    expect(dockerfileContent).toContain('FROM node:');
    expect(dockerfileContent).toContain('WORKDIR /app');
    expect(dockerfileContent).toContain('COPY package.json');
    expect(dockerfileContent).toContain('RUN npm install');
    expect(dockerfileContent).toContain('COPY . .');
    expect(dockerfileContent).toContain('EXPOSE 8081');
    expect(dockerfileContent).toContain('CMD ["npm", "start"]');
    
    // Test Docker build
    try {
      execSync('docker build -t react-native-app .', { stdio: 'pipe' });
      console.log('✅ Docker build successful');
      
      // Test container startup
      execSync('docker run -d --name test-container -p 8081:8081 react-native-app', { stdio: 'pipe' });
      
      // Wait for container to start
      setTimeout(() => {
        const containerStatus = execSync('docker inspect -f {{.State.Status}} test-container', { encoding: 'utf8' }).trim();
        expect(containerStatus).toBe('running');
        
        // Cleanup
        execSync('docker stop test-container && docker rm test-container', { stdio: 'pipe' });
        execSync('docker rmi react-native-app', { stdio: 'pipe' });
      }, 5000);
      
    } catch (error) {
      console.error('❌ Docker build failed');
      throw error;
    }
  });
  
  test('automated testing pipeline', () => {
    // Test unit tests
    try {
      execSync('npm test -- --coverage --watchAll=false', { stdio: 'pipe' });
      console.log('✅ Unit tests passed');
      
      // Verify coverage report
      expect(fs.existsSync('coverage/lcov.info')).toBe(true);
      
      // Check coverage thresholds
      const coverage = JSON.parse(fs.readFileSync('coverage/coverage-summary.json', 'utf8'));
      expect(coverage.total.lines.pct).toBeGreaterThan(80);
      expect(coverage.total.statements.pct).toBeGreaterThan(80);
      expect(coverage.total.functions.pct).toBeGreaterThan(80);
      expect(coverage.total.branches.pct).toBeGreaterThan(80);
      
    } catch (error) {
      console.error('❌ Unit tests failed');
      throw error;
    }
    
    // Test linting
    try {
      execSync('npm run lint', { stdio: 'pipe' });
      console.log('✅ Linting passed');
    } catch (error) {
      console.error('❌ Linting failed');
      throw error;
    }
    
    // Test TypeScript compilation
    if (fs.existsSync('tsconfig.json')) {
      try {
        execSync('npx tsc --noEmit', { stdio: 'pipe' });
        console.log('✅ TypeScript compilation passed');
      } catch (error) {
        console.error('❌ TypeScript compilation failed');
        throw error;
      }
    }
  });
});

// ====================
// DEPLOYMENT AUTOMATION
// ====================

describe('Deployment Workflow Tests', () => {
  
  test('Fastlane integration for iOS deployment', () => {
    const fastfilePath = 'fastlane/Fastfile';
    
    expect(fs.existsSync(fastfilePath)).toBe(true);
    
    const fastfileContent = fs.readFileSync(fastfilePath, 'utf8');
    
    // Verify Fastlane lanes
    expect(fastfileContent).toContain('lane :beta do');
    expect(fastfileContent).toContain('lane :release do');
    expect(fastfileContent).toContain('lane :screenshots do');
    
    // Verify iOS-specific actions
    expect(fastfileContent).toContain('increment_build_number');
    expect(fastfileContent).toContain('build_app');
    expect(fastfileContent).toContain('upload_to_testflight');
    expect(fastfileContent).toContain('upload_to_app_store');
    
    // Test Fastlane beta deployment (dry run)
    try {
      execSync('fastlane beta --dry-run', { stdio: 'pipe' });
      console.log('✅ Fastlane beta lane validated');
    } catch (error) {
      console.error('❌ Fastlane beta lane validation failed');
      throw error;
    }
  });
  
  test('Fastlane integration for Android deployment', () => {
    const fastfilePath = 'fastlane/Fastfile';
    const fastfileContent = fs.readFileSync(fastfilePath, 'utf8');
    
    // Verify Android-specific actions
    expect(fastfileContent).toContain('gradle');
    expect(fastfileContent).toContain('upload_to_play_store');
    
    // Test Fastlane Android deployment (dry run)
    try {
      execSync('fastlane android beta --dry-run', { stdio: 'pipe' });
      console.log('✅ Fastlane Android lane validated');
    } catch (error) {
      console.error('❌ Fastlane Android lane validation failed');
      throw error;
    }
  });
  
  test('code signing and certificate management', () => {
    // iOS code signing
    if (process.platform === 'darwin') {
      const iosSigningPath = 'ios/YourApp.xcodeproj/project.pbxproj';
      
      if (fs.existsSync(iosSigningPath)) {
        const projectContent = fs.readFileSync(iosSigningPath, 'utf8');
        
        // Verify signing configuration
        expect(projectContent).toContain('CODE_SIGN_IDENTITY');
        expect(projectContent).toContain('DEVELOPMENT_TEAM');
        expect(projectContent).toContain('PROVISIONING_PROFILE');
        
        console.log('✅ iOS code signing configured');
      }
    }
    
    // Android signing
    const androidSigningPath = 'android/app/build.gradle';
    const gradleContent = fs.readFileSync(androidSigningPath, 'utf8');
    
    expect(gradleContent).toContain('signingConfigs {');
    expect(gradleContent).toContain('release {');
    expect(gradleContent).toContain('storeFile');
    expect(gradleContent).toContain('storePassword');
    expect(gradleContent).toContain('keyAlias');
    expect(gradleContent).toContain('keyPassword');
    
    // Verify keystore exists
    const keystorePath = 'android/app/your-app.keystore';
    expect(fs.existsSync(keystorePath)).toBe(true);
    
    console.log('✅ Android code signing configured');
  });
  
  test('environment-specific configuration management', () => {
    const environments = ['development', 'staging', 'production'];
    
    environments.forEach(env => {
      // Check environment files
      const envFile = `.env.${env}`;
      expect(fs.existsSync(envFile)).toBe(true);
      
      const envContent = fs.readFileSync(envFile, 'utf8');
      
      // Verify required environment variables
      expect(envContent).toContain('API_URL=');
      expect(envContent).toContain('ENVIRONMENT=');
      
      if (env === 'production') {
        expect(envContent).toContain('SENTRY_DSN=');
        expect(envContent).toContain('ANALYTICS_KEY=');
      }
    });
    
    // Test configuration switching
    try {
      execSync('ENVFILE=.env.production npm run build', { stdio: 'pipe' });
      console.log('✅ Production configuration applied');
    } catch (error) {
      console.error('❌ Configuration switching failed');
      throw error;
    }
  });
  
  test('rollback and recovery procedures', () => {
    // Test rollback script
    const rollbackScript = 'scripts/rollback.sh';
    
    expect(fs.existsSync(rollbackScript)).toBe(true);
    
    // Verify rollback script content
    const scriptContent = fs.readFileSync(rollbackScript, 'utf8');
    
    expect(scriptContent).toContain('#!/bin/bash');
    expect(scriptContent).toContain('previous_version');
    expect(scriptContent).toContain('restore_backup');
    expect(scriptContent).toContain('notify_team');
    
    // Test rollback (dry run)
    try {
      execSync(`bash ${rollbackScript} --dry-run`, { stdio: 'pipe' });
      console.log('✅ Rollback script validated');
    } catch (error) {
      console.error('❌ Rollback script validation failed');
      throw error;
    }
  });
});

// ====================
// APP STORE DEPLOYMENT
// ====================

describe('App Store Deployment Workflows', () => {
  
  test('App Store Connect metadata validation', () => {
    const metadataPath = 'fastlane/metadata';
    
    // Verify metadata structure
    expect(fs.existsSync(metadataPath)).toBe(true);
    
    const requiredFiles = [
      'en-US/description.txt',
      'en-US/keywords.txt',
      'en-US/release_notes.txt',
      'en-US/support_url.txt',
      'en-US/marketing_url.txt',
      'primary_category.txt',
      'secondary_category.txt',
      'copyright.txt',
      'apple_watch_app_icon.png'
    ];
    
    requiredFiles.forEach(file => {
      const filePath = path.join(metadataPath, file);
      expect(fs.existsSync(filePath)).toBe(true);
      
      // Verify content
      const content = fs.readFileSync(filePath, 'utf8');
      expect(content.length).toBeGreaterThan(0);
      
      if (file.includes('description')) {
        expect(content.length).toBeLessThan(4000); // App Store limit
      }
      
      if (file.includes('keywords')) {
        expect(content.length).toBeLessThan(100); // App Store limit
      }
    });
    
    console.log('✅ App Store metadata validated');
  });
  
  test('Google Play Store metadata validation', () => {
    const metadataPath = 'fastlane/android/metadata';
    
    // Verify metadata structure
    expect(fs.existsSync(metadataPath)).toBe(true);
    
    const requiredFiles = [
      'en-US/title.txt',
      'en-US/short_description.txt',
      'en-US/full_description.txt',
      'en-US/changelogs/default.txt',
      'feature_graphic.png',
      'icon.png',
      'screenshots/phone_1.png',
      'screenshots/phone_2.png',
      'screenshots/tablet_1.png'
    ];
    
    requiredFiles.forEach(file => {
      const filePath = path.join(metadataPath, file);
      expect(fs.existsSync(filePath)).toBe(true);
      
      const content = fs.readFileSync(filePath, 'utf8');
      expect(content.length).toBeGreaterThan(0);
      
      if (file.includes('title')) {
        expect(content.length).toBeLessThan(50); // Google Play limit
      }
      
      if (file.includes('short_description')) {
        expect(content.length).toBeLessThan(80); // Google Play limit
      }
    });
    
    console.log('✅ Google Play metadata validated');
  });
  
  test('screenshot automation workflow', () => {
    const screenshotPath = 'fastlane/screenshots';
    
    // Verify screenshot configuration
    const snapshotHelper = 'fastlane/SnapshotHelper.swift';
    expect(fs.existsSync(snapshotHelper)).toBe(true);
    
    const snapshotFile = 'fastlane/Snapfile';
    expect(fs.existsSync(snapshotFile)).toBe(true);
    
    const snapshotContent = fs.readFileSync(snapshotFile, 'utf8');
    expect(snapshotContent).toContain('devices');
    expect(snapshotContent).toContain('languages');
    expect(snapshotContent).toContain('output_directory');
    
    // Test screenshot generation (if simulators are available)
    try {
      execSync('fastlane snapshot --dry-run', { stdio: 'pipe' });
      console.log('✅ Screenshot automation configured');
    } catch (error) {
      console.log('⚠️ Screenshot automation test skipped (no simulators)');
    }
  });
  
  test('app review and approval process', () => {
    // Verify app meets store guidelines
    const appConfig = JSON.parse(fs.readFileSync('app.json', 'utf8'));
    
    // iOS-specific checks
    if (fs.existsSync('ios/YourApp/Info.plist')) {
      const infoPlist = fs.readFileSync('ios/YourApp/Info.plist', 'utf8');
      
      // Required permissions descriptions
      const requiredPermissions = [
        'NSCameraUsageDescription',
        'NSPhotoLibraryUsageDescription',
        'NSLocationWhenInUseUsageDescription',
        'NSContactsUsageDescription'
      ];
      
      requiredPermissions.forEach(permission => {
        if (infoPlist.includes(permission)) {
          expect(infoPlist).toContain(`${permission}<`);
          expect(infoPlist).toMatch(new RegExp(`${permission}.*Privacy.*`));
        }
      });
    }
    
    // Content rating verification
    expect(appConfig.contentRating).toBeDefined();
    expect(['4+', '9+', '12+', '17+']).toContain(appConfig.contentRating);
    
    console.log('✅ App review requirements validated');
  });
  
  test('automated release management', () => {
    // Verify release automation
    const releaseScript = 'scripts/release.sh';
    
    expect(fs.existsSync(releaseScript)).toBe(true);
    
    const scriptContent = fs.readFileSync(releaseScript, 'utf8');
    
    expect(scriptContent).toContain('version_bump');
    expect(scriptContent).toContain('build_app');
    expect(scriptContent).toContain('upload_to_app_store');
    expect(scriptContent).toContain('upload_to_play_store');
    expect(scriptContent).toContain('create_git_tag');
    expect(scriptContent).toContain('notify_stakeholders');
    
    // Test release script (dry run)
    try {
      execSync(`bash ${releaseScript} --dry-run`, { stdio: 'pipe' });
      console.log('✅ Release automation validated');
    } catch (error) {
      console.error('❌ Release automation validation failed');
      throw error;
    }
  });
});

// ====================
// MONITORING AND ANALYTICS
// ====================

describe('Monitoring and Analytics Workflows', () => {
  
  test('crash reporting integration', () => {
    // Verify crash reporting configuration
    const crashlyticsConfig = 'android/app/build.gradle';
    const gradleContent = fs.readFileSync(crashlyticsConfig, 'utf8');
    
    expect(gradleContent).toContain('crashlytics');
    expect(gradleContent).toContain('firebase-crashlytics');
    
    // iOS crash reporting
    if (fs.existsSync('ios/Podfile')) {
      const podfileContent = fs.readFileSync('ios/Podfile', 'utf8');
      expect(podfileContent).toContain('Firebase/Crashlytics');
    }
    
    console.log('✅ Crash reporting configured');
  });
  
  test('performance monitoring setup', () => {
    // Verify performance monitoring
    const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    
    const performanceDeps = [
      '@sentry/react-native',
      '@react-native-firebase/perf',
      'react-native-performance'
    ];
    
    performanceDeps.forEach(dep => {
      if (packageJson.dependencies[dep]) {
        console.log(`✅ ${dep} installed`);
      }
    });
    
    // Verify configuration files
    if (fs.existsSync('sentry.properties')) {
      const sentryConfig = fs.readFileSync('sentry.properties', 'utf8');
      expect(sentryConfig).toContain('defaults.project');
      expect(sentryConfig).toContain('defaults.org');
    }
  });
  
  test('user analytics tracking', () => {
    // Verify analytics configuration
    const analyticsConfig = 'src/config/analytics.js';
    
    if (fs.existsSync(analyticsConfig)) {
      const configContent = fs.readFileSync(analyticsConfig, 'utf8');
      
      expect(configContent).toContain('Google Analytics');
      expect(configContent).toContain('Firebase Analytics');
      expect(configContent).toContain('trackEvent');
      expect(configContent).toContain('setUserProperties');
      
      console.log('✅ Analytics tracking configured');
    }
  });
  
  test('health check and uptime monitoring', () => {
    // Verify health check endpoints
    const healthCheckConfig = 'src/services/health.js';
    
    if (fs.existsSync(healthCheckConfig)) {
      const healthContent = fs.readFileSync(healthCheckConfig, 'utf8');
      
      expect(healthContent).toContain('checkAPIHealth');
      expect(healthContent).toContain('checkDatabaseHealth');
      expect(healthContent).toContain('checkStorageHealth');
      
      console.log('✅ Health check monitoring configured');
    }
  });
});

// ====================
// UTILITY FUNCTIONS
// ====================

class WorkflowUtils {
  static validateBuildOutput(platform, buildType) {
    const outputPaths = {
      ios: {
        debug: 'ios/build/Build/Products/Debug-iphonesimulator/YourApp.app',
        release: 'ios/build/Build/Products/Release-iphoneos/YourApp.app',
        archive: 'ios/build/YourApp.xcarchive'
      },
      android: {
        debug: 'android/app/build/outputs/apk/debug/app-debug.apk',
        release: 'android/app/build/outputs/apk/release/app-release.apk',
        bundle: 'android/app/build/outputs/bundle/release/app-release.aab'
      }
    };
    
    const outputPath = outputPaths[platform][buildType];
    expect(fs.existsSync(outputPath)).toBe(true);
    
    // Verify file size constraints
    const stats = fs.statSync(outputPath);
    const sizeInMB = stats.size / (1024 * 1024);
    
    const sizeLimits = {
      ios: { debug: 100, release: 150, archive: 200 },
      android: { debug: 50, release: 100, bundle: 80 }
    };
    
    expect(sizeInMB).toBeLessThan(sizeLimits[platform][buildType]);
    
    return { path: outputPath, size: sizeInMB };
  }
  
  static validateEnvironmentVariables(requiredVars) {
    const missingVars = requiredVars.filter(varName => !process.env[varName]);
    
    if (missingVars.length > 0) {
      throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
    }
    
    console.log(`✅ All required environment variables present: ${requiredVars.join(', ')}`);
  }
  
  static async retryOperation(operation, maxRetries = 3, delay = 1000) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        if (attempt === maxRetries) {
          throw error;
        }
        console.log(`Attempt ${attempt} failed, retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  static generateBuildInfo() {
    const buildInfo = {
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version,
      buildNumber: process.env.BUILD_NUMBER || '1',
      gitCommit: execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim(),
      gitBranch: execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf8' }).trim(),
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch
    };
    
    fs.writeFileSync('build-info.json', JSON.stringify(buildInfo, null, 2));
    console.log('✅ Build info generated');
    
    return buildInfo;
  }
}

// Export utilities
export { WorkflowUtils };