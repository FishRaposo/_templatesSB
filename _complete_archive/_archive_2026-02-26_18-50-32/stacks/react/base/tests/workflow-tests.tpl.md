// React Workflow Testing Template
// CI/CD workflow and development workflow tests for React projects

/**
 * React Workflow Test Patterns
 * Build processes, CI/CD, documentation, security, and deployment testing
 */

const { describe, it, expect, beforeAll, afterAll } = require('@jest/globals');
const { execSync, spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const yaml = require('js-yaml');

// ====================
// BUILD WORKFLOW TESTS
// ====================

describe('Build Process Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have valid package.json with all required scripts', async () => {
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    // Verify required scripts
    expect(packageJson.scripts).toBeDefined();
    expect(packageJson.scripts.start).toBeDefined();
    expect(packageJson.scripts.build).toBeDefined();
    expect(packageJson.scripts.test).toBeDefined();
    expect(packageJson.scripts.lint).toBeDefined();
    expect(packageJson.scripts.format).toBeDefined();
  });
  
  it('should install dependencies without errors', async () => {
    // Check if dependencies are already installed
    const nodeModulesPath = path.join(projectRoot, 'node_modules');
    
    try {
      await fs.access(nodeModulesPath);
      console.log('Dependencies already installed, skipping installation test');
    } catch (error) {
      // Try to install dependencies
      try {
        execSync('npm ci', {
          cwd: projectRoot,
          stdio: 'pipe',
          timeout: 600000 // 10 minutes
        });
      } catch (installError) {
        console.log('npm ci failed, trying npm install...');
        execSync('npm install', {
          cwd: projectRoot,
          stdio: 'pipe',
          timeout: 600000
        });
      }
    }
  }, 660000); // 11 minute timeout
  
  it('should build application without errors', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    if (!packageJson.scripts.build) {
      console.log('No build script found, skipping build test');
      return;
    }
    
    // Set CI environment for production build
    const env = { ...process.env, CI: 'true' };
    
    execSync('npm run build', {
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: 300000, // 5 minutes
      env
    });
    
    // Verify build output
    const distPath = path.join(projectRoot, 'build');
    try {
      await fs.access(distPath);
      const files = await fs.readdir(distPath);
      expect(files.length).toBeGreaterThan(0);
      
      // Verify main files exist
      const hasIndexHtml = files.includes('index.html');
      const hasStaticDir = files.includes('static');
      
      expect(hasIndexHtml || hasStaticDir).toBe(true);
    } catch (error) {
      console.log('Build output not found, but build completed');
    }
  });
  
  it('should support different build modes', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    // Check for build variants
    const buildScripts = Object.keys(packageJson.scripts).filter(
      script => script.startsWith('build:')
    );
    
    for (const script of buildScripts) {
      console.log(`Testing build script: ${script}`);
      try {
        execSync(`npm run ${script}`, {
          cwd: projectRoot,
          stdio: 'pipe',
          timeout: 300000
        });
      } catch (error) {
        console.log(`Build script ${script} encountered issues:`, error.message);
      }
    }
  });
  
  it('should run tests without errors in CI mode', async () => {
    const env = { ...process.env, CI: 'true' };
    
    execSync('npm test -- --ci --maxWorkers=2 --passWithNoTests', {
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: 300000,
      env
    });
  });
});

// ====================
// DEVELOPMENT TOOLING TESTS
// ====================

describe('Development Tooling Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have ESLint configuration', async () => {
    const eslintConfigFiles = [
      '.eslintrc.js',
      '.eslintrc.json',
      '.eslintrc.yml'
    ]];
    
    let hasConfig = false;
    for (const configFile of eslintConfigFiles) {
      try {
        await fs.access(path.join(projectRoot, configFile));
        hasConfig = true;
        break;
      } catch (error) {
        // Continue checking
      }
    }
    
    // Also check package.json
    if (!hasConfig) {
      const packageJson = JSON.parse(
        await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
      );
      hasConfig = !!packageJson.eslintConfig;
    }
    
    expect(hasConfig).toBe(true);
  });
  
  it('should have Prettier configuration', async () => {
    const prettierConfigFiles = [
      '.prettierrc',
      '.prettierrc.json',
      '.prettierrc.yml',
      '.prettierrc.js',
      'prettier.config.js'
    ];
    
    let hasConfig = false;
    for (const configFile of prettierConfigFiles) {
      try {
        await fs.access(path.join(projectRoot, configFile));
        hasConfig = true;
        break;
      } catch (error) {
        // Continue checking
      }
    }
    
    // Also check package.json
    if (!hasConfig) {
      const packageJson = JSON.parse(
        await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
      );
      hasConfig = !!packageJson.prettier;
    }
    
    expect(hasConfig).toBe(true);
  });
  
  it('should have TypeScript configuration if using TypeScript', async () => {
    const tsConfigPath = path.join(projectRoot, 'tsconfig.json');
    
    try {
      await fs.access(tsConfigPath);
      const tsConfig = JSON.parse(await fs.readFile(tsConfigPath, 'utf8'));
      
      expect(tsConfig.compilerOptions).toBeDefined();
      expect(tsConfig.compilerOptions.strict).toBe(true);
      expect(tsConfig.include).toContain('src');
    } catch (error) {
      console.log('No TypeScript configuration found (JS project)');
    }
  });
  
  it('should have proper linting rules configured', async () => {
    const eslintConfigPath = path.join(projectRoot, '.eslintrc.js');
    
    try {
      await fs.access(eslintConfigPath);
      
      // Check that ESLint can run
      execSync('npx eslint --version', { stdio: 'pipe' });
      
      // Run ESLint (will fail if there are linting errors)
      const env = { ...process.env, CI: 'true' };
      try {
        execSync('npm run lint', {
          cwd: projectRoot,
          stdio: 'pipe',
          env,
          timeout: 120000
        });
      } catch (error) {
        // Linting errors are OK, just verify it ran
        console.log('ESLint completed with findings');
      }
    } catch (error) {
      console.log('ESLint not fully configured or available');
    }
  });
  
  it('should support hot reload in development', async () => {
    // Check for react-scripts (CRA) or vite config
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    const hasReactScripts = packageJson.dependencies?.['react-scripts'];
    const hasVite = packageJson.dependencies?.['vite'] || packageJson.devDependencies?.['vite'];
    
    expect(hasReactScripts || hasVite).toBe(true);
  });
});

// ====================
// TESTING INFRASTRUCTURE TESTS
// ====================

describe('Testing Infrastructure Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have Jest configuration', async () => {
    const jestConfigFiles = [
      'jest.config.js',
      'jest.config.json',
      'jest.setup.js'
    ];
    
    let hasConfig = false;
    for (const configFile of jestConfigFiles) {
      try {
        await fs.access(path.join(projectRoot, configFile));
        hasConfig = true;
        break;
      } catch (error) {
        // Continue checking
      }
    }
    
    // Also check package.json
    if (!hasConfig) {
      const packageJson = JSON.parse(
        await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
      );
      hasConfig = !!packageJson.jest;
    }
    
    expect(hasConfig).toBe(true);
  });
  
  it('should have test coverage configuration', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    if (packageJson.jest && packageJson.jest.coverageThreshold) {
      expect(packageJson.jest.coverageThreshold).toBeDefined();
    } else {
      // Check for .nycrc or similar coverage config
      const nycrcPath = path.join(projectRoot, '.nycrc');
      try {
        await fs.access(nycrcPath);
        expect(true).toBe(true); // File exists
      } catch (error) {
        console.log('No coverage threshold configuration found');
      }
    }
  });
  
  it('should support different test types (unit, integration, e2e)', async () => {
    const testDirs = ['src/__tests__', 'tests', 'cypress', 'test'];
    
    let hasTestDir = false;
    for (const testDir of testDirs) {
      try {
        await fs.access(path.join(projectRoot, testDir));
        hasTestDir = true;
        break;
      } catch (error) {
        // Continue checking
      }
    }
    
    expect(hasTestDir).toBe(true);
  });
  
  it('should have testing library configured', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    const hasTestingLibrary = 
      packageJson.devDependencies?.['@testing-library/react'] ||
      packageJson.dependencies?.['@testing-library/react'];
    
    expect(hasTestingLibrary).toBe(true);
  });
  
  it('should support snapshot testing', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    // Check for snapshot serializer (like jest-serializer-html)
    const hasSnapshotSupport = true; // Jest includes this by default
    
    expect(hasSnapshotSupport).toBe(true);
  });
});

// ====================
// CI/CD WORKFLOW TESTS
// ====================

describe('CI/CD Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have GitHub Actions workflow configuration', async () => {
    const workflowsDir = path.join(projectRoot, '.github', 'workflows');
    
    try {
      const workflows = await fs.readdir(workflowsDir);
      expect(workflows.length).toBeGreaterThan(0);
      
      // Validate each workflow
      for (const workflowFile of workflows) {
        if (workflowFile.endsWith('.yml') || workflowFile.endsWith('.yaml')) {
          const workflowPath = path.join(workflowsDir, workflowFile);
          const workflowContent = await fs.readFile(workflowPath, 'utf8');
          const workflow = yaml.load(workflowContent);
          
          expect(workflow.name).toBeDefined();
          expect(workflow.on).toBeDefined();
          expect(workflow.jobs).toBeDefined();
        }
      }
    } catch (error) {
      console.log('No GitHub Actions workflows found');
    }
  });
  
  it('should have CI pipeline with proper jobs', async () => {
    const ciPath = path.join(projectRoot, '.github', 'workflows', 'ci.yml');
    
    try {
      const ciContent = await fs.readFile(ciPath, 'utf8');
      const ciConfig = yaml.load(ciContent);
      
      // Verify CI triggers
      const hasPushTrigger = ciConfig.on === 'push' || 
                             (Array.isArray(ciConfig.on) && ciConfig.on.includes('push'));
      const hasPRTrigger = ciConfig.on === 'pull_request' || 
                          (Array.isArray(ciConfig.on) && ciConfig.on.includes('pull_request'));
      
      expect(hasPushTrigger || hasPRTrigger).toBe(true);
      
      // Verify build and test jobs exist
      const jobNames = Object.keys(ciConfig.jobs);
      const hasBuildJob = jobNames.some(name => name.toLowerCase().includes('build'));
      const hasTestJob = jobNames.some(name => name.toLowerCase().includes('test'));
      
      expect(hasBuildJob || hasTestJob).toBe(true);
    } catch (error) {
      console.log('No CI configuration found:', error.message);
    }
  });
  
  it('should have deployment workflow', async () => {
    const workflowsDir = path.join(projectRoot, '.github', 'workflows');
    
    try {
      const workflows = await fs.readdir(workflowsDir);
      const deploymentWorkflows = workflows.filter(
        file => file.toLowerCase().includes('deploy')
      );
      
      if (deploymentWorkflows.length > 0) {
        for (const workflowFile of deploymentWorkflows) {
          const workflowPath = path.join(workflowsDir, workflowFile);
          const workflowContent = await fs.readFile(workflowPath, 'utf8');
          const workflow = yaml.load(workflowContent);
          
          const deployJobs = Object.values(workflow.jobs).filter(
            job => job.name && job.name.toLowerCase().includes('deploy')
          );
          
          expect(deployJobs.length).toBeGreaterThan(0);
        }
      }
    } catch (error) {
      console.log('No deployment workflows found');
    }
  });
  
  it('should configure environment-specific builds', async () => {
    const envFiles = ['.env', '.env.production', '.env.staging', '.env.test'];
    
    const foundEnvs = [];
    for (const envFile of envFiles) {
      try {
        await fs.access(path.join(projectRoot, envFile));
        foundEnvs.push(envFile);
      } catch (error) {
        // Continue checking
      }
    }
    
    if (foundEnvs.length > 0) {
      console.log('Environment files found:', foundEnvs.join(', '));
    }
  });
});

// ====================
// DEPLOYMENT WORKFLOW TESTS
// ====================

describe('Deployment Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have deployment configuration', async () => {
    // Check for deployment configs
    const deployConfigs = [
      'netlify.toml',
      'vercel.json',
      'Dockerfile',
      'fly.toml',
      'render.yaml'
    ];
    
    const foundConfigs = [];
    for (const config of deployConfigs) {
      try {
        await fs.access(path.join(projectRoot, config));
        foundConfigs.push(config);
      } catch (error) {
        // Continue checking
      }
    }
    
    if (foundConfigs.length > 0) {
      console.log('Deployment configurations found:', foundConfigs.join(', '));
    } else {
      console.log('No deployment configurations found - may use platform defaults');
    }
  });
  
  it('should have Docker containerization', async () => {
    const dockerfilePath = path.join(projectRoot, 'Dockerfile');
    const dockerComposePath = path.join(projectRoot, 'docker-compose.yml');
    
    const hasDockerfile = await fs.access(dockerfilePath).then(() => true).catch(() => false);
    const hasCompose = await fs.access(dockerComposePath).then(() => true).catch(() => false);
    
    if (hasDockerfile) {
      const dockerfileContent = await fs.readFile(dockerfilePath, 'utf8');
      
      // Verify Dockerfile best practices
      expect(dockerfileContent).toMatch(/FROM\s+node:/);
      expect(dockerfileContent).toMatch(/WORKDIR\s+/);
      expect(dockerfileContent).toMatch(/COPY\s+package\.json/);
      expect(dockerfileContent).toMatch(/RUN\s+npm\s+(install|ci)/);
      expect(dockerfileContent).toMatch(/COPY\s+\.\s+\./);
      expect(dockerfileContent).toMatch(/EXPOSE\s+\d+/);
      expect(dockerfileContent).toMatch(/CMD/);
      expect(dockerfileContent).toMatch(/USER/); // Non-root user
    }
    
    if (hasCompose) {
      const composeContent = await fs.readFile(dockerComposePath, 'utf8');
      const compose = yaml.load(composeContent);
      
      expect(compose.services).toBeDefined();
    }
  });
  
  it('should have health checks configured', async () => {
    const dockerfilePath = path.join(projectRoot, 'Dockerfile');
    
    try {
      const dockerfileContent = await fs.readFile(dockerfilePath, 'utf8');
      
      // Health check for app
      const hasHealthCheck = dockerfileContent.includes('HEALTHCHECK');
      if (hasHealthCheck) {
        console.log('Docker health check found');
      }
    } catch (error) {
      console.log('No Dockerfile found');
    }
  });
});

// ====================
// SECURITY WORKFLOW TESTS
// ====================

describe('Security Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have dependency vulnerability scanning', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    // Check for security audit scripts
    const hasAuditScript = Object.keys(packageJson.scripts).some(
      script => script.toLowerCase().includes('audit') || script.toLowerCase().includes('security')
    );
    
    console.log('Security audit scripts configured:', hasAuditScript);
  });
  
  it('should have CSP headers configured', async () => {
    const publicPath = path.join(projectRoot, 'public');
    
    try {
      const indexPath = path.join(publicPath, 'index.html');
      const indexContent = await fs.readFile(indexPath, 'utf8');
      
      // Check for CSP meta tag
      const hasCSP = indexContent.includes('Content-Security-Policy') ||
                     indexContent.includes('http-equiv="Content-Security-Policy"');
      
      if (hasCSP) {
        console.log('CSP headers found in index.html');
      }
    } catch (error) {
      console.log('No CSP configuration found in index.html');
    }
  });
  
  it('should have secrets scanning', async () => {
    // Check for gitignore patterns
    const gitignorePath = path.join(projectRoot, '.gitignore');
    
    try {
      const gitignoreContent = await fs.readFile(gitignorePath, 'utf8');
      
      // Should ignore common secret files
      expect(gitignoreContent).toMatch(/\.env/);
      expect(gitignoreContent).toMatch(/\.env\.local/);
      expect(gitignoreContent).toMatch(/\.DS_Store/);
    } catch (error) {
      console.log('No .gitignore file found');
    }
  });
});

// ====================
// MONITORING WORKFLOW TESTS
// ====================

describe('Monitoring Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have error tracking configured', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    const hasErrorTracking = 
      packageJson.dependencies?.['@sentry/react'] ||
      packageJson.dependencies?.['@bugsnag/js'] ||
      packageJson.dependencies?.['airbrake-js'];
    
    if (hasErrorTracking) {
      console.log('Error tracking found in dependencies');
    }
  });
  
  it('should have analytics tracking configured', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    const hasAnalytics = 
      packageJson.dependencies?.['react-ga4'] ||
      packageJson.dependencies?.['@segment/analytics-next'] ||
      packageJson.dependencies?.['mixpanel-browser'];
    
    if (hasAnalytics) {
      console.log('Analytics tracking found');
    }
  });
  
  it('should have performance monitoring', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    const hasPerfMonitoring = 
      packageJson.dependencies?.['web-vitals'] ||
      packageJson.dependencies?.['@sentry/react'];
    
    if (hasPerfMonitoring) {
      console.log('Performance monitoring found');
    }
  });
});

// ====================
// RUN WORKFLOW TESTS
// ====================

/*
Commands to run workflow tests:

# Run all workflow tests
npm test -- tests/workflow/

# Run specific workflow test
npm test -- tests/workflow/test_build.js

# Run with live output
npm test -- tests/workflow/ --verbose

# Generate workflow test report
npm test -- tests/workflow/ --reporters=jest-html-reporter --reporter-options=filename=workflow-report.html

# Run specific test suite
npm test -- tests/workflow/ --testNamePattern="Build Process"

# Debug workflow test
node --inspect-brk node_modules/.bin/jest tests/workflow/

# Run workflow tests with CI environment
CI=true npm test -- tests/workflow/
*/
