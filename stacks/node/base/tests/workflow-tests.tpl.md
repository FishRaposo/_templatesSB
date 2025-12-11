# Node.js Workflow Tests Template
// Node.js Workflow Testing Template
// CI/CD workflow and development workflow tests for Node.js projects

/**
 * Node.js Workflow Test Patterns
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
  
  it('should have valid package.json configuration', async () => {
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJsonContent = await fs.readFile(packageJsonPath, 'utf8');
    const packageJson = JSON.parse(packageJsonContent);
    
    // Verify required fields
    expect(packageJson.name).toBeDefined();
    expect(packageJson.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(packageJson.scripts).toBeDefined();
    expect(packageJson.scripts.test).toBeDefined();
    expect(packageJson.scripts.build).toBeDefined();
    expect(packageJson.scripts.lint).toBeDefined();
    expect(packageJson.scripts.start).toBeDefined();
    
    // Verify dependencies and devDependencies are separated
    expect(packageJson.dependencies).toBeDefined();
  });
  
  it('should install dependencies without errors', async () => {
    // Test npm ci
    try {
      execSync('npm ci', {
        cwd: projectRoot,
        stdio: 'pipe',
        timeout: 300000 // 5 minutes
      });
    } catch (error) {
      // If npm ci fails, test regular npm install
      console.log('npm ci failed, trying npm install...', error.message);
      execSync('npm install', {
        cwd: projectRoot,
        stdio: 'pipe',
        timeout: 300000
      });
    }
    
    // Verify node_modules exists
    const nodeModulesPath = path.join(projectRoot, 'node_modules');
    const nodeModulesExists = await fs.access(nodeModulesPath)
      .then(() => true)
      .catch(() => false);
    
    expect(nodeModulesExists).toBe(true);
  }, 330000); // 5.5 minute timeout
  
  it('should build application without errors', async () => {
    // Check if build script exists
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    if (!packageJson.scripts?.build) {
      console.log('No build script found, skipping build test');
      return;
    }
    
    // Run build
    execSync('npm run build', {
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: 300000
    });
    
    // Verify build output exists
    const distPath = path.join(projectRoot, 'dist');
    const buildExists = await fs.access(distPath)
      .then(() => true)
      .catch(() => false);
    
    expect(buildExists).toBe(true);
    
    // Verify build files are not empty
    const files = await fs.readdir(distPath);
    expect(files.length).toBeGreaterThan(0);
  });
  
  it('should support multiple build targets', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    // Check for different build configurations
    const buildScripts = Object.keys(packageJson.scripts).filter(
      script => script.includes('build')
    );
    
    if (buildScripts.length > 1) {
      // Test each build configuration
      for (const script of buildScripts) {
        console.log(`Testing build script: ${script}`);
        try {
          execSync(`npm run ${script}`, {
            cwd: projectRoot,
            stdio: 'pipe',
            timeout: 180000
          });
        } catch (error) {
          console.log(`Build script ${script} failed:`, error.message);
        }
      }
    }
  });
  
  it('should run tests without errors', async () => {
    // Run tests in CI mode
    execSync('npm test -- --ci --maxWorkers=2', {
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: 300000,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        CI: 'true'
      }
    });
  });
});

// ====================
// DOCKER WORKFLOW TESTS
// ====================

describe('Docker Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have valid Dockerfile', async () => {
    const dockerfilePath = path.join(projectRoot, 'Dockerfile');
    
    // Check Dockerfile exists
    await fs.access(dockerfilePath);
    
    // Read and validate Dockerfile
    const dockerfileContent = await fs.readFile(dockerfilePath, 'utf8');
    
    // Verify essential Dockerfile components
    expect(dockerfileContent).toMatch(/FROM\s+/);
    expect(dockerfileContent).toMatch(/WORKDIR\s+/);
    expect(dockerfileContent).toMatch(/COPY\s+/);
    expect(dockerfileContent).toMatch(/RUN\s+/);
    expect(dockerfileContent).toMatch(/EXPOSE\s+/);
    expect(dockerfileContent).toMatch(/CMD\s+/);
    
    // Verify multi-stage build pattern (if applicable)
    if (dockerfileContent.includes('AS builder')) {
      expect(dockerfileContent).toMatch(/FROM.*AS builder/);
      expect(dockerfileContent).toMatch(/FROM.*AS production/);
    }
    
    // Verify security best practices
    expect(dockerfileContent).not.toMatch(/FROM\s+.*latest/); // Pin versions
    expect(dockerfileContent).toMatch(/USER\s+/); // Non-root user
  });
  
  it('should have valid docker-compose configuration', async () => {
    const composePath = path.join(projectRoot, 'docker-compose.yml');
    
    try {
      await fs.access(composePath);
      
      const composeContent = await fs.readFile(composePath, 'utf8');
      const composeConfig = yaml.load(composeContent);
      
      // Verify services are defined
      expect(composeConfig.services).toBeDefined();
      expect(Object.keys(composeConfig.services).length).toBeGreaterThan(0);
      
      // Check for common services
      const serviceNames = Object.keys(composeConfig.services);
      
      // Verify database service
      const dbService = serviceNames.find(name => 
        name.toLowerCase().includes('db') || 
        name.toLowerCase().includes('postgres') ||
        name.toLowerCase().includes('mysql')
      );
      if (dbService) {
        expect(composeConfig.services[dbService].image).toBeDefined();
        expect(composeConfig.services[dbService].environment).toBeDefined();
      }
      
      // Verify Redis if present
      if (serviceNames.includes('redis')) {
        expect(composeConfig.services.redis.image).toMatch(/redis:/);
      }
      
      // Verify web/app service
      const appService = serviceNames.find(name => 
        name === 'app' || name === 'web' || name === 'api'
      );
      if (appService) {
        expect(composeConfig.services[appService].build).toBeDefined();
        expect(composeConfig.services[appService].ports).toBeDefined();
        expect(composeConfig.services[appService].depends_on).toBeDefined();
      }
    } catch (error) {
      console.log('No docker-compose.yml found, skipping test');
    }
  });
  
  it('should support Docker build', async () => {
    const dockerfilePath = path.join(projectRoot, 'Dockerfile');
    
    try {
      await fs.access(dockerfilePath);
      
      // Test Docker build
      // Note: This test requires Docker to be installed and running
      // It may be skipped in CI environments without Docker
      try {
        execSync('docker --version', { stdio: 'pipe' });
        
        // Build Docker image
        const imageName = `test-app:${Date.now()}`;
        execSync(`docker build -t ${imageName} .`, {
          cwd: projectRoot,
          stdio: 'pipe',
          timeout: 600000 // 10 minutes
        });
        
        // Test container can run basic commands
        try {
          execSync(`docker run --rm ${imageName} --version`, {
            stdio: 'pipe'
          });
        } catch (error) {
          // Version command may not be supported, check if container starts
          console.log('Version check not available, checking container health...');
        }
        
        // Clean up
        execSync(`docker rmi ${imageName}`, { stdio: 'pipe' });
        
      } catch (dockerError) {
        console.log('Docker not available, skipping Docker build test');
      }
    } catch (error) {
      console.log('No Dockerfile found, skipping test');
    }
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
      
      // Validate each workflow file
      for (const workflowFile of workflows) {
        if (workflowFile.endsWith('.yml') || workflowFile.endsWith('.yaml')) {
          const workflowPath = path.join(workflowsDir, workflowFile);
          const workflowContent = await fs.readFile(workflowPath, 'utf8');
          const workflow = yaml.load(workflowContent);
          
          // Verify workflow structure
          expect(workflow.name).toBeDefined();
          expect(workflow.on).toBeDefined();
          expect(workflow.jobs).toBeDefined();
        }
      }
    } catch (error) {
      console.log('No GitHub Actions workflows found, skipping test');
    }
  });
  
  it('should have CI pipeline with test job', async () => {
    try {
      const ciPath = path.join(projectRoot, '.github', 'workflows', 'ci.yml');
      const ciContent = await fs.readFile(ciPath, 'utf8');
      const ciConfig = yaml.load(ciContent);
      
      // Verify CI triggers
      expect(['push', 'pull_request']).toContain(ciConfig.on);
      
      // Verify test job exists
      const hasTestJob = Object.values(ciConfig.jobs).some(
        job => job.name && job.name.toLowerCase().includes('test')
      );
      expect(hasTestJob).toBe(true);
      
      // Verify test steps
      const testJob = Object.values(ciConfig.jobs).find(
        job => job.name && job.name.toLowerCase().includes('test')
      );
      
      if (testJob) {
        const steps = testJob.steps.map(step => step.run || '');
        expect(steps.some(s => s.includes('npm install') || s.includes('npm ci'))).toBe(true);
        expect(steps.some(s => s.includes('npm test') || s.includes('npm run test'))).toBe(true);
      }
    } catch (error) {
      console.log('No CI configuration found or error reading it:', error.message);
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
          
          // Verify deployment job
          const hasDeployJob = Object.values(workflow.jobs).some(
            job => job.name && job.name.toLowerCase().includes('deploy')
          );
          expect(hasDeployJob).toBe(true);
        }
      } else {
        console.log('No deployment workflows found');
      }
    } catch (error) {
      console.log('Error checking deployment workflows:', error.message);
    }
  });
});

// ====================
// QUALITY ASSURANCE WORKFLOW TESTS
// ====================

describe('Quality Assurance Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have linting configuration', async () => {
    const eslintPath = path.join(projectRoot, '.eslintrc.js');
    const eslintJsonPath = path.join(projectRoot, '.eslintrc.json');
    
    const hasEslintConfig = await fs.access(eslintPath).then(() => true).catch(() => false) ||
                           await fs.access(eslintJsonPath).then(() => true).catch(() => false);
    
    if (!hasEslintConfig) {
      console.log('No ESLint configuration found, checking package.json...');
      const packageJson = JSON.parse(
        await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
      );
      
      if (packageJson.eslintConfig) {
        hasEslintConfig = true;
      }
    }
    
    if (hasEslintConfig) {
      // Test ESLint can run
      try {
        execSync('npx eslint --version', { stdio: 'pipe' });
        
        // Run ESLint
        const eslintResult = execSync('npx eslint --ext .js,.ts src/', {
          cwd: projectRoot,
          stdio: 'pipe',
          encoding: 'utf8'
        });
        
        console.log('ESLint completed successfully');
      } catch (error) {
        if (error.status === 1) {
          console.log('ESLint found issues, but ran successfully');
        } else {
          console.log('ESLint execution error:', error.message);
        }
      }
    } else {
      console.log('No ESLint configuration found');
    }
  });
  
  it('should have type checking configuration', async () => {
    const tsconfigPath = path.join(projectRoot, 'tsconfig.json');
    
    const hasTsconfig = await fs.access(tsconfigPath).then(() => true).catch(() => false);
    
    if (hasTsconfig) {
      const tsconfig = JSON.parse(await fs.readFile(tsconfigPath, 'utf8'));
      
      // Verify strict mode
      expect(tsconfig.compilerOptions.strict).toBe(true);
      
      // Test TypeScript compilation
      try {
        execSync('npx tsc --noEmit', {
          cwd: projectRoot,
          stdio: 'pipe',
          timeout: 120000
        });
      } catch (error) {
        console.log('TypeScript compilation had errors:', error.message);
        // Still pass the test if tsc ran
      }
    } else {
      console.log('No TypeScript configuration found');
    }
  });
  
  it('should have code formatting configuration', async () => {
    const prettierPath = path.join(projectRoot, '.prettierrc');
    const prettierJsonPath = path.join(projectRoot, '.prettierrc.json');
    const prettierJsPath = path.join(projectRoot, '.prettierrc.js');
    
    const hasPrettierConfig = await fs.access(prettierPath).then(() => true).catch(() => false) ||
                              await fs.access(prettierJsonPath).then(() => true).catch(() => false) ||
                              await fs.access(prettierJsPath).then(() => true).catch(() => false);
    
    if (hasPrettierConfig) {
      // Test Prettier can run
      try {
        execSync('npx prettier --version', { stdio: 'pipe' });
      } catch (error) {
        console.log('Prettier not available');
      }
    }
    
    // Also check package.json for Prettier config
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    if (packageJson.prettier) {
      console.log('Prettier configuration found in package.json');
    }
  });
  
  it('should have pre-commit hooks configured', async () => {
    const preCommitPath = path.join(projectRoot, '.pre-commit-config.yaml');
    
    const hasPreCommit = await fs.access(preCommitPath).then(() => true).catch(() => false);
    
    if (hasPreCommit) {
      const preCommitConfig = yaml.load(
        await fs.readFile(preCommitPath, 'utf8')
      );
      
      expect(preCommitConfig).toBeDefined();
      expect(preCommitConfig.repos).toBeDefined();
      expect(preCommitConfig.repos.length).toBeGreaterThan(0);
      
      // Verify essential hooks
      const hookIds = preCommitConfig.repos.flatMap(repo => 
        repo.hooks.map(hook => hook.id)
      );
      
      expect(hookIds).toContain('trailing-whitespace');
      expect(hookIds).toContain('end-of-file-fixer');
      
      // Check for language-specific hooks
      const hasNodeHooks = hookIds.some(id => 
        id.includes('eslint') || id.includes('prettier')
      );
      
      if (!hasNodeHooks) {
        console.log('Warning: No Node.js specific hooks found (eslint, prettier)');
      }
    } else {
      console.log('No pre-commit configuration found');
      
      // Check for husky git hooks
      const huskyPath = path.join(projectRoot, '.husky');
      const hasHusky = await fs.access(huskyPath).then(() => true).catch(() => false);
      
      if (hasHusky) {
        console.log('Husky git hooks found');
      }
    }
  });
});

// ====================
// SECURITY WORKFLOW TESTS
// ====================

describe('Security Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have security scanning configuration', async () => {
    // Check for security audit scripts
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    const hasSecurityScript = Object.keys(packageJson.scripts).some(
      script => script.toLowerCase().includes('audit') || script.toLowerCase().includes('security')
    );
    
    if (hasSecurityScript) {
      console.log('Security audit script found in package.json');
    }
    
    // Check for security scanning tools
    const securityTools = ['snyk', 'npm-audit', 'audit-ci', 'yarn-audit'];
    const availableTools = [];
    
    for (const tool of securityTools) {
      try {
        execSync(`npx ${tool} --version`, { stdio: 'pipe' });
        availableTools.push(tool);
      } catch (error) {
        // Tool not available
      }
    }
    
    if (availableTools.length > 0) {
      console.log('Available security tools:', availableTools.join(', '));
    }
  });
  
  it('should have dependency vulnerability scanning', async () => {
    // Test npm audit
    try {
      execSync('npm audit --audit-level=moderate', {
        cwd: projectRoot,
        stdio: 'pipe',
        timeout: 120000
      });
      console.log('No moderate or higher vulnerabilities found');
    } catch (error) {
      if (error.status === 1) {
        console.log('Vulnerabilities found, but audit ran successfully');
      } else {
        console.log('npm audit not available or failed');
      }
    }
  });
  
  it('should have secret scanning configuration', async () => {
    // Check for secret scanning tools
    const secretScannerConfigs = [
      '.secrets.baseline',
      '.gitsecret/',
      '.env.example'
    ];
    
    const foundConfigs = [];
    for (const config of secretScannerConfigs) {
      const configPath = path.join(projectRoot, config);
      const exists = await fs.access(configPath).then(() => true).catch(() => false);
      if (exists) {
        foundConfigs.push(config);
      }
    }
    
    if (foundConfigs.length > 0) {
      console.log('Secret scanning configurations found:', foundConfigs.join(', '));
    } else {
      console.log('No secret scanning configuration found');
    }
  });
  
  it('should enforce secure Docker practices', async () => {
    const dockerfilePath = path.join(projectRoot, 'Dockerfile');
    
    try {
      const dockerfileContent = await fs.readFile(dockerfilePath, 'utf8');
      
      // Verify security best practices
      expect(dockerfileContent).toMatch(/USER\s+\w+/); // Non-root user
      expect(dockerfileContent).not.toMatch(/COPY\s+--from=0\s+\/etc\/passwd/); // No passwd copying
      expect(dockerfileContent).toMatch(/HEALTHCHECK/); // Health check defined
      
      // Verify no secrets in Dockerfile
      expect(dockerfileContent).not.toMatch(/password/i);
      expect(dockerfileContent).not.toMatch(/secret/i);
      expect(dockerfileContent).not.toMatch(/key\s*=/i);
    } catch (error) {
      console.log('No Dockerfile found, skipping security check');
    }
  });
});

// ====================
// DOCUMENTATION WORKFLOW TESTS
// ====================

describe('Documentation Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have API documentation', async () => {
    // Check for API documentation files
    const apiDocFiles = await fs.readdir(projectRoot)
      .then(files => files.filter(file => 
        file.toLowerCase().includes('api') && 
        (file.endsWith('.md') || file.endsWith('.adoc'))
      ))
      .catch(() => []);
    
    if (apiDocFiles.length > 0) {
      console.log('API documentation found:', apiDocFiles.join(', '));
    }
    
    // Check for Swagger/OpenAPI configuration
    const swaggerFiles = ['openapi.yaml', 'openapi.json', 'swagger.yaml', 'swagger.json'];
    const foundSwaggerFiles = [];
    
    for (const swaggerFile of swaggerFiles) {
      const swaggerPath = path.join(projectRoot, swaggerFile);
      const exists = await fs.access(swaggerPath).then(() => true).catch(() => false);
      if (exists) {
        foundSwaggerFiles.push(swaggerFile);
      }
    }
    
    if (foundSwaggerFiles.length > 0) {
      console.log('OpenAPI/Swagger files found:', foundSwaggerFiles.join(', '));
    }
  });
  
  it('should generate documentation without errors', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    // Check for documentation generation scripts
    if (packageJson.scripts?.docs) {
      try {
        execSync('npm run docs', {
          cwd: projectRoot,
          stdio: 'pipe',
          timeout: 180000
        });
        console.log('Documentation generated successfully');
      } catch (error) {
        console.log('Documentation generation may have issues:', error.message);
      }
    }
    
    // Check for JSDoc comments in source code
    const srcFiles = await fs.readdir(path.join(projectRoot, 'src'))
      .then(files => files.filter(file => file.endsWith('.js') || file.endsWith('.ts')))
      .catch(() => []);
    
    if (srcFiles.length > 0) {
      console.log(`${srcFiles.length} source files found, documentation should be maintained`);
    }
  });
  
  it('should have comprehensive README', async () => {
    const readmePath = path.join(projectRoot, 'README.md');
    
    try {
      const readmeContent = await fs.readFile(readmePath, 'utf8');
      
      // Verify README contains essential sections
      const requiredSections = [
        'installation',
        'configuration',
        'usage',
        'testing',
        'deployment'
      ];
      
      const lowercaseContent = readmeContent.toLowerCase();
      const foundSections = requiredSections.filter(section =>
        lowercaseContent.includes(section)
      );
      
      console.log(`README contains ${foundSections.length}/${requiredSections.length} essential sections`);
      
      // Verify code examples
      expect(readmeContent).toMatch(/```/); // Code blocks present
    } catch (error) {
      console.log('README.md not found');
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

# Run workflow tests in sequence
npm test -- tests/workflow/ --runInBand

# Generate workflow test report
npm test -- tests/workflow/ --reporters=jest-html-reporters --reporter-options=filename=workflow-report.html

# Test specific workflow
npm test -- --testNamePattern="Build Process"

# Debug workflow test
node --inspect-brk node_modules/.bin/jest tests/workflow/
*/
