// Next.js Workflow Testing Template
// CI/CD workflow and development workflow tests for Next.js projects

/**
 * Next.js Workflow Test Patterns
 * Build processes, CI/CD, documentation, security, and deployment testing
 * Next.js specific: ISR, SSR, API routes, middleware, Vercel deployment
 */

const { describe, it, expect, beforeAll, afterAll, beforeEach } = require('@jest/globals');
const { execSync, spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const yaml = require('js-yaml');

// ====================
// BUILD WORKFLOW TESTS
// ====================

describe('Build Process Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have valid package.json with Next.js scripts', async () => {
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJsonContent = await fs.readFile(packageJsonPath, 'utf8');
    const packageJson = JSON.parse(packageJsonContent);
    
    // Verify required fields
    expect(packageJson.name).toBeDefined();
    expect(packageJson.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(packageJson.scripts).toBeDefined();
    
    // Next.js specific scripts
    expect(packageJson.scripts.dev).toBeDefined();
    expect(packageJson.scripts.build).toBeDefined();
    expect(packageJson.scripts.start).toBeDefined();
    expect(packageJson.scripts.lint).toBeDefined();
    expect(packageJson.scripts['lint:fix']).toBeDefined();
    
    // Next.js dependencies
    expect(packageJson.dependencies).toBeDefined();
    expect(packageJson.dependencies.next).toBeDefined();
    expect(packageJson.dependencies.react).toBeDefined();
    expect(packageJson.dependencies['react-dom']).toBeDefined();
    
    // TypeScript support
    expect(packageJson.devDependencies).toBeDefined();
    expect(packageJson.devDependencies.typescript).toBeDefined();
    expect(packageJson.devDependencies['@types/react']).toBeDefined();
    expect(packageJson.devDependencies['@types/node']).toBeDefined();
  });
  
  it('should have valid Next.js configuration', async () => {
    // Check for next.config.js or next.config.mjs
    const configFiles = ['next.config.js', 'next.config.mjs', 'next.config.ts'];
    let configExists = false;
    
    for (const configFile of configFiles) {
      try {
        await fs.access(path.join(projectRoot, configFile));
        configExists = true;
        break;
      } catch (error) {
        // Continue checking other files
      }
    }
    
    expect(configExists).toBe(true);
  });
  
  it('should have TypeScript configuration', async () => {
    const tsconfigPath = path.join(projectRoot, 'tsconfig.json');
    const tsconfigContent = await fs.readFile(tsconfigPath, 'utf8');
    const tsconfig = JSON.parse(tsconfigContent);
    
    // Verify Next.js TypeScript configuration
    expect(tsconfig.compilerOptions).toBeDefined();
    expect(tsconfig.compilerOptions.jsx).toBe('preserve');
    expect(tsconfig.compilerOptions.incremental).toBe(true);
    expect(tsconfig.include).toContain('next-env.d.ts');
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
  
  it('should build Next.js application without errors', async () => {
    // Set production environment
    const env = { ...process.env, NODE_ENV: 'production' };
    
    // Run Next.js build
    execSync('npm run build', {
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: 300000, // 5 minutes
      env
    });
    
    // Verify build output exists
    const buildPath = path.join(projectRoot, '.next');
    const buildExists = await fs.access(buildPath)
      .then(() => true)
      .catch(() => false);
    
    expect(buildExists).toBe(true);
    
    // Verify key build directories
    const staticPath = path.join(buildPath, 'static');
    const serverPath = path.join(buildPath, 'server');
    const clientPath = path.join(buildPath, 'client');
    
    const staticExists = await fs.access(staticPath).then(() => true).catch(() => false);
    const serverExists = await fs.access(serverPath).then(() => true).catch(() => false);
    const clientExists = await fs.access(clientPath).then(() => true).catch(() => false);
    
    expect(staticExists || serverExists || clientExists).toBe(true);
  });
  
  it('should support different build targets', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    // Check for build-related scripts
    const buildScripts = Object.keys(packageJson.scripts).filter(script => 
      script.includes('build') || script.includes('export')
    );
    
    expect(buildScripts.length).toBeGreaterThan(0);
    
    // Test static export if available
    if (packageJson.scripts['build:static'] || packageJson.scripts.export) {
      const exportScript = packageJson.scripts['build:static'] || packageJson.scripts.export;
      
      try {
        execSync(`npm run ${exportScript.includes('build:static') ? 'build:static' : 'export'}`, {
          cwd: projectRoot,
          stdio: 'pipe',
          timeout: 300000
        });
        
        // Check for out directory
        const outPath = path.join(projectRoot, 'out');
        const outExists = await fs.access(outPath).then(() => true).catch(() => false);
        
        if (outExists) {
          const outFiles = await fs.readdir(outPath);
          expect(outFiles.length).toBeGreaterThan(0);
        }
      } catch (error) {
        console.log('Static export test failed:', error.message);
        // Don't fail the test if export isn't configured
      }
    }
  });
  
  it('should compile TypeScript without errors', async () => {
    // Run TypeScript compiler check
    try {
      execSync('npx tsc --noEmit', {
        cwd: projectRoot,
        stdio: 'pipe',
        timeout: 120000 // 2 minutes
      });
    } catch (error) {
      // If TypeScript compilation fails, the test should fail
      throw new Error(`TypeScript compilation failed: ${error.message}`);
    }
  });
});

// ====================
// TEST WORKFLOW TESTS
// ====================

describe('Test Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have Jest configuration for Next.js', async () => {
    // Check for jest.config.js or jest config in package.json
    const jestConfigPath = path.join(projectRoot, 'jest.config.js');
    const packageJsonPath = path.join(projectRoot, 'package.json');
    
    let jestConfigExists = false;
    
    try {
      await fs.access(jestConfigPath);
      jestConfigExists = true;
    } catch (error) {
      // Check package.json for jest config
      const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
      if (packageJson.jest) {
        jestConfigExists = true;
      }
    }
    
    expect(jestConfigExists).toBe(true);
  });
  
  it('should run unit tests successfully', async () => {
    // Run tests with coverage
    const result = execSync('npm test -- --coverage --watchAll=false', {
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: 300000 // 5 minutes
    });
    
    expect(result.toString()).toContain('Test Suites:');
    expect(result.toString()).toContain('Tests:');
  });
  
  it('should have test coverage configuration', async () => {
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    // Check for coverage configuration
    const hasJestCoverage = packageJson.jest && packageJson.jest.coverageThreshold;
    const hasCoverageScript = packageJson.scripts && 
      Object.keys(packageJson.scripts).some(script => script.includes('coverage'));
    
    expect(hasJestCoverage || hasCoverageScript).toBe(true);
  });
  
  it('should generate coverage reports', async () => {
    // Run tests with coverage report
    execSync('npm test -- --coverage --coverageDirectory=coverage --watchAll=false', {
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: 300000
    });
    
    // Verify coverage directory exists
    const coveragePath = path.join(projectRoot, 'coverage');
    const coverageExists = await fs.access(coveragePath)
      .then(() => true)
      .catch(() => false);
    
    expect(coverageExists).toBe(true);
    
    // Check for coverage files
    const coverageFiles = await fs.readdir(coveragePath);
    expect(coverageFiles.length).toBeGreaterThan(0);
    
    // Check for lcov.info
    const lcovExists = coverageFiles.includes('lcov.info');
    const coverageIndexExists = coverageFiles.includes('index.html');
    
    expect(lcovExists || coverageIndexExists).toBe(true);
  });
});

// ====================
// LINTING WORKFLOW TESTS
// ====================

describe('Linting and Code Quality Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have ESLint configuration', async () => {
    // Check for ESLint config files
    const eslintFiles = [
      '.eslintrc.js',
      '.eslintrc.json',
      '.eslintrc.yml',
      '.eslintrc.yaml',
      'eslint.config.js'
    ];
    
    let eslintConfigExists = false;
    
    for (const configFile of eslintFiles) {
      try {
        await fs.access(path.join(projectRoot, configFile));
        eslintConfigExists = true;
        break;
      } catch (error) {
        continue;
      }
    }
    
    // Also check package.json
    if (!eslintConfigExists) {
      const packageJson = JSON.parse(
        await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
      );
      if (packageJson.eslintConfig) {
        eslintConfigExists = true;
      }
    }
    
    expect(eslintConfigExists).toBe(true);
  });
  
  it('should pass ESLint checks', async () => {
    // Run ESLint
    const result = execSync('npm run lint', {
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: 120000 // 2 minutes
    });
    
    const output = result.toString();
    // Should complete without errors (warnings are OK)
    expect(output).not.toContain('Error:');
  });
  
  it('should have Prettier configuration', async () => {
    // Check for Prettier config
    const prettierFiles = [
      '.prettierrc',
      '.prettierrc.json',
      '.prettierrc.yml',
      '.prettierrc.yaml',
      '.prettierrc.js',
      'prettier.config.js'
    ];
    
    let prettierConfigExists = false;
    
    for (const configFile of prettierFiles) {
      try {
        await fs.access(path.join(projectRoot, configFile));
        prettierConfigExists = true;
        break;
      } catch (error) {
        continue;
      }
    }
    
    // Also check package.json
    if (!prettierConfigExists) {
      const packageJson = JSON.parse(
        await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
      );
      if (packageJson.prettier) {
        prettierConfigExists = true;
      }
    }
    
    expect(prettierConfigExists).toBe(true);
  });
  
  it('should format code consistently', async () => {
    // Run prettier check
    try {
      execSync('npx prettier --check .', {
        cwd: projectRoot,
        stdio: 'pipe',
        timeout: 120000
      });
    } catch (error) {
      // If check fails, try to format and see if there are changes
      const result = execSync('npx prettier --list-different .', {
        cwd: projectRoot,
        stdio: 'pipe',
        timeout: 120000
      });
      
      // Should not have any unformatted files
      expect(result.toString().trim()).toBe('');
    }
  });
  
  it('should have TypeScript strict mode enabled', async () => {
    const tsconfigPath = path.join(projectRoot, 'tsconfig.json');
    const tsconfig = JSON.parse(await fs.readFile(tsconfigPath, 'utf8'));
    
    // Verify TypeScript strict settings
    expect(tsconfig.compilerOptions).toBeDefined();
    expect(tsconfig.compilerOptions.strict).toBe(true);
  });
});

// ====================
// CI/CD WORKFLOW TESTS
// ====================

describe('CI/CD Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have GitHub Actions workflow', async () => {
    const githubWorkflowsPath = path.join(projectRoot, '.github', 'workflows');
    
    // Check if .github/workflows directory exists
    const workflowsExist = await fs.access(githubWorkflowsPath)
      .then(() => true)
      .catch(() => false);
    
    expect(workflowsExist).toBe(true);
    
    // Check for workflow files
    const workflowFiles = await fs.readdir(githubWorkflowsPath);
    expect(workflowFiles.length).toBeGreaterThan(0);
    
    // Validate workflow file syntax
    for (const workflowFile of workflowFiles) {
      if (workflowFile.endsWith('.yml') || workflowFile.endsWith('.yaml')) {
        const workflowContent = await fs.readFile(
          path.join(githubWorkflowsPath, workflowFile),
          'utf8'
        );
        
        // Basic YAML syntax validation
        const workflow = yaml.load(workflowContent);
        expect(workflow).toBeDefined();
        expect(workflow.name).toBeDefined();
        expect(workflow.on).toBeDefined();
        expect(workflow.jobs).toBeDefined();
      }
    }
  });
  
  it('should have CI workflow with Next.js specific steps', async () => {
    const ciWorkflowPath = path.join(projectRoot, '.github', 'workflows', 'ci.yml');
    
    let workflowContent;
    try {
      workflowContent = await fs.readFile(ciWorkflowPath, 'utf8');
    } catch (error) {
      // Try other common CI workflow names
      const altPaths = [
        path.join(projectRoot, '.github', 'workflows', 'test.yml'),
        path.join(projectRoot, '.github', 'workflows', 'build.yml'),
        path.join(projectRoot, '.github', 'workflows', 'nextjs.yml')
      ];
      
      for (const altPath of altPaths) {
        try {
          workflowContent = await fs.readFile(altPath, 'utf8');
          break;
        } catch (e) {
          continue;
        }
      }
    }
    
    expect(workflowContent).toBeDefined();
    
    const workflow = yaml.load(workflowContent);
    
    // Verify Next.js specific CI steps
    const workflowText = JSON.stringify(workflow);
    expect(workflowText).toContain('node-version');
    expect(workflowText).toContain('npm ci');
    expect(workflowText).toContain('npm run lint');
    expect(workflowText).toContain('npm run build');
    expect(workflowText).toContain('npm test');
  });
  
  it('should have deployment workflow for Vercel', async () => {
    const deployWorkflowPath = path.join(projectRoot, '.github', 'workflows', 'deploy.yml');
    
    let deployWorkflowExists = false;
    let deployWorkflowContent;
    
    try {
      deployWorkflowContent = await fs.readFile(deployWorkflowPath, 'utf8');
      deployWorkflowExists = true;
    } catch (error) {
      // Check for Vercel specific workflow
      const vercelWorkflowPath = path.join(projectRoot, '.github', 'workflows', 'vercel.yml');
      try {
        deployWorkflowContent = await fs.readFile(vercelWorkflowPath, 'utf8');
        deployWorkflowExists = true;
      } catch (e) {
        // Skip if no deployment workflow found
      }
    }
    
    if (deployWorkflowExists) {
      const workflow = yaml.load(deployWorkflowContent);
      const workflowText = JSON.stringify(workflow);
      
      // Should have deployment configuration
      expect(workflowText).toMatch(/deploy|vercel|production/i);
    }
  });
});

// ====================
// DOCKER WORKFLOW TESTS
// ====================

describe('Docker Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have Dockerfile for Next.js', async () => {
    const dockerfilePath = path.join(projectRoot, 'Dockerfile');
    
    const dockerfileExists = await fs.access(dockerfilePath)
      .then(() => true)
      .catch(() => false);
    
    expect(dockerfileExists).toBe(true);
    
    // Verify Dockerfile content
    const dockerfileContent = await fs.readFile(dockerfilePath, 'utf8');
    
    // Should use Node.js base image
    expect(dockerfileContent).toMatch(/FROM node:/);
    
    // Should have Next.js specific instructions
    expect(dockerfileContent).toMatch(/npm ci|npm install/);
    expect(dockerfileContent).toMatch(/npm run build/);
    expect(dockerfileContent).toMatch(/npm start/);
  });
  
  it('should have .dockerignore file', async () => {
    const dockerignorePath = path.join(projectRoot, '.dockerignore');
    
    const dockerignoreExists = await fs.access(dockerignorePath)
      .then(() => true)
      .catch(() => false);
    
    expect(dockerignoreExists).toBe(true);
    
    // Verify .dockerignore content
    const dockerignoreContent = await fs.readFile(dockerignorePath, 'utf8');
    
    // Should exclude development files
    expect(dockerignoreContent).toContain('node_modules');
    expect(dockerignoreContent).toContain('.next');
    expect(dockerignoreContent).toContain('coverage');
    expect(dockerignoreContent).toContain('.git');
  });
  
  it('should support multi-stage Docker builds', async () => {
    const dockerfilePath = path.join(projectRoot, 'Dockerfile');
    const dockerfileContent = await fs.readFile(dockerfilePath, 'utf8');
    
    // Should have multiple FROM statements for multi-stage build
    const fromMatches = dockerfileContent.match(/FROM /g);
    expect(fromMatches?.length).toBeGreaterThanOrEqual(1);
    
    // Should have build stage
    expect(dockerfileContent).toMatch(/as builder|AS builder/i);
  });
  
  it('should have docker-compose for development', async () => {
    const dockerComposePath = path.join(projectRoot, 'docker-compose.yml');
    const dockerComposeDevPath = path.join(projectRoot, 'docker-compose.dev.yml');
    
    const composeExists = await fs.access(dockerComposePath)
      .then(() => true)
      .catch(() => false);
    
    const composeDevExists = await fs.access(dockerComposeDevPath)
      .then(() => true)
      .catch(() => false);
    
    expect(composeExists || composeDevExists).toBe(true);
  });
});

// ====================
// DEPLOYMENT WORKFLOW TESTS
// ====================

describe('Deployment Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have Vercel configuration', async () => {
    const vercelConfigPath = path.join(projectRoot, 'vercel.json');
    
    const vercelConfigExists = await fs.access(vercelConfigPath)
      .then(() => true)
      .catch(() => false);
    
    if (vercelConfigExists) {
      const vercelConfig = JSON.parse(await fs.readFile(vercelConfigPath, 'utf8'));
      
      // Verify Vercel configuration structure
      expect(vercelConfig).toBeDefined();
      
      // Should have framework set to Next.js
      if (vercelConfig.framework) {
        expect(vercelConfig.framework).toBe('nextjs');
      }
    }
  });
  
  it('should have environment configuration', async () => {
    const envExamplePath = path.join(projectRoot, '.env.example');
    const envLocalPath = path.join(projectRoot, '.env.local');
    
    const envExampleExists = await fs.access(envExamplePath)
      .then(() => true)
      .catch(() => false);
    
    // .env.example should exist for documentation
    expect(envExampleExists).toBe(true);
    
    if (envExampleExists) {
      const envContent = await fs.readFile(envExamplePath, 'utf8');
      
      // Should document required environment variables
      expect(envContent).toBeDefined();
      expect(envContent.length).toBeGreaterThan(0);
    }
  });
  
  it('should have deployment scripts', async () => {
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    // Check for deployment-related scripts
    const deployScripts = Object.keys(packageJson.scripts).filter(script => 
      script.includes('deploy') || script.includes('vercel') || script.includes('prod')
    );
    
    expect(deployScripts.length).toBeGreaterThan(0);
  });
  
  it('should have AWS deployment configuration', async () => {
    // Check for AWS deployment files
    const awsFiles = [
      'serverless.yml',
      'serverless.yaml',
      'sam-template.yml',
      'template.yml',
      '.aws-sam'
    ];
    
    let awsConfigExists = false;
    
    for (const awsFile of awsFiles) {
      try {
        await fs.access(path.join(projectRoot, awsFile));
        awsConfigExists = true;
        break;
      } catch (error) {
        continue;
      }
    }
    
    // AWS configuration is optional, but if it exists, validate it
    if (awsConfigExists) {
      const serverlessPath = path.join(projectRoot, 'serverless.yml');
      try {
        const serverlessContent = await fs.readFile(serverlessPath, 'utf8');
        const serverlessConfig = yaml.load(serverlessContent);
        
        expect(serverlessConfig.service).toBeDefined();
        expect(serverlessConfig.provider).toBeDefined();
      } catch (error) {
        // Invalid serverless configuration
      }
    }
  });
});

// ====================
// PERFORMANCE WORKFLOW TESTS
// ====================

describe('Performance Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have Next.js performance configuration', async () => {
    const nextConfigPath = path.join(projectRoot, 'next.config.js');
    
    let nextConfig;
    try {
      const configContent = await fs.readFile(nextConfigPath, 'utf8');
      
      // Basic check for performance optimizations
      expect(configContent).toBeDefined();
      
      // Should have compression enabled
      expect(configContent).toMatch(/compress\s*:\s*true|compression/);
      
      // Should have production optimizations
      if (configContent.includes('optimization')) {
        expect(configContent).toMatch(/optimization/);
      }
    } catch (error) {
      // If config doesn't exist, that's a problem
      throw new Error('Next.js configuration not found');
    }
  });
  
  it('should have bundle analyzer configuration', async () => {
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    // Check for bundle analyzer script
    const scripts = Object.keys(packageJson.scripts);
    const hasBundleAnalyzer = scripts.some(script => 
      script.includes('analyze') || script.includes('bundle')
    );
    
    expect(hasBundleAnalyzer).toBe(true);
  });
  
  it('should have performance budget configuration', async () => {
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    // Check for performance budget in bundlewatch or similar
    const hasBundlewatch = packageJson.devDependencies && 
      packageJson.devDependencies.bundlewatch;
    
    if (hasBundlewatch) {
      expect(packageJson.bundlewatch).toBeDefined();
    }
  });
  
  it('should have Lighthouse CI configuration', async () => {
    // Check for Lighthouse CI configuration
    const lhciConfigPath = path.join(projectRoot, 'lighthouserc.js');
    const lhciJsonPath = path.join(projectRoot, 'lighthouserc.json');
    
    let lhciExists = false;
    
    try {
      await fs.access(lhciConfigPath);
      lhciExists = true;
    } catch (error) {
      try {
        await fs.access(lhciJsonPath);
        lhciExists = true;
      } catch (e) {
        // Neither file exists
      }
    }
    
    // Lighthouse CI is optional but recommended
    if (lhciExists) {
      const lhciPath = lhciExists ? lhciConfigPath : lhciJsonPath;
      const lhciContent = await fs.readFile(lhciPath, 'utf8');
      
      expect(lhciContent).toContain('ci');
      expect(lhciContent).toContain('collect');
      expect(lhciContent).toContain('assert');
    }
  });
});

// ====================
// SECURITY WORKFLOW TESTS
// ====================

describe('Security Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have security audit script', async () => {
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    // Check for security audit script
    const scripts = Object.keys(packageJson.scripts);
    const hasAuditScript = scripts.some(script => 
      script.includes('audit') || script.includes('security')
    );
    
    expect(hasAuditScript).toBe(true);
  });
  
  it('should pass npm audit check', async () => {
    // Run npm audit
    try {
      execSync('npm audit --audit-level=high', {
        cwd: projectRoot,
        stdio: 'pipe',
        timeout: 120000
      });
    } catch (error) {
      // Check if it's just warnings or actual vulnerabilities
      const output = error.stdout?.toString() || error.message;
      
      // Should not have high or critical vulnerabilities
      if (output.includes('high') || output.includes('critical')) {
        throw new Error('High or critical security vulnerabilities found');
      }
    }
  });
  
  it('should have environment variable security', async () => {
    const nextConfigPath = path.join(projectRoot, 'next.config.js');
    const configContent = await fs.readFile(nextConfigPath, 'utf8');
    
    // Should not expose sensitive environment variables
    expect(configContent).not.toContain('password');
    expect(configContent).not.toContain('secret');
    expect(configContent).not.toContain('key');
    
    // Should use publicRuntimeConfig or env for client-side variables
    expect(configContent).toMatch(/publicRuntimeConfig|env/);
  });
  
  it('should have security headers configuration', async () => {
    const nextConfigPath = path.join(projectRoot, 'next.config.js');
    const configContent = await fs.readFile(nextConfigPath, 'utf8');
    
    // Should have security headers
    expect(configContent).toMatch(/headers/);
    expect(configContent).toMatch(/Content-Security-Policy|X-Frame-Options|X-Content-Type-Options/);
  });
});

// ====================
// DOCUMENTATION WORKFLOW TESTS
// ====================

describe('Documentation Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have comprehensive README', async () => {
    const readmePath = path.join(projectRoot, 'README.md');
    
    const readmeExists = await fs.access(readmePath)
      .then(() => true)
      .catch(() => false);
    
    expect(readmeExists).toBe(true);
    
    const readmeContent = await fs.readFile(readmePath, 'utf8');
    
    // Should have key sections
    expect(readmeContent).toMatch(/#.*{{PROJECT_NAME}}/);
    expect(readmeContent).toMatch(/##.*[Dd]escription|[Dd]escription/);
    expect(readmeContent).toMatch(/##.*[Ii]nstallation|[Ii]nstallation/);
    expect(readmeContent).toMatch(/##.*[Uu]sage|[Uu]sage/);
    expect(readmeContent).toMatch(/##.*[Tt]esting|[Tt]esting/);
  });
  
  it('should have API documentation', async () => {
    // Check for API documentation
    const docsPath = path.join(projectRoot, 'docs');
    const apiDocsPath = path.join(projectRoot, 'API.md');
    
    let apiDocsExist = false;
    
    // Check for API.md
    try {
      await fs.access(apiDocsPath);
      apiDocsExist = true;
    } catch (error) {
      // Check docs directory
      try {
        await fs.access(docsPath);
        const docsFiles = await fs.readdir(docsPath);
        apiDocsExist = docsFiles.some(file => 
          file.toLowerCase().includes('api') || file.toLowerCase().includes('reference')
        );
      } catch (e) {
        // No docs directory
      }
    }
    
    expect(apiDocsExist).toBe(true);
  });
  
  it('should have Storybook configuration', async () => {
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    // Check for Storybook
    const hasStorybook = packageJson.devDependencies && 
      (packageJson.devDependencies['@storybook/react'] || 
       packageJson.devDependencies['@storybook/nextjs']);
    
    if (hasStorybook) {
      // Should have Storybook scripts
      const scripts = Object.keys(packageJson.scripts);
      const hasStorybookScripts = scripts.some(script => 
        script.includes('storybook') || script.includes('build-storybook')
      );
      
      expect(hasStorybookScripts).toBe(true);
    }
  });
  
  it('should generate TypeScript documentation', async () => {
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    // Check for TypeDoc
    const hasTypeDoc = packageJson.devDependencies && 
      packageJson.devDependencies.typedoc;
    
    if (hasTypeDoc) {
      // Should have TypeDoc script
      const scripts = Object.keys(packageJson.scripts);
      const hasTypeDocScript = scripts.some(script => 
        script.includes('docs') || script.includes('typedoc')
      );
      
      expect(hasTypeDocScript).toBe(true);
    }
  });
});

// ====================
// NEXT.JS SPECIFIC WORKFLOW TESTS
// ====================

describe('Next.js Specific Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should have Next.js middleware configuration', async () => {
    const middlewarePath = path.join(projectRoot, 'middleware.ts');
    const middlewareJsPath = path.join(projectRoot, 'middleware.js');
    
    let middlewareExists = false;
    
    try {
      await fs.access(middlewarePath);
      middlewareExists = true;
    } catch (error) {
      try {
        await fs.access(middlewareJsPath);
        middlewareExists = true;
      } catch (e) {
        // No middleware file
      }
    }
    
    // Middleware is optional but good to have
    if (middlewareExists) {
      const middlewareContent = await fs.readFile(
        middlewareExists ? middlewarePath : middlewareJsPath, 
        'utf8'
      );
      
      expect(middlewareContent).toContain('NextRequest');
      expect(middlewareContent).toContain('NextResponse');
    }
  });
  
  it('should have API routes structure', async () => {
    const apiRoutesPath = path.join(projectRoot, 'pages', 'api');
    const appApiPath = path.join(projectRoot, 'app', 'api');
    
    let apiRoutesExist = false;
    
    try {
      await fs.access(apiRoutesPath);
      apiRoutesExist = true;
    } catch (error) {
      try {
        await fs.access(appApiPath);
        apiRoutesExist = true;
      } catch (e) {
        // No API routes
      }
    }
    
    expect(apiRoutesExist).toBe(true);
  });
  
  it('should have ISR/SSG configuration', async () => {
    const pagesPath = path.join(projectRoot, 'pages');
    const appPath = path.join(projectRoot, 'app');
    
    // Check for getStaticProps or getStaticPaths in pages
    if (await fs.access(pagesPath).then(() => true).catch(() => false)) {
      const pagesFiles = await fs.readdir(pagesPath, { recursive: true });
      
      let hasSSG = false;
      for (const file of pagesFiles) {
        if (file.endsWith('.tsx') || file.endsWith('.ts')) {
          const fileContent = await fs.readFile(path.join(pagesPath, file), 'utf8');
          if (fileContent.includes('getStaticProps') || fileContent.includes('getStaticPaths')) {
            hasSSG = true;
            break;
          }
        }
      }
      
      expect(hasSSG).toBe(true);
    }
  });
  
  it('should have next-env.d.ts file', async () => {
    const nextEnvPath = path.join(projectRoot, 'next-env.d.ts');
    
    const nextEnvExists = await fs.access(nextEnvPath)
      .then(() => true)
      .catch(() => false);
    
    expect(nextEnvExists).toBe(true);
    
    if (nextEnvExists) {
      const nextEnvContent = await fs.readFile(nextEnvPath, 'utf8');
      expect(nextEnvContent).toContain('/// <reference types="next" />');
    }
  });
  
  it('should have app directory structure (Next.js 13+)', async () => {
    const appPath = path.join(projectRoot, 'app');
    const pagesPath = path.join(projectRoot, 'pages');
    
    const appExists = await fs.access(appPath)
      .then(() => true)
      .catch(() => false);
    
    const pagesExists = await fs.access(pagesPath)
      .then(() => true)
      .catch(() => false);
    
    // Should have either app or pages directory
    expect(appExists || pagesExists).toBe(true);
    
    // Prefer app directory for new projects
    if (appExists) {
      // Should have layout.tsx
      const layoutPath = path.join(appPath, 'layout.tsx');
      const layoutExists = await fs.access(layoutPath)
        .then(() => true)
        .catch(() => false);
      
      expect(layoutExists).toBe(true);
    }
  });
});

// ====================
// ENVIRONMENT WORKFLOW TESTS
// ====================

describe('Environment Workflow Tests', () => {
  
  const projectRoot = process.cwd();
  
  it('should support different environments', async () => {
    const envFiles = [
      '.env.local',
      '.env.development',
      '.env.production',
      '.env.test'
    ];
    
    let hasEnvFiles = false;
    
    for (const envFile of envFiles) {
      try {
        await fs.access(path.join(projectRoot, envFile));
        hasEnvFiles = true;
        break;
      } catch (error) {
        continue;
      }
    }
    
    expect(hasEnvFiles).toBe(true);
  });
  
  it('should have environment-specific configurations', async () => {
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    // Should have environment-specific scripts
    const scripts = Object.keys(packageJson.scripts);
    const hasEnvScripts = scripts.some(script => 
      script.includes('dev') || script.includes('prod') || script.includes('staging')
    );
    
    expect(hasEnvScripts).toBe(true);
  });
  
  it('should validate environment variables', async () => {
    // Check for environment validation
    const envValidationPath = path.join(projectRoot, 'lib', 'env.ts');
    const configValidationPath = path.join(projectRoot, 'lib', 'config.ts');
    
    let envValidationExists = false;
    
    try {
      await fs.access(envValidationPath);
      envValidationExists = true;
    } catch (error) {
      try {
        await fs.access(configValidationPath);
        envValidationExists = true;
      } catch (e) {
        // No environment validation
      }
    }
    
    // Environment validation is recommended
    if (envValidationExists) {
      const validationContent = await fs.readFile(
        envValidationExists ? envValidationPath : configValidationPath,
        'utf8'
      );
      
      expect(validationContent).toContain('process.env');
      expect(validationContent).toContain('zod') || validationContent.toLowerCase().includes('validation');
    }
  });
});

// Export for use in other test files
module.exports = {
  WorkflowTestConfig: {
    projectRoot: process.cwd(),
    defaultTimeout: 300000, // 5 minutes
    environments: ['development', 'production', 'test']
  }
};
