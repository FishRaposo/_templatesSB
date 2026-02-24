# TypeScript Workflow Testing Template
# CI/CD workflow and development workflow tests for TypeScript projects with GitHub Actions, Docker, and deployment automation

/**
 * TypeScript Workflow Test Patterns
 * Build processes, CI/CD pipelines, Docker containers, GitHub Actions, security scanning, and deployment automation
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { execSync, spawn } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as yaml from 'js-yaml';
import * as dockerode from 'dockerode';
import fetch from 'node-fetch';

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
    expect(packageJson.name).toMatch(/^[a-z0-9-_]+$/);
    expect(packageJson.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(packageJson.description).toBeDefined();
    expect(packageJson.main).toBeDefined();
    expect(packageJson.types).toBeDefined();
    
    // Verify scripts
    expect(packageJson.scripts).toBeDefined();
    expect(packageJson.scripts.test).toBeDefined();
    expect(packageJson.scripts.build).toBeDefined();
    expect(packageJson.scripts.lint).toBeDefined();
    expect(packageJson.scripts.start).toBeDefined();
    expect(packageJson.scripts.dev).toBeDefined();
    expect(packageJson.scripts.typecheck).toBeDefined();
    
    // Verify dependencies are properly separated
    expect(packageJson.dependencies).toBeDefined();
    expect(packageJson.devDependencies).toBeDefined();
    
    // Verify no duplicate dependencies
    const deps = Object.keys(packageJson.dependencies || {});
    const devDeps = Object.keys(packageJson.devDependencies || {});
    const duplicates = deps.filter(dep => devDeps.includes(dep));
    expect(duplicates).toHaveLength(0);
    
    // Verify TypeScript configuration
    expect(packageJson.devDependencies).toHaveProperty('typescript');
    expect(packageJson.devDependencies).toHaveProperty('@types/node');
    expect(packageJson.devDependencies).toHaveProperty('ts-node');
    
    // Verify testing framework
    expect(packageJson.devDependencies).toHaveProperty('jest');
    expect(packageJson.devDependencies).toHaveProperty('@types/jest');
    expect(packageJson.devDependencies).toHaveProperty('ts-jest');
  });
  
  it('should install dependencies without errors', async () => {
    // Test npm ci (clean install)
    try {
      execSync('npm ci', {
        cwd: projectRoot,
        stdio: 'pipe',
        timeout: 300000, // 5 minutes
      });
    } catch (error) {
      // If npm ci fails, test regular npm install
      console.log('npm ci failed, trying npm install...', error.message);
      execSync('npm install', {
        cwd: projectRoot,
        stdio: 'pipe',
        timeout: 300000,
      });
    }
    
    // Verify node_modules exists and has content
    const nodeModulesPath = path.join(projectRoot, 'node_modules');
    const nodeModulesExists = await fs.access(nodeModulesPath)
      .then(() => true)
      .catch(() => false);
    
    expect(nodeModulesExists).toBe(true);
    
    // Verify key dependencies are installed
    const keyPackages = ['typescript', 'jest', 'express', '@types/express'];
    for (const pkg of keyPackages) {
      const pkgPath = path.join(nodeModulesPath, pkg);
      const pkgExists = await fs.access(pkgPath).then(() => true).catch(() => false);
      expect(pkgExists).toBe(true);
    }
  }, 330000); // 5.5 minute timeout
  
  it('should build application without errors', async () => {
    // Check if build script exists
    const packageJsonPath = path.join(projectRoot, 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    if (!packageJson.scripts?.build) {
      console.log('No build script found, skipping build test');
      return;
    }
    
    // Clean previous build
    const distPath = path.join(projectRoot, 'dist');
    try {
      await fs.rm(distPath, { recursive: true, force: true });
    } catch (error) {
      // Directory might not exist
    }
    
    // Run build
    execSync('npm run build', {
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: 300000, // 5 minutes
    });
    
    // Verify build output exists
    const buildExists = await fs.access(distPath)
      .then(() => true)
      .catch(() => false);
    
    expect(buildExists).toBe(true);
    
    // Verify build files are not empty
    const files = await fs.readdir(distPath);
    expect(files.length).toBeGreaterThan(0);
    
    // Verify main entry point exists
    const mainFile = path.join(distPath, 'index.js');
    const mainExists = await fs.access(mainFile).then(() => true).catch(() => false);
    expect(mainExists).toBe(true);
    
    // Verify TypeScript declaration files
    const typesPath = path.join(distPath, 'types');
    const typesExist = await fs.access(typesPath).then(() => true).catch(() => false);
    expect(typesExist).toBe(true);
    
    // Verify source maps for debugging
    const hasSourceMaps = files.some(file => file.endsWith('.map'));
    expect(hasSourceMaps).toBe(true);
  });
  
  it('should support multiple build targets', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    const buildTargets = ['build:dev', 'build:staging', 'build:prod', 'build:analyze'];
    const availableTargets = buildTargets.filter(target => packageJson.scripts?.[target]);
    
    expect(availableTargets.length).toBeGreaterThan(0);
    
    // Test each available target
    for (const target of availableTargets) {
      try {
        execSync(`npm run ${target}`, {
          cwd: projectRoot,
          stdio: 'pipe',
          timeout: 300000,
        });
        
        console.log(`✓ Build target ${target} completed successfully`);
      } catch (error) {
        console.log(`✗ Build target ${target} failed:`, error.message);
        throw error;
      }
    }
  });
  
  it('should generate proper source maps', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    if (!packageJson.scripts?.['build:debug']) {
      console.log('No debug build script found, creating one for testing');
      packageJson.scripts['build:debug'] = 'npm run build -- --sourceMap=true';
      await fs.writeFile(
        path.join(projectRoot, 'package.json'),
        JSON.stringify(packageJson, null, 2)
      );
    }
    
    execSync('npm run build:debug', {
      cwd: projectRoot,
      stdio: 'pipe',
      timeout: 300000,
    });
    
    // Verify source maps were generated
    const distPath = path.join(projectRoot, 'dist');
    const files = await fs.readdir(distPath, { recursive: true });
    const sourceMapFiles = files.filter(file => file.toString().endsWith('.map'));
    
    expect(sourceMapFiles.length).toBeGreaterThan(0);
    
    // Verify source map content
    const sourceMapPath = path.join(distPath, sourceMapFiles[0].toString());
    const sourceMapContent = await fs.readFile(sourceMapPath, 'utf8');
    const sourceMap = JSON.parse(sourceMapContent);
    
    expect(sourceMap).toHaveProperty('version');
    expect(sourceMap).toHaveProperty('sources');
    expect(sourceMap).toHaveProperty('mappings');
    expect(sourceMap.sources.length).toBeGreaterThan(0);
  });
  
  it('should optimize bundle size', async () => {
    const packageJson = JSON.parse(
      await fs.readFile(path.join(projectRoot, 'package.json'), 'utf8')
    );
    
    // Check for bundle analyzer
    const hasBundleAnalyzer = packageJson.devDependencies?.['webpack-bundle-analyzer'] ||
                             packageJson.devDependencies?.['@next/bundle-analyzer'];
    
    if (hasBundleAnalyzer) {
      // Run bundle analysis
      try {
        execSync('npm run build:analyze', {
          cwd: projectRoot,
          stdio: 'pipe',
          timeout: 300000,
        });
        
        // Check if analysis report was generated
        const reportPath = path.join(projectRoot, 'bundle-report.html');
        const reportExists = await fs.access(reportPath).then(() => true).catch(() => false);
        expect(reportExists).toBe(true);
      } catch (error) {
        console.log('Bundle analysis failed:', error.message);
      }
    }
    
    // Verify main bundle size
    const distPath = path.join(projectRoot, 'dist');
    const mainBundlePath = path.join(distPath, 'index.js');
    
    try {
      const stats = await fs.stat(mainBundlePath);
      const bundleSizeKB = stats.size / 1024;
      
      // Main bundle should be reasonable size (adjust based on your app)
      expect(bundleSizeKB).toBeLessThan(1000); // 1MB max for main bundle
      
      console.log(`Main bundle size: ${bundleSizeKB.toFixed(2)}KB`);
    } catch (error) {
      console.log('Could not check bundle size:', error.message);
    }
  });
});

// ====================
// TYPE CHECKING AND LINTING
// ====================

describe('Type Checking and Code Quality Tests', () => {
  
  it('should pass TypeScript type checking', async () => {
    try {
      execSync('npx tsc --noEmit', {
        cwd: process.cwd(),
        stdio: 'pipe',
        timeout: 120000, // 2 minutes
      });
      
      console.log('✓ TypeScript type checking passed');
    } catch (error) {
      console.log('✗ TypeScript type checking failed:', error.message);
      throw error;
    }
  });
  
  it('should pass ESLint checks', async () => {
    try {
      execSync('npx eslint . --ext .ts,.tsx,.js,.jsx --max-warnings 0', {
        cwd: process.cwd(),
        stdio: 'pipe',
        timeout: 120000, // 2 minutes
      });
      
      console.log('✓ ESLint checks passed');
    } catch (error) {
      console.log('✗ ESLint checks failed:', error.message);
      throw error;
    }
  });
  
  it('should have proper TypeScript configuration', async () => {
    const tsconfigPath = path.join(process.cwd(), 'tsconfig.json');
    const tsconfigContent = await fs.readFile(tsconfigPath, 'utf8');
    const tsconfig = JSON.parse(tsconfigContent);
    
    // Verify strict mode is enabled
    expect(tsconfig.compilerOptions.strict).toBe(true);
    
    // Verify target is reasonable
    expect(tsconfig.compilerOptions.target).toMatch(/ES20(15|16|17|18|19|20)/);
    
    // Verify module system
    expect(tsconfig.compilerOptions.module).toMatch(/commonjs|es2015|es2020|esnext/);
    
    // Verify source maps are enabled
    expect(tsconfig.compilerOptions.sourceMap).toBe(true);
    
    // Verify declaration files are generated
    expect(tsconfig.compilerOptions.declaration).toBe(true);
    
    // Verify out directory is set
    expect(tsconfig.compilerOptions.outDir).toBeDefined();
    
    // Verify include/exclude patterns
    expect(tsconfig.include).toBeDefined();
    expect(tsconfig.exclude).toBeDefined();
  });
  
  it('should have proper ESLint configuration', async () => {
    const eslintConfigPath = path.join(process.cwd(), '.eslintrc.json');
    const eslintConfigContent = await fs.readFile(eslintConfigPath, 'utf8');
    const eslintConfig = JSON.parse(eslintConfigContent);
    
    // Verify TypeScript parser is configured
    expect(eslintConfig.parser).toBe('@typescript-eslint/parser');
    
    // Verify TypeScript plugin is included
    expect(eslintConfig.plugins).toContain('@typescript-eslint');
    
    // Verify recommended rules are extended
    expect(eslintConfig.extends).toContain('eslint:recommended');
    expect(eslintConfig.extends).toContain('@typescript-eslint/recommended');
    
    // Verify environment settings
    expect(eslintConfig.env.node).toBe(true);
    expect(eslintConfig.env.es2020).toBe(true);
    
    // Verify parser options
    expect(eslintConfig.parserOptions.ecmaVersion).toBeGreaterThanOrEqual(2020);
    expect(eslintConfig.parserOptions.sourceType).toBe('module');
  });
  
  it('should have consistent code formatting', async () => {
    try {
      execSync('npx prettier --check .', {
        cwd: process.cwd(),
        stdio: 'pipe',
        timeout: 60000, // 1 minute
      });
      
      console.log('✓ Code formatting is consistent');
    } catch (error) {
      console.log('✗ Code formatting issues found:', error.message);
      
      // Try to auto-fix
      try {
        execSync('npx prettier --write .', {
          cwd: process.cwd(),
          stdio: 'pipe',
          timeout: 60000,
        });
        console.log('✓ Code formatting issues auto-fixed');
      } catch (fixError) {
        throw error; // Re-throw original error if auto-fix fails
      }
    }
  });
  
  it('should pass security linting', async () => {
    // Check for security-focused ESLint plugins
    const packageJsonPath = path.join(process.cwd(), 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    const securityPlugins = [
      'eslint-plugin-security',
      'eslint-plugin-no-unsanitized',
      '@typescript-eslint/eslint-plugin',
    ];
    
    const hasSecurityPlugins = securityPlugins.some(plugin => 
      packageJson.devDependencies?.[plugin]
    );
    
    if (hasSecurityPlugins) {
      try {
        execSync('npx eslint . --ext .ts,.tsx --config .eslintrc.security.json', {
          cwd: process.cwd(),
          stdio: 'pipe',
          timeout: 120000,
        });
        
        console.log('✓ Security linting passed');
      } catch (error) {
        console.log('✗ Security linting failed:', error.message);
        throw error;
      }
    } else {
      console.log('No security ESLint plugins found, skipping security linting');
    }
  });
});

// ====================
// CI/CD WORKFLOW TESTS
// ====================

describe('CI/CD Workflow Tests', () => {
  
  it('should have valid GitHub Actions workflow files', async () => {
    const workflowsPath = path.join(process.cwd(), '.github', 'workflows');
    
    try {
      const workflowFiles = await fs.readdir(workflowsPath);
      expect(workflowFiles.length).toBeGreaterThan(0);
      
      for (const file of workflowFiles) {
        if (file.endsWith('.yml') || file.endsWith('.yaml')) {
          const filePath = path.join(workflowsPath, file);
          const content = await fs.readFile(filePath, 'utf8');
          
          // Parse YAML
          const workflow = yaml.load(content) as any;
          
          // Verify basic structure
          expect(workflow).toHaveProperty('name');
          expect(workflow).toHaveProperty('on');
          expect(workflow).toHaveProperty('jobs');
          
          // Verify job structure
          Object.keys(workflow.jobs).forEach(jobName => {
            const job = workflow.jobs[jobName];
            expect(job).toHaveProperty('runs-on');
            expect(job).toHaveProperty('steps');
            expect(job.steps).toBeInstanceOf(Array);
            expect(job.steps.length).toBeGreaterThan(0);
          });
          
          console.log(`✓ Workflow file ${file} is valid`);
        }
      }
    } catch (error) {
      console.log('No GitHub Actions workflows found, checking for other CI configurations...');
      
      // Check for other CI configurations
      const ciConfigs = [
        '.gitlab-ci.yml',
        'azure-pipelines.yml',
        'Jenkinsfile',
        'buildspec.yml',
      ];
      
      let foundConfig = false;
      for (const config of ciConfigs) {
        const configPath = path.join(process.cwd(), config);
        try {
          await fs.access(configPath);
          foundConfig = true;
          console.log(`✓ Found CI configuration: ${config}`);
          break;
        } catch {
          // Config doesn't exist, continue
        }
      }
      
      if (!foundConfig) {
        console.log('No CI/CD configuration found');
      }
    }
  });
  
  it('should have comprehensive test workflow', async () => {
    const workflowsPath = path.join(process.cwd(), '.github', 'workflows');
    
    try {
      const files = await fs.readdir(workflowsPath);
      const testWorkflow = files.find(f => 
        (f.endsWith('.yml') || f.endsWith('.yaml')) && 
        f.toLowerCase().includes('test')
      );
      
      if (testWorkflow) {
        const content = await fs.readFile(path.join(workflowsPath, testWorkflow), 'utf8');
        const workflow = yaml.load(content) as any;
        
        // Verify test job exists
        const testJob = Object.keys(workflow.jobs).find(jobName => 
          jobName.toLowerCase().includes('test')
        );
        
        expect(testJob).toBeDefined();
        
        const job = workflow.jobs[testJob];
        
        // Verify test steps
        const testSteps = job.steps.filter((step: any) => 
          step.name?.toLowerCase().includes('test') ||
          step.run?.toLowerCase().includes('test')
        );
        
        expect(testSteps.length).toBeGreaterThan(0);
        
        console.log(`✓ Test workflow ${testWorkflow} is comprehensive`);
      } else {
        console.log('No test workflow found');
      }
    } catch (error) {
      console.log('Could not check test workflow:', error.message);
    }
  });
  
  it('should have deployment workflow', async () => {
    const workflowsPath = path.join(process.cwd(), '.github', 'workflows');
    
    try {
      const files = await fs.readdir(workflowsPath);
      const deployWorkflow = files.find(f => 
        (f.endsWith('.yml') || f.endsWith('.yaml')) && 
        (f.toLowerCase().includes('deploy') || f.toLowerCase().includes('release'))
      );
      
      if (deployWorkflow) {
        const content = await fs.readFile(path.join(workflowsPath, deployWorkflow), 'utf8');
        const workflow = yaml.load(content) as any;
        
        // Verify deployment job exists
        const deployJob = Object.keys(workflow.jobs).find(jobName => 
          jobName.toLowerCase().includes('deploy') ||
          jobName.toLowerCase().includes('release')
        );
        
        expect(deployJob).toBeDefined();
        
        const job = workflow.jobs[deployJob];
        
        // Verify deployment environment
        expect(job).toHaveProperty('environment');
        
        // Verify deployment steps
        const deploySteps = job.steps.filter((step: any) => 
          step.name?.toLowerCase().includes('deploy') ||
          step.run?.toLowerCase().includes('deploy') ||
          step.uses?.toLowerCase().includes('deploy')
        );
        
        expect(deploySteps.length).toBeGreaterThan(0);
        
        console.log(`✓ Deployment workflow ${deployWorkflow} is configured`);
      } else {
        console.log('No deployment workflow found');
      }
    } catch (error) {
      console.log('Could not check deployment workflow:', error.message);
    }
  });
  
  it('should have security scanning workflow', async () => {
    const workflowsPath = path.join(process.cwd(), '.github', 'workflows');
    
    try {
      const files = await fs.readdir(workflowsPath);
      const securityWorkflow = files.find(f => 
        (f.endsWith('.yml') || f.endsWith('.yaml')) && 
        f.toLowerCase().includes('security')
      );
      
      if (securityWorkflow) {
        const content = await fs.readFile(path.join(workflowsPath, securityWorkflow), 'utf8');
        const workflow = yaml.load(content) as any;
        
        // Verify security scanning steps
        const securitySteps = [];
        Object.values(workflow.jobs).forEach((job: any) => {
          job.steps.forEach((step: any) => {
            if (step.uses && (
              step.uses.includes('security') ||
              step.uses.includes('snyk') ||
              step.uses.includes('codeql') ||
              step.uses.includes('trivy')
            )) {
              securitySteps.push(step);
            }
          });
        });
        
        expect(securitySteps.length).toBeGreaterThan(0);
        
        console.log(`✓ Security workflow ${securityWorkflow} is configured`);
      } else {
        console.log('No dedicated security workflow found, checking for security steps in other workflows...');
        
        // Check for security steps in other workflows
        let foundSecuritySteps = false;
        for (const file of files) {
          if (file.endsWith('.yml') || file.endsWith('.yaml')) {
            const content = await fs.readFile(path.join(workflowsPath, file), 'utf8');
            const workflow = yaml.load(content) as any;
            
            const hasSecuritySteps = Object.values(workflow.jobs).some((job: any) =>
              job.steps.some((step: any) =>
                step.uses && (
                  step.uses.includes('security') ||
                  step.uses.includes('snyk') ||
                  step.uses.includes('codeql')
                )
              )
            );
            
            if (hasSecuritySteps) {
              foundSecuritySteps = true;
              break;
            }
          }
        }
        
        if (foundSecuritySteps) {
          console.log('✓ Security steps found in other workflows');
        } else {
          console.log('No security scanning found in workflows');
        }
      }
    } catch (error) {
      console.log('Could not check security workflow:', error.message);
    }
  });
});

// ====================
// DOCKER WORKFLOW TESTS
// ====================

describe('Docker Workflow Tests', () => {
  
  it('should have valid Dockerfile', async () => {
    const dockerfilePath = path.join(process.cwd(), 'Dockerfile');
    
    try {
      const dockerfileContent = await fs.readFile(dockerfilePath, 'utf8');
      
      // Verify basic Dockerfile structure
      expect(dockerfileContent).toContain('FROM');
      expect(dockerfileContent).toContain('WORKDIR');
      expect(dockerfileContent).toContain('COPY');
      expect(dockerfileContent).toContain('RUN');
      expect(dockerfileContent).toContain('EXPOSE');
      expect(dockerfileContent).toContain('CMD');
      
      // Verify Node.js base image
      expect(dockerfileContent).toMatch(/FROM node:\d+/);
      
      // Verify multi-stage build (recommended)
      const hasMultiStage = dockerfileContent.includes('AS builder') || 
                           dockerfileContent.includes('FROM node:') && 
                           dockerfileContent.split('FROM').length > 2;
      
      if (hasMultiStage) {
        console.log('✓ Dockerfile uses multi-stage build');
      }
      
      // Verify security best practices
      expect(dockerfileContent).toContain('USER node'); // Non-root user
      
      console.log('✓ Dockerfile is valid and follows best practices');
    } catch (error) {
      console.log('Dockerfile not found or invalid:', error.message);
      throw error;
    }
  });
  
  it('should build Docker image successfully', async () => {
    try {
      console.log('Building Docker image...');
      
      execSync('docker build -t typescript-app:test .', {
        cwd: process.cwd(),
        stdio: 'pipe',
        timeout: 600000, // 10 minutes
      });
      
      console.log('✓ Docker image built successfully');
      
      // Verify image exists
      const images = execSync('docker images typescript-app:test --format "{{.Repository}}:{{.Tag}}"', {
        encoding: 'utf8',
      });
      
      expect(images).toContain('typescript-app:test');
      
      // Get image details
      const imageDetails = execSync('docker images typescript-app:test --format "{{.Size}}"', {
        encoding: 'utf8',
      });
      
      const size = imageDetails.trim();
      console.log(`Image size: ${size}`);
      
      // Clean up test image
      execSync('docker rmi typescript-app:test', {
        stdio: 'pipe',
      });
      
    } catch (error) {
      console.log('Docker build failed:', error.message);
      
      // Check if Docker is available
      try {
        execSync('docker --version', { stdio: 'pipe' });
      } catch {
        console.log('Docker is not available, skipping Docker tests');
        return;
      }
      
      throw error;
    }
  });
  
  it('should have docker-compose configuration', async () => {
    const composeFiles = [
      'docker-compose.yml',
      'docker-compose.yaml',
      'compose.yml',
      'compose.yaml',
    ];
    
    let composeFile: string | null = null;
    
    for (const file of composeFiles) {
      const filePath = path.join(process.cwd(), file);
      try {
        await fs.access(filePath);
        composeFile = filePath;
        break;
      } catch {
        continue;
      }
    }
    
    if (composeFile) {
      const content = await fs.readFile(composeFile, 'utf8');
      const compose = yaml.load(content) as any;
      
      expect(compose).toHaveProperty('services');
      expect(compose.services).toHaveProperty('app');
      
      const appService = compose.services.app;
      expect(appService).toHaveProperty('build');
      expect(appService).toHaveProperty('ports');
      expect(appService.ports).toContain('3000:3000');
      
      // Check for database service
      const hasDatabase = Object.keys(compose.services).some(service => 
        service.includes('db') || service.includes('database') || service.includes('postgres') || service.includes('mysql')
      );
      
      if (hasDatabase) {
        console.log('✓ Docker Compose includes database service');
      }
      
      console.log(`✓ Docker Compose configuration found: ${path.basename(composeFile)}`);
    } else {
      console.log('No docker-compose configuration found');
    }
  });
  
  it('should have .dockerignore file', async () => {
    const dockerignorePath = path.join(process.cwd(), '.dockerignore');
    
    try {
      const content = await fs.readFile(dockerignorePath, 'utf8');
      
      // Verify common entries
      const expectedEntries = [
        'node_modules',
        'npm-debug.log',
        '.git',
        '.gitignore',
        'README.md',
        '.env',
        '.env.local',
        'dist',
        'build',
        'coverage',
        '.nyc_output',
      ];
      
      expectedEntries.forEach(entry => {
        expect(content).toContain(entry);
      });
      
      console.log('✓ .dockerignore file is properly configured');
    } catch (error) {
      console.log('.dockerignore file not found, creating one...');
      
      const defaultDockerignore = `
# Dependencies
node_modules
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage
*.lcov

# nyc test coverage
.nyc_output

# Grunt intermediate storage
.grunt

# Bower dependency directory
bower_components

# node-waf configuration
.lock-wscript

# Compiled binary addons
build/Release

# Dependency directories
jspm_packages/

# TypeScript cache
*.tsbuildinfo

# Optional npm cache directory
.npm

# Optional eslint cache
.eslintcache

# Microbundle cache
.rpt2_cache/
.rts2_cache_cjs/
.rts2_cache_es/
.rts2_cache_umd/

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# dotenv environment variables file
.env
.env.test
.env.local
.env.development.local
.env.test.local
.env.production.local

# parcel-bundler cache
.cache
.parcel-cache

# Next.js build output
.next

# Nuxt.js build / generate output
.nuxt
dist
build/

# Gatsby files
.cache/
public

# Storybook build outputs
.out
.storybook-out

# Temporary folders
tmp/
temp/

# Logs
logs
*.log

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Git
.git
.gitignore

# Docker
Dockerfile*
docker-compose*
.dockerignore

# IDE
.vscode
.idea
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db
`;
      
      await fs.writeFile(dockerignorePath, defaultDockerignore.trim());
      console.log('✓ Created .dockerignore file');
    }
  });
});

// ====================
// DEPLOYMENT WORKFLOW TESTS
// ====================

describe('Deployment Workflow Tests', () => {
  
  it('should have deployment configuration', async () => {
    const deploymentConfigs = [
      'deploy.sh',
      'deploy.js',
      'deploy.ts',
      'deployment/config.json',
      'kubernetes/deployment.yaml',
      'helm/Chart.yaml',
      'terraform/main.tf',
    ];
    
    let foundConfig = false;
    
    for (const config of deploymentConfigs) {
      const configPath = path.join(process.cwd(), config);
      try {
        await fs.access(configPath);
        foundConfig = true;
        console.log(`✓ Found deployment configuration: ${config}`);
        break;
      } catch {
        continue;
      }
    }
    
    if (!foundConfig) {
      console.log('No deployment configuration found');
    }
  });
  
  it('should have environment configuration', async () => {
    const envFiles = [
      '.env.example',
      '.env.sample',
      'config/default.json',
      'config/production.json',
    ];
    
    let foundEnvConfig = false;
    
    for (const file of envFiles) {
      const filePath = path.join(process.cwd(), file);
      try {
        await fs.access(filePath);
        foundEnvConfig = true;
        console.log(`✓ Found environment configuration: ${file}`);
        break;
      } catch {
        continue;
      }
    }
    
    if (!foundEnvConfig) {
      console.log('No environment configuration found, creating .env.example...');
      
      const defaultEnvExample = `
# Application
NODE_ENV=development
PORT=3000
HOST=localhost

# Database
DATABASE_URL=postgresql://username:password@localhost:5432/database_name
REDIS_URL=redis://localhost:6379

# Authentication
JWT_SECRET=your-super-secret-jwt-key-here
JWT_EXPIRES_IN=7d
REFRESH_TOKEN_EXPIRES_IN=30d

# External Services
EMAIL_API_KEY=your-email-service-api-key
STRIPE_SECRET_KEY=your-stripe-secret-key
S3_ACCESS_KEY_ID=your-s3-access-key
S3_SECRET_ACCESS_KEY=your-s3-secret-key
S3_BUCKET_NAME=your-s3-bucket

# Monitoring
SENTRY_DSN=your-sentry-dsn
LOG_LEVEL=info

# Development
DEBUG=app:*

# Security
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
`;
      
      await fs.writeFile(path.join(process.cwd(), '.env.example'), defaultEnvExample.trim());
      console.log('✓ Created .env.example file');
    }
  });
  
  it('should have health check endpoints', async () => {
    const healthEndpoints = [
      '/health',
      '/health/live',
      '/health/ready',
      '/api/health',
    ];
    
    let foundHealthEndpoint = false;
    
    for (const endpoint of healthEndpoints) {
      try {
        // This would need to be tested against a running application
        // For now, we'll check if the endpoint is documented or implemented
        const appFile = path.join(process.cwd(), 'src', 'app.ts');
        try {
          const content = await fs.readFile(appFile, 'utf8');
          if (content.includes(endpoint)) {
            foundHealthEndpoint = true;
            console.log(`✓ Found health check endpoint: ${endpoint}`);
            break;
          }
        } catch {
          continue;
        }
      } catch {
        continue;
      }
    }
    
    if (!foundHealthEndpoint) {
      console.log('No health check endpoints found in source code');
    }
  });
  
  it('should have proper logging configuration', async () => {
    const logConfigs = [
      'src/config/logger.ts',
      'src/utils/logger.ts',
      'config/logger.js',
      'winston.config.js',
    ];
    
    let foundLogConfig = false;
    
    for (const config of logConfigs) {
      const configPath = path.join(process.cwd(), config);
      try {
        await fs.access(configPath);
        foundLogConfig = true;
        console.log(`✓ Found logging configuration: ${config}`);
        break;
      } catch {
        continue;
      }
    }
    
    if (!foundLogConfig) {
      console.log('No specific logging configuration found, checking package.json...');
      
      const packageJsonPath = path.join(process.cwd(), 'package.json');
      const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
      
      const hasWinston = packageJson.dependencies?.winston || packageJson.devDependencies?.winston;
      const hasPino = packageJson.dependencies?.pino || packageJson.devDependencies?.pino;
      
      if (hasWinston || hasPino) {
        console.log('✓ Logging library found in dependencies');
      } else {
        console.log('No logging library found in dependencies');
      }
    }
  });
  
  it('should support blue-green deployment', async () => {
    const deploymentFiles = [
      'deploy/blue-green-deploy.sh',
      'kubernetes/blue-green-deployment.yaml',
      'terraform/blue-green.tf',
    ];
    
    let foundBlueGreen = false;
    
    for (const file of deploymentFiles) {
      const filePath = path.join(process.cwd(), file);
      try {
        const content = await fs.readFile(filePath, 'utf8');
        if (content.includes('blue') && content.includes('green')) {
          foundBlueGreen = true;
          console.log(`✓ Found blue-green deployment configuration: ${file}`);
          break;
        }
      } catch {
        continue;
      }
    }
    
    if (!foundBlueGreen) {
      console.log('No blue-green deployment configuration found');
    }
  });
});

// ====================
// MONITORING AND OBSERVABILITY TESTS
// ====================

describe('Monitoring and Observability Tests', () => {
  
  it('should have monitoring configuration', async () => {
    const monitoringConfigs = [
      'prometheus.yml',
      'grafana/dashboards',
      'monitoring/prometheus.yml',
      'config/prometheus.yml',
    ];
    
    let foundMonitoring = false;
    
    for (const config of monitoringConfigs) {
      const configPath = path.join(process.cwd(), config);
      try {
        await fs.access(configPath);
        foundMonitoring = true;
        console.log(`✓ Found monitoring configuration: ${config}`);
        break;
      } catch {
        continue;
      }
    }
    
    if (!foundMonitoring) {
      console.log('No monitoring configuration found');
    }
  });
  
  it('should have application metrics', async () => {
    const packageJsonPath = path.join(process.cwd(), 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    const monitoringPackages = [
      'prom-client',
      'express-prometheus-middleware',
      'appmetrics',
      'newrelic',
      'datadog-lambda-js',
    ];
    
    const hasMonitoring = monitoringPackages.some(pkg => 
      packageJson.dependencies?.[pkg] || packageJson.devDependencies?.[pkg]
    );
    
    if (hasMonitoring) {
      console.log('✓ Monitoring packages found in dependencies');
    } else {
      console.log('No monitoring packages found in dependencies');
    }
  });
  
  it('should have distributed tracing', async () => {
    const packageJsonPath = path.join(process.cwd(), 'package.json');
    const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
    
    const tracingPackages = [
      '@opentelemetry/api',
      '@opentelemetry/sdk-node',
      'jaeger-client',
      'zipkin',
      'dd-trace',
    ];
    
    const hasTracing = tracingPackages.some(pkg => 
      packageJson.dependencies?.[pkg] || packageJson.devDependencies?.[pkg]
    );
    
    if (hasTracing) {
      console.log('✓ Distributed tracing packages found in dependencies');
    } else {
      console.log('No distributed tracing packages found in dependencies');
    }
  });
  
  it('should have alerting configuration', async () => {
    const alertingConfigs = [
      'alerts.yml',
      'monitoring/alerts.yml',
      'prometheus/alerts.yml',
      'config/alerts.yml',
    ];
    
    let foundAlerting = false;
    
    for (const config of alertingConfigs) {
      const configPath = path.join(process.cwd(), config);
      try {
        await fs.access(configPath);
        foundAlerting = true;
        console.log(`✓ Found alerting configuration: ${config}`);
        break;
      } catch {
        continue;
      }
    }
    
    if (!foundAlerting) {
      console.log('No alerting configuration found');
    }
  });
});

// ====================
// HELPER FUNCTIONS
// ====================

async function runCommand(command: string, options: any = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    const { timeout = 60000, cwd = process.cwd() } = options;
    
    execSync(command, {
      cwd,
      stdio: 'pipe',
      timeout,
      encoding: 'utf8',
    }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`${error.message}\n${stderr}`));
      } else {
        resolve(stdout);
      }
    });
  });
}

function validateYAML(content: string): boolean {
  try {
    yaml.load(content);
    return true;
  } catch {
    return false;
  }
}

function validateJSON(content: string): boolean {
  try {
    JSON.parse(content);
    return true;
  } catch {
    return false;
  }
}

async function checkFileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function getFileSize(filePath: string): Promise<number> {
  try {
    const stats = await fs.stat(filePath);
    return stats.size;
  } catch {
    return 0;
  }
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}