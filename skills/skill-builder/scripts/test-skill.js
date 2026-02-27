#!/usr/bin/env node
/**
 * Universal Skill Test Framework
 * Tests skills across different scenarios and platforms
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import yaml from 'js-yaml';

const execAsync = promisify(exec);

class SkillTester {
  constructor(skillPath) {
    this.skillPath = path.resolve(skillPath);
    this.skillName = path.basename(this.skillPath);
    this.testResults = [];
  }

  async runTests() {
    console.log(`\n🧪 Testing skill: ${this.skillName}`);
    console.log('='.repeat(50));

    await this.testLoading();
    await this.testMetadata();
    await this.testDependencies();
    await this.testExecution();
    await this.testErrorHandling();

    this.printResults();
    return this.testResults.filter(r => r.status === 'failed').length === 0;
  }

  async testLoading() {
    console.log('\n📥 Testing skill loading...');

    await this.runTest('Skill file exists', async () => {
      const skillFile = path.join(this.skillPath, 'SKILL.md');
      await fs.access(skillFile);
      return true;
    });

    await this.runTest('Frontmatter parses correctly', async () => {
      const skillFile = path.join(this.skillPath, 'SKILL.md');
      const content = await fs.readFile(skillFile, 'utf-8');
      const frontmatterMatch = content.match(/^---\n(.*?)\n---/s);
      
      if (!frontmatterMatch) {
        throw new Error('No frontmatter found');
      }
      
      yaml.load(frontmatterMatch[1]);
      return true;
    });

    await this.runTest('Name matches directory', async () => {
      const skillFile = path.join(this.skillPath, 'SKILL.md');
      const content = await fs.readFile(skillFile, 'utf-8');
      const frontmatterMatch = content.match(/^---\n(.*?)\n---/s);
      const frontmatter = yaml.load(frontmatterMatch[1]);
      
      if (frontmatter.name !== this.skillName) {
        throw new Error(`Name '${frontmatter.name}' does not match directory '${this.skillName}'`);
      }
      return true;
    });
  }

  async testMetadata() {
    console.log('\n📋 Testing metadata...');

    await this.runTest('Required fields present', async () => {
      const skillFile = path.join(this.skillPath, 'SKILL.md');
      const content = await fs.readFile(skillFile, 'utf-8');
      const frontmatterMatch = content.match(/^---\n(.*?)\n---/s);
      const frontmatter = yaml.load(frontmatterMatch[1]);
      
      const required = ['name', 'description'];
      for (const field of required) {
        if (!frontmatter[field]) {
          throw new Error(`Missing required field: ${field}`);
        }
      }
      return true;
    });

    await this.runTest('Description is specific', async () => {
      const skillFile = path.join(this.skillPath, 'SKILL.md');
      const content = await fs.readFile(skillFile, 'utf-8');
      const frontmatterMatch = content.match(/^---\n(.*?)\n---/s);
      const frontmatter = yaml.load(frontmatterMatch[1]);
      
      const desc = frontmatter.description;
      if (desc.length < 50) {
        throw new Error('Description too short (should be at least 50 characters)');
      }
      
      const vague = ['help with', 'process files', 'handle data'];
      for (const phrase of vague) {
        if (desc.toLowerCase().includes(phrase)) {
          throw new Error(`Description contains vague phrase: '${phrase}'`);
        }
      }
      
      return true;
    });
  }

  async testDependencies() {
    console.log('\n📦 Testing dependencies...');

    // Check config.json
    await this.runTest('Config.json is valid', async () => {
      const configFile = path.join(this.skillPath, 'config.json');
      try {
        const content = await fs.readFile(configFile, 'utf-8');
        JSON.parse(content);
        return true;
      } catch (e) {
        if (e.code === 'ENOENT') {
          return true; // Optional file
        }
        throw e;
      }
    });

    // Check Python dependencies
    await this.runTest('Python dependencies installable', async () => {
      const configFile = path.join(this.skillPath, 'config.json');
      try {
        const content = await fs.readFile(configFile, 'utf-8');
        const config = JSON.parse(content);
        
        if (config.dependencies?.python?.length > 0) {
          // Try to check if packages exist
          for (const dep of config.dependencies.python) {
            const pkg = dep.split('>=')[0].split('==')[0];
            try {
              await execAsync(`pip show ${pkg}`);
            } catch {
              throw new Error(`Python package not installed: ${pkg}`);
            }
          }
        }
        return true;
      } catch (e) {
        if (e.code === 'ENOENT') {
          return true;
        }
        throw e;
      }
    });

    // Check Node.js dependencies
    await this.runTest('Node.js dependencies installable', async () => {
      const configFile = path.join(this.skillPath, 'config.json');
      try {
        const content = await fs.readFile(configFile, 'utf-8');
        const config = JSON.parse(content);
        
        if (config.dependencies?.node?.length > 0) {
          // Check if package.json exists
          const packageFile = path.join(this.skillPath, 'package.json');
          try {
            await fs.access(packageFile);
          } catch {
            throw new Error('Node.js dependencies specified but no package.json found');
          }
        }
        return true;
      } catch (e) {
        if (e.code === 'ENOENT') {
          return true;
        }
        throw e;
      }
    });
  }

  async testExecution() {
    console.log('\n⚡ Testing execution...');

    // Test script execution
    await this.runTest('Scripts are executable', async () => {
      const scriptsDir = path.join(this.skillPath, 'scripts');
      try {
        const scripts = await fs.readdir(scriptsDir);
        
        for (const script of scripts) {
          if (script.endsWith('.js')) {
            // Try to parse the JavaScript
            const scriptPath = path.join(scriptsDir, script);
            const content = await fs.readFile(scriptPath, 'utf-8');
            
            // Basic syntax check
            if (content.includes('import') && !content.includes('"type": "module"')) {
              // Check if package.json has type: module
              const packageFile = path.join(this.skillPath, 'package.json');
              try {
                const pkgContent = await fs.readFile(packageFile, 'utf-8');
                const pkg = JSON.parse(pkgContent);
                if (pkg.type !== 'module') {
                  throw new Error(`Script ${script} uses ES modules but package.json doesn't have "type": "module"`);
                }
              } catch {
                throw new Error(`Script ${script} uses ES modules but no package.json found`);
              }
            }
          }
        }
        return true;
      } catch (e) {
        if (e.code === 'ENOENT') {
          return true; // No scripts directory
        }
        throw e;
      }
    });

    // Test template rendering
    await this.runTest('Templates are accessible', async () => {
      const templatesDir = path.join(this.skillPath, 'templates');
      try {
        const templates = await fs.readdir(templatesDir);
        
        for (const template of templates) {
          const templatePath = path.join(templatesDir, template);
          const content = await fs.readFile(templatePath, 'utf-8');
          
          // Check for template variables
          if (content.includes('{{') && content.includes('}}')) {
            // Basic template syntax check
            console.log(`  ✓ Template ${template} uses template syntax`);
          }
        }
        return true;
      } catch (e) {
        if (e.code === 'ENOENT') {
          return true; // No templates directory
        }
        throw e;
      }
    });
  }

  async testErrorHandling() {
    console.log('\n🛡️ Testing error handling...');

    await this.runTest('Error handling in instructions', async () => {
      const skillFile = path.join(this.skillPath, 'SKILL.md');
      const content = await fs.readFile(skillFile, 'utf-8');
      
      // Check for error handling sections
      if (!content.toLowerCase().includes('error') && 
          !content.toLowerCase().includes('troubleshoot') &&
          !content.toLowerCase().includes('issue')) {
        throw new Error('No error handling or troubleshooting section found');
      }
      
      return true;
    });

    await this.runTest('Fallback mechanisms defined', async () => {
      const configFile = path.join(this.skillPath, 'config.json');
      try {
        const content = await fs.readFile(configFile, 'utf-8');
        const config = JSON.parse(content);
        
        if (config.fallbacks) {
          console.log('  ✓ Fallback mechanisms defined');
        }
        
        return true;
      } catch (e) {
        if (e.code === 'ENOENT') {
          return true;
        }
        throw e;
      }
    });
  }

  async runTest(name, testFn) {
    try {
      await testFn();
      this.testResults.push({ name, status: 'passed' });
      console.log(`  ✓ ${name}`);
    } catch (error) {
      this.testResults.push({ name, status: 'failed', error: error.message });
      console.log(`  ✗ ${name}: ${error.message}`);
    }
  }

  printResults() {
    console.log('\n' + '='.repeat(50));
    console.log('📊 TEST RESULTS');
    console.log('='.repeat(50));

    const passed = this.testResults.filter(r => r.status === 'passed').length;
    const failed = this.testResults.filter(r => r.status === 'failed').length;

    if (failed === 0) {
      console.log('✅ All tests passed!');
    } else {
      console.log(`\n❌ Failed tests (${failed}):`);
      this.testResults
        .filter(r => r.status === 'failed')
        .forEach(test => {
          console.log(`  - ${test.name}: ${test.error}`);
        });
    }

    console.log(`\nSummary: ${passed} passed, ${failed} failed`);
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const skillPath = process.argv[2];
  
  if (!skillPath) {
    console.error('Usage: node test-skill.js <skill-path>');
    process.exit(1);
  }

  const tester = new SkillTester(skillPath);
  tester.runTests()
    .then(success => {
      process.exit(success ? 0 : 1);
    })
    .catch(error => {
      console.error('Testing failed:', error);
      process.exit(1);
    });
}

export default SkillTester;
