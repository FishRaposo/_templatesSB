#!/usr/bin/env node
/**
 * Universal Skill Validator
 * Validates skills against the universal skill standard
 */

import fs from 'fs/promises';
import path from 'path';
import yaml from 'js-yaml';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class SkillValidator {
  constructor(skillPath) {
    this.skillPath = path.resolve(skillPath);
    this.errors = [];
    this.warnings = [];
    this.skillDir = path.basename(this.skillPath);
  }

  async validate() {
    console.log(`\n🔍 Validating skill: ${this.skillDir}`);
    console.log('='.repeat(50));

    await this.checkStructure();
    await this.validateFrontmatter();
    await this.checkSupportingFiles();
    await this.validateDependencies();
    await this.checkPermissions();
    await this.validateCrossPlatform();

    this.printResults();
    return this.errors.length === 0;
  }

  async checkStructure() {
    console.log('\n📁 Checking structure...');

    // Check SKILL.md exists
    const skillFile = path.join(this.skillPath, 'SKILL.md');
    try {
      await fs.access(skillFile);
      console.log('✓ SKILL.md exists');
    } catch {
      this.errors.push('SKILL.md not found');
      return;
    }

    // Check directory name matches
    const content = await fs.readFile(skillFile, 'utf-8');
    const frontmatterMatch = content.match(/^---\n(.*?)\n---/s);
    
    if (frontmatterMatch) {
      try {
        const frontmatter = yaml.load(frontmatterMatch[1]);
        if (frontmatter.name !== this.skillDir) {
          this.errors.push(`Directory name '${this.skillDir}' does not match frontmatter name '${frontmatter.name}'`);
        } else {
          console.log('✓ Directory name matches frontmatter');
        }
      } catch (e) {
        this.errors.push('Invalid YAML in frontmatter');
      }
    }

    // Check optional directories
    const optionalDirs = ['scripts', 'templates', 'examples', 'tests'];
    for (const dir of optionalDirs) {
      const dirPath = path.join(this.skillPath, dir);
      try {
        await fs.access(dirPath);
        console.log(`✓ ${dir}/ directory exists`);
      } catch {
        this.warnings.push(`${dir}/ directory not found (optional)`);
      }
    }
  }

  async validateFrontmatter() {
    console.log('\n📋 Validating frontmatter...');

    const skillFile = path.join(this.skillPath, 'SKILL.md');
    const content = await fs.readFile(skillFile, 'utf-8');
    const frontmatterMatch = content.match(/^---\n(.*?)\n---/s);

    if (!frontmatterMatch) {
      this.errors.push('No frontmatter found');
      return;
    }

    try {
      const frontmatter = yaml.load(frontmatterMatch[1]);

      // Check required fields
      const required = ['name', 'description'];
      for (const field of required) {
        if (!frontmatter[field]) {
          this.errors.push(`Required field missing: ${field}`);
        } else {
          console.log(`✓ ${field} field present`);
        }
      }

      // Validate name format
      if (frontmatter.name) {
        const namePattern = /^[a-z0-9]+(-[a-z0-9]+)*$/;
        if (!namePattern.test(frontmatter.name)) {
          this.errors.push('Name must contain only lowercase letters, numbers, and hyphens');
        } else {
          console.log('✓ Name format is valid');
        }
      }

      // Validate description
      if (frontmatter.description) {
        if (frontmatter.description.length < 10) {
          this.warnings.push('Description seems too short');
        } else if (frontmatter.description.length > 1024) {
          this.errors.push('Description exceeds 1024 characters');
        } else {
          console.log('✓ Description length is valid');
        }

        // Check for vague descriptions
        const vaguePhrases = ['help with', 'process files', 'handle data'];
        const descLower = frontmatter.description.toLowerCase();
        for (const phrase of vaguePhrases) {
          if (descLower.includes(phrase)) {
            this.warnings.push(`Description contains vague phrase: '${phrase}'`);
          }
        }
      }

      // Validate optional fields
      const optionalFields = ['version', 'tags', 'category', 'dependencies', 'permissions'];
      for (const field of optionalFields) {
        if (frontmatter[field]) {
          console.log(`✓ ${field} field present`);
        }
      }

    } catch (e) {
      this.errors.push(`Error parsing frontmatter: ${e.message}`);
    }
  }

  async checkSupportingFiles() {
    console.log('\n📄 Checking supporting files...');

    // Check config.json
    const configFile = path.join(this.skillPath, 'config.json');
    try {
      const configContent = await fs.readFile(configFile, 'utf-8');
      JSON.parse(configContent);
      console.log('✓ config.json is valid JSON');
    } catch {
      this.warnings.push('config.json not found or invalid (optional)');
    }

    // Check README.md
    const readmeFile = path.join(this.skillPath, 'README.md');
    try {
      await fs.access(readmeFile);
      console.log('✓ README.md exists');
    } catch {
      this.warnings.push('README.md not found (optional)');
    }

    // Check scripts
    const scriptsDir = path.join(this.skillPath, 'scripts');
    try {
      const scripts = await fs.readdir(scriptsDir);
      for (const script of scripts) {
        if (script.endsWith('.js') || script.endsWith('.py')) {
          console.log(`✓ Script found: ${script}`);
        }
      }
    } catch {
      // No scripts directory
    }
  }

  async validateDependencies() {
    console.log('\n📦 Validating dependencies...');

    const configFile = path.join(this.skillPath, 'config.json');
    try {
      const configContent = await fs.readFile(configFile, 'utf-8');
      const config = JSON.parse(configContent);
      
      if (config.dependencies) {
        for (const [lang, deps] of Object.entries(config.dependencies)) {
          if (Array.isArray(deps) && deps.length > 0) {
            console.log(`✓ ${lang} dependencies specified`);
          }
        }
      }
    } catch {
      // No config file
    }
  }

  async checkPermissions() {
    console.log('\n🔒 Checking permissions...');

    const configFile = path.join(this.skillPath, 'config.json');
    try {
      const configContent = await fs.readFile(configFile, 'utf-8');
      const config = JSON.parse(configContent);
      
      if (config.permissions) {
        const perms = config.permissions;
        
        // Check for dangerous permissions
        if (perms.network?.outbound && !perms.external_apis?.length) {
          this.warnings.push('Network access allowed but no external APIs specified');
        }
        
        if (perms.code_execution?.shell) {
          this.warnings.push('Shell code execution enabled - ensure this is necessary');
        }
        
        console.log('✓ Permissions defined');
      }
    } catch {
      // No config file
    }
  }

  async validateCrossPlatform() {
    console.log('\n🌐 Checking cross-platform compatibility...');

    const configFile = path.join(this.skillPath, 'config.json');
    try {
      const configContent = await fs.readFile(configFile, 'utf-8');
      const config = JSON.parse(configContent);
      
      if (config.agent_support) {
        const supportedAgents = Object.keys(config.agent_support);
        console.log(`✓ Agent support defined for: ${supportedAgents.join(', ')}`);
        
        // Check for at least one universal agent
        if (!supportedAgents.includes('generic') && !supportedAgents.includes('claude')) {
          this.warnings.push('Consider adding support for generic agents');
        }
      }
    } catch {
      // No config file
    }

    // Check for platform-specific paths
    const skillFile = path.join(this.skillPath, 'SKILL.md');
    const content = await fs.readFile(skillFile, 'utf-8');
    
    if (content.includes('~/.claude/') || content.includes('~/.roo/')) {
      this.warnings.push('Contains platform-specific paths - consider using universal paths');
    }
  }

  printResults() {
    console.log('\n' + '='.repeat(50));
    console.log('📊 VALIDATION RESULTS');
    console.log('='.repeat(50));

    if (this.errors.length === 0 && this.warnings.length === 0) {
      console.log('✅ Skill passed all validations!');
    } else {
      if (this.errors.length > 0) {
        console.log(`\n❌ ERRORS (${this.errors.length}):`);
        this.errors.forEach((error, i) => {
          console.log(`  ${i + 1}. ${error}`);
        });
      }

      if (this.warnings.length > 0) {
        console.log(`\n⚠️  WARNINGS (${this.warnings.length}):`);
        this.warnings.forEach((warning, i) => {
          console.log(`  ${i + 1}. ${warning}`);
        });
      }
    }

    console.log(`\nSummary: ${this.errors.length} errors, ${this.warnings.length} warnings`);
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const skillPath = process.argv[2];
  
  if (!skillPath) {
    console.error('Usage: node validate-skill.js <skill-path>');
    process.exit(1);
  }

  const validator = new SkillValidator(skillPath);
  validator.validate()
    .then(success => {
      process.exit(success ? 0 : 1);
    })
    .catch(error => {
      console.error('Validation failed:', error);
      process.exit(1);
    });
}

export default SkillValidator;
