#!/usr/bin/env node
/**
 * Batch Skill Validator
 * Validates multiple skills in a directory
 */

import fs from 'fs/promises';
import path from 'path';
import { glob } from 'glob';
import chalk from 'chalk';
import SkillValidator from './validate-skill.js';

class BatchValidator {
  constructor(skillsDir) {
    this.skillsDir = path.resolve(skillsDir);
    this.results = [];
  }

  async validateAll() {
    console.log(`\n🔍 Batch validating skills in: ${this.skillsDir}`);
    console.log('='.repeat(60));

    // Find all skill directories
    const skillDirs = await this.findSkillDirectories();
    
    if (skillDirs.length === 0) {
      console.log(chalk.yellow('No skill directories found.'));
      return;
    }

    console.log(`Found ${skillDirs.length} skill(s)\n`);

    // Validate each skill
    for (const skillDir of skillDirs) {
      const validator = new SkillValidator(skillDir);
      const success = await validator.validate();
      
      this.results.push({
        name: path.basename(skillDir),
        path: skillDir,
        success
      });
    }

    this.printSummary();
  }

  async findSkillDirectories() {
    const pattern = path.join(this.skillsDir, '*', 'SKILL.md');
    const files = await glob(pattern);
    
    return files.map(file => path.dirname(file));
  }

  printSummary() {
    console.log('\n' + '='.repeat(60));
    console.log('📊 BATCH VALIDATION SUMMARY');
    console.log('='.repeat(60));

    const successful = this.results.filter(r => r.success);
    const failed = this.results.filter(r => !r.success);

    if (successful.length > 0) {
      console.log(chalk.green(`\n✅ Valid skills (${successful.length}):`));
      successful.forEach(result => {
        console.log(chalk.green(`  - ${result.name}`));
      });
    }

    if (failed.length > 0) {
      console.log(chalk.red(`\n❌ Invalid skills (${failed.length}):`));
      failed.forEach(result => {
        console.log(chalk.red(`  - ${result.name}`));
      });
    }

    console.log(`\nSummary: ${successful.length} passed, ${failed.length} failed`);
    
    if (failed.length > 0) {
      console.log(chalk.red('\n⚠️  Some skills failed validation. Please fix the issues above.'));
      process.exit(1);
    } else {
      console.log(chalk.green('\n🎉 All skills passed validation!'));
    }
  }
}

// CLI interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const skillsDir = process.argv[2] || './skills';
  
  const validator = new BatchValidator(skillsDir);
  validator.validateAll()
    .catch(error => {
      console.error(chalk.red('Batch validation failed:'), error);
      process.exit(1);
    });
}

export default BatchValidator;
