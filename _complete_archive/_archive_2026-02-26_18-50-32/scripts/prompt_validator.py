#!/usr/bin/env python3
"""
Prompt Validation System
Validates all user inputs and prompts before execution
Protects against injection attacks, malformed input, and excessive token usage
"""

import re
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class ValidationLevel(Enum):
    """Validation strictness levels"""
    PERMISSIVE = "permissive"
    STANDARD = "standard"
    STRICT = "strict"

@dataclass
class ValidationResult:
    """Result of prompt validation"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    sanitized_input: Optional[str] = None
    token_estimate: Optional[int] = None

class PromptValidator:
    """Comprehensive prompt validation system"""
    
    def __init__(self, validation_level: ValidationLevel = ValidationLevel.STANDARD):
        self.validation_level = validation_level
        self.max_description_length = 2000
        self.max_project_name_length = 100
        self.max_stack_name_length = 50
        
        # Security patterns to block
        self.dangerous_patterns = [
            r'<script.*?>.*?</script>',  # Script tags
            r'javascript:',              # JavaScript protocol
            r'data:',                    # Data protocol
            r'vbscript:',                # VBScript protocol
            r'on\w+\s*=',                # Event handlers
            r'eval\s*\(',                # eval() function
            r'exec\s*\(',                # exec() function
            r'__import__\s*\(',          # Python import
            r'subprocess\.',             # Subprocess calls
            r'os\.',                     # OS module calls
            r'\$\{.*\}',                 # Shell command substitution
            r'`.*`',                     # Backtick commands
            r'\.\./.*',                  # Directory traversal
            r'etc/passwd',               # System file access
            r'cmd\.exe',                 # Windows command
            r'powershell',               # PowerShell
            r'bash\s+-c',                # Bash command execution
            r'rm\s+-rf\s+/',             # rm -rf command
            r'DROP\s+TABLE',             # SQL injection
            r'DELETE\s+FROM',            # SQL injection
            r'INSERT\s+INTO',            # SQL injection
            r'UPDATE\s+.*\s+SET',        # SQL injection
            r'UNION\s+SELECT',           # SQL injection
            r'sudo\s+',                  # Sudo commands
            r'chmod\s+',                 # Permission changes
            r'chown\s+',                 # Ownership changes
        ]
        
        # Compile regex patterns for efficiency
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.DOTALL) 
                                 for pattern in self.dangerous_patterns]
        
        # Allowed characters for different input types
        self.allowed_project_chars = re.compile(r'^[a-zA-Z0-9_-]+$')
        self.allowed_stack_chars = re.compile(r'^[a-z]+$')
        
    def validate_project_description(self, description: str) -> ValidationResult:
        """Validate project description input"""
        errors = []
        warnings = []
        
        if not description or not description.strip():
            errors.append("Project description cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        # Length validation
        if len(description) > self.max_description_length:
            errors.append(f"Description too long (max {self.max_description_length} characters)")
        
        if len(description) < 10:
            warnings.append("Description very short - may not provide enough context")
        
        # Security validation
        sanitized = description
        for pattern in self.compiled_patterns:
            if pattern.search(description):
                errors.append(f"Potentially dangerous content detected: {pattern.pattern}")
                # Remove dangerous content for sanitization
                sanitized = pattern.sub('[REMOVED]', sanitized)
        
        # Content validation
        if not re.search(r'[a-zA-Z]', description):
            errors.append("Description must contain alphabetic characters")
        
        # Token estimation (rough approximation)
        token_estimate = len(description.split()) * 1.3  # Rough token estimate
        
        # Check for potential injection attempts
        suspicious_patterns = [
            r'\b(drop|delete|truncate|alter)\s+(table|database|schema)',
            r'\b(insert|update)\s+.*\b(set|where)\s*=',
            r'\bunion\s+select',
            r'\b(exec|execute)\s+',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, description, re.IGNORECASE):
                warnings.append(f"Suspicious pattern detected: {pattern}")
        
        # Level-specific validation
        if self.validation_level == ValidationLevel.STRICT:
            # Additional strict validation
            if len(description.split()) < 3:
                errors.append("Description must contain at least 3 words in strict mode")
            
            if not re.search(r'\b(app|application|system|platform|service|tool|project)\b', description, re.IGNORECASE):
                warnings.append("Description doesn't clearly indicate a software project")
        
        is_valid = len(errors) == 0
        return ValidationResult(is_valid, errors, warnings, sanitized, int(token_estimate))
    
    def validate_project_name(self, name: str) -> ValidationResult:
        """Validate project name input"""
        errors = []
        warnings = []
        
        if not name or not name.strip():
            errors.append("Project name cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        # Length validation
        if len(name) > self.max_project_name_length:
            errors.append(f"Project name too long (max {self.max_project_name_length} characters)")
        
        if len(name) < 2:
            errors.append("Project name too short (min 2 characters)")
        
        # Character validation
        if not self.allowed_project_chars.match(name):
            errors.append("Project name can only contain letters, numbers, hyphens, and underscores")
        
        # Reserved names
        reserved_names = ['test', 'demo', 'example', 'sample', 'temp', 'tmp', 'admin', 'root', 'system']
        if name.lower() in reserved_names:
            warnings.append(f"Project name '{name}' is commonly reserved and may cause conflicts")
        
        # System conflicts
        system_conflicts = ['con', 'prn', 'aux', 'nul', 'com1', 'com2', 'lpt1', 'lpt2']
        if name.lower() in system_conflicts:
            errors.append(f"Project name '{name}' conflicts with system reserved names")
        
        is_valid = len(errors) == 0
        return ValidationResult(is_valid, errors, warnings, name)
    
    def validate_stack_name(self, stack: str) -> ValidationResult:
        """Validate technology stack input"""
        errors = []
        warnings = []
        
        if not stack or not stack.strip():
            errors.append("Stack name cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        # Length validation
        if len(stack) > self.max_stack_name_length:
            errors.append(f"Stack name too long (max {self.max_stack_name_length} characters)")
        
        # Character validation
        if not self.allowed_stack_chars.match(stack):
            errors.append("Stack name can only contain lowercase letters")
        
        # Known stacks
        known_stacks = ['python', 'node', 'go', 'react', 'nextjs', 'flutter', 'sql', 'r']
        if stack not in known_stacks:
            warnings.append(f"Stack '{stack}' is not in the known supported stacks: {', '.join(known_stacks)}")
        
        is_valid = len(errors) == 0
        return ValidationResult(is_valid, errors, warnings, stack)
    
    def validate_template_placeholders(self, content: str, required_placeholders: List[str]) -> ValidationResult:
        """Validate that all required template placeholders are present"""
        errors = []
        warnings = []
        
        # Find all placeholders in content
        placeholder_pattern = r'\{\{(\w+)\}\}'
        found_placeholders = re.findall(placeholder_pattern, content)
        
        # Check for missing required placeholders
        for placeholder in required_placeholders:
            if placeholder not in found_placeholders:
                errors.append(f"Missing required placeholder: {{{{ {placeholder} }}}}")
        
        # Check for undefined placeholders
        for placeholder in found_placeholders:
            if placeholder not in required_placeholders:
                warnings.append(f"Undefined placeholder found: {{{{ {placeholder} }}}}")
        
        # Check for malformed placeholders
        malformed_pattern = r'\{\{[^}]*$|^\{[^}]*\}\}'
        if re.search(malformed_pattern, content, re.MULTILINE):
            errors.append("Malformed placeholder syntax detected")
        
        is_valid = len(errors) == 0
        return ValidationResult(is_valid, errors, warnings, content)
    
    def validate_yaml_config(self, config_content: str) -> ValidationResult:
        """Validate YAML configuration content"""
        errors = []
        warnings = []
        
        if not config_content or not config_content.strip():
            errors.append("YAML configuration cannot be empty")
            return ValidationResult(False, errors, warnings)
        
        try:
            # Parse YAML to check syntax
            config_data = yaml.safe_load(config_content)
            
            if not isinstance(config_data, dict):
                errors.append("YAML configuration must be a dictionary/object")
                return ValidationResult(False, errors, warnings)
            
            # Check for required top-level keys
            required_keys = ['tasks', 'project_name']
            for key in required_keys:
                if key not in config_data:
                    errors.append(f"Missing required configuration key: {key}")
            
            # Validate tasks section
            if 'tasks' in config_data:
                tasks = config_data['tasks']
                if not isinstance(tasks, list):
                    errors.append("Tasks must be a list")
                else:
                    if len(tasks) == 0:
                        warnings.append("No tasks specified in configuration")
                    elif len(tasks) > 20:
                        warnings.append("Large number of tasks may impact performance")
            
            # Validate project name
            if 'project_name' in config_data:
                project_name_result = self.validate_project_name(str(config_data['project_name']))
                errors.extend(project_name_result.errors)
                warnings.extend(project_name_result.warnings)
            
        except yaml.YAMLError as e:
            errors.append(f"Invalid YAML syntax: {e}")
        except Exception as e:
            errors.append(f"Configuration validation error: {e}")
        
        is_valid = len(errors) == 0
        return ValidationResult(is_valid, errors, warnings, config_content)
    
    def validate_cli_arguments(self, args: Dict[str, Any]) -> ValidationResult:
        """Validate command-line arguments"""
        errors = []
        warnings = []
        
        # Validate description if present
        if 'description' in args:
            desc_result = self.validate_project_description(args['description'])
            errors.extend(desc_result.errors)
            warnings.extend(desc_result.warnings)
        
        # Validate project name if present
        if 'project_name' in args:
            name_result = self.validate_project_name(args['project_name'])
            errors.extend(name_result.errors)
            warnings.extend(name_result.warnings)
        
        # Validate stack if present
        if 'stack' in args:
            stack_result = self.validate_stack_name(args['stack'])
            errors.extend(stack_result.errors)
            warnings.extend(stack_result.warnings)
        
        # Validate file paths
        if 'output' in args and args['output']:
            output_path = Path(args['output'])
            try:
                # Check if parent directory exists or can be created
                if not output_path.parent.exists():
                    warnings.append(f"Output directory does not exist: {output_path.parent}")
                
                # Check file extension
                if output_path.suffix not in ['.yaml', '.yml', '.json', '.md']:
                    warnings.append(f"Unexpected file extension: {output_path.suffix}")
                    
            except Exception as e:
                errors.append(f"Invalid output path: {e}")
        
        is_valid = len(errors) == 0
        return ValidationResult(is_valid, errors, warnings)
    
    def sanitize_input(self, input_text: str) -> str:
        """Sanitize input text by removing dangerous content"""
        sanitized = input_text
        
        # Remove dangerous patterns
        for pattern in self.compiled_patterns:
            sanitized = pattern.sub('[REMOVED]', sanitized)
        
        # Normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        return sanitized
    
    def get_validation_summary(self, results: List[ValidationResult]) -> Dict[str, Any]:
        """Get summary of multiple validation results"""
        total_errors = sum(len(result.errors) for result in results)
        total_warnings = sum(len(result.warnings) for result in results)
        all_valid = all(result.is_valid for result in results)
        
        return {
            'overall_valid': all_valid,
            'total_errors': total_errors,
            'total_warnings': total_warnings,
            'validation_level': self.validation_level.value,
            'results': results
        }

def main():
    """CLI interface for prompt validation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate prompts and inputs')
    parser.add_argument('--description', '-d', help='Validate project description')
    parser.add_argument('--project-name', '-p', help='Validate project name')
    parser.add_argument('--stack', '-s', help='Validate stack name')
    parser.add_argument('--yaml-file', '-y', help='Validate YAML configuration file')
    parser.add_argument('--level', '-l', choices=['permissive', 'standard', 'strict'], 
                       default='standard', help='Validation level')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    validator = PromptValidator(ValidationLevel(args.level))
    results = []
    
    if args.description:
        result = validator.validate_project_description(args.description)
        results.append(('description', result))
    
    if args.project_name:
        result = validator.validate_project_name(args.project_name)
        results.append(('project_name', result))
    
    if args.stack:
        result = validator.validate_stack_name(args.stack)
        results.append(('stack', result))
    
    if args.yaml_file:
        try:
            with open(args.yaml_file, 'r', encoding='utf-8') as f:
                yaml_content = f.read()
            result = validator.validate_yaml_config(yaml_content)
            results.append(('yaml_file', result))
        except Exception as e:
            print(f"❌ Error reading YAML file: {e}")
            sys.exit(1)
    
    if not results:
        print("❌ No input provided for validation")
        parser.print_help()
        sys.exit(1)
    
    # Display results
    summary = validator.get_validation_summary([r[1] for r in results])
    
    print("🔍 Prompt Validation Results")
    print("=" * 40)
    print(f"Validation Level: {summary['validation_level'].title()}")
    print(f"Overall Status: {'✅ VALID' if summary['overall_valid'] else '❌ INVALID'}")
    print(f"Total Errors: {summary['total_errors']}")
    print(f"Total Warnings: {summary['total_warnings']}")
    print()
    
    for input_type, result in results:
        print(f"📋 {input_type.replace('_', ' ').title()}:")
        print(f"   Status: {'✅ Valid' if result.is_valid else '❌ Invalid'}")
        
        if args.verbose:
            if result.errors:
                print("   Errors:")
                for error in result.errors:
                    print(f"     - {error}")
            
            if result.warnings:
                print("   Warnings:")
                for warning in result.warnings:
                    print(f"     - {warning}")
            
            if result.token_estimate:
                print(f"   Token Estimate: {result.token_estimate}")
        
        print()
    
    if not summary['overall_valid']:
        sys.exit(1)

if __name__ == "__main__":
    main()
