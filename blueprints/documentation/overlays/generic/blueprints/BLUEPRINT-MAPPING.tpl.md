# BLUEPRINT-MAPPING.md - Blueprint Parser & Mapping Logic

**Purpose**: Transforms user blueprints into complete, tier-aligned documentation systems with deterministic generation.  
**Version**: 1.0  
**Last Updated**: 2025-12-09  
**Design**: LLM-native, architecture-consistent, agent-friendly, cheap to run, generalizable  

---

## 🧠 Blueprint-to-Index Mapping Logic

### Overview
This system takes a user-provided blueprint and automatically produces:
- Documentation files aligned to tier requirements
- Tests based on testing strategy and examples  
- Folder structure from architecture patterns
- Code following framework specifications
- Missing sections with TODO markers

**Input**:
- Project blueprint (user-provided description/goals)
- `tier-index.yaml` (tier requirements and file mappings)
- Selected tier (MVP/Core/Full)
- Framework patterns (React, Node, Python, etc.)
- Universal documentation templates

**Output**:
- Complete repo with docs/tests/code aligned to tier and blueprint
- Consistency guarantee (passes validation script)

---

## 📋 Step 1: Blueprint Parsing Logic

### Blueprint Analysis Function
```python
def parse_blueprint(blueprint_text: str) -> Dict[str, Any]:
    """
    Parse user blueprint to extract project characteristics.
    
    Returns: Dict with project metadata and requirements
    """
    blueprint = {
        "project_type": detect_project_type(blueprint_text),
        "features": extract_features(blueprint_text),
        "architecture": extract_architecture(blueprint_text),
        "tech_stack": detect_tech_stack(blueprint_text),
        "framework": detect_framework(blueprint_text),
        "user_flows": extract_user_flows(blueprint_text),
        "data_models": extract_data_models(blueprint_text),
        "endpoints": extract_endpoints(blueprint_text),
        "components": extract_components(blueprint_text),
        "milestones": extract_milestones(blueprint_text),
        "timeline": extract_timeline(blueprint_text),
        "team_size": extract_team_size(blueprint_text),
        "business_requirements": extract_business_requirements(blueprint_text)
    }
    
    return blueprint

def detect_project_type(text: str) -> str:
    """Detect project type from blueprint keywords."""
    indicators = {
        "web": ["web app", "website", "frontend", "ui", "react", "vue", "angular"],
        "mobile": ["mobile app", "ios", "android", "flutter", "react native"],
        "api": ["api", "backend", "service", "rest", "graphql"],
        "cli": ["cli", "command line", "tool", "utility"],
        "library": ["library", "package", "sdk", "framework"]
    }
    
    for project_type, keywords in indicators.items():
        if any(keyword in text.lower() for keyword in keywords):
            return project_type
    
    return "web"  # Default

def extract_features(text: str) -> List[str]:
    """Extract feature list from blueprint."""
    features = []
    
    # Look for bullet points, numbered lists, or feature phrases
    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        if line.startswith(('-', '*', '•')) or re.match(r'^\d+\.', line):
            feature = line.lstrip('-*•0123456789. ').strip()
            if feature and len(feature) > 3:
                features.append(feature)
    
    return features

def extract_architecture(text: str) -> Dict[str, Any]:
    """Extract architecture patterns and structure."""
    architecture = {
        "type": "monolithic",  # Default
        "layers": [],
        "patterns": [],
        "folders": {}
    }
    
    # Detect architecture type
    if any(word in text.lower() for word in ["microservice", "microservices"]):
        architecture["type"] = "microservices"
    elif any(word in text.lower() for word in ["serverless", "lambda", "functions"]):
        architecture["type"] = "serverless"
    
    # Extract layers
    layer_keywords = ["frontend", "backend", "api", "database", "cache", "auth"]
    for keyword in layer_keywords:
        if keyword in text.lower():
            architecture["layers"].append(keyword)
    
    return architecture

def detect_tech_stack(text: str) -> Dict[str, str]:
    """Detect technology stack from blueprint."""
    stack = {}
    
    # Frontend detection
    frontend_map = {
        "react": ["react", "jsx", "tsx"],
        "vue": ["vue", "vuex"],
        "angular": ["angular", "typescript", "rxjs"],
        "flutter": ["flutter", "dart"],
        "swift": ["swift", "ios"],
        "kotlin": ["kotlin", "android"]
    }
    
    for tech, keywords in frontend_map.items():
        if any(keyword in text.lower() for keyword in keywords):
            stack["frontend"] = tech
            break
    
    # Backend detection
    backend_map = {
        "node": ["node", "express", "javascript"],
        "python": ["python", "django", "flask", "fastapi"],
        "java": ["java", "spring", "maven"],
        "dotnet": ["dotnet", "c#", "asp.net"],
        "go": ["go", "golang"]
    }
    
    for tech, keywords in backend_map.items():
        if any(keyword in text.lower() for keyword in keywords):
            stack["backend"] = tech
            break
    
    # Database detection
    db_map = {
        "postgresql": ["postgresql", "postgres"],
        "mysql": ["mysql"],
        "mongodb": ["mongodb", "mongo"],
        "sqlite": ["sqlite"],
        "redis": ["redis"]
    }
    
    for tech, keywords in db_map.items():
        if any(keyword in text.lower() for keyword in keywords):
            stack["database"] = tech
            break
    
    return stack
```

---

## 🎯 Step 2: Tier-Aware Generation Logic

### Load Tier and Filter Requirements
```python
def load_tier_requirements(tier: str) -> Dict[str, Any]:
    """Load tier requirements from tier-index.yaml."""
    with open("tier-index.yaml", 'r') as f:
        index = yaml.safe_load(f)
    
    tier_config = index["tiers"][tier.lower()]
    return {
        "required_files": tier_config["required"],
        "recommended_files": tier_config["recommended"],
        "ignored_files": tier_config.get("ignored", []),
        "coverage_target": tier_config["coverage_target"],
        "min_content_size": tier_config.get("min_file_size", 200)
    }

def filter_files_by_tier(all_templates: Dict[str, str], tier_requirements: Dict) -> Dict[str, str]:
    """Filter templates based on tier requirements."""
    filtered = {}
    
    for file_path, template_path in all_templates.items():
        if file_path in tier_requirements["required_files"]:
            filtered[file_path] = template_path
        elif file_path in tier_requirements["recommended_files"]:
            filtered[file_path] = template_path
    
    return filtered
```

### Generate Files with Tier-Specific Content
```python
def generate_file_content(file_name: str, blueprint: Dict, tier: str, templates: Dict) -> str:
    """Generate content for a specific file based on blueprint and tier."""
    
    # Get base template
    template_path = templates.get(file_name)
    if template_path and os.path.exists(template_path):
        with open(template_path, 'r') as f:
            content = f.read()
    else:
        content = generate_basic_template(file_name)
    
    # Apply tier-specific modifications
    content = apply_tier_modifications(content, tier, file_name)
    
    # Fill blueprint placeholders
    content = fill_blueprint_placeholders(content, blueprint, file_name)
    
    # Apply framework-specific patterns
    if blueprint.get("framework"):
        content = apply_framework_patterns(content, blueprint["framework"], file_name)
    
    return content

def apply_tier_modifications(content: str, tier: str, file_name: str) -> str:
    """Apply tier-specific content modifications."""
    
    if tier == "mvp":
        # Simplify content for MVP
        if file_name == "README.md":
            content = simplify_readme(content)
        elif file_name == "TESTING.md":
            content = simplify_testing(content)
        elif file_name == "ARCHITECTURE.md":
            content = simplify_architecture(content)
    
    elif tier == "core":
        # Standard production-ready content
        if file_name == "TESTING.md":
            content = add_coverage_requirements(content, "85%+")
        elif file_name == "TODO.md":
            content = add_phase_structure(content, ["Phase 1", "Phase 2"])
    
    elif tier == "full":
        # Enterprise-grade comprehensive content
        if file_name == "TESTING.md":
            content = add_comprehensive_testing(content)
        elif file_name == "TODO.md":
            content = add_phase_structure(content, ["Phase 1", "Phase 2", "Phase 3", "Phase 4"])
        elif file_name == "ARCHITECTURE.md":
            content = add_enterprise_architecture(content)
    
    return content

def fill_blueprint_placeholders(content: str, blueprint: Dict, file_name: str) -> str:
    """Replace placeholders with blueprint-specific content."""
    
    replacements = {
        "{PROJECT_NAME}": blueprint.get("project_name", "My Project"),
        "{PROJECT_DESCRIPTION}": blueprint.get("description", "Project description"),
        "{FRAMEWORK}": blueprint.get("framework", "Unknown"),
        "{TECH_STACK}": format_tech_stack(blueprint.get("tech_stack", {})),
        "{FEATURES}": format_features(blueprint.get("features", [])),
        "{ARCHITECTURE}": format_architecture(blueprint.get("architecture", {})),
        "{ENDPOINTS}": format_endpoints(blueprint.get("endpoints", [])),
        "{DATA_MODELS}": format_data_models(blueprint.get("data_models", [])),
        "{USER_FLOWS}": format_user_flows(blueprint.get("user_flows", [])),
        "{TIMELINE}": blueprint.get("timeline", "3 months"),
        "{TEAM_SIZE}": blueprint.get("team_size", "2 developers")
    }
    
    for placeholder, value in replacements.items():
        content = content.replace(placeholder, value)
    
    return content
```

---

## 🗺️ Step 3: Template Mapping System

### Machine-Parseable Mapping Table
```yaml
# blueprint-mapping.yaml - Compressed mapping for agents
mapping:
  README.md:
    source: [blueprint.summary, blueprint.features]
    template: "universal/README.md"
    generation_order: 1
    tier_variations:
      mvp: "brief overview (3-5 sections)"
      core: "standard overview (all sections)"
      full: "comprehensive overview (detailed sections)"
    placeholders: ["{PROJECT_NAME}", "{PROJECT_DESCRIPTION}", "{FEATURES}", "{TECH_STACK}"]
    
  ARCHITECTURE.md:
    source: [blueprint.architecture]
    template: "generated"  # No template, generate from scratch
    generation_order: 2
    tier_variations:
      mvp: "basic stack and folders"
      core: "detailed architecture with patterns"
      full: "enterprise architecture with ADRs"
    placeholders: ["{ARCHITECTURE}", "{TECH_STACK}", "{DATA_MODELS}"]
    
  TODO.md:
    source: [blueprint.features, blueprint.milestones]
    template: "examples/PROJECT-ROADMAP.md"
    generation_order: 3
    tier_variations:
      mvp: "simple checklist"
      core: "phase-based roadmap (Phase 1-2)"
      full: "comprehensive roadmap (Phase 1-4)"
    placeholders: ["{FEATURES}", "{MILESTONES}", "{TIMELINE}"]
    
  WORKFLOWS.md:
    source: [framework.patterns, blueprint.commands]
    template: "generated"
    generation_order: 4
    tier_variations:
      mvp: "basic commands"
      core: "development and deployment workflows"
      full: "complete workflows including governance"
    placeholders: ["{FRAMEWORK}", "{PROJECT_NAME}"]
    
  TESTING.md:
    source: [testing.strategy]
    template: "universal/TESTING-STRATEGY.md"
    generation_order: 5
    tier_variations:
      mvp: "smoke test plan"
      core: "full testing strategy (85%+ coverage)"
      full: "comprehensive testing doctrine (95%+ coverage)"
    placeholders: ["{FRAMEWORK}", "{COVERAGE_TARGET}"]
    
  TESTING-EXAMPLES.md:
    source: [testing.examples.framework]
    template: "examples/TESTING-EXAMPLES.md"
    generation_order: 6
    tier_variations:
      mvp: "not included"
      core: "framework-specific examples"
      full: "complete examples for all test types"
    placeholders: ["{FRAMEWORK}", "{TEST_TYPES}"]
    
  DOCUMENTATION-BLUEPRINT.md:
    source: [universal.docs]
    template: "universal/DOCUMENTATION-BLUEPRINT.md"
    generation_order: 7
    tier_variations:
      mvp: "not included"
      core: "project-specific (5-10 files)"
      full: "complete blueprint (all 20 files)"
    placeholders: ["{PROJECT_NAME}", "{TIER}"]
    
  API-DOCUMENTATION.md:
    source: [blueprint.api]
    template: "examples/API-DOCUMENTATION.md"
    generation_order: 8
    tier_variations:
      mvp: "brief endpoint list"
      core: "complete API documentation"
      full: "comprehensive API with auth, rate limiting"
    placeholders: ["{ENDPOINTS}", "{AUTH_METHOD}", "{DATA_MODELS}"]
    
  FRAMEWORK-PATTERNS.md:
    source: [framework.patterns]
    template: "examples/FRAMEWORK-PATTERNS.md"
    generation_order: 9
    tier_variations:
      mvp: "not included"
      core: "tech-specific architecture rules"
      full: "complete patterns with ADRs"
    placeholders: ["{FRAMEWORK}", "{ARCHITECTURE_TYPE}"]
    
  PROJECT-ROADMAP.md:
    source: [blueprint.milestones, blueprint.timeline]
    template: "examples/PROJECT-ROADMAP.md"
    generation_order: 10
    tier_variations:
      mvp: "not included (use TODO.md)"
      core: "Phase 1-2 with milestones"
      full: "Phase 1-4 with dependencies"
    placeholders: ["{MILESTONES}", "{TIMELINE}", "{FEATURES}"]
    
  INTEGRATION-GUIDE.md:
    source: [universal.integration]
    template: "universal/INTEGRATION-GUIDE.md"
    generation_order: 11
    tier_variations:
      mvp: "not included"
      core: "standard integration guide"
      full: "complete guide with advanced workflows"
    placeholders: ["{PROJECT_NAME}", "{TIER}"]
    
  AGENTS.md:
    source: [universal.agents]
    template: "universal/AGENTS.md"
    generation_order: 12
    tier_variations:
      mvp: "not included"
      core: "project-specific configuration"
      full: "comprehensive multi-agent setup"
    placeholders: ["{PROJECT_NAME}", "{FRAMEWORK}", "{TIER}"]
    
  QUICKSTART-AI.md:
    source: [universal.quickstart]
    template: "QUICKSTART-AI.md"
    generation_order: 13
    tier_variations:
      mvp: "not included"
      core: "project-specific quickstart"
      full: "enterprise quickstart with all features"
    placeholders: ["{PROJECT_NAME}", "{FRAMEWORK}", "{TIER}"]
    
  MIGRATION-GUIDE.md:
    source: [blueprint.migrations]
    template: "examples/MIGRATION-GUIDE.md"
    generation_order: 14
    tier_variations:
      mvp: "not included"
      core: "basic structure (even if empty)"
      full: "complete guide with scripts and examples"
    placeholders: ["{FRAMEWORK}", "{MIGRATION_STEPS}"]
    
  TESTING-STRATEGY.md:
    source: [testing.strategy.comprehensive]
    template: "universal/TESTING-STRATEGY.md"
    generation_order: 15
    tier_variations:
      mvp: "not included"
      core: "not included (use TESTING.md)"
      full: "comprehensive testing doctrine"
    placeholders: ["{TEST_TYPES}", "{COVERAGE_TARGET}", "{FRAMEWORK}"]
    
  DEPLOYMENT.md:
    source: [blueprint.deployment]
    template: "generated"
    generation_order: 16
    tier_variations:
      mvp: "not included"
      core: "not included"
      full: "complete deployment strategy"
    placeholders: ["{ENVIRONMENTS}", "{DEPLOYMENT_STEPS}"]
    
  SECURITY.md:
    source: [blueprint.security]
    template: "generated"
    generation_order: 17
    tier_variations:
      mvp: "not included"
      core: "not included"
      full: "comprehensive security documentation"
    placeholders: ["{AUTH_METHOD}", "{SECURITY_MEASURES}"]
    
  DATA-MODEL.md:
    source: [blueprint.data_models]
    template: "generated"
    generation_order: 18
    tier_variations:
      mvp: "not included"
      core: "not included"
      full: "complete data model documentation"
    placeholders: ["{DATA_MODELS}", "{RELATIONSHIPS}"]
    
  ANALYTICS.md:
    source: [blueprint.analytics]
    template: "generated"
    generation_order: 19
    tier_variations:
      mvp: "not included"
      core: "optional (if analytics needed)"
      full: "complete analytics implementation"
    placeholders: ["{ANALYTICS_EVENTS}", "{TRACKING_TOOLS}"]
    
  CONFIGURATION.md:
    source: [blueprint.configuration]
    template: "generated"
    generation_order: 20
    tier_variations:
      mvp: "not included"
      core: "optional (if multi-env needed)"
      full: "complete configuration management"
    placeholders: ["{ENVIRONMENTS}", "{CONFIG_VARS}"]
    
  LOCAL-DEV.md:
    source: [blueprint.local_dev]
    template: "generated"
    generation_order: 21
    tier_variations:
      mvp: "not included"
      core: "optional (if team onboarding)"
      full: "comprehensive developer setup"
    placeholders: ["{SETUP_STEPS}", "{PREREQUISITES}"]
    
  CI-CD.md:
    source: [blueprint.cicd]
    template: "generated"
    generation_order: 22
    tier_variations:
      mvp: "not included"
      core: "not included"
      full: "complete CI/CD pipeline"
    placeholders: ["{PIPELINE_STAGES}", "{QUALITY_GATES}"]

conditional_files:
  API-DESIGN.md:
    condition: "project_type == 'api' and tier == 'mvp'"
    template: "examples/API-DOCUMENTATION.md"
    source: [blueprint.api]
    
  UI-FLOW.md:
    condition: "project_type in ['web', 'mobile'] and tier == 'mvp'"
    template: "generated"
    source: [blueprint.user_flows]
```

### Bidirectional Mapping (Reverse Engineering)
```yaml
reverse_mapping:
  # From existing docs back to blueprint sections
  blueprint_sections:
    summary: ["README.md#overview", "README.md#purpose"]
    features: ["README.md#features", "TODO.md#features"]
    architecture: ["ARCHITECTURE.md", "FRAMEWORK-PATTERNS.md"]
    api: ["API-DOCUMENTATION.md", "API-DESIGN.md"]
    testing: ["TESTING.md", "TESTING-EXAMPLES.md", "TESTING-STRATEGY.md"]
    deployment: ["DEPLOYMENT.md", "CI-CD.md"]
    security: ["SECURITY.md"]
    data_models: ["DATA-MODEL.md", "API-DOCUMENTATION.md#schemas"]
    workflows: ["WORKFLOWS.md", "QUICKSTART-AI.md"]
    milestones: ["PROJECT-ROADMAP.md", "TODO.md"]
```

---

## ✅ Step 4: Validation Integration

### Auto-Validate Generated Content
```python
def validate_generated_content(tier: str, generated_files: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate generated content against tier requirements using VALIDATION.md logic.
    
    Returns: Validation report with compliance metrics
    """
    from validation import DocumentationValidator
    
    validator = DocumentationValidator()
    
    # Create temporary files for validation
    temp_dir = tempfile.mkdtemp()
    try:
        for file_path, content in generated_files.items():
            full_path = os.path.join(temp_dir, file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'w') as f:
                f.write(content)
        
        # Run validation
        validation_result = validator.validate(tier, temp_dir)
        
        return validation_result
        
    finally:
        shutil.rmtree(temp_dir)

def ensure_validation_pass(blueprint: Dict, tier: str, generated_files: Dict[str, str]) -> Dict[str, str]:
    """
    Generate content and ensure it passes validation, fixing issues automatically.
    
    Returns: Validated and fixed generated files
    """
    max_attempts = 3
    
    for attempt in range(max_attempts):
        # Validate current generation
        validation = validate_generated_content(tier, generated_files)
        
        if validation["report"]["status"] == "PASS":
            return generated_files
        
        # Fix identified issues
        generated_files = fix_validation_issues(generated_files, validation["suggestions"])
    
    # If still failing after max attempts, raise exception with details
    raise ValidationError(f"Failed to generate valid content after {max_attempts} attempts: {validation}")

def fix_validation_issues(generated_files: Dict[str, str], suggestions: List[Dict]) -> Dict[str, str]:
    """
    Apply automatic fixes based on validation suggestions.
    
    Returns: Updated generated files
    """
    for suggestion in suggestions:
        if suggestion["action"] == "GENERATE_FILE":
            file_name = suggestion["file"]
            if file_name not in generated_files:
                generated_files[file_name] = generate_minimal_content(file_name)
        
        elif suggestion["action"] == "EXPAND_FILE":
            file_name = suggestion["file"]
            if file_name in generated_files:
                current_content = generated_files[file_name]
                if len(current_content) < 200:
                    generated_files[file_name] = expand_content(current_content, file_name)
        
        elif suggestion["action"] == "UPDATE_FILE":
            file_name = suggestion["file"]
            if file_name in generated_files:
                generated_files[file_name] = update_content(generated_files[file_name], file_name)
    
    return generated_files
```

---

## 🚀 Step 5: Complete Implementation

### Blueprint Compiler Class
```python
#!/usr/bin/env python3
"""
Blueprint Compiler - Transforms blueprints into complete documentation systems
Usage: python3 blueprint_compiler.py --blueprint "project description" --tier core
"""

import yaml
import os
import sys
import argparse
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any

class BlueprintCompiler:
    def __init__(self, tier_index_path="tier-index.yaml", mapping_path="blueprint-mapping.yaml"):
        self.tier_index_path = tier_index_path
        self.mapping_path = mapping_path
        self.tier_index = None
        self.mapping = None
        
    def load_configuration(self):
        """Load tier index and mapping configuration."""
        with open(self.tier_index_path, 'r') as f:
            self.tier_index = yaml.safe_load(f)
        
        with open(self.mapping_path, 'r') as f:
            self.mapping = yaml.safe_load(f)
    
    def compile(self, blueprint_text: str, tier: str, output_dir: str = ".") -> Dict[str, Any]:
        """
        Compile blueprint into complete documentation system.
        
        Returns: Compilation result with generated files and validation report
        """
        # Load configuration
        self.load_configuration()
        
        # Parse blueprint
        blueprint = self.parse_blueprint(blueprint_text)
        
        # Select tier (using QUICKSTART-AI.md logic)
        selected_tier = self.select_tier(blueprint, tier)
        
        # Load tier requirements
        tier_requirements = self.load_tier_requirements(selected_tier)
        
        # Generate files in correct order
        generated_files = self.generate_all_files(blueprint, selected_tier, tier_requirements)
        
        # Validate and fix if needed
        validated_files = self.ensure_validation_pass(blueprint, selected_tier, generated_files)
        
        # Write files to disk
        self.write_files(validated_files, output_dir)
        
        # Generate final report
        report = self.generate_compilation_report(blueprint, selected_tier, validated_files)
        
        return report
    
    def parse_blueprint(self, blueprint_text: str) -> Dict[str, Any]:
        """Parse blueprint text into structured data."""
        # Implementation from Step 1
        return parse_blueprint(blueprint_text)
    
    def select_tier(self, blueprint: Dict, explicit_tier: str = None) -> str:
        """Select appropriate tier using QUICKSTART-AI.md logic."""
        if explicit_tier:
            return explicit_tier.lower()
        
        # Use tier selection algorithm
        from tier_selection import select_tier
        return select_tier(blueprint)
    
    def generate_all_files(self, blueprint: Dict, tier: str, tier_requirements: Dict) -> Dict[str, str]:
        """Generate all required files in correct order."""
        generated_files = {}
        
        # Get mapping for tier
        tier_mapping = self.get_tier_mapping(tier)
        
        # Generate files in dependency order
        for file_name in sorted(tier_mapping.keys(), key=lambda x: tier_mapping[x]["generation_order"]):
            if self.should_generate_file(file_name, tier_requirements, blueprint):
                content = self.generate_file_content(file_name, blueprint, tier, tier_mapping)
                generated_files[file_name] = content
        
        # Add conditional files
        conditional_files = self.get_conditional_files(blueprint, tier)
        for file_name, config in conditional_files.items():
            content = self.generate_file_content(file_name, blueprint, tier, config)
            generated_files[file_name] = content
        
        return generated_files
    
    def get_tier_mapping(self, tier: str) -> Dict[str, Dict]:
        """Get file mapping for specific tier."""
        tier_mapping = {}
        
        for file_name, config in self.mapping["mapping"].items():
            if self.is_file_in_tier(file_name, tier, config):
                tier_mapping[file_name] = config
        
        return tier_mapping
    
    def is_file_in_tier(self, file_name: str, tier: str, config: Dict) -> bool:
        """Check if file should be generated for given tier."""
        tier_variations = config.get("tier_variations", {})
        
        if tier not in tier_variations:
            return False
        
        variation = tier_variations[tier]
        if variation == "not included":
            return False
        
        return True
    
    def should_generate_file(self, file_name: str, tier_requirements: Dict, blueprint: Dict) -> bool:
        """Check if file should be generated based on requirements and blueprint."""
        # Check if in required files
        if file_name in tier_requirements["required_files"]:
            return True
        
        # Check if in recommended files and blueprint has relevant content
        if file_name in tier_requirements["recommended_files"]:
            return self.blueprint_has_relevant_content(blueprint, file_name)
        
        return False
    
    def blueprint_has_relevant_content(self, blueprint: Dict, file_name: str) -> bool:
        """Check if blueprint has content relevant to specific file."""
        relevance_map = {
            "API-DOCUMENTATION.md": ["endpoints"],
            "ANALYTICS.md": ["analytics"],
            "CONFIGURATION.md": ["environments"],
            "LOCAL-DEV.md": ["team_size"],
            "DEPLOYMENT.md": ["deployment"],
            "SECURITY.md": ["security"],
            "DATA-MODEL.md": ["data_models"]
        }
        
        relevant_keys = relevance_map.get(file_name, [])
        return any(blueprint.get(key) for key in relevant_keys)
    
    def generate_file_content(self, file_name: str, blueprint: Dict, tier: str, mapping_config: Dict) -> str:
        """Generate content for specific file."""
        # Get template path
        template_path = mapping_config.get("template")
        
        if template_path == "generated":
            content = self.generate_from_scratch(file_name, blueprint, tier)
        elif template_path and os.path.exists(template_path):
            with open(template_path, 'r') as f:
                content = f.read()
        else:
            content = self.generate_basic_template(file_name)
        
        # Apply tier modifications
        content = self.apply_tier_modifications(content, tier, file_name, mapping_config)
        
        # Fill placeholders
        content = self.fill_placeholders(content, blueprint, file_name)
        
        return content
    
    def write_files(self, files: Dict[str, str], output_dir: str):
        """Write generated files to disk."""
        output_path = Path(output_dir)
        
        for file_name, content in files.items():
            file_path = output_path / file_name
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w') as f:
                f.write(content)
    
    def generate_compilation_report(self, blueprint: Dict, tier: str, files: Dict[str, str]) -> Dict[str, Any]:
        """Generate final compilation report."""
        return {
            "blueprint": blueprint,
            "tier": tier,
            "files_generated": len(files),
            "file_list": list(files.keys()),
            "validation_status": "PASS",  # Should always pass after ensure_validation_pass
            "timestamp": time.time()
        }

def main():
    parser = argparse.ArgumentParser(description="Compile blueprint into documentation system")
    parser.add_argument("--blueprint", required=True, help="Project blueprint description")
    parser.add_argument("--tier", choices=["mvp", "core", "full"], help="Target tier (auto-detected if not specified)")
    parser.add_argument("--output", default=".", help="Output directory")
    parser.add_argument("--validate", action="store_true", help="Run validation after generation")
    
    args = parser.parse_args()
    
    try:
        compiler = BlueprintCompiler()
        result = compiler.compile(args.blueprint, args.tier, args.output)
        
        print(f"✅ Blueprint compilation complete!")
        print(f"📋 Tier: {result['tier'].upper()}")
        print(f"📄 Files generated: {result['files_generated']}")
        print(f"📁 Output directory: {args.output}")
        
        if args.validate:
            print(f"✅ Validation status: {result['validation_status']}")
        
    except Exception as e:
        print(f"❌ Compilation failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
```

---

## 🎯 Usage Examples

### For AI Agents
```python
# Simple usage
compiler = BlueprintCompiler()
result = compiler.compile(
    blueprint="React web app for task management with user authentication, real-time updates, and analytics dashboard",
    tier="core",
    output_dir="./my-project"
)

# With automatic tier detection
result = compiler.compile(
    blueprint="Mobile app for expense tracking with offline support and sync",
    tier=None,  # Auto-detect
    output_dir="./expense-app"
)
```

### For CLI Usage
```bash
# Basic compilation
python3 blueprint_compiler.py --blueprint "React dashboard for data visualization" --tier core

# Auto-detect tier
python3 blueprint_compiler.py --blueprint "Simple CLI tool for file conversion"

# Specify output directory
python3 blueprint_compiler.py --blueprint "Flutter app for meditation" --tier mvp --output ./meditation-app

# With validation
python3 blueprint_compiler.py --blueprint "Enterprise SaaS platform" --tier full --validate
```

---

## 🔧 Integration Points

### With QUICKSTART-AI.md
- Uses `select_tier()` function for automatic tier detection
- Respects human override through explicit tier parameter
- Applies tier-specific content variations

### With VALIDATION.md  
- Auto-validates generated content using validation logic
- Fixes issues automatically before final output
- Ensures 100% compliance with tier requirements

### With tier-index.yaml
- Sources file requirements and mappings
- Applies tier-specific filters and rules
- Maintains consistency across the system

---

**Performance**: O(n) where n = number of files to generate, typically < 30.  
**Reliability**: Deterministic generation with validation guarantees.  
**Extensibility**: Easy to add new file types, frameworks, or tiers.

---

*This blueprint compiler transforms user requirements into complete, validated documentation systems with perfect tier alignment.*
