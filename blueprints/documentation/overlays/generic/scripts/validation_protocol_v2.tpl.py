#!/usr/bin/env python3
"""
Validation Protocol v2 - Self-Healing Auto-Repair Reasoning Loop
Implements the 8-step validation protocol from docs/platform-engineering/VALIDATION-PROTOCOL-v2.md
Usage: python3 scripts/validation_protocol_v2.py --tier core [--blueprint blueprint.yaml]
"""

import yaml
import os
import sys
import json
import glob
import argparse
from pathlib import Path
from typing import Dict, List, Any, Tuple

class ValidationProtocolV2:
    def __init__(self, tier_index_path="tier-index.yaml"):
        self.tier_index_path = tier_index_path
        self.tier_config = None
        
    def run_validation_protocol(self, blueprint: Dict, tier: str, repo_path: str = ".") -> Dict[str, Any]:
        """Execute complete 8-step validation protocol."""
        
        # Step 1: Load tier requirements
        print("[AI] Step 1: Loading tier index...")
        self.tier_config = self.load_tier_index(tier)
        
        # Step 2: Scan repository
        print("[AI] Step 2: Scanning repository...")
        repo_files = self.scan_repo(repo_path)
        
        # Step 3: Validate structure
        print("[AI] Step 3: Validating structure...")
        repair_list, rewrite_list, suggest_list = self.validate_structure(self.tier_config, repo_files)
        
        # Step 4: Document parity check
        print("[AI] Step 4: Checking document parity...")
        update_list = self.check_parity(blueprint, repo_files)
        
        # Step 5: Auto-repair loop
        print("[AI] Step 5: Running auto-repair...")
        self.execute_repairs(repair_list, rewrite_list, update_list, blueprint, tier)
        
        # Step 6: Testing parity check
        print("[AI] Step 6: Checking testing parity...")
        missing_docs, missing_tests = self.check_testing_parity(repo_files)
        
        # Step 7: Output report
        print("[AI] Step 7: Generating report...")
        report = self.generate_report(repair_list, rewrite_list, update_list, suggest_list, missing_docs, missing_tests)
        
        # Step 8: Confirmation pass
        print("[AI] Step 8: Running confirmation pass...")
        final_result = self.confirmation_pass(tier, repo_path)
        
        return {
            "protocol_version": "v2.0",
            "status": final_result["status"],
            "report": report,
            "final_validation": final_result
        }
    
    def load_tier_index(self, tier: str) -> Dict[str, Any]:
        """Load tier requirements from index."""
        try:
            with open(self.tier_index_path, 'r') as f:
                index = yaml.safe_load(f)
            
            tier_key = tier.lower()
            if tier_key not in index["tiers"]:
                raise ValueError(f"Invalid tier: {tier}")
            
            return index["tiers"][tier_key]
        except FileNotFoundError:
            raise FileNotFoundError(f"Tier index not found: {self.tier_index_path}")
    
    def scan_repo(self, repo_path: str) -> Dict[str, Dict[str, Any]]:
        """Scan repository for documentation files."""
        repo_files = {}
        base_path = Path(repo_path)
        
        # Scan docs directory and root for markdown files
        patterns = ["docs/*.md", "*.md"]
        
        for pattern in patterns:
            for file_path in base_path.glob(pattern):
                if file_path.is_file():
                    rel_path = str(file_path.relative_to(base_path))
                    
                    # Skip _templates directory
                    if "_templates" in rel_path:
                        continue
                    
                    stat = file_path.stat()
                    repo_files[rel_path] = {
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                        "path": str(file_path)
                    }
        
        return repo_files
    
    def validate_structure(self, tier_config: Dict, repo_files: Dict) -> Tuple[List[str], List[str], List[str]]:
        """Validate required files exist and meet standards."""
        repair_list = []
        rewrite_list = []
        suggest_list = []
        
        required_files = tier_config.get("required", [])
        recommended_files = tier_config.get("recommended", [])
        min_file_size = tier_config.get("min_file_size", 200)
        
        # Check required files
        for req_file in required_files:
            if req_file not in repo_files:
                repair_list.append(req_file)
            else:
                file_info = repo_files[req_file]
                if file_info["size"] < min_file_size:
                    rewrite_list.append(req_file)
        
        # Check recommended files
        for rec_file in recommended_files:
            if rec_file not in repo_files:
                suggest_list.append(rec_file)
        
        return repair_list, rewrite_list, suggest_list
    
    def check_parity(self, blueprint: Dict, repo_files: Dict) -> List[str]:
        """Check blueprint vs documentation parity."""
        update_list = []
        
        # Check features vs TODO.md
        if "TODO.md" in repo_files and "features" in blueprint:
            doc_features = self.parse_todo_features(repo_files["TODO.md"]["path"])
            blueprint_features = set(blueprint.get("features", []))
            
            if doc_features != blueprint_features:
                update_list.append("TODO.md")
        
        # Check endpoints vs API-DOCUMENTATION.md
        if "API-DOCUMENTATION.md" in repo_files and "endpoints" in blueprint:
            doc_endpoints = self.parse_api_endpoints(repo_files["API-DOCUMENTATION.md"]["path"])
            blueprint_endpoints = set(blueprint.get("endpoints", []))
            
            if doc_endpoints != blueprint_endpoints:
                update_list.append("API-DOCUMENTATION.md")
        
        return update_list
    
    def parse_todo_features(self, todo_path: str) -> set:
        """Extract features from TODO.md."""
        try:
            with open(todo_path, 'r') as f:
                content = f.read()
            
            features = set()
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('- [ ]') or line.startswith('* [ ]'):
                    feature = line.replace('- [ ]', '').replace('* [ ]', '').strip()
                    if feature:
                        features.add(feature)
            
            return features
        except:
            return set()
    
    def parse_api_endpoints(self, api_path: str) -> set:
        """Extract endpoints from API-DOCUMENTATION.md."""
        try:
            with open(api_path, 'r') as f:
                content = f.read()
            
            endpoints = set()
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ')):
                    endpoint = line.split(' ', 1)[1].strip()
                    if endpoint:
                        endpoints.add(endpoint)
            
            return endpoints
        except:
            return set()
    
    def execute_repairs(self, repair_list: List[str], rewrite_list: List[str], update_list: List[str], 
                       blueprint: Dict, tier: str):
        """Execute auto-repair operations."""
        
        # Repair missing files
        for file_name in repair_list:
            print(f"  🔧 Repairing missing file: {file_name}")
            self.generate_file_from_template(file_name, blueprint, tier)
        
        # Rewrite incomplete files
        for file_name in rewrite_list:
            print(f"  🔄 Rewriting incomplete file: {file_name}")
            self.generate_file_from_template(file_name, blueprint, tier)
        
        # Update parity issues
        for file_name in update_list:
            print(f"  📝 Updating parity issue: {file_name}")
            self.update_file_parity(file_name, blueprint)
    
    def generate_file_from_template(self, file_name: str, blueprint: Dict, tier: str):
        """Generate file from tier template."""
        # Load tier templates
        template_path = "TIERED-TEMPLATES.md"
        if not os.path.exists(template_path):
            print(f"  ⚠️  Template file not found: {template_path}")
            return
        
        with open(template_path, 'r') as f:
            templates_content = f.read()
        
        # Find appropriate template
        tier_section = f"## 🟩 MVP TIER" if tier == "mvp" else \
                      f"## 🟦 CORE TIER" if tier == "core" else \
                      f"## 🟧 FULL TIER"
        
        # Simple template extraction (in production, use proper parsing)
        template_start = templates_content.find(tier_section)
        if template_start == -1:
            print(f"  ⚠️  Tier template not found: {tier}")
            return
        
        template_section = templates_content[template_start:]
        next_tier_start = template_section.find("## 🟦") if tier == "mvp" else \
                         template_section.find("## 🟧") if tier == "core" else -1
        
        if next_tier_start != -1:
            template_section = template_section[:next_tier_start]
        
        # Find specific file template
        file_marker = f"### {file_name}"
        file_start = template_section.find(file_marker)
        if file_start == -1:
            print(f"  ⚠️  File template not found: {file_name}")
            return
        
        file_template = template_section[file_start:]
        next_file_start = file_template.find("\n### ")
        if next_file_start != -1:
            file_template = file_template[:next_file_start]
        
        # Extract markdown content
        lines = file_template.split('\n')
        if lines and lines[0].startswith(f"### {file_name}"):
            lines = lines[1:]  # Remove header
        
        # Remove leading ```markdown and ``` if present
        if lines and lines[0].strip() == "```markdown":
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        
        content = '\n'.join(lines).strip()
        
        # Fill placeholders
        content = self.fill_placeholders(content, blueprint)
        
        # Write file
        os.makedirs(os.path.dirname(file_name), exist_ok=True)
        with open(file_name, 'w') as f:
            f.write(content)
        
        print(f"  ✅ Generated: {file_name}")
    
    def fill_placeholders(self, content: str, blueprint: Dict) -> str:
        """Fill template placeholders with blueprint data."""
        replacements = {
            "{PROJECT_NAME}": blueprint.get("project_name", "My Project"),
            "{PROJECT_DESCRIPTION}": blueprint.get("description", "Project description"),
            "{FRAMEWORK}": blueprint.get("framework", "Unknown"),
            "{FEATURES}": self.format_features(blueprint.get("features", [])),
            "{ARCHITECTURE}": blueprint.get("architecture", "Architecture details"),
            "{DATA_MODELS}": blueprint.get("data_models", "Data models"),
            "{ENDPOINTS}": self.format_endpoints(blueprint.get("endpoints", [])),
            "{TIMELINE}": blueprint.get("timeline", "3 months"),
            "{TEAM_SIZE}": blueprint.get("team_size", "2 developers")
        }
        
        for placeholder, value in replacements.items():
            content = content.replace(placeholder, value)
        
        return content
    
    def format_features(self, features: List[str]) -> str:
        """Format features list for template."""
        if not features:
            return "- Feature 1\n- Feature 2\n- Feature 3"
        return '\n'.join(f"- {feature}" for feature in features)
    
    def format_endpoints(self, endpoints: List[str]) -> str:
        """Format endpoints list for template."""
        if not endpoints:
            return "GET /api/example"
        return '\n'.join(endpoints)
    
    def update_file_parity(self, file_name: str, blueprint: Dict):
        """Update file to match blueprint parity."""
        # For now, regenerate the file
        # In production, this would do more intelligent diff-based updates
        tier = blueprint.get("tier", "core")
        self.generate_file_from_template(file_name, blueprint, tier)
    
    def check_testing_parity(self, repo_files: Dict) -> Tuple[List[str], List[str]]:
        """Check testing vs documentation parity."""
        missing_docs = []
        missing_tests = []
        
        # Simplified implementation
        # In production, this would parse actual test files
        
        return missing_docs, missing_tests
    
    def generate_report(self, repair_list: List[str], rewrite_list: List[str], update_list: List[str],
                       suggest_list: List[str], missing_docs: List[str], missing_tests: List[str]) -> Dict[str, Any]:
        """Generate validation report."""
        return {
            "missing_docs_created": len(repair_list),
            "outdated_docs_fixed": len(rewrite_list),
            "inconsistencies_resolved": len(update_list),
            "recommended_docs_suggested": len(suggest_list),
            "testing_parity_issues": len(missing_docs) + len(missing_tests),
            "files_processed": {
                "repaired": repair_list,
                "rewritten": rewrite_list,
                "updated": update_list,
                "suggested": suggest_list
            }
        }
    
    def confirmation_pass(self, tier: str, repo_path: str) -> Dict[str, Any]:
        """Re-run validation to confirm consistency."""
        print("  🔍 Running confirmation validation...")
        
        # Re-scan and validate
        repo_files = self.scan_repo(repo_path)
        repair_list, rewrite_list, suggest_list = self.validate_structure(self.tier_config, repo_files)
        
        if not repair_list and not rewrite_list:
            return {"status": "SUCCESS", "message": "All validation checks passed"}
        else:
            return {
                "status": "REQUIRES_HUMAN", 
                "message": "Validation still has issues",
                "remaining_issues": repair_list + rewrite_list
            }

def load_blueprint(blueprint_path: str) -> Dict[str, Any]:
    """Load blueprint from file."""
    try:
        with open(blueprint_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        # Return minimal blueprint if file not found
        return {
            "project_name": "My Project",
            "description": "Auto-generated project",
            "features": ["Feature 1", "Feature 2"],
            "framework": "Unknown",
            "tier": "core"
        }

def main():
    parser = argparse.ArgumentParser(description="Validation Protocol v2 - Self-Healing Auto-Repair")
    parser.add_argument("--tier", required=True, choices=["mvp", "core", "full"], help="Target tier")
    parser.add_argument("--blueprint", default="blueprint.yaml", help="Blueprint file path")
    parser.add_argument("--path", default=".", help="Repository path")
    parser.add_argument("--json", action="store_true", help="JSON output")
    
    args = parser.parse_args()
    
    try:
        # Load blueprint
        blueprint = load_blueprint(args.blueprint)
        blueprint["tier"] = args.tier
        
        # Run validation protocol
        protocol = ValidationProtocolV2()
        result = protocol.run_validation_protocol(blueprint, args.tier, args.path)
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("\n=== VALIDATION PROTOCOL v2 REPORT ===")
            print(f"Status: {result['status']}")
            print(f"Missing docs created: {result['report']['missing_docs_created']}")
            print(f"Outdated docs fixed: {result['report']['outdated_docs_fixed']}")
            print(f"Inconsistencies resolved: {result['report']['inconsistencies_resolved']}")
            print(f"Recommended docs suggested: {result['report']['recommended_docs_suggested']}")
            
            if result['status'] == "SUCCESS":
                print("\n✅ Validation protocol completed successfully")
            else:
                print(f"\n⚠️  Validation requires human intervention")
                print(f"Issues: {result['final_validation']['remaining_issues']}")
        
        # Exit with appropriate code
        sys.exit(0 if result["status"] == "SUCCESS" else 1)
        
    except Exception as e:
        print(f"Validation protocol error: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
