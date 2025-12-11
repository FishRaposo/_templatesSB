#!/usr/bin/env python3
"""
Dynamic Tier Configuration Parser
Eliminates manual sync between tier-index.yaml and QUICKSTART-AI.md
"""

import yaml
import sys
import os
from pathlib import Path

def load_tier_config(tier_name: str, templates_dir: str = None) -> dict:
    """
    Load tier configuration from tier-index.yaml
    
    Args:
        tier_name: The tier to load (mvp, core, full)
        templates_dir: Directory containing tier-index.yaml (auto-detected if None)
    
    Returns:
        Dictionary with tier configuration
    """
    try:
        # Auto-detect tier-index.yaml location
        if templates_dir is None:
            # Check current directory first (for calls from project root)
            if Path("tier-index.yaml").exists():
                tier_index_path = Path("tier-index.yaml")
            else:
                # Fall back to script-relative path (for calls from scripts/)
                tier_index_path = Path(__file__).parent.parent / "tier-index.yaml"
        else:
            tier_index_path = Path(templates_dir) / "tier-index.yaml"
        
        if not tier_index_path.exists():
            raise FileNotFoundError(f"tier-index.yaml not found at {tier_index_path}")
        
        with open(tier_index_path, 'r') as f:
            config = yaml.safe_load(f)
        
        tier_config = config["tiers"].get(tier_name.lower())
        
        if not tier_config:
            raise ValueError(f"Tier '{tier_name}' not found in tier-index.yaml")
        
        return {
            "required": tier_config.get("required", []),
            "recommended": tier_config.get("recommended", []),
            "ignored": tier_config.get("ignored", []),
            "coverage_target": tier_config.get("coverage_target", ""),
            "setup_time": tier_config.get("setup_time", ""),
            "name": tier_config.get("name", ""),
            "purpose": tier_config.get("purpose", ""),
            "llm_goal": tier_config.get("llm_goal", "")
        }
    
    except Exception as e:
        print(f"Error loading tier config: {e}", file=sys.stderr)
        sys.exit(1)

def get_tier_requirements(tier_name: str, format: str = "bash") -> str:
    """
    Get tier requirements in specified format
    
    Args:
        tier_name: The tier to load
        format: Output format (bash, json, yaml)
    
    Returns:
        Formatted string of tier requirements
    """
    config = load_tier_config(tier_name)
    
    if format == "bash":
        required_files = ' '.join([f'"{f}"' for f in config["required"]])
        recommended_files = ' '.join([f'"{f}"' for f in config["recommended"]])
        
        return f'''
REQUIRED_FILES=({required_files})
RECOMMENDED_FILES=({recommended_files})
COVERAGE_TARGET="{config["coverage_target"]}"
SETUP_TIME="{config["setup_time"]}"
TIER_NAME="{config["name"]}"
TIER_PURPOSE="{config["purpose"]}"
'''
    
    elif format == "json":
        import json
        return json.dumps(config, indent=2)
    
    elif format == "yaml":
        return yaml.dump(config, default_flow_style=False)
    
    else:
        raise ValueError(f"Unsupported format: {format}")

def validate_template_availability(tier_name: str, templates_dir: str = "_templates") -> dict:
    """
    Validate that all required templates exist
    
    Args:
        tier_name: The tier to validate
        templates_dir: Directory containing templates
    
    Returns:
        Dictionary with validation results
    """
    config = load_tier_config(tier_name, templates_dir)
    templates_path = Path(templates_dir)
    
    validation_results = {
        "tier": tier_name,
        "required_files": {},
        "recommended_files": {},
        "missing_templates": [],
        "available_templates": []
    }
    
    # Check required files
    for file_name in config["required"]:
        file_path = find_template_path(file_name, templates_path)
        if file_path:
            validation_results["required_files"][file_name] = {"found": True, "path": str(file_path)}
            validation_results["available_templates"].append(str(file_path))
        else:
            validation_results["required_files"][file_name] = {"found": False, "path": None}
            validation_results["missing_templates"].append(file_name)
    
    # Check recommended files
    for file_name in config["recommended"]:
        file_path = find_template_path(file_name, templates_path)
        if file_path:
            validation_results["recommended_files"][file_name] = {"found": True, "path": str(file_path)}
        else:
            validation_results["recommended_files"][file_name] = {"found": False, "path": None}
            validation_results["missing_templates"].append(file_name)
    
    return validation_results

def find_template_path(file_name: str, templates_dir: Path) -> Path:
    """
    Find template file in universal/ or examples/ directories
    
    Args:
        file_name: Name of the template file
        templates_dir: Root templates directory
    
    Returns:
        Path to the template file or None if not found
    """
    # Check universal/ directory
    universal_path = templates_dir / "universal" / file_name
    if universal_path.exists():
        return universal_path
    
    # Check examples/ directory
    examples_path = templates_dir / "examples" / file_name
    if examples_path.exists():
        return examples_path
    
    # Check root directory (for QUICKSTART-AI.md, etc.)
    root_path = templates_dir / file_name
    if root_path.exists():
        return root_path
    
    return None

def main():
    """CLI interface for tier configuration"""
    if len(sys.argv) < 2:
        print("Usage: python3 tier_config.py <tier> [format] [templates_dir]")
        print("Tiers: mvp, core, full")
        print("Formats: bash, json, yaml (default: bash)")
        sys.exit(1)
    
    tier_name = sys.argv[1]
    format_type = sys.argv[2] if len(sys.argv) > 2 else "bash"
    templates_dir = sys.argv[3] if len(sys.argv) > 3 else "_templates"
    
    try:
        result = get_tier_requirements(tier_name, format_type)
        print(result)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
