"""
Blueprint Configuration Management
Centralized blueprint management for the Universal Template System
"""

import os
import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path

# Blueprint configuration paths
BLUEPRINTS_DIR = Path(__file__).parent.parent / "blueprints"

def get_available_blueprints() -> List[str]:
    """
    Get list of available blueprint IDs
    
    Returns:
        List of blueprint directory names
    """
    if not BLUEPRINTS_DIR.exists():
        return []
    
    blueprints = []
    for item in BLUEPRINTS_DIR.iterdir():
        if item.is_dir() and (item / "blueprint.meta.yaml").exists():
            blueprints.append(item.name)
    
    return sorted(blueprints)

def load_blueprint_metadata(blueprint_id: str) -> Optional[Dict[str, Any]]:
    """
    Load blueprint metadata from blueprint.meta.yaml
    
    Args:
        blueprint_id: The blueprint identifier
        
    Returns:
        Dictionary containing blueprint metadata or None if not found
    """
    meta_file = BLUEPRINTS_DIR / blueprint_id / "blueprint.meta.yaml"
    
    if not meta_file.exists():
        return None
    
    try:
        with open(meta_file, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading blueprint metadata for {blueprint_id}: {e}")
        return None

def get_blueprint_description(blueprint_id: str) -> str:
    """
    Get human-readable description of a blueprint
    
    Args:
        blueprint_id: The blueprint identifier
        
    Returns:
        Description string or error message
    """
    metadata = load_blueprint_metadata(blueprint_id)
    if not metadata:
        return f"Blueprint '{blueprint_id}' not found"
    
    return metadata.get('description', f"Blueprint: {blueprint_id}")

def get_supported_stacks(blueprint_id: str) -> Dict[str, List[str]]:
    """
    Get stack requirements for a blueprint
    
    Args:
        blueprint_id: The blueprint identifier
        
    Returns:
        Dictionary with 'required', 'recommended', 'supported' stack lists
    """
    metadata = load_blueprint_metadata(blueprint_id)
    if not metadata:
        return {'required': [], 'recommended': [], 'supported': []}
    
    stacks = metadata.get('stacks', {})
    return {
        'required': stacks.get('required', []),
        'recommended': stacks.get('recommended', []),
        'supported': stacks.get('supported', [])
    }

def get_tier_defaults(blueprint_id: str) -> Dict[str, str]:
    """
    Get tier defaults for a blueprint
    
    Args:
        blueprint_id: The blueprint identifier
        
    Returns:
        Dictionary with tier defaults
    """
    metadata = load_blueprint_metadata(blueprint_id)
    if not metadata:
        return {'overall': 'core', 'frontend': 'mvp', 'backend': 'core'}
    
    return metadata.get('tier_defaults', {'overall': 'core', 'frontend': 'mvp', 'backend': 'core'})

def get_task_configuration(blueprint_id: str) -> Dict[str, List[str]]:
    """
    Get task configuration for a blueprint
    
    Args:
        blueprint_id: The blueprint identifier
        
    Returns:
        Dictionary with 'required', 'recommended', 'optional' task lists
    """
    metadata = load_blueprint_metadata(blueprint_id)
    if not metadata:
        return {'required': [], 'recommended': [], 'optional': []}
    
    tasks = metadata.get('tasks', {})
    return {
        'required': tasks.get('required', []),
        'recommended': tasks.get('recommended', []),
        'optional': tasks.get('optional', [])
    }

def get_blueprint_constraints(blueprint_id: str) -> Dict[str, Any]:
    """
    Get constraints and invariants for a blueprint
    
    Args:
        blueprint_id: The blueprint identifier
        
    Returns:
        Dictionary containing blueprint constraints
    """
    metadata = load_blueprint_metadata(blueprint_id)
    if not metadata:
        return {}
    
    return metadata.get('constraints', {})

def get_blueprint_overlays(blueprint_id: str) -> Dict[str, Dict[str, Any]]:
    """
    Get overlay configuration for a blueprint
    
    Args:
        blueprint_id: The blueprint identifier
        
    Returns:
        Dictionary mapping stack names to overlay configurations
    """
    metadata = load_blueprint_metadata(blueprint_id)
    if not metadata:
        return {}
    
    return metadata.get('overlays', {})

def get_llm_hints(blueprint_id: str) -> Dict[str, Any]:
    """
    Get LLM hints for a blueprint
    
    Args:
        blueprint_id: The blueprint identifier
        
    Returns:
        Dictionary containing LLM prompts and keywords
    """
    metadata = load_blueprint_metadata(blueprint_id)
    if not metadata:
        return {}
    
    return metadata.get('llm', {})

def validate_blueprint(blueprint_id: str) -> List[str]:
    """
    Validate blueprint configuration
    
    Args:
        blueprint_id: The blueprint identifier
        
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    # Check blueprint directory exists
    blueprint_dir = BLUEPRINTS_DIR / blueprint_id
    if not blueprint_dir.exists():
        errors.append(f"Blueprint directory not found: {blueprint_dir}")
        return errors
    
    # Check required files exist
    required_files = [
        "BLUEPRINT.md",
        "blueprint.meta.yaml"
    ]
    
    for file_name in required_files:
        if not (blueprint_dir / file_name).exists():
            errors.append(f"Required file missing: {file_name}")
    
    # Validate metadata structure
    metadata = load_blueprint_metadata(blueprint_id)
    if metadata:
        # Check required fields
        required_fields = ['id', 'version', 'name', 'type']
        for field in required_fields:
            if field not in metadata:
                errors.append(f"Required metadata field missing: {field}")
        
        # Validate stacks configuration
        stacks = metadata.get('stacks', {})
        if 'required' not in stacks:
            errors.append("Stacks configuration missing 'required' field")
        
        # Validate tasks configuration
        tasks = metadata.get('tasks', {})
        task_categories = ['required', 'recommended', 'optional']
        for category in task_categories:
            if category not in tasks:
                errors.append(f"Tasks configuration missing '{category}' field")
    
    return errors

def get_blueprint_summary(blueprint_id: str) -> Dict[str, Any]:
    """
    Get a comprehensive summary of a blueprint
    
    Args:
        blueprint_id: The blueprint identifier
        
    Returns:
        Dictionary containing blueprint summary
    """
    metadata = load_blueprint_metadata(blueprint_id)
    if not metadata:
        return {'error': f"Blueprint '{blueprint_id}' not found"}
    
    return {
        'id': metadata.get('id'),
        'name': metadata.get('name'),
        'category': metadata.get('category'),
        'type': metadata.get('type'),
        'description': metadata.get('description'),
        'stacks': get_supported_stacks(blueprint_id),
        'tier_defaults': get_tier_defaults(blueprint_id),
        'tasks': get_task_configuration(blueprint_id),
        'constraints': get_blueprint_constraints(blueprint_id),
        'validation_errors': validate_blueprint(blueprint_id)
    }

# Convenience function for common operations
def list_blueprints_with_summaries() -> Dict[str, Dict[str, Any]]:
    """
    Get all available blueprints with their summaries
    
    Returns:
        Dictionary mapping blueprint IDs to their summaries
    """
    blueprints = {}
    for blueprint_id in get_available_blueprints():
        blueprints[blueprint_id] = get_blueprint_summary(blueprint_id)
    
    return blueprints

if __name__ == "__main__":
    # Test blueprint configuration
    print("Available Blueprints:")
    for blueprint_id in get_available_blueprints():
        summary = get_blueprint_summary(blueprint_id)
        print(f"  {blueprint_id}: {summary.get('name', 'Unknown')}")
        if summary.get('validation_errors'):
            print(f"    Errors: {summary['validation_errors']}")
