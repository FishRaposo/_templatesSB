"""
Template Metadata Schema
Pydantic models for validating template manifests across the Universal Template System
"""

import json
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
from pydantic import BaseModel, Field, field_validator, ConfigDict


class TemplateMetadata(BaseModel):
    """
    Base template metadata model
    Conservative schema allowing extra fields for gradual migration
    """
    model_config = ConfigDict(extra='allow')
    
    id: str = Field(..., description="Unique identifier for the template")
    name: str = Field(..., description="Human-readable template name")
    description: str = Field(..., description="Template description")
    version: str = Field(..., description="Semantic version (e.g., '1.0.0')")
    language: Union[str, List[str]] = Field(..., description="Programming language(s)")
    
    # Optional fields
    tags: Optional[List[str]] = Field(None, description="Categorization tags")
    authors: Optional[List[str]] = Field(None, description="Template authors")
    license: Optional[str] = Field(None, description="License identifier")
    example_projects: Optional[List[str]] = Field(None, description="Example project references")
    
    @field_validator('version')
    @classmethod
    def validate_version(cls, v: str) -> str:
        """Validate semantic versioning format (lenient)"""
        if not v or not any(c.isdigit() for c in v):
            raise ValueError(f"Version must contain at least one digit: {v}")
        return v
    
    @field_validator('language')
    @classmethod
    def validate_language(cls, v: Union[str, List[str]]) -> Union[str, List[str]]:
        """Ensure language is not empty"""
        if isinstance(v, list) and not v:
            raise ValueError("Language list cannot be empty")
        if isinstance(v, str) and not v.strip():
            raise ValueError("Language string cannot be empty")
        return v


class BlueprintMetadata(BaseModel):
    """
    Blueprint metadata model for product archetype definitions
    Based on existing blueprint.meta.yaml structure
    """
    model_config = ConfigDict(extra='allow')
    
    id: str = Field(..., description="Unique blueprint identifier")
    name: str = Field(..., description="Blueprint display name")
    version: int = Field(..., description="Blueprint version number")
    category: str = Field(..., description="Blueprint category")
    description: str = Field(..., description="Blueprint description")
    type: str = Field(..., description="Product type (app, pipeline, api, etc.)")
    
    # Stack configuration
    stacks: Optional[Dict[str, List[str]]] = Field(None, description="Stack requirements")
    
    # Tier defaults
    tier_defaults: Optional[Dict[str, str]] = Field(None, description="Default tier settings")
    
    # Task configuration
    tasks: Optional[Dict[str, List[str]]] = Field(None, description="Task requirements")
    
    # Constraints
    constraints: Optional[Dict[str, Any]] = Field(None, description="Blueprint constraints")
    
    # Overlays
    overlays: Optional[Dict[str, Dict[str, Any]]] = Field(None, description="Stack-specific overlays")
    
    # Hooks
    hooks: Optional[Dict[str, List[str]]] = Field(None, description="Lifecycle hooks")
    
    # LLM hints
    llm: Optional[Dict[str, Any]] = Field(None, description="LLM generation hints")
    
    @field_validator('version')
    @classmethod
    def validate_version(cls, v: int) -> int:
        """Ensure version is positive"""
        if v < 1:
            raise ValueError(f"Version must be >= 1: {v}")
        return v
    
    @field_validator('type')
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate product type"""
        valid_types = ["app", "pipeline", "api", "agent_system", "dashboard"]
        if v not in valid_types:
            # Allow unknown types with warning (for future extensibility)
            pass
        return v


class TaskMetadata(BaseModel):
    """
    Task metadata model for the 46-task library
    Conservative schema based on task-index.yaml structure
    """
    model_config = ConfigDict(extra='allow')
    
    id: str = Field(..., description="Unique task identifier")
    name: str = Field(..., description="Task display name")
    description: str = Field(..., description="Task description")
    category: str = Field(..., description="Task category")
    
    # Optional fields
    languages: Optional[List[str]] = Field(None, description="Supported languages")
    stacks: Optional[List[str]] = Field(None, description="Supported stacks")
    tiers: Optional[List[str]] = Field(None, description="Supported tiers")
    dependencies: Optional[List[str]] = Field(None, description="Task dependencies")
    tags: Optional[List[str]] = Field(None, description="Categorization tags")
    
    @field_validator('category')
    @classmethod
    def validate_category(cls, v: str) -> str:
        """Ensure category is not empty"""
        if not v or not v.strip():
            raise ValueError("Category cannot be empty")
        return v


def export_json_schema(output_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Export JSON Schema for all template metadata models
    
    Args:
        output_path: Optional path to write JSON schema file
        
    Returns:
        Dictionary containing JSON schemas for all models
    """
    schemas = {
        "TemplateMetadata": TemplateMetadata.model_json_schema(),
        "BlueprintMetadata": BlueprintMetadata.model_json_schema(),
        "TaskMetadata": TaskMetadata.model_json_schema(),
    }
    
    combined_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Universal Template System Metadata Schemas",
        "version": "1.0.0",
        "description": "JSON Schema definitions for template system metadata validation",
        "schemas": schemas
    }
    
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(combined_schema, f, indent=2)
        print(f"JSON Schema exported to: {output_path}")
    
    return combined_schema


if __name__ == "__main__":
    # Export schema when run directly
    schema_path = Path(__file__).parent / "template_schema.json"
    export_json_schema(schema_path)
