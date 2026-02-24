"""
Blueprint Resolution System
Handles merging of blueprint + stack + tier + tasks into an intermediate representation
"""

import yaml
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from pathlib import Path

# Import existing configuration systems
from stack_config import get_all_stacks, get_all_tiers
from blueprint_config import (
    load_blueprint_metadata,
    get_supported_stacks,
    get_tier_defaults,
    get_task_configuration,
    get_blueprint_constraints,
    get_blueprint_overlays,
    get_llm_hints
)

@dataclass
class ProjectSpecification:
    """Input project specification from user/UI"""
    name: str
    blueprint: str
    stacks: Dict[str, str]  # layer -> stack mapping (e.g., {"frontend": "flutter", "backend": "python"})
    tier: Optional[Dict[str, str]] = None  # layer -> tier mapping
    tasks: Optional[Dict[str, List[str]]] = None  # category -> task list
    description: str = ""

@dataclass
class IntermediateRepresentation:
    """Internal representation after blueprint resolution"""
    blueprint: str
    name: str
    description: str
    stacks: List[str]
    tiers: Dict[str, str]  # stack -> tier mapping
    tasks: Dict[str, List[str]]  # category -> task mapping
    constraints: Dict[str, Any]
    overlays: Dict[str, Dict[str, Any]]
    llm_hints: Dict[str, Any]
    metadata: Dict[str, Any]

class BlueprintResolver:
    """Handles blueprint resolution according to the 7-step algorithm"""
    
    def __init__(self):
        self.available_stacks = get_all_stacks()
        self.available_tiers = get_all_tiers()
    
    def resolve(self, project_spec: ProjectSpecification) -> IntermediateRepresentation:
        """
        Main resolution method - executes the 7-step algorithm
        
        Args:
            project_spec: User-provided project specification
            
        Returns:
            Intermediate representation ready for generation
        """
        # Step 1: Load blueprint metadata
        blueprint_meta = self._load_blueprint_metadata(project_spec.blueprint)
        if not blueprint_meta:
            raise ValueError(f"Blueprint '{project_spec.blueprint}' not found")
        
        # Step 2: Resolve stacks
        resolved_stacks = self._resolve_stacks(project_spec, blueprint_meta)
        
        # Step 3: Resolve tiers
        resolved_tiers = self._resolve_tiers(project_spec, blueprint_meta, resolved_stacks)
        
        # Step 4: Resolve tasks
        resolved_tasks = self._resolve_tasks(project_spec, blueprint_meta)
        
        # Step 5: Produce intermediate representation
        ir = self._produce_ir(
            project_spec, blueprint_meta, 
            resolved_stacks, resolved_tiers, resolved_tasks
        )
        
        # Step 6 & 7: Generator calls and validation are handled separately
        # This resolver focuses on producing the IR
        
        return ir
    
    def _load_blueprint_metadata(self, blueprint_id: str) -> Optional[Dict[str, Any]]:
        """Step 1: Load blueprint metadata"""
        return load_blueprint_metadata(blueprint_id)
    
    def _resolve_stacks(self, project_spec: ProjectSpecification, blueprint_meta: Dict[str, Any]) -> List[str]:
        """
        Step 2: Resolve stacks according to blueprint requirements
        
        Ensures required stacks are present, recommends optional stacks,
        validates against supported stacks
        """
        blueprint_stacks = get_supported_stacks(project_spec.blueprint)
        resolved_stacks = []
        
        # Check required stacks
        required_stacks = blueprint_stacks['required']
        for required_stack in required_stacks:
            if required_stack not in self.available_stacks:
                raise ValueError(f"Required stack '{required_stack}' not available in system")
            if required_stack not in project_spec.stacks.values():
                # Auto-add required stack if not specified
                resolved_stacks.append(required_stack)
        
        # Add user-specified stacks
        for layer, stack in project_spec.stacks.items():
            if stack not in self.available_stacks:
                raise ValueError(f"Stack '{stack}' not available in system")
            if stack not in blueprint_stacks['required'] + blueprint_stacks['recommended'] + blueprint_stacks['supported']:
                raise ValueError(f"Stack '{stack}' not supported by blueprint '{project_spec.blueprint}'")
            if stack not in resolved_stacks:
                resolved_stacks.append(stack)
        
        # Auto-add recommended stacks if not specified and not forbidden
        recommended_stacks = blueprint_stacks['recommended']
        for recommended_stack in recommended_stacks:
            if recommended_stack not in resolved_stacks and recommended_stack in self.available_stacks:
                # Add recommended stack (user can remove later if needed)
                resolved_stacks.append(recommended_stack)
        
        return resolved_stacks
    
    def _resolve_tiers(self, project_spec: ProjectSpecification, blueprint_meta: Dict[str, Any], stacks: List[str]) -> Dict[str, str]:
        """
        Step 3: Resolve tiers according to blueprint defaults and user overrides
        
        Applies blueprint tier defaults, allows per-layer overrides
        """
        blueprint_tiers = get_tier_defaults(project_spec.blueprint)
        resolved_tiers = {}
        
        # Apply blueprint defaults
        if project_spec.tier is None:
            # Use blueprint defaults
            for stack in stacks:
                if stack in ['flutter', 'react', 'react_native']:
                    resolved_tiers[stack] = blueprint_tiers.get('frontend', 'mvp')
                elif stack in ['python', 'node', 'go']:
                    resolved_tiers[stack] = blueprint_tiers.get('backend', 'core')
                else:
                    resolved_tiers[stack] = blueprint_tiers.get('overall', 'core')
        else:
            # Apply user-specified tiers
            for layer, tier in project_spec.tier.items():
                if tier not in self.available_tiers:
                    raise ValueError(f"Tier '{tier}' not available in system")
                
                # Map layer to actual stack
                if layer in project_spec.stacks:
                    stack = project_spec.stacks[layer]
                    resolved_tiers[stack] = tier
            
            # Fill in missing tiers with blueprint defaults
            for stack in stacks:
                if stack not in resolved_tiers:
                    if stack in ['flutter', 'react', 'react_native']:
                        resolved_tiers[stack] = blueprint_tiers.get('frontend', 'mvp')
                    elif stack in ['python', 'node', 'go']:
                        resolved_tiers[stack] = blueprint_tiers.get('backend', 'core')
                    else:
                        resolved_tiers[stack] = blueprint_tiers.get('overall', 'core')
        
        return resolved_tiers
    
    def _resolve_tasks(self, project_spec: ProjectSpecification, blueprint_meta: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Step 4: Resolve tasks according to blueprint configuration
        
        Required tasks are always enabled
        Recommended tasks are auto-enabled unless user explicitly disables
        Optional tasks are only enabled if user selects them
        """
        blueprint_tasks = get_task_configuration(project_spec.blueprint)
        resolved_tasks = {
            'required': blueprint_tasks['required'].copy(),
            'recommended': blueprint_tasks['recommended'].copy(),
            'optional': []
        }
        
        # Add user-specified optional tasks
        if project_spec.tasks and 'optional' in project_spec.tasks:
            user_optional = project_spec.tasks['optional']
            for task in user_optional:
                if task in blueprint_tasks['optional']:
                    resolved_tasks['optional'].append(task)
        
        # Handle user disabling recommended tasks (if specified)
        if project_spec.tasks and 'disabled' in project_spec.tasks:
            disabled_tasks = project_spec.tasks['disabled']
            for task in disabled_tasks:
                if task in resolved_tasks['recommended']:
                    resolved_tasks['recommended'].remove(task)
        
        return resolved_tasks
    
    def _produce_ir(self, project_spec: ProjectSpecification, blueprint_meta: Dict[str, Any], 
                   stacks: List[str], tiers: Dict[str, str], tasks: Dict[str, List[str]]) -> IntermediateRepresentation:
        """
        Step 5: Produce intermediate representation
        
        Combines all resolved information into a structured IR
        """
        constraints = get_blueprint_constraints(project_spec.blueprint)
        overlays = get_blueprint_overlays(project_spec.blueprint)
        llm_hints = get_llm_hints(project_spec.blueprint)
        
        # Flatten tasks for easier processing
        all_tasks = (
            tasks['required'] + 
            tasks['recommended'] + 
            tasks['optional']
        )
        
        return IntermediateRepresentation(
            blueprint=project_spec.blueprint,
            name=project_spec.name,
            description=project_spec.description,
            stacks=stacks,
            tiers=tiers,
            tasks={
                'all': all_tasks,
                'by_category': tasks
            },
            constraints=constraints,
            overlays=overlays,
            llm_hints=llm_hints,
            metadata={
                'blueprint_version': blueprint_meta.get('version', '1'),
                'blueprint_type': blueprint_meta.get('type', 'app'),
                'blueprint_category': blueprint_meta.get('category', 'unknown'),
                'generated_at': str(Path.cwd()),
                'resolution_confidence': self._calculate_resolution_confidence(project_spec, blueprint_meta, stacks, tiers, tasks)
            }
        )
    
    def _calculate_resolution_confidence(self, project_spec: ProjectSpecification, blueprint_meta: Dict[str, Any],
                                        stacks: List[str], tiers: Dict[str, str], tasks: Dict[str, List[str]]) -> float:
        """Calculate confidence score for the resolution (0.0 to 1.0)"""
        score = 0.0
        
        # Blueprint exists and is valid (0.3)
        if blueprint_meta:
            score += 0.3
        
        # All required stacks present (0.2)
        required_stacks = get_supported_stacks(project_spec.blueprint)['required']
        if all(req in stacks for req in required_stacks):
            score += 0.2
        
        # Recommended stacks included (0.1)
        recommended_stacks = get_supported_stacks(project_spec.blueprint)['recommended']
        if any(rec in stacks for rec in recommended_stacks):
            score += 0.1
        
        # Tiers properly assigned (0.2)
        if all(stack in tiers for stack in stacks):
            score += 0.2
        
        # Required tasks included (0.2)
        if tasks['required']:
            score += 0.2
        
        return min(score, 1.0)
    
    def validate_resolution(self, ir: IntermediateRepresentation) -> List[str]:
        """
        Step 7: Validate the resolved IR against blueprint constraints
        
        Returns list of validation errors (empty if valid)
        """
        errors = []
        
        # Validate stack constraints
        if 'single_primary_feature' in ir.constraints and ir.constraints['single_primary_feature']:
            # Check that we're not creating a complex multi-feature app
            if len(ir.tasks['all']) > 10:
                errors.append("Too many tasks for single-primary-feature constraint")
        
        # Validate monetization constraints
        if 'monetization' in ir.constraints:
            monetization = ir.constraints['monetization']
            if 'model' in monetization:
                required_tasks = []
                if 'freemium' in monetization['model']:
                    required_tasks.extend(['billing-stripe', 'auth-basic'])
                if 'one_time' in monetization['model']:
                    required_tasks.append('billing-stripe')
                
                for task in required_tasks:
                    if task not in ir.tasks['all']:
                        errors.append(f"Required task '{task}' missing for monetization model")
        
        # Validate platform constraints
        if 'platforms' in ir.constraints:
            platforms = ir.constraints['platforms']
            if 'flutter' in ir.stacks and platforms:
                # Flutter should target mobile platforms
                if not any(p in ['android', 'ios'] for p in platforms):
                    errors.append("Flutter stack should target mobile platforms")
        
        return errors

# Convenience functions for common operations
def resolve_project(project_name: str, blueprint_id: str, stacks: Dict[str, str], 
                   description: str = "", tiers: Optional[Dict[str, str]] = None,
                   tasks: Optional[Dict[str, List[str]]] = None) -> IntermediateRepresentation:
    """
    Convenience function to resolve a project specification
    
    Args:
        project_name: Name of the project
        blueprint_id: Blueprint identifier
        stacks: Layer to stack mapping
        description: Project description
        tiers: Optional layer to tier mapping
        tasks: Optional task configuration
        
    Returns:
        Resolved intermediate representation
    """
    resolver = BlueprintResolver()
    project_spec = ProjectSpecification(
        name=project_name,
        blueprint=blueprint_id,
        stacks=stacks,
        tier=tiers,
        tasks=tasks,
        description=description
    )
    
    return resolver.resolve(project_spec)

if __name__ == "__main__":
    # Test blueprint resolution
    print("Testing Blueprint Resolution System")
    
    # Example: Resolve a MINS project
    try:
        ir = resolve_project(
            project_name="FocusPulse",
            blueprint_id="mins",
            stacks={"frontend": "flutter", "backend": "python"},
            description="A single-purpose focus tracking app with premium features",
            tiers={"frontend": "mvp", "backend": "core"},
            tasks={"optional": ["seo-keyword-research"]}
        )
        
        print("Resolution successful!")
        print(f"Blueprint: {ir.blueprint}")
        print(f"Stacks: {ir.stacks}")
        print(f"Tiers: {ir.tiers}")
        print(f"Tasks: {ir.tasks}")
        print(f"Confidence: {ir.metadata['resolution_confidence']:.2f}")
        
        # Validate resolution
        resolver = BlueprintResolver()
        errors = resolver.validate_resolution(ir)
        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Validation passed!")
            
    except Exception as e:
        print(f"Resolution failed: {e}")
