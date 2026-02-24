#!/usr/bin/env python3
"""
Analyze reference-projects and reference-projects directories to determine which contains current reference projects
"""

from pathlib import Path
from stack_config import get_all_stacks

def analyze_directory_structure():
    """Analyze both directories to understand their contents"""
    
    base_dir = Path(__file__).parent.parent
    
    # Analyze reference-projects
    test_projects_dir = base_dir / 'reference-projects'
    reference_projects_dir = base_dir / 'reference-projects'
    
    print("🔍 Analyzing Project Directories")
    print("=" * 60)
    
    # Count projects in reference-projects
    test_mvp = test_projects_dir / 'mvp'
    test_core = test_projects_dir / 'core'
    test_enterprise = test_projects_dir / 'enterprise'
    
    test_mvp_projects = [d for d in test_mvp.iterdir() if d.is_dir() and 'reference' in d.name] if test_mvp.exists() else []
    test_core_projects = [d for d in test_core.iterdir() if d.is_dir() and 'reference' in d.name] if test_core.exists() else []
    test_enterprise_projects = [d for d in test_enterprise.iterdir() if d.is_dir() and 'reference' in d.name] if test_enterprise.exists() else []
    
    print(f"reference-projects/:")
    print(f"  MVP: {len(test_mvp_projects)} projects")
    print(f"  Core: {len(test_core_projects)} projects") 
    print(f"  Enterprise: {len(test_enterprise_projects)} projects")
    print(f"  Total: {len(test_mvp_projects) + len(test_core_projects) + len(test_enterprise_projects)} projects")
    
    # Count projects in reference-projects
    ref_mvp = reference_projects_dir / 'mvp'
    ref_core = reference_projects_dir / 'core'
    ref_enterprise = reference_projects_dir / 'enterprise'
    
    ref_mvp_projects = [d for d in ref_mvp.iterdir() if d.is_dir() and 'reference' in d.name] if ref_mvp.exists() else []
    ref_core_projects = [d for d in ref_core.iterdir() if d.is_dir() and 'reference' in d.name] if ref_core.exists() else []
    ref_enterprise_projects = [d for d in ref_enterprise.iterdir() if d.is_dir() and 'reference' in d.name] if ref_enterprise.exists() else []
    
    print(f"\nreference-projects/:")
    print(f"  MVP: {len(ref_mvp_projects)} projects")
    print(f"  Core: {len(ref_core_projects)} projects")
    print(f"  Enterprise: {len(ref_enterprise_projects)} projects")
    print(f"  Total: {len(ref_mvp_projects) + len(ref_core_projects) + len(ref_enterprise_projects)} projects")
    
    # List actual project names
    print(f"\n📋 reference-projects MVP projects:")
    for project in sorted(test_mvp_projects):
        print(f"  {project.name}")
    
    print(f"\n📋 reference-projects MVP projects:")
    for project in sorted(ref_mvp_projects):
        print(f"  {project.name}")
    
    # Check which has the current 11 stacks
    expected_stacks = get_all_stacks()
    
    test_has_all_stacks = all(
        any(stack in p.name for p in test_mvp_projects) for stack in expected_stacks
    )
    
    ref_has_all_stacks = all(
        any(stack in p.name for p in ref_mvp_projects) for stack in expected_stacks
    )
    
    print(f"\n✅ Stack Coverage Analysis:")
    print(f"reference-projects has all 8 stacks: {test_has_all_stacks}")
    print(f"reference-projects has all 8 stacks: {ref_has_all_stacks}")
    
    # Determine which is current
    test_total = len(test_mvp_projects) + len(test_core_projects) + len(test_enterprise_projects)
    ref_total = len(ref_mvp_projects) + len(ref_core_projects) + len(ref_enterprise_projects)
    
    print(f"\n🎯 Recommendation:")
    if test_total == 24 and ref_total < 24:
        print("reference-projects/ contains the current 24 reference projects")
        print("reference-projects/ is outdated and can be deleted")
    elif ref_total == 24 and test_total < 24:
        print("reference-projects/ contains the current 24 reference projects")
        print("reference-projects/ is outdated and can be deleted")
    elif test_total == ref_total == 24:
        print("Both directories contain 24 projects - check which is more recent")
        # Check modification times
        ref_index_time = reference_projects_dir / 'REFERENCE-PROJECTS-INDEX.md'
        ref_index_time = reference_projects_dir / 'REFERENCE-PROJECTS-INDEX.md'
        
        if test_index_time.exists() and ref_index_time.exists():
            test_mtime = test_index_time.stat().st_mtime
            ref_mtime = ref_index_time.stat().st_mtime
            
            if test_mtime > ref_mtime:
                print("reference-projects/ is more recent - keep it, delete reference-projects/")
            else:
                print("reference-projects/ is more recent - keep it, delete reference-projects/")
    else:
        print(f"Unexpected state - reference-projects: {test_total}, reference-projects: {ref_total}")
    
    return {
        'test_total': test_total,
        'ref_total': ref_total,
        'test_has_all_stacks': test_has_all_stacks,
        'ref_has_all_stacks': ref_has_all_stacks,
        'test_mvp_projects': [p.name for p in test_mvp_projects],
        'ref_mvp_projects': [p.name for p in ref_mvp_projects]
    }

if __name__ == "__main__":
    analyze_directory_structure()
