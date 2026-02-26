#!/usr/bin/env python3
"""
Stack Listing Script

Lists all available stacks with their capabilities, templates, and reference projects.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import sys

class StackLister:
    def __init__(self, templates_root: Path):
        self.templates_root = templates_root
        self.stacks_dir = templates_root / "stacks"
        self.reference_projects_dir = templates_root / "reference-projects"
        self.tiers_dir = templates_root / "tiers"

    def list_all(self, detailed: bool = False) -> Dict[str, Any]:
        """List all stacks with their metadata."""
        print("🔧 Available Stacks")
        print("=" * 50)
        
        if not self.stacks_dir.exists():
            print("❌ Stacks directory not found")
            return {}
        
        # Discover stacks
        stack_dirs = [d for d in self.stacks_dir.iterdir() 
                     if d.is_dir() and not d.name.startswith('.')]
        
        stacks = {}
        
        for stack_dir in sorted(stack_dirs):
            stack_name = stack_dir.name
            metadata = self.get_stack_metadata(stack_name, stack_dir)
            
            if metadata:
                stacks[stack_name] = metadata
                self.print_stack_summary(stack_name, metadata, detailed)
        
        # Print summary
        print(f"\n📊 Summary: {len(stacks)} stacks found")
        
        # Print tier coverage
        self.print_tier_coverage(stacks)
        
        # Print stack matrix
        self.print_stack_matrix(stacks)
        
        return stacks

    def get_stack_metadata(self, stack_name: str, stack_dir: Path) -> Optional[Dict[str, Any]]:
        """Get comprehensive metadata for a stack."""
        metadata = {
            "name": stack_name,
            "directory": str(stack_dir),
            "has_base": (stack_dir / "base").exists(),
            "reference_projects": {},
            "template_count": {},
            "capabilities": []
        }
        
        # Load README for additional info
        readme_path = stack_dir / "README.md"
        if readme_path.exists():
            metadata.update(self.parse_stack_readme(readme_path))
        
        # Count templates
        base_dir = stack_dir / "base"
        if base_dir.exists():
            for subdir in ["code", "docs", "tests"]:
                subdir_path = base_dir / subdir
                if subdir_path.exists():
                    templates = list(subdir_path.rglob("*.tpl.*"))
                    metadata["template_count"][subdir] = len(templates)
        
        # Check reference projects
        for tier in ["mvp", "core", "enterprise"]:
            project_dir = self.reference_projects_dir / tier / f"{tier}-{stack_name}-reference"
            metadata["reference_projects"][tier] = project_dir.exists()
        
        # Determine stack type and capabilities
        metadata["type"] = self.determine_stack_type(stack_name)
        metadata["capabilities"] = self.get_stack_capabilities(stack_name, stack_dir)
        
        return metadata

    def parse_stack_readme(self, readme_path: Path) -> Dict[str, Any]:
        """Parse stack README.md for metadata."""
        metadata = {}
        
        try:
            with open(readme_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract title
            lines = content.split('\n')
            for line in lines:
                if line.startswith('# '):
                    metadata["display_name"] = line[2:].strip()
                    break
            
            # Extract purpose
            if "**Purpose**:" in content:
                purpose_start = content.find("**Purpose**:")
                purpose_end = content.find("\n", purpose_start)
                if purpose_end != -1:
                    purpose = content[purpose_start:purpose_end]
                    metadata["purpose"] = purpose.replace("**Purpose**:", "").strip()
            
            # Extract language/framework
            if "**Language**:" in content:
                lang_start = content.find("**Language**:")
                lang_end = content.find("\n", lang_start)
                if lang_end != -1:
                    lang = content[lang_start:lang_end]
                    metadata["language"] = lang.replace("**Language**:", "").strip()
            
            if "**Framework**:" in content:
                fw_start = content.find("**Framework**:")
                fw_end = content.find("\n", fw_start)
                if fw_end != -1:
                    fw = content[fw_start:fw_end]
                    metadata["framework"] = fw.replace("**Framework**:", "").strip()
            
        except Exception:
            pass  # Ignore README parsing errors
        
        return metadata

    def determine_stack_type(self, stack_name: str) -> str:
        """Determine the type of stack."""
        stack_types = {
            "flutter": "mobile",
            "react_native": "mobile",
            "python": "data-science",
            "r": "data-analytics",
            "node": "backend",
            "go": "backend",
            "react": "web",
            "next": "web",
            "sql": "database",
            "typescript": "web",
            "generic": "utility"
        }
        return stack_types.get(stack_name, "unknown")

    def get_stack_capabilities(self, stack_name: str, stack_dir: Path) -> List[str]:
        """Get stack capabilities based on templates."""
        capabilities = []
        
        base_dir = stack_dir / "base"
        if base_dir.exists():
            # Check for specific capabilities
            code_dir = base_dir / "code"
            if code_dir.exists():
                if (code_dir / "http-client.tpl").exists():
                    capabilities.append("http-client")
                if (code_dir / "config-management.tpl").exists():
                    capabilities.append("config-management")
                if (code_dir / "testing-utilities.tpl").exists():
                    capabilities.append("testing")
            
            docs_dir = base_dir / "docs"
            if docs_dir.exists():
                if (docs_dir / "CI-EXAMPLES-.tpl.md").exists():
                    capabilities.append("ci-cd")
                if (docs_dir / "PERFORMANCE.tpl.md").exists():
                    capabilities.append("performance")
        
        return capabilities

    def print_stack_summary(self, stack_name: str, metadata: Dict[str, Any], detailed: bool = False):
        """Print a summary of a stack."""
        display_name = metadata.get('display_name', stack_name.title())
        print(f"\n🔧 {display_name}")
        print(f"   ID: {stack_name}")
        print(f"   Type: {metadata.get('type', 'Unknown')}")
        
        if 'purpose' in metadata:
            purpose = metadata['purpose']
            if purpose:
                short_purpose = purpose[:80] + ('...' if len(purpose) > 80 else '')
                print(f"   Purpose: {short_purpose}")
        
        if 'language' in metadata:
            print(f"   Language: {metadata['language']}")
        
        if 'framework' in metadata:
            print(f"   Framework: {metadata['framework']}")
        
        # Print template counts
        template_count = metadata.get('template_count', {})
        total_templates = sum(template_count.values())
        print(f"   Templates: {total_templates} total")
        if template_count:
            for category, count in template_count.items():
                print(f"     {category}: {count}")
        
        # Print reference project status
        ref_projects = metadata.get('reference_projects', {})
        available_tiers = [tier for tier, exists in ref_projects.items() if exists]
        if available_tiers:
            print(f"   Reference Projects: {', '.join(available_tiers)}")
        
        # Print capabilities
        capabilities = metadata.get('capabilities', [])
        if capabilities:
            print(f"   Capabilities: {', '.join(capabilities)}")
        
        if detailed:
            # Print detailed information
            print(f"   Directory: {metadata['directory']}")
            print(f"   Has Base Templates: {metadata['has_base']}")

    def print_tier_coverage(self, stacks: Dict[str, Any]):
        """Print tier coverage statistics."""
        print("\n📊 Tier Coverage")
        print("-" * 30)
        
        tier_counts = {"mvp": 0, "core": 0, "enterprise": 0}
        
        for stack_name, metadata in stacks.items():
            ref_projects = metadata.get('reference_projects', {})
            for tier, exists in ref_projects.items():
                if exists:
                    tier_counts[tier] += 1
        
        for tier, count in tier_counts.items():
            percentage = (count / len(stacks)) * 100 if stacks else 0
            print(f"  {tier.title():12}: {count:2}/{len(stacks):2} stacks ({percentage:.0f}%)")

    def print_stack_matrix(self, stacks: Dict[str, Any]):
        """Print a capability matrix of all stacks."""
        print("\n📋 Stack Capability Matrix")
        print("-" * 50)
        
        # Collect all capabilities
        all_capabilities = set()
        for metadata in stacks.values():
            all_capabilities.update(metadata.get('capabilities', []))
        
        if not all_capabilities:
            return
        
        # Print header
        header = "Stack".ljust(15)
        for cap in sorted(all_capabilities):
            header += cap[:8].ljust(10)
        print(header)
        print("-" * len(header))
        
        # Print rows
        for stack_name, metadata in sorted(stacks.items()):
            row = stack_name.ljust(15)
            capabilities = set(metadata.get('capabilities', []))
            for cap in sorted(all_capabilities):
                row += "✓".ljust(10) if cap in capabilities else " ".ljust(10)
            print(row)

    def list_by_type(self, stack_type: str = None):
        """List stacks by type."""
        stacks = self.list_all()
        
        if stack_type:
            filtered = {name: meta for name, meta in stacks.items() 
                       if meta.get('type') == stack_type}
            print(f"\n🔧 Type: {stack_type}")
            print("=" * 50)
            for name, meta in filtered.items():
                display_name = meta.get('display_name', name.title())
                print(f"  • {display_name} ({name})")
        else:
            # Group by type
            types = {}
            for name, meta in stacks.items():
                stype = meta.get('type', 'Unknown')
                if stype not in types:
                    types[stype] = []
                types[stype].append((name, meta))
            
            print("\n🔧 Stacks by Type")
            print("=" * 50)
            for stype, items in sorted(types.items()):
                print(f"\n{stype.title()} ({len(items)}):")
                for name, meta in items:
                    display_name = meta.get('display_name', name.title())
                    print(f"  • {display_name} ({name})")

    def compare_stacks(self, stack_names: List[str]):
        """Compare multiple stacks."""
        stacks = self.list_all()
        
        print(f"\n📊 Stack Comparison")
        print("=" * 50)
        
        # Get metadata for comparison
        compare_data = {}
        for stack_name in stack_names:
            if stack_name in stacks:
                compare_data[stack_name] = stacks[stack_name]
            else:
                print(f"⚠️  Stack '{stack_name}' not found")
        
        if not compare_data:
            return
        
        # Print comparison table
        categories = ["type", "language", "framework", "templates", "reference_projects", "capabilities"]
        
        for category in categories:
            print(f"\n{category.title()}:")
            for stack_name, metadata in compare_data.items():
                value = metadata.get(category, "N/A")
                if isinstance(value, dict):
                    if category == "template_count":
                        total = sum(value.values())
                        value = f"{total} total"
                    elif category == "reference_projects":
                        available = [k for k, v in value.items() if v]
                        value = f"{', '.join(available)}" if available else "None"
                    else:
                        value = str(value)
                elif isinstance(value, list):
                    value = f"{', '.join(value)}" if value else "None"
                
                display_name = metadata.get('display_name', stack_name.title())
                print(f"  {display_name:20}: {value}")

    def recommend_stack(self, description: str):
        """Recommend stacks based on description."""
        stacks = self.list_all()
        
        print(f"\n🎯 Stack Recommendations for: {description}")
        print("=" * 50)
        
        # Simple keyword-based recommendation
        keywords = description.lower().split()
        
        recommendations = []
        
        for stack_name, metadata in stacks.items():
            score = 0
            stack_info = f"{metadata.get('display_name', '')} {metadata.get('purpose', '')} {metadata.get('language', '')} {metadata.get('framework', '')}".lower()
            
            # Score based on keyword matches
            for keyword in keywords:
                if keyword in stack_info:
                    score += 1
            
            # Bonus for type matches
            if "mobile" in keywords and metadata.get('type') == 'mobile':
                score += 2
            elif "web" in keywords and metadata.get('type') == 'web':
                score += 2
            elif "backend" in keywords and metadata.get('type') == 'backend':
                score += 2
            elif "data" in keywords and metadata.get('type') in ['data-science', 'data-analytics']:
                score += 2
            
            if score > 0:
                recommendations.append((stack_name, metadata, score))
        
        # Sort by score
        recommendations.sort(key=lambda x: x[2], reverse=True)
        
        if recommendations:
            print("Top recommendations:")
            for stack_name, metadata, score in recommendations[:5]:
                display_name = metadata.get('display_name', stack_name.title())
                print(f"  {score}x {display_name} ({stack_name})")
                if 'purpose' in metadata:
                    print(f"     {metadata['purpose'][:100]}...")
        else:
            print("No specific recommendations. Consider:")
            for stack_name in ['python', 'node', 'flutter', 'react']:
                if stack_name in stacks:
                    metadata = stacks[stack_name]
                    display_name = metadata.get('display_name', stack_name.title())
                    print(f"  • {display_name} ({stack_name})")

def main():
    """Main listing script."""
    templates_root = Path(__file__).parent.parent
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "--help":
            print("Usage: python list_stacks.py [command] [options]")
            print("Commands:")
            print("  (no args)    List all stacks")
            print("  --detailed   Show detailed information")
            print("  --type       List by type")
            print("  --compare    Compare multiple stacks")
            print("  --recommend  Recommend stack based on description")
            return
        
        lister = StackLister(templates_root)
        
        if command == "--detailed":
            lister.list_all(detailed=True)
        elif command == "--type":
            if len(sys.argv) > 2:
                lister.list_by_type(sys.argv[2])
            else:
                lister.list_by_type()
        elif command == "--compare":
            if len(sys.argv) > 2:
                lister.compare_stacks(sys.argv[2:])
            else:
                print("Error: Stack names required")
                print("Usage: python list_stacks.py --compare <stack1> <stack2> [...]")
        elif command == "--recommend":
            if len(sys.argv) > 2:
                description = " ".join(sys.argv[2:])
                lister.recommend_stack(description)
            else:
                print("Error: Description required")
                print("Usage: python list_stacks.py --recommend <description>")
        else:
            print(f"Unknown command: {command}")
            print("Use --help for usage information")
    else:
        # Default: list all stacks
        lister = StackLister(templates_root)
        lister.list_all()

if __name__ == "__main__":
    main()
