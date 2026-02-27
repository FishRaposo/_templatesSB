# Memory System Validation Script

This document contains the validation script for the memory system. Copy this to `memory-system/scripts/validate-memory.py` to use it.

## Script Code

```python
#!/usr/bin/env python3
"""Validate memory system files for consistency.

Usage:
    python validate-memory.py [--project-root PATH]

This script validates the memory system files for a project:
- Layer 0: AGENTS.md exists and is non-empty
- Layer 1: CHANGELOG.md format and event integrity
- Layer 2: graph.md consistency and completeness
- Layer 3: context.md staleness check

Exit codes:
    0 - All validations passed
    1 - One or more validation errors
"""

import re
import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta


def validate_agents_md(project_root: Path) -> list[str]:
    """Validate Layer 0: AGENTS.md exists and is non-empty."""
    errors = []
    agents_path = project_root / "AGENTS.md"
    
    if not agents_path.exists():
        errors.append("L0: AGENTS.md not found at project root")
        return errors
    
    content = agents_path.read_text().strip()
    if not content:
        errors.append("L0: AGENTS.md is empty")
    
    return errors


def validate_changelog(project_root: Path) -> list[str]:
    """Validate Layer 1: CHANGELOG.md format and integrity."""
    errors = []
    changelog_path = project_root / "CHANGELOG.md"
    
    if not changelog_path.exists():
        errors.append("L1: CHANGELOG.md not found at project root")
        return errors
    
    content = changelog_path.read_text()
    
    # Check for Event Log section
    if "## Event Log" not in content:
        errors.append("L1: Missing '## Event Log' section in CHANGELOG.md")
        return errors
    
    # Extract events
    event_pattern = r'### (evt-(\d+)) \| (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}) \| ([^|]+) \| (\w+)'
    events = re.findall(event_pattern, content)
    
    if not events:
        return errors  # No events yet is valid for new projects
    
    # Check sequential IDs
    event_ids = [int(e[1]) for e in events]
    expected_ids = list(range(1, max(event_ids) + 1))
    
    if sorted(event_ids) != expected_ids:
        errors.append(f"L1: Non-sequential event IDs. Found: {event_ids}, expected: {expected_ids}")
    
    # Check for duplicate IDs
    if len(event_ids) != len(set(event_ids)):
        errors.append("L1: Duplicate event IDs found")
    
    # Validate event format
    for event in events:
        event_id, event_num, date, time, agent, event_type = event
        
        # Validate event type
        valid_types = ['decision', 'create', 'modify', 'delete', 'test', 'fix', 
                       'dependency', 'blocker', 'milestone', 'escalation', 'handoff']
        if event_type not in valid_types:
            errors.append(f"L1: Invalid event type '{event_type}' in {event_id}")
        
        # Validate date format
        try:
            datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M")
        except ValueError:
            errors.append(f"L1: Invalid timestamp in {event_id}")
    
    # Check for required fields in each event
    event_sections = re.split(r'### evt-\d+', content)[1:]  # Skip header
    for i, section in enumerate(event_sections):
        event_id = f"evt-{i+1}"
        
        if "**Scope**:" not in section:
            errors.append(f"L1: Missing 'Scope' field in {event_id}")
        if "**Summary**:" not in section:
            errors.append(f"L1: Missing 'Summary' field in {event_id}")
    
    return errors


def validate_graph(project_root: Path) -> list[str]:
    """Validate Layer 2: graph.md consistency."""
    errors = []
    graph_path = project_root / ".memory" / "graph.md"
    
    if not graph_path.exists():
        # Graph is optional for MVP tier
        return errors
    
    content = graph_path.read_text()
    
    # Check for required sections
    required_sections = ["## Nodes", "## Edges", "## Meta"]
    for section in required_sections:
        if section not in content:
            errors.append(f"L2: Missing '{section}' section in graph.md")
    
    if errors:
        return errors
    
    # Extract nodes
    nodes_section = content.split("## Nodes")[1].split("##")[0]
    node_pattern = r'\| ([^|]+) \| (\w+) \| (\w+) \| (evt-\d+) \| (evt-\d+|—) \|'
    nodes = re.findall(node_pattern, nodes_section)
    
    node_names = [n[0].strip() for n in nodes]
    
    # Validate node types
    valid_types = ['component', 'task', 'dependency', 'decision', 'document', 'milestone']
    for node in nodes:
        if node[1] not in valid_types:
            errors.append(f"L2: Invalid node type '{node[1]}' for node '{node[0]}'")
    
    # Validate node statuses
    valid_statuses = ['active', 'blocked', 'completed', 'deprecated', 'planned']
    for node in nodes:
        if node[2] not in valid_statuses:
            errors.append(f"L2: Invalid node status '{node[2]}' for node '{node[0]}'")
    
    # Extract edges
    edges_section = content.split("## Edges")[1].split("##")[0]
    edge_pattern = r'\| ([^|]+) \| ([^|]+) \| (\w+) \| (evt-\d+) \|'
    edges = re.findall(edge_pattern, edges_section)
    
    # Check for orphan edges
    for edge in edges:
        from_node, to_node, relation, _ = edge
        from_node = from_node.strip()
        to_node = to_node.strip()
        
        if from_node not in node_names:
            errors.append(f"L2: Edge references non-existent 'from' node '{from_node}'")
        if to_node not in node_names:
            errors.append(f"L2: Edge references non-existent 'to' node '{to_node}'")
    
    # Validate edge relations
    valid_relations = ['depends_on', 'blocks', 'implements', 'tests', 'documents', 
                       'contains', 'precedes', 'related_to']
    for edge in edges:
        if edge[2] not in valid_relations:
            errors.append(f"L2: Invalid edge relation '{edge[2]}'")
    
    # Validate Meta section
    meta_section = content.split("## Meta")[1]
    
    # Check event horizon
    horizon_match = re.search(r'\*\*Event horizon\*\*:\s*(evt-\d+|—)', meta_section)
    if horizon_match:
        horizon = horizon_match.group(1)
        if horizon != "—":
            # Verify event exists in changelog
            changelog_path = project_root / "CHANGELOG.md"
            if changelog_path.exists():
                changelog_content = changelog_path.read_text()
                if horizon not in changelog_content:
                    errors.append(f"L2: Event horizon '{horizon}' not found in CHANGELOG.md")
    
    return errors


def validate_context(project_root: Path) -> list[str]:
    """Validate Layer 3: context.md staleness."""
    errors = []
    context_path = project_root / ".memory" / "context.md"
    changelog_path = project_root / "CHANGELOG.md"
    
    if not context_path.exists():
        # Context is optional for MVP tier
        return errors
    
    if not changelog_path.exists():
        return errors  # Already reported in L1 validation
    
    context_content = context_path.read_text()
    changelog_content = changelog_path.read_text()
    
    # Get event horizon from context
    horizon_match = re.search(r'Event horizon:\s*(evt-\d+)', context_content)
    if not horizon_match:
        errors.append("L3: Missing 'Event horizon' in context.md")
        return errors
    
    context_horizon = horizon_match.group(1)
    
    # Get last event from changelog
    event_pattern = r'### (evt-\d+) \|'
    events = re.findall(event_pattern, changelog_content)
    
    if events:
        last_event = events[-1]
        
        if context_horizon != last_event:
            errors.append(f"L3: Context is stale. Event horizon: {context_horizon}, last event: {last_event}")
    
    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate memory system files")
    parser.add_argument("--project-root", type=Path, default=Path.cwd(),
                        help="Path to project root (default: current directory)")
    args = parser.parse_args()
    
    project_root = args.project_root.resolve()
    
    print(f"Validating memory system at: {project_root}")
    print("-" * 50)
    
    all_errors = []
    
    # Validate each layer
    print("Layer 0: AGENTS.md...")
    errors = validate_agents_md(project_root)
    all_errors.extend(errors)
    print(f"  {'✓' if not errors else '✗'} Found {len(errors)} error(s)")
    
    print("Layer 1: CHANGELOG.md...")
    errors = validate_changelog(project_root)
    all_errors.extend(errors)
    print(f"  {'✓' if not errors else '✗'} Found {len(errors)} error(s)")
    
    print("Layer 2: graph.md...")
    errors = validate_graph(project_root)
    all_errors.extend(errors)
    print(f"  {'✓' if not errors else '✗'} Found {len(errors)} error(s)")
    
    print("Layer 3: context.md...")
    errors = validate_context(project_root)
    all_errors.extend(errors)
    print(f"  {'✓' if not errors else '✗'} Found {len(errors)} error(s)")
    
    print("-" * 50)
    
    if all_errors:
        print("\nValidation errors:")
        for error in all_errors:
            print(f"  - {error}")
        sys.exit(1)
    else:
        print("✓ All memory system validations passed")
        sys.exit(0)


if __name__ == "__main__":
    main()
```

## Usage

```bash
# Validate current directory
python validate-memory.py

# Validate specific project
python validate-memory.py --project-root /path/to/project
```

## Validation Checks

### Layer 0: AGENTS.md
- File exists at project root
- File is non-empty

### Layer 1: CHANGELOG.md
- File exists at project root
- Contains `## Event Log` section
- Event IDs are sequential (evt-001, evt-002, etc.)
- No duplicate event IDs
- Valid event types (decision, create, modify, delete, test, fix, dependency, blocker, milestone, escalation, handoff)
- Valid timestamp format (YYYY-MM-DD HH:MM)
- Required fields present (Scope, Summary)

### Layer 2: graph.md
- Required sections present (Nodes, Edges, Meta)
- Valid node types (component, task, dependency, decision, document, milestone)
- Valid node statuses (active, blocked, completed, deprecated, planned)
- Valid edge relations (depends_on, blocks, implements, tests, documents, contains, precedes, related_to)
- No orphan edges (edges referencing non-existent nodes)
- Event horizon matches an event in CHANGELOG.md

### Layer 3: context.md
- Event horizon present
- Event horizon matches last event in CHANGELOG.md (staleness check)
