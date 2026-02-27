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
from datetime import datetime


def validate_agents_md(project_root: Path) -> list[str]:
    """Validate Layer 0: AGENTS.md exists and is non-empty."""
    errors = []
    agents_path = project_root / "AGENTS.md"

    if not agents_path.exists():
        errors.append("L0: AGENTS.md not found at project root")
        return errors

    content = agents_path.read_text(encoding="utf-8").strip()
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

    content = changelog_path.read_text(encoding="utf-8")

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
        errors.append(
            f"L1: Non-sequential event IDs. Found: {event_ids}, expected: {expected_ids}"
        )

    # Check for duplicate IDs
    if len(event_ids) != len(set(event_ids)):
        errors.append("L1: Duplicate event IDs found")

    # Validate event format
    for event in events:
        event_id, event_num, date, time, agent, event_type = event

        # Validate event type
        valid_types = [
            "decision", "create", "modify", "delete", "test", "fix",
            "dependency", "blocker", "milestone", "escalation", "handoff", "archive"
        ]
        if event_type not in valid_types:
            errors.append(f"L1: Invalid event type '{event_type}' in {event_id}")

        # Validate date format
        try:
            datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M")
        except ValueError:
            errors.append(f"L1: Invalid timestamp in {event_id}")

    # Check for required fields in each event
    event_sections = re.split(r'### evt-\d+', content)[1:]
    for i, section in enumerate(event_sections):
        event_id = events[i][0] if i < len(events) else f"evt-{i + 1}"
        if "**Scope**" not in section and "**Scope**:" not in section:
            errors.append(f"L1: Missing 'Scope' field in {event_id}")
        if "**Summary**" not in section and "**Summary**:" not in section:
            errors.append(f"L1: Missing 'Summary' field in {event_id}")

    return errors


def validate_graph(project_root: Path) -> list[str]:
    """Validate Layer 2: graph.md consistency."""
    errors = []
    graph_path = project_root / ".memory" / "graph.md"

    if not graph_path.exists():
        return errors

    content = graph_path.read_text(encoding="utf-8")

    # Check for required sections
    required_sections = ["## Nodes", "## Edges", "## Meta"]
    for section in required_sections:
        if section not in content:
            errors.append(f"L2: Missing '{section}' section in graph.md")

    if errors:
        return errors

    # Extract nodes (allow empty table)
    if "## Nodes" in content and "## Edges" in content:
        nodes_section = content.split("## Nodes")[1].split("##")[0]
        node_pattern = r'\| ([^|]+) \| (\w+) \| (\w+) \| (evt-\d+|—) \| (evt-\d+|—) \|'
        nodes = re.findall(node_pattern, nodes_section)
        node_names = [n[0].strip() for n in nodes]

        valid_types = ["component", "task", "dependency", "decision", "document", "milestone"]
        valid_statuses = ["active", "blocked", "completed", "deprecated", "planned"]
        for node in nodes:
            if node[1] not in valid_types:
                errors.append(f"L2: Invalid node type '{node[1]}' for node '{node[0]}'")
            if node[2] not in valid_statuses:
                errors.append(f"L2: Invalid node status '{node[2]}' for node '{node[0]}'")

        # Extract edges
        edges_section = content.split("## Edges")[1].split("##")[0]
        edge_pattern = r'\| ([^|]+) \| ([^|]+) \| (\w+) \| (evt-\d+) \|'
        edges = re.findall(edge_pattern, edges_section)

        for edge in edges:
            from_node, to_node, relation = edge[0].strip(), edge[1].strip(), edge[2]
            if from_node not in node_names:
                errors.append(f"L2: Edge references non-existent 'from' node '{from_node}'")
            if to_node not in node_names:
                errors.append(f"L2: Edge references non-existent 'to' node '{to_node}'")

        valid_relations = [
            "depends_on", "blocks", "implements", "tests", "documents",
            "contains", "precedes", "related_to"
        ]
        for edge in edges:
            if edge[2] not in valid_relations:
                errors.append(f"L2: Invalid edge relation '{edge[2]}'")

    # Validate Meta section / event horizon
    if "## Meta" in content:
        meta_section = content.split("## Meta")[1]
        horizon_match = re.search(r'\*\*Event horizon\*\*:\s*(evt-\d+|—)', meta_section)
        if horizon_match:
            horizon = horizon_match.group(1).strip()
            if horizon != "—":
                changelog_path = project_root / "CHANGELOG.md"
                if changelog_path.exists():
                    changelog_content = changelog_path.read_text(encoding="utf-8")
                    if horizon not in changelog_content:
                        errors.append(
                            f"L2: Event horizon '{horizon}' not found in CHANGELOG.md"
                        )

    return errors


def validate_context(project_root: Path) -> list[str]:
    """Validate Layer 3: context.md staleness."""
    errors = []
    context_path = project_root / ".memory" / "context.md"
    changelog_path = project_root / "CHANGELOG.md"

    if not context_path.exists():
        return errors

    if not changelog_path.exists():
        return errors

    context_content = context_path.read_text(encoding="utf-8")
    changelog_content = changelog_path.read_text(encoding="utf-8")

    # Event horizon may appear as "Event horizon:" or "**Event horizon**:"
    horizon_match = re.search(
        r'(?:\*\*)?Event horizon(?:\*\*)?:\s*(evt-\d+)',
        context_content
    )
    if not horizon_match:
        errors.append("L3: Missing 'Event horizon' in context.md")
        return errors

    context_horizon = horizon_match.group(1)
    event_pattern = r'### (evt-\d+) \|'
    events = re.findall(event_pattern, changelog_content)

    if events:
        last_event = events[-1]
        if context_horizon != last_event:
            errors.append(
                f"L3: Context is stale. Event horizon: {context_horizon}, last event: {last_event}"
            )

    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate memory system files")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
        help="Path to project root (default: current directory)",
    )
    args = parser.parse_args()

    project_root = args.project_root.resolve()

    print(f"Validating memory system at: {project_root}")
    print("-" * 50)

    all_errors = []

    for label, validator in [
        ("Layer 0: AGENTS.md", validate_agents_md),
        ("Layer 1: CHANGELOG.md", validate_changelog),
        ("Layer 2: graph.md", validate_graph),
        ("Layer 3: context.md", validate_context),
    ]:
        print(f"{label}...")
        errors = validator(project_root)
        all_errors.extend(errors)
        status = "OK" if not errors else "FAIL"
        print(f"  [{status}] {len(errors)} error(s)")

    print("-" * 50)

    if all_errors:
        print("\nValidation errors:")
        for error in all_errors:
            print(f"  - {error}")
        sys.exit(1)
    print("OK All memory system validations passed")
    sys.exit(0)


if __name__ == "__main__":
    main()
