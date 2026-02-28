# Configuration constants shared between scaffold.py and validate.py

TIERS = {"mvp", "core", "full"}
STACKS = {"python", "node", "go", "generic"}

TIER_FILES = {
    "mvp": [
        "AGENTS.md",
        "CHANGELOG.md",
        "README.md",
        ".memory/context.md",
    ],
    "core": [
        "AGENTS.md",
        "CHANGELOG.md",
        "README.md",
        "TODO.md",
        "QUICKSTART.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        ".memory/graph.md",
        ".memory/context.md",
        "docs/SYSTEM-MAP.md",
        "docs/PROMPT-VALIDATION.md",
    ],
    "full": [
        "AGENTS.md",
        "CHANGELOG.md",
        "README.md",
        "TODO.md",
        "QUICKSTART.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "WORKFLOW.md",
        "CODE_OF_CONDUCT.md",
        "LICENSE.md",
        "EVALS.md",
        "DOCUMENTATION-OVERVIEW.md",
        ".memory/graph.md",
        ".memory/context.md",
        "docs/SYSTEM-MAP.md",
        "docs/PROMPT-VALIDATION.md",
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/CODEOWNERS",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/ISSUE_TEMPLATE/bug_report.md",
        ".github/ISSUE_TEMPLATE/feature_request.md",
    ],
}

REQUIRED_SECTIONS = {
    "AGENTS.md": [
        "## Project Identity",
        "## Do",
        "## Don't",
        "## Workflow",
        "## Three Pillars",
    ],
    "CHANGELOG.md": ["## Event Log"],
    "README.md": ["## What It Does", "## Quick Start", "## Key Features"],
    "TODO.md": ["## Active", "## Done"],
    "QUICKSTART.md": ["## Prerequisites", "## Installation", "## First Run"],
    "CONTRIBUTING.md": [
        "## Reporting Bugs",
        "## Development Setup",
        "## Pull Request Process",
    ],
    "SECURITY.md": ["## Supported Versions", "## Reporting a Vulnerability"],
    ".memory/graph.md": ["## Nodes", "## Edges", "## Meta"],
    ".memory/context.md": ["## Active Mission", "## Next Actions"],
    "docs/SYSTEM-MAP.md": ["## System Overview", "## Component Inventory"],
}

CORE_PLACEHOLDERS = {
    "PROJECT_NAME",
    "PROJECT_DESCRIPTION",
    "PROJECT_TAGLINE",
    "REPO_URL",
    "TIER",
    "STACK",
    "LICENSE_NAME",
}

REQUIRED_SECTIONS_FULL = {
    "AGENTS.md": [
        "## Project Identity",
        "## Do",
        "## Don't",
        "## File Naming",
        "## Workflow",
        "## Three Pillars",
        "## Memory System",
        "## Prompt Validation",
    ],
    "CHANGELOG.md": ["## Event Format", "## Event Log"],
    "README.md": [
        "## What It Does",
        "## Quick Start",
        "## Key Features",
        "## Tech Stack",
    ],
    "TODO.md": ["## Active", "## In Progress", "## Blocked", "## Done"],
    "QUICKSTART.md": [
        "## Prerequisites",
        "## Installation",
        "## First Run",
        "## Common Errors",
    ],
    "CONTRIBUTING.md": [
        "## Reporting Bugs",
        "## Feature Requests",
        "## Development Setup",
        "## Pull Request Process",
    ],
    "SECURITY.md": [
        "## Supported Versions",
        "## Reporting a Vulnerability",
        "## Response Timeline",
    ],
    ".memory/graph.md": ["## Nodes", "## Edges", "## Meta"],
    ".memory/context.md": [
        "## Active Mission",
        "## Active Tasks",
        "## Constraints",
        "## Blockers",
        "## Recent Changes",
        "## Next Actions",
    ],
    "docs/SYSTEM-MAP.md": [
        "## System Overview",
        "## Component Inventory",
        "## Data Flow",
        "## Dependency Map",
    ],
    "WORKFLOW.md": ["## Branching", "## Release"],
    "CODE_OF_CONDUCT.md": ["## Our Pledge", "## Enforcement"],
    "LICENSE.md": [],
    "EVALS.md": ["## Metrics", "## Benchmarks"],
    "DOCUMENTATION-OVERVIEW.md": [
        "## Root-Level Documents",
        "## docs/ Directory",
        "## Memory System",
    ],
}
