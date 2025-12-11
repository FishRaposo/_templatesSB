#!/usr/bin/env python3
"""
Add standard header comments to all template files that are missing them.
"""

import os
import re
from pathlib import Path
from datetime import datetime

# Standard header template
HEADER_TEMPLATE = """# Universal Template System - {stack_name} Stack
# Generated: {date}
# Purpose: {purpose}
# Tier: {tier}
# Stack: {stack}
# Category: {category}
"""

def get_template_info(file_path: Path) -> dict:
    """Extract template information from file path"""
    parts = file_path.parts
    
    # Determine stack
    stack = "unknown"
    for part in parts:
        if part in ["flutter", "python", "go", "node", "react", "react_native", "next", "r", "sql", "typescript", "generic"]:
            stack = part
            break
    
    # Determine tier
    tier = "base"
    if "mvp" in parts:
        tier = "mvp"
    elif "core" in parts:
        tier = "core"
    elif "enterprise" in parts:
        tier = "enterprise"
    
    # Determine purpose from filename
    filename = file_path.stem
    if "config" in filename.lower():
        purpose = "Configuration management utilities"
    elif "data" in filename.lower() and "validation" in filename.lower():
        purpose = "Data validation utilities"
    elif "error" in filename.lower() and "handling" in filename.lower():
        purpose = "Error handling utilities"
    elif "http" in filename.lower() or "client" in filename.lower():
        purpose = "HTTP client utilities"
    elif "logging" in filename.lower():
        purpose = "Logging utilities"
    elif "testing" in filename.lower() or "test" in filename.lower():
        purpose = "Testing utilities"
    elif "integration" in filename.lower():
        purpose = "Integration tests"
    elif "unit" in filename.lower():
        purpose = "Unit tests"
    elif "widget" in filename.lower():
        purpose = "Widget tests"
    elif "component" in filename.lower():
        purpose = "Component tests"
    elif "app" in filename.lower() and "structure" in filename.lower():
        purpose = "Application structure overlay"
    elif "monetization" in filename.lower() or "hooks" in filename.lower():
        purpose = "Monetization integration hooks"
    else:
        purpose = f"{stack} template utilities"
    
    # Determine category
    if "tests" in parts:
        category = "testing"
    elif "code" in parts:
        category = "utilities"
    elif "overlays" in parts:
        category = "overlay"
    else:
        category = "template"
    
    return {
        "stack_name": stack.title(),
        "tier": tier,
        "stack": stack,
        "purpose": purpose,
        "category": category
    }

def has_header(content: str) -> bool:
    """Check if file already has a header comment"""
    lines = content.split('\n')
    for i, line in enumerate(lines[:5]):  # Check first 5 lines
        if line.strip().startswith('#') and 'Universal Template System' in line:
            return True
    return False

def add_header_to_file(file_path: Path):
    """Add header to a single template file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Skip if already has header
        if has_header(content):
            return False
        
        # Get template info
        info = get_template_info(file_path)
        
        # Create header
        header = HEADER_TEMPLATE.format(
            stack_name=info["stack_name"],
            date=datetime.now().strftime("%Y-%m-%d"),
            purpose=info["purpose"],
            tier=info["tier"],
            stack=info["stack"],
            category=info["category"]
        )
        
        # Add header to content
        new_content = header + "\n" + content
        
        # Write back
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        return True
        
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def main():
    """Main function to add headers to all template files"""
    templates_root = Path(".")
    
    # Find all template files
    template_files = []
    for pattern in ["**/*.tpl.*", "**/overlays/**/*.dart"]:
        template_files.extend(templates_root.glob(pattern))
    
    print(f"Found {len(template_files)} template files")
    
    # Add headers to files that need them
    updated_count = 0
    for file_path in template_files:
        # Skip certain directories
        if any(skip in str(file_path) for skip in ["__pycache__", ".git", "reference-projects"]):
            continue
        
        if add_header_to_file(file_path):
            print(f"Added header to: {file_path}")
            updated_count += 1
    
    print(f"\nUpdated {updated_count} template files with headers")

if __name__ == "__main__":
    main()
