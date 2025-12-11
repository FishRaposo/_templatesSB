#!/usr/bin/env python3
"""
System Repair Script
Fixes corrupted templates, renames files, and standardizes headers.
"""

import os
import re
import sys
from pathlib import Path

def get_canonical_header(file_path):
    """Generate the canonical header for a file"""
    file_name = file_path.name
    file_ext = file_path.suffix

    # Extract task name (parent dir name usually)
    # structure: tasks/task-name/stacks/stack-name/...
    parts = file_path.parts
    task_name = "unknown"
    if "tasks" in parts:
        try:
            task_idx = parts.index("tasks")
            task_name = parts[task_idx + 1]
        except IndexError:
            pass

    if file_ext in ['.py']:
        return f'''"""
File: {file_name}
Purpose: Template for {task_name} implementation
Generated for: {{{{PROJECT_NAME}}}}
"""

'''
    elif file_ext in ['.js', '.ts', '.jsx', '.tsx']:
        return f'''/**
 * File: {file_name}
 * Purpose: Template for {task_name} implementation
 * Generated for: {{{{PROJECT_NAME}}}}
 */

'''
    elif file_ext in ['.dart']:
        return f'''///
/// File: {file_name}
/// Purpose: Template for {task_name} implementation
/// Generated for: {{{{PROJECT_NAME}}}}
///

'''
    elif file_ext in ['.md']:
        return f'''<!--
File: {file_name}
Purpose: Template for {task_name} implementation
Template Version: 1.0
-->

'''
    elif file_ext in ['.sql', '.R']:
        return f'''-- File: {file_name}
-- Purpose: Template for {task_name} implementation
-- Generated for: {{{{PROJECT_NAME}}}}

'''
    elif file_ext in ['.go']:
        return f'''// File: {file_name}
// Purpose: Template for {task_name} implementation
// Generated for: {{{{PROJECT_NAME}}}}

'''
    else:
        return f'''# File: {file_name}
# Purpose: Template for {task_name} implementation
# Generated for: {{{{PROJECT_NAME}}}}

'''

def strip_headers(content):
    """Remove known bad headers from the top of the file"""

    # Patterns to match headers
    patterns = [
        # The # Universal Template System header
        r'^# Universal Template System[\s\S]*?(?=\n\n|\n[^\#]|$)',
        # The /** Template: ... */ header
        r'^\/\*\*[\s\S]*?Template:[\s\S]*?\*\/',
        # The /** File: ... */ header (our own canonical, remove to regenerate)
        r'^\/\*\*[\s\S]*?File:[\s\S]*?\*\/',
        # The // FILE: header
        r'^\/\/ FILE:[\s\S]*?(?=\n\n|\n[^\/]|$)',
        # The // Template: header
        r'^\/\/ Template:[\s\S]*?(?=\n\n|\n[^\/]|$)',
        # The /// Template: header (Dart)
        r'^\/\/\/ Template:[\s\S]*?(?=\n\n|\n[^\/]|$)',
        # The /// File: header (Dart canonical)
        r'^\/\/\/[\s\S]*?File:[\s\S]*?(?=\n\n|\n[^\/]|$)',
        # The # File: header (old canonical)
        r'^# File:[\s\S]*?(?=\n\n|\n[^\#]|$)',
        # Python """ File: ... """ header
        r'^"""[\s\S]*?File:[\s\S]*?"""',
        # HTML <!-- File: ... --> header
        r'^<!--[\s\S]*?File:[\s\S]*?-->',
    ]

    # Handle shebang
    shebang = ""
    if content.startswith("#!"):
        lines = content.split('\n')
        shebang = lines[0] + "\n"
        content = '\n'.join(lines[1:])

    content = content.lstrip()

    # Iteratively remove headers until none match
    changed = True
    while changed:
        changed = False
        content = content.lstrip()
        for pattern in patterns:
            match = re.match(pattern, content)
            if match:
                content = content[match.end():]
                changed = True
                break

    return shebang + content.lstrip()

def fix_file(file_path):
    """Fix a single file: rename if needed, fix header"""

    # Rename .jsx to .tsx
    if file_path.name.endswith('.tpl.jsx') and 'tasks' in file_path.parts:
        new_path = file_path.with_suffix('.tsx') # .tpl.tsx
        # wait, suffix of .tpl.jsx is .jsx. with_suffix('.tsx') -> .tpl.tsx. Correct.
        try:
            if not new_path.exists():
                file_path.rename(new_path)
                print(f"Renamed {file_path.name} -> {new_path.name}")
                file_path = new_path
            else:
                print(f"Skipping rename {file_path.name} -> {new_path.name} (target exists)")
                # If target exists, maybe we should fix target and delete source?
                # For now, let's process the source as is, or maybe checking target is enough.
                # If we renamed it in previous run, file_path (the old name) shouldn't exist in iterdir logic?
                # But here we are processing `file_path` passed from `rglob`.
                # If `rglob` found .jsx, it exists.
                pass
        except Exception as e:
            print(f"Error renaming {file_path}: {e}")
            return

    # Read content
    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return

    # Clean content
    cleaned = strip_headers(content)

    # Add new header
    header = get_canonical_header(file_path)
    new_content = header + cleaned

    # Write back
    if new_content != content:
        try:
            file_path.write_text(new_content, encoding='utf-8')
            print(f"Fixed headers in {file_path.name}")
        except Exception as e:
            print(f"Error writing {file_path}: {e}")

def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    root = Path(target_dir)
    print(f"Starting repair in {root}...")

    # Find all templates
    files = list(root.rglob('*.tpl.*'))

    print(f"Found {len(files)} files to check.")

    for file_path in files:
        if '.git' in file_path.parts:
            continue

        fix_file(file_path)

    print("Repair complete.")

if __name__ == "__main__":
    main()
