#!/usr/bin/env python3
"""
Add standard header comments to template files missing them.
"""

import sys
import os
from pathlib import Path

def add_header_comment(file_path):
    """Add a standard header comment to a template file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Skip if already has header comment
        if content.strip().startswith(('"""', "'''", "<!--", "/*", "#", "//")):
            return True
        
        file_name = file_path.name
        file_ext = file_path.suffix
        
        # Create appropriate header based on file type
        if file_ext in ['.py']:
            header = f'''"""
File: {file_name}
Purpose: Template for {file_path.parent.parent.name} implementation
Generated for: {{PROJECT_NAME}}
"""

'''
        elif file_ext in ['.js', '.ts', '.jsx', '.tsx']:
            header = f'''/**
 * File: {file_name}
 * Purpose: Template for {file_path.parent.parent.name} implementation
 * Generated for: {{PROJECT_NAME}}
 */

'''
        elif file_ext in ['.dart']:
            header = f'''///
/// File: {file_name}
/// Purpose: Template for {file_path.parent.parent.name} implementation
/// Generated for: {{PROJECT_NAME}}
///

'''
        elif file_ext in ['.md']:
            header = f'''<!--
File: {file_name}
Purpose: Template for {file_path.parent.parent.name} implementation
Template Version: 1.0
-->

'''
        elif file_ext in ['.sql', '.R']:
            header = f'''-- File: {file_name}
-- Purpose: Template for {file_path.parent.parent.name} implementation
-- Generated for: {{PROJECT_NAME}}

'''
        else:
            header = f'''# File: {file_name}
# Purpose: Template for {file_path.parent.parent.name} implementation
# Generated for: {{PROJECT_NAME}}

'''
        
        # Write back with header
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(header + content)
        
        print(f"Added header to: {file_path}")
        return True
        
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def process_directory(directory, extensions=None):
    """Process all template files in a directory"""
    if extensions is None:
        extensions = ['.tpl.py', '.tpl.js', '.tpl.ts', '.tpl.jsx', '.tpl.tsx', '.tpl.dart', 
                     '.tpl.md', '.tpl.sql', '.tpl.R', '.tpl.Go', '.tpl.java', '.tpl.cs']
    
    processed = 0
    errors = 0
    
    for file_path in Path(directory).rglob("*"):
        if file_path.is_file() and any(str(file_path).endswith(ext) for ext in extensions):
            if add_header_comment(file_path):
                processed += 1
            else:
                errors += 1
    
    return processed, errors

def main():
    if len(sys.argv) < 2:
        print("Usage: python add-header-comments.py <directory> [extensions...]")
        sys.exit(1)
    
    directory = sys.argv[1]
    extensions = sys.argv[2:] if len(sys.argv) > 2 else None
    
    if not Path(directory).exists():
        print(f"Error: Directory {directory} does not exist")
        sys.exit(1)
    
    print(f"Processing template files in {directory}...")
    processed, errors = process_directory(directory, extensions)
    
    print(f"\nCompleted:")
    print(f"  - Processed: {processed} files")
    print(f"  - Errors: {errors} files")

if __name__ == "__main__":
    main()
