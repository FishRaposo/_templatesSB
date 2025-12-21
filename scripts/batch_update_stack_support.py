# Batch update stack support for all tasks
import re

# Read the task-index.yaml file
with open('c:/Projects/_templates/tasks/task-index.yaml', 'r') as f:
    content = f.read()

# Define stack support levels based on our analysis
# Full support: python, node, go, nextjs (where we found implementations)
# Base-fallback: rust, typescript, flutter, react, react_native, r, sql, generic

# Pattern to match allowed_stacks sections
pattern = r'(allowed_stacks:\n(?:    - .+\n)+)'

def add_stack_support(match):
    allowed_section = match.group(1)
    
    # Extract the stacks from allowed_stacks
    stacks = re.findall(r'    - (.+)', allowed_section)
    
    # Generate stack_support based on stack name
    support_lines = ['    stack_support:']
    for stack in stacks:
        if stack in ['python', 'node', 'go', 'nextjs']:
            support_lines.append(f'      {stack}: full')
        else:
            support_lines.append(f'      {stack}: base-fallback')
    
    # Combine allowed_stacks with stack_support
    return allowed_section + '\n'.join(support_lines) + '\n'

# Apply the transformation
updated_content = re.sub(pattern, add_stack_support, content)

# Write back to file
with open('c:/Projects/_templates/tasks/task-index.yaml', 'w') as f:
    f.write(updated_content)

print("Updated task-index.yaml with stack support levels for all tasks")
