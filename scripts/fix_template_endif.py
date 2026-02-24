#!/usr/bin/env python3
"""
Fix missing {% endif %} tags in all CONFIG.tpl.yaml files
"""

from pathlib import Path

def fix_endif_tags():
    """Add missing {% endif %} tags to all CONFIG.tpl.yaml files"""
    
    base_dir = Path(__file__).parent.parent
    tasks_dir = base_dir / 'tasks'
    
    fixed_count = 0
    total_count = 0
    
    # Find all CONFIG.tpl.yaml files
    config_files = list(tasks_dir.glob('*/universal/code/CONFIG.tpl.yaml'))
    
    print("🔧 Fixing missing {% endif %} tags in " + str(len(config_files)) + " CONFIG.tpl.yaml files")
    print("=" * 70)
    
    for config_file in config_files:
        total_count += 1
        task_name = config_file.parent.parent.parent.name
        
        try:
            content = config_file.read_text(encoding='utf-8')
            original_content = content
            
            # Check if file has if tags but no endif tags
            if_tags = [line for line in content.split('\n') if '{% if' in line]
            endif_tags = [line for line in content.split('\n') if '{% endif' in line]
            
            if len(if_tags) > len(endif_tags):
                # Find where to insert the endif tag (after the stack-specific section)
                lines = content.split('\n')
                insert_idx = -1
                
                for i, line in enumerate(lines):
                    if '{% endif' in line:
                        insert_idx = -1  # Already has endif
                        break
                    elif '{% if' in line:
                        # Look for the end of the if block (next section or end of file)
                        for j in range(i + 1, len(lines)):
                            if lines[j].strip() == '' or lines[j].startswith('#') or (not lines[j].startswith('  ') and not '{% elif' in lines[j]):
                                insert_idx = j
                                break
                        break
                
                if insert_idx >= 0:
                    lines.insert(insert_idx, '  {% endif %}')
                    content = '\n'.join(lines)
                    
                    if content != original_content:
                        config_file.write_text(content, encoding='utf-8')
                        fixed_count += 1
                        print(f"  ✅ Fixed {task_name}/CONFIG.tpl.yaml")
                    else:
                        print(f"  ℹ️  No fix needed for {task_name}/CONFIG.tpl.yaml")
                else:
                    print(f"  ⚠️  Could not determine insertion point for {task_name}")
            else:
                print(f"  ℹ️  No missing endif tags in {task_name}/CONFIG.tpl.yaml")
                
        except Exception as e:
            print(f"  ❌ Error processing {task_name}/CONFIG.tpl.yaml: {e}")
    
    print(f"\n📊 SUMMARY:")
    print(f"  Total files processed: {total_count}")
    print(f"  Files fixed: {fixed_count}")
    print(f"  Files with no issues: {total_count - fixed_count}")

def verify_fix():
    """Verify that all CONFIG.tpl.yaml files now have matching if/endif tags"""
    
    base_dir = Path(__file__).parent.parent
    tasks_dir = base_dir / 'tasks'
    
    config_files = list(tasks_dir.glob('*/universal/code/CONFIG.tpl.yaml'))
    
    print(f"\n🔍 Verifying fixes in {len(config_files)} CONFIG.tpl.yaml files")
    print("=" * 70)
    
    issues_found = 0
    
    for config_file in config_files:
        task_name = config_file.parent.parent.parent.name
        
        try:
            content = config_file.read_text(encoding='utf-8')
            
            if_tags = [line for line in content.split('\n') if '{% if' in line]
            endif_tags = [line for line in content.split('\n') if '{% endif' in line]
            
            if len(if_tags) != len(endif_tags):
                issues_found += 1
                print(f"  ❌ {task_name}: {len(if_tags)} if tags, {len(endif_tags)} endif tags")
            else:
                print(f"  ✅ {task_name}: Matching if/endif tags")
                
        except Exception as e:
            issues_found += 1
            print(f"  ❌ Error reading {task_name}: {e}")
    
    print(f"\n📊 VERIFICATION RESULTS:")
    print(f"  Files with matching tags: {len(config_files) - issues_found}")
    print(f"  Files with issues: {issues_found}")
    
    return issues_found == 0

if __name__ == "__main__":
    fix_endif_tags()
    success = verify_fix()
    
    if success:
        print("\n🎉 All CONFIG.tpl.yaml files have been fixed successfully!")
    else:
        print("\n⚠️  Some files still have issues. Please review manually.")
