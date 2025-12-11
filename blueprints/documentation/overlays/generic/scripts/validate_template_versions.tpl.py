#!/usr/bin/env python3
"""
Template Version Validation Script
Validates template version metadata in tier-index.yaml
Used by GitHub Actions CI pipeline
"""

import yaml
import sys

def validate_template_versions():
    """Validate version metadata in tier-index.yaml."""
    try:
        # Load tier-index.yaml
        with open('tier-index.yaml', 'r') as f:
            config = yaml.safe_load(f)

        # Check template metadata exists
        if 'template_metadata' not in config:
            print('❌ Missing template_metadata section')
            return False

        if 'versions' not in config['template_metadata']:
            print('❌ Missing versions in template_metadata')
            return False

        versions = config['template_metadata']['versions']

        # Check all referenced templates have versions
        all_files = set()
        for tier_config in config['tiers'].values():
            all_files.update(tier_config.get('required', []))
            all_files.update(tier_config.get('recommended', []))

        missing_versions = []
        for file_name in all_files:
            if file_name not in versions:
                missing_versions.append(file_name)

        if missing_versions:
            print(f'❌ Missing versions for: {missing_versions}')
            return False

        print(f'✅ All {len(versions)} templates have version metadata')
        return True

    except Exception as e:
        print(f'❌ Validation failed: {e}')
        return False

if __name__ == "__main__":
    success = validate_template_versions()
    sys.exit(0 if success else 1)
