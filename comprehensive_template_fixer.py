#!/usr/bin/env python3
"""
Comprehensive template fixer - Fixes all remaining template issues
"""

import os
import re
from pathlib import Path

TEMPLATE_ROOT = Path(__file__).parent

# Go service template pattern
GO_SERVICE_TEMPLATE = '''// {{{{SERVICE_NAME}}}} Service for Go
// Generated for {{{{PROJECT_NAME}}}}
package {{{{package}}}}

import (
    "context"
)

// {{{{ServiceClass}}}}Service handles {{{{task_name}}}} operations
type {{{{ServiceClass}}}}Service struct {{
    config  map[string]interface{{}}
    enabled bool
    timeout int
}}

// Config holds service configuration
type Config struct {{
    Enabled bool
    Timeout int
}}

// New{{{{ServiceClass}}}}Service creates a new service instance
func New{{{{ServiceClass}}}}Service(cfg Config) *{{{{ServiceClass}}}}Service {{
    return &{{{{ServiceClass}}}}Service{{
        config:  make(map[string]interface{{}}),
        enabled: cfg.Enabled,
        timeout: cfg.Timeout,
    }}
}}

// Execute runs the {{{{task_name}}}} service
func (s *{{{{ServiceClass}}}}Service) Execute(ctx context.Context, input map[string]interface{{}}) (map[string]interface{{}}, error) {{
    // TODO: Implement {{{{task_name}}}} logic
    return map[string]interface{{}}{{"status": "success", "data": input}}, nil
}}

// GetStatus returns service health status
func (s *{{{{ServiceClass}}}}Service) GetStatus() map[string]interface{{}} {{
    return map[string]interface{{}}{{"status": "healthy", "service": "{{{{PROJECT_NAME}}}}-{{{{task_name}}}}", "enabled": s.enabled, "stack": "go"}}
}}

// Shutdown gracefully stops the service
func (s *{{{{ServiceClass}}}}Service) Shutdown() error {{
    s.enabled = false
    return nil
}}
'''

def camel_case_to_snake_case(name):
    """Convert camelCase to snake_case"""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def title_case(text):
    """Convert snake_case or camelCase to Title Case"""
    return ' '.join(word.capitalize() for word in re.split(r'[-_]', text))

def fix_go_templates():
    """Fix all 20 Go templates with wrong Python syntax"""
    go_tasks = [
        ('admin-panel', 'AdminPanel'),
        ('analytics-event-pipeline', 'AnalyticsEventPipeline'),
        ('audit-logging', 'AuditLogging'),
        ('canary-release', 'CanaryRelease'),
        ('config-management', 'ConfigManagement'),
        ('crud-module', 'CrudModule'),
        ('error-reporting', 'ErrorReporting'),
        ('etl-pipeline', 'EtlPipeline'),
        ('feature-flags', 'FeatureFlags'),
        ('file-processing-pipeline', 'FileProcessingPipeline'),
        ('healthchecks-telemetry', 'HealthchecksTelemetry'),
        ('job-queue', 'JobQueue'),
        ('link-monitoring', 'LinkMonitoring'),
        ('multitenancy', 'Multitenancy'),
        ('public-api-gateway', 'PublicApiGateway'),
        ('rest-api-service', 'RestApiService'),
        ('scheduled-tasks', 'ScheduledTasks'),
        ('seo-rank-tracker', 'SeoRankTracker'),
        ('web-scraping', 'WebScraping'),
        ('webhook-consumer', 'WebhookConsumer'),
    ]

    count = 0
    for task_name, service_class in go_tasks:
        file_path = TEMPLATE_ROOT / 'tasks' / task_name / 'stacks' / 'go' / 'base' / 'code' / f'{camel_case_to_snake_case(service_class)}_service.tpl.go'

        if file_path.exists():
            service_name = title_case(service_class)
            content = GO_SERVICE_TEMPLATE.replace(
                '{{{{SERVICE_NAME}}}}', service_name
            ).replace(
                '{{{{PROJECT_NAME}}}}', '{{PROJECT_NAME}}'
            ).replace(
                '{{{{ServiceClass}}}}', service_class
            ).replace(
                '{{{{task_name}}}}', task_name
            ).replace(
                '{{{{package}}}}', camel_case_to_snake_case(service_class)
            )

            try:
                file_path.write_text(content, encoding='utf-8')
                print(f'[OK] Fixed: {file_path.relative_to(TEMPLATE_ROOT)}')
                count += 1
            except Exception as e:
                print(f'[ERROR] Error fixing {file_path}: {e}')

    print(f'\n[OK] Fixed {count} Go templates')
    return count

def fix_jsx_to_tsx():
    """Rename 13 .tpl.jsx files to .tpl.tsx"""
    jsx_tasks = [
        'admin-panel', 'auth-oauth', 'config-management', 'crud-module',
        'docs-site', 'email-campaign-engine', 'feature-flags', 'landing-page',
        'notification-center', 'seo-onpage-auditor', 'team-workspaces',
        'user-profile-management', 'web-dashboard'
    ]

    count = 0
    for task_name in jsx_tasks:
        jsx_file = TEMPLATE_ROOT / 'tasks' / task_name / 'stacks' / 'react' / 'base' / 'code' / f'{camel_case_to_snake_case(task_name)}_component.tpl.jsx'
        tsx_file = TEMPLATE_ROOT / 'tasks' / task_name / 'stacks' / 'react' / 'base' / 'code' / f'{camel_case_to_snake_case(task_name)}_component.tpl.tsx'

        if jsx_file.exists() and not tsx_file.exists():
            try:
                jsx_file.rename(tsx_file)
                print(f'[OK] Renamed: {jsx_file.name} -> {tsx_file.name}')
                count += 1
            except Exception as e:
                print(f'[ERROR] Error renaming {jsx_file}: {e}')

    print(f'\n[OK] Renamed {count} JSX files to TSX')
    return count

def add_header_comments():
    """Add standardized header comments to 80 files without them"""

    headers = {
        '.js': '''/**
 * Template: {filename}
 * Purpose: {purpose}
 * Stack: node
 * Tier: {tier}
 */

''',
        '.jsx': '''/**
 * Template: {filename}
 * Purpose: {purpose}
 * Stack: react
 * Tier: {tier}
 */

''',
        '.tsx': '''/**
 * Template: {filename}
 * Purpose: {purpose}
 * Stack: typescript
 * Tier: {tier}
 */

''',
        '.ts': '''/**
 * Template: {filename}
 * Purpose: {purpose}
 * Stack: typescript
 * Tier: {tier}
 */

''',
        '.go': '''// Template: {filename}
// Purpose: {purpose}
// Stack: go
// Tier: {tier}

''',
        '.dart': '''/// Template: {filename}
/// Purpose: {purpose}
/// Stack: flutter
/// Tier: {tier}

''',
    }

    count = 0
    for root, dirs, files in os.walk(TEMPLATE_ROOT):
        for file in files:
            if not file.endswith('.tpl.md'):
                for ext, header_template in headers.items():
                    if file.endswith(f'.tpl{ext}'):
                        file_path = Path(root) / file
                        try:
                            content = file_path.read_text(encoding='utf-8')
                        except UnicodeDecodeError:
                            try:
                                content = file_path.read_text(encoding='cp1252')
                            except:
                                continue

                        # Skip if already has header
                        if content.startswith(('/**', '//', '///', '"""')):
                            continue

                        # Determine tier and purpose
                        tier = 'core' if '/core/' in str(file_path) else 'mvp' if '/mvp/' in str(file_path) else 'enterprise' if '/enterprise/' in str(file_path) else 'base'
                        purpose = f'{file.replace(".tpl", "").replace(ext, "")} template'

                        header = header_template.format(filename=file, purpose=purpose, tier=tier)
                        new_content = header + content

                        try:
                            file_path.write_text(new_content, encoding='utf-8')
                            print(f'[OK] Added header: {file_path.relative_to(TEMPLATE_ROOT)}')
                            count += 1
                        except Exception as e:
                            pass  # Skip files that can't be written

    print(f'\n[OK] Added headers to {count} files')
    return count

if __name__ == '__main__':
    print('Starting comprehensive template fixes...\n')
    print('=== Phase 2: Fixing Go Templates ===')
    go_count = fix_go_templates()

    print('\n=== Phase 4: Renaming JSX to TSX ===')
    jsx_count = fix_jsx_to_tsx()

    print('\n=== Phase 5: Adding Header Comments ===')
    header_count = add_header_comments()

    print(f'\n[OK] TOTAL FIXES COMPLETED:')
    print(f'   - Go templates: {go_count}')
    print(f'   - JSX->TSX renames: {jsx_count}')
    print(f'   - Header comments: {header_count}')
    print('\nComprehensive template fixes completed!')
