#!/usr/bin/env python3
"""
Template fixer script - Fixes all template issues systematically
"""

import os
import re
from pathlib import Path

# Template root
TEMPLATE_ROOT = Path(__file__).parent

# Node.js service template pattern
NODE_SERVICE_TEMPLATE = '''#!/usr/bin/env node
/**
 * Template: {filename}
 * Purpose: {purpose} for Node.js applications
 * Stack: node
 * Generated for: {{{{PROJECT_NAME}}}}
 */

const {{ EventEmitter }} = require('events');

/**
 * {service_name} service configuration
 */
const DEFAULT_CONFIG = {{
    enabled: true,
    timeout: 30000,
    maxRetries: 3
}};

/**
 * {service_class}Service - Manages {task_name} operations
 * @extends EventEmitter
 */
class {service_class}Service extends EventEmitter {{
    constructor(config = {{}}) {{
        super();
        this.config = {{ ...DEFAULT_CONFIG, ...config }};
        this.enabled = this.config.enabled;
        this.timeout = this.config.timeout;
        this.initialized = false;
    }}

    async initialize() {{
        if (this.initialized) return;

        try {{
            // TODO: Add initialization logic
            this.initialized = true;
            this.emit('initialized');
        }} catch (error) {{
            this.emit('error', error);
            throw error;
        }}
    }}

    async execute(inputData) {{
        if (!this.enabled) {{
            return {{ status: 'disabled', message: 'Service is disabled' }};
        }}

        const startTime = Date.now();

        try {{
            // TODO: Implement {task_name} logic here
            const result = await this._process(inputData);
            const responseTime = Date.now() - startTime;
            this.emit('success', {{ responseTime }});

            return {{ status: 'success', data: result, responseTime }};
        }} catch (error) {{
            const responseTime = Date.now() - startTime;
            this.emit('error', {{ error, responseTime }});
            return {{ status: 'error', error: error.message, responseTime }};
        }}
    }}

    async _process(inputData) {{
        // TODO: Implement {task_name} specific logic
        return inputData;
    }}

    async validate(inputData) {{
        if (!inputData || typeof inputData !== 'object') return false;
        // TODO: Add specific validation rules
        return true;
    }}

    getStatus() {{
        return {{
            status: this.initialized ? 'healthy' : 'not_initialized',
            service: '{{{{PROJECT_NAME}}}}-{task_name}',
            enabled: this.enabled,
            stack: 'node',
            uptime: process.uptime()
        }};
    }}

    async shutdown() {{
        try {{
            this.initialized = false;
            this.emit('shutdown');
        }} catch (error) {{
            this.emit('error', error);
            throw error;
        }}
    }}
}}

module.exports = {{ {service_class}Service, DEFAULT_CONFIG }};
'''

def camel_to_title(name):
    """Convert camel case to title case"""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1 \2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1 \2', s1).title()

def fix_nodejs_templates():
    """Fix all Node.js templates with wrong syntax"""
    node_tasks = [
        ('email-campaign-engine', 'EmailCampaignEngine'),
        ('embedding-index', 'EmbeddingIndex'),
        ('error-reporting', 'ErrorReporting'),
        ('feature-flags', 'FeatureFlags'),
        ('file-processing-pipeline', 'FileProcessingPipeline'),
        ('healthchecks-telemetry', 'HealthchecksTelemetry'),
        ('job-queue', 'JobQueue'),
        ('llm-prompt-router', 'LlmPromptRouter'),
        ('multitenancy', 'Multitenancy'),
        ('notification-center', 'NotificationCenter'),
        ('public-api-gateway', 'PublicApiGateway'),
        ('rest-api-service', 'RestApiService'),
        ('sample-data-generator', 'SampleDataGenerator'),
        ('scheduled-tasks', 'ScheduledTasks'),
        ('team-workspaces', 'TeamWorkspaces'),
        ('user-profile-management', 'UserProfileManagement'),
        ('web-scraping', 'WebScraping'),
        ('webhook-consumer', 'WebhookConsumer'),
        ('llm-prompt-router', 'LlmPromptRouter'),
        ('multitenancy', 'Multitenancy'),
    ]

    count = 0
    for task_name, service_class in node_tasks:
        file_path = TEMPLATE_ROOT / 'tasks' / task_name / 'stacks' / 'node' / 'base' / 'code' / f'{task_name.replace("-", "_")}_service.tpl.js'

        if file_path.exists():
            purpose = camel_to_title(service_class)
            content = NODE_SERVICE_TEMPLATE.format(
                filename=file_path.name,
                purpose=purpose,
                service_name=purpose,
                service_class=service_class,
                task_name=task_name
            )

            try:
                file_path.write_text(content)
                print(f'✅ Fixed: {file_path.relative_to(TEMPLATE_ROOT)}')
                count += 1
            except Exception as e:
                print(f'❌ Error fixing {file_path}: {e}')

    print(f'\n✅ Fixed {count} Node.js templates')
    return count

if __name__ == '__main__':
    print('Starting template fixes...\n')
    fix_nodejs_templates()
    print('\nTemplate fixes completed!')
