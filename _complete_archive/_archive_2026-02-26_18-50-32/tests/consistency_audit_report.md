# Template Consistency Audit Report

Generated: audit_template_consistency.py

## Summary
- Critical Issues: 12
- Warnings: 15

## Reference Project Analysis

### File Structure Consistency

#### Flutter

**Mvp Tier:**
- Unexpected files: ['lib\\main.dart', 'test\\widget_test.dart']
- Total files: 12

**Core Tier:**
- Unexpected files: ['lib\\main.dart', 'test\\widget_test.dart']
- Total files: 6

**Enterprise Tier:**
- Unexpected files: ['lib\\main.dart', 'test\\widget_test.dart']
- Total files: 6

#### React_Native

**Mvp Tier:**
- Total files: 5

**Core Tier:**
- Total files: 5

**Enterprise Tier:**
- Total files: 5

#### React

**Mvp Tier:**
- Total files: 6

**Core Tier:**
- Total files: 6

**Enterprise Tier:**
- Total files: 6

#### Node

**Mvp Tier:**
- Total files: 5682

**Core Tier:**
- Total files: 2829

**Enterprise Tier:**
- Total files: 5

#### Go

**Mvp Tier:**
- Total files: 5

**Core Tier:**
- Total files: 5

**Enterprise Tier:**
- Total files: 5

#### Python

**Mvp Tier:**
- Total files: 11

**Core Tier:**
- Total files: 5

**Enterprise Tier:**
- Total files: 5

#### R

**Mvp Tier:**
- Unexpected files: ['analysis.R', 'requirements.txt', 'test_analysis.R']
- Total files: 7

**Core Tier:**
- Unexpected files: ['analysis.R', 'requirements.txt', 'test_analysis.R']
- Total files: 7

**Enterprise Tier:**
- Unexpected files: ['analysis.R', 'requirements.txt', 'test_analysis.R']
- Total files: 7

#### Sql

**Mvp Tier:**
- Unexpected files: ['procedures.sql', 'test_data.sql']
- Total files: 6

**Core Tier:**
- Unexpected files: ['procedures.sql', 'test_data.sql']
- Total files: 6

**Enterprise Tier:**
- Unexpected files: ['procedures.sql', 'test_data.sql']
- Total files: 6

#### Generic

**Mvp Tier:**
- Unexpected files: ['ARCHITECTURE.md', 'dependencies.txt', 'PROJECT_SUMMARY.md', 'README.md', 'validate-project.sh', 'VALIDATION_REPORT.json', 'code\\authentication-pattern.md', 'code\\config-management-pattern.md', 'code\\data-validation-pattern.md', 'code\\error-handling-pattern.md', 'code\\http-client-pattern.md', 'code\\logging-pattern.md', 'deployment\\README.md', 'docs\\setup-guide.md', 'project-structure\\README.md', 'testing-strategy\\README.md', 'tests\\integration-tests-pattern.md', 'tests\\test-utilities-pattern.md', 'tests\\unit-tests-pattern.md', 'examples\\basic\\config-examples.md', 'examples\\basic\\user-management-pseudocode.md']
- Total files: 21

**Core Tier:**
- Unexpected files: ['ARCHITECTURE.md', 'dependencies.txt', 'README.md', 'validate.sh', 'code\\authentication-pattern.md', 'code\\config-management-pattern.md', 'code\\data-validation-pattern.md', 'code\\error-handling-pattern.md', 'code\\http-client-pattern.md', 'code\\logging-pattern.md', 'deployment-patterns\\CI_CD_PIPELINES.md', 'docs\\setup-guide.md', 'observability\\OBSERVABILITY_GUIDE.md', 'testing-patterns\\TESTING_PYRAMID.md', 'tests\\integration-tests-pattern.md', 'tests\\test-utilities-pattern.md', 'tests\\unit-tests-pattern.md', 'design-patterns\\mvc-pattern\\MVC_PATTERN.md', 'design-patterns\\repository-pattern\\REPOSITORY_PATTERN.md', 'design-patterns\\service-layer\\SERVICE_LAYER.md']
- Total files: 20

**Enterprise Tier:**
- Unexpected files: ['ARCHITECTURE.md', 'dependencies.txt', 'README.md', 'code\\authentication-pattern.md', 'code\\config-management-pattern.md', 'code\\data-validation-pattern.md', 'code\\error-handling-pattern.md', 'code\\http-client-pattern.md', 'code\\logging-pattern.md', 'compliance\\regulatory-mapping.md', 'disaster-recovery\\business-continuity-plan.md', 'docs\\setup-guide.md', 'enterprise-patterns\\domain-driven-design.md', 'governance\\it-governance-framework.md', 'migration\\assessment-framework.md', 'monitoring\\enterprise-monitoring.md', 'multi-cloud\\deployment-strategies.md', 'security\\enterprise-security-framework.md', 'tests\\integration-tests-pattern.md', 'tests\\test-utilities-pattern.md', 'tests\\unit-tests-pattern.md']
- Total files: 21

#### Typescript

**Mvp Tier:**
- Unexpected files: ['.eslintrc.js', 'jest.config.js', 'package.json', 'README.md', 'tsconfig.json', 'src\\app.ts', 'src\\index.ts', 'tests\\app.test.ts', 'src\\routes\\index.ts', 'src\\test\\setup.ts', 'src\\__tests__\\app.test.ts']
- Total files: 13

**Core Tier:**
- Unexpected files: ['.eslintrc.js', '.eslintrc.json', 'jest.config.js', 'package.json', 'README.md', 'tsconfig.json', 'src\\app.ts', 'src\\index.ts', 'tests\\setup.ts', 'tests\\integration\\user.routes.test.ts', 'tests\\unit\\user.service.test.ts', 'src\\config\\database.ts', 'src\\controllers\\auth.controller.ts', 'src\\controllers\\user.controller.ts', 'src\\middleware\\auth.middleware.ts', 'src\\middleware\\error.middleware.ts', 'src\\middleware\\logger.middleware.ts', 'src\\migrations\\1733929200000-CreateUsersTable.ts', 'src\\models\\user.model.ts', 'src\\routes\\auth.routes.ts', 'src\\routes\\index.ts', 'src\\routes\\user.routes.ts', 'src\\services\\user.service.ts', 'src\\test\\setup.ts', 'src\\__tests__\\app.test.ts']
- Total files: 28

**Enterprise Tier:**
- Unexpected files: ['.eslintrc.js', 'jest.config.js', 'package.json', 'README.md', 'tsconfig.json', 'src\\app.ts', 'src\\index.ts', 'src\\config\\config.ts', 'src\\config\\database.ts', 'src\\config\\rabbitmq.ts', 'src\\config\\redis.ts', 'src\\events\\eventbus.ts', 'src\\middleware\\auth.middleware.ts', 'src\\test\\setup.ts', 'src\\utils\\logger.ts', 'src\\utils\\metrics.ts', 'src\\utils\\tracer.ts', 'src\\__tests__\\app.test.ts']
- Total files: 19

## Critical Issues

1. r/mvp: Missing sections: ['## Overview', '## Setup']
2. r/core: Missing sections: ['## Overview', '## Setup']
3. r/enterprise: Missing sections: ['## Overview', '## Setup']
4. sql/mvp: Missing sections: ['## Overview', '## Setup']
5. sql/core: Missing sections: ['## Overview', '## Setup']
6. sql/enterprise: Missing sections: ['## Overview', '## Setup']
7. generic/mvp: Missing sections: ['## Overview', '## Features', '## Setup', '## Testing']
8. generic/core: Missing sections: ['## Overview', '## Features', '## Setup', '## Testing']
9. generic/enterprise: Missing sections: ['## Overview', '## Features', '## Setup', '## Testing']
10. typescript/mvp: Missing sections: ['## Overview', '## Features', '## Setup', '## Testing']
11. typescript/core: Missing sections: ['## Overview', '## Features', '## Setup', '## Testing']
12. typescript/enterprise: Missing sections: ['## Overview', '## Features', '## Setup', '## Testing']

## Warnings

1. flutter/mvp: Unexpected files: ['lib\\main.dart', 'test\\widget_test.dart']
2. flutter/core: Unexpected files: ['lib\\main.dart', 'test\\widget_test.dart']
3. flutter/enterprise: Unexpected files: ['lib\\main.dart', 'test\\widget_test.dart']
4. r/mvp: Unexpected files: ['analysis.R', 'requirements.txt', 'test_analysis.R']
5. r/core: Unexpected files: ['analysis.R', 'requirements.txt', 'test_analysis.R']
6. r/enterprise: Unexpected files: ['analysis.R', 'requirements.txt', 'test_analysis.R']
7. sql/mvp: Unexpected files: ['procedures.sql', 'test_data.sql']
8. sql/core: Unexpected files: ['procedures.sql', 'test_data.sql']
9. sql/enterprise: Unexpected files: ['procedures.sql', 'test_data.sql']
10. generic/mvp: Unexpected files: ['ARCHITECTURE.md', 'dependencies.txt', 'PROJECT_SUMMARY.md', 'README.md', 'validate-project.sh', 'VALIDATION_REPORT.json', 'code\\authentication-pattern.md', 'code\\config-management-pattern.md', 'code\\data-validation-pattern.md', 'code\\error-handling-pattern.md', 'code\\http-client-pattern.md', 'code\\logging-pattern.md', 'deployment\\README.md', 'docs\\setup-guide.md', 'project-structure\\README.md', 'testing-strategy\\README.md', 'tests\\integration-tests-pattern.md', 'tests\\test-utilities-pattern.md', 'tests\\unit-tests-pattern.md', 'examples\\basic\\config-examples.md', 'examples\\basic\\user-management-pseudocode.md']
11. generic/core: Unexpected files: ['ARCHITECTURE.md', 'dependencies.txt', 'README.md', 'validate.sh', 'code\\authentication-pattern.md', 'code\\config-management-pattern.md', 'code\\data-validation-pattern.md', 'code\\error-handling-pattern.md', 'code\\http-client-pattern.md', 'code\\logging-pattern.md', 'deployment-patterns\\CI_CD_PIPELINES.md', 'docs\\setup-guide.md', 'observability\\OBSERVABILITY_GUIDE.md', 'testing-patterns\\TESTING_PYRAMID.md', 'tests\\integration-tests-pattern.md', 'tests\\test-utilities-pattern.md', 'tests\\unit-tests-pattern.md', 'design-patterns\\mvc-pattern\\MVC_PATTERN.md', 'design-patterns\\repository-pattern\\REPOSITORY_PATTERN.md', 'design-patterns\\service-layer\\SERVICE_LAYER.md']
12. generic/enterprise: Unexpected files: ['ARCHITECTURE.md', 'dependencies.txt', 'README.md', 'code\\authentication-pattern.md', 'code\\config-management-pattern.md', 'code\\data-validation-pattern.md', 'code\\error-handling-pattern.md', 'code\\http-client-pattern.md', 'code\\logging-pattern.md', 'compliance\\regulatory-mapping.md', 'disaster-recovery\\business-continuity-plan.md', 'docs\\setup-guide.md', 'enterprise-patterns\\domain-driven-design.md', 'governance\\it-governance-framework.md', 'migration\\assessment-framework.md', 'monitoring\\enterprise-monitoring.md', 'multi-cloud\\deployment-strategies.md', 'security\\enterprise-security-framework.md', 'tests\\integration-tests-pattern.md', 'tests\\test-utilities-pattern.md', 'tests\\unit-tests-pattern.md']
13. typescript/mvp: Unexpected files: ['.eslintrc.js', 'jest.config.js', 'package.json', 'README.md', 'tsconfig.json', 'src\\app.ts', 'src\\index.ts', 'tests\\app.test.ts', 'src\\routes\\index.ts', 'src\\test\\setup.ts', 'src\\__tests__\\app.test.ts']
14. typescript/core: Unexpected files: ['.eslintrc.js', '.eslintrc.json', 'jest.config.js', 'package.json', 'README.md', 'tsconfig.json', 'src\\app.ts', 'src\\index.ts', 'tests\\setup.ts', 'tests\\integration\\user.routes.test.ts', 'tests\\unit\\user.service.test.ts', 'src\\config\\database.ts', 'src\\controllers\\auth.controller.ts', 'src\\controllers\\user.controller.ts', 'src\\middleware\\auth.middleware.ts', 'src\\middleware\\error.middleware.ts', 'src\\middleware\\logger.middleware.ts', 'src\\migrations\\1733929200000-CreateUsersTable.ts', 'src\\models\\user.model.ts', 'src\\routes\\auth.routes.ts', 'src\\routes\\index.ts', 'src\\routes\\user.routes.ts', 'src\\services\\user.service.ts', 'src\\test\\setup.ts', 'src\\__tests__\\app.test.ts']
15. typescript/enterprise: Unexpected files: ['.eslintrc.js', 'jest.config.js', 'package.json', 'README.md', 'tsconfig.json', 'src\\app.ts', 'src\\index.ts', 'src\\config\\config.ts', 'src\\config\\database.ts', 'src\\config\\rabbitmq.ts', 'src\\config\\redis.ts', 'src\\events\\eventbus.ts', 'src\\middleware\\auth.middleware.ts', 'src\\test\\setup.ts', 'src\\utils\\logger.ts', 'src\\utils\\metrics.ts', 'src\\utils\\tracer.ts', 'src\\__tests__\\app.test.ts']
