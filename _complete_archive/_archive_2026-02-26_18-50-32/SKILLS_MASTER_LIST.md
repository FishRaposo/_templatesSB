# Skills Master List

**Total Skills**: 766 (all unique)  
**Total Packs**: 60 (50 core + 10 bonus)  
**Categories**: 14  
**Completed**: 3 of 50 — [`1-programming-core`](skill-packs/1-programming-core/PACK.md), [`2-code-quality`](skill-packs/2-code-quality/PACK.md), [`3-testing-mastery`](skill-packs/3-testing-mastery/PACK.md)  
**Pack Location**: `skill-packs/{pack-id}/`  
**Updated**: 2026-02-15

---

## How to Use This File

This is the **single source of truth** for all agent skills across all packs. Every skill is actionable and directly invocable.

### For AI Agents
- Find the right skill by scanning the category that matches your task
- Cross-reference with completed pack reference files for working implementations
- Each skill answers: *"What can the agent help me DO?"*

### For Pack Builders
- Use [`skill-packs/HOW_TO_CREATE_SKILL_PACKS.md`](skill-packs/HOW_TO_CREATE_SKILL_PACKS.md) to build new packs
- Use [`skill-packs/TASKS-TEMPLATE.md`](skill-packs/TASKS-TEMPLATE.md) to create verification tasks
- Pull source material from [`ARCHIVE_INDEX.md`](ARCHIVE_INDEX.md) (see cross-references below)

### Completed Pack Reference Files

Pack 1 (`1-programming-core`) has 19 standalone reference files — use these as context for programming tasks:

| Reference File | Topics |
|----------------|--------|
| [`sorting-algorithms.md`](skill-packs/1-programming-core/_reference-files/sorting-algorithms.md) | Merge Sort, Heap Sort, Binary Search |
| [`hashmap-implementation.md`](skill-packs/1-programming-core/_reference-files/hashmap-implementation.md) | HashMap from scratch, separate chaining |
| [`algorithm-optimization-patterns.md`](skill-packs/1-programming-core/_reference-files/algorithm-optimization-patterns.md) | Hash set optimization, memoization |
| [`dynamic-programming-lis.md`](skill-packs/1-programming-core/_reference-files/dynamic-programming-lis.md) | LIS: brute force → DP → binary search |
| [`payment-gateway-abstraction.md`](skill-packs/1-programming-core/_reference-files/payment-gateway-abstraction.md) | Dependency Inversion, swappable backends |
| [`modular-architecture-guide.md`](skill-packs/1-programming-core/_reference-files/modular-architecture-guide.md) | Monolith → modules (Python/JS) |
| [`recursion-patterns.md`](skill-packs/1-programming-core/_reference-files/recursion-patterns.md) | Flatten, Tower of Hanoi, permutations |
| [`iteration-patterns.md`](skill-packs/1-programming-core/_reference-files/iteration-patterns.md) | Sliding window, generators, chunked processing |
| [`functional-programming-patterns.md`](skill-packs/1-programming-core/_reference-files/functional-programming-patterns.md) | Pure functions, composition, pipe/compose |
| [`runtime-type-validation.md`](skill-packs/1-programming-core/_reference-files/runtime-type-validation.md) | Schema validation library (JS/Python) |
| [`state-machine-pattern.md`](skill-packs/1-programming-core/_reference-files/state-machine-pattern.md) | Order lifecycle, guard clauses |
| [`python-decorator-patterns.md`](skill-packs/1-programming-core/_reference-files/python-decorator-patterns.md) | @timed, @retry, @validate, metaclasses |
| [`lru-cache-implementation.md`](skill-packs/1-programming-core/_reference-files/lru-cache-implementation.md) | HashMap + Doubly Linked List, O(1) ops |
| [`plugin-system-architecture.md`](skill-packs/1-programming-core/_reference-files/plugin-system-architecture.md) | Plugin interface, dependency resolution |
| [`data-pipeline-architecture.md`](skill-packs/1-programming-core/_reference-files/data-pipeline-architecture.md) | Lazy streaming, top-K selection |
| [`topk-optimization.md`](skill-packs/1-programming-core/_reference-files/topk-optimization.md) | O(n log n) → O(n) with heap + bucket sort |
| [`code-generation-patterns.md`](skill-packs/1-programming-core/_reference-files/code-generation-patterns.md) | CRUD scaffolding, topological sort |
| [`json-query-engine.md`](skill-packs/1-programming-core/_reference-files/json-query-engine.md) | Recursive descent parser, JSON traversal |
| [`in-memory-database-engine.md`](skill-packs/1-programming-core/_reference-files/in-memory-database-engine.md) | Complete DB: B-tree, SQL parser, transactions |

> **Full index**: [`skill-packs/1-programming-core/_reference-files/INDEX.md`](skill-packs/1-programming-core/_reference-files/INDEX.md)

### Archive Cross-References

Source material for building new packs lives in [`ARCHIVE_INDEX.md`](ARCHIVE_INDEX.md). All paths below are relative to `_complete_archive/`.

#### Source Material

| Need | Archive Location |
|------|-----------------|
| **1,014-skill deep inventory** | `_supporting-files/COMPREHENSIVE_SKILLS_INVENTORY.md` |
| **20 thematic packs (alternate org)** | `_supporting-files/SKILLS_THEMATIC_PACKS.md` |
| **Skill format specification** | `_supporting-files/UNIVERSAL_SKILL_STANDARDS.md` |
| **Gold standard SKILL.md examples** | `agent-skills-main/skills/react-best-practices/` |
| **Machine-readable skill DB** | `_supporting-files/skills_database_final.json` |
| **47 task templates (code)** | `_templates-main/tasks/` |
| **12 stack-specific patterns** | `_templates-main/stacks/` |
| **5 project blueprints** | `_templates-main/blueprints/` |
| **Agent-specific guides** | `_templates-main/CLAUDE.md`, `CURSOR.md`, `WINDSURF.md`, etc. |

#### Category → Archive Feature Catalog Mapping

Use this to find relevant source material when building packs in each category. Archive Feature Catalog is in [`ARCHIVE_INDEX.md` §10](ARCHIVE_INDEX.md#10-feature-catalog-by-domain).

| Master List Category | Archive Feature Catalog | Archive Task Templates |
|---------------------|------------------------|----------------------|
| **1. Programming Fundamentals** (1-4) | §A Core Software Engineering | `project-bootstrap`, `docs-site` |
| **2. Software Architecture** (5-8) | §A Architecture, Design Patterns | — |
| **3. Backend Development** (9-12) | §C Backend, DevOps | `rest-api-service`, `graphql-api`, `ci-template` |
| **4. Frontend Development** (13-16) | §B Web Development, Frontend | `web-dashboard`, `landing-page` |
| **5. Data & Analytics** (17-20) | §D Data Engineering, Analytics | `etl-pipeline`, `analytics-event-pipeline`, `data-exploration-report` |
| **6. Cloud & Infrastructure** (21-25) | §C Cloud, DevOps, Networking | `healthchecks-telemetry`, `config-management`, `canary-release` |
| **7. AI & Intelligent Systems** (26-28) | §D AI/ML, Agentic AI, MLOps | `llm-prompt-router`, `rag-pipeline`, `agentic-workflow`, `embedding-index` |
| **8. Mobile Development** (29-30) | §F Mobile, Cross-Platform | — |
| **9. Development Practices** (31-35) | §A Code Quality, DevEx, Documentation | `feature-flags`, `audit-logging` |
| **10. Development Tools** (36-38) | §A DevEx, Automation | `sample-data-generator`, `code-refactor-agent` |
| **11. Data & Integration** (39-41) | §C API, Integration | `public-api-gateway`, `webhook-consumer` |
| **12. Advanced Systems** (42-46) | §C Backend, §A Architecture | — |
| **13. Industry & Platform** (47-50) | §G Industry Verticals, §E Security/Compliance | `billing-stripe`, `auth-oauth`, `email-campaign-engine` |
| **14. Bonus Skills** (51-60) | §G Gaming, §H Emerging Tech | — |

#### Archive Thematic Packs → Master List Mapping

The archive's 20 thematic packs (1,014 skills) overlap with but are organized differently from this master list. Use them as **supplementary source material**, not as a replacement.

| Archive Thematic Pack | Closest Master List Packs |
|----------------------|--------------------------|
| Foundation (1) + Dev Core (2) | 1-4 (Programming Fundamentals) |
| Operations (3) + Cloud/DevOps (4) | 12, 21-25 (DevOps, Cloud & Infrastructure) |
| Data Eng (5) + Analytics (6) | 17-20 (Data & Analytics), 28 (Data Viz) |
| Frontend (7) + Full Stack (8) | 13-16 (Frontend), 9 (Backend) |
| Mobile (9) | 29-30 (Mobile Development) |
| AI/ML (10) | 26-27 (ML, Agentic AI) |
| Security (11) | 11 (Security Implementation) |
| Testing (12) | 3 (Testing Mastery) |
| Emerging (13) | 51-54 (Bonus: Niche Technologies) |
| Architecture (14) | 5-8 (Software Architecture) |
| E-commerce (15) + Content (16) | 47 (Industry Verticals), 49 (Content Mgmt) |
| API/Integration (17) + Workflow (18) | 39-41 (Data & Integration), 38 (Automation) |
| Dev Tools (19) + Utilities (20) | 36-37 (Dev Environment, Build Automation) |

> **Full archive guide**: [`ARCHIVE_INDEX.md`](ARCHIVE_INDEX.md)

---

## 1. Programming Fundamentals

### 1-programming-core (12 skills) ✅ COMPLETED
Fundamental programming concepts that apply across all languages and paradigms. Includes multi-language examples (JS, Python, Go, Rust), Language Adaptation Guide, 19 reference files, and full cross-linking.
- **algorithms** - Design, analyze, implement, and optimize algorithms
- **data-structures** - Select, implement, and analyze data structures
- **complexity-analysis** - Analyze algorithm efficiency and optimize performance
- **problem-solving** - Approach challenges systematically using computational thinking
- **abstraction** - Simplify complex systems through abstraction
- **modularity** - Design modular systems with reusable components
- **recursion** - Solve problems using recursive approaches
- **iteration-patterns** - Implement efficient iteration techniques
- **functional-paradigm** - Write clean, predictable functional code
- **data-types** - Choose and use appropriate data types
- **control-flow** - Implement effective control flow patterns
- **metaprogramming** - Write code that manipulates or generates other code

### 2-code-quality (12 skills) ✅ COMPLETED
Writing clean, maintainable, and robust code. Includes multi-language examples (JS, Python, Go), 5 cross-skill integration examples, and full cross-linking.
- **clean-code** - Write readable, maintainable code
- **code-refactoring** - Improve code structure without changing behavior
- **code-deduplication** - Eliminate duplicate code effectively
- **error-handling** - Implement robust error management
- **input-validation** - Validate and sanitize inputs securely
- **logging-strategies** - Implement effective logging
- **code-quality-review** - Measure and improve code through structured review
- **technical-debt** - Manage and reduce technical debt
- **code-metrics** - Measure and improve code quality
- **simplify-complexity** - Reduce unnecessary complexity
- **code-standards** - Establish and enforce coding standards
- **legacy-code-migration** - Migrate legacy code safely

### 3-testing-mastery (12 skills)
Comprehensive testing strategies and implementation
- **test-driven-development** - Write tests before code to drive design
- **unit-testing** - Create effective unit tests for components
- **integration-testing** - Test component interactions and integration
- **test-automation** - Build automated testing pipelines
- **test-doubles** - Create mocks, stubs, and fakes for testing
- **behavior-driven-development** - Define behavior through examples
- **performance-testing** - Test system performance under load
- **test-strategy** - Design comprehensive testing strategies
- **test-data-management** - Manage test data effectively
- **debugging-tests** - Debug failing tests efficiently
- **mutation-testing** - Use mutation testing for test quality
- **visual-testing** - Implement visual regression testing

### 4-performance-optimization (12 skills)
Optimizing code and system performance
- **performance-analysis** - Analyze and identify performance bottlenecks
- **caching-strategies** - Implement effective caching for performance
- **algorithm-optimization** - Optimize algorithms for better performance
- **memory-optimization** - Reduce memory usage and prevent leaks
- **database-optimization** - Optimize database queries and design
- **concurrency-optimization** - Improve performance through parallel processing
- **network-optimization** - Optimize network communication
- **profiling-tools** - Use profiling tools to measure performance
- **lazy-loading** - Implement lazy loading for resource optimization
- **resource-management** - Manage system resources efficiently
- **performance-budgeting** - Set and monitor performance budgets
- **render-optimization** - Optimize rendering performance

---

## 2. Software Architecture

### 5-architecture-fundamentals (14 skills)
Core architectural patterns and principles
- **architecture-patterns** - Implement architectural design patterns
- **layered-architecture** - Design layered system architecture
- **hexagonal-architecture** - Apply hexagonal/port-and-adapter pattern
- **clean-architecture** - Implement clean architecture principles
- **modular-monolith** - Design modular monolithic systems
- **plugin-architecture** - Build extensible plugin systems
- **space-based-architecture** - Design space-based architectures
- **pipeline-architecture** - Implement pipeline processing patterns
- **system-component-design** - Design effective system components
- **architecture-decision-records** - Document architectural decisions
- **architecture-evolution** - Evolve architectures over time
- **architecture-governance** - Govern architectural decisions
- **architecture-risk-analysis** - Analyze architectural risks
- **architecture-evaluation** - Evaluate architecture quality

### 6-microservices-patterns (14 skills)
Microservices architecture and implementation
- **microservices-design** - Design microservice architectures
- **service-discovery** - Implement service discovery mechanisms
- **api-gateway** - Implement API gateway patterns
- **service-mesh** - Build service mesh architectures
- **inter-service-communication** - Design service communication
- **distributed-architecture** - Build distributed systems
- **microservices-security** - Secure microservice architectures
- **circuit-breaker** - Implement circuit breaker patterns
- **message-brokers** - Use message brokers for async communication
- **event-driven-integration** - Integrate services through events
- **service-orchestration** - Orchestrate microservices
- **saga-pattern** - Coordinate distributed workflows with saga pattern
- **service-decomposition** - Decompose monoliths to services
- **service-testing** - Test microservice architectures

### 7-domain-driven-design (14 skills)
DDD concepts and implementation
- **domain-driven-design** - Apply DDD principles
- **bounded-contexts** - Define and implement bounded contexts
- **domain-boundaries** - Define domain boundaries and ownership
- **domain-events** - Implement domain event patterns
- **ubiquitous-language** - Establish ubiquitous language
- **context-mapping** - Map domain contexts
- **domain-modeling** - Model domains effectively
- **entity-design** - Design domain entities
- **value-objects** - Define immutable types with equality by content
- **domain-services** - Encapsulate domain logic that doesn't belong to entities
- **ddd-strategic-design** - Apply strategic DDD
- **ddd-tactical-design** - Apply tactical DDD
- **domain-service-factoring** - Refactor to domain services
- **aggregate-design** - Design effective aggregates

### 8-api-design (14 skills)
API design and implementation
- **api-design** - Design effective APIs
- **rest-api-design** - Design RESTful APIs
- **graphql-schema-design** - Design GraphQL schemas
- **api-versioning** - Implement API versioning strategies
- **api-documentation** - Create comprehensive API documentation
- **api-testing** - Test APIs effectively
- **api-authentication** - Implement API auth flows (OAuth, API keys, JWT)
- **rate-limiting** - Implement API rate limiting
- **api-first-design** - Apply API-first approach
- **asyncapi-design** - Design async APIs
- **api-analytics** - Analyze API usage
- **api-gateway-patterns** - Implement advanced gateway patterns
- **api-contract-testing** - Test API contracts
- **api-monitoring** - Monitor API performance and usage

---

## 3. Backend Development

### 9-backend-services (15 skills)
Core backend development concepts
- **backend-development** - Develop backend services
- **request-response-cycle** - Handle request-response cycles
- **middleware-development** - Create middleware components
- **service-layer** - Implement service layer patterns
- **repository-pattern** - Abstract data access behind collection-like interfaces
- **business-logic** - Structure and validate core business rules
- **application-services** - Coordinate use cases across domain and infrastructure
- **backend-architecture** - Structure backend layers, modules, and dependencies
- **session-management** - Manage user sessions
- **background-jobs** - Implement background job processing
- **websockets** - Implement WebSocket communication
- **message-queues** - Use message queues for async processing
- **graphql-implementation** - Implement GraphQL servers
- **event-sourcing** - Implement event sourcing patterns
- **cqrs-pattern** - Implement Command Query Responsibility Segregation

### 10-data-persistence (14 skills)
Data storage and management
- **database-design** - Design effective databases
- **orm-usage** - Use ORMs effectively
- **database-migrations** - Version and apply schema changes safely
- **query-optimization** - Optimize database queries
- **transaction-management** - Manage database transactions
- **data-validation** - Validate data at persistence layer
- **data-mapping** - Map data between layers
- **database-performance-tuning** - Tune database performance
- **nosql-patterns** - Model data for document, key-value, and graph stores
- **data-consistency** - Maintain ACID/BASE guarantees across operations
- **database-backups** - Implement backup strategies
- **data-archiving** - Archive historical data
- **database-sharding** - Partition data across multiple database instances
- **data-replication** - Replicate data for availability

### 11-security-implementation (14 skills)
Implementing security in applications
- **authentication** - Implement authentication systems
- **authorization** - Implement authorization mechanisms
- **security-headers** - Configure CSP, HSTS, CORS, and X-Frame-Options headers
- **csrf-protection** - Prevent CSRF attacks
- **xss-prevention** - Prevent XSS attacks
- **sql-injection-prevention** - Prevent SQL injection
- **encryption-implementation** - Implement encryption
- **security-auditing** - Audit security implementations
- **secure-configuration** - Configure security settings
- **vulnerability-scanning** - Scan for vulnerabilities
- **oauth-implementation** - Implement OAuth flows
- **jwt-tokens** - Implement JWT token handling
- **api-security** - Secure API endpoints
- **security-testing** - Test security implementations

### 12-devops-automation (14 skills)
DevOps practices and automation
- **ci-cd-pipelines** - Build CI/CD pipelines
- **ci-cd-infrastructure** - Manage CI/CD infrastructure and runners
- **release-orchestration** - Orchestrate multi-stage releases
- **orchestration** - Orchestrate containers
- **deployment-strategies** - Choose blue-green, canary, rolling, or A/B deploys
- **observability-integration** - Integrate monitoring, logging, and tracing
- **log-aggregation** - Aggregate and analyze logs
- **backup-strategies** - Plan backup schedules, retention, and restore procedures
- **rollback-strategies** - Plan rollback and disaster recovery
- **automation-scripts** - Write reusable scripts for CI/CD and ops tasks
- **environment-management** - Manage environments
- **release-automation** - Automate releases
- **environment-provisioning** - Provision and validate environments
- **blue-green-deployment** - Implement blue-green deployments

---

## 4. Frontend Development

### 13-frontend-foundations (15 skills)
Core frontend development concepts
- **frontend-development** - Develop frontend applications
- **html-css-mastery** - Master HTML and CSS
- **javascript-fundamentals** - Master JavaScript fundamentals
- **responsive-design** - Build layouts that adapt to any screen sizes
- **web-accessibility** - Meet WCAG standards for inclusive web experiences
- **cross-browser-compatibility** - Ensure cross-browser compatibility
- **frontend-architecture** - Structure frontend apps with clean separation of concerns
- **asset-optimization** - Optimize frontend assets
- **web-performance** - Reduce load times, bundle size, and rendering latency
- **progressive-enhancement** - Build core experiences that work without JavaScript
- **build-tools** - Use build tools (webpack, vite, parcel)
- **package-managers** - Manage packages (npm, yarn, pnpm)
- **css-frameworks** - Use CSS frameworks (tailwind, bootstrap)
- **browser-apis** - Use browser APIs effectively
- **web-components** - Create encapsulated custom HTML elements

### 14-ui-component-design (14 skills)
Design and implement UI components
- **component-design** - Design reusable components
- **component-libraries** - Build and maintain reusable UI component libraries
- **styling-strategies** - Choose CSS-in-JS, modules, utility-first, or preprocessors
- **css-architecture** - Organize CSS with BEM, ITCSS, or atomic patterns
- **design-systems** - Build consistent design tokens, components, and documentation
- **component-testing** - Test UI components
- **component-composition** - Compose components effectively
- **stateful-components** - Manage component state
- **component-optimization** - Optimize component performance
- **component-documentation** - Document components
- **component-variants** - Create component variations
- **component-theming** - Implement theming systems
- **component-animation** - Add animations to components
- **component-accessibility** - Meet keyboard, screen reader, and ARIA standards

### 15-state-management (14 skills)
Manage application state
- **state-management** - Manage application state
- **redux-patterns** - Structure stores, reducers, actions, and selectors
- **mobx-usage** - Use MobX effectively
- **context-api** - Share state across components without prop drilling
- **state-persistence** - Persist state
- **state-synchronization** - Synchronize state
- **immutable-state** - Enforce immutability for predictable state updates
- **state-testing** - Test state management
- **state-architecture** - Choose the right state management approach for the app
- **state-optimization** - Optimize state performance
- **state-normalization** - Normalize state structure
- **state-middleware** - Intercept, transform, and log state transitions
- **state-hydration** - Hydrate and restore state across sessions
- **state-debugging** - Debug state changes

### 16-frontend-performance (14 skills)
Optimize frontend performance
- **bundle-optimization** - Optimize JavaScript bundles
- **image-optimization** - Optimize images for web
- **code-splitting** - Split and lazy-load code bundles
- **browser-caching** - Implement browser and CDN caching
- **dom-optimization** - Optimize DOM manipulation and rendering
- **request-optimization** - Optimize frontend network requests
- **performance-monitoring** - Monitor frontend performance
- **critical-path** - Optimize critical rendering path
- **resource-prioritization** - Prioritize resource loading
- **lighthouse-optimization** - Meet Lighthouse and performance budgets
- **core-web-vitals** - Improve LCP, INP, and CLS metrics
- **runtime-optimization** - Optimize runtime performance
- **frontend-benchmarking** - Benchmark and test frontend performance
- **performance-auditing** - Audit performance issues

---

## 5. Data & Analytics

### 17-data-processing (14 skills)
Process and transform data
- **data-processing** - Process data efficiently
- **etl-pipelines** - Extract, transform, and load data across systems
- **data-transformation** - Transform data structures
- **data-quality-checks** - Validate and verify data quality
- **data-cleaning** - Clean and preprocess data
- **batch-processing** - Process large datasets in scheduled batch jobs
- **data-streaming** - Stream data between systems
- **data-aggregation** - Aggregate data effectively
- **data-enrichment** - Enrich data with additional info
- **data-formatting** - Format data for consumption
- **data-partitioning** - Partition data efficiently
- **data-reduction** - Reduce, compress, and deduplicate data
- **data-profiling** - Profile data characteristics
- **data-lineage-tracking** - Track data lineage

### 18-stream-processing (14 skills)
Process real-time data streams
- **stream-processing** - Process data streams
- **event-streaming** - Publish and consume event streams in real-time
- **real-time-processing** - Process data in real-time
- **stream-architectures** - Choose Kappa, Lambda, or hybrid stream topologies
- **kafka-usage** - Use Kafka effectively
- **event-queue-processing** - Process events from queues
- **pub-sub-patterns** - Apply pub/sub patterns
- **windowing-operations** - Group stream events by time, count, or session windows
- **stateful-streams** - Track running aggregates and state across stream events
- **stream-monitoring** - Monitor stream processing
- **stream-testing** - Test stream applications
- **stream-scaling** - Scale stream processing
- **stream-analytics** - Analyze stream data
- **stream-error-handling** - Handle stream errors

### 19-data-pipelines (14 skills)
Build and manage data pipelines
- **pipeline-design** - Design data pipelines
- **pipeline-orchestration** - Orchestrate pipelines
- **pipeline-monitoring** - Monitor pipelines
- **data-governance** - Govern data quality
- **data-lineage** - Trace data origin, transformations, and downstream consumers
- **pipeline-testing** - Test data pipelines
- **pipeline-scaling** - Scale data pipelines
- **pipeline-security** - Secure data pipelines
- **pipeline-optimization** - Optimize pipelines
- **pipeline-documentation** - Document pipelines
- **data-quality** - Define and enforce data quality rules and SLAs
- **pipeline-versioning** - Version pipeline code
- **pipeline-failover** - Recover pipelines from failures with checkpointing and retries
- **pipeline-scheduling** - Schedule pipeline runs

### 20-data-science (10 skills)
Analyze data, build models, and communicate insights
- **statistical-analysis** - Apply statistical methods to data problems
- **exploratory-data-analysis** - Explore and understand datasets systematically
- **hypothesis-testing** - Design and run statistical tests
- **regression-modeling** - Build regression and prediction models
- **classification-modeling** - Build classification and clustering models
- **time-series-analysis** - Analyze and forecast time series data
- **experiment-design** - Design A/B tests and controlled experiments
- **insight-communication** - Communicate data insights through narratives and reports
- **jupyter-workflows** - Build reproducible analysis in notebooks
- **bi-dashboards** - Create business intelligence dashboards and reports

---

## 6. Cloud & Infrastructure

### 21-cloud-deployment (14 skills)
Deploy applications to the cloud
- **cloud-deployment** - Deploy to cloud platforms
- **cloud-native-patterns** - Apply cloud-native patterns
- **serverless-architecture** - Build serverless applications
- **cloud-migration** - Migrate to cloud
- **multi-cloud-strategy** - Implement multi-cloud strategy
- **hybrid-cloud** - Use hybrid cloud architectures
- **cloud-cost-optimization** - Optimize cloud costs
- **cloud-security** - Secure cloud deployments
- **cloud-monitoring** - Monitor cloud resources
- **disaster-recovery** - Implement cloud disaster recovery
- **cloud-networking** - Configure VPCs, subnets, peering, and DNS in the cloud
- **cloud-storage** - Use cloud storage services
- **cloud-compute** - Use cloud compute services
- **cloud-databases** - Use cloud database services

### 22-containerization (14 skills)
Containerize applications
- **docker-usage** - Use Docker effectively
- **container-orchestration** - Orchestrate containers
- **kubernetes-deployment** - Deploy to Kubernetes
- **container-security** - Secure containers
- **container-optimization** - Optimize containers
- **container-networking** - Configure bridge, overlay, and host container networks
- **container-storage** - Mount volumes, persistent storage, and shared filesystems
- **container-monitoring** - Monitor containers
- **container-scaling** - Scale containerized apps
- **container-best-practices** - Follow image layering, health checks, and security practices
- **container-registry** - Manage container registries
- **container-ci-cd** - CI/CD for containers
- **container-debugging** - Debug container issues
- **container-security-scanning** - Scan containers for vulnerabilities

### 23-infrastructure-code (14 skills)
Manage infrastructure with code
- **infrastructure-as-code** - Implement IaC
- **terraform-usage** - Use Terraform effectively
- **ansible-automation** - Automate with Ansible
- **puppet-configuration** - Configure with Puppet
- **chef-recipes** - Define infrastructure state with Chef cookbooks
- **cloudformation-templates** - Provision AWS resources with declarative templates
- **arm-templates** - Deploy Azure resources with ARM/Bicep templates
- **infrastructure-testing** - Test infrastructure
- **infrastructure-security** - Secure infrastructure
- **infrastructure-monitoring** - Monitor infrastructure
- **infrastructure-scaling** - Scale infrastructure
- **infrastructure-compliance** - Ensure compliance
- **infrastructure-drift** - Detect infrastructure drift
- **infrastructure-backups** - Backup infrastructure configurations

### 24-monitoring-observability (14 skills)
Monitor and observe systems
- **monitoring-setup** - Set up monitoring
- **metrics-collection** - Collect metrics
- **log-analysis** - Analyze logs
- **distributed-tracing** - Trace requests across service boundaries with OpenTelemetry
- **alerting-strategies** - Set up alerting
- **dashboard-creation** - Create monitoring dashboards
- **observability-patterns** - Correlate logs, metrics, and traces for full-stack visibility
- **apm-implementation** - Implement APM
- **sla-monitoring** - Monitor SLAs
- **incident-response** - Respond to incidents
- **synthetic-monitoring** - Simulate user journeys to detect issues proactively
- **observability-data** - Manage cardinality, retention, and cost of telemetry data
- **root-cause-analysis** - Analyze root causes
- **alert-automation** - Automate alerting and incident workflows

### 25-networking-protocols (10 skills)
Configure, secure, and troubleshoot network infrastructure
- **tcp-ip-fundamentals** - Debug and optimize TCP/IP communication
- **dns-management** - Configure DNS records, resolution, and troubleshooting
- **ssl-tls-implementation** - Implement TLS certificates and HTTPS
- **firewall-configuration** - Configure firewall rules and network policies
- **reverse-proxy-setup** - Set up Nginx, Caddy, HAProxy reverse proxies
- **cdn-configuration** - Configure CDN caching, rules, and invalidation
- **ddos-mitigation** - Implement DDoS protection strategies
- **vpn-setup** - Configure VPN tunnels and secure network access
- **network-troubleshooting** - Diagnose network issues with standard tools
- **api-protocol-selection** - Choose between REST, gRPC, WebSocket, GraphQL, MQTT

---

## 7. AI & Intelligent Systems

### 26-machine-learning (14 skills)
Implement machine learning solutions
- **ml-model-development** - Develop ML models
- **data-preprocessing** - Preprocess ML data
- **feature-engineering** - Engineer features
- **model-training** - Train ML models
- **model-evaluation** - Evaluate models
- **model-deployment** - Deploy ML models
- **ml-monitoring** - Monitor ML models
- **ml-optimization** - Optimize ML performance
- **deep-learning** - Build neural networks with CNNs, RNNs, and transformers
- **ml-interpretability** - Interpret ML models
- **ml-pipelines** - Automate model training, validation, and deployment workflows
- **automl-usage** - Use AutoML tools
- **ml-serving** - Serve ML models
- **ml-experimentation** - Track ML experiments

### 27-agentic-ai (12 skills)
Build, evaluate, and operate AI agents and LLM-powered systems
- **prompt-engineering** - Design effective prompts, chains, and templates
- **rag-pipelines** - Build retrieval-augmented generation systems
- **embedding-search** - Implement vector embeddings and semantic search
- **multi-agent-orchestration** - Coordinate multiple AI agents on complex tasks
- **llm-evaluation** - Evaluate, benchmark, and compare LLM outputs
- **ai-guardrails** - Implement safety rails, content filtering, and output validation
- **tool-use-design** - Design tool interfaces and function calling for AI agents
- **agent-memory** - Implement short-term and long-term memory for agents
- **fine-tuning** - Fine-tune and adapt models for specific domains
- **llm-cost-optimization** - Optimize token usage, caching, and model routing
- **ai-observability** - Monitor, trace, and debug AI/LLM pipelines
- **skill-development** - Create, test, and publish reusable agent skills

### 28-data-visualization (12 skills)
Create visual representations of data
- **chart-creation** - Create effective charts and graphs
- **dashboard-design** - Design data dashboards
- **interactive-visualizations** - Add zoom, filter, drill-down, and hover interactions
- **data-storytelling** - Tell stories with data
- **visualization-libraries** - Use D3, Chart.js, Plotly
- **map-visualizations** - Create geographic visualizations
- **real-time-dashboards** - Build real-time dashboards
- **mobile-visualizations** - Optimize for mobile
- **accessibility-viz** - Make visualizations accessible
- **performance-viz** - Optimize visualization performance
- **custom-visualizations** - Build bespoke charts beyond standard library options
- **data-animation** - Animate data changes

---

## 8. Mobile Development

### 29-mobile-development (14 skills)
Develop mobile applications
- **mobile-development** - Develop mobile apps
- **ios-development** - Develop iOS applications
- **android-development** - Develop Android applications
- **mobile-ui-design** - Design mobile UI
- **mobile-performance** - Reduce startup time, memory usage, and frame drops
- **mobile-security** - Secure mobile apps
- **mobile-testing** - Test mobile applications
- **app-store-deployment** - Deploy to app stores
- **mobile-analytics** - Analyze mobile usage
- **push-notifications** - Send targeted push notifications with FCM/APNs
- **mobile-offline** - Implement offline support
- **mobile-background-tasks** - Handle background tasks
- **mobile-permissions** - Handle app permissions
- **mobile-battery-optimization** - Optimize battery usage

### 30-cross-platform (12 skills)
Develop cross-platform applications
- **react-native-development** - Develop with React Native
- **flutter-development** - Develop with Flutter
- **xamarin-development** - Develop with Xamarin
- **ionic-development** - Develop with Ionic
- **cordova-development** - Develop with Cordova
- **progressive-web-apps** - Build PWAs
- **cross-platform-testing** - Test cross-platform apps
- **platform-specific-features** - Use platform features
- **cross-platform-performance** - Optimize performance
- **code-sharing-strategies** - Share code effectively
- **cross-platform-ui** - Design cross-platform UI
- **native-modules** - Bridge platform-specific APIs into cross-platform code

---

## 9. Development Practices

### 31-collaboration-workflows (12 skills)
Collaborate effectively on development
- **git-workflow** - Choose and enforce Git branching and merge strategies
- **branching-strategies** - Select GitFlow, trunk-based, or feature-branch models
- **merge-conflicts** - Diagnose and resolve conflicting code changes
- **code-review** - Give constructive feedback and catch issues in reviews
- **pull-requests** - Structure, review, and merge pull requests effectively
- **commit-messages** - Write good commit messages
- **collaboration-tools** - Set up GitHub, Linear, Slack, and team tools
- **team-communication** - Communicate effectively
- **knowledge-sharing** - Share knowledge
- **onboarding-process** - Onboard team members
- **code-ownership** - Define CODEOWNERS and responsibility boundaries
- **collaboration-conflicts** - Resolve team conflicts

### 32-project-management (12 skills)
Manage development projects
- **project-planning** - Plan projects
- **agile-methodologies** - Apply agile methods
- **scrum-implementation** - Implement Scrum
- **kanban-boards** - Visualize and manage work-in-progress with Kanban
- **sprint-planning** - Plan sprints
- **risk-management** - Manage project risks
- **stakeholder-management** - Manage stakeholders
- **project-tracking** - Track project progress
- **resource-allocation** - Allocate resources
- **delivery-planning** - Plan deliveries
- **project-estimation** - Estimate project effort
- **milestone-tracking** - Track project milestones

### 33-documentation-mastery (14 skills)
Create and maintain documentation
- **documentation-fundamentals** - Master documentation basics
- **documentation-automation** - Auto-generate docs from code and schemas
- **code-documentation** - Document code
- **readme-writing** - Write effective READMEs
- **technical-writing** - Write technical content
- **technical-documentation** - Write and maintain technical docs
- **diagram-creation** - Create technical diagrams
- **user-guides** - Write step-by-step guides for end users
- **changelog-maintenance** - Maintain changelogs
- **documentation-search** - Make documentation searchable
- **documentation-versioning** - Version documentation
- **documentation-analytics** - Analyze documentation usage
- **documentation-localization** - Localize documentation
- **documentation-templates** - Standardize docs with reusable templates and schemas

### 34-configuration-management (12 skills)
Manage application configuration
- **configuration-management** - Manage configurations
- **environment-variables** - Manage config via env vars across environments
- **configuration-files** - Manage config files
- **secret-management** - Manage secrets
- **runtime-configuration** - Manage runtime config and feature switches
- **a-b-testing** - Implement A/B testing
- **configuration-validation** - Validate configurations
- **configuration-deployment** - Deploy configurations
- **configuration-monitoring** - Monitor configurations
- **configuration-security** - Secure configurations
- **configuration-encryption** - Encrypt sensitive configurations
- **configuration-auditing** - Audit configuration changes

### 35-feature-management (10 skills)
Manage feature development
- **feature-flags** - Control feature visibility with runtime flags and targeting
- **feature-lifecycle** - Manage feature lifecycle from creation to sunset
- **feature-rollout** - Roll out features
- **feature-testing** - Test features
- **feature-analytics** - Analyze feature usage
- **feature-deprecation** - Deprecate features
- **feature-documentation** - Document features
- **feature-branching** - Manage feature branches
- **feature-experiments** - Run feature experiments
- **feature-feedback** - Collect feature feedback

---

## 10. Development Tools

### 36-development-environment (12 skills)
Set up and optimize development environment
- **ide-setup** - Configure IDE effectively
- **development-tools** - Choose and use dev tools
- **debugging-skills** - Debug code effectively
- **productivity-tools** - Configure linters, formatters, snippets, and dev shortcuts
- **keyboard-shortcuts** - Master keyboard shortcuts
- **terminal-usage** - Use terminal efficiently
- **shell-scripting** - Write shell scripts
- **vscode-extensions** - Use VS Code extensions
- **docker-development** - Develop with Docker
- **local-development** - Set up local dev environment
- **remote-development** - Develop remotely
- **environment-configuration** - Configure dev environments

### 37-build-automation (12 skills)
Automate build processes
- **build-systems** - Configure Webpack, Vite, esbuild, or Gradle builds
- **task-runners** - Automate dev tasks with npm scripts, Make, or Turborepo
- **dependency-management** - Manage dependencies
- **version-management** - Manage versions
- **build-optimization** - Optimize builds
- **build-caching** - Cache build artifacts
- **incremental-builds** - Rebuild only changed files for faster iteration
- **build-pipelines** - Chain build steps: lint, compile, test, bundle, deploy
- **build-monitoring** - Monitor builds
- **build-debugging** - Debug build issues
- **build-artifacts** - Version, store, and distribute build outputs
- **build-verification** - Verify build integrity

### 38-automation-scripts (12 skills)
Create automation and utility scripts
- **script-writing** - Write effective automation scripts
- **task-automation** - Automate repetitive tasks
- **file-automation** - Automate file operations
- **data-automation** - Automate data processing
- **deployment-automation** - Automate deployments
- **monitoring-automation** - Automate monitoring tasks
- **backup-automation** - Automate backup processes
- **report-automation** - Generate automated reports
- **notification-automation** - Automate notifications
- **maintenance-automation** - Automate system maintenance
- **workflow-automation** - Automate complex workflows
- **cron-jobs** - Schedule automated tasks

---

## 11. Data & Integration

### 39-data-formats (12 skills)
Work with various data formats and serialization
- **json-handling** - Process JSON data effectively
- **xml-processing** - Parse and generate XML
- **protocol-buffers** - Define schemas and serialize data with Protobuf
- **avro-usage** - Work with Avro format
- **csv-processing** - Process CSV files
- **yaml-configuration** - Use YAML for configuration
- **data-serialization** - Serialize data structures
- **format-conversion** - Convert between formats
- **schema-validation** - Validate data schemas
- **binary-formats** - Handle binary data formats
- **data-compression** - Compress and decompress data
- **data-encryption** - Encrypt sensitive data

### 40-integration-patterns (14 skills)
Integrate with external systems
- **api-integration** - Integrate with external APIs
- **webhook-implementation** - Implement webhooks
- **third-party-auth** - Integrate OAuth providers
- **payment-gateways** - Integrate payment systems
- **email-services** - Integrate email providers
- **sms-services** - Integrate SMS providers
- **social-integration** - Integrate social platforms
- **calendar-integration** - Integrate calendar systems
- **file-storage-integration** - Integrate cloud storage
- **analytics-integration** - Integrate analytics tools
- **crm-integration** - Integrate CRM systems
- **erp-integration** - Integrate ERP systems
- **notification-services** - Send push, email, SMS, and in-app notifications
- **mapping-services** - Integrate mapping APIs

### 41-search-implementation (12 skills)
Implement search functionality
- **search-architecture** - Design search systems
- **elasticsearch-usage** - Use Elasticsearch effectively
- **full-text-search** - Implement full-text search
- **search-optimization** - Optimize search performance
- **search-analytics** - Analyze search behavior
- **autocomplete** - Suggest results as users type with prefix/fuzzy matching
- **search-filters** - Create advanced filters
- **search-ranking** - Implement ranking algorithms
- **search-ui** - Design search interfaces
- **voice-search** - Accept and process voice queries for search
- **search-indexing** - Index content for search
- **search-relevance** - Improve search relevance

---

## 12. Advanced Systems

### 42-advanced-debugging (12 skills)
Advanced debugging techniques
- **advanced-debugging** - Apply advanced debugging techniques
- **memory-leak-detection** - Detect memory leaks
- **performance-profiling** - Profile application performance
- **concurrency-debugging** - Debug concurrent code
- **remote-debugging** - Debug remote applications
- **production-debugging** - Debug in production
- **crash-analysis** - Analyze application crashes
- **debugging-tools** - Use advanced debugging tools
- **logging-debugging** - Use logs for debugging
- **debugging-strategies** - Choose top-down, bottom-up, or bisect approaches
- **post-mortem-debugging** - Debug after failures
- **debugging-automation** - Automate debugging tasks

### 43-concurrency-patterns (14 skills)
Implement concurrent solutions
- **concurrent-programming** - Program concurrently
- **thread-safety** - Protect shared state from concurrent access bugs
- **synchronization** - Synchronize concurrent code
- **async-programming** - Program asynchronously
- **parallel-processing** - Process in parallel
- **lock-free-programming** - Program without locks
- **actor-model** - Isolate state in message-passing actors (Akka, Erlang)
- **reactive-programming** - Program reactively
- **race-conditions** - Detect and prevent timing-dependent bugs
- **deadlock-prevention** - Prevent deadlocks
- **concurrent-data-structures** - Use lock-free queues, maps, and atomic types
- **async-patterns** - Apply fan-out, fan-in, pipeline, and retry patterns
- **coroutine-usage** - Use coroutines effectively
- **concurrency-testing** - Test concurrent code

### 44-distributed-systems (15 skills)
Build distributed systems
- **distributed-systems** - Design systems that span multiple networked nodes
- **consensus-algorithms** - Implement consensus
- **distributed-logging** - Log in distributed systems
- **distributed-caching** - Cache in distributed systems
- **distributed-locks** - Coordinate exclusive access across distributed nodes
- **distributed-load-management** - Manage load across distributed nodes
- **network-partitions** - Keep systems functional during network splits
- **eventual-consistency** - Design for convergence without strong consistency
- **request-correlation** - Correlate requests across distributed services
- **system-scalability** - Scale distributed systems
- **distributed-computing** - Parallelize computation across a cluster
- **cap-theorem** - Make tradeoffs between consistency, availability, and partitions
- **distributed-storage** - Replicate and shard data across storage nodes
- **distributed-load-balancing** - Balance load across distributed nodes
- **service-registry** - Register and discover services dynamically

### 45-system-design (15 skills)
Design complex systems
- **system-design** - Design systems
- **scalability-design** - Design for scale
- **availability-design** - Design for availability
- **consistency-design** - Design for consistency
- **partitioning-design** - Design partitions
- **replication-design** - Design replication
- **caching-design** - Design caching
- **load-distribution-design** - Design load distribution strategies
- **capacity-planning** - Plan capacity
- **system-evolution** - Evolve systems
- **design-interviews** - Solve design interview problems
- **system-integration** - Integrate systems
- **data-flow-design** - Design data flows
- **security-design** - Design security
- **monitoring-design** - Design monitoring

### 46-scalability-patterns (14 skills)
Scale applications effectively
- **horizontal-scaling** - Scale horizontally
- **vertical-scaling** - Scale vertically
- **database-scaling** - Scale databases
- **cache-scaling** - Scale caches
- **load-balancing** - Balance load
- **auto-scaling** - Implement auto-scaling
- **performance-tuning** - Tune for performance
- **resource-optimization** - Optimize resources
- **bottleneck-analysis** - Analyze bottlenecks
- **scaling-strategies** - Plan scaling
- **cdn-usage** - Use CDNs effectively
- **global-scaling** - Scale globally
- **microservices-scaling** - Scale microservices
- **cost-optimization** - Optimize scaling costs

---

## 13. Industry & Platform

### 47-industry-verticals (12 skills)
Build domain-specific business systems across industries
- **ecommerce-systems** - Build product catalogs, carts, and checkout flows
- **payment-processing** - Integrate payment gateways and handle transactions
- **inventory-management** - Build inventory tracking and warehouse systems
- **fintech-systems** - Implement trading, banking, and financial platforms
- **fraud-detection** - Build fraud detection and risk scoring systems
- **healthcare-systems** - Develop EMR integrations and clinical workflows
- **hipaa-compliance** - Implement HIPAA-compliant data handling
- **edtech-platforms** - Build LMS, assessment engines, and learning tools
- **logistics-systems** - Build shipping, routing, and fleet management
- **subscription-billing** - Implement recurring billing and subscription management
- **marketplace-platforms** - Build multi-vendor marketplace systems
- **real-estate-platforms** - Build property listings, search, and CRM

### 48-cloud-platforms (14 skills)
Work with major cloud providers and platforms
- **aws-services** - Use AWS core services
- **azure-services** - Utilize Azure platform
- **gcp-services** - Leverage Google Cloud Platform
- **cloud-comparison** - Compare cloud providers
- **multi-cloud-management** - Manage multi-cloud deployments
- **cloud-marketplace** - Publish and consume services from cloud marketplaces
- **cloud-integration** - Integrate cloud services
- **serverless-platforms** - Deploy to Lambda, Cloud Functions, or Azure Functions
- **paas-services** - Utilize Platform as a Service
- **saas-integration** - Integrate SaaS solutions
- **cloud-migration-tools** - Use migration tools
- **cloud-cost-analysis** - Analyze cloud costs
- **cloud-compliance** - Meet regulatory requirements in cloud environments
- **cloud-governance** - Govern cloud resources

### 49-content-management (12 skills)
Manage and deliver content
- **cms-integration** - Integrate with CMS platforms
- **content-delivery** - Serve content efficiently with CDNs and edge caching
- **content-caching** - Cache content effectively
- **content-search** - Search within content
- **content-personalization** - Personalize content
- **content-workflows** - Define editorial review, approval, and publishing pipelines
- **content-versioning** - Version content
- **content-localization** - Localize content
- **content-analytics** - Analyze content usage
- **headless-cms** - Deliver content via API from Contentful, Strapi, or Sanity
- **content-migration** - Migrate content between systems
- **content-security** - Secure content management

### 50-professional-skills (12 skills)
Develop professional and career skills
- **tech-communication** - Communicate technical concepts clearly
- **presentation-skills** - Present technical content
- **code-interviews** - Succeed in coding interviews
- **salary-negotiation** - Negotiate compensation
- **networking** - Build professional network
- **mentoring** - Mentor and be mentored
- **continuous-learning** - Stay current with evolving technologies and practices
- **open-source** - Contribute to open source
- **side-projects** - Ship personal projects to practice and demonstrate skills
- **personal-branding** - Build technical brand
- **career-planning** - Plan career progression
- **skill-assessment** - Assess and improve skills

---

## 14. Bonus Skills

> Specialized packs for niche domains and deep specializations not in the 50 core packs. Build on demand.

### A. Niche Technologies

### 51-blockchain (12 skills)
Develop blockchain applications
- **blockchain-development** - Develop blockchain apps
- **smart-contracts** - Write and deploy Solidity/Rust contracts on-chain
- **dapp-development** - Develop DApps
- **cryptocurrency-integration** - Integrate cryptocurrencies
- **blockchain-security** - Secure blockchain apps
- **consensus-mechanisms** - Implement consensus
- **token-economics** - Model token supply, distribution, and incentive mechanisms
- **blockchain-scaling** - Scale blockchain solutions
- **blockchain-testing** - Test blockchain apps
- **blockchain-optimization** - Optimize blockchain performance
- **blockchain-integration** - Integrate with existing systems
- **blockchain-auditing** - Audit blockchain implementations

### 52-game-development (14 skills)
Develop games
- **game-development** - Develop games
- **unity-development** - Develop with Unity
- **unreal-development** - Develop with Unreal
- **game-physics** - Simulate collisions, gravity, and rigid body dynamics
- **game-ai** - Build pathfinding, behavior trees, and NPC decision-making
- **game-performance** - Hit target frame rates with rendering and memory optimization
- **multiplayer-games** - Sync game state across players with netcode
- **game-monetization** - Monetize games
- **game-analytics** - Analyze game data
- **game-testing** - Test games
- **game-audio** - Integrate spatial audio, music, and sound effects
- **game-ui** - Build HUDs, menus, and in-game interfaces
- **game-networking** - Handle latency, prediction, and server authority
- **game-deployment** - Deploy games to platforms

### 53-iot-development (14 skills)
Develop IoT solutions
- **iot-development** - Develop IoT solutions
- **embedded-programming** - Program embedded systems
- **sensor-integration** - Integrate sensors
- **iot-security** - Secure IoT devices
- **edge-computing** - Run compute at the network edge near data sources
- **iot-protocols** - Communicate over MQTT, CoAP, Zigbee, and BLE
- **iot-data-processing** - Process IoT data
- **iot-deployment** - Deploy IoT solutions
- **iot-monitoring** - Monitor IoT systems
- **iot-scaling** - Scale IoT solutions
- **iot-gateways** - Bridge IoT devices to cloud via protocol translation
- **iot-firmware** - Write and update firmware for embedded IoT devices
- **iot-connectivity** - Manage device provisioning, pairing, and mesh networks
- **iot-analytics** - Analyze IoT data

### 54-emerging-technologies (12 skills)
Explore cutting-edge technologies
- **quantum-computing** - Write quantum circuits with Qiskit, Cirq, or Q#
- **ar-vr-development** - Develop AR/VR applications
- **voice-interfaces** - Build Alexa skills, Google Actions, and voice UIs
- **edge-ai** - Deploy AI at the edge
- **serverless-advanced** - Advanced serverless patterns
- **webassembly** - Compile C/Rust to Wasm for near-native browser performance
- **ai-integration** - Integrate AI capabilities
- **blockchain-advanced** - Advanced blockchain concepts
- **5g-applications** - Develop for 5G networks
- **future-web** - Explore future web technologies
- **robotics-integration** - Integrate with robotics
- **biometric-integration** - Integrate biometric authentication

### B. Deep Technical Specializations

### 55-compiler-engineering (10 skills)
Build language tools, compilers, interpreters, and runtime systems
- **compiler-design** - Design and implement compilers for custom languages
- **interpreter-design** - Build interpreters and REPLs
- **language-design** - Design programming language syntax and semantics
- **macro-systems** - Implement hygienic and procedural macro systems
- **template-metaprogramming** - Generate code at compile time with templates
- **ast-manipulation** - Parse, transform, and generate abstract syntax trees
- **bytecode-generation** - Emit and optimize bytecode for virtual machines
- **jit-compilation** - Implement just-in-time compilation strategies
- **garbage-collection** - Design and implement garbage collection algorithms
- **memory-management** - Build custom allocators and memory management systems

### 56-cs-theory-applied (10 skills)
Apply computer science theory to solve practical engineering problems
- **complexity-theory-applied** - Classify problem difficulty and choose tractable approaches
- **formal-verification** - Prove program correctness with formal methods
- **type-system-design** - Design and implement type systems and type checkers
- **language-semantics** - Define operational and denotational semantics
- **complexity-classification** - Map problems to complexity classes (P, NP, etc.)
- **graph-algorithms-advanced** - Apply advanced graph theory (flows, matchings, planarity)
- **information-coding** - Implement error-correcting codes and compression theory
- **cryptographic-primitives** - Implement ciphers, hashes, and key exchange from theory
- **computability-analysis** - Determine what is computable and design reductions
- **state-automata** - Build finite automata, pushdown automata, and Turing machines

### C. Platform & Domain

### 57-platform-development (10 skills)
Build on specific vendor platforms and ecosystems
- **salesforce-development** - Develop on Salesforce (Apex, Lightning, SOQL)
- **sap-development** - Build SAP integrations and ABAP extensions
- **oracle-development** - Develop with Oracle DB, PL/SQL, and Oracle Cloud
- **microsoft-platform** - Build on Azure, .NET, Power Platform, and M365
- **adobe-development** - Extend Adobe Experience Manager and Creative Cloud
- **shopify-development** - Build Shopify themes, apps, and Liquid templates
- **wordpress-development** - Develop WordPress themes, plugins, and REST APIs
- **drupal-development** - Build Drupal modules, themes, and migrations
- **jira-automation** - Automate Jira workflows, custom fields, and integrations
- **confluence-automation** - Automate Confluence spaces, templates, and macros

### 58-domain-engineering (10 skills)
Build software for specialized technical domains
- **mainframe-development** - Develop and modernize mainframe applications
- **legacy-language-support** - Work with COBOL, FORTRAN, and legacy codebases
- **scientific-computing** - Implement numerical methods and HPC workloads
- **bioinformatics** - Build genomics pipelines and sequence analysis tools
- **computational-finance** - Implement pricing models, risk analysis, and trading systems
- **game-engine-development** - Build custom game engines and rendering pipelines
- **cad-development** - Develop CAD tools, 3D modeling, and parametric design
- **gis-development** - Build geospatial systems, mapping, and spatial analysis
- **embedded-systems-advanced** - Program bare-metal, RTOS, and hardware interfaces
- **simulation-systems** - Build physics, agent-based, and discrete-event simulations

### D. Leadership & Process

### 59-technical-leadership (10 skills)
Lead technical teams, products, and organizational change
- **technical-team-leadership** - Lead engineering teams and manage tech talent
- **agile-coaching** - Coach teams on agile practices and continuous improvement
- **scrum-facilitation** - Facilitate Scrum ceremonies and remove impediments
- **technical-product-management** - Manage technical product roadmaps and priorities
- **technical-business-analysis** - Bridge business requirements and technical solutions
- **requirements-engineering** - Elicit, analyze, and document system requirements
- **technical-stakeholder-management** - Manage stakeholder expectations on technical projects
- **technical-change-management** - Lead technology migrations and organizational change
- **vendor-evaluation** - Evaluate, select, and manage technology vendors
- **certification-preparation** - Prepare for technical certifications (AWS, Azure, K8s, etc.)

### 60-process-governance (10 skills)
Implement process frameworks, standards, and governance
- **process-optimization** - Apply Six Sigma and statistical process control to dev workflows
- **lean-development** - Eliminate waste and optimize flow in software delivery
- **devops-transformation** - Transform organizations toward DevOps culture and practices
- **digital-transformation** - Plan and execute digital transformation initiatives
- **agile-transformation** - Scale agile practices across the organization
- **itil-service-management** - Implement ITIL service management processes
- **governance-frameworks** - Apply COBIT and IT governance frameworks
- **standards-compliance** - Implement ISO 27001, ISO 9001, and industry standards
- **regulatory-compliance** - Meet GDPR, HIPAA, SOX, and sector-specific regulations
- **technical-auditing** - Conduct technical audits and compliance assessments

---

## Statistics

### Totals
- **766 unique skills** across 60 packs, 14 categories
- **0 duplicate skill names** (all resolved — see changelog)
- **1 pack completed** with reference files
- **50 core packs** (662 skills) + **10 bonus packs** (104 skills)

### Skill Count Distribution
| Size | Count | Packs |
|------|-------|-------|
| 10 skills | 9 | 20, 25, 35, 55, 56, 57, 58, 59, 60 |
| 12 skills | 21 | 1, 2, 3, 4, 27, 28, 30, 31, 32, 34, 36, 37, 38, 39, 41, 42, 47, 49, 50, 51, 54 |
| 14 skills | 26 | 5, 6, 7, 8, 10, 11, 12, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 26, 29, 33, 40, 43, 46, 48, 52, 53 |
| 15 skills | 4 | 9, 13, 44, 45 |

### Completion Status
- ✅ **1-programming-core** — 12 skills, 19 reference files, fully cross-linked
- ✅ **2-code-quality** — 12 skills, 19 reference files, fully cross-linked
- ⬜ All other packs — planned, not yet built

### Standalone Skills (Outside Pack System)

These skills live at the repo root, not inside a numbered pack. They support the skill-building workflow itself.

| Skill | Location | Purpose |
|-------|----------|---------|
| **skill-builder** | `skill-builder/` | Create, edit, and convert AI agent skills across platforms |
| **generating-agents-md** | `generating-agents-md/` | Generate and audit AGENTS.md files with Three Pillars Framework (AUTOMATING, TESTING, DOCUMENTING) |

---

## Changelog

### 2026-02-09: Prompt Validation Protocol & Archive Reference
- **Created `PROMPT-VALIDATION-PROTOCOL.md`** — required protocol for all agents to validate user prompts before execution (Quick 2-min MUST PASS, Standard 10-min for complex prompts, 5-dimension scoring, type-specific checks)
- **Created `prompt-validation/` reference directory** — examples and security patterns for prompt validation
- **Created `_complete_archive/PROMPT-VALIDATION-SYSTEM-REFERENCE.md`** — comprehensive reference documenting the archive's original validation system (8 scripts, 4 specs, 3 reports)
- **Integrated prompt validation into AGENTS.md** — added mandatory protocol section and Three Pillars integration

### 2026-02-07: Three Pillars Framework & Standalone Skills
- **Added Three Pillars Framework** (AUTOMATING, TESTING, DOCUMENTING) to the `generating-agents-md` skill, creation guide, and local AGENTS.md
- **Added standalone skills section** to this file — `skill-builder` and `generating-agents-md` now tracked here
- **Created ARCHIVE-DOCUMENTATION-INDEX.md** — comprehensive index of 80+ documentation files in `_complete_archive/`
- **Updated README.md** with current project structure, completed packs, standalone skills, and Three Pillars

### 2026-02-07: Duplicate Resolution & Archive Integration
- **Renamed** to `SKILLS_MASTER_LIST.md` (was `ALL_SKILLS_MASTER_LIST_V4_COMPREHENSIVE.md`)
- **Resolved 30 duplicate/overlapping skill names** (27 cross-pack + 3 within-pack) by renaming the less-specific instance. All renames preserved in skill descriptions. Affected packs: 2, 5, 6, 7, 8, 10, 12, 15, 16, 17, 18, 23, 32, 33, 34, 42, 43, 49, 50.
- **Integrated** with `ARCHIVE_INDEX.md` and Pack 1 reference files
- **Fixed stats**: total 700 → 662, categories 12 → 17

### 2026-02-07: Bonus Expansion + Full Reorganization
- **Added 10 bonus packs** (51-60): 4 new high-demand packs + 6 from previously excluded skills
- **Promoted 4 to core**: 20-data-science, 25-networking-protocols, 27-agentic-ai, 47-industry-verticals
- **Demoted 4 to bonus**: 51-blockchain, 52-game-development, 53-iot-development, 54-emerging-technologies
- **Consolidated 17 categories → 14**: merged single-pack categories, created "AI & Intelligent Systems" (26-28) and "Industry & Platform" (47-50)
- **Renumbered all packs 20-60** for sequential ordering within categories

---

*Last Updated: 2026-02-07*
