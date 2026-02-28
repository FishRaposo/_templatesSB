# Suggestions for New Templates

**Purpose**: Actionable ideas for new templates across all seven types—Skills, Tasks, Blueprints, Subagents, Rules, Recipes, and Protocols.  
**Audience**: Contributors and adopters extending the template ecosystem.  
**See also**: `TEMPLATES-SYSTEM-OVERVIEW.md`, `AGENTIC-ASSETS-FRAMEWORK.md`, `.agents/skills/skill-setup/` for creating skills.

---

## How to Use This Document

- **Prioritize by need**: Pick suggestions that fill gaps in your project or the repo (e.g. no security protocol yet, no refactor subagent).
- **Follow existing patterns**: Use the framework and current skills/tasks/blueprints as structure reference.
- **Create in order when possible**: Protocol → protocol skill; then Rules reference; then Skills/Recipes/Subagents that use them.

---

## 1. Skills — New Capability Ideas

Skills teach agents *how to do something well* and are invoked by trigger keywords. Current skills are mostly **setup** (rules-setup, memory-system-setup, blueprints-setup, etc.). Suggestions below add **domain and quality** capabilities.

| Suggestion | Description | Triggers / When to use |
|------------|-------------|-------------------------|
| **changelog-and-release-notes** | How to write clear CHANGELOG entries and release notes (event format, grouping, semver). | "changelog", "release notes", "what changed" |
| **safe-git-workflow** | Branching, commit messages, when to force-push, protecting main. | "git workflow", "commit message", "branch strategy" |
| **api-design-rest** | REST resource naming, status codes, versioning, idempotency. | "REST API", "API design", "endpoint design" |
| **error-handling-and-logging** | Structured errors, logging levels, correlation IDs, what not to log. | "error handling", "logging", "exceptions" |
| **testing-strategies** | Unit vs integration vs E2E, mocking, test data, coverage goals. | "testing strategy", "write tests", "test coverage" |
| **security-review-checklist** | Common vulnerabilities, secrets handling, input validation, dependency audit. | "security review", "vulnerabilities", "secrets" |
| **refactoring-incremental** | Small steps, preserving behavior, when to extract vs inline. | "refactor", "clean up code", "technical debt" |
| **documentation-as-code** | README structure, API docs from code, docstrings, ADRs. | "documentation", "README", "API docs" |
| **dependency-upgrade** | Assessing breaking changes, lockfiles, upgrade order. | "upgrade dependency", "bump version", "dependency update" |

**Creation**: Use `.agents/skills/skill-setup/`; add SKILL.md (frontmatter + steps + multi-language examples), config.json (keywords, patterns), README.md.

---

## 2. Tasks — New Implementation Units

Tasks are *how to implement a feature* with full code, config, and docs per stack/tier. Suggestions are feature-level and can feed Blueprints and Recipes.

| Suggestion | Description | Stacks / Tiers |
|------------|-------------|----------------|
| **billing-stripe** | Stripe integration: products, prices, checkout, webhooks, customer portal. | python, node; mvp → core |
| **email-send-and-templates** | Transactional email (SendGrid, Resend, etc.), templates, tracking. | python, node; mvp → core |
| **file-upload-storage** | Upload to S3/R2/GCS, presigned URLs, virus scan hook. | python, node; core → enterprise |
| **rate-limiting** | Per-user/per-IP limits, backoff, headers. | python, node, go; core |
| **audit-log** | Append-only audit events, query by actor/resource/time. | universal + stacks; core → enterprise |
| **feature-flags** | Toggle by user/segment, rollout %, kill switch. | python, node; core |
| **search-basic** | Full-text search (DB-native or Elasticsearch/Meilisearch). | python, node; core → enterprise |
| **multi-tenant-isolation** | Tenant context, row-level filtering, schema-per-tenant options. | python, node; core → enterprise |
| **health-and-readiness** | /health, /ready, dependency checks, liveness. | universal; mvp |
| **openapi-and-clients** | OpenAPI spec from code, generate client SDKs. | python, node; core |

**Creation**: Add `tasks/<task-name>/` with TASK.md, config.yaml, universal/, stacks/{stack}/; register in task-index.yaml.

---

## 3. Blueprints — New Product Archetypes

Blueprints define *what to build* and drive project generation with stacks, tiers, and task lists.

| Suggestion | Description | Stacks | Example required tasks |
|------------|-------------|--------|------------------------|
| **api-first-backend** | Backend-only API (REST/GraphQL), no UI. | python, node, go | auth-basic, crud-module, health-and-readiness, openapi-and-clients |
| **mobile-plus-api** | Mobile app (Flutter/React Native) + backend API. | flutter, python/node | auth-basic, crud-module, push (optional) |
| **internal-tools** | Admin/dashboard for internal ops, authz by role. | node, python | auth-basic, audit-log, crud-module |
| **data-consumer** | Read-heavy: ingest, transform, serve (ETL + API). | python, node | auth-basic, search-basic, rate-limiting |
| **docs-and-content-site** | Docs site or marketing site (SSG/SSR). | node (Next/Astro), python (MkDocs) | — |
| **event-driven-service** | Event producer/consumer, message queue. | python, node, go | auth-basic, audit-log, health-and-readiness |

**Creation**: Add `blueprints/<id>/` with blueprint.meta.yaml, BLUEPRINT.md, overlays per stack.

---

## 4. Subagents — New Worker Profiles

Subagents are *who does the work*—curated skills, compatible blueprints/recipes, and workflows.

| Suggestion | Description | Primary skills | Workflows |
|------------|-------------|----------------|-----------|
| **code-reviewer** | PR/code review: structure, bugs, security, style. | clean-code, security-review-checklist, error-handling-and-logging | review → report |
| **testing-specialist** | Test design and implementation. | testing-strategies, refactoring-incremental | generate_tests, improve_coverage |
| **docs-writer** | README, API docs, ADRs, release notes. | documentation-as-code, changelog-and-release-notes | doc_pass, release_notes |
| **devops-and-observability** | CI/CD, health checks, logging, alerts. | safe-git-workflow, error-handling-and-logging | pipeline_check, observability_review |
| **security-auditor** | Security review and dependency audit. | security-review-checklist, api-design-rest | audit, dependency_audit |
| **refactor-specialist** | Safe, incremental refactors. | refactoring-incremental, testing-strategies | refactor_plan, execute_refactor |

**Creation**: Add `subagents/<id>/` with subagent.yaml, SUBAGENT.md, workflows/.

---

## 5. Rules — New Rule Files and Scopes

Rules define *how agents must behave*. Existing: AGENTS.md (canonical), CLAUDE.md, CURSOR.md, WINDSURF.md. Suggestions add tool entries or scope-specific rules.

| Suggestion | Description | Location / Name |
|------------|-------------|-----------------|
| **Additional tool rule file** | Entry for another AI tool (e.g. CODY.md, AIDER.md) that points to AGENTS.md and adds tool-specific commands. | Project root, ALL CAPS |
| **Frontend scope** | Conventions for UI: components, state, a11y, styling. | .cursor/rules/frontend.md |
| **Backend scope** | Conventions for APIs: auth, errors, logging, DB. | .cursor/rules/backend.md |
| **Docs scope** | How to update README, CHANGELOG, protocols. | .cursor/rules/docs.md |
| **Security rule section** | Blocked patterns, secrets, dependency checks; reference security protocol if present. | New section in AGENTS.md or linked .cursor/rules/security.md |

**Creation**: Use `.agents/skills/rules-setup/`. Keep one canonical AGENTS.md; add thin tool files and .cursor/rules/*.md as needed.

---

## 6. Recipes — New Feature Bundles

Recipes bundle *Tasks + Skills* for common scenarios. They reference tasks and list skills; optionally specify compatible blueprints.

| Suggestion | Description | Example tasks | Example skills |
|------------|-------------|---------------|----------------|
| **observability** | Logging, metrics, health, error tracking. | health-and-readiness, audit-log (optional) | error-handling-and-logging, documentation-as-code |
| **payments** | Payments and subscriptions. | billing-stripe | api-design-rest, security-review-checklist |
| **content-and-notifications** | Email + optional push. | email-send-and-templates, notification-center (if task exists) | documentation-as-code |
| **multi-tenant-saas** | Tenant isolation + billing. | multi-tenant-isolation, billing-stripe, auth-basic | security-review-checklist, api-design-rest |
| **search-and-discovery** | Search and basic discovery. | search-basic, rate-limiting | api-design-rest |
| **launch-readiness** | What’s needed before launch. | auth-basic, health-and-readiness, rate-limiting, audit-log | safe-git-workflow, changelog-and-release-notes |

**Creation**: Add `recipes/<id>/` with recipe.yaml (tasks, skills, blueprints.compatible), RECIPE.md.

---

## 7. Protocols — New Process Definitions

Protocols define *how a process works* in one versionable doc; Rules reference them, and **protocol skills** install/maintain them.

| Suggestion | Description | Referenced by | Protocol skill |
|------------|-------------|---------------|----------------|
| **SECURITY-REVIEW-PROTOCOL** | Steps for security review: secrets, dependencies, input validation, authz. | AGENTS.md Safety / Before deploy | security-review-setup (new skill) |
| **CHANGELOG-AND-EVENTS-PROTOCOL** | Event format, where to append, how to derive context/graph. | AGENTS.md Memory / CHANGELOG | memory-system-setup (extend) or changelog-protocol-setup |
| **BRANCHING-AND-RELEASE-PROTOCOL** | Branch strategy, release tags, versioning. | AGENTS.md Git Workflow | safe-git-workflow-setup (new skill) |
| **DOCUMENTATION-PROTOCOL** | When to update README/CHANGELOG/docs, where ADRs live. | AGENTS.md DOCUMENTING | documentation-protocol-setup (new skill) |
| **ROLLBACK-AND-INCIDENT-PROTOCOL** | Rollback steps, incident logging, post-mortem. | AGENTS.md or ops rule | incident-protocol-setup (new skill) |

**Creation**: Add `docs/protocols/PROTOCOL-NAME-PROTOCOL.md`. Create or extend a protocol skill that installs/updates it and optionally injects a short summary into AGENTS.md.

---

## Cross-Type Summary

| Type | Focus of suggestions |
|------|----------------------|
| **Skills** | Domain and quality (changelog, git, API design, testing, security, refactor, docs, dependencies). |
| **Tasks** | Concrete features (billing, email, upload, rate limit, audit, feature flags, search, multi-tenant, health, OpenAPI). |
| **Blueprints** | Product shapes (API-first, mobile+API, internal tools, data consumer, docs site, event-driven). |
| **Subagents** | Worker roles (reviewer, testing, docs, devops, security, refactor). |
| **Rules** | Extra tool entries and scope rules (frontend, backend, docs, security). |
| **Recipes** | Bundles (observability, payments, content/notifications, multi-tenant, search, launch-readiness). |
| **Protocols** | Processes (security review, changelog/events, branching/release, documentation, rollback/incident). |

---

## Suggested Order of Implementation

1. **Protocols + protocol skills** for any process you want agents to follow (e.g. SECURITY-REVIEW-PROTOCOL + security-review-setup).
2. **Rules** updates so AGENTS.md (or tool/scope rules) reference the new protocols.
3. **Skills** that match the protocols and fill capability gaps (e.g. security-review-checklist, changelog-and-release-notes).
4. **Tasks** for features you need in blueprints/recipes (e.g. billing-stripe, health-and-readiness).
5. **Blueprints** and **Recipes** that use those tasks and skills.
6. **Subagents** that bundle the new skills and workflows.

---

*For creating skills: `.agents/skills/skill-setup/`. For framework structure: `AGENTIC-ASSETS-FRAMEWORK.md`. For overview: `TEMPLATES-SYSTEM-OVERVIEW.md`.*
