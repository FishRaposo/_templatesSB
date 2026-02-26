# FEATURES.md

**Purpose**: Feature inventory and capability matrix for {{PROJECT_NAME}}.
**Last Updated**: {{LAST_UPDATED_DATE}}

## Rules

- This file must cover **every feature explicitly mentioned** in the project requirements.
- If a requirement implies a feature, it must be included.
- Keep feature names stable and add a short ID if needed (e.g. `F-001`).

## Overview

## Feature Matrix

| Feature | Description | Status | Tier | Platform | Docs | Tests |
|--------|-------------|--------|------|----------|------|-------|
| [FEATURE_NAME] | [SHORT_DESCRIPTION] | [PLANNED|IN_PROGRESS|DONE] | [FREE|PREMIUM] | [ALL|WEB|IOS|ANDROID|DESKTOP] | [LINK_OR_N/A] | [LINK_OR_N/A] |

## Feature Details

For each feature listed above, add:

- **Scope**
- **User workflow summary** (link into `WORKFLOW.md` where applicable)
- **Acceptance criteria**
- **Key files/modules**
- **Docs to update** (e.g. `docs/USER-MANUAL.md`, `docs/API-REFERENCE.md`)

## Definitions

- **Status**: PLANNED, IN_PROGRESS, DONE
- **Tier**: FREE, PREMIUM

## Change Policy

- Update this file for every feature addition, modification, or removal.
- If a PR changes user-visible behavior, it must update:
  - `FEATURES.md`
  - `WORKFLOW.md`
  - any impacted docs under `docs/`
