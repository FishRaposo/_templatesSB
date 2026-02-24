# Knowledge Graph

_Queryable view of skills, packs, and their relationships_

**Last Updated:** 2026-02-23
**Source:** CHANGELOG.md, skill-packs/

## Entities

### Skill Packs

| ID | Name | Status | Skills Count | Reference Files |
|----|------|--------|--------------|-----------------|
| [[pack-001]] | 1-programming-core | Complete | 12 | 19 |
| [[pack-002]] | 2-code-quality | Complete | 12 | 19 |
| [[pack-003]] | 3-testing-mastery | In Progress | 12 | 0 |

### Standalone Skills

| ID | Name | Status | Location |
|----|------|--------|----------|
| [[skill-s001]] | skill-builder | Complete | /skill-builder/ |
| [[skill-s002]] | generating-agents-md | Complete | /agents-setup/ |
| [[skill-s003]] | memory-system | Complete | /memory-system/ |

### Skills (Pack 1 - Programming Core)

| ID | Name | Pack | Status |
|----|------|------|--------|
| [[skill-001]] | algorithms | pack-001 | Complete |
| [[skill-002]] | data-structures | pack-001 | Complete |
| [[skill-003]] | complexity-analysis | pack-001 | Complete |
| [[skill-004]] | problem-solving | pack-001 | Complete |
| [[skill-005]] | abstraction | pack-001 | Complete |
| [[skill-006]] | modularity | pack-001 | Complete |
| [[skill-007]] | recursion | pack-001 | Complete |
| [[skill-008]] | iteration-patterns | pack-001 | Complete |
| [[skill-009]] | functional-paradigm | pack-001 | Complete |
| [[skill-010]] | data-types | pack-001 | Complete |
| [[skill-011]] | control-flow | pack-001 | Complete |
| [[skill-012]] | metaprogramming | pack-001 | Complete |

### Reference Files (Sample)

| ID | Path | Type | Related |
|----|------|------|---------|
| [[ref-001]] | sorting-algorithms.md | guide | skill-001 |
| [[ref-002]] | hashmap-implementation.md | guide | skill-002 |
| [[ref-003]] | algorithm-optimization-patterns.md | guide | skill-001, skill-003 |
| [[ref-004]] | dynamic-programming-lis.md | guide | skill-004, skill-001 |
| [[ref-005]] | clean-code-patterns.md | guide | skill-101 |
| [[ref-006]] | refactoring-workflows.md | guide | skill-102 |

## Relations

### Depends On
- [[skill-003]] → depends on → [[skill-001]] (complexity builds on algorithms)
- [[skill-008]] → depends on → [[skill-007]] (iteration vs recursion)
- [[pack-003]] → depends on → [[pack-001]] (testing builds on fundamentals)
- [[pack-003]] → depends on → [[pack-002]] (testing works with quality skills)

### Part Of
- [[skill-001]] → part of → [[pack-001]]
- [[skill-002]] → part of → [[pack-001]]
- [[skill-003]] → part of → [[pack-001]]
- [[skill-004]] → part of → [[pack-001]]
- [[skill-005]] → part of → [[pack-001]]
- [[skill-006]] → part of → [[pack-001]]
- [[skill-007]] → part of → [[pack-001]]
- [[skill-008]] → part of → [[pack-001]]
- [[skill-009]] → part of → [[pack-001]]
- [[skill-010]] → part of → [[pack-001]]
- [[skill-011]] → part of → [[pack-001]]
- [[skill-012]] → part of → [[pack-001]]

### References
- [[ref-001]] → documents → [[skill-001]]
- [[ref-002]] → documents → [[skill-002]]
- [[ref-003]] → documents → [[skill-001]], [[skill-003]]
- [[ref-004]] → documents → [[skill-004]], [[skill-001]]

## Statistics

- **Total Packs:** 60 (3 started/complete, 57 planned)
- **Total Skills:** 766 (36 complete, 12 in progress, 718 planned)
- **Completed:** 2 packs (24 skills)
- **In Progress:** 1 pack (12 skills)
- **Reference Files:** 38 (19 per completed pack)

---

*Regenerate: After significant batch of skill creation*
