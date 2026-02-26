# Task Validation Matrix

## Required Task Components

Based on examining existing tasks, each task should have:
1. **Universal Templates** (in `universal/` directory)
   - `code/` - Universal code templates
   - `docs/` - Documentation templates
   - `tests/` - Test strategy templates
2. **Stack Implementations** (in `stacks/` directory)
   - At least one stack implementation
   - Each stack should have `code/`, `docs/`, `tests/`
3. **Metadata** (in task-index.yaml)
   - Description, categories, allowed_stacks
   - File mappings with proper template paths
   - Invariant reference

## Task Validation Results

| Task | Universal Code | Universal Docs | Universal Tests | Stack Count | Full Support Stacks | Base-Fallback Stacks | Status |
|------|----------------|----------------|-----------------|-------------|-------------------|---------------------|--------|

### Analysis of Sample Tasks

#### ✅ Well-Implemented Tasks
- **auth-basic**: Has universal templates + 3 stack implementations (node, python, nextjs)
- **crud-module**: Has universal templates + 5 stack implementations
- **rest-api-service**: Has universal templates + 4 stack implementations

#### ⚠️ Tasks with Limited Implementation
- **llm-prompt-router**: Has universal templates but only 2 stack implementations
- Many AI-specific tasks likely have similar limitations

## Key Findings

### Universal Template Coverage
- All examined tasks have the required universal directory structure
- Universal templates provide fallback for unsupported stacks

### Stack Implementation Gaps
1. **Limited Stack Coverage**: Most tasks only implement 2-5 stacks out of 12
2. **Missing Modern Stacks**: Many tasks lack rust, typescript, flutter implementations
3. **Inconsistent Support**: Some tasks have go, others don't

### Categories with Poor Coverage
1. **AI-Specific Tasks** (llm-prompt-router, rag-pipeline, agentic-workflow)
2. **SEO/Growth Tasks** (seo-* tasks)
3. **Data Analytics Tasks** (segmentation-clustering, forecasting-engine)

## Recommendations

### Immediate Actions
1. **Prioritize Core Tasks**: Ensure auth-basic, rest-api-service, web-scraping have full stack support
2. **Add Base Templates**: All stacks should have base templates (already done)
3. **Update Documentation**: Clearly mark which stacks have full vs base-fallback support

### Implementation Strategy
1. **Phase 1**: Add stack implementations for high-demand tasks
   - auth-basic, rest-api-service, web-scraping, crud-module
   - Target stacks: rust, typescript, flutter
   
2. **Phase 2**: Expand to specialized categories
   - AI tasks: Add python/node implementations
   - SEO tasks: Add web framework support
   
3. **Phase 3**: Comprehensive coverage
   - All 47 tasks with at least 4 stack implementations
   - Focus on most-used stacks per category

## Validation Checklist

For each task:
- [ ] Universal templates exist in all categories
- [ ] At least one stack implementation exists
- [ ] Task-index.yaml entry is complete
- [ ] Invariant file exists and is referenced
- [ ] Stack support levels are accurately marked
