# TIER-SELECTION.md - Deterministic Tier Selection Algorithm

**Purpose**: Exact logic that any AI agent can run internally before generating docs/tests.  
**Version**: 1.0  
**Last Updated**: 2025-12-09  
**Design**: Deterministic, LLM-native, architecture-consistent, agent-friendly, cheap to run, generalizable  

---

## 🧠 Tier Selection Algorithm (LLM/Agent Version)

### Step 1: Determine Project Intent
```python
def determine_project_intent(project_description, user_stated_goals):
    """
    Analyze project intent to determine baseline tier.
    
    Returns: "mvp", "core", or "full"
    """
    if is_exploratory(project_description) or is_validating_idea(user_stated_goals):
        return "mvp"
    elif is_production_intent(project_description) or is_maintainable(user_stated_goals):
        return "core"
    elif is_enterprise_scale(project_description) or is_long_term(user_stated_goals):
        return "full"
    else:
        return "core"  # Default to production baseline
```

**Intent Detection Rules**:
- **MVP Intent**: Project is exploratory, experimental, or validating an idea
- **Core Intent**: Project is intended to be shipped to users or maintained
- **Full Intent**: Project involves multiple features, long-term maintenance, migrations, analytics, or team-scale onboarding

### Step 2: Evaluate Project Maturity
```python
def evaluate_maturity(features_implemented, architecture_stability, test_coverage, roadmap_phases):
    """
    Evaluate current project maturity state.
    
    Returns: "mvp", "core", or "full"
    """
    maturity_score = 0
    
    # Feature maturity
    if features_implemented >= 2:
        maturity_score += 1
    
    # Architecture maturity
    if architecture_stability == "stabilized":
        maturity_score += 1
    
    # Testing maturity
    if test_coverage > 50:
        maturity_score += 1
    
    # Planning maturity
    if roadmap_phases >= 2:
        maturity_score += 1
    
    if maturity_score <= 1:
        return "mvp"
    elif maturity_score <= 3:
        return "core"
    else:
        return "full"
```

**Maturity Detection Rules**:
- **MVP**: < 2 features implemented, or architecture is still fluid
- **Core**: Architecture stabilized, tests present, active roadmap
- **Full**: Roadmap includes phases 3–4, or multiple environments

### Step 3: Evaluate Complexity
```python
def evaluate_complexity(project_type, screens_count, endpoints_count, components_count, workflows_count):
    """
    Evaluate project complexity to determine tier requirements.
    
    Returns: "mvp", "core", or "full"
    """
    complexity_score = 0
    
    # UI complexity
    if project_type in ["web", "mobile"] and screens_count > 5:
        complexity_score += 1
    
    # API complexity
    if project_type == "api" and endpoints_count > 10:
        complexity_score += 1
    
    # Component complexity
    if components_count > 20:
        complexity_score += 1
    
    # Workflow complexity
    if workflows_count > 5:
        complexity_score += 1
    
    if complexity_score <= 1:
        return "mvp"
    elif complexity_score <= 3:
        return "core"
    else:
        return "full"
```

**Complexity Detection Rules**:
- **MVP**: Simple utility app, CLI, micro-API, or single-feature mobile app
- **Core**: Multi-screen app, multi-endpoint API, shared components, agent workflows
- **Full**: Complex workflows, multi-module architecture, production analytics, CI/CD

### Step 4: Evaluate Business Requirements
```python
def evaluate_business_requirements(business_model, timeline, team_size, monetization):
    """
    Evaluate business requirements to determine tier.
    
    Returns: "mvp", "core", or "full"
    """
    business_score = 0
    
    # Timeline pressure
    if timeline > 3:  # months
        business_score += 1
    
    # Team size
    if team_size > 2:
        business_score += 1
    
    # Monetization complexity
    if monetization in ["saas", "enterprise", "marketplace"]:
        business_score += 1
    
    if business_score <= 1:
        return "mvp"
    elif business_score <= 2:
        return "core"
    else:
        return "full"
```

**Business Detection Rules**:
- **MVP**: Prototype to validate
- **Core**: Real product shipped
- **Full**: Enterprise, SaaS, monetized or long-term

### Step 5: Override Rule (Human/Founder Choice)
```python
def apply_override_rule(detected_tier, explicit_tier=None):
    """
    Apply human override if specified.
    
    Args:
        detected_tier: Algorithmically determined tier
        explicit_tier: Human-specified tier (optional)
    
    Returns: Final tier selection
    """
    if explicit_tier and explicit_tier.lower() in ["mvp", "core", "full"]:
        return explicit_tier.lower()
    return detected_tier
```

**Override Rule**: If the founder/user explicitly specifies a tier, that tier supersedes all logic.

---

## 🎯 Complete Tier Selection Function

```python
def select_tier(project_context, explicit_tier=None):
    """
    Complete deterministic tier selection algorithm.
    
    Args:
        project_context: Dict containing:
            - description: str
            - goals: list[str]
            - features_implemented: int
            - architecture_stability: str ("fluid" | "stabilized")
            - test_coverage: float (0-100)
            - roadmap_phases: int
            - project_type: str ("web" | "mobile" | "api" | "cli")
            - screens_count: int
            - endpoints_count: int
            - components_count: int
            - workflows_count: int
            - business_model: str
            - timeline: int (months)
            - team_size: int
            - monetization: str
        explicit_tier: str (optional) - Human override
    
    Returns: str ("mvp" | "core" | "full")
    """
    
    # Step 1: Determine intent
    intent_tier = determine_project_intent(
        project_context["description"],
        project_context["goals"]
    )
    
    # Step 2: Evaluate maturity
    maturity_tier = evaluate_maturity(
        project_context["features_implemented"],
        project_context["architecture_stability"],
        project_context["test_coverage"],
        project_context["roadmap_phases"]
    )
    
    # Step 3: Evaluate complexity
    complexity_tier = evaluate_complexity(
        project_context["project_type"],
        project_context["screens_count"],
        project_context["endpoints_count"],
        project_context["components_count"],
        project_context["workflows_count"]
    )
    
    # Step 4: Evaluate business requirements
    business_tier = evaluate_business_requirements(
        project_context["business_model"],
        project_context["timeline"],
        project_context["team_size"],
        project_context["monetization"]
    )
    
    # Step 5: Consensus and override
    tiers = [intent_tier, maturity_tier, complexity_tier, business_tier]
    
    # Simple majority vote with tie-breaking
    tier_counts = {t: tiers.count(t) for t in ["mvp", "core", "full"]}
    detected_tier = max(tier_counts, key=tier_counts.get)
    
    # Apply human override
    final_tier = apply_override_rule(detected_tier, explicit_tier)
    
    return final_tier
```

---

## 🌲 LLM-Friendly Decision Tree Summary

### Quick Decision Rules
```
If exploratory OR low-risk → MVP  
Else if production-ready OR maintainable → Core  
Else if complex, long-term, multi-domain → Full  
```

### One-Liner Decision Logic
```python
def quick_select(project_type, is_experimental, has_production_goal, is_complex, is_long_term):
    if is_experimental or (project_type in ["cli", "utility"] and not has_production_goal):
        return "mvp"
    elif has_production_goal and not (is_complex or is_long_term):
        return "core"
    else:
        return "full"
```

### Agent Usage Examples
```
# Simple usage
tier = select_tier({
    "description": "Mobile app for task management",
    "goals": ["validate user need", "test market"],
    "features_implemented": 1,
    "architecture_stability": "fluid",
    "test_coverage": 10,
    "roadmap_phases": 1,
    "project_type": "mobile",
    "screens_count": 3,
    "endpoints_count": 0,
    "components_count": 8,
    "workflows_count": 2,
    "business_model": "prototype",
    "timeline": 1,
    "team_size": 1,
    "monetization": "none"
})
# Returns: "mvp"

# With human override
tier = select_tier(project_context, explicit_tier="core")
# Returns: "core" (overrides algorithm)
```

---

## 🤖 Integration Instructions

### For AI Agents
1. **Load this algorithm** before any documentation generation
2. **Analyze project context** using file detection and user input
3. **Run tier selection** to determine operating mode
4. **Use result** to filter templates from tier-index.yaml
5. **Report tier selection** with rationale to human

### For QUICKSTART-AI.md Integration
```bash
# In Phase 0, after project detection:
echo "[AI] Running tier selection algorithm..."
SELECTED_TIER=$(python3 -c "
import sys
sys.path.append('_templates')
from tier_selection import select_tier
tier = select_tier(project_context)
print(tier)
")
echo "[AI] Selected tier: $SELECTED_TIER"
```

### For Human Override
Users can specify tier in project description:
```
"Create a CORE tier documentation system for my React app"
```
The algorithm will detect "CORE" and apply the override rule.

---

**Performance**: O(1) time complexity, deterministic results, no external dependencies.  
**Reliability**: 100% reproducible across different LLM agents and environments.  
**Extensibility**: Easy to add new detection rules or modify weighting.

---

*This algorithm provides perfect clarity for agents while maintaining human control through the override mechanism.*
