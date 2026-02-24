#!/usr/bin/env python3
"""
Unified Project Analysis and Building Pipeline

This script creates an end-to-end automation system that:
1. Analyzes any project to detect stack, tasks, and tier requirements
2. Builds project scaffolding using the template system
3. Documents gaps and creates actionable implementation plans

Usage:
    python scripts/analyze_and_build.py --description "Real-time chat app with auth"
    python scripts/analyze_and_build.py --file project-requirements.txt
    python scripts/analyze_and_build.py --interactive
    python scripts/analyze_and_build.py --analyze-existing --build
    python scripts/analyze_and_build.py --dry-run --description "E-commerce platform"
"""

import argparse
import json
import yaml
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
import subprocess

# Import our existing systems
try:
    from detect_project_tasks import TaskDetectionSystem, TaskMatch, MissingTask, StackRecommendation
except ImportError:
    print("❌ Task detection system not found. Please ensure detect_project_tasks.py is available.")
    sys.exit(1)

class ProjectAnalysisPipeline:
    """Unified pipeline for project analysis, building, and gap documentation"""
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent
        self.tasks_dir = self.templates_dir / "tasks"
        self.task_index_path = self.tasks_dir / "task-index.yaml"
        self.gaps_dir = self.templates_dir / "docs" / "task-gaps"
        self.reports_dir = self.templates_dir / "reports"
        
        # Ensure directories exist
        self.gaps_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize detection system
        self.detector = TaskDetectionSystem()
        
        # Load task index for validation
        with open(self.task_index_path, 'r', encoding='utf-8') as f:
            self.task_index = yaml.safe_load(f)
    
    def analyze_project(self, description: str, suggest_stacks: bool = True) -> Dict[str, Any]:
        """Analyze project requirements and return comprehensive analysis"""
        print("🔍 Analyzing project requirements...")
        
        # Run task detection
        matched_tasks, gaps, stack_recommendation = self.detector.analyze_requirements(
            description, suggest_stacks
        )
        
        # Validate against available templates
        validated_tasks = self._validate_tasks(matched_tasks)
        
        # Build analysis report (keep objects for now, serialize later)
        analysis = {
            "timestamp": datetime.now().isoformat(),
            "description": description,
            "stack_recommendation": stack_recommendation,  # Keep as object
            "detected_tasks": validated_tasks,  # Keep as objects
            "detected_gaps": gaps,  # Keep as objects
            "validation_summary": self._create_validation_summary(validated_tasks, gaps),
            "build_readiness": self._assess_build_readiness(validated_tasks, gaps)
        }
        
        return analysis
    
    def _validate_tasks(self, tasks: List[TaskMatch]) -> List[TaskMatch]:
        """Validate detected tasks against available templates"""
        validated_tasks = []
        
        for task in tasks:
            task_id = task.task_id
            
            # Check if task exists in our template system
            if task_id in self.task_index.get('tasks', {}):
                task_data = self.task_index['tasks'][task_id]
                
                # Check if task has file mappings
                files = task_data.get('files', [])
                if files:
                    task.has_templates = True
                    task.template_count = len(files)
                else:
                    task.has_templates = False
                    task.template_count = 0
                
                validated_tasks.append(task)
            else:
                print(f"⚠️  Task {task_id} detected but not available in template system")
        
        return validated_tasks
    
    def _serialize_task_match(self, task: TaskMatch) -> Dict[str, Any]:
        """Serialize TaskMatch for JSON output"""
        return {
            "task_id": task.task_id,
            "task_name": task.task_name,
            "description": task.description,
            "categories": task.categories,
            "confidence": task.confidence,
            "matched_keywords": task.matched_keywords,
            "tier": task.tier,
            "has_templates": getattr(task, 'has_templates', False),
            "template_count": getattr(task, 'template_count', 0)
        }
    
    def _serialize_missing_task(self, gap: MissingTask) -> Dict[str, Any]:
        """Serialize MissingTask for JSON output"""
        return {
            "suggested_name": gap.suggested_name,
            "description": gap.description,
            "categories": gap.categories,
            "suggested_stacks": gap.suggested_stacks,
            "suggested_tier": gap.suggested_tier,
            "requirements": gap.requirements,
            "gap_reason": gap.gap_reason,
            "priority": gap.priority
        }
    
    def _create_validation_summary(self, tasks: List[TaskMatch], gaps: List[MissingTask]) -> Dict[str, Any]:
        """Create summary of validation results"""
        total_detected = len(tasks) + len(gaps)
        available_tasks = len([t for t in tasks if getattr(t, 'has_templates', False)])
        
        return {
            "total_requirements_detected": total_detected,
            "tasks_with_templates": available_tasks,
            "tasks_without_templates": len(tasks) - available_tasks,
            "identified_gaps": len(gaps),
            "coverage_percentage": round((available_tasks / total_detected * 100) if total_detected > 0 else 0, 1)
        }
    
    def _assess_build_readiness(self, tasks: List[TaskMatch], gaps: List[MissingTask]) -> Dict[str, Any]:
        """Assess how ready the project is for building"""
        available_tasks = len([t for t in tasks if getattr(t, 'has_templates', False)])
        high_confidence_tasks = len([t for t in tasks if t.confidence >= 0.5])
        high_priority_gaps = len([g for g in gaps if g.priority in ['high', 'critical']])
        
        if available_tasks >= 5 and high_confidence_tasks >= 3:
            readiness = "high"
        elif available_tasks >= 3 and high_confidence_tasks >= 2:
            readiness = "medium"
        else:
            readiness = "low"
        
        return {
            "readiness_level": readiness,
            "available_tasks": available_tasks,
            "high_confidence_tasks": high_confidence_tasks,
            "high_priority_gaps": high_priority_gaps,
            "recommendation": self._get_build_recommendation(readiness, available_tasks, high_priority_gaps)
        }
    
    def _get_build_recommendation(self, readiness: str, available_tasks: int, high_priority_gaps: int) -> str:
        """Get build recommendation based on readiness assessment"""
        if readiness == "high":
            return "Ready to build with current templates. Address gaps in future iterations."
        elif readiness == "medium":
            return "Can build core functionality. Consider addressing high-priority gaps first."
        else:
            return "Limited building capability. Recommend addressing gaps before proceeding."
    
    def generate_build_config(self, analysis: Dict[str, Any], output_path: Optional[Path] = None) -> Dict[str, Any]:
        """Generate resolver-compatible build configuration"""
        print("⚙️  Generating build configuration...")
        
        # Extract stack recommendation
        stack_rec = analysis.get("stack_recommendation")
        primary_stack = stack_rec.primary_stack if stack_rec else "python"
        secondary_stack = stack_rec.secondary_stack if stack_rec else None
        
        # Filter tasks that have templates
        buildable_tasks = [
            task for task in analysis["detected_tasks"] 
            if getattr(task, 'has_templates', False)
        ]
        
        # Determine tier based on task complexity and confidence
        high_confidence_tasks = len([t for t in buildable_tasks if t.confidence >= 0.5])
        if high_confidence_tasks >= 5:
            tier = "full"
        elif high_confidence_tasks >= 3:
            tier = "core"
        else:
            tier = "mvp"
        
        # Create build configuration
        build_config = {
            "project": {
                "name": "detected-project",
                "stack": primary_stack,
                "secondary_stack": secondary_stack,
                "tier": tier,
                "description": analysis["description"],
                "generated_at": analysis["timestamp"]
            },
            "tasks": {},
            "metadata": {
                "detection_confidence": "high" if analysis["validation_summary"]["coverage_percentage"] >= 70 else "medium",
                "total_tasks": len(buildable_tasks),
                "source": "automated_detection"
            }
        }
        
        # Add tasks to configuration
        for task in buildable_tasks:
            task_id = task.task_id
            build_config["tasks"][task_id] = {
                "enabled": True,
                "tier": task.tier or tier,
                "confidence": task.confidence,
                "categories": task.categories
            }
        
        # Save configuration if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(build_config, f, default_flow_style=False, allow_unicode=True)
            print(f"✅ Build configuration saved: {output_path}")
        
        return build_config
    
    def build_project(self, build_config: Dict[str, Any], output_dir: Path, dry_run: bool = False) -> bool:
        """Build project using the template system"""
        if dry_run:
            print("🔍 DRY RUN: Would build project with configuration:")
            print(f"  Stack: {build_config['project']['stack']}")
            print(f"  Tier: {build_config['project']['tier']}")
            print(f"  Tasks: {len(build_config['tasks'])}")
            for task_id in build_config['tasks']:
                print(f"    - {task_id}")
            return True
        
        print(f"🏗️  Building project in: {output_dir}")
        
        # Create temporary config file for resolver
        temp_config = output_dir / "build-config.yaml"
        with open(temp_config, 'w', encoding='utf-8') as f:
            yaml.dump(build_config, f, default_flow_style=False, allow_unicode=True)
        
        try:
            # Call resolver script
            resolver_script = self.templates_dir / "scripts" / "resolve_project.py"
            if not resolver_script.exists():
                print("❌ Resolver script not found")
                return False
            
            result = subprocess.run([
                sys.executable, str(resolver_script),
                "--config", str(temp_config),
                "--output", str(output_dir)
            ], capture_output=True, text=True, cwd=self.templates_dir)
            
            if result.returncode == 0:
                print("✅ Project built successfully")
                print(result.stdout)
                return True
            else:
                print(f"❌ Build failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Build error: {e}")
            return False
        finally:
            # Clean up temporary config
            if temp_config.exists():
                temp_config.unlink()
    
    def generate_gap_documentation(self, analysis: Dict[str, Any], output_path: Optional[Path] = None) -> str:
        """Generate comprehensive gap documentation"""
        print("📝 Generating gap documentation...")
        
        gaps = analysis["detected_gaps"]
        if not gaps:
            return "No gaps identified - all detected requirements are covered by available templates."
        
        # Sort gaps by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_gaps = sorted(gaps, key=lambda g: priority_order.get(g.priority, 3))
        
        # Generate markdown documentation
        doc_content = f"""# Task Gap Analysis Report

**Generated:** {analysis['timestamp']}  
**Project:** {analysis['description'][:100]}{'...' if len(analysis['description']) > 100 else ''}

## Summary

- **Total Gaps Identified:** {len(gaps)}
- **Critical Priority:** {len([g for g in gaps if g.priority == 'critical'])}
- **High Priority:** {len([g for g in gaps if g.priority == 'high'])}
- **Medium Priority:** {len([g for g in gaps if g.priority == 'medium'])}
- **Low Priority:** {len([g for g in gaps if g.priority == 'low'])}

## Implementation Roadmap

### Phase 1: Critical & High Priority Gaps
{self._generate_phase_section([g for g in sorted_gaps if g.priority in ['critical', 'high']])}

### Phase 2: Medium Priority Gaps
{self._generate_phase_section([g for g in sorted_gaps if g.priority == 'medium'])}

### Phase 3: Low Priority Gaps
{self._generate_phase_section([g for g in sorted_gaps if g.priority == 'low'])}

## Detailed Gap Analysis

{self._generate_detailed_gaps(sorted_gaps)}

## Implementation Guidelines

### Adding New Tasks

1. **Create Task Directory:**
   ```bash
   mkdir tasks/{{TASK_NAME}}
   ```

2. **Generate Templates:**
   ```bash
   python scripts/scaffold_tasks.py --task {{TASK_NAME}}
   ```

3. **Update Task Index:**
   - Add task metadata to `tasks/expanded-task-index.yaml`
   - Regenerate file mappings with `python scripts/generate_task_mappings.py`

4. **Test Integration:**
   ```bash
   python scripts/detect_project_tasks.py --description "test {{TASK_NAME}}"
   ```

### Priority Guidelines

- **Critical:** Core functionality that blocks project viability
- **High:** Important features that significantly impact user experience
- **Medium:** Nice-to-have features that enhance functionality
- **Low:** Optional features or edge cases

---
*This report was generated automatically by the Project Analysis Pipeline*
"""
        
        # Save documentation if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(doc_content)
            print(f"✅ Gap documentation saved: {output_path}")
        
        return doc_content
    
    def _generate_phase_section(self, gaps: List[MissingTask]) -> str:
        """Generate implementation phase section"""
        if not gaps:
            return "No gaps in this phase.\n"
        
        section = ""
        for gap in gaps:
            section += f"- **{gap.suggested_name}** ({gap.priority} priority)\n"
            section += f"  - Categories: {', '.join(gap.categories)}\n"
            section += f"  - Suggested stacks: {', '.join(gap.suggested_stacks)}\n"
        return section + "\n"
    
    def _generate_detailed_gaps(self, gaps: List[MissingTask]) -> str:
        """Generate detailed gap analysis"""
        details = ""
        for i, gap in enumerate(gaps, 1):
            details += f"""### {i}. {gap.suggested_name}

**Priority:** {gap.priority}  
**Categories:** {', '.join(gap.categories)}  
**Suggested Stacks:** {', '.join(gap.suggested_stacks)}  
**Suggested Tier:** {gap.suggested_tier}

**Description:**
{gap.description}

**Gap Reason:**
{gap.gap_reason}

**Requirements:**
"""
            for req in gap.requirements:
                details += f"- {req}\n"
            
            details += "\n---\n\n"
        
        return details
    
    def run_full_pipeline(self, description: str, output_dir: Path, 
                          build: bool = True, dry_run: bool = False) -> Dict[str, Any]:
        """Run the complete analysis and building pipeline"""
        print("🚀 Starting Project Analysis and Building Pipeline")
        print("=" * 60)
        
        # Step 1: Analyze project
        analysis = self.analyze_project(description)
        
        # Step 2: Generate build configuration
        build_config = self.generate_build_config(analysis)
        
        # Step 3: Build project (if requested)
        build_success = True
        if build and not dry_run:
            build_success = self.build_project(build_config, output_dir, dry_run)
        
        # Step 4: Generate gap documentation
        gap_doc = self.generate_gap_documentation(analysis)
        
        # Step 5: Serialize analysis for JSON export
        serialized_analysis = self._serialize_analysis_for_export(analysis)
        
        # Step 6: Save comprehensive report
        report = {
            "analysis": serialized_analysis,
            "build_config": build_config,
            "build_success": build_success,
            "gap_documentation": gap_doc
        }
        
        report_path = output_dir / "analysis-report.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        gap_doc_path = output_dir / "gap-analysis.md"
        with open(gap_doc_path, 'w', encoding='utf-8') as f:
            f.write(gap_doc)
        
        build_config_path = output_dir / "build-config.yaml"
        with open(build_config_path, 'w', encoding='utf-8') as f:
            yaml.dump(build_config, f, default_flow_style=False, allow_unicode=True)
        
        # Print summary
        self._print_pipeline_summary(analysis, build_success, output_dir)
        
        return report
    
    def _serialize_analysis_for_export(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize analysis objects for JSON export"""
        serialized = {
            "timestamp": analysis["timestamp"],
            "description": analysis["description"],
            "validation_summary": analysis["validation_summary"],
            "build_readiness": analysis["build_readiness"]
        }
        
        # Serialize stack recommendation
        stack_rec = analysis.get("stack_recommendation")
        if stack_rec:
            serialized["stack_recommendation"] = {
                "primary_stack": stack_rec.primary_stack,
                "secondary_stack": stack_rec.secondary_stack,
                "confidence": stack_rec.confidence,
                "reasoning": stack_rec.reasoning,
                "use_case": stack_rec.use_case
            }
        else:
            serialized["stack_recommendation"] = None
        
        # Serialize detected tasks
        serialized["detected_tasks"] = [
            self._serialize_task_match(task) for task in analysis["detected_tasks"]
        ]
        
        # Serialize detected gaps
        serialized["detected_gaps"] = [
            self._serialize_missing_task(gap) for gap in analysis["detected_gaps"]
        ]
        
        return serialized
    
    def _print_pipeline_summary(self, analysis: Dict[str, Any], build_success: bool, output_dir: Path):
        """Print pipeline execution summary"""
        print("\n" + "=" * 60)
        print("📊 PIPELINE EXECUTION SUMMARY")
        print("=" * 60)
        
        summary = analysis["validation_summary"]
        readiness = analysis["build_readiness"]
        
        print(f"📈 Requirements Analysis:")
        print(f"   Total detected: {summary['total_requirements_detected']}")
        print(f"   Coverage: {summary['coverage_percentage']}%")
        print(f"   Ready to build: {summary['tasks_with_templates']} tasks")
        
        print(f"\n🎯 Build Readiness: {readiness['readiness_level'].upper()}")
        print(f"   Recommendation: {readiness['recommendation']}")
        
        if analysis["stack_recommendation"]:
            stack = analysis["stack_recommendation"]
            print(f"\n🔧 Stack Recommendation:")
            print(f"   Primary: {stack.primary_stack}")
            if stack.secondary_stack:
                print(f"   Secondary: {stack.secondary_stack}")
            print(f"   Confidence: {stack.confidence:.2f}")
        
        if analysis["detected_gaps"]:
            print(f"\n⚠️  Gaps Identified: {len(analysis['detected_gaps'])}")
            high_priority = len([g for g in analysis["detected_gaps"] if g.priority in ["critical", "high"]])
            if high_priority > 0:
                print(f"   High priority: {high_priority}")
        
        print(f"\n📁 Output Files:")
        print(f"   Project: {output_dir}")
        print(f"   Report: {output_dir / 'analysis-report.json'}")
        print(f"   Gap analysis: {output_dir / 'gap-analysis.md'}")
        print(f"   Build config: {output_dir / 'build-config.yaml'}")
        
        if build_success:
            print(f"\n✅ Status: Pipeline completed successfully")
        else:
            print(f"\n⚠️  Status: Analysis complete, build may have issues")

def main():
    """Main entry point"""
    
    # Import prompt validation
    try:
        from prompt_validator import PromptValidator, ValidationLevel
    except ImportError:
        print("❌ ERROR: Prompt validation is required for security")
        print("Please ensure prompt_validator.py is available in the scripts directory")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="Project Analysis and Building Pipeline")
    parser.add_argument("--description", help="Project description to analyze")
    parser.add_argument("--file", help="File containing project requirements")
    parser.add_argument("--interactive", action="store_true", help="Run interactive analysis")
    parser.add_argument("--analyze-existing", action="store_true", help="Analyze existing project files")
    parser.add_argument("--output", help="Output directory for generated project", default="generated-project")
    parser.add_argument("--build", action="store_true", default=True, help="Build the project")
    parser.add_argument("--no-build", action="store_true", help="Skip building, only analyze")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without executing")
    parser.add_argument("--config-only", action="store_true", help="Only generate build configuration")
    
    args = parser.parse_args()
    
    # Validate all inputs before processing
    validator = PromptValidator(ValidationLevel.STANDARD)
    
    # Validate project description if provided
    if args.description:
        desc_result = validator.validate_project_description(args.description)
        if not desc_result.is_valid:
            print("❌ Project description validation failed:")
            for error in desc_result.errors:
                print(f"   - {error}")
            sys.exit(1)
        
        # Show warnings if any
        if desc_result.warnings:
            print("⚠️  Project description warnings:")
            for warning in desc_result.warnings:
                print(f"   - {warning}")
            print()
    
    # Validate output directory
    if args.output:
        args_dict = {'output': args.output}
        output_result = validator.validate_cli_arguments(args_dict)
        if not output_result.is_valid:
            print("❌ Output directory validation failed:")
            for error in output_result.errors:
                print(f"   - {error}")
            sys.exit(1)
    
    # Handle build flags
    build = args.build and not args.no_build and not args.config_only
    
    # Initialize pipeline
    pipeline = ProjectAnalysisPipeline()
    
    # Get project description
    description = ""
    if args.interactive:
        print("🔍 Interactive Project Analysis")
        print("=" * 40)
        description = input("Describe your project: ").strip()
        
        # Validate interactive input
        desc_result = validator.validate_project_description(description)
        if not desc_result.is_valid:
            print("❌ Project description validation failed:")
            for error in desc_result.errors:
                print(f"   - {error}")
            sys.exit(1)
        
        # Show warnings if any
        if desc_result.warnings:
            print("⚠️  Project description warnings:")
            for warning in desc_result.warnings:
                print(f"   - {warning}")
            print()
            
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                description = f.read()
            
            # Validate file content
            desc_result = validator.validate_project_description(description)
            if not desc_result.is_valid:
                print("❌ File content validation failed:")
                for error in desc_result.errors:
                    print(f"   - {error}")
                sys.exit(1)
            
            # Show warnings if any
            if desc_result.warnings:
                print("⚠️  File content warnings:")
                for warning in desc_result.warnings:
                    print(f"   - {warning}")
                print()
                    
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            sys.exit(1)
    elif args.description:
        description = args.description
    else:
        print("❌ Error: Please provide a project description using --description, --file, or --interactive")
        parser.print_help()
        sys.exit(1)
    if not description:
        print("❌ No project description provided")
        return
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)
    
    # Run pipeline
    if args.config_only:
        # Only generate build configuration
        analysis = pipeline.analyze_project(description)
        build_config = pipeline.generate_build_config(analysis, output_dir / "build-config.yaml")
        print(f"✅ Build configuration generated: {output_dir / 'build-config.yaml'}")
    else:
        # Run full pipeline
        report = pipeline.run_full_pipeline(
            description=description,
            output_dir=output_dir,
            build=build,
            dry_run=args.dry_run
        )

if __name__ == "__main__":
    main()
