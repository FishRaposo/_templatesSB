#!/usr/bin/env python3
"""
Tier Upgrade Detection System
Automatically analyzes project metrics and suggests tier upgrades (MVP → Core → Enterprise)

Version: 1.0.0
Last Updated: 2025-12-10
"""

import os
import yaml
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import argparse

UPGRADE_DETECTOR_VERSION = "1.0.0"

class TierUpgradeDetector:
    def __init__(self, project_dir: str = "."):
        self.project_dir = Path(project_dir)
        self.templates_dir = self.find_templates_dir()
        self.tier_index = self.load_tier_index()
        self.current_tier = self.detect_current_tier()
        self._project_metrics = None  # Cache for idempotency
        
    @property
    def project_metrics(self) -> Dict:
        """Get project metrics with caching for idempotency"""
        if self._project_metrics is None:
            self._project_metrics = self.analyze_project_metrics()
        return self._project_metrics
        
    def find_templates_dir(self) -> Optional[Path]:
        """Find the _templates directory"""
        current = self.project_dir
        while current != current.parent:
            templates_dir = current / "_templates"
            if templates_dir.exists():
                return templates_dir
            current = current.parent
        return None
    
    def load_tier_index(self) -> Dict:
        """Load tier-index.yaml from templates directory"""
        if not self.templates_dir:
            return {}
        
        tier_index_file = self.templates_dir / "tier-index.yaml"
        if not tier_index_file.exists():
            return {}
        
        with open(tier_index_file, 'r') as f:
            return yaml.safe_load(f)
    
    def get_upgrade_criteria(self) -> Dict:
        """Get upgrade criteria from tier-index.yaml or use defaults"""
        # Check if criteria are defined in tier-index.yaml
        upgrade_criteria = {}
        
        try:
            upgrade_criteria = self.tier_index.get("upgrade_criteria", {})
            
            # Validate the structure of upgrade criteria
            if upgrade_criteria:
                required_keys = ["mvp_to_core", "core_to_enterprise"]
                for key in required_keys:
                    if key not in upgrade_criteria:
                        print(f"⚠️  Missing upgrade criteria '{key}' in tier-index.yaml, using defaults")
                        upgrade_criteria = {}
                        break
                    else:
                        # Validate each criteria has required fields
                        criteria = upgrade_criteria[key]
                        if not isinstance(criteria, dict):
                            print(f"⚠️  Invalid upgrade criteria format for '{key}', using defaults")
                            upgrade_criteria = {}
                            break
        except Exception as e:
            print(f"⚠️  Error reading upgrade criteria from tier-index.yaml: {str(e)}")
            print("⚠️  Using default upgrade criteria")
            upgrade_criteria = {}
        
        if not upgrade_criteria:
            # Use default criteria with configurable readiness threshold
            upgrade_criteria = {
                "mvp_to_core": {
                    "min_files": 10,
                    "min_docs": 5,
                    "min_coverage": 70,
                    "min_size_kb": 50,
                    "min_complexity": 3,
                    "min_age_days": 7,
                    "readiness_threshold": 0.7
                },
                "core_to_enterprise": {
                    "min_files": 25,
                    "min_docs": 15,
                    "min_coverage": 90,
                    "min_size_kb": 200,
                    "min_complexity": 6,
                    "min_team_indicators": 5,
                    "min_age_days": 30,
                    "readiness_threshold": 0.7
                }
            }
        
        return upgrade_criteria
    
    def detect_current_tier(self) -> str:
        """Detect current project tier based on existing files"""
        if not self.templates_dir:
            return "unknown"
        
        # Look for tier indicators in project files
        tier_indicators = {
            "mvp": ["TODO.md", "smoke_test", "0-20%"],
            "core": ["TESTING.md", "85%+", "DOCUMENTATION-BLUEPRINT.md", "FRAMEWORK-PATTERNS.md"],
            "enterprise": ["TESTING-STRATEGY.md", "95%+", "SECURITY.md", "DEPLOYMENT.md", "DATA-MODEL.md"]
        }
        
        tier_scores = {"mvp": 0, "core": 0, "enterprise": 0}
        
        # Check README.md for tier mentions
        readme_file = self.project_dir / "README.md"
        if readme_file.exists():
            with open(readme_file, 'r') as f:
                content = f.read().lower()
                for tier, indicators in tier_indicators.items():
                    for indicator in indicators:
                        if indicator.lower() in content:
                            tier_scores[tier] += 2
        
        # Check documentation files
        for file_path in self.project_dir.rglob("*.md"):
            if file_path.is_file():
                try:
                    with open(file_path, 'r') as f:
                        content = f.read().lower()
                        for tier, indicators in tier_indicators.items():
                            for indicator in indicators:
                                if indicator.lower() in content:
                                    tier_scores[tier] += 1
                except:
                    continue
        
        # Return tier with highest score
        if tier_scores["enterprise"] >= 3:
            return "enterprise"
        elif tier_scores["core"] >= 3:
            return "core"
        elif tier_scores["mvp"] >= 1:
            return "mvp"
        
        return "unknown"
    
    def get_actual_test_coverage(self) -> float:
        """Get actual test coverage from coverage tools"""
        # Use the cached metrics if available, otherwise call with empty metrics
        if hasattr(self, '_project_metrics') and self._project_metrics:
            return self.get_actual_test_coverage_with_metrics(self._project_metrics)
        else:
            return self.get_actual_test_coverage_with_metrics({})
    
    def get_actual_test_coverage_with_metrics(self, metrics: Dict) -> float:
        """Get actual test coverage from coverage tools"""
        # Try different coverage tools based on project type
        coverage_commands = [
            # Python coverage
            ["python", "-m", "coverage", "report", "--format=json"],
            ["pytest", "--cov=json"],
            # JavaScript/Node coverage
            ["npm", "test", "--", "--coverage", "--json"],
            ["yarn", "test", "--coverage", "--json"],
            # Dart/Flutter coverage
            ["flutter", "test", "--coverage"],
            # Go coverage
            ["go", "test", "-coverprofile=coverage.out"],
        ]
        
        for cmd in coverage_commands:
            try:
                import subprocess
                print(f"ℹ️  Trying coverage tool: {' '.join(cmd)}")
                result = subprocess.run(cmd, cwd=self.project_dir, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    coverage = self.parse_coverage_output(result.stdout, cmd[0])
                    if coverage > 0:
                        print(f"✅ Coverage tool succeeded: {coverage:.1f}%")
                        return coverage
                else:
                    print(f"⚠️  Coverage tool failed: {result.stderr.strip()}")
            except subprocess.TimeoutExpired:
                print(f"⚠️  Coverage tool timed out after 60s: {' '.join(cmd)}")
            except Exception as e:
                print(f"⚠️  Coverage tool error: {str(e)}")
                continue
        
        print(f"⚠️  All coverage tools failed, using estimation fallback")
        # Fallback to estimation if no coverage tool works
        return self.estimate_test_coverage()
    
    def parse_coverage_output(self, output: str, tool: str) -> float:
        """Parse coverage output from different tools"""
        try:
            if "coverage" in tool.lower():
                # Python coverage.py JSON output
                data = json.loads(output)
                if "totals" in data:
                    return data["totals"].get("percent_covered", 0)
            elif "pytest" in tool.lower():
                # Pytest coverage
                lines = output.split('\n')
                for line in lines:
                    if "TOTAL" in line and "%" in line:
                        match = re.search(r'(\d+\.?\d*)%', line)
                        if match:
                            return float(match.group(1))
            elif "flutter" in tool.lower():
                # Flutter coverage
                lines = output.split('\n')
                for line in lines:
                    if "lines" in line.lower() and "%" in line:
                        match = re.search(r'(\d+\.?\d*)%', line)
                        if match:
                            return float(match.group(1))
        except:
            pass
        
        return 0.0
    
    def estimate_test_coverage(self) -> float:
        """Fallback test coverage estimation"""
        if self.project_metrics["code_files"] > 0:
            return min(95, (self.project_metrics["test_files"] / self.project_metrics["code_files"]) * 100)
        return 0.0
    
    def analyze_project_metrics(self) -> Dict:
        """Analyze project metrics for tier upgrade consideration"""
        metrics = {
            "file_count": 0,
            "documentation_files": 0,
            "test_files": 0,
            "code_files": 0,
            "total_size_kb": 0,
            "test_coverage_estimate": 0,
            "team_size_indicators": 0,
            "project_complexity": 0,
            "age_days": 0
        }
        
        # Count files and types
        for file_path in self.project_dir.rglob("*"):
            if file_path.is_file() and not self.is_ignored_file(file_path):
                metrics["file_count"] += 1
                
                # Calculate size
                try:
                    metrics["total_size_kb"] += file_path.stat().st_size / 1024
                except:
                    pass
                
                # Categorize files
                if file_path.suffix.lower() in ['.md', '.txt']:
                    metrics["documentation_files"] += 1
                elif any(pattern in file_path.name.lower() for pattern in ['test', 'spec']):
                    metrics["test_files"] += 1
                elif file_path.suffix.lower() in ['.py', '.js', '.ts', '.jsx', '.tsx', '.dart', '.go', '.java']:
                    metrics["code_files"] += 1
        
        # Store metrics for use in get_actual_test_coverage (temporarily)
        temp_metrics = metrics
        
        # Get actual test coverage after metrics are built
        metrics["test_coverage_estimate"] = self.get_actual_test_coverage_with_metrics(temp_metrics)
        
        # Detect team size indicators from documentation
        team_indicators = ["contributor", "team", "developer", "maintainer", "collaborator"]
        for file_path in self.project_dir.rglob("*.md"):
            if file_path.is_file():
                try:
                    with open(file_path, 'r') as f:
                        content = f.read().lower()
                        for indicator in team_indicators:
                            metrics["team_size_indicators"] += content.count(indicator)
                except:
                    continue
        
        # Calculate project complexity
        complexity_files = ['api', 'database', 'deployment', 'security', 'analytics', 'monitoring']
        for file_path in self.project_dir.rglob("*.md"):
            if file_path.is_file():
                try:
                    with open(file_path, 'r') as f:
                        content = f.read().lower()
                        for complexity_file in complexity_files:
                            if complexity_file in content:
                                metrics["project_complexity"] += 1
                except:
                    continue
        
        # Calculate project age
        try:
            oldest_file = min(
                (f.stat().st_mtime for f in self.project_dir.rglob("*") if f.is_file() and not self.is_ignored_file(f)),
                default=0
            )
            if oldest_file > 0:
                metrics["age_days"] = (datetime.now().timestamp() - oldest_file) / (24 * 3600)
        except:
            pass
        
        # Store final metrics in cache after all calculations are complete
        self._project_metrics = metrics
        return metrics
    
    def is_ignored_file(self, file_path: Path) -> bool:
        """Check if file should be ignored in metrics"""
        ignore_patterns = [
            'node_modules', '.git', '__pycache__', '.vscode', '.idea',
            'build', 'dist', '.DS_Store', '*.log', '*.tmp'
        ]
        
        path_str = str(file_path).lower()
        return any(pattern in path_str for pattern in ignore_patterns)
    
    def evaluate_upgrade_readiness(self) -> Dict:
        """Evaluate if project is ready for tier upgrade"""
        if self.current_tier == "enterprise":
            return {"ready": False, "reason": "Already at highest tier", "next_tier": None}
        
        if self.current_tier == "unknown":
            return {"ready": False, "reason": "Cannot determine current tier", "next_tier": "mvp"}
        
        # Get upgrade criteria from tier-index.yaml or defaults
        upgrade_criteria = self.get_upgrade_criteria()
        
        metrics = self.project_metrics
        next_tier = {"mvp": "core", "core": "enterprise"}[self.current_tier]
        criteria_key = f"{self.current_tier}_to_{next_tier}"
        criteria = upgrade_criteria.get(criteria_key, {})
        
        # Evaluate each criterion
        passed_criteria = []
        failed_criteria = []
        
        if metrics["file_count"] >= criteria.get("min_files", 0):
            passed_criteria.append(f"File count: {metrics['file_count']} >= {criteria.get('min_files', 0)}")
        else:
            failed_criteria.append(f"File count: {metrics['file_count']} < {criteria.get('min_files', 0)}")
        
        if metrics["documentation_files"] >= criteria.get("min_docs", 0):
            passed_criteria.append(f"Documentation: {metrics['documentation_files']} >= {criteria.get('min_docs', 0)}")
        else:
            failed_criteria.append(f"Documentation: {metrics['documentation_files']} < {criteria.get('min_docs', 0)}")
        
        if metrics["test_coverage_estimate"] >= criteria.get("min_coverage", 0):
            passed_criteria.append(f"Test coverage: {metrics['test_coverage_estimate']:.1f}% >= {criteria.get('min_coverage', 0)}%")
        else:
            failed_criteria.append(f"Test coverage: {metrics['test_coverage_estimate']:.1f}% < {criteria.get('min_coverage', 0)}%")
        
        if metrics["total_size_kb"] >= criteria.get("min_size_kb", 0):
            passed_criteria.append(f"Project size: {metrics['total_size_kb']:.0f}KB >= {criteria.get('min_size_kb', 0)}KB")
        else:
            failed_criteria.append(f"Project size: {metrics['total_size_kb']:.0f}KB < {criteria.get('min_size_kb', 0)}KB")
        
        if metrics["project_complexity"] >= criteria.get("min_complexity", 0):
            passed_criteria.append(f"Complexity: {metrics['project_complexity']} >= {criteria.get('min_complexity', 0)}")
        else:
            failed_criteria.append(f"Complexity: {metrics['project_complexity']} < {criteria.get('min_complexity', 0)}")
        
        if metrics["age_days"] >= criteria.get("min_age_days", 0):
            passed_criteria.append(f"Project age: {metrics['age_days']:.0f} days >= {criteria.get('min_age_days', 0)} days")
        else:
            failed_criteria.append(f"Project age: {metrics['age_days']:.0f} days < {criteria.get('min_age_days', 0)} days")
        
        if "min_team_indicators" in criteria:
            if metrics["team_size_indicators"] >= criteria["min_team_indicators"]:
                passed_criteria.append(f"Team indicators: {metrics['team_size_indicators']} >= {criteria['min_team_indicators']}")
            else:
                failed_criteria.append(f"Team indicators: {metrics['team_size_indicators']} < {criteria['min_team_indicators']}")
        
        # Determine readiness using configurable threshold
        total_criteria = len(criteria)
        passed_count = len(passed_criteria)
        readiness_ratio = passed_count / total_criteria if total_criteria > 0 else 0
        readiness_threshold = criteria.get("readiness_threshold", 0.7)
        
        ready = readiness_ratio >= readiness_threshold
        
        return {
            "ready": ready,
            "readiness_ratio": readiness_ratio,
            "next_tier": next_tier,
            "passed_criteria": passed_criteria,
            "failed_criteria": failed_criteria,
            "metrics": metrics
        }
    
    def create_backup(self) -> str:
        """Create backup of project files before upgrade"""
        from datetime import datetime
        import shutil
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = self.project_dir / ".tier-upgrade-backup" / timestamp
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup existing template files
        backed_up_files = []
        for file_path in self.project_dir.rglob("*.md"):
            if file_path.is_file() and not self.is_ignored_file(file_path):
                relative_path = file_path.relative_to(self.project_dir)
                backup_path = backup_dir / relative_path
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file_path, backup_path)
                backed_up_files.append(str(relative_path))
        
        # Save backup metadata
        backup_metadata = {
            "timestamp": timestamp,
            "current_tier": self.current_tier,
            "backed_up_files": backed_up_files,
            "project_metrics": self.project_metrics
        }
        
        metadata_file = backup_dir / "backup_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(backup_metadata, f, indent=2)
        
        return str(backup_dir)
    
    def restore_backup(self, backup_timestamp: str) -> Dict:
        """Restore project from backup"""
        import shutil
        
        backup_dir = self.project_dir / ".tier-upgrade-backup" / backup_timestamp
        if not backup_dir.exists():
            return {"success": False, "error": f"Backup {backup_timestamp} not found"}
        
        try:
            # Remove current template files
            for file_path in self.project_dir.rglob("*.md"):
                if file_path.is_file() and not self.is_ignored_file(file_path):
                    file_path.unlink()
            
            # Restore backed up files
            restored_files = []
            for file_path in backup_dir.rglob("*.md"):
                if file_path.is_file():
                    relative_path = file_path.relative_to(backup_dir)
                    target_path = self.project_dir / relative_path
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file_path, target_path)
                    restored_files.append(str(relative_path))
            
            return {
                "success": True,
                "restored_files": restored_files,
                "backup_timestamp": backup_timestamp
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def list_backups(self) -> List[Dict]:
        """List available backups"""
        backup_dir = self.project_dir / ".tier-upgrade-backup"
        if not backup_dir.exists():
            return []
        
        backups = []
        for backup_path in backup_dir.iterdir():
            if backup_path.is_dir():
                metadata_file = backup_path / "backup_metadata.json"
                if metadata_file.exists():
                    try:
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)
                        backups.append({
                            "timestamp": backup_path.name,
                            "current_tier": metadata.get("current_tier", "unknown"),
                            "files_count": len(metadata.get("backed_up_files", [])),
                            "backup_time": metadata.get("timestamp", "")
                        })
                    except:
                        continue
        
        return sorted(backups, key=lambda x: x["timestamp"], reverse=True)
    
    def confirm_upgrade(self, upgrade_plan: Dict, force: bool = False) -> bool:
        """Show upgrade plan and ask for confirmation"""
        if force:
            return True
        
        print(f"\n🔄 UPGRADE PLAN PREVIEW")
        print("=" * 40)
        print(f"Files to copy: {upgrade_plan['total_files_needed']}")
        print(f"Estimated time: {upgrade_plan['estimated_time']}")
        print(f"Coverage target: {upgrade_plan['coverage_target']}")
        
        if upgrade_plan["missing_files"]:
            print(f"\n📄 Files that will be copied:")
            for missing in upgrade_plan["missing_files"]:
                print(f"  • {missing['file']} - {missing['purpose']}")
        
        print(f"\n⚠️  This will modify your project files.")
        print(f"💾 A backup will be created automatically.")
        
        while True:
            response = input(f"\nProceed with upgrade? [y/N]: ").strip().lower()
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no', '']:
                return False
            else:
                print("Please enter 'y' for yes or 'n' for no.")
    
    def perform_automatic_upgrade(self, next_tier: str, force: bool = False) -> Dict:
        """Perform automatic tier upgrade by copying missing templates"""
        if not self.templates_dir:
            return {"success": False, "error": "Templates directory not found"}
        
        upgrade_plan = self.generate_upgrade_plan(next_tier)
        
        if "error" in upgrade_plan:
            return upgrade_plan
        
        # Show upgrade plan and get confirmation
        if not self.confirm_upgrade(upgrade_plan, force):
            return {"success": False, "error": "Upgrade cancelled by user"}
        
        # Create backup before upgrade
        print(f"\n💾 Creating backup...")
        backup_path = self.create_backup()
        print(f"✅ Backup created: {backup_path}")
        
        copied_files = []
        failed_files = []
        
        try:
            for missing_file in upgrade_plan["missing_files"]:
                source_path = self.templates_dir / "universal" / "docs" / missing_file["file"]
                target_path = self.project_dir / missing_file["file"]
                
                try:
                    if source_path.exists():
                        # Create target directory if it doesn't exist
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        # Copy the file
                        import shutil
                        shutil.copy2(source_path, target_path)
                        copied_files.append(missing_file["file"])
                        print(f"✅ Copied: {missing_file['file']}")
                    else:
                        failed_files.append(f"{missing_file['file']} (source not found)")
                        print(f"❌ Failed: {missing_file['file']} (source not found)")
                except Exception as e:
                    failed_files.append(f"{missing_file['file']} (error: {str(e)})")
                    print(f"❌ Failed: {missing_file['file']} (error: {str(e)})")
            
            # Update tier information in project files
            print(f"\n🔄 Updating project tier information...")
            self.update_project_tier_info(next_tier)
            
            # Run validation to ensure upgrade was successful
            print(f"\n🔍 Running post-upgrade validation...")
            validation_result = self.run_post_upgrade_validation(next_tier)
            
            if not validation_result["passed"]:
                print(f"⚠️  Validation failed: {validation_result['issues']}")
                print(f"💡 You can restore backup with: python tier_upgrade_detector.py --restore {backup_path.split('/')[-1]}")
            else:
                print(f"✅ Validation passed!")
            
            return {
                "success": len(failed_files) == 0,
                "copied_files": copied_files,
                "failed_files": failed_files,
                "validation_result": validation_result,
                "backup_path": backup_path
            }
            
        except Exception as e:
            print(f"❌ Upgrade failed: {str(e)}")
            print(f"💡 You can restore backup with: python tier_upgrade_detector.py --restore {backup_path.split('/')[-1]}")
            return {
                "success": False,
                "error": str(e),
                "backup_path": backup_path
            }
    
    def update_project_tier_info(self, new_tier: str):
        """Update tier information in project files"""
        readme_file = self.project_dir / "README.md"
        if readme_file.exists():
            try:
                with open(readme_file, 'r') as f:
                    content = f.read()
                
                # Update tier mentions
                old_tier_pattern = r'(Tier|tier):\s*(MVP|Core|Enterprise|FULL)'
                new_content = re.sub(old_tier_pattern, f'Tier: {new_tier.upper()}', content, flags=re.IGNORECASE)
                
                if new_content != content:
                    with open(readme_file, 'w') as f:
                        f.write(new_content)
            except:
                pass
    
    def run_post_upgrade_validation(self, tier: str) -> Dict:
        """Run validation scripts to verify upgrade success"""
        validation_result = {"passed": True, "issues": []}
        
        # Try to run the template validation script
        validation_script = self.templates_dir / "validate-restructure.py"
        if validation_script.exists():
            try:
                import subprocess
                result = subprocess.run(
                    ["python", str(validation_script)], 
                    cwd=self.project_dir, 
                    capture_output=True, 
                    text=True, 
                    timeout=60
                )
                
                if result.returncode != 0:
                    validation_result["passed"] = False
                    validation_result["issues"].append(f"Validation script failed: {result.stderr}")
            except Exception as e:
                validation_result["issues"].append(f"Could not run validation: {str(e)}")
        
        return validation_result
    
    def generate_upgrade_plan(self, next_tier: str) -> Dict:
        """Generate upgrade plan for next tier"""
        if not self.templates_dir:
            return {"error": "Templates directory not found"}
        
        # Get tier requirements from tier-index.yaml
        tier_requirements = self.get_tier_requirements(next_tier)
        
        # Identify missing files
        existing_files = set()
        for file_path in self.project_dir.rglob("*"):
            if file_path.is_file() and file_path.suffix in ['.md', '.yaml', '.yml']:
                existing_files.add(file_path.name)
        
        missing_files = []
        for requirement in tier_requirements.get("docs", []):
            file_name = requirement.get("file", "")
            if file_name and file_name not in existing_files:
                missing_files.append({
                    "file": file_name,
                    "purpose": requirement.get("purpose", ""),
                    "template_path": f"universal/docs/{file_name}"
                })
        
        return {
            "missing_files": missing_files,
            "total_files_needed": len(missing_files),
            "estimated_time": self.estimate_upgrade_time(next_tier, len(missing_files)),
            "coverage_target": self.get_coverage_target(next_tier)
        }
    
    def get_tier_requirements(self, tier: str) -> Dict:
        """Get tier requirements from tier-index.yaml"""
        tier_overlays = self.tier_index.get("tier_overlays", {})
        tier_config = tier_overlays.get(tier, {})
        return tier_config
    
    def estimate_upgrade_time(self, tier: str, missing_files: int) -> str:
        """Estimate time required for upgrade"""
        time_estimates = {
            "core": "2-4 hours",
            "enterprise": "1-2 days"
        }
        base_time = time_estimates.get(tier, "Unknown")
        
        if missing_files > 10:
            return f"{base_time} (plus {missing_files - 10 * 15} minutes for additional files)"
        return base_time
    
    def get_coverage_target(self, tier: str) -> str:
        """Get coverage target for tier"""
        coverage_targets = {
            "mvp": "0-20%",
            "core": "85%+",
            "enterprise": "95%+"
        }
        return coverage_targets.get(tier, "Unknown")
    
    def save_upgrade_history(self, upgrade_result: Dict):
        """Save upgrade analysis to history file"""
        history_file = self.project_dir / ".tier-upgrade-history.json"
        
        history = []
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    history = json.load(f)
            except:
                history = []
        
        history.append({
            "timestamp": datetime.now().isoformat(),
            "current_tier": self.current_tier,
            "analysis": upgrade_result
        })
        
        # Keep only last 10 analyses
        history = history[-10:]
        
        with open(history_file, 'w') as f:
            json.dump(history, f, indent=2)
    
    def cleanup_old_backups(self, keep_count: int = 10):
        """Clean up old backups, keeping only the most recent ones"""
        backups = self.list_backups()
        if len(backups) <= keep_count:
            return
        
        backups_to_remove = backups[keep_count:]
        removed_count = 0
        
        for backup in backups_to_remove:
            backup_dir = self.project_dir / ".tier-upgrade-backup" / backup["timestamp"]
            try:
                import shutil
                shutil.rmtree(backup_dir)
                removed_count += 1
            except:
                pass
        
        if removed_count > 0:
            print(f"🧹 Cleaned up {removed_count} old backups (kept last {keep_count})")
    
    def print_upgrade_analysis(self, dry_run: bool = False):
        """Print comprehensive upgrade analysis"""
        print(f"\n🔍 TIER UPGRADE ANALYSIS")
        print("=" * 50)
        print(f"Current Tier: {self.current_tier.upper()}")
        print(f"Project Directory: {self.project_dir}")
        
        # Print current metrics
        metrics = self.project_metrics
        print(f"\n📊 CURRENT PROJECT METRICS:")
        print(f"  • Total Files: {metrics['file_count']}")
        print(f"  • Documentation Files: {metrics['documentation_files']}")
        print(f"  • Test Files: {metrics['test_files']}")
        print(f"  • Code Files: {metrics['code_files']}")
        print(f"  • Project Size: {metrics['total_size_kb']:.0f} KB")
        print(f"  • Estimated Test Coverage: {metrics['test_coverage_estimate']:.1f}%")
        print(f"  • Project Age: {metrics['age_days']:.0f} days")
        print(f"  • Complexity Score: {metrics['project_complexity']}")
        
        # Evaluate upgrade readiness
        upgrade_result = self.evaluate_upgrade_readiness()
        
        if upgrade_result["ready"]:
            print(f"\n✅ READY FOR UPGRADE TO {upgrade_result['next_tier'].upper()}!")
            print(f"Readiness: {upgrade_result['readiness_ratio']:.1%}")
            
            print(f"\n✅ PASSED CRITERIA:")
            for criterion in upgrade_result["passed_criteria"]:
                print(f"  ✓ {criterion}")
            
            if upgrade_result["failed_criteria"]:
                print(f"\n⚠️  MINOR ISSUES (but acceptable):")
                for criterion in upgrade_result["failed_criteria"]:
                    print(f"  ⚠ {criterion}")
            
            # Generate upgrade plan
            upgrade_plan = self.generate_upgrade_plan(upgrade_result["next_tier"])
            if "missing_files" in upgrade_plan:
                print(f"\n📋 UPGRADE PLAN:")
                print(f"  • Files to add: {upgrade_plan['total_files_needed']}")
                print(f"  • Estimated time: {upgrade_plan['estimated_time']}")
                print(f"  • Coverage target: {upgrade_plan['coverage_target']}")
                
                if upgrade_plan["missing_files"]:
                    print(f"\n📄 MISSING FILES:")
                    for missing in upgrade_plan["missing_files"][:5]:  # Show first 5
                        print(f"  • {missing['file']} - {missing['purpose']}")
                    if len(upgrade_plan["missing_files"]) > 5:
                        print(f"  • ... and {len(upgrade_plan['missing_files']) - 5} more files")
        else:
            print(f"\n❌ NOT READY FOR UPGRADE")
            print(f"Reason: {upgrade_result['reason']}")
            
            if upgrade_result["failed_criteria"]:
                print(f"\n❌ FAILED CRITERIA:")
                for criterion in upgrade_result["failed_criteria"]:
                    print(f"  ✗ {criterion}")
            
            if upgrade_result["passed_criteria"]:
                print(f"\n✅ MET CRITERIA:")
                for criterion in upgrade_result["passed_criteria"]:
                    print(f"  ✓ {criterion}")
        
        # Save analysis to history
        self.save_upgrade_history(upgrade_result)

def main():
    parser = argparse.ArgumentParser(description="Analyze project for tier upgrade readiness and perform upgrades")
    parser.add_argument("--project-dir", default=".", help="Project directory to analyze")
    parser.add_argument("--dry-run", action="store_true", help="Only analyze, don't suggest actions")
    parser.add_argument("--check-only", action="store_true", help="Run analysis without prompts or modifications")
    parser.add_argument("--auto-upgrade", action="store_true", help="Automatically perform upgrade if ready")
    parser.add_argument("--force", action="store_true", help="Bypass confirmation prompts (for CI/CD)")
    parser.add_argument("--restore", help="Restore project from backup timestamp")
    parser.add_argument("--list-backups", action="store_true", help="List available backups")
    parser.add_argument("--cleanup-backups", action="store_true", help="Clean up old backups")
    parser.add_argument("--version", action="store_true", help="Show version information")
    
    args = parser.parse_args()
    
    # Handle version flag
    if args.version:
        print(f"Tier Upgrade Detection System v{UPGRADE_DETECTOR_VERSION}")
        print(f"Last Updated: 2025-12-10")
        return
    
    detector = TierUpgradeDetector(args.project_dir)
    
    # Handle restore command
    if args.restore:
        print(f"🔄 Restoring from backup: {args.restore}")
        result = detector.restore_backup(args.restore)
        if result["success"]:
            print(f"✅ Restore completed successfully!")
            print(f"Restored {len(result['restored_files'])} files:")
            for file in result["restored_files"]:
                print(f"  • {file}")
        else:
            print(f"❌ Restore failed: {result['error']}")
        return
    
    # Handle list backups command
    if args.list_backups:
        backups = detector.list_backups()
        if backups:
            print(f"\n📦 Available Backups:")
            print("=" * 40)
            for backup in backups:
                print(f"📅 {backup['timestamp']}")
                print(f"   Tier: {backup['current_tier']}")
                print(f"   Files: {backup['files_count']}")
                print(f"   Time: {backup['backup_time']}")
                print()
        else:
            print(f"ℹ️  No backups found.")
        return
    
    # Handle cleanup backups command
    if args.cleanup_backups:
        detector.cleanup_old_backups()
        return
    
    # Run upgrade analysis
    if args.check_only:
        # Silent analysis for CI/CD
        upgrade_result = detector.evaluate_upgrade_readiness()
        print(f"Current tier: {detector.current_tier}")
        print(f"Ready for upgrade: {upgrade_result['ready']}")
        if upgrade_result['ready']:
            print(f"Next tier: {upgrade_result['next_tier']}")
            print(f"Readiness: {upgrade_result['readiness_ratio']:.1%}")
        return
    
    # Full analysis with detailed output
    detector.print_upgrade_analysis(args.dry_run)
    
    if args.auto_upgrade:
        upgrade_result = detector.evaluate_upgrade_readiness()
        if upgrade_result["ready"]:
            print(f"\n🚀 AUTO-UPGRADE TRIGGERED: {detector.current_tier} → {upgrade_result['next_tier']}")
            result = detector.perform_automatic_upgrade(upgrade_result["next_tier"], args.force)
            
            if result["success"]:
                print(f"\n✅ UPGRADE COMPLETED SUCCESSFULLY!")
                print(f"Copied {len(result['copied_files'])} files:")
                for file in result["copied_files"]:
                    print(f"  • {file}")
                
                if result["validation_result"]["passed"]:
                    print(f"✅ Post-upgrade validation passed!")
                else:
                    print(f"⚠️  Post-upgrade validation had issues:")
                    for issue in result["validation_result"]["issues"]:
                        print(f"  • {issue}")
                
                print(f"💾 Backup saved at: {result['backup_path']}")
            else:
                print(f"\n❌ UPGRADE FAILED!")
                print(f"Error: {result.get('error', 'Unknown error')}")
                if "backup_path" in result:
                    print(f"💾 Backup available at: {result['backup_path']}")
        else:
            print(f"\n⏸️  AUTO-UPGRADE SKIPPED: Project not ready for upgrade")
    
    # Cleanup old backups after successful operations
    if not args.dry_run:
        detector.cleanup_old_backups()

if __name__ == "__main__":
    main()
