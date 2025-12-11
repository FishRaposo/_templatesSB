#!/usr/bin/env python3
"""
Unit tests for analyze_and_build
"""

import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

try:
    import analyze_and_build
except ImportError as e:
    print(f"Warning: Could not import analyze_and_build: {e}")
    analyze_and_build = None

class TestAnalyzeAndBuild(unittest.TestCase):
    """Test suite for analyze_and_build"""

    def setUp(self):
        """Setup for each test"""
        if analyze_and_build is None:
            self.skipTest("analyze_and_build module not available")

    def test_integration_smoke(self):
        """Smoke test for basic functionality"""

        # Prepare mock data for yaml.safe_load (task index)
        task_index_data = {
            'tasks': {
                'task-1': {
                    'files': ['file1.py'],
                    'description': 'Task 1 description',
                    'categories': ['cat1']
                }
            }
        }

        # Mock dependencies
        with patch('analyze_and_build.TaskDetectionSystem') as MockDetector, \
             patch('analyze_and_build.yaml') as mock_yaml, \
             patch('builtins.open', mock_open()) as mock_file, \
             patch('analyze_and_build.subprocess.run') as mock_subprocess, \
             patch('pathlib.Path.mkdir') as mock_mkdir:

            # Setup Mock Detector
            mock_detector_instance = MockDetector.return_value

            # Mock TaskMatch objects
            task1 = Mock()
            task1.task_id = "task-1"
            task1.task_name = "Task 1"
            task1.description = "Description 1"
            task1.categories = ["cat1"]
            task1.confidence = 0.9
            task1.matched_keywords = ["key1"]
            task1.tier = "core"

            # Mock MissingTask objects
            gap1 = Mock()
            gap1.suggested_name = "gap-1"
            gap1.description = "Gap Description"
            gap1.categories = ["cat2"]
            gap1.suggested_stacks = ["python"]
            gap1.suggested_tier = "core"
            gap1.requirements = ["req1"]
            gap1.gap_reason = "reason"
            gap1.priority = "high"

            # Mock StackRecommendation
            stack_rec = Mock()
            stack_rec.primary_stack = "python"
            stack_rec.secondary_stack = "node"
            stack_rec.confidence = 0.8
            stack_rec.reasoning = ["reason"]
            stack_rec.use_case = "web"

            # Configure analyze_requirements return value
            mock_detector_instance.analyze_requirements.return_value = (
                [task1], [gap1], stack_rec
            )

            # Configure yaml.safe_load to return task_index_data
            mock_yaml.safe_load.return_value = task_index_data

            # Initialize pipeline
            pipeline = analyze_and_build.ProjectAnalysisPipeline()

            # Run pipeline
            description = "Test project description"
            output_dir = Path("test_output")

            # Mock subprocess success
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = "Build successful"

            report = pipeline.run_full_pipeline(
                description=description,
                output_dir=output_dir,
                build=True,
                dry_run=False
            )

            # Assertions
            self.assertIn("analysis", report)
            self.assertIn("build_config", report)
            self.assertTrue(report["build_success"])
            self.assertIn("gap_documentation", report)

            # Verify calls
            mock_detector_instance.analyze_requirements.assert_called_once()
            mock_subprocess.assert_called_once()

            # Verify build config contains expected task
            build_config = report["build_config"]
            self.assertIn("task-1", build_config["tasks"])
            self.assertTrue(build_config["tasks"]["task-1"]["enabled"])

if __name__ == '__main__':
    unittest.main()
