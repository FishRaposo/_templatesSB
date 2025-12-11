#!/usr/bin/env python3
"""
Unit tests for analyze_and_build
"""

import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open

# Add scripts directory to path
repo_root = Path(__file__).resolve().parent.parent.parent
scripts_dir = repo_root / "scripts"
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

try:
    import analyze_and_build
except ImportError as e:
    print(f"Warning: Could not import analyze_and_build: {e}")
    analyze_and_build = None

class TestAnalyzeAndBuild(unittest.TestCase):
    """Test suite for top-level analyze_and_build functions"""

    def setUp(self):
        if analyze_and_build is None:
            self.skipTest("analyze_and_build module not found")

    def test_main(self):
        """Test main function"""
        # TODO: Implement based on docstring: Main entry point...
        # Current logic is main() calls sys.exit, so we need to mock sys.exit and argv
        # Skipping for now as user requested test_generate_build_config
        pass

class TestProjectAnalysisPipeline(unittest.TestCase):
    """Test ProjectAnalysisPipeline class"""

    def setUp(self):
        """Setup for each test"""
        if analyze_and_build is None:
            self.skipTest("analyze_and_build module not found")

        # Mock dependencies
        self.mock_detector_patcher = patch('analyze_and_build.TaskDetectionSystem')
        self.MockTaskDetectionSystem = self.mock_detector_patcher.start()

        # Mock Path to prevent filesystem access in __init__
        self.mock_path_patcher = patch('analyze_and_build.Path')
        self.MockPath = self.mock_path_patcher.start()

        # Setup mock path behavior
        self.mock_path_instance = MagicMock()
        self.MockPath.return_value = self.mock_path_instance
        self.mock_path_instance.parent.parent = self.mock_path_instance
        self.mock_path_instance.__truediv__.return_value = self.mock_path_instance

        # Mock yaml
        self.mock_yaml_patcher = patch('analyze_and_build.yaml')
        self.mock_yaml = self.mock_yaml_patcher.start()
        self.mock_yaml.safe_load.return_value = {'tasks': {}}

        # Mock open
        self.mock_open = mock_open(read_data="tasks: {}")
        self.open_patcher = patch('builtins.open', self.mock_open)
        self.open_patcher.start()

        # Initialize pipeline with mocked __file__
        with patch('analyze_and_build.__file__', str(scripts_dir / 'analyze_and_build.py')):
            self.pipeline = analyze_and_build.ProjectAnalysisPipeline()

    def tearDown(self):
        if analyze_and_build:
            self.mock_detector_patcher.stop()
            self.mock_path_patcher.stop()
            self.mock_yaml_patcher.stop()
            self.open_patcher.stop()

    def test_analyze_project(self):
        """Test analyze_project method"""
        # Placeholder
        pass

    def test_generate_build_config(self):
        """Test generate_build_config method"""

        # Arrange
        # Mock stack recommendation object
        mock_stack_rec = MagicMock()
        mock_stack_rec.primary_stack = "python"
        mock_stack_rec.secondary_stack = "react"

        # Mock TaskMatch objects using MagicMock
        # We need to simulate object attributes, MagicMock does this well
        task1 = MagicMock()
        task1.task_id = "task_auth"
        task1.has_templates = True
        task1.confidence = 0.9
        task1.tier = "core"
        task1.categories = ["auth"]

        task2 = MagicMock()
        task2.task_id = "task_missing"
        task2.has_templates = False

        task3 = MagicMock()
        task3.task_id = "task_ui"
        task3.has_templates = True
        task3.confidence = 0.4
        task3.tier = None
        task3.categories = ["frontend"]

        analysis = {
            "description": "Test Project Description",
            "timestamp": "2024-01-01T12:00:00",
            "stack_recommendation": mock_stack_rec,
            "detected_tasks": [task1, task2, task3],
            "detected_gaps": [],
            "validation_summary": {
                "coverage_percentage": 75.0,
                "total_requirements_detected": 3,
                "tasks_with_templates": 2
            }
        }

        output_path = "dummy_output.yaml"

        # Act
        config = self.pipeline.generate_build_config(analysis, output_path)

        # Assert
        # Verify project info
        self.assertEqual(config["project"]["name"], "detected-project")
        self.assertEqual(config["project"]["stack"], "python")
        self.assertEqual(config["project"]["secondary_stack"], "react")
        self.assertEqual(config["project"]["description"], "Test Project Description")

        # Verify tasks
        self.assertIn("task_auth", config["tasks"])
        self.assertIn("task_ui", config["tasks"])
        self.assertNotIn("task_missing", config["tasks"])

        self.assertEqual(config["tasks"]["task_auth"]["tier"], "core")
        self.assertEqual(config["tasks"]["task_ui"]["tier"], "mvp") # Fallback to project tier

        # Verify project tier calculation
        # Only 1 high confidence task (task1), so tier should be 'mvp'
        self.assertEqual(config["project"]["tier"], "mvp")

        # Verify metadata
        self.assertEqual(config["metadata"]["detection_confidence"], "high")
        self.assertEqual(config["metadata"]["total_tasks"], 2)

        # Verify file write
        self.mock_yaml.dump.assert_called()
        self.mock_open.assert_called_with(output_path, 'w', encoding='utf-8')

    def test_build_project(self):
        """Test build_project method"""
        pass

    def test_generate_gap_documentation(self):
        """Test generate_gap_documentation method"""
        pass

    def test_run_full_pipeline(self):
        """Test run_full_pipeline method"""
        pass

if __name__ == '__main__':
    unittest.main()
