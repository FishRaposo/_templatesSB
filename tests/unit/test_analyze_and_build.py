#!/usr/bin/env python3
"""
Unit tests for analyze_and_build.py
"""

import unittest
import sys
import json
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open, ANY

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

# Import module under test
try:
    import analyze_and_build
    from analyze_and_build import ProjectAnalysisPipeline
except ImportError:
    analyze_and_build = None
    ProjectAnalysisPipeline = None

class TestProjectAnalysisPipeline(unittest.TestCase):
    """Test suite for ProjectAnalysisPipeline class"""

    def setUp(self):
        """Setup for each test"""
        if analyze_and_build is None:
            self.skipTest("analyze_and_build module not available")

        # Patch TaskDetectionSystem
        self.task_detection_patcher = patch('analyze_and_build.TaskDetectionSystem')
        self.MockTaskDetectionSystem = self.task_detection_patcher.start()

        # Patch builtins.open for __init__ loading task-index.yaml and file writes
        self.mock_file = mock_open(read_data="tasks: {}")
        self.open_patcher = patch('builtins.open', self.mock_file)
        self.mock_open = self.open_patcher.start()

        # Patch yaml because __init__ uses yaml.safe_load
        self.yaml_load_patcher = patch('analyze_and_build.yaml.safe_load', return_value={'tasks': {}})
        self.mock_yaml_load = self.yaml_load_patcher.start()

        self.yaml_dump_patcher = patch('analyze_and_build.yaml.dump')
        self.mock_yaml_dump = self.yaml_dump_patcher.start()

        # Patch json for report writing
        self.json_dump_patcher = patch('analyze_and_build.json.dump')
        self.mock_json_dump = self.json_dump_patcher.start()

        # Initialize the pipeline
        self.pipeline = ProjectAnalysisPipeline()

        # Common mocks for internal methods
        self.mock_analysis = {
            "timestamp": "2025-01-01T00:00:00",
            "description": "test project",
            "stack_recommendation": MagicMock(primary_stack="python", secondary_stack=None, confidence=0.9),
            "detected_tasks": [],
            "detected_gaps": [],
            "validation_summary": {
                "total_requirements_detected": 5,
                "coverage_percentage": 80.0,
                "tasks_with_templates": 4
            },
            "build_readiness": {
                "readiness_level": "high",
                "recommendation": "Ready"
            }
        }
        self.mock_build_config = {"project": {"name": "test"}, "tasks": {}}
        self.mock_gap_doc = "# Gap Analysis"
        self.mock_serialized_analysis = {"timestamp": "..."}

    def tearDown(self):
        """Cleanup after each test"""
        self.task_detection_patcher.stop()
        self.open_patcher.stop()
        self.yaml_load_patcher.stop()
        self.yaml_dump_patcher.stop()
        self.json_dump_patcher.stop()

    def _setup_pipeline_mocks(self):
        """Helper to setup mocks on the pipeline instance"""
        self.pipeline.analyze_project = MagicMock(return_value=self.mock_analysis)
        self.pipeline.generate_build_config = MagicMock(return_value=self.mock_build_config)
        self.pipeline.build_project = MagicMock(return_value=True)
        self.pipeline.generate_gap_documentation = MagicMock(return_value=self.mock_gap_doc)
        self.pipeline._serialize_analysis_for_export = MagicMock(return_value=self.mock_serialized_analysis)
        self.pipeline._print_pipeline_summary = MagicMock()

    def test_run_full_pipeline_success(self):
        """Test run_full_pipeline method (happy path)"""
        self._setup_pipeline_mocks()

        description = "Create a test project"
        output_dir = Path("/tmp/test_output")

        result = self.pipeline.run_full_pipeline(
            description=description,
            output_dir=output_dir,
            build=True,
            dry_run=False
        )

        # Verify method calls
        self.pipeline.analyze_project.assert_called_once_with(description)
        self.pipeline.generate_build_config.assert_called_once_with(self.mock_analysis)
        self.pipeline.build_project.assert_called_once_with(self.mock_build_config, output_dir, False)
        self.pipeline.generate_gap_documentation.assert_called_once_with(self.mock_analysis)

        # Verify file writes
        self.mock_json_dump.assert_called()
        self.mock_yaml_dump.assert_called()
        self.mock_open().write.assert_any_call(self.mock_gap_doc)

        # Verify result
        self.assertEqual(result['build_success'], True)

    def test_run_full_pipeline_no_build(self):
        """Test run_full_pipeline with build=False"""
        self._setup_pipeline_mocks()

        output_dir = Path("/tmp/test_output")

        result = self.pipeline.run_full_pipeline(
            description="test",
            output_dir=output_dir,
            build=False
        )

        # Verify build_project NOT called
        self.pipeline.build_project.assert_not_called()

        # Verify result still successful
        self.assertEqual(result['build_success'], True)

    def test_run_full_pipeline_build_failure(self):
        """Test run_full_pipeline when build fails"""
        self._setup_pipeline_mocks()
        self.pipeline.build_project.return_value = False

        output_dir = Path("/tmp/test_output")

        result = self.pipeline.run_full_pipeline(
            description="test",
            output_dir=output_dir,
            build=True
        )

        # Verify build_project called
        self.pipeline.build_project.assert_called_once()

        # Verify result indicates failure
        self.assertEqual(result['build_success'], False)

    def test_integration_smoke(self):
        """Smoke test for basic functionality"""
        self.assertIsNotNone(self.pipeline)

if __name__ == '__main__':
    unittest.main()
