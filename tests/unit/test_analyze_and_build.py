#!/usr/bin/env python3
"""
Unit tests for analyze_and_build
"""

import unittest
import sys
import tempfile
import yaml
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

# Import the module under test
try:
    import analyze_and_build
except ImportError:
    analyze_and_build = None

class TestAnalyzeAndBuild(unittest.TestCase):
    """Test suite for ProjectAnalysisPipeline"""

    def setUp(self):
        """Setup for each test"""
        if analyze_and_build is None:
            self.skipTest("analyze_and_build module not imported")

        # Create a temporary directory for the test environment
        self.test_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.test_dir.cleanup)
        self.test_path = Path(self.test_dir.name)

        # Create mock directory structure
        self.tasks_dir = self.test_path / "tasks"
        self.tasks_dir.mkdir()

        self.scripts_dir = self.test_path / "scripts"
        self.scripts_dir.mkdir()

        self.docs_dir = self.test_path / "docs" / "task-gaps"
        self.docs_dir.mkdir(parents=True)

        self.reports_dir = self.test_path / "reports"
        self.reports_dir.mkdir()

        # Create a dummy task-index.yaml
        self.task_index_data = {
            'tasks': {
                'task-1': {
                    'files': ['file1.py'],
                    'tier': 'mvp',
                    'description': 'Test Task 1',
                    'categories': ['test']
                }
            }
        }
        self.task_index_path = self.tasks_dir / "task-index.yaml"
        with open(self.task_index_path, "w") as f:
            yaml.dump(self.task_index_data, f)

        # Patch TaskDetectionSystem
        self.mock_detector_patcher = patch('analyze_and_build.TaskDetectionSystem')
        self.mock_detector_cls = self.mock_detector_patcher.start()
        self.mock_detector = self.mock_detector_cls.return_value

        # Configure mock detector default return
        self.mock_detector.analyze_requirements.return_value = ([], [], None)

        # Patch __file__ in analyze_and_build to point to our temp scripts dir
        # This ensures the pipeline initializes with our temp directories
        self.original_file = analyze_and_build.__file__
        analyze_and_build.__file__ = str(self.scripts_dir / "analyze_and_build.py")

        # Initialize the pipeline
        self.pipeline = analyze_and_build.ProjectAnalysisPipeline()

    def tearDown(self):
        """Cleanup after each test"""
        if analyze_and_build:
            analyze_and_build.__file__ = self.original_file

        if hasattr(self, 'mock_detector_patcher'):
            self.mock_detector_patcher.stop()

    def test_init(self):
        """Test initialization of ProjectAnalysisPipeline"""
        self.assertTrue(self.pipeline.gaps_dir.exists())
        self.assertTrue(self.pipeline.reports_dir.exists())
        self.assertEqual(self.pipeline.task_index, self.task_index_data)

    def test_analyze_project(self):
        """Test analyze_project method"""
        # Arrange
        description = "Test project"
        # Mock the detector return values
        mock_task = Mock()
        mock_task.task_id = 'task-1'
        mock_task.confidence = 0.8
        mock_task.has_templates = False # Default
        mock_task.categories = ['test']
        mock_task.tier = 'mvp'

        mock_gap = Mock()

        mock_stack = Mock()
        mock_stack.primary_stack = 'python'
        mock_stack.secondary_stack = None
        mock_stack.confidence = 0.9

        self.mock_detector.analyze_requirements.return_value = ([mock_task], [mock_gap], mock_stack)

        # Act
        analysis = self.pipeline.analyze_project(description)

        # Assert
        self.assertEqual(analysis['description'], description)
        self.assertIn('detected_tasks', analysis)
        self.assertEqual(len(analysis['detected_tasks']), 1)
        # Note: analyze_project validates tasks against task_index
        # Since 'task-1' is in our dummy task_index, it should be validated and updated
        task = analysis['detected_tasks'][0]
        self.assertEqual(task.task_id, 'task-1')
        self.assertTrue(task.has_templates)
        self.assertEqual(task.template_count, 1)

    def test_generate_build_config(self):
        """Test generate_build_config method"""
        # Arrange
        mock_task = Mock()
        mock_task.task_id = 'task-1'
        mock_task.confidence = 0.8
        mock_task.has_templates = True
        mock_task.categories = ['test']
        mock_task.tier = 'mvp'

        analysis = {
            "timestamp": "2023-01-01",
            "description": "Test Project",
            "stack_recommendation": Mock(primary_stack="python", secondary_stack=None),
            "detected_tasks": [mock_task],
            "detected_gaps": [],
            "validation_summary": {"coverage_percentage": 100}
        }

        output_path = self.test_path / "build-config.yaml"

        # Act
        config = self.pipeline.generate_build_config(analysis, output_path)

        # Assert
        self.assertTrue(output_path.exists())
        self.assertEqual(config['project']['stack'], 'python')
        self.assertIn('task-1', config['tasks'])

    def test_build_project(self):
        """Test build_project method"""
        # Arrange
        build_config = {
            "project": {"stack": "python", "tier": "mvp"},
            "tasks": {}
        }
        output_dir = self.test_path / "output"
        output_dir.mkdir()

        # Patch subprocess.run
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "Success"

            # Create dummy resolver script
            resolver_script = self.scripts_dir / "resolve_project.py"
            with open(resolver_script, "w") as f:
                f.write("pass")

            # Act
            result = self.pipeline.build_project(build_config, output_dir)

            # Assert
            self.assertTrue(result)
            mock_run.assert_called_once()

            # Check arguments passed to subprocess
            args, _ = mock_run.call_args
            cmd_list = args[0]
            self.assertIn(str(resolver_script), cmd_list)
            self.assertIn(str(output_dir), cmd_list)

    def test_generate_gap_documentation(self):
        """Test generate_gap_documentation method"""
        # Arrange
        mock_gap = Mock()
        mock_gap.priority = 'high'
        mock_gap.suggested_name = 'gap-1'
        mock_gap.categories = ['cat1']
        mock_gap.suggested_stacks = ['python']
        mock_gap.description = 'Gap description'
        mock_gap.gap_reason = 'Reason'
        mock_gap.requirements = ['req1']

        analysis = {
            "timestamp": "2023-01-01",
            "description": "Test Project",
            "detected_gaps": [mock_gap]
        }
        output_path = self.test_path / "gap-analysis.md"

        # Act
        content = self.pipeline.generate_gap_documentation(analysis, output_path)

        # Assert
        self.assertTrue(output_path.exists())
        self.assertIn('gap-1', content)
        self.assertIn('Gap description', content)

    def test_run_full_pipeline(self):
        """Test run_full_pipeline method"""
        # Arrange
        description = "Test Description"
        output_dir = self.test_path / "full_output"
        output_dir.mkdir()

        # Mock methods to isolate pipeline logic
        self.pipeline.analyze_project = Mock(return_value={
            "timestamp": "now",
            "description": description,
            "validation_summary": {"coverage_percentage": 100, "total_requirements_detected": 1, "tasks_with_templates": 1},
            "build_readiness": {"readiness_level": "high", "recommendation": "Good"},
            "stack_recommendation": Mock(primary_stack="python", secondary_stack=None, confidence=1.0),
            "detected_tasks": [],
            "detected_gaps": []
        })
        self.pipeline.generate_build_config = Mock(return_value={
            "project": {"stack": "python"},
            "tasks": {}
        })
        self.pipeline.build_project = Mock(return_value=True)
        self.pipeline.generate_gap_documentation = Mock(return_value="Gap Doc")
        # We don't need to mock _serialize_analysis_for_export if we provide enough data,
        # but mocking makes it simpler to avoid key errors if we missed something.
        self.pipeline._serialize_analysis_for_export = Mock(return_value={})

        # Act
        report = self.pipeline.run_full_pipeline(description, output_dir, build=True, dry_run=False)

        # Assert
        self.pipeline.analyze_project.assert_called_once_with(description)
        self.pipeline.generate_build_config.assert_called_once()
        self.pipeline.build_project.assert_called_once()
        self.assertTrue((output_dir / "analysis-report.json").exists())

if __name__ == '__main__':
    unittest.main()
