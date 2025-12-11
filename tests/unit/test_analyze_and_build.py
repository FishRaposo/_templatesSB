#!/usr/bin/env python3
"""
Unit tests for analyze_and_build
"""

import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

try:
    import analyze_and_build
    from detect_project_tasks import TaskMatch, MissingTask, StackRecommendation
except ImportError as e:
    print(f"Warning: Could not import dependencies: {e}")
    analyze_and_build = None

class TestAnalyzeAndBuild(unittest.TestCase):
    """Test suite for analyze_and_build"""

    def setUp(self):
        """Setup for each test"""
        if analyze_and_build is None:
            self.skipTest("Module not available")

        # Mock TaskDetectionSystem
        self.mock_detector_patcher = patch('analyze_and_build.TaskDetectionSystem')
        self.MockTaskDetectionSystem = self.mock_detector_patcher.start()

        # Mock loading of task-index.yaml
        self.mock_file_open = patch('builtins.open', new_callable=MagicMock)
        self.mock_open = self.mock_file_open.start()

        self.mock_yaml_load = patch('analyze_and_build.yaml.safe_load')
        self.mock_yaml = self.mock_yaml_load.start()
        self.mock_yaml.return_value = {
            'tasks': {
                'task-1': {'files': ['f1']},
                'task-2': {'files': []}
            }
        }

    def tearDown(self):
        """Cleanup after each test"""
        self.mock_detector_patcher.stop()
        self.mock_file_open.stop()
        self.mock_yaml_load.stop()

    def test_main(self):
        """Test main function"""
        # TODO: Implement based on docstring: Main entry point...
        with self.assertRaises(NotImplementedError):
            self.fail('Test not implemented yet')

    def test_analyze_project(self):
        """Test analyze_project function"""
        # Arrange
        description = "Test project description"
        suggest_stacks = True

        # Create mock objects using the imported dataclasses
        mock_task = TaskMatch(
            task_id='task-1',
            task_name='Task 1',
            description='Description 1',
            categories=['cat1'],
            confidence=0.9,
            matched_keywords=['kw1'],
            tier='core'
        )

        mock_gap = MissingTask(
            suggested_name='gap-1',
            description='Gap Description',
            categories=['cat2'],
            suggested_stacks=['python'],
            suggested_tier='core',
            requirements=['req1'],
            gap_reason='reason',
            priority='high'
        )

        mock_stack_rec = StackRecommendation(
            primary_stack='python',
            secondary_stack='node',
            confidence=0.8,
            reasoning=['reason1'],
            use_case='web'
        )

        # Setup the mock detector to return our mock data
        mock_detector_instance = self.MockTaskDetectionSystem.return_value
        mock_detector_instance.analyze_requirements.return_value = (
            [mock_task],
            [mock_gap],
            mock_stack_rec
        )

        # Instantiate the pipeline
        pipeline = analyze_and_build.ProjectAnalysisPipeline()

        # Act
        analysis = pipeline.analyze_project(description, suggest_stacks)

        # Assert
        self.assertEqual(analysis['description'], description)
        self.assertEqual(analysis['stack_recommendation'], mock_stack_rec)

        # Verify tasks
        self.assertEqual(len(analysis['detected_tasks']), 1)
        detected_task = analysis['detected_tasks'][0]
        self.assertEqual(detected_task.task_id, 'task-1')
        self.assertTrue(detected_task.has_templates)
        self.assertEqual(detected_task.template_count, 1)

        # Verify gaps
        self.assertEqual(len(analysis['detected_gaps']), 1)
        self.assertEqual(analysis['detected_gaps'][0].suggested_name, 'gap-1')

        # Verify validation summary
        summary = analysis['validation_summary']
        self.assertEqual(summary['total_requirements_detected'], 2)
        self.assertEqual(summary['tasks_with_templates'], 1)
        self.assertEqual(summary['identified_gaps'], 1)

        # Verify call arguments
        mock_detector_instance.analyze_requirements.assert_called_once_with(description, suggest_stacks)

    def test_generate_build_config(self):
        """Test generate_build_config function"""
        with self.assertRaises(NotImplementedError):
            self.fail('Test not implemented yet')

    def test_build_project(self):
        """Test build_project function"""
        with self.assertRaises(NotImplementedError):
            self.fail('Test not implemented yet')

    def test_generate_gap_documentation(self):
        """Test generate_gap_documentation function"""
        with self.assertRaises(NotImplementedError):
            self.fail('Test not implemented yet')

    def test_run_full_pipeline(self):
        """Test run_full_pipeline function"""
        with self.assertRaises(NotImplementedError):
            self.fail('Test not implemented yet')

if __name__ == '__main__':
    unittest.main()
