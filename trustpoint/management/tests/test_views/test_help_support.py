"""Test suite for help_support views."""
import os
import tempfile
import time
from pathlib import Path

from django.test import RequestFactory, TestCase, override_settings
from management.views.help_support import HelpView


class HelpViewTest(TestCase):
    """Test suite for HelpView."""

    def setUp(self):
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = HelpView()

    def test_template_name(self):
        """Test that the correct template is used."""
        self.assertEqual(self.view.template_name, 'management/help.html')

    def test_get_context_data_adds_page_category(self):
        """Test get_context_data adds page_category to context."""
        context = self.view.get_context_data()
        self.assertIn('page_category', context)
        self.assertEqual(context['page_category'], 'settings')

    def test_get_context_data_adds_page_name(self):
        """Test get_context_data adds page_name to context."""
        context = self.view.get_context_data()
        self.assertIn('page_name', context)
        self.assertEqual(context['page_name'], 'help')

    def test_get_context_data_preserves_parent_context(self):
        """Test get_context_data preserves context from parent class."""
        context = self.view.get_context_data(custom_key='custom_value')
        self.assertIn('custom_key', context)
        self.assertEqual(context['custom_key'], 'custom_value')

    def test_get_context_data_with_kwargs(self):
        """Test get_context_data works with various kwargs."""
        kwargs = {
            'key1': 'value1',
            'key2': 123,
            'key3': ['list', 'values'],
        }
        context = self.view.get_context_data(**kwargs)

        for key, value in kwargs.items():
            self.assertIn(key, context)
            self.assertEqual(context[key], value)

        # Ensure our additions are still there
        self.assertEqual(context['page_category'], 'settings')
        self.assertEqual(context['page_name'], 'help')

    def test_get_context_data_returns_dict(self):
        """Test get_context_data returns a dictionary."""
        context = self.view.get_context_data()
        self.assertIsInstance(context, dict)

    def test_help_view_inherits_from_template_view(self):
        """Test HelpView is a TemplateView."""
        from django.views.generic import TemplateView
        self.assertTrue(issubclass(HelpView, TemplateView))

    def test_get_context_data_with_active_build(self):
        """Test context when a documentation build is actively running."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            base_dir = temp_path / 'project' / 'trustpoint'

            # Setup fake directory structure
            docs_dir = base_dir.parent / 'docs'
            docs_dir.mkdir(parents=True)

            # Create a fresh lock file
            lock_file = docs_dir / '.building'
            lock_file.touch()

            with override_settings(BASE_DIR=base_dir):
                context = self.view.get_context_data()

                self.assertTrue(context['build_in_progress'])
                self.assertTrue(lock_file.exists())  # Ensure it wasn't accidentally deleted

    def test_get_context_data_with_stale_build_lock(self):
        """Test context when a crashed build leaves a stale lock file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            base_dir = temp_path / 'project' / 'trustpoint'

            # Setup fake directory structure
            docs_dir = base_dir.parent / 'docs'
            docs_dir.mkdir(parents=True)

            # Create a lock file
            lock_file = docs_dir / '.building'
            lock_file.touch()

            # Modify the file's modified time to be older than the 300s timeout
            stale_time = time.time() - 400
            os.utime(lock_file, (stale_time, stale_time))

            with override_settings(BASE_DIR=base_dir):
                context = self.view.get_context_data()

                self.assertFalse(context['build_in_progress'])
                self.assertFalse(lock_file.exists())  # Ensure the view cleaned it up

    def test_get_context_data_with_local_docs_available(self):
        """Test context when local documentation has been successfully built."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            base_dir = temp_path / 'project' / 'trustpoint'

            # Setup fake directory structure for finished docs
            docs_index = base_dir.parent / 'docs' / 'build' / 'html' / 'index.html'
            docs_index.parent.mkdir(parents=True)
            docs_index.touch()

            with override_settings(BASE_DIR=base_dir):
                context = self.view.get_context_data()
                self.assertTrue(context['local_docs_available'])