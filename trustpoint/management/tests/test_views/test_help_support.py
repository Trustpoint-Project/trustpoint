"""Test suite for help_support views."""
from django.test import RequestFactory, TestCase
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
