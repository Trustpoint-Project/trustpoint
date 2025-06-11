"""Tests for the ContextDataMixin class."""

from typing import Any

from django.test import RequestFactory, TestCase
from django.views.generic import TemplateView

from trustpoint.views.base import ContextDataMixin


class MockView(ContextDataMixin, TemplateView):
    """Mock view for testing ContextDataMixin."""
    template_name = 'example_template.html'

    context_page_category = 'test_category'
    context_page_name = 'test_name'
    context_custom_field = 'custom_value'


class ContextDataMixinTestMixin:
    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Override get_context_data to simulate ContextDataMixin behavior."""
        prefix = 'context_'
        for attr in dir(self):
            if attr.startswith(prefix) and len(attr) > len(prefix):
                kwargs.setdefault(attr[len(prefix) :], getattr(self, attr))
        context = super().get_context_data(**kwargs)
        return context


class ContextDataMixinTests(TestCase):
    """Test cases for ContextDataMixin."""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.request = self.factory.get('/')  # Mock GET request
        self.view = MockView()
        self.view.request = self.request

    def test_context_attributes_added(self):
        """Test that 'context_' prefixed attributes are added to the context data."""
        context = self.view.get_context_data()

        self.assertIn('page_category', context, "Expected 'page_category' to be in context.")
        self.assertEqual(
            context['page_category'], 'test_category',
            "Expected 'page_category' to match the 'context_page_category' value."
        )

        self.assertIn('page_name', context, "Expected 'page_name' to be in context.")
        self.assertEqual(
            context['page_name'], 'test_name',
            "Expected 'page_name' to match the 'context_page_name' value."
        )

        self.assertIn('custom_field', context, "Expected 'custom_field' to be in context.")
        self.assertEqual(
            context['custom_field'], 'custom_value',
            "Expected 'custom_field' to match the 'context_custom_field' value."
        )


    def test_no_unprefixed_attributes_added(self):
        """Test that attributes without 'context_' prefix are not added to the context data."""
        self.view.some_other_field = 'unexpected_value'
        context = self.view.get_context_data()

        self.assertNotIn(
            'some_other_field',
            context,
            "Expected 'some_other_field' not to be in context because it is not prefixed with 'context_'.",
        )

    def test_overridden_context_does_not_change(self):
        """Test that existing context keys are not overridden by 'context_' prefixed attributes."""
        overridden_context = {'page_category': 'override_category'}
        context = self.view.get_context_data(**overridden_context)

        self.assertEqual(
            context['page_category'],
            'override_category',
            "Expected 'page_category' to remain unchanged in the presence of overridden context.",
        )

        self.assertEqual(
            context['page_name'],
            'test_name',
            "Expected other 'context_' attributes to still be added if not overridden.",
        )

    def test_context_data_with_additional_kwargs(self):
        """Test that additional kwargs passed to get_context_data are included in the context."""
        additional_context = {'extra_key': 'extra_value'}
        context = self.view.get_context_data(**additional_context)

        self.assertIn('extra_key', context, "Expected 'extra_key' to be in the context.")
        self.assertEqual(
            context['extra_key'], 'extra_value',
            "Expected 'extra_key' to match the value passed in additional kwargs."
        )
