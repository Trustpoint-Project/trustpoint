"""Tests for SortableTableMixin with is_active field."""
from typing import Any

from django.db import models
from django.db.models import QuerySet
from django.http import HttpRequest
from django.test import RequestFactory, TestCase

from trustpoint.views.base import SortableTableMixin


class ModelWithIsActive(models.Model):
    """Test model with is_active field."""
    
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        """Meta options for the test model."""
        app_label = 'test_app'


class TestSortableTableMixinWithIsActive(TestCase):
    """Test cases for SortableTableMixin with is_active field."""

    def setUp(self) -> None:
        """Set up the test environment for each test case."""
        self.factory = RequestFactory()

    def test_sort_with_is_active_field(self) -> None:
        """Test that models with is_active are sorted with is_active priority."""
        class TestView(SortableTableMixin):
            model = ModelWithIsActive
            queryset = None
            default_sort_param = 'name'
            request = HttpRequest()

        view = TestView()
        view.request = self.factory.get('/?sort=name')
        
        # Mock the queryset to test order_by is called correctly
        class MockQuerySet:
            def all(self) -> 'MockQuerySet':
                return self
            
            def order_by(self, *args: str) -> list[str]:
                return list(args)
        
        # Monkey-patch the model's objects manager
        original_objects = ModelWithIsActive.objects
        ModelWithIsActive.objects = MockQuerySet()  # type: ignore[assignment]
        
        try:
            result = view.get_queryset()
            # Should order by -is_active first, then by the sort param
            assert result == ['-is_active', 'name']
        finally:
            # Restore original objects manager
            ModelWithIsActive.objects = original_objects  # type: ignore[assignment]

    def test_sort_without_is_active_field(self) -> None:
        """Test that models without is_active are sorted normally."""
        class ModelWithoutIsActive(models.Model):
            name = models.CharField(max_length=100)
            
            class Meta:
                app_label = 'test_app'
        
        class TestView(SortableTableMixin):
            model = ModelWithoutIsActive
            queryset = None
            default_sort_param = 'name'
            request = HttpRequest()

        view = TestView()
        view.request = self.factory.get('/?sort=name')
        
        # Mock the queryset
        class MockQuerySet:
            def all(self) -> 'MockQuerySet':
                return self
            
            def order_by(self, *args: str) -> list[str]:
                return list(args)
        
        # Monkey-patch the model's objects manager
        original_objects = getattr(ModelWithoutIsActive, 'objects', None)
        ModelWithoutIsActive.objects = MockQuerySet()  # type: ignore[assignment]
        
        try:
            result = view.get_queryset()
            # Should only order by the sort param
            assert result == ['name']
        finally:
            # Restore if it existed
            if original_objects:
                ModelWithoutIsActive.objects = original_objects  # type: ignore[assignment]
