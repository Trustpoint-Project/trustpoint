from django.test import TestCase
from django.http import Http404
from django.urls import reverse
from django.views.generic import ListView
from django.test.client import RequestFactory
from django.contrib.auth.models import User
from unittest.mock import patch
from trustpoint.views.base import ListInDetailView
from myapp.models import ParentModel, ChildModel  # Replace with actual models


class TestListInDetailView(TestCase):
    """Test cases for ListInDetailView."""

    @classmethod
    def setUpTestData(cls):
        # Create test data for the ParentModel and the related ChildModel
        cls.parent = ParentModel.objects.create(name="Parent 1")  # Replace fields with your actual model fields
        cls.child1 = ChildModel.objects.create(name="Child 1", parent=cls.parent)  # Replace with actual relationships
        cls.child2 = ChildModel.objects.create(name="Child 2", parent=cls.parent)

    def setUp(self):
        self.factory = RequestFactory()
        self.view = ListInDetailView()

    def test_get_object_success(self):
        """Test that get_object retrieves the correct ParentModel instance."""
        request = self.factory.get('/')
        self.view.request = request

        # Assign the required kwargs
        self.view.kwargs = {'pk': self.parent.pk}
        self.view.detail_model = ParentModel  # Set the detail model in the view

        obj = self.view.get_object()
        self.assertEqual(obj, self.parent, "get_object() should return the correct ParentModel instance.")

    def test_get_object_missing_pk(self):
        """Test that get_object raises AttributeError if 'pk' is missing."""
        request = self.factory.get('/')
        self.view.request = request

        # Missing 'pk' in kwargs
        self.view.kwargs = {}
        self.view.detail_model = ParentModel

        with self.assertRaises(AttributeError, msg="get_object() should raise AttributeError if 'pk' is missing."):
            self.view.get_object()

    def test_get_object_invalid_pk(self):
        """Test that get_object raises Http404 if the object does not exist."""
        request = self.factory.get('/')
        self.view.request = request

        # Assign an invalid 'pk'
        self.view.kwargs = {'pk': 9999}  # Nonexistent PK
        self.view.detail_model = ParentModel

        with self.assertRaises(Http404, msg="get_object() should raise Http404 if no object matches the given PK."):
            self.view.get_object()

    def test_get_queryset_for_object(self):
        """Test that get_queryset_for_object retrieves the queryset of the detail model."""
        request = self.factory.get('/')
        self.view.request = request
        self.view.detail_model = ParentModel

        queryset = self.view.get_queryset_for_object()
        self.assertQuerysetEqual(
            queryset, ParentModel.objects.all(), transform=lambda x: x, msg="get_queryset_for_object() should return all ParentModel objects."
        )

    def test_get_context_data(self):
        """Test that get_context_data adds detail_context_object_name and context_object_name to context."""
        request = self.factory.get('/')
        self.view.request = request

        # Mock required attributes
        self.view.kwargs = {'pk': self.parent.pk}
        self.view.detail_model = ParentModel
        self.view.model = ChildModel
        self.view.object_list = ChildModel.objects.all()  # Assign a queryset for the ListView context
        self.view.object = self.parent

        context = self.view.get_context_data()
        self.assertIn('object', context, "'object' should be in the context.")
        self.assertEqual(context['object'], self.parent, "'object' in the context should match the ParentModel instance.")
        self.assertIn('childmodel_list', context, "'childmodel_list' (default context_object_name) should be in the context.")