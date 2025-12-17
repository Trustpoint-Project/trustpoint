"""Tests for the BulkDeleteView and related classes."""
from typing import Any

import pytest
from devices.models import DeviceModel
from django.core.exceptions import ImproperlyConfigured
from django.db.models import QuerySet
from django.http import Http404, HttpResponse
from django.test import RequestFactory, TestCase
from django.urls import reverse

from trustpoint.views.base import (
    BaseBulkDeleteView,
    BulkDeleteView,
    PrimaryKeyListFromPrimaryKeyString,
    PrimaryKeyQuerysetFromUrlMixin,
)


class TestPrimaryKeyListFromPrimaryKeyString(TestCase):
    """Test cases for PrimaryKeyListFromPrimaryKeyString."""

    def test_get_pks_as_list_single_pk(self) -> None:
        """Test parsing a single primary key."""
        pks = '1'
        result = PrimaryKeyListFromPrimaryKeyString.get_pks_as_list(pks)
        assert result == ['1']

    def test_get_pks_as_list_multiple_pks(self) -> None:
        """Test parsing multiple primary keys."""
        pks = '1/2/3'
        result = PrimaryKeyListFromPrimaryKeyString.get_pks_as_list(pks)
        assert result == ['1', '2', '3']

    def test_get_pks_as_list_trailing_slash(self) -> None:
        """Test parsing with trailing slash."""
        pks = '1/2/3/'
        result = PrimaryKeyListFromPrimaryKeyString.get_pks_as_list(pks)
        assert result == ['1', '2', '3']

    def test_get_pks_as_list_empty_string(self) -> None:
        """Test parsing an empty string."""
        pks = ''
        result = PrimaryKeyListFromPrimaryKeyString.get_pks_as_list(pks)
        assert result == []

    def test_get_pks_as_list_duplicates(self) -> None:
        """Test that duplicates raise Http404."""
        pks = '1/2/1'
        with pytest.raises(Http404) as exc_info:
            PrimaryKeyListFromPrimaryKeyString.get_pks_as_list(pks)
        assert 'Duplicates in query primary key list found.' in str(exc_info.value)


class TestPrimaryKeyQuerysetFromUrlMixin(TestCase):
    """Test cases for PrimaryKeyQuerysetFromUrlMixin."""

    @classmethod
    def setUpTestData(cls) -> None:
        """Create test data for the test class."""
        cls.device1 = DeviceModel.objects.create(common_name='Device A', serial_number='12345')
        cls.device2 = DeviceModel.objects.create(common_name='Device B', serial_number='67890')
        cls.device3 = DeviceModel.objects.create(common_name='Device C', serial_number='54321')

    def test_get_queryset_all_objects(self) -> None:
        """Test getting all objects when no pks provided."""
        class TestView(PrimaryKeyQuerysetFromUrlMixin):
            model = DeviceModel
            queryset = None
            kwargs = {'pks': ''}

        view = TestView()
        queryset = view.get_queryset()
        assert queryset is not None
        assert queryset.count() == 3

    def test_get_queryset_with_pks(self) -> None:
        """Test getting queryset with specific pks."""
        class TestView(PrimaryKeyQuerysetFromUrlMixin):
            model = DeviceModel
            queryset = None
            kwargs = {'pks': f'{self.device1.pk}/{self.device2.pk}/'}

        view = TestView()
        queryset = view.get_queryset()
        assert queryset is not None
        assert queryset.count() == 2
        assert self.device1 in queryset
        assert self.device2 in queryset
        assert self.device3 not in queryset

    def test_get_queryset_with_invalid_pk(self) -> None:
        """Test getting queryset with invalid pk."""
        class TestView(PrimaryKeyQuerysetFromUrlMixin):
            model = DeviceModel
            queryset = None
            kwargs = {'pks': f'{self.device1.pk}/99999/'}

        view = TestView()
        queryset = view.get_queryset()
        # Should return an empty queryset when pk count doesn't match queryset count
        assert isinstance(queryset, QuerySet)
        assert queryset.count() == 0

    def test_get_queryset_cached(self) -> None:
        """Test that queryset is cached."""
        cached_queryset = DeviceModel.objects.filter(pk=self.device1.pk)
        
        class TestView(PrimaryKeyQuerysetFromUrlMixin):
            model = DeviceModel
            queryset = cached_queryset
            kwargs = {'pks': ''}

        view = TestView()
        result = view.get_queryset()
        assert result == cached_queryset


class TestBaseBulkDeleteView(TestCase):
    """Test cases for BaseBulkDeleteView."""

    @classmethod
    def setUpTestData(cls) -> None:
        """Create test data for the test class."""
        cls.device1 = DeviceModel.objects.create(common_name='Device A', serial_number='12345')
        cls.device2 = DeviceModel.objects.create(common_name='Device B', serial_number='67890')

    def setUp(self) -> None:
        """Set up the test environment for each test case."""
        self.factory = RequestFactory()

    def test_post_valid_form(self) -> None:
        """Test POST request with valid form."""
        device1_pk = self.device1.pk
        
        class TestBulkDeleteView(BaseBulkDeleteView):
            model = DeviceModel
            success_url = '/success/'
            
            def get_queryset(self) -> QuerySet[Any]:
                return DeviceModel.objects.filter(pk=device1_pk)

        view = TestBulkDeleteView()
        request = self.factory.post('/delete/')
        view.request = request  # Set request attribute
        
        # Store initial count
        initial_count = DeviceModel.objects.count()
        
        response = view.post(request)
        
        # Check response is redirect
        assert response.status_code == 302
        assert response.url == '/success/'
        
        # Check device was deleted
        assert DeviceModel.objects.count() == initial_count - 1
        assert not DeviceModel.objects.filter(pk=device1_pk).exists()

    def test_get_success_url_missing(self) -> None:
        """Test that missing success_url raises ImproperlyConfigured."""
        class TestBulkDeleteView(BaseBulkDeleteView):
            model = DeviceModel
            success_url = None

        view = TestBulkDeleteView()
        
        with pytest.raises(ImproperlyConfigured) as exc_info:
            view.get_success_url()
        assert 'No URL to redirect to. Provide a success_url.' in str(exc_info.value)

    def test_get_success_url_provided(self) -> None:
        """Test getting success_url when provided."""
        class TestBulkDeleteView(BaseBulkDeleteView):
            success_url = '/test-success/'

        view = TestBulkDeleteView()
        result = view.get_success_url()
        assert result == '/test-success/'


class TestBulkDeleteView(TestCase):
    """Test cases for BulkDeleteView."""

    @classmethod
    def setUpTestData(cls) -> None:
        """Create test data for the test class."""
        cls.device1 = DeviceModel.objects.create(common_name='Device A', serial_number='12345')
        cls.device2 = DeviceModel.objects.create(common_name='Device B', serial_number='67890')

    def test_bulk_delete_view_inheritance(self) -> None:
        """Test that BulkDeleteView inherits correctly."""
        view = BulkDeleteView()
        assert hasattr(view, 'get_queryset')
        assert hasattr(view, 'post')
        assert hasattr(view, 'get_success_url')
